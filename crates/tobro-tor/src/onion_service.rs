//! Onion service hosting integration (Arti `tor-hsservice` + `tor-hsrproxy`).
//!
//! Launches enabled v3 onion services on a running `TorClient`, forwards
//! incoming streams to configured local targets, and reports status/errors.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context as _;
use arti_client::TorClient;
use futures::StreamExt as _;
use safelog::DisplayRedacted as _;
use serde::{Deserialize, Serialize};
use tor_hsrproxy::OnionServiceReverseProxy;
use tor_hsrproxy::config::{
    Encapsulation, ProxyAction, ProxyConfigBuilder, ProxyPattern, ProxyRule, TargetAddr,
};
use tor_hsservice::{HsNickname, RunningOnionService};
use tor_rtcompat::{Runtime, SpawnExt as _};
use tracing::{info, warn};

/// Desired onion service to host at runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostedOnionService {
    /// Stable service id (store id).
    pub id: String,
    /// Arti/hs nickname (must be a valid `HsNickname`).
    pub nickname: String,
    /// Human-readable name.
    pub name: String,
    /// Port mappings.
    pub ports: Vec<HostedOnionPort>,
}

/// Virtual port -> local target mapping.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostedOnionPort {
    /// Onion-facing virtual port.
    pub virt_port: u16,
    /// Local target host (IP/hostname resolved by the proxy as configured).
    pub target_host: String,
    /// Local target TCP port.
    pub target_port: u16,
}

/// Runtime status snapshot for a hosted onion service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum OnionServiceRuntimeStatus {
    /// Launch requested / waiting for publication details.
    Starting,
    /// Onion address is known (published/available to report).
    Published {
        /// The `.onion` address.
        onion_address: String,
    },
    /// Failed to launch or encountered an error.
    Error {
        /// Safe error message.
        message: String,
    },
    /// Stopped/disabled.
    Stopped,
}

/// A launched onion service and its reverse proxy.
#[derive(Clone)]
pub struct RunningHostedService {
    /// Store/service id.
    pub id: String,
    nickname: HsNickname,
    svc: Arc<RunningOnionService>,
    _proxy: Arc<OnionServiceReverseProxy>,
}

impl std::fmt::Debug for RunningHostedService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RunningHostedService")
            .field("id", &self.id)
            .field("nickname", &self.nickname.to_string())
            .finish_non_exhaustive()
    }
}

impl RunningHostedService {
    /// Current best-effort onion address, if available.
    pub fn onion_address(&self) -> Option<String> {
        self.svc
            .onion_address()
            .map(|a| a.display_unredacted().to_string())
    }

    /// Subscribe to service status changes, enriched with the published onion
    /// address when available.
    pub fn status_events(
        &self,
    ) -> impl futures::Stream<Item = OnionServiceRuntimeStatus> + Send + 'static {
        let id = self.id.clone();
        let svc = Arc::clone(&self.svc);
        let mut stream = self.svc.status_events();
        async_stream::stream! {
            while let Some(st) = stream.next().await {
                let mut status = map_status(&id, &st);
                if matches!(status, OnionServiceRuntimeStatus::Starting)
                    && let Some(addr) = svc.onion_address()
                {
                    status = OnionServiceRuntimeStatus::Published {
                        onion_address: addr.display_unredacted().to_string(),
                    };
                }
                yield status;
            }
        }
    }

    /// Raw tor-hsservice status stream.
    pub fn raw_status_events(
        &self,
    ) -> impl futures::Stream<Item = tor_hsservice::status::OnionServiceStatus> + Send + 'static
    {
        self.svc.status_events()
    }
}

/// Map a tor-hsservice status snapshot to a runtime status.
pub fn map_status(
    id: &str,
    st: &tor_hsservice::status::OnionServiceStatus,
) -> OnionServiceRuntimeStatus {
    use tor_hsservice::status::State;
    match st.state() {
        State::Running => {
            let _ = id;
            OnionServiceRuntimeStatus::Starting
        }
        State::DegradedReachable | State::DegradedUnreachable | State::Bootstrapping => {
            OnionServiceRuntimeStatus::Starting
        }
        State::Shutdown => OnionServiceRuntimeStatus::Stopped,
        State::Broken => OnionServiceRuntimeStatus::Error {
            message: st
                .current_problem()
                .map(|p| format!("{p:?}"))
                .unwrap_or_else(|| "onion service is broken".to_owned()),
        },
        _ => OnionServiceRuntimeStatus::Starting,
    }
}

fn build_proxy_config(
    spec: &HostedOnionService,
) -> anyhow::Result<tor_hsrproxy::config::ProxyConfig> {
    let mut b = ProxyConfigBuilder::default();
    for port in &spec.ports {
        let pattern = ProxyPattern::one_port(port.virt_port).with_context(|| {
            format!(
                "invalid virtual port {} for {}",
                port.virt_port, spec.nickname
            )
        })?;
        let host = port.target_host.trim();
        let host = if host.is_empty() { "127.0.0.1" } else { host };
        let addr = resolve_target(host, port.target_port).with_context(|| {
            format!(
                "invalid target {}:{} for {}",
                host, port.target_port, spec.nickname
            )
        })?;
        let rule = ProxyRule::new(
            pattern,
            ProxyAction::Forward(Encapsulation::Simple, TargetAddr::Inet(addr)),
        );
        b.proxy_ports().push(rule);
    }
    b.build().context("invalid onion service proxy config")
}

fn resolve_target(host: &str, port: u16) -> anyhow::Result<SocketAddr> {
    if let Ok(ip) = host.parse() {
        return Ok(SocketAddr::new(ip, port));
    }
    // Resolve hostname locally (best-effort). For loopback names prefer 127.0.0.1.
    if host.eq_ignore_ascii_case("localhost") {
        return Ok(SocketAddr::from(([127, 0, 0, 1], port)));
    }
    use std::net::ToSocketAddrs as _;
    let mut addrs = (host, port)
        .to_socket_addrs()
        .with_context(|| format!("could not resolve target host {host}"))?;
    addrs
        .next()
        .with_context(|| format!("no addresses resolved for target host {host}"))
}

fn build_service_config(
    spec: &HostedOnionService,
) -> anyhow::Result<arti_client::config::onion_service::OnionServiceConfig> {
    let mut b = arti_client::config::onion_service::OnionServiceConfigBuilder::default();
    let nick: HsNickname = spec
        .nickname
        .parse()
        .with_context(|| format!("invalid onion service nickname {:?}", spec.nickname))?;
    b.nickname(nick);
    b.build().context("invalid onion service config")
}

/// Launch a hosted onion service on `client`.
pub fn launch<R: Runtime + Send + Sync + 'static>(
    client: &TorClient<R>,
    spec: HostedOnionService,
) -> anyhow::Result<(RunningHostedService, OnionServiceRuntimeStatus)> {
    if spec.ports.is_empty() {
        anyhow::bail!("onion service {} has no port mappings", spec.name);
    }
    let svc_cfg = build_service_config(&spec)?;
    let proxy_cfg = build_proxy_config(&spec)?;
    let nickname: HsNickname = spec.nickname.parse().context("invalid nickname")?;

    let (svc, request_stream) = client
        .launch_onion_service(svc_cfg)
        .with_context(|| format!("failed to launch onion service {}", spec.name))?
        .ok_or_else(|| anyhow::anyhow!("onion service {} is disabled in Tor config", spec.name))?;

    let proxy = OnionServiceReverseProxy::new(proxy_cfg);
    let proxy_for_task = Arc::clone(&proxy);
    let nick_for_task = nickname.clone();
    let id_for_task = spec.id.clone();
    let runtime = client.runtime().clone();
    let runtime_for_task = runtime.clone();
    runtime.spawn(async move {
        match proxy_for_task
            .handle_requests(runtime_for_task, nick_for_task.clone(), request_stream)
            .await
        {
            Ok(()) => info!(id=%id_for_task, nickname=%nick_for_task, "onion service proxy exited"),
            Err(e) => warn!(id=%id_for_task, nickname=%nick_for_task, error=%format!("{e:#}"), "onion service proxy error"),
        }
    })?;

    let running = RunningHostedService {
        id: spec.id.clone(),
        nickname,
        svc,
        _proxy: proxy,
    };
    let initial = running
        .onion_address()
        .map(|onion_address| OnionServiceRuntimeStatus::Published { onion_address })
        .unwrap_or(OnionServiceRuntimeStatus::Starting);
    Ok((running, initial))
}
