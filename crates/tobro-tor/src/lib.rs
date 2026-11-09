//! Arti integration boundary for tobro.
//!
//! This is the M0 feasibility spike: it bootstraps a [`TorClient`], streams
//! bootstrap progress, verifies a request over Tor, and hosts Arti's
//! SOCKS/HTTP and DNS listeners.
//!
//! # M0 finding: where listeners live
//!
//! Arti 2.8.0 exposes `bind_proxy`/`run_proxy_with_listeners` and the DNS
//! `bind_dns_resolver`, but not the methods that actually *run* a bound
//! listener (`StreamProxy::run_proxy`, `DnsProxy::run_dns_proxy` are
//! `pub(crate)`). The only supported way to host SOCKS + HTTP CONNECT + DNS
//! from a library is [`arti::run_proxy`], which owns the `TorClient` it serves.
//!
//! That is why [`Tor`] (bootstrap events, connectivity checks) and [`serve`]
//! (long-running listeners) are separate phases: a `TorClient` holds an
//! exclusive lock on its state directory, so the observation client must be
//! dropped before the serving client is created. The [`adapter`] module provides
//! the M1 supervised start/stop/status wrapper around this pattern.

#![forbid(unsafe_code)]

pub mod adapter;
pub mod custom_proxy;
pub mod isolation;
pub mod proxy;

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use arti::proxy::ListenProtocols;
use arti_client::config::{CfgPath, TorClientConfig, TorClientConfigBuilder};
use arti_client::status::BootstrapStatus;
use arti_client::{BootstrapBehavior, TorClient};
use futures::StreamExt as _;
use futures::io::{AsyncReadExt, AsyncWriteExt};
use serde::Serialize;
use tokio::time::timeout;
use tor_config::{ConfigurationSources, ConfigurationTree, Listen};
use tor_rtcompat::PreferredRuntime;
use tracing::debug;

/// Arti release this crate is built against; keep in sync with the workspace pin.
pub const ARTI_VERSION: &str = "2.8.0";

/// Default local SOCKS port (Orbot-compatible). Also carries HTTP CONNECT
/// while Arti serves both protocols on one listener.
pub const DEFAULT_SOCKS_PORT: u16 = 9050;

/// Default local HTTP CONNECT port (Orbot-compatible config value). With Arti
/// 2.8 this is served on the same listener as SOCKS.
pub const DEFAULT_HTTP_PORT: u16 = 9050;

/// Default local DNS proxy port (Orbot-compatible).
pub const DEFAULT_DNS_PORT: u16 = 9053;

/// The concrete Arti client type used by tobro.
pub type Client = TorClient<PreferredRuntime>;

/// One bootstrap progress notification.
#[derive(Debug, Clone, Serialize)]
pub struct BootstrapEvent {
    /// Rough progress from 0 to 100.
    pub percent: u8,
    /// True once the client can carry traffic.
    pub ready: bool,
    /// Set when Arti believes it is stuck, with Arti's explanation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocked: Option<String>,
    /// Human-readable status, including connection and directory detail.
    pub detail: String,
}

impl BootstrapEvent {
    fn from_status(status: &BootstrapStatus) -> Self {
        let percent = (status.as_frac() * 100.0).round().clamp(0.0, 100.0) as u8;
        Self {
            percent: if status.ready_for_traffic() {
                100
            } else {
                percent
            },
            ready: status.ready_for_traffic(),
            blocked: status.blocked().map(|b| b.message().to_string()),
            detail: status.to_string(),
        }
    }
}

/// Result of requesting a URL through the Tor network.
#[derive(Debug, Clone, Serialize)]
pub struct HttpCheck {
    /// Host and port that were contacted.
    pub target: String,
    /// HTTP status code from the first response line.
    pub status: u16,
    /// Wall-clock time for connect, request, and response.
    pub elapsed_ms: u64,
}

/// A bootstrapped (or bootstrapping) Arti client, plus progress reporting.
pub struct Tor {
    client: Arc<Client>,
}

impl std::fmt::Debug for Tor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tor").finish_non_exhaustive()
    }
}

impl Tor {
    /// Create an unbootstrapped client with tobro-controlled state directories.
    pub async fn create(state_dir: &Path, cache_dir: &Path) -> anyhow::Result<Self> {
        let config = client_config(state_dir, cache_dir)?;
        let client = Client::builder()
            .config(config)
            .bootstrap_behavior(BootstrapBehavior::Manual)
            .create_unbootstrapped_async()
            .await?;
        Ok(Self { client })
    }

    /// The underlying Arti client handle.
    pub fn client(&self) -> &Arc<Client> {
        &self.client
    }

    /// Bootstrap, invoking `on_event` whenever progress changes.
    ///
    /// Returns how long bootstrapping took once the client is usable.
    pub async fn bootstrap<F>(&self, mut on_event: F) -> anyhow::Result<Duration>
    where
        F: FnMut(BootstrapEvent),
    {
        let started = Instant::now();
        let mut events = self.client.bootstrap_events();
        let bootstrap = self.client.bootstrap();
        tokio::pin!(bootstrap);

        let mut last: Option<(u8, Option<String>)> = None;
        let mut events_open = true;

        loop {
            tokio::select! {
                // Poll the bootstrap future first so the initial "waiting to
                // be told to bootstrap" status is not reported as a problem.
                biased;
                result = &mut bootstrap => {
                    result.context("Arti bootstrap failed")?;
                    // Bootstrap success means the client can carry traffic, but
                    // the status snapshot can lag by one update. Report the
                    // authoritative outcome, not a stale percentage.
                    let mut event = BootstrapEvent::from_status(&self.client.bootstrap_status());
                    if !event.ready {
                        event.detail = "bootstrap complete".to_owned();
                    }
                    event.percent = 100;
                    event.ready = true;
                    event.blocked = None;
                    on_event(event);
                    return Ok(started.elapsed());
                }
                maybe = events.next(), if events_open => {
                    match maybe {
                        Some(status) => {
                            let event = BootstrapEvent::from_status(&status);
                            let key = (event.percent, event.blocked.clone());
                            if last.as_ref() != Some(&key) {
                                on_event(event);
                                last = Some(key);
                            }
                        }
                        // The status stream ends only when the client is dropped.
                        None => events_open = false,
                    }
                }
            }
        }
    }

    /// Request `/` from `host:port` through Tor and return the HTTP status.
    ///
    /// This deliberately speaks raw HTTP/1.0 over the Tor stream so the spike
    /// needs no TLS or HTTP stack of its own.
    pub async fn check_http(
        &self,
        host: &str,
        port: u16,
        limit: Duration,
    ) -> anyhow::Result<HttpCheck> {
        let target = format!("{host}:{port}");
        let started = Instant::now();

        let mut stream = timeout(limit, self.client.connect((host, port)))
            .await
            .with_context(|| format!("timed out connecting to {target}"))??;

        let request = format!("GET / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n");
        timeout(limit, async {
            stream.write_all(request.as_bytes()).await?;
            stream.flush().await?;
            Ok::<_, std::io::Error>(())
        })
        .await
        .with_context(|| format!("timed out sending request to {target}"))??;

        let mut response = Vec::new();
        timeout(
            limit,
            (&mut stream).take(64 * 1024).read_to_end(&mut response),
        )
        .await
        .with_context(|| format!("timed out reading response from {target}"))??;

        let status = parse_http_status(&response)
            .with_context(|| format!("no HTTP status line in response from {target}"))?;

        debug!(%target, status, "request over Tor succeeded");

        Ok(HttpCheck {
            target,
            status,
            elapsed_ms: started.elapsed().as_millis() as u64,
        })
    }
}

/// Host local SOCKS/HTTP CONNECT and DNS listeners until shutdown.
///
/// `state_dir` and `cache_dir` must be the same directories the observing
/// [`Tor`] client used; Arti caches the network consensus there, so a serving
/// client can bootstrap from disk/state.
///
/// When `bind_all_interfaces` is true, listeners bind to `0.0.0.0` (opt-in).
///
/// Uses Arti's built-in `run_proxy` when no custom isolation/frontend or
/// network StreamPrefs are required. Otherwise uses tobro's custom proxy path
/// to apply isolation and/or default StreamPrefs (M2).
pub async fn serve(
    state_dir: &Path,
    cache_dir: &Path,
    socks_port: u16,
    dns_port: u16,
    bind_all_interfaces: bool,
    stream_isolation: adapter::StreamIsolationPolicy,
    network_prefs: adapter::NetworkStreamPrefs,
) -> anyhow::Result<()> {
    let config = client_config(state_dir, cache_dir)?;
    let needs_custom = stream_isolation.needs_frontend() || network_prefs.is_active();

    if needs_custom {
        return serve_custom(
            state_dir,
            cache_dir,
            config,
            socks_port,
            dns_port,
            bind_all_interfaces,
            stream_isolation,
            network_prefs,
        )
        .await;
    }

    // `arti::run_proxy` would otherwise write its port-info file into the
    // standalone Arti application's data directory. Keep it with tobro state.
    let mut arti_config = arti::ArtiConfigBuilder::default();
    arti_config
        .storage()
        .port_info_file(CfgPath::new_literal(state_dir.join("port_info.json")));
    let arti_config = arti_config.build()?;

    let runtime = PreferredRuntime::current()?;

    arti::run_proxy(
        runtime,
        listen_for_port(socks_port, bind_all_interfaces)?,
        listen_for_port(dns_port, bind_all_interfaces)?,
        ListenProtocols::SocksAndHttpConnect,
        ConfigurationSources::new_empty(),
        ConfigurationTree::default(),
        arti_config,
        config,
    )
    .await
}

async fn serve_with_isolation(
    state_dir: &Path,
    _cache_dir: &Path,
    config: TorClientConfig,
    socks_port: u16,
    dns_port: u16,
    bind_all_interfaces: bool,
    stream_isolation: adapter::StreamIsolationPolicy,
) -> anyhow::Result<()> {
    // Reserve an ephemeral localhost port for the backend arti::run_proxy
    // SOCKS/HTTP listener. Our isolation front-end binds the user-facing port
    // and forwards with isolation injection; arti handles DNS and the actual
    // Tor proxying on the backend port. This preserves a single Arti client and
    // state lock.
    let backend_listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .context("could not reserve backend proxy port")?;
    let backend_socks_port = backend_listener.local_addr()?.port();
    drop(backend_listener);

    let mut arti_config = arti::ArtiConfigBuilder::default();
    arti_config
        .storage()
        .port_info_file(CfgPath::new_literal(state_dir.join("port_info.json")));
    let arti_config = arti_config.build()?;
    let runtime = PreferredRuntime::current()?;

    let backend = arti::run_proxy(
        runtime,
        Listen::new_localhost(backend_socks_port),
        listen_for_port(dns_port, bind_all_interfaces)?,
        ListenProtocols::SocksAndHttpConnect,
        ConfigurationSources::new_empty(),
        ConfigurationTree::default(),
        arti_config,
        config,
    );
    tokio::pin!(backend);

    let bind_ip = if bind_all_interfaces {
        std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
    } else {
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
    };
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let frontend = proxy::run_isolation_frontend(
        stream_isolation,
        std::net::SocketAddr::new(bind_ip, socks_port),
        std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            backend_socks_port,
        ),
        shutdown_rx,
    );
    tokio::pin!(frontend);

    tokio::select! {
        biased;
        res = &mut frontend => {
            let _ = shutdown_tx.send(());
            res.context("isolation front-end failed")
        }
        res = &mut backend => {
            let _ = shutdown_tx.send(());
            res.context("backend Tor proxy failed")
        }
    }
}

async fn serve_custom(
    state_dir: &Path,
    cache_dir: &Path,
    config: TorClientConfig,
    socks_port: u16,
    dns_port: u16,
    bind_all_interfaces: bool,
    stream_isolation: adapter::StreamIsolationPolicy,
    network_prefs: adapter::NetworkStreamPrefs,
) -> anyhow::Result<()> {
    // If only destination/port isolation is needed and no network StreamPrefs,
    // preserve the proven forwarding front-end path.
    if !network_prefs.is_active() && stream_isolation.needs_frontend() {
        return serve_with_isolation(
            state_dir,
            cache_dir,
            config,
            socks_port,
            dns_port,
            bind_all_interfaces,
            stream_isolation,
        )
        .await;
    }

    // Custom path: own the TorClient so we can apply default StreamPrefs
    // (exit country, IPv6, M2) and isolation.
    let client = Client::builder()
        .config(config)
        .bootstrap_behavior(BootstrapBehavior::OnDemand)
        .create_unbootstrapped_async()
        .await
        .context("could not create the serving Arti client")?;
    client
        .bootstrap()
        .await
        .context("Arti bootstrap failed for custom proxy")?;

    custom_proxy::serve(
        client,
        socks_port,
        dns_port,
        bind_all_interfaces,
        stream_isolation,
        network_prefs,
    )
    .await
}

fn listen_for_port(port: u16, bind_all_interfaces: bool) -> anyhow::Result<Listen> {
    if !bind_all_interfaces {
        return Ok(Listen::new_localhost(port));
    }
    // tor-config 0.48 exposes localhost constructors but builds other listen
    // specs via serde. Binding all interfaces is an explicit opt-in (M2/F-13).
    let listen: Listen = serde_json::from_value(serde_json::Value::String(format!(
        "0.0.0.0:{port}"
    )))
    .with_context(|| format!("could not build an all-interfaces listener for port {port}"))?;
    Ok(listen)
}

fn client_config(state_dir: &Path, cache_dir: &Path) -> anyhow::Result<TorClientConfig> {
    // Ensure private permissions before Arti/mistrust checks. This also repairs
    // existing directories created with overly permissive modes (e.g. 0755).
    ensure_private_dir(state_dir)?;
    ensure_private_dir(cache_dir)?;

    let config = TorClientConfigBuilder::from_directories(state_dir, cache_dir).build()?;

    // Arti refuses state/cache directories that are accessible to other users.
    // `make_directory` creates them with 0700 (Unix) and verifies the result.
    let mistrust = config.fs_mistrust().clone();
    mistrust.make_directory(state_dir)?;
    mistrust.make_directory(cache_dir)?;

    Ok(config)
}

#[cfg(unix)]
fn ensure_private_dir(dir: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
    if dir.exists() {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("failed to set private permissions on {}", dir.display()))?;
    } else {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .with_context(|| format!("failed to create private directory {}", dir.display()))?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_private_dir(dir: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir)
        .with_context(|| format!("failed to create directory {}", dir.display()))?;
    Ok(())
}

/// Extract the status code from the first line of an HTTP response.
pub fn parse_http_status(response: &[u8]) -> Option<u16> {
    let line = response.split(|&b| b == b'\n').next()?;
    let line = std::str::from_utf8(line).ok()?.trim_end();
    let mut parts = line.split_whitespace();
    let version = parts.next()?;
    if !version.starts_with("HTTP/") {
        return None;
    }
    parts.next()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::{listen_for_port, parse_http_status};

    #[test]
    fn parses_http_status_lines() {
        assert_eq!(parse_http_status(b"HTTP/1.0 200 OK\r\n\r\n"), Some(200));
        assert_eq!(
            parse_http_status(b"HTTP/1.1 301 Moved\r\nLocation: /x\r\n"),
            Some(301)
        );
        assert_eq!(parse_http_status(b"garbage\r\n"), None);
        assert_eq!(parse_http_status(b"HTTP/1.0 nope\r\n"), None);
        assert_eq!(parse_http_status(b""), None);
    }

    #[test]
    fn builds_localhost_and_all_interfaces_listeners() -> Result<(), Box<dyn std::error::Error>> {
        let local = listen_for_port(9050, false)?;
        assert!(local.is_loopback_only());
        let all = listen_for_port(9050, true)?;
        assert!(!all.is_loopback_only());
        Ok(())
    }
}
