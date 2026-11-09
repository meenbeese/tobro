//! M1 adapter interface around Arti.
//!
//! This wraps the M0 two-phase pattern (bootstrap observer, then serving proxy)
//! required by Arti 2.8's `arti::run_proxy` ownership/lock behavior:
//! - `arti::run_proxy` owns the client it serves and holds an exclusive state-dir lock.
//! - An observer client used for bootstrap/status must be dropped before serving.
//!
//! M1 uses a supervised start: bootstrap to "ready for traffic" with progress events,
//! then hand off to a serving task. Stop cancels the serving task.
//!
//! `arti::run_proxy` returns a `!Send` future, so the serving phase is returned as a
//! future for the caller/supervisor to run (e.g. on a dedicated runtime/thread or local task).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::Context as _;
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, watch};
use tor_chanmgr::ProxyProtocol;

use crate::{BootstrapEvent, BridgeSettings, Tor};

fn encode_userinfo_component(s: &str) -> String {
    utf8_percent_encode(s, NON_ALPHANUMERIC).to_string()
}

/// Effective outbound proxy applied to Arti channel connections (F-18/F-19).
///
/// For Shadowsocks, this represents the local `sslocal` SOCKS5 endpoint after
/// the sidecar is started by the daemon.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct OutboundProxySettings {
    /// Proxy protocol, or `None` for direct connections.
    #[serde(skip)]
    pub proxy: Option<ProxyProtocol>,
    /// Human-readable summary (no secrets) for status/logging.
    pub summary: Option<String>,
}

impl OutboundProxySettings {
    /// No outbound proxy.
    pub fn direct() -> Self {
        Self::default()
    }

    fn parse_url(url: &str, summary: String) -> anyhow::Result<Self> {
        let proxy = ProxyProtocol::from_str(url)
            .map_err(|e| anyhow::anyhow!("invalid outbound proxy URL: {e}"))?;
        Ok(Self {
            proxy: Some(proxy),
            summary: Some(summary),
        })
    }

    /// Build an HTTP CONNECT outbound proxy.
    pub fn http(addr: SocketAddr, username: String, password: String) -> anyhow::Result<Self> {
        if username.is_empty() && !password.is_empty() {
            anyhow::bail!("HTTP proxy auth requires a username when a password is set");
        }
        let (url, summary) = if username.is_empty() {
            (format!("http://{addr}"), format!("http://{addr}"))
        } else {
            let user = encode_userinfo_component(&username);
            let auth = if password.is_empty() {
                format!("{user}@")
            } else {
                let pass = encode_userinfo_component(&password);
                format!("{user}:{pass}@")
            };
            (
                format!("http://{auth}{addr}"),
                format!("http://<auth>@{addr}"),
            )
        };
        Self::parse_url(&url, summary)
    }

    /// Build a SOCKS outbound proxy.
    pub fn socks(
        version: u8,
        addr: SocketAddr,
        username: String,
        password: String,
    ) -> anyhow::Result<Self> {
        let scheme = match version {
            4 => "socks4",
            5 => "socks5",
            _ => anyhow::bail!("unsupported SOCKS version {version}"),
        };
        if version == 4 && !password.is_empty() {
            anyhow::bail!("SOCKS4 does not support password authentication; use SOCKS5");
        }
        let (url, summary) = if username.is_empty() && password.is_empty() {
            (format!("{scheme}://{addr}"), format!("{scheme}://{addr}"))
        } else if version == 4 {
            let user = encode_userinfo_component(&username);
            (
                format!("{scheme}://{user}@{addr}"),
                format!("{scheme}://<auth>@{addr}"),
            )
        } else {
            let user = encode_userinfo_component(&username);
            let pass = encode_userinfo_component(&password);
            (
                format!("{scheme}://{user}:{pass}@{addr}"),
                format!("{scheme}://<auth>@{addr}"),
            )
        };
        Self::parse_url(&url, summary)
    }

    /// Local SOCKS5 endpoint for a Shadowsocks `sslocal` sidecar.
    pub fn shadowsocks_local(addr: SocketAddr) -> anyhow::Result<Self> {
        Self::parse_url(
            &format!("socks5://{addr}"),
            format!("shadowsocks via local socks5://{addr}"),
        )
    }

    /// True when a proxy is configured.
    pub fn is_active(&self) -> bool {
        self.proxy.is_some()
    }
}

/// Stream isolation policy (F-42/F-43).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct StreamIsolationPolicy {
    /// Isolate by destination address.
    pub isolate_destination: bool,
    /// Isolate by destination port.
    pub isolate_port: bool,
    /// Isolate by client protocol (SOCKS vs HTTP CONNECT).
    pub isolate_protocol: bool,
    /// SOCKS auth keep-alive isolation: treat SOCKS auth as a persistent
    /// isolation key (Arti natively isolates by provided auth; this keeps the
    /// policy explicit).
    pub keep_alive_isolation: bool,
}

/// Default network stream preferences (M2: exit country, IPv6/IP version).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkStreamPrefs {
    /// Preferred exit country (ISO 3166-1 alpha-2, lowercase), or `None` for any.
    pub exit_country: Option<String>,
    /// IP version preference for streams (F-44).
    pub ip_version: IpVersionPref,
}

/// IP version preference (mirrors config; serde-compatible string form).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpVersionPref {
    /// Prefer IPv4, allow IPv6.
    #[default]
    Ipv4Preferred,
    /// Prefer IPv6, allow IPv4.
    Ipv6Preferred,
    /// Only IPv4.
    Ipv4Only,
    /// Only IPv6.
    Ipv6Only,
}

impl NetworkStreamPrefs {
    /// True when non-default prefs require custom StreamPrefs application.
    pub fn is_active(&self) -> bool {
        self.exit_country
            .as_deref()
            .is_some_and(|s| !s.trim().is_empty())
            || self.ip_version != IpVersionPref::Ipv4Preferred
    }
}

impl StreamIsolationPolicy {
    /// True when destination/port isolation requires tobro's thin proxy
    /// front-end behavior beyond Arti's built-in auth/header isolation.
    pub fn needs_frontend(self) -> bool {
        self.isolate_destination || self.isolate_port
    }
}

/// Listener and proxy behavior configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListenerConfig {
    /// SOCKS5 port (also carries HTTP CONNECT while listeners are combined).
    pub socks_port: u16,
    /// HTTP CONNECT port (reported; served on `socks_port` while combined).
    pub http_port: u16,
    /// UDP DNS proxy port.
    pub dns_port: u16,
    /// Bind listeners on all interfaces instead of loopback only (opt-in).
    #[serde(default)]
    pub bind_all_interfaces: bool,
    /// Stream isolation policy (F-42/F-43).
    #[serde(default)]
    pub stream_isolation: StreamIsolationPolicy,
    /// Default network stream preferences (M2: exit country, IPv6).
    #[serde(default)]
    pub network_prefs: NetworkStreamPrefs,
    /// Bridge/pluggable transport settings (M3: lyrebird obfs4/meek_lite/webtunnel).
    #[serde(default)]
    pub bridges: BridgeSettings,
    /// Upstream/outbound proxy for Tor channel connections (F-18/F-19).
    /// Runtime-only; not serialized as part of listener config snapshots.
    #[serde(default, skip)]
    pub outbound_proxy: OutboundProxySettings,
}

impl Default for ListenerConfig {
    fn default() -> Self {
        Self {
            socks_port: crate::DEFAULT_SOCKS_PORT,
            http_port: crate::DEFAULT_HTTP_PORT,
            dns_port: crate::DEFAULT_DNS_PORT,
            bind_all_interfaces: false,
            stream_isolation: StreamIsolationPolicy::default(),
            network_prefs: NetworkStreamPrefs::default(),
            bridges: BridgeSettings::default(),
            outbound_proxy: OutboundProxySettings::default(),
        }
    }
}

impl ListenerConfig {
    /// True when tobro must run its custom proxy path (isolation frontend or
    /// non-default network StreamPrefs) instead of `arti::run_proxy`.
    pub fn needs_custom_proxy(&self) -> bool {
        self.stream_isolation.needs_frontend() || self.network_prefs.is_active()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_stream_prefs_active_only_for_non_default() {
        assert!(!NetworkStreamPrefs::default().is_active());
        let prefs = NetworkStreamPrefs {
            exit_country: Some("us".to_owned()),
            ..Default::default()
        };
        assert!(prefs.is_active());
        let prefs = NetworkStreamPrefs {
            ip_version: IpVersionPref::Ipv6Only,
            ..Default::default()
        };
        assert!(prefs.is_active());
        let prefs = NetworkStreamPrefs {
            exit_country: Some("   ".to_owned()),
            ..Default::default()
        };
        assert!(!prefs.is_active());
    }

    #[test]
    fn listener_needs_custom_proxy_for_network_or_isolation() {
        let mut cfg = ListenerConfig::default();
        assert!(!cfg.needs_custom_proxy());
        cfg.stream_isolation.isolate_destination = true;
        assert!(cfg.needs_custom_proxy());
        let mut cfg = ListenerConfig::default();
        cfg.network_prefs.ip_version = IpVersionPref::Ipv6Preferred;
        assert!(cfg.needs_custom_proxy());
        let mut cfg = ListenerConfig::default();
        cfg.network_prefs.exit_country = Some("de".to_owned());
        assert!(cfg.needs_custom_proxy());
    }

    #[test]
    fn ip_version_pref_serde_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        for (s, v) in [
            ("\"ipv4_preferred\"", IpVersionPref::Ipv4Preferred),
            ("\"ipv6_preferred\"", IpVersionPref::Ipv6Preferred),
            ("\"ipv4_only\"", IpVersionPref::Ipv4Only),
            ("\"ipv6_only\"", IpVersionPref::Ipv6Only),
        ] {
            let parsed: IpVersionPref = serde_json::from_str(s)?;
            assert_eq!(parsed, v);
            assert_eq!(serde_json::to_string(&v)?, s);
        }
        Ok(())
    }
}

impl ListenerConfig {
    /// Effective HTTP port (follows SOCKS when unset/combined).
    pub fn effective_http_port(&self) -> u16 {
        if self.http_port == 0 {
            self.socks_port
        } else {
            self.http_port
        }
    }
}

/// High-level adapter status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AdapterStatus {
    /// Not started.
    Stopped,
    /// Bootstrapping in progress.
    Bootstrapping {
        /// Best-effort percentage.
        percent: u8,
        /// Detail message.
        detail: String,
    },
    /// Bootstrapped and local listeners are serving.
    Ready {
        /// Active listener configuration.
        listeners: ListenerConfig,
    },
    /// Failed.
    Failed {
        /// User-safe message.
        message: String,
    },
}

/// Events emitted by the adapter.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum AdapterEvent {
    /// Bootstrap progress update.
    Bootstrap(BootstrapEvent),
    /// Status changed.
    Status(AdapterStatus),
}

/// Control handle for observing a prepared/running service.
#[derive(Debug, Clone)]
pub struct ServiceControl {
    status_tx: watch::Sender<AdapterStatus>,
    events_tx: broadcast::Sender<AdapterEvent>,
    listeners: ListenerConfig,
}

impl ServiceControl {
    /// Current status snapshot.
    pub fn status(&self) -> AdapterStatus {
        self.status_tx.borrow().clone()
    }

    /// Subscribe to events.
    pub fn subscribe(&self) -> broadcast::Receiver<AdapterEvent> {
        self.events_tx.subscribe()
    }

    /// Active listener configuration.
    pub fn listeners(&self) -> &ListenerConfig {
        &self.listeners
    }

    fn set_status(&self, status: AdapterStatus) {
        let _ = self.status_tx.send(status.clone());
        let _ = self.events_tx.send(AdapterEvent::Status(status));
    }
}

/// Prepared service: bootstrap is complete and the serving future is ready to run.
///
/// The serving future is `!Send` because `arti::run_proxy` is not `Send` in Arti 2.8.
pub struct PreparedService {
    /// Observation/control handle.
    pub control: ServiceControl,
    state_dir: PathBuf,
    cache_dir: PathBuf,
    listeners: ListenerConfig,
}

impl std::fmt::Debug for PreparedService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedService")
            .field("listeners", &self.listeners)
            .finish_non_exhaustive()
    }
}

impl PreparedService {
    /// Run the proxy until `shutdown` resolves or the proxy exits/fails.
    ///
    /// This future is `!Send`; run it with `tokio::task::spawn_local`, a current-thread
    /// runtime, or a dedicated thread.
    pub async fn serve(
        self,
        mut shutdown: tokio::sync::oneshot::Receiver<()>,
    ) -> anyhow::Result<()> {
        let control = self.control.clone();
        let serve = crate::serve_with_bridges(
            &self.state_dir,
            &self.cache_dir,
            self.listeners.socks_port,
            self.listeners.dns_port,
            self.listeners.bind_all_interfaces,
            self.listeners.stream_isolation,
            self.listeners.network_prefs.clone(),
            &self.listeners.bridges,
            &self.listeners.outbound_proxy,
        );
        tokio::pin!(serve);

        let result = tokio::select! {
            biased;
            _ = &mut shutdown => {
                control.set_status(AdapterStatus::Stopped);
                Ok(())
            }
            result = &mut serve => {
                match &result {
                    Ok(()) => control.set_status(AdapterStatus::Stopped),
                    Err(err) => control.set_status(AdapterStatus::Failed {
                        message: format!("{err:#}"),
                    }),
                }
                result
            }
        };
        result
    }
}

/// Bootstrap Tor and prepare local listeners.
///
/// `state_dir`/`cache_dir` are shared across bootstrap and serving phases; the
/// observer is dropped before serving to release the state-dir lock.
///
/// Returns once bootstrap is complete. Call [`PreparedService::serve`] to run the
/// proxy (a `!Send` future) until shutdown.
pub async fn bootstrap_and_prepare(
    state_dir: PathBuf,
    cache_dir: PathBuf,
    listeners: ListenerConfig,
) -> anyhow::Result<PreparedService> {
    let (status_tx, _status_rx) = watch::channel(AdapterStatus::Stopped);
    let (events_tx, _events_rx) = broadcast::channel(64);
    let control = ServiceControl {
        status_tx,
        events_tx,
        listeners: listeners.clone(),
    };

    control.set_status(AdapterStatus::Bootstrapping {
        percent: 0,
        detail: "starting".to_owned(),
    });

    let observer = Tor::create_with_settings(
        &state_dir,
        &cache_dir,
        &listeners.bridges,
        &listeners.outbound_proxy,
    )
    .await
    .context("could not create the Arti client")?;

    let events_for_bootstrap = control.events_tx.clone();
    let status_for_bootstrap = control.status_tx.clone();
    let events_for_status = control.events_tx.clone();
    observer
        .bootstrap(move |event| {
            let status = AdapterStatus::Bootstrapping {
                percent: event.percent,
                detail: event.detail.clone(),
            };
            let _ = status_for_bootstrap.send(status.clone());
            let _ = events_for_bootstrap.send(AdapterEvent::Bootstrap(event));
            let _ = events_for_status.send(AdapterEvent::Status(status));
        })
        .await
        .context("Arti bootstrap failed")?;

    // Release the exclusive state-dir lock before starting the serving client.
    drop(observer);

    control.set_status(AdapterStatus::Ready {
        listeners: listeners.clone(),
    });

    Ok(PreparedService {
        control,
        state_dir,
        cache_dir,
        listeners,
    })
}

/// Convenience: create status/event channels for an externally managed service.
pub fn channels() -> (
    watch::Sender<AdapterStatus>,
    broadcast::Sender<AdapterEvent>,
) {
    let (status_tx, _status_rx) = watch::channel(AdapterStatus::Stopped);
    let (events_tx, _events_rx) = broadcast::channel(64);
    (status_tx, events_tx)
}
