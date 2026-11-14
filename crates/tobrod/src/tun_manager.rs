//! Daemon-side wiring for `tobro-helper`, the privileged TUN helper
//! (M7, plan §4.7).
//!
//! # What this module does
//!
//! - Builds a validated [`TunnelPlan`] from the daemon's `[tun]` config:
//!   tunnel device, default routes into the device, DNS interception
//!   addresses, kill-switch policy, and split-tunnel bypass routes
//!   (CIDR rules directly; domain rules resolved to IP prefixes first).
//! - Owns the single lock-step connection to the helper: connect + handshake
//!   on demand, apply, converge on config changes, periodic heartbeat,
//!   teardown on disconnect/shutdown.
//! - Reports status for the `tun.status` IPC method (phase, helper info,
//!   helper binary location/hash check).
//!
//! # What it deliberately does not do (yet)
//!
//! - The TUN routing engine (`tun2proxy`: TCP forwarding, DNS interception,
//!   UDP policy) is a separate M7 task. Until it lands, `tun.enabled` is
//!   rejected by config validation, so [`TunManager::apply`] can only be
//!   driven in tests (against the mock helper). The wiring and semantics are
//!   complete; flipping the activation gate is a one-line config change once
//!   the engine exists.
//! - Helper installation and privilege prompts are the installer task; the
//!   manager only talks to an already-running helper endpoint.
//! - Fail-closed kill-switch enforcement for a *dead helper* is the helper's
//!   own exit path (idle window/shutdown teardown); a dead daemon is covered
//!   by the same helper-side cleanup. The manager's job is to notice the
//!   loss (heartbeat) and record it.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use serde_json::json;
use tobro_config::{KillSwitchPolicy, SplitDestination, TunConfig};
use tobro_tun::{
    DnsConfig, HelperError, HelperInfo, KillSwitchMode, Prefix, RouteSpec, TunDevice,
    TunHelperClient, TunnelPlan,
};
use tokio::sync::Mutex;

use crate::lifecycle::State;
use crate::supervisor::SupervisorEvent;

// --- Tunnel addressing -----------------------------------------------------

/// IPv4 address assigned to the TUN device (`10.111.222.252/30`, RFC 1918).
/// The protocol requires host bits zeroed on device addresses, so the
/// network address doubles as the interface address (the same form the
/// `tobro-tun` protocol tests use).
pub const TUNNEL_PREFIX_V4: &str = "10.111.222.252/30";
/// IPv6 address assigned to the TUN device (randomly-chosen ULA).
pub const TUNNEL_PREFIX_V6: &str = "fd6b:626f:6272:6f::/64";
/// System resolver target for IPv4 while the tunnel is up: the address the
/// routing engine will answer DNS on (interception; forwarded to the
/// daemon's local DNS port). Never a loopback address (the helper rejects
/// pointing the system resolver at loopback).
pub const TUNNEL_DNS_V4: Ipv4Addr = Ipv4Addr::new(10, 111, 222, 254);
/// IPv6 counterpart of [`TUNNEL_DNS_V4`].
pub const TUNNEL_DNS_V6: Ipv6Addr = Ipv6Addr::new(0xfd6b, 0x626f, 0x6272, 0x6f, 0, 0, 0, 2);

/// How often the heartbeat pings the helper while a plan is applied.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);

// --- Status types ----------------------------------------------------------

/// Manager phase, as surfaced by `tun.status`.
#[derive(Debug, Clone, PartialEq)]
pub enum TunPhase {
    /// `tun.enabled = false` (or nothing applied yet): nothing privileged
    /// has been requested. This is the only reachable phase in production
    /// builds until the routing engine lands.
    Disabled,
    /// TUN was requested but no plan is currently applied (e.g. after a
    /// teardown).
    Idle,
    /// A plan is applied and being heartbeated.
    Active(Box<ActiveTun>),
    /// The last privileged operation failed; user-safe detail attached.
    Error(String),
}

impl TunPhase {
    /// Stable machine-readable name for IPC consumers.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Idle => "idle",
            Self::Active(_) => "active",
            Self::Error(_) => "error",
        }
    }
}

/// Details of the currently applied plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveTun {
    /// Interface name reported by the helper.
    pub interface: String,
    /// Helper generation counter after the apply.
    pub generation: u64,
    /// Kill-switch mode of the applied plan.
    pub kill_switch: KillSwitchMode,
    /// How many exclude-rule destinations became bypass routes.
    pub bypass_routes: usize,
    /// Domain exclude rules skipped because resolution failed (user's own
    /// rule names; daemon logs intentionally carry only counts).
    pub skipped_domains: Vec<String>,
}

/// Located `tobro-helper` binary (informational; the installer owns install).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelperBinaryStatus {
    /// Path the binary was found at.
    pub path: String,
    /// When `tun.helper_sha256_hex` is configured: whether the located
    /// binary matched the pin. `None` when no pin is configured.
    pub sha256_matches: Option<bool>,
}

/// Snapshot of the TUN wiring state for IPC consumers.
#[derive(Debug, Clone, PartialEq)]
pub struct TunStatus {
    /// Helper IPC endpoint the manager uses.
    pub endpoint: String,
    /// Current phase.
    pub phase: TunPhase,
    /// Last helper probe result (`None` = not probed yet).
    pub helper_reachable: Option<bool>,
    /// Helper handshake info from the last successful probe/apply.
    pub helper: Option<HelperInfo>,
    /// Located helper binary (when a `[tun]` config has been observed).
    pub helper_binary: Option<HelperBinaryStatus>,
    /// False until the TUN routing engine lands (M7). While false, config
    /// validation rejects `tun.enabled` and nothing privileged runs.
    pub engine_available: bool,
}

impl TunStatus {
    /// JSON form for the `tun.status` IPC method.
    pub fn to_json(&self) -> serde_json::Value {
        json!({
            "endpoint": self.endpoint,
            "state": self.phase.name(),
            "engine_available": self.engine_available,
            "helper_reachable": self.helper_reachable,
            "helper": self.helper.as_ref().map(|h| json!({
                "protocol_version": h.protocol_version,
                "helper_version": h.helper_version,
            })),
            "helper_binary": self.helper_binary.as_ref().map(|b| json!({
                "path": b.path,
                "sha256_matches": b.sha256_matches,
            })),
            "active": match &self.phase {
                TunPhase::Active(active) => Some(json!({
                    "interface": active.interface,
                    "generation": active.generation,
                    "kill_switch": active.kill_switch,
                    "bypass_routes": active.bypass_routes,
                    "skipped_domains": active.skipped_domains,
                })),
                _ => None,
            },
            "error": match &self.phase {
                TunPhase::Error(message) => Some(message.clone()),
                _ => None,
            },
            "note": if self.engine_available {
                None
            } else {
                Some(
                    "the TUN routing engine is not implemented in this build; tun.enabled is rejected by config validation until it lands (planned in milestone M7)",
                )
            },
        })
    }
}

// --- Gateway discovery -----------------------------------------------------

/// Default gateways discovered before the tunnel is applied. Split-tunnel
/// bypass routes must point at these (a more-specific route via the physical
/// gateway wins over the TUN default route).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Gateways {
    /// Default IPv4 gateway, if one was discovered.
    pub v4: Option<IpAddr>,
    /// Default IPv6 gateway, if one was discovered.
    pub v6: Option<IpAddr>,
}

impl Gateways {
    /// The gateway matching `family`, for bypass routes.
    fn for_family(&self, family: IpAddr) -> Option<IpAddr> {
        match family {
            IpAddr::V4(_) => self.v4,
            IpAddr::V6(_) => self.v6,
        }
    }
}

/// Discover the pre-tunnel default gateways.
///
/// Linux reads `/proc/net/{route,ipv6_route}` (unprivileged, no FFI, no
/// unsafe). Other platforms report nothing yet: with exclude rules
/// configured, plan building fails with a clear message instead of silently
/// tunneling a destination the user asked to bypass. Gateway discovery for
/// macOS/Windows lands with their split-tunnel engine work.
pub(crate) async fn discover_gateways() -> Gateways {
    #[cfg(target_os = "linux")]
    {
        // File reads are quick; keep them off the async core with a blocking
        // task anyway (spawn_blocking is unavailable without a handle here —
        // these are tiny files, read them inline).
        let v4 = default_gateway_v4_proc();
        let v6 = default_gateway_v6_proc();
        Gateways { v4, v6 }
    }
    #[cfg(not(target_os = "linux"))]
    {
        Gateways { v4: None, v6: None }
    }
}

/// Parse the first default IPv4 route with a gateway from `/proc/net/route`.
#[cfg(target_os = "linux")]
fn default_gateway_v4_proc() -> Option<IpAddr> {
    let text = std::fs::read_to_string("/proc/net/route").ok()?;
    for line in text.lines().skip(1) {
        let cols: Vec<&str> = line.split('\t').collect();
        if cols.len() < 3 {
            continue;
        }
        // Columns: Iface, Destination, Gateway, ... (hex, little-endian u32).
        if cols[1] != "00000000" || cols[2] == "00000000" {
            continue;
        }
        let Ok(raw) = u32::from_str_radix(cols[2], 16) else {
            continue;
        };
        return Some(IpAddr::V4(Ipv4Addr::from(raw.to_le_bytes())));
    }
    None
}

/// Parse the first default IPv6 route with a gateway from
/// `/proc/net/ipv6_route`.
#[cfg(target_os = "linux")]
fn default_gateway_v6_proc() -> Option<IpAddr> {
    let text = std::fs::read_to_string("/proc/net/ipv6_route").ok()?;
    for line in text.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 5 {
            continue;
        }
        // Columns: Dest, DstLen, Source, SrcLen, NextHop, Metric, ...
        // (hex; addresses are in byte order, unlike /proc/net/route).
        let is_default = cols[0] == "00000000000000000000000000000000" && cols[1] == "00";
        let has_gateway = !cols[4].is_empty() && cols[4] != "00000000000000000000000000000000";
        if !is_default || !has_gateway {
            continue;
        }
        let bytes: [u8; 16] = (0..16)
            .filter_map(|i| u8::from_str_radix(&cols[4][i * 2..i * 2 + 2], 16).ok())
            .collect::<Vec<u8>>()
            .try_into()
            .ok()?;
        return Some(IpAddr::V6(Ipv6Addr::from(bytes)));
    }
    None
}

// --- Plan building ---------------------------------------------------------

/// Result notes from plan building (surfaced through status).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct PlanNotes {
    /// Domain rules skipped because resolution failed.
    pub skipped_domains: Vec<String>,
}

/// Resolve a domain exclude rule to the IPs its bypass routes should cover.
pub(crate) type DomainResolver<'a> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<IpAddr>, String>> + Send + 'a>>;

/// Production resolver: the system resolver (before the tunnel is applied,
/// DNS still goes direct, so domain rules resolve to their direct IPs).
async fn resolve_domain_default(name: &str) -> Result<Vec<IpAddr>, String> {
    let mut ips = Vec::new();
    match tokio::net::lookup_host((name.to_owned(), 443u16)).await {
        Ok(addrs) => {
            for addr in addrs {
                let ip = addr.ip();
                if !ips.contains(&ip) {
                    ips.push(ip);
                }
            }
        }
        Err(error) => return Err(error.to_string()),
    }
    if ips.is_empty() {
        return Err("the resolver returned no addresses".to_owned());
    }
    Ok(ips)
}

/// Build the [`TunnelPlan`] for `config`, with injectable gateway knowledge
/// and domain resolution (tests).
///
/// Fails when a CIDR exclude rule has no matching-family gateway: silently
/// tunneling a destination the user asked to bypass is the worse failure.
/// Unresolvable *domain* rules are skipped with a note instead — a transient
/// DNS failure should not block connecting (the rule simply tunnels via Tor,
/// an availability loss, never a privacy leak).
pub(crate) async fn build_plan_with(
    config: &TunConfig,
    gateways: &Gateways,
    resolve_domain: &(dyn Fn(&str) -> DomainResolver<'_> + Send + Sync),
) -> Result<(TunnelPlan, PlanNotes), String> {
    let v4_prefix =
        Prefix::parse(TUNNEL_PREFIX_V4).map_err(|error| error.to_string())?;
    let v6_prefix =
        Prefix::parse(TUNNEL_PREFIX_V6).map_err(|error| error.to_string())?;
    let device = TunDevice {
        name: String::new(), // helper's platform default
        addresses: vec![v4_prefix, v6_prefix],
        mtu: config.mtu,
    };
    // Default routes for both families point into the device. No explicit
    // metric: the helper's routes must win over the physical defaults for
    // the tunnel to capture traffic, and the kill-switch blackhole sits one
    // metric above whatever the plan uses.
    let routes = vec![
        RouteSpec {
            destination: Prefix {
                addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                prefix_len: 0,
            },
            gateway: None,
            metric: None,
        },
        RouteSpec {
            destination: Prefix {
                addr: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                prefix_len: 0,
            },
            gateway: None,
            metric: None,
        },
    ];

    let mut bypass_routes = Vec::new();
    let mut skipped_domains = Vec::new();
    for (index, destination) in config
        .parse_exclude_rules()
        .map_err(|e| e.to_string())?
        .iter()
        .enumerate()
    {
        match destination {
            SplitDestination::Cidr(cidr) => {
                let gateway = gateways.for_family(cidr.addr).ok_or_else(|| {
                    format!(
                        "tun.exclude_rules[{index}]: cannot route {} directly (split tunnel): \
                         no default gateway for this address family was discovered on this \
                         platform; gateway discovery is implemented on Linux in this build",
                        cidr.text
                    )
                })?;
                bypass_routes.push(RouteSpec {
                    destination: Prefix {
                        addr: cidr.addr,
                        prefix_len: cidr.prefix_len,
                    },
                    gateway: Some(gateway),
                    metric: None,
                });
            }
            SplitDestination::Domain(domain) => match resolve_domain(&domain.name).await {
                Ok(ips) => {
                    for ip in ips {
                        bypass_routes.push(RouteSpec {
                            destination: Prefix {
                                addr: ip,
                                prefix_len: match ip {
                                    IpAddr::V4(_) => 32,
                                    IpAddr::V6(_) => 128,
                                },
                            },
                            gateway: gateways.for_family(ip),
                            metric: None,
                        });
                    }
                }
                Err(_reason) => {
                    // User-safe detail for status; logs carry the index only.
                    skipped_domains.push(domain.name.clone());
                    tracing::warn!(
                        rule = index,
                        "split-tunnel domain rule could not be resolved; its traffic \
                         goes through the tunnel until the next convergence"
                    );
                }
            },
        }
    }

    let plan = TunnelPlan {
        device,
        routes,
        bypass_routes,
        dns: DnsConfig {
            servers: vec![IpAddr::V4(TUNNEL_DNS_V4), IpAddr::V6(TUNNEL_DNS_V6)],
        },
        kill_switch: match config.kill_switch {
            KillSwitchPolicy::Restore => KillSwitchMode::Restore,
            KillSwitchPolicy::Block => KillSwitchMode::Block,
        },
    };
    plan.validate().map_err(|e| e.to_string())?;
    Ok((plan, PlanNotes { skipped_domains }))
}

/// Build the plan with production gateway discovery and resolution.
pub(crate) async fn build_plan(
    config: &TunConfig,
) -> Result<(TunnelPlan, PlanNotes), String> {
    let gateways = discover_gateways().await;
    build_plan_with(config, &gateways, &|name| {
        Box::pin(async move { resolve_domain_default(name).await })
    })
    .await
}

// --- Manager ---------------------------------------------------------------

/// Shared wiring state.
#[derive(Debug)]
struct Inner {
    endpoint: PathBuf,
    state: RwLock<TunPhase>,
    probe: RwLock<Probe>,
    config: RwLock<Option<TunConfig>>,
    client: Mutex<Option<TunHelperClient>>,
    heartbeat_running: AtomicBool,
}

/// Last helper probe outcome.
#[derive(Debug, Clone, Default)]
struct Probe {
    reachable: Option<bool>,
    info: Option<HelperInfo>,
}

/// Daemon-side manager for the privileged TUN helper.
///
/// Cloneable handle; all state is shared. See the module docs for scope.
#[derive(Debug, Clone)]
pub struct TunManager {
    inner: Arc<Inner>,
}

impl TunManager {
    /// Manager for `endpoint` (the helper's IPC socket/pipe).
    pub fn new(endpoint: PathBuf) -> Self {
        Self {
            inner: Arc::new(Inner {
                endpoint,
                state: RwLock::new(TunPhase::Disabled),
                probe: RwLock::new(Probe::default()),
                config: RwLock::new(None),
                client: Mutex::new(None),
                heartbeat_running: AtomicBool::new(false),
            }),
        }
    }

    /// Manager for the platform-default helper endpoint.
    pub fn with_default_endpoint() -> Self {
        Self::new(PathBuf::from(tobro_tun::default_endpoint()))
    }

    fn phase(&self) -> TunPhase {
        self.inner
            .state
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn set_phase(&self, phase: TunPhase) {
        *self
            .inner
            .state
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = phase;
    }

    fn set_probe(&self, probe: Probe) {
        *self
            .inner
            .probe
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = probe;
    }

    fn store_config(&self, config: TunConfig) {
        *self
            .inner
            .config
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(config);
    }

    fn stored_config(&self) -> Option<TunConfig> {
        self.inner
            .config
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Current status snapshot (no I/O except the helper-binary lookup when
    /// a config has been observed).
    pub fn status(&self) -> TunStatus {
        let phase = self.phase();
        let probe = self
            .inner
            .probe
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let config = self.stored_config();
        TunStatus {
            endpoint: self.inner.endpoint.display().to_string(),
            phase,
            helper_reachable: probe.reachable,
            helper: probe.info,
            helper_binary: helper_binary_status(config.as_ref()),
            engine_available: false,
        }
    }

    /// Best-effort helper availability probe (bounded; a missing helper is
    /// normal and not an error while TUN mode is disabled).
    pub async fn probe(&self) {
        if matches!(self.phase(), TunPhase::Active(_)) {
            return;
        }
        match connect_and_handshake(&self.inner.endpoint).await {
            Ok((client, info)) => {
                self.set_probe(Probe {
                    reachable: Some(true),
                    info: Some(info),
                });
                drop(client);
            }
            Err(_) => {
                self.set_probe(Probe {
                    reachable: Some(false),
                    info: None,
                });
            }
        }
    }

    /// Converge the system to `config`: apply a plan when TUN is enabled,
    /// tear down when it is not. Idempotent.
    ///
    /// # Errors
    ///
    /// Plan building or the helper rejected the request. The previous plan
    /// (if any) stays applied — the helper keeps system state converged to
    /// what it last accepted, which is never half of a new plan.
    /// Converge the TUN wiring to `config`. Idempotent: apply a plan when
    /// TUN is enabled, tear down when it is not.
    ///
    /// # Errors
    ///
    /// Plan building or the helper rejected the request. The previous plan
    /// (if any) stays applied — the helper keeps system state converged to
    /// what it last accepted, which is never half of a new plan.
    pub async fn apply(&self, config: &TunConfig) -> Result<(), String> {
        self.store_config(config.clone());
        if !config.is_active() {
            self.teardown("tun disabled in config").await;
            return Ok(());
        }
        let (plan, notes) = match build_plan(config).await {
            Ok(plan) => plan,
            Err(message) => {
                self.set_phase(TunPhase::Error(format!("TUN plan failed to build: {message}")));
                return Err(message);
            }
        };
        let bypass_count = plan.bypass_routes.len();
        let applied = match self
            .run("apply the TUN plan", |client| {
                // Clone per attempt: a retried call must see the same plan,
                // and the boxed future owns its copy.
                let plan = plan.clone();
                Box::pin(async move { client.apply_plan(&plan).await })
            })
            .await
        {
            Ok(applied) => applied,
            Err(error) => {
                let message = error.to_string();
                self.set_phase(TunPhase::Error(format!("TUN apply failed: {message}")));
                return Err(message);
            }
        };
        self.set_phase(TunPhase::Active(Box::new(ActiveTun {
            interface: applied.interface,
            generation: applied.generation,
            kill_switch: plan.kill_switch,
            bypass_routes: bypass_count,
            skipped_domains: notes.skipped_domains,
        })));
        self.ensure_heartbeat();
        Ok(())
    }

    /// Best-effort teardown of the applied plan (device, routes, DNS, kill
    /// switch). Never fails loudly: if the helper is unreachable, its own
    /// exit path (idle window, shutdown signal) tears the system down.
    pub async fn teardown(&self, reason: &str) {
        if matches!(self.phase(), TunPhase::Disabled) {
            return;
        }
        self.set_phase(TunPhase::Idle);
        let result = self
            .run("tear down the TUN plan", |client| {
                Box::pin(async move { client.teardown().await })
            })
            .await;
        // Drop the connection either way; the helper cleans up its end.
        *self.inner.client.lock().await = None;
        match result {
            Ok(_generation) => tracing::info!(reason, "TUN plan torn down"),
            Err(error) => tracing::warn!(
                reason,
                %error,
                "TUN teardown did not complete; the helper tears down on its own exit"
            ),
        }
    }

    /// Re-apply the stored config when TUN is enabled but no plan is active
    /// (after a helper restart or a supervisor auto-retry).
    async fn reapply(&self) {
        let Some(config) = self.stored_config() else {
            return;
        };
        if !config.is_active() || matches!(self.phase(), TunPhase::Active(_) | TunPhase::Disabled) {
            return;
        }
        if let Err(error) = self.apply(&config).await {
            tracing::warn!(%error, "TUN re-apply failed");
        }
    }

    /// React to a supervisor failure while TUN is active: with the restore
    /// policy, tear the tunnel down (normal networking returns); with the
    /// block policy, leave the plan in place — the TUN device with nothing
    /// reading it *is* the fail-closed kill switch.
    async fn on_tor_failed(&self) {
        let Some(config) = self.stored_config() else {
            return;
        };
        if !config.is_active() || !matches!(self.phase(), TunPhase::Active(_)) {
            return;
        }
        match config.kill_switch {
            KillSwitchPolicy::Restore => self.teardown("tor failed (restore policy)").await,
            KillSwitchPolicy::Block => tracing::warn!(
                "tor failed with the fail-closed kill switch policy: the TUN plan stays \
                 applied and traffic is blocked until the tunnel is restored or TUN mode \
                 is disabled"
            ),
        }
    }

    /// Keep a heartbeat running while a plan is applied.
    fn ensure_heartbeat(&self) {
        if self.inner.heartbeat_running.swap(true, Ordering::SeqCst) {
            return;
        }
        let manager = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(HEARTBEAT_INTERVAL).await;
                if !matches!(manager.phase(), TunPhase::Active(_)) {
                    break;
                }
                if manager.heartbeat_ping().await.is_err() {
                    break;
                }
            }
            manager.inner.heartbeat_running.store(false, Ordering::SeqCst);
        });
    }

    /// One heartbeat: confirm the helper still has the plan applied; on a
    /// connection failure record the loss; if the helper lost the plan
    /// (restart), converge by re-applying the stored config.
    async fn heartbeat_ping(&self) -> Result<(), ()> {
        let result = self
            .run("check the TUN helper state", |client| {
                Box::pin(async move { client.status().await })
            })
            .await;
        match result {
            Ok(status) if status.active => Ok(()),
            Ok(_) => {
                tracing::warn!("TUN helper no longer has the plan applied; re-applying");
                self.set_phase(TunPhase::Idle);
                self.reapply().await;
                if matches!(self.phase(), TunPhase::Active(_)) {
                    Ok(())
                } else {
                    Err(())
                }
            }
            Err(error) => {
                self.set_phase(TunPhase::Error(format!(
                    "TUN helper became unreachable: {error}"
                )));
                Err(())
            }
        }
    }

    /// Run one helper operation over the shared connection, reconnecting
    /// (once) after a transport-level failure of an existing connection.
    async fn run<T, F>(&self, describe: &'static str, mut op: F) -> Result<T, HelperError>
    where
        F: for<'a> FnMut(&'a mut TunHelperClient) -> HelperCall<'a, T>,
    {
        let mut guard = self.inner.client.lock().await;
        let mut retried = false;
        loop {
            let mut client = match guard.take() {
                Some(client) => client,
                None => {
                    let (client, info) = connect_and_handshake(&self.inner.endpoint)
                        .await
                        .map_err(|error| {
                            tracing::info!(%error, endpoint = %self.inner.endpoint.display(), describe, "could not connect to the TUN helper");
                            error
                        })?;
                    self.set_probe(Probe {
                        reachable: Some(true),
                        info: Some(info),
                    });
                    client
                }
            };
            match op(&mut client).await {
                Ok(value) => {
                    *guard = Some(client);
                    return Ok(value);
                }
                Err(error) => {
                    let transport = matches!(
                        error,
                        HelperError::Io(_) | HelperError::Closed | HelperError::Timeout { .. }
                    );
                    if transport && !retried {
                        retried = true;
                        continue;
                    }
                    *guard = (!transport).then_some(client);
                    return Err(error);
                }
            }
        }
    }
}

/// A boxed helper call (`run` keeps lifetimes simple).
type HelperCall<'a, T> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, HelperError>> + Send + 'a>>;

/// Connect to the helper and complete the handshake.
///
/// Returns the client (left unassociated) plus the handshake info.
async fn connect_and_handshake(
    endpoint: &std::path::Path,
) -> Result<(TunHelperClient, HelperInfo), HelperError> {
    let mut client =
        TunHelperClient::connect_with_retry(endpoint, 3, Duration::from_millis(250)).await?;
    let info = client.handshake().await?;
    Ok((client, info))
}

// --- Helper binary lookup (status only) ------------------------------------

/// Locate the `tobro-helper` binary for status reporting and verify an
/// optional SHA-256 pin. The daemon never spawns the helper; installation
/// and privilege prompts are the installer's job.
fn helper_binary_status(config: Option<&TunConfig>) -> Option<HelperBinaryStatus> {
    let config = config?;
    let mut search_dirs = Vec::new();
    if let Some(dir) = config.helper_dir.as_deref() {
        search_dirs.push(PathBuf::from(dir));
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        search_dirs.push(dir.to_path_buf());
        search_dirs.push(dir.join("binaries"));
        search_dirs.push(dir.join("../Resources"));
        search_dirs.push(dir.join("../Resources/binaries"));
    }
    let located = crate::pt_supervisor::locate(&crate::pt_supervisor::LocateOptions {
        explicit_path: config.helper_path.as_ref().map(PathBuf::from),
        search_dirs,
        names: vec![
            std::ffi::OsString::from("tobro-helper"),
            std::ffi::OsString::from("tobro-helper.exe"),
        ],
    })
    .ok()?;
    let sha256_matches = config.helper_sha256_hex.as_ref().map(|expected| {
        sha256_file_hex(&located.path)
            .map(|actual| actual == *expected)
            .unwrap_or(false)
    });
    Some(HelperBinaryStatus {
        path: located.path.display().to_string(),
        sha256_matches,
    })
}

/// SHA-256 of a file as lowercase hex; `None` when unreadable.
fn sha256_file_hex(path: &std::path::Path) -> Option<String> {
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(path).ok()?;
    let digest = Sha256::digest(&bytes);
    Some(hex::encode(digest))
}

// --- Supervisor link -------------------------------------------------------

/// React to supervisor events while TUN mode is active:
///
/// - **Ready** — re-apply the stored config if the plan went missing (a
///   supervisor auto-retry reconnects Tor without going through
///   `SupervisorControl::connect`, which is where plans are applied).
/// - **Failed** — kill-switch policy reaction (see
///   [`TunManager::on_tor_failed`]).
/// - **Stopped** — tear down (also the manual disconnect path; idempotent).
pub fn spawn_supervisor_link(
    manager: TunManager,
    mut events: tokio::sync::broadcast::Receiver<SupervisorEvent>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match events.recv().await {
                Ok(SupervisorEvent::StateChanged(snapshot)) => match snapshot.state {
                    State::Ready => manager.reapply().await,
                    State::Stopped => manager.teardown("tor stopped").await,
                    State::Failed { .. } => manager.on_tor_failed().await,
                    _ => {}
                },
                Ok(_) => {}
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
            }
        }
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use tobro_config::{SplitRule, UdpPolicy};
    use tobro_tun::MockHelper;

    fn enabled_config() -> TunConfig {
        TunConfig {
            enabled: true,
            ..TunConfig::default()
        }
    }

    fn disabled_config() -> TunConfig {
        TunConfig::default()
    }

    fn no_resolver() -> impl Fn(&str) -> DomainResolver<'_> {
        |_| {
            Box::pin(async { Err("resolver disabled in test".to_owned()) }) as DomainResolver<'_>
        }
    }

    fn static_resolver(addresses: Vec<IpAddr>) -> impl Fn(&str) -> DomainResolver<'_> {
        move |_| {
            let addresses = addresses.clone();
            Box::pin(async move { Ok(addresses) })
        }
    }

    #[tokio::test]
    async fn plan_builds_the_default_tunnel_state() {
        let mut config = enabled_config();
        config.udp_policy = UdpPolicy::BlockAll;
        let (plan, notes) = build_plan_with(&config, &Gateways::default(), &no_resolver())
            .await
            .expect("default plan must build");

        assert_eq!(plan.device.name, "");
        assert_eq!(plan.device.mtu, tobro_config::DEFAULT_TUN_MTU);
        assert_eq!(plan.device.addresses.len(), 2);
        // Defaults for both families point into the device.
        assert_eq!(plan.routes.len(), 2);
        assert!(plan.routes.iter().all(|route| route.gateway.is_none()));
        assert!(plan
            .routes
            .iter()
            .any(|route| route.destination.prefix_len == 0
                && matches!(route.destination.addr, IpAddr::V4(_))));
        assert!(plan
            .routes
            .iter()
            .any(|route| route.destination.prefix_len == 0
                && matches!(route.destination.addr, IpAddr::V6(_))));
        // DNS points at the engine's interception addresses.
        assert_eq!(plan.dns.servers.len(), 2);
        assert!(plan.dns.servers.contains(&IpAddr::V4(TUNNEL_DNS_V4)));
        assert!(plan.dns.servers.contains(&IpAddr::V6(TUNNEL_DNS_V6)));
        assert_eq!(plan.kill_switch, KillSwitchMode::Restore);
        assert!(plan.bypass_routes.is_empty());
        assert!(notes.skipped_domains.is_empty());
    }

    #[tokio::test]
    async fn plan_maps_the_block_kill_switch_policy() {
        let mut config = enabled_config();
        config.kill_switch = KillSwitchPolicy::Block;
        let (plan, _) = build_plan_with(&config, &Gateways::default(), &no_resolver())
            .await
            .expect("plan must build");
        assert_eq!(plan.kill_switch, KillSwitchMode::Block);
    }

    #[tokio::test]
    async fn cidr_rules_become_bypass_routes_through_the_gateway() {
        let mut config = enabled_config();
        config.exclude_rules = vec![
            SplitRule::new("192.0.2.0/24"),
            SplitRule::new("2001:db8::/32"),
        ];
        let gateways = Gateways {
            v4: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            v6: Some(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1))),
        };
        let (plan, notes) = build_plan_with(&config, &gateways, &no_resolver())
            .await
            .expect("plan must build");
        assert_eq!(plan.bypass_routes.len(), 2);
        assert!(plan.bypass_routes.iter().all(|route| {
            route.gateway.is_some() && route.gateway.unwrap().is_ipv4() == route.destination.addr.is_ipv4()
        }));
        assert!(notes.skipped_domains.is_empty());
    }

    #[tokio::test]
    async fn cidr_rules_fail_without_a_discovered_gateway() {
        let mut config = enabled_config();
        config.exclude_rules = vec![SplitRule::new("192.0.2.0/24")];
        let error = build_plan_with(&config, &Gateways::default(), &no_resolver())
            .await
            .expect_err("no gateway: must fail instead of tunneling the rule");
        assert!(error.contains("tun.exclude_rules[0]"), "{error}");
        assert!(error.contains("no default gateway"), "{error}");
    }

    #[tokio::test]
    async fn domain_rules_resolve_into_host_routes() {
        let mut config = enabled_config();
        config.exclude_rules = vec![SplitRule::new("example.com")];
        let gateways = Gateways {
            v4: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            v6: Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
        };
        let resolve = static_resolver(vec![
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        ]);
        let (plan, notes) = build_plan_with(&config, &gateways, &resolve)
            .await
            .expect("plan must build");
        assert_eq!(plan.bypass_routes.len(), 2);
        assert!(plan
            .bypass_routes
            .iter()
            .any(|route| route.destination.prefix_len == 32
                && route.destination.addr == IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))));
        assert!(plan
            .bypass_routes
            .iter()
            .any(|route| route.destination.prefix_len == 128));
        assert!(notes.skipped_domains.is_empty());
    }

    #[tokio::test]
    async fn unresolvable_domain_rules_are_skipped_with_a_note() {
        let mut config = enabled_config();
        config.exclude_rules = vec![SplitRule::new("example.com")];
        let gateways = Gateways {
            v4: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            v6: None,
        };
        let (plan, notes) = build_plan_with(&config, &gateways, &no_resolver())
            .await
            .expect("domain rules must not block the plan");
        assert!(plan.bypass_routes.is_empty());
        assert_eq!(notes.skipped_domains, vec!["example.com".to_owned()]);
    }

    #[cfg(unix)]
    async fn mock_helper() -> (tempfile::TempDir, MockHelper) {
        let dir = tempfile::tempdir().expect("tempdir");
        let helper = MockHelper::start(dir.path().join("helper.sock"))
            .await
            .expect("mock helper");
        (dir, helper)
    }

    #[cfg(unix)]
    fn manager_for(dir: &tempfile::TempDir) -> TunManager {
        TunManager::new(dir.path().join("helper.sock"))
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn manager_applies_and_tears_down_against_the_mock() {
        let (dir, helper) = mock_helper().await;
        let manager = manager_for(&dir);

        // A disabled config never touches the helper.
        manager.apply(&disabled_config()).await.expect("disabled is a no-op");
        assert_eq!(manager.status().phase, TunPhase::Disabled);
        assert_eq!(helper.state().lock().unwrap().handshakes, 0);

        // Applying an enabled config applies the plan.
        manager.apply(&enabled_config()).await.expect("apply");
        let status = manager.status();
        let TunPhase::Active(active) = &status.phase else {
            panic!("expected an active phase, got {:?}", status.phase);
        };
        assert_eq!(active.interface, "tobro0");
        assert_eq!(active.generation, 1);
        assert_eq!(active.kill_switch, KillSwitchMode::Restore);

        let mock = helper.state();
        {
            let mock = mock.lock().unwrap();
            assert_eq!(mock.applies, 1);
            assert_eq!(mock.teardowns, 0);
            let plan = mock.last_plan.as_ref().expect("plan recorded");
            assert_eq!(plan.kill_switch, KillSwitchMode::Restore);
            assert_eq!(plan.dns.servers.len(), 2);
        }
        drop(mock);

        // Teardown converges the helper back to nothing.
        manager.teardown("test").await;
        assert_eq!(manager.status().phase, TunPhase::Idle);
        assert_eq!(helper.state().lock().unwrap().teardowns, 1);
        assert!(!helper.state().lock().unwrap().active);

        helper.shutdown().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn helper_rejection_marks_the_manager_failed() {
        let (dir, helper) = mock_helper().await;
        let state = helper.state();
        helper.set_responder(Some(Arc::new(move |request| {
            if matches!(
                request,
                tobro_tun::HelperRequest::ApplyPlan { .. }
            ) {
                tobro_tun::MockReply::Respond(tobro_tun::HelperResponse::Rejected {
                    code: tobro_tun::reject_codes::DEVICE_ERROR,
                    message: "device creation failed (mock)".to_owned(),
                })
            } else {
                tobro_tun::MockReply::Default
            }
        })));
        drop(state);

        let manager = manager_for(&dir);
        let error = manager
            .apply(&enabled_config())
            .await
            .expect_err("rejected plan must fail");
        assert!(error.contains("rejected") || error.contains("device"), "{error}");
        let TunPhase::Error(message) = manager.status().phase else {
            panic!("expected an error phase");
        };
        assert!(message.contains("device creation failed"), "{message}");

        helper.shutdown().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn manager_survives_a_helper_restart_and_converges() {
        let (dir, helper) = mock_helper().await;
        let path = dir.path().join("helper.sock");
        let manager = manager_for(&dir);
        manager.apply(&enabled_config()).await.expect("apply");

        // Restart the helper: the daemon's connection dies and the new
        // helper starts with no plan applied.
        helper.shutdown().await;
        let helper = MockHelper::start(&path).await.expect("restarted mock");
        // The heartbeat path notices the helper lost the plan and converges
        // by re-applying the stored config over a fresh connection.
        let ping = manager.heartbeat_ping().await;
        assert!(ping.is_ok(), "the heartbeat must recover after a helper restart");
        let mock = helper.state();
        {
            let mock = mock.lock().unwrap();
            assert!(mock.active, "the plan must be re-applied after a helper restart");
            assert_eq!(mock.applies, 1);
        }
        drop(mock);

        helper.shutdown().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn status_reports_helper_reachability() {
        let (dir, helper) = mock_helper().await;
        let manager = manager_for(&dir);

        manager.probe().await;
        let status = manager.status();
        assert_eq!(status.helper_reachable, Some(true));
        assert_eq!(status.helper.map(|h| h.helper_version), Some("mock".to_owned()));

        helper.shutdown().await;
        manager.probe().await;
        assert_eq!(manager.status().helper_reachable, Some(false));
    }

    #[test]
    fn status_json_carries_phase_and_note() {
        let manager = TunManager::with_default_endpoint();
        let json = manager.status().to_json();
        assert_eq!(json["state"], "disabled");
        assert_eq!(json["engine_available"], false);
        assert!(json["note"].is_string());
        assert_eq!(json["helper_reachable"], serde_json::Value::Null);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn proc_route_parsing_handles_loopback_free_tables() {
        // The parsers tolerate missing files; on a normal Linux test host
        // they return something valid or nothing at all, never panic.
        let _ = default_gateway_v4_proc();
        let _ = default_gateway_v6_proc();
    }
}
