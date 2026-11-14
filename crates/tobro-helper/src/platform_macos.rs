//! macOS TUN backend — utun device + PF_ROUTE routes + SystemConfiguration
//! DNS (M7 T4b).
//!
//! Design notes:
//!
//! - The kernel names utun devices itself (`utunN`); the requested plan name
//!   is ignored and the actual name is returned to the daemon, which uses it
//!   for subsequent calls.
//! - tun2 addresses the device at creation only (`SIOCAIFADDR`); macOS
//!   cannot re-address a live utun device, so a changed address is an error
//!   asking for a teardown first. MTU *can* be changed via an ioctl and is
//!   converged idempotently.
//! - Routes go through `tobro-osapi`'s PF_ROUTE FFI (the helper never shells
//!   out, §10.5). Add is replace-on-add (`EEXIST` → delete + re-add);
//!   deletes are idempotent (`ESRCH` → success). Route metrics are ignored:
//!   BSD has no metric ordering.
//! - DNS replaces the global `State:/Network/Global/DNS` dynamic-store key
//!   after backing the previous value up as an XML property list; teardown
//!   restores it. Resolver-service-level integration is future work (M8).
//! - `KillSwitchMode::Block` installs PF rules through `tobro-osapi`'s
//!   `/dev/pf` FFI (the helper never shells out, §10.5): pass on loopback
//!   and the tunnel interface, block-drop everything outbound. The rules
//!   live in the root filter ruleset and fail closed — they keep enforcing
//!   if the helper crashes — and teardown removes them again. A ruleset
//!   holding foreign rules is never touched (the apply fails closed
//!   instead). PF is enabled through the ref-counted `DIOCSTARTREF` token
//!   interface; an apply that finds the rules already installed and PF
//!   running (e.g. after a helper crash) adopts that state without taking
//!   a second reference, so crash cycles do not leak enable references.
//! - `SCDynamicStore` is not `Send`; every SystemConfiguration call runs
//!   inside `tokio::task::spawn_blocking`. Logs carry counts only, never
//!   addresses or destinations (§10.5).

use std::net::{IpAddr, Ipv4Addr};

use async_trait::async_trait;
use tobro_tun::{DnsConfig, KillSwitchMode, Prefix, RouteSpec, TunDevice};
use tun2::AbstractDevice;

use crate::platform::{Platform, PlatformError};

/// Derive the destination (peer) address tun2 expects for a point-to-point
/// utun device: address + 1, or the address itself for /32.
fn peer_address(address: Ipv4Addr, prefix_len: u8) -> Ipv4Addr {
    if prefix_len == 32 {
        address
    } else {
        Ipv4Addr::from(u32::from(address).wrapping_add(1))
    }
}

/// The netmask for an IPv4 prefix length.
fn prefix_mask(prefix_len: u8) -> Ipv4Addr {
    if prefix_len == 0 {
        Ipv4Addr::UNSPECIFIED
    } else {
        Ipv4Addr::from(u32::MAX << (32 - u32::from(prefix_len)))
    }
}

/// The first IPv4 address of the plan, if any.
fn first_ipv4(addresses: &[Prefix]) -> Option<&Prefix> {
    addresses
        .iter()
        .find(|prefix| matches!(prefix.addr, IpAddr::V4(_)))
}

/// Active PF kill-switch enforcement: the open `/dev/pf` session and the
/// reference token that releases the PF enable on teardown.
struct EnabledKillSwitch {
    pf: tobro_osapi::pf::PfSession,
    /// The `DIOCSTARTREF` release token, `None` when this apply did not
    /// enable PF: the rules were already loaded and PF was already running
    /// from a previous (possibly crashed) helper instance, so no reference
    /// was taken and none may be released.
    token: Option<u64>,
}

impl std::fmt::Debug for EnabledKillSwitch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Count-only; never the token value (§10.5).
        f.debug_struct("EnabledKillSwitch").finish_non_exhaustive()
    }
}

/// Device-scoped helper state: everything `teardown` must undo.
struct DeviceState {
    /// The actual interface name the kernel assigned (`utunN`).
    name: String,
    /// The interface's kernel index (used for route installation).
    index: u32,
    device: tun2::AsyncDevice,
    /// The IPv4 address configured at creation; a plan that asks for a
    /// different one is refused (macOS cannot re-address a live utun).
    applied_address: Prefix,
    /// Routes the helper installed (tunnel + bypass), for convergence.
    installed_routes: Vec<RouteSpec>,
    /// The global DNS key backup: `None` = not backed up yet; `Some(None)` =
    /// the key did not exist; `Some(Some(xml))` = the previous value.
    dns_backup: Option<Option<Vec<u8>>>,
    /// PF enforcement installed by `KillSwitchMode::Block`.
    kill_switch: Option<EnabledKillSwitch>,
}

impl DeviceState {
    /// The number of tracked route entries (for count-only logging).
    fn tracked_route_count(&self) -> usize {
        self.installed_routes.len()
    }
}

impl std::fmt::Debug for DeviceState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Count-only summary; never device details (§10.5).
        f.debug_struct("DeviceState")
            .field("tracked_routes", &self.installed_routes.len())
            .field("dns_backup_taken", &self.dns_backup.is_some())
            .field("kill_switch_enforced", &self.kill_switch.is_some())
            .finish_non_exhaustive()
    }
}

/// The macOS privileged backend.
#[derive(Debug, Default)]
pub struct MacosPlatform {
    state: tokio::sync::Mutex<Option<DeviceState>>,
}

impl MacosPlatform {
    /// Build the backend. Nothing OS-level to open up front: the routing
    /// socket and the dynamic store are created per operation.
    pub fn new() -> Self {
        Self::default()
    }

    /// Remove every route this device state tracks (best-effort).
    async fn remove_tracked_routes(&self, state: &mut DeviceState) -> usize {
        let mut removed = 0usize;
        for spec in state.installed_routes.drain(..) {
            let route = tobro_osapi_route(&spec, state.index);
            // Deletions are idempotent on the FFI level; count successes.
            match tobro_osapi::bsd_route::delete_route(&route) {
                Ok(()) => removed += 1,
                Err(error) => tracing::warn!("could not remove a tracked route: {error}"),
            }
        }
        removed
    }
}

/// Convert a validated plan route into the FFI route type.
fn tobro_osapi_route(spec: &RouteSpec, interface_index: u32) -> tobro_osapi::Route {
    tobro_osapi::Route {
        destination: spec.destination.addr,
        prefix_len: spec.destination.prefix_len,
        gateway: spec.gateway,
        interface_index,
        metric: spec.metric,
    }
}

/// Run a blocking SystemConfiguration operation via `tobro-osapi`. CF
/// objects never cross threads; only plain bytes/bools do.
async fn sc_blocking<T, F>(operation: F) -> Result<T, PlatformError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, String> + Send + 'static,
{
    tokio::task::spawn_blocking(operation)
        .await
        .map_err(|error| PlatformError::Dns(format!("DNS task failed: {error}")))?
        .map_err(PlatformError::Dns)
}

/// The XML property-list backup of the global DNS key: `None` = not backed
/// up yet; `Some(None)` = the key did not exist; `Some(Some(xml))` = the
/// previous value. (See `tobro_osapi::sc_dns`.)

#[async_trait]
impl Platform for MacosPlatform {
    async fn create_device(&self, device: &TunDevice) -> Result<String, PlatformError> {
        let mut guard = self.state.lock().await;

        // The requested name is advisory on macOS: the kernel always assigns
        // `utunN`. A device the helper already owns is reused.
        if guard.is_none() {
            // tun2 requires the first IPv4 address up front (SIOCAIFADDR at
            // creation); without one its defaults apply.
            let ipv4 = first_ipv4(&device.addresses).copied();
            let mut config = tun2::Configuration::default();
            config.mtu(device.mtu).up();
            if let Some(prefix) = &ipv4 {
                let IpAddr::V4(address) = prefix.addr else {
                    return Err(PlatformError::Device(
                        "internal: non-IPv4 address selected".to_owned(),
                    ));
                };
                if prefix.prefix_len > 32 {
                    return Err(PlatformError::Device(format!(
                        "prefix length {} does not fit an IPv4 address",
                        prefix.prefix_len
                    )));
                }
                config
                    .address(address)
                    .netmask(prefix_mask(prefix.prefix_len))
                    .destination(peer_address(address, prefix.prefix_len));
            }
            // No name: the kernel assigns `utunN` (a non-utun name is
            // rejected by tun2 on macOS).
            tracing::info!(
                "creating the utun device (addresses={}, mtu={})",
                device.addresses.len(),
                device.mtu
            );
            let tun = tun2::create_as_async(&config).map_err(|error| {
                PlatformError::Device(format!("could not create the utun device: {error}"))
            })?;
            let name = tun.tun_name().map_err(|error| {
                PlatformError::Device(format!("utun device has no name: {error}"))
            })?;
            let index = tun.tun_index().map_err(|error| {
                PlatformError::Device(format!("utun device has no index: {error}"))
            })?;
            let index = u32::try_from(index)
                .map_err(|_| PlatformError::Device("utun index overflow".to_owned()))?;
            *guard = Some(DeviceState {
                name: name.clone(),
                index,
                device: tun,
                applied_address: ipv4.unwrap_or(Prefix {
                    addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                    prefix_len: 0,
                }),
                installed_routes: Vec::new(),
                dns_backup: None,
                kill_switch: None,
            });
        }

        // Converge what can be converged on reuse (MTU only; addressing is
        // creation-time on macOS).
        let state = guard
            .as_mut()
            .ok_or_else(|| PlatformError::Device("internal: device state missing".to_owned()))?;
        state.device.set_mtu(device.mtu).map_err(|error| {
            PlatformError::Device(format!("could not set the device MTU: {error}"))
        })?;
        if let Some(prefix) = first_ipv4(&device.addresses)
            && state.applied_address != *prefix
        {
            return Err(PlatformError::Device(
                "macOS cannot re-address a live utun device; tear down first (the helper will recreate it on the next apply)".to_owned(),
            ));
        }
        Ok(state.name.clone())
    }

    async fn apply_routes(
        &self,
        interface: &str,
        routes: &[RouteSpec],
        bypass_routes: &[RouteSpec],
    ) -> Result<(), PlatformError> {
        let mut guard = self.state.lock().await;
        let state = guard.as_mut().ok_or_else(|| {
            PlatformError::Route("no active TUN device; routes follow device creation".to_owned())
        })?;
        if state.name != interface {
            return Err(PlatformError::Route(format!(
                "plan targets interface {interface} but the active device is {}",
                state.name
            )));
        }

        // Route ops are blocking syscalls; keep them off the async runtime.
        let desired: Vec<RouteSpec> = routes.iter().chain(bypass_routes.iter()).cloned().collect();
        let index = state.index;
        let additions: Vec<(RouteSpec, bool)> = bypass_routes
            .iter()
            .map(|spec| (spec.clone(), true))
            .chain(routes.iter().map(|spec| (spec.clone(), false)))
            .collect();
        tokio::task::spawn_blocking(move || -> Result<(), PlatformError> {
            for (spec, bypass) in additions {
                let route = tobro_osapi_route(&spec, index);
                let kind = if bypass { "bypass" } else { "tunnel" };
                match tobro_osapi::bsd_route::add_route(&route) {
                    Ok(()) => {}
                    // Replace semantics: delete the existing entry, re-add.
                    Err(tobro_osapi::RouteError::Exists) => {
                        tobro_osapi::bsd_route::delete_route(&route).map_err(|error| {
                            PlatformError::Route(format!(
                                "could not replace an existing {kind} route: {error}"
                            ))
                        })?;
                        tobro_osapi::bsd_route::add_route(&route).map_err(|error| {
                            PlatformError::Route(format!(
                                "could not install the {kind} route: {error}"
                            ))
                        })?;
                    }
                    Err(error) => {
                        return Err(PlatformError::Route(format!(
                            "could not install the {kind} route: {error}"
                        )));
                    }
                }
            }
            Ok(())
        })
        .await
        .map_err(|error| PlatformError::Route(format!("route task failed: {error}")))??;

        // Remove routes the new plan no longer wants.
        let stale: Vec<RouteSpec> = state
            .installed_routes
            .iter()
            .filter(|spec| !desired.contains(spec))
            .cloned()
            .collect();
        let mut removed = 0usize;
        for spec in &stale {
            let route = tobro_osapi_route(spec, index);
            match tobro_osapi::bsd_route::delete_route(&route) {
                Ok(()) => removed += 1,
                Err(error) => {
                    return Err(PlatformError::Route(format!(
                        "could not remove a stale route: {error}"
                    )));
                }
            }
        }
        state.installed_routes = desired;
        tracing::info!(
            "apply_routes: converged ({} tunnel, {} bypass, {removed} removed)",
            routes.len(),
            bypass_routes.len()
        );
        Ok(())
    }

    async fn apply_dns(&self, dns: &DnsConfig) -> Result<(), PlatformError> {
        let mut guard = self.state.lock().await;
        let state = guard.as_mut().ok_or_else(|| {
            PlatformError::Dns("no active TUN device; DNS follows device creation".to_owned())
        })?;
        // The first apply of a tunnel lifetime backs up the previous value;
        // later applies only overwrite (they are our own settings).
        let take_backup = state.dns_backup.is_none();
        let servers = dns.servers.clone();
        let backup =
            sc_blocking(move || tobro_osapi::sc_dns::apply_dns(servers, take_backup)).await?;
        if state.dns_backup.is_none() {
            state.dns_backup = backup;
        }
        tracing::info!(
            "apply_dns: system resolver set ({} server(s))",
            dns.servers.len()
        );
        Ok(())
    }

    async fn apply_kill_switch(&self, mode: KillSwitchMode) -> Result<(), PlatformError> {
        // The kill switch follows device creation: there is always an
        // enforced device here.
        let mut guard = self.state.lock().await;
        let state = guard.as_mut().ok_or_else(|| {
            PlatformError::KillSwitch(
                "no active TUN device; the kill switch follows device creation".to_owned(),
            )
        })?;
        match mode {
            KillSwitchMode::Block => {
                if state.kill_switch.is_some() {
                    tracing::info!("apply_kill_switch: PF enforcement already active");
                    return Ok(()); // idempotent
                }
                let interface = state.name.clone();
                let enforcement = tokio::task::spawn_blocking(
                    move || -> Result<(EnabledKillSwitch, usize), PlatformError> {
                        let pf = tobro_osapi::pf::PfSession::open().map_err(|error| {
                            PlatformError::KillSwitch(format!("could not open /dev/pf: {error}"))
                        })?;
                        let loaded = pf.apply_kill_switch_rules(&interface).map_err(|error| {
                            PlatformError::KillSwitch(format!(
                                "could not install the PF kill-switch rules: {error}"
                            ))
                        })?;
                        // Take an enable reference only when needed. If the
                        // rules were already installed and PF is already
                        // running, that running reference may belong to a
                        // previous helper instance (crash-relaunch): its
                        // token is unrecoverable, so re-enabling here would
                        // leak one reference per crash cycle. PF stops only
                        // when *all* references are gone, which is exactly
                        // the fail-closed property the kill switch relies on.
                        let token = if loaded > 0
                            || !pf.is_running().map_err(|error| {
                                PlatformError::KillSwitch(format!(
                                    "could not query the packet filter state: {error}"
                                ))
                            })? {
                            Some(pf.enable().map_err(|error| {
                                PlatformError::KillSwitch(format!(
                                    "could not enable the packet filter: {error}"
                                ))
                            })?)
                        } else {
                            None
                        };
                        Ok((EnabledKillSwitch { pf, token }, loaded))
                    },
                )
                .await
                .map_err(|error| {
                    PlatformError::KillSwitch(format!("kill switch task failed: {error}"))
                })??;
                let (enforcement, loaded) = enforcement;
                tracing::info!(
                    "apply_kill_switch: PF enforcement active ({loaded} rule(s) loaded)"
                );
                state.kill_switch = Some(enforcement);
            }
            KillSwitchMode::Restore | KillSwitchMode::Disabled => {
                // Teardown order is fail-closed: routes are already gone, so
                // the block keeps covering the leak direction until the
                // rules themselves are removed.
                if let Some(enforcement) = state.kill_switch.take() {
                    let outcome = tokio::task::spawn_blocking(move || {
                        // Remove the rules first, then release the enable
                        // reference (releasing it could stop PF evaluating
                        // the block while the rules are still installed).
                        // The reference is released only if this instance
                        // took one (`token` is None when enforcement was
                        // adopted from a previous run without a reference).
                        let result =
                            enforcement
                                .pf
                                .remove_kill_switch_rules()
                                .and_then(|removed| match enforcement.token {
                                    Some(token) => enforcement.pf.disable(token).map(|_| removed),
                                    None => Ok(removed),
                                });
                        (enforcement, result)
                    })
                    .await;
                    match outcome {
                        Ok((enforcement, Ok(removed))) => {
                            drop(enforcement);
                            tracing::info!(
                                "apply_kill_switch: enforcement removed ({removed} rule(s))"
                            );
                        }
                        Ok((enforcement, Err(error))) => {
                            // Keep the enforcement tracked (fail-closed): the
                            // rules stay installed and PF stays enabled.
                            state.kill_switch = Some(enforcement);
                            return Err(PlatformError::KillSwitch(format!(
                                "could not remove the PF kill-switch enforcement: {error}"
                            )));
                        }
                        Err(error) => {
                            // The closure owns the session; if the task died
                            // without running, the kernel state persists
                            // untracked and a later apply re-establishes
                            // tracking (the rules are recognized by label).
                            return Err(PlatformError::KillSwitch(format!(
                                "kill switch task failed: {error}"
                            )));
                        }
                    }
                }
            }
        }
        Ok(())
    }

    async fn teardown(&self) -> Result<(), PlatformError> {
        let mut guard = self.state.lock().await;
        let Some(mut state) = guard.take() else {
            return Ok(()); // never applied: idempotent no-op
        };
        let tracked = state.tracked_route_count();
        let removed = self.remove_tracked_routes(&mut state).await;
        // Remove the PF enforcement (rules first, then the enable reference:
        // releasing the reference could stop PF evaluating the block while
        // the rules are still installed) while everything else is already
        // back to stock.
        let enforcement = state.kill_switch.take();
        let enforcement_removed = tokio::task::spawn_blocking(move || {
            let Some(enforcement) = enforcement else {
                return Ok(0usize);
            };
            enforcement
                .pf
                .remove_kill_switch_rules()
                .and_then(|removed| {
                    // Release the enable reference only if this instance took
                    // one (`token` is None when enforcement was adopted from
                    // a previous run without a reference).
                    match enforcement.token {
                        Some(token) => enforcement.pf.disable(token).map(|_| removed),
                        None => Ok(removed),
                    }
                })
        })
        .await
        .map_err(|error| PlatformError::KillSwitch(format!("kill switch task failed: {error}")))?;
        match enforcement_removed {
            Ok(rules_removed) => {
                tracing::info!(
                    "teardown: kill-switch enforcement removed ({rules_removed} rule(s))"
                );
            }
            Err(error) => {
                tracing::warn!("teardown: could not remove the PF enforcement: {error}");
            }
        }
        // Restore DNS best-effort, then drop the device: closing the utun
        // makes the kernel remove the interface and its device routes.
        let backup = state.dns_backup.take();
        let restore = sc_blocking(move || tobro_osapi::sc_dns::restore_dns(backup)).await;
        if let Err(error) = restore {
            tracing::warn!("teardown: {error}");
        }
        drop(state.device);
        tracing::info!(
            "teardown: done ({tracked} tracked route(s), {removed} removed successfully)"
        );
        Ok(())
    }
}

/// Real-host integration test: needs root and a real macOS host (run with
/// `cargo test -p tobro-helper -- --ignored` under sudo). The helper owns
/// the whole lifecycle: utun device, routes, DNS, teardown.
#[cfg(all(test, target_os = "macos"))]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod macos_integration {
    use super::*;
    use std::net::Ipv6Addr;

    #[tokio::test]
    #[ignore = "requires root and a real macOS host"]
    async fn device_routes_dns_and_teardown_on_a_real_host() {
        let platform = MacosPlatform::new();
        let device = TunDevice {
            name: String::new(), // the kernel assigns utunN
            addresses: vec![Prefix {
                addr: IpAddr::V4(Ipv4Addr::new(10, 111, 222, 252)),
                prefix_len: 30,
            }],
            mtu: 1400,
        };
        let name = platform.create_device(&device).await.expect("create");
        assert!(name.starts_with("utun"), "{name}");

        let default_route = RouteSpec {
            destination: Prefix {
                addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                prefix_len: 0,
            },
            gateway: None,
            metric: Some(60),
        };
        let bypass = RouteSpec {
            destination: Prefix {
                addr: IpAddr::V4("192.0.2.0".parse().expect("valid")),
                prefix_len: 24,
            },
            gateway: Some(IpAddr::V4("198.51.100.1".parse().expect("valid"))),
            metric: None,
        };
        let routes = [default_route];
        let bypass_routes = [bypass];
        platform
            .apply_routes(&name, &routes, &bypass_routes)
            .await
            .expect("routes");
        // Applying again converges idempotently.
        platform
            .apply_routes(&name, &routes, &bypass_routes)
            .await
            .expect("routes again");

        // DNS: the real global key is backed up and restored.
        let dns = DnsConfig {
            servers: vec![
                IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
                IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 0x1111)),
            ],
        };
        platform.apply_dns(&dns).await.expect("dns");

        // Block installs PF enforcement (fail-closed on the real host) and
        // is idempotent; Restore removes it again; teardown stays a no-op
        // after that. Note: while the block is active this machine loses
        // all egress except loopback and the tunnel interface.
        platform
            .apply_kill_switch(KillSwitchMode::Block)
            .await
            .expect("block");
        platform
            .apply_kill_switch(KillSwitchMode::Block)
            .await
            .expect("block again (idempotent)");
        platform
            .apply_kill_switch(KillSwitchMode::Restore)
            .await
            .expect("restore");

        platform.teardown().await.expect("teardown");
        // A second teardown is an idempotent no-op.
        platform.teardown().await.expect("teardown again");
    }
}
