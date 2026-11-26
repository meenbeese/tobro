//! Windows TUN backend — wintun device + iphlpapi routes + adapter-scoped
//! DNS (M7 T4c).
//!
//! Design notes:
//!
//! - The device is a wintun adapter created through `tun2`; the first IPv4
//!   address, MTU, and the up state are set at creation (tun2 calls
//!   `set_network_addresses_tuple` with our address + netmask and no
//!   gateway). The plan's IPv6 addresses are then added through iphlpapi
//!   (`CreateUnicastIpAddressEntry` in `tobro-osapi`), so the adapter is
//!   dual-stack like the Linux device. Every apply gets a fresh adapter: the
//!   service stops the routing engine (which owns the device) first, and
//!   closing the last wintun handle removes the adapter.
//! - The adapter index and DNS settings are managed through
//!   `wintun-bindings` by re-opening the adapter by name (DNS set on our own
//!   adapter is cleaned up automatically when the adapter is deleted, so no
//!   backup is needed).
//! - Routes go through `tobro-osapi`'s iphlpapi FFI. Adds report
//!   `Exists`/deletes `NotFound`, so convergence mirrors the other backends:
//!   replace-on-add, idempotent deletes.
//! - `wintun.dll` must sit next to the helper binary: packaging ships it with
//!   the helper sidecar and `tobro-install` copies it into the privileged
//!   helper directory. The driver library is loaded lazily on first use so
//!   `status`/`teardown` still work before the driver is available.
//! - `KillSwitchMode::Block` installs persistent Windows Filtering Platform
//!   filters through `tobro-osapi`'s WFP FFI (the helper never shells out,
//!   §10.5): permit loopback, the tunnel adapter (matched by LUID), and each
//!   split-tunnel bypass destination (remote-subnet permits), then block all
//!   other egress, per family. The objects live in the WFP store and fail
//!   closed — they keep enforcing if the helper crashes — and teardown
//!   removes them by sweeping the dedicated sublayer, never touching
//!   foreign filters.
//! - Logs carry counts only, never addresses or destinations (§10.5).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use async_trait::async_trait;
use tobro_tun::{DnsConfig, KillSwitchMode, Prefix, RouteSpec, TunDevice};
use tun2::AbstractDevice;
use wintun_bindings::Wintun;

use crate::platform::{CreatedDevice, Platform, PlatformError};

/// Derive the netmask for an IPv4 prefix length (tun2 expects a mask IP).
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

/// Convert a validated plan route into the FFI route type.
fn osapi_route(spec: &RouteSpec, interface_index: u32) -> tobro_osapi::Route {
    tobro_osapi::Route {
        destination: spec.destination.addr,
        prefix_len: spec.destination.prefix_len,
        gateway: spec.gateway,
        interface_index,
        metric: spec.metric,
    }
}

/// The physical adapters' interface indices per family, resolved once at
/// device creation — before any route is applied, so the per-family default
/// route still resolves to the physical network. Bypass routes must pin
/// these indices: a gateway route's row names its egress adapter, and
/// pinning the wintun index would send bypass traffic back into the tunnel.
#[derive(Debug, Clone, Copy, Default)]
struct PhysicalAdapters {
    v4: Option<u32>,
    v6: Option<u32>,
}

impl PhysicalAdapters {
    /// The resolved index for a destination's family, if known.
    fn for_family(&self, family: IpAddr) -> Option<u32> {
        match family {
            IpAddr::V4(_) => self.v4,
            IpAddr::V6(_) => self.v6,
        }
    }
}

/// Resolve the physical adapters through iphlpapi (blocking; runs off the
/// async core). A family with no connectivity resolves to `None`.
fn resolve_physical_adapters() -> PhysicalAdapters {
    let v4 = tobro_osapi::win_route::best_route(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
        .ok()
        .flatten()
        .map(|route| route.interface_index);
    let v6 = tobro_osapi::win_route::best_route(IpAddr::V6(Ipv6Addr::UNSPECIFIED))
        .ok()
        .flatten()
        .map(|route| route.interface_index);
    PhysicalAdapters { v4, v6 }
}

/// The bypass destinations as `(address, prefix length)` pairs for the WFP
/// permit filters (the gateway is not part of a filter condition).
fn bypass_pairs(bypass_routes: &[RouteSpec]) -> Vec<(IpAddr, u8)> {
    bypass_routes
        .iter()
        .map(|spec| (spec.destination.addr, spec.destination.prefix_len))
        .collect()
}

/// The interface index one route's row is built with: tunnel routes (no
/// gateway) pin the adapter itself, bypass routes pin their family's
/// physical adapter. Errors when a bypass route's family had no
/// connectivity at device creation (the plan's gateway discovery and this
/// resolution can disagree; failing is the honest answer — the traffic
/// would otherwise be sent into the tunnel and, with a kill switch, be
/// dropped entirely).
fn route_row_index(
    spec: &RouteSpec,
    tunnel_index: u32,
    physical: &PhysicalAdapters,
) -> Result<u32, PlatformError> {
    if spec.gateway.is_none() {
        return Ok(tunnel_index);
    }
    physical.for_family(spec.destination.addr).ok_or_else(|| {
        PlatformError::Route(
            "cannot build a bypass route row: no physical adapter was discovered for this \
             address family at device creation"
                .to_owned(),
        )
    })
}

/// Device-scoped helper state: everything `teardown` must undo.
///
/// The device handle itself is *not* stored here: the routing engine owns it
/// (the service starts/stops the engine around device creation).
struct DeviceState {
    /// The adapter's friendly name ("tobro" unless the plan names one).
    name: String,
    /// The adapter's Win32 interface index.
    index: u32,
    /// The loaded wintun driver library (re-opening the adapter needs it).
    wintun: Wintun,
    /// The physical adapters' indices per family (resolved at creation).
    physical: PhysicalAdapters,
    /// Routes the helper installed (tunnel + bypass), for convergence.
    installed_routes: Vec<RouteSpec>,
    /// Whether WFP kill-switch filters are currently installed (the filters
    /// themselves are key-based, so only the presence bit is tracked).
    /// Carried across device recreation: the filters outlive the adapter and
    /// must be removed by a later apply/teardown.
    kill_switch: bool,
}

impl DeviceState {
    /// The number of tracked route entries (for count-only logging).
    fn tracked_route_count(&self) -> usize {
        self.installed_routes.len()
    }

    /// Re-open the adapter by name for adapter-level operations (DNS, MTU,
    /// delete). The fresh handle is the sole reference, so `delete` can
    /// consume it.
    fn reopen_adapter(&self) -> Result<std::sync::Arc<wintun_bindings::Adapter>, PlatformError> {
        wintun_bindings::Adapter::open(&self.wintun, &self.name).map_err(|error| {
            PlatformError::Device(format!("could not re-open the wintun adapter: {error}"))
        })
    }
}

impl std::fmt::Debug for DeviceState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Count-only summary; never device details (§10.5).
        f.debug_struct("DeviceState")
            .field("tracked_routes", &self.installed_routes.len())
            .field("kill_switch_enforced", &self.kill_switch)
            .finish_non_exhaustive()
    }
}

/// The Windows privileged backend.
#[derive(Debug, Default)]
pub struct WindowsPlatform {
    state: tokio::sync::Mutex<Option<DeviceState>>,
}

impl WindowsPlatform {
    /// Build the backend. The wintun driver library is loaded lazily on
    /// first device creation so non-device operations still work before the
    /// driver is bundled.
    pub fn new() -> Self {
        Self::default()
    }

    /// Remove every route this device state tracks (best-effort).
    async fn remove_tracked_routes(&self, state: &mut DeviceState) -> usize {
        let mut removed = 0usize;
        for spec in state.installed_routes.drain(..) {
            // A missing physical index falls back to the adapter index so a
            // best-effort delete still targets the likely row.
            let index = route_row_index(&spec, state.index, &state.physical).unwrap_or(state.index);
            let route = osapi_route(&spec, index);
            match tobro_osapi::win_route::delete_route(&route) {
                Ok(()) => removed += 1,
                Err(error) => tracing::warn!("could not remove a tracked route: {error}"),
            }
        }
        removed
    }
}

#[async_trait]
impl Platform for WindowsPlatform {
    async fn create_device(&self, device: &TunDevice) -> Result<CreatedDevice, PlatformError> {
        let mut guard = self.state.lock().await;

        // The previous adapter is already gone: the service stops the engine
        // (which owns packet I/O) before converging to a new plan, and closing
        // a created wintun adapter removes it. So this always creates a fresh
        // adapter. Keep the previous state until the new device exists, so a
        // failed creation can still be torn down (routes, WFP enforcement).
        let wintun = match guard.as_ref() {
            Some(state) => {
                let mut removed = 0usize;
                for spec in state
                    .installed_routes
                    .iter()
                    .filter(|spec| spec.gateway.is_some())
                {
                    // A missing physical index falls back to the adapter index
                    // so a best-effort delete still targets the likely row.
                    let index =
                        route_row_index(spec, state.index, &state.physical).unwrap_or(state.index);
                    match tobro_osapi::win_route::delete_route(&osapi_route(spec, index)) {
                        Ok(()) => removed += 1,
                        Err(error) => {
                            tracing::warn!("could not remove a stale bypass route: {error}");
                        }
                    }
                }
                if removed > 0 {
                    tracing::info!("create_device: removed {removed} stale bypass route(s)");
                }
                std::sync::Arc::clone(&state.wintun)
            }
            None => {
                let wintun_path = tobro_osapi::win_route::default_wintun_path();
                tokio::task::spawn_blocking(move || {
                    tobro_osapi::win_route::load_wintun(wintun_path.as_os_str())
                })
                .await
                .map_err(|error| {
                    PlatformError::Device(format!("driver load task failed: {error}"))
                })?
                .map_err(|error| {
                    PlatformError::Device(format!(
                        "could not load the wintun driver from beside the helper binary \
                         (reinstall the helper so wintun.dll is copied next to it): {error}"
                    ))
                })?
            }
        };

        let name = if device.name.is_empty() {
            "tobro".to_owned()
        } else {
            device.name.clone()
        };

        // tun2 addresses the adapter at creation: first IPv4 address +
        // netmask, no gateway (destination stays unset). Without a plan
        // address tun2's defaults apply.
        let ipv4 = first_ipv4(&device.addresses).copied();
        let mut config = tun2::Configuration::default();
        config.tun_name(&name).mtu(device.mtu).up();
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
                .netmask(prefix_mask(prefix.prefix_len));
        }
        tracing::info!(
            "creating the wintun adapter (name_set={}, addresses={}, mtu={})",
            !device.name.is_empty(),
            device.addresses.len(),
            device.mtu
        );
        let tun = tun2::create_as_async(&config).map_err(|error| {
            PlatformError::Device(format!("could not create the wintun adapter: {error}"))
        })?;
        let index = tun.tun_index().map_err(|error| {
            PlatformError::Device(format!("adapter has no interface index: {error}"))
        })?;
        let index = u32::try_from(index)
            .map_err(|_| PlatformError::Device("adapter index overflow".to_owned()))?;
        // Resolve the physical adapters now, before any route of this tunnel
        // lifetime exists: afterwards the per-family default route would
        // resolve to the tunnel itself.
        let physical = tokio::task::spawn_blocking(resolve_physical_adapters)
            .await
            .map_err(|error| {
                PlatformError::Device(format!("adapter discovery task failed: {error}"))
            })?;

        // tun2 only assigns the first IPv4 address, at creation. Add the
        // plan's IPv6 addresses through iphlpapi (`CreateUnicastIpAddressEntry`)
        // so the adapter is dual-stack like the Linux device. The address is
        // adapter-scoped: closing the adapter removes it, so teardown needs no
        // explicit cleanup.
        let ipv6: Vec<(IpAddr, u8)> = device
            .addresses
            .iter()
            .filter(|prefix| matches!(prefix.addr, IpAddr::V6(_)))
            .map(|prefix| (prefix.addr, prefix.prefix_len))
            .collect();
        for (address, prefix_len) in &ipv6 {
            tobro_osapi::win_route::add_unicast_address(index, *address, *prefix_len).map_err(
                |error| {
                    PlatformError::Device(format!(
                        "could not assign an IPv6 address to the wintun adapter: {error}"
                    ))
                },
            )?;
        }
        if !ipv6.is_empty() {
            tracing::info!("create_device: assigned {} IPv6 address(es)", ipv6.len());
        }

        // Carry what the adapter does not take with it: the WFP enforcement
        // outlives the adapter and must be removed by a later apply/teardown.
        let kill_switch = guard.as_ref().is_some_and(|state| state.kill_switch);
        *guard = Some(DeviceState {
            name: name.clone(),
            index,
            wintun,
            physical,
            installed_routes: Vec::new(),
            kill_switch,
        });

        Ok(CreatedDevice {
            interface: name,
            packet_io: Some(tun),
        })
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

        let desired: Vec<RouteSpec> = routes.iter().chain(bypass_routes.iter()).cloned().collect();
        let index = state.index;
        let physical = state.physical;
        let additions: Vec<(RouteSpec, bool)> = bypass_routes
            .iter()
            .map(|spec| (spec.clone(), true))
            .chain(routes.iter().map(|spec| (spec.clone(), false)))
            .collect();
        tokio::task::spawn_blocking(move || -> Result<(), PlatformError> {
            for (spec, bypass) in additions {
                let row_index = route_row_index(&spec, index, &physical)?;
                let route = osapi_route(&spec, row_index);
                let kind = if bypass { "bypass" } else { "tunnel" };
                match tobro_osapi::win_route::add_route(&route) {
                    Ok(()) => {}
                    // Replace semantics: delete the existing entry, re-add.
                    Err(tobro_osapi::RouteError::Exists) => {
                        tobro_osapi::win_route::delete_route(&route).map_err(|error| {
                            PlatformError::Route(format!(
                                "could not replace an existing {kind} route: {error}"
                            ))
                        })?;
                        tobro_osapi::win_route::add_route(&route).map_err(|error| {
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
            // The row to delete was built with the index from its install
            // time; a missing physical index falls back to the adapter
            // index so the delete still targets the likely row.
            let row_index = route_row_index(spec, index, &state.physical).unwrap_or(index);
            let route = osapi_route(spec, row_index);
            match tobro_osapi::win_route::delete_route(&route) {
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
        let guard = self.state.lock().await;
        let state = guard.as_ref().ok_or_else(|| {
            PlatformError::Dns("no active TUN device; DNS follows device creation".to_owned())
        })?;
        // DNS is scoped to our own adapter: it disappears with the adapter
        // on teardown, so there is nothing to back up.
        let servers = dns.servers.clone();
        let adapter = state.reopen_adapter()?;
        adapter.set_dns_servers(&servers).map_err(|error| {
            PlatformError::Dns(format!("could not set the adapter DNS servers: {error}"))
        })?;
        tracing::info!(
            "apply_dns: adapter resolver set ({} server(s))",
            dns.servers.len()
        );
        Ok(())
    }

    async fn apply_kill_switch(
        &self,
        mode: KillSwitchMode,
        bypass_routes: &[RouteSpec],
    ) -> Result<(), PlatformError> {
        // The kill switch follows device creation: there is always an
        // enforced adapter here.
        let mut guard = self.state.lock().await;
        let state = guard.as_mut().ok_or_else(|| {
            PlatformError::KillSwitch(
                "no active TUN device; the kill switch follows device creation".to_owned(),
            )
        })?;
        match mode {
            KillSwitchMode::Block => {
                let mut journal = crate::recovery::load();
                journal.block_all = true;
                crate::recovery::save(&journal).map_err(PlatformError::KillSwitch)?;
                // The WFP apply is replace-semantics (the sublayer is swept
                // first), so re-applying converges the enforcement with the
                // current bypass set; no early return for an already-active
                // kill switch.
                let bypass = bypass_pairs(bypass_routes);
                // The filters pin the adapter LUID, so read it fresh from
                // the adapter (it changes when the adapter is recreated).
                let adapter = state.reopen_adapter()?;
                let luid = adapter.get_luid();
                drop(adapter);
                let filters =
                    tokio::task::spawn_blocking(move || -> Result<usize, PlatformError> {
                        let engine = tobro_osapi::wfp::WfpEngine::open().map_err(|error| {
                            PlatformError::KillSwitch(format!(
                                "could not open the Windows Filtering Platform engine: {error}"
                            ))
                        })?;
                        engine
                            .apply_kill_switch(tobro_osapi::wfp::adapter_luid(luid), &bypass)
                            .map_err(|error| {
                                PlatformError::KillSwitch(format!(
                                    "could not install the WFP kill-switch filters: {error}"
                                ))
                            })
                    })
                    .await
                    .map_err(|error| {
                        PlatformError::KillSwitch(format!("kill switch task failed: {error}"))
                    })??;
                state.kill_switch = true;
                tracing::info!("apply_kill_switch: WFP enforcement active ({filters} filter(s))");
            }
            KillSwitchMode::Restore | KillSwitchMode::Disabled => {
                let mut journal = crate::recovery::load();
                journal.block_all = false;
                let _ = crate::recovery::save(&journal);
                // Teardown order is fail-closed: routes are already gone, so
                // the block keeps covering the leak direction until the
                // filters themselves are removed.
                if state.kill_switch {
                    tokio::task::spawn_blocking(move || -> Result<(), PlatformError> {
                        let engine = tobro_osapi::wfp::WfpEngine::open().map_err(|error| {
                            PlatformError::KillSwitch(format!(
                                "could not open the Windows Filtering Platform engine: {error}"
                            ))
                        })?;
                        engine.remove_kill_switch().map_err(|error| {
                            PlatformError::KillSwitch(format!(
                                "could not remove the WFP kill-switch filters: {error}"
                            ))
                        })
                    })
                    .await
                    .map_err(|error| {
                        PlatformError::KillSwitch(format!("kill switch task failed: {error}"))
                    })??;
                    state.kill_switch = false;
                    tracing::info!("apply_kill_switch: enforcement removed");
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
        // Remove the WFP enforcement (fail-closed order: the block stays up
        // until the routes are back to stock) before the adapter vanishes.
        if state.kill_switch {
            let enforcement_removed =
                tokio::task::spawn_blocking(move || -> Result<(), PlatformError> {
                    let engine = tobro_osapi::wfp::WfpEngine::open().map_err(|error| {
                        PlatformError::KillSwitch(format!(
                            "could not open the Windows Filtering Platform engine: {error}"
                        ))
                    })?;
                    engine.remove_kill_switch().map_err(|error| {
                        PlatformError::KillSwitch(format!(
                            "could not remove the WFP kill-switch filters: {error}"
                        ))
                    })
                })
                .await
                .map_err(|error| {
                    PlatformError::KillSwitch(format!("kill switch task failed: {error}"))
                });
            if let Err(error) = enforcement_removed {
                tracing::warn!("teardown: could not remove the WFP enforcement: {error}");
            } else {
                state.kill_switch = false;
                tracing::info!("teardown: kill-switch enforcement removed");
            }
        }
        // Deconstruct the state. The adapter itself is removed when the
        // service stops the engine (which owns the device) right after this
        // teardown: closing the last wintun handle deletes the adapter, and
        // its addressing and DNS settings go with it.
        let DeviceState {
            name,
            wintun,
            index: _,
            physical: _,
            installed_routes: _,
            kill_switch: _,
        } = state;
        drop((name, wintun));
        tracing::info!(
            "teardown: done ({tracked} tracked route(s), {removed} removed successfully)"
        );
        let mut journal = crate::recovery::load();
        journal.block_all = false;
        let _ = crate::recovery::clear();
        Ok(())
    }
}
