//! Windows TUN backend — wintun device + iphlpapi routes + adapter-scoped
//! DNS (M7 T4c).
//!
//! Design notes:
//!
//! - The device is a wintun adapter created through `tun2`; addressing and
//!   MTU are set at creation (tun2 calls `set_network_addresses_tuple` with
//!   our address + netmask and no gateway). Like macOS, a changed address on
//!   a reused device is refused with a teardown-first error; MTU is
//!   converged via the adapter.
//! - The adapter index and DNS settings are managed through
//!   `wintun-bindings` by re-opening the adapter by name (DNS set on our own
//!   adapter is cleaned up automatically when the adapter is deleted, so no
//!   backup is needed).
//! - Routes go through `tobro-osapi`'s iphlpapi FFI. Adds report
//!   `Exists`/deletes `NotFound`, so convergence mirrors the other backends:
//!   replace-on-add, idempotent deletes.
//! - `wintun.dll` must sit next to the helper binary (bundled by packaging,
//!   M8); until then device creation fails with a clear error. The driver
//!   library is loaded lazily on first use so `status`/`teardown` still work.
//! - `KillSwitchMode::Block` is unsupported here: fail-closed enforcement
//!   belongs in Windows Filtering Platform (WFP), deferred to M8.
//! - Logs carry counts only, never addresses or destinations (§10.5).

use std::net::{IpAddr, Ipv4Addr};

use async_trait::async_trait;
use tobro_tun::{DnsConfig, KillSwitchMode, Prefix, RouteSpec, TunDevice};
use tun2::AbstractDevice;
use wintun_bindings::Wintun;

use crate::platform::{Platform, PlatformError};

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

/// Device-scoped helper state: everything `teardown` must undo.
struct DeviceState {
    /// The adapter's friendly name ("tobro" unless the plan names one).
    name: String,
    /// The adapter's Win32 interface index.
    index: u32,
    device: tun2::AsyncDevice,
    /// The loaded wintun driver library (re-opening the adapter needs it).
    wintun: Wintun,
    /// The IPv4 address configured at creation.
    applied_address: Prefix,
    /// Routes the helper installed (tunnel + bypass), for convergence.
    installed_routes: Vec<RouteSpec>,
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
            let route = osapi_route(&spec, state.index);
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
    async fn create_device(&self, device: &TunDevice) -> Result<String, PlatformError> {
        let mut guard = self.state.lock().await;

        // A reused device is kept as-is (address/MTU converge below where
        // the OS allows it).
        if guard.is_none() {
            let name = if device.name.is_empty() {
                "tobro".to_owned()
            } else {
                device.name.clone()
            };
            let wintun_path = tobro_osapi::win_route::default_wintun_path();
            let wintun = tokio::task::spawn_blocking(move || {
                tobro_osapi::win_route::load_wintun(wintun_path.as_os_str())
            })
            .await
            .map_err(|error| PlatformError::Device(format!("driver load task failed: {error}")))?
            .map_err(|error| {
                PlatformError::Device(format!(
                    "could not load the wintun driver from beside the helper binary: {error}"
                ))
            })?;

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
            *guard = Some(DeviceState {
                name,
                index,
                device: tun,
                wintun,
                applied_address: ipv4.unwrap_or(Prefix {
                    addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                    prefix_len: 0,
                }),
                installed_routes: Vec::new(),
            });
        }

        // Converge what can be converged on reuse: MTU (addressing is
        // creation-time on Windows).
        let state = guard
            .as_mut()
            .ok_or_else(|| PlatformError::Device("internal: device state missing".to_owned()))?;
        if let Some(prefix) = first_ipv4(&device.addresses)
            && state.applied_address != *prefix
        {
            return Err(PlatformError::Device(
                "Windows cannot re-address a live wintun adapter; tear down first (the helper will recreate it on the next apply)".to_owned(),
            ));
        }
        let mtu = usize::from(device.mtu);
        let adapter = state.reopen_adapter()?;
        adapter.set_mtu(mtu).map_err(|error| {
            PlatformError::Device(format!("could not set the adapter MTU: {error}"))
        })?;
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

        let desired: Vec<RouteSpec> = routes.iter().chain(bypass_routes.iter()).cloned().collect();
        let index = state.index;
        let additions: Vec<(RouteSpec, bool)> = bypass_routes
            .iter()
            .map(|spec| (spec.clone(), true))
            .chain(routes.iter().map(|spec| (spec.clone(), false)))
            .collect();
        tokio::task::spawn_blocking(move || -> Result<(), PlatformError> {
            for (spec, bypass) in additions {
                let route = osapi_route(&spec, index);
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
            let route = osapi_route(spec, index);
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

    async fn apply_kill_switch(&self, mode: KillSwitchMode) -> Result<(), PlatformError> {
        let guard = self.state.lock().await;
        if guard.is_none() {
            return Err(PlatformError::KillSwitch(
                "no active TUN device; the kill switch follows device creation".to_owned(),
            ));
        }
        drop(guard);
        match mode {
            KillSwitchMode::Block => Err(PlatformError::Unsupported(
                "fail-closed enforcement needs Windows Filtering Platform rules, deferred to M8; use the restore policy or skip the kill switch on Windows for now".to_owned(),
            )),
            KillSwitchMode::Restore | KillSwitchMode::Disabled => Ok(()),
        }
    }

    async fn teardown(&self) -> Result<(), PlatformError> {
        let mut guard = self.state.lock().await;
        let Some(mut state) = guard.take() else {
            return Ok(()); // never applied: idempotent no-op
        };
        let tracked = state.tracked_route_count();
        let removed = self.remove_tracked_routes(&mut state).await;
        // Deconstruct the state: drop the device (ends the wintun session),
        // then delete the adapter — its addressing and DNS settings
        // disappear with it.
        let DeviceState {
            name,
            wintun,
            device,
            index: _,
            applied_address: _,
            installed_routes: _,
        } = state;
        drop(device);
        let delete_result = match wintun_bindings::Adapter::open(&wintun, &name) {
            Ok(adapter) => match std::sync::Arc::try_unwrap(adapter) {
                Ok(adapter) => adapter.delete().map_err(|error| {
                    PlatformError::Device(format!("could not delete the wintun adapter: {error}"))
                }),
                Err(_) => Err(PlatformError::Device(
                    "the wintun adapter is still referenced by another handle".to_owned(),
                )),
            },
            Err(error) => Err(PlatformError::Device(format!(
                "could not re-open the wintun adapter: {error}"
            ))),
        };
        if let Err(error) = delete_result {
            tracing::warn!("teardown: {error}");
        }
        tracing::info!(
            "teardown: done ({tracked} tracked route(s), {removed} removed successfully)"
        );
        Ok(())
    }
}
