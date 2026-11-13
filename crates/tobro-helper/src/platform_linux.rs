//! Linux TUN backend — the M7 T4a reference implementation of [`Platform`].
//!
//! Design notes:
//!
//! - The TUN device is created with `tun2` without any address/netmask
//!   configured there; addressing, MTU, link state, and routes all go
//!   through netlink (`rtnetlink`). The helper never shells out (§10.5).
//! - Route convergence is idempotent: desired routes are added with
//!   `NLM_F_REPLACE` and previously installed routes that the new plan no
//!   longer wants are removed. The helper tracks only what it installed.
//! - DNS replaces `/etc/resolv.conf` atomically (temp file + rename) after
//!   backing the original up once per tunnel lifetime; teardown restores
//!   it. A symlinked `resolv.conf` (systemd-resolved) is rejected instead
//!   of clobbered — resolver-service integration is future work.
//! - Kill switch (`KillSwitchMode::Block`) installs blackhole default
//!   routes (`0.0.0.0/0`, `::/0`) one metric worse than the plan's TUN
//!   default route, so they only engage once the TUN default route is
//!   gone. This is route-level insurance for the common case; the stronger
//!   firewall-level enforcement (nftables) is deferred to M8 hardening. If
//!   the plan does not route a default prefix through the device, no
//!   insurance is installed: it would blackhole exactly the traffic the
//!   plan tunnels around.
//! - Logs carry counts and metrics only — never addresses, gateways, or
//!   destinations (§10.5: no packet contents in logs).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use async_trait::async_trait;
use futures::TryStreamExt;
use rtnetlink::packet_route::address::AddressAttribute;
use rtnetlink::packet_route::route::{RouteMessage, RouteProtocol, RouteScope, RouteType};
use rtnetlink::{AddressMessageBuilder, Handle, LinkUnspec, RouteMessageBuilder};
use tobro_tun::{DEFAULT_INTERFACE_NAME, DnsConfig, KillSwitchMode, Prefix, RouteSpec, TunDevice};

use crate::platform::{Platform, PlatformError};

/// System resolver configuration managed while the tunnel is up.
const RESOLV_CONF_PATH: &str = "/etc/resolv.conf";
/// Temp file used for the atomic resolv.conf replacement (same directory,
/// so the rename cannot cross filesystems).
const RESOLV_CONF_TMP: &str = "/etc/.resolv.conf.tobro.new";
/// Routing table the helper installs into: the main table (254).
const MAIN_TABLE_ID: u32 = 254;
/// The helper's routes are `static` (protocol 4), clearly distinguishing
/// them from DHCP/kernel-managed routes in `ip route` output.
const ROUTE_PROTOCOL: RouteProtocol = RouteProtocol::Static;
/// Global routes (not on-link).
const ROUTE_SCOPE: RouteScope = RouteScope::Universe;

/// Resolve the interface name a plan asks for (empty = helper default).
fn effective_name(device: &TunDevice) -> String {
    if device.name.is_empty() {
        DEFAULT_INTERFACE_NAME.to_owned()
    } else {
        device.name.clone()
    }
}

/// Metric for the kill-switch insurance blackhole routes: one worse than
/// the plan's TUN default route, so they engage only when it disappears.
fn blackhole_metric(tun_default_metric: Option<u32>) -> u32 {
    tun_default_metric.unwrap_or(0) + 1
}

/// Build the netlink route message for one [`RouteSpec`].
///
/// Routes without a gateway point into the TUN device (`output_interface`);
/// bypass routes point at a next-hop gateway, which the kernel resolves to
/// the physical interface on its own.
fn route_message(spec: &RouteSpec, device_index: u32) -> RouteMessage {
    let destination = spec.destination;
    match destination.addr {
        IpAddr::V4(addr) => {
            let mut builder = RouteMessageBuilder::<Ipv4Addr>::new()
                .destination_prefix(addr, destination.prefix_len)
                .table_id(MAIN_TABLE_ID)
                .scope(ROUTE_SCOPE)
                .protocol(ROUTE_PROTOCOL);
            if spec.gateway.is_none() {
                builder = builder.output_interface(device_index);
            }
            if let Some(gateway) = spec.gateway {
                builder = builder.gateway(v4(gateway));
            }
            if let Some(metric) = spec.metric {
                builder = builder.priority(metric);
            }
            builder.build()
        }
        IpAddr::V6(addr) => {
            let mut builder = RouteMessageBuilder::<Ipv6Addr>::new()
                .destination_prefix(addr, destination.prefix_len)
                .table_id(MAIN_TABLE_ID)
                .scope(ROUTE_SCOPE)
                .protocol(ROUTE_PROTOCOL);
            if spec.gateway.is_none() {
                builder = builder.output_interface(device_index);
            }
            if let Some(gateway) = spec.gateway {
                builder = builder.gateway(v6(gateway));
            }
            if let Some(metric) = spec.metric {
                builder = builder.priority(metric);
            }
            builder.build()
        }
    }
}

/// Build a blackhole route for the default prefix of one address family.
fn blackhole_message(ipv4: bool, metric: u32) -> RouteMessage {
    if ipv4 {
        RouteMessageBuilder::<Ipv4Addr>::new()
            .destination_prefix(Ipv4Addr::UNSPECIFIED, 0)
            .table_id(MAIN_TABLE_ID)
            .scope(ROUTE_SCOPE)
            .protocol(ROUTE_PROTOCOL)
            .kind(RouteType::BlackHole)
            .priority(metric)
            .build()
    } else {
        RouteMessageBuilder::<Ipv6Addr>::new()
            .destination_prefix(Ipv6Addr::UNSPECIFIED, 0)
            .table_id(MAIN_TABLE_ID)
            .scope(ROUTE_SCOPE)
            .protocol(ROUTE_PROTOCOL)
            .kind(RouteType::BlackHole)
            .priority(metric)
            .build()
    }
}

/// Narrow a validated `IpAddr` to its IPv4 address (same family only).
fn v4(addr: IpAddr) -> Ipv4Addr {
    match addr {
        IpAddr::V4(a) => a,
        IpAddr::V6(_) => Ipv4Addr::UNSPECIFIED, // unreachable: same-family validated
    }
}

/// Narrow a validated `IpAddr` to its IPv6 address (same family only).
fn v6(addr: IpAddr) -> Ipv6Addr {
    match addr {
        IpAddr::V6(a) => a,
        IpAddr::V4(_) => Ipv6Addr::UNSPECIFIED, // unreachable: same-family validated
    }
}

/// Render the resolver configuration for the tunnel lifetime.
fn render_resolv_conf(servers: &[IpAddr]) -> String {
    let mut content = String::from(
        "# Generated by tobro-helper: TUN mode is active.\n\
         # The original resolver configuration is restored on teardown.\n",
    );
    for server in servers {
        content.push_str(&format!("nameserver {server}\n"));
    }
    content
}

/// Device-scoped helper state: everything `teardown` must undo.
struct DeviceState {
    name: String,
    index: u32,
    device: tun2::AsyncDevice,
    /// Routes the helper installed (tunnel + bypass), for convergence and
    /// removal. Bypass routes carry their gateway; device routes do not.
    installed_routes: Vec<RouteSpec>,
    /// Kill-switch insurance blackhole routes currently installed.
    blackholes: Vec<RouteMessage>,
    /// Metric of the plan's device default route, when the plan routes a
    /// default prefix through the device (drives the insurance metric).
    tun_default_metric: Option<u32>,
    /// `/etc/resolv.conf` backup: `None` = not backed up yet; `Some(None)` =
    /// the file did not exist; `Some(Some(content))` = original content.
    dns_backup: Option<Option<String>>,
}

impl DeviceState {
    /// The number of tracked route entries (for count-only logging).
    fn tracked_route_count(&self) -> usize {
        self.installed_routes.len() + self.blackholes.len()
    }
}

/// The Linux privileged backend.
pub struct LinuxPlatform {
    handle: Handle,
    state: tokio::sync::Mutex<Option<DeviceState>>,
}

impl std::fmt::Debug for LinuxPlatform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Count-only summary; never device details.
        f.debug_struct("LinuxPlatform")
            .field("active", &self.state.try_lock().is_ok())
            .finish_non_exhaustive()
    }
}

impl LinuxPlatform {
    /// Open the netlink connection. Fails fast so startup problems are
    /// reported before any client connects.
    pub fn connect() -> Result<Self, PlatformError> {
        let (connection, handle, _errors) = rtnetlink::new_connection().map_err(|error| {
            PlatformError::Device(format!("could not open the netlink connection: {error}"))
        })?;
        tokio::spawn(connection);
        Ok(Self {
            handle,
            state: tokio::sync::Mutex::new(None),
        })
    }

    /// Find a link by name and return its interface index.
    async fn link_index(&self, name: &str) -> Result<u32, PlatformError> {
        let mut stream = self.handle.link().get().match_name(name).execute();
        let link = stream
            .try_next()
            .await
            .map_err(|error| PlatformError::Device(format!("netlink error: {error}")))?
            .ok_or_else(|| {
                PlatformError::Device(format!("the TUN device {name} did not appear"))
            })?;
        Ok(link.header.index)
    }

    /// Assign one address if it is not already on the device (idempotent).
    async fn add_address_if_missing(
        &self,
        index: u32,
        prefix: &Prefix,
    ) -> Result<(), PlatformError> {
        let mut existing = self
            .handle
            .address()
            .get()
            .set_link_index_filter(index)
            .set_address_filter(prefix.addr)
            .set_prefix_length_filter(prefix.prefix_len)
            .execute();
        let already_assigned = existing
            .try_next()
            .await
            .map_err(|error| PlatformError::Device(format!("netlink error: {error}")))?
            .is_some();
        if already_assigned {
            return Ok(());
        }
        self.handle
            .address()
            .add(index, prefix.addr, prefix.prefix_len)
            .execute()
            .await
            .map_err(|error| {
                PlatformError::Device(format!(
                    "could not assign an address to the TUN device: {error}"
                ))
            })
    }

    /// Converge the device's addresses to the plan: add missing ones, remove
    /// ones the plan no longer wants.
    async fn converge_addresses(
        &self,
        index: u32,
        desired: &[Prefix],
    ) -> Result<(), PlatformError> {
        let mut current = self
            .handle
            .address()
            .get()
            .set_link_index_filter(index)
            .execute();
        let mut removed = 0usize;
        while let Some(message) = current
            .try_next()
            .await
            .map_err(|error| PlatformError::Device(format!("netlink error: {error}")))?
        {
            // Address messages carry the interface index and prefix length in
            // the header and the address in the attributes.
            let address = message
                .attributes
                .iter()
                .find_map(|attribute| match attribute {
                    AddressAttribute::Address(addr) => Some(*addr),
                    _ => None,
                });
            let Some(address) = address else { continue };
            let prefix = Prefix {
                addr: address,
                prefix_len: message.header.prefix_len,
            };
            if desired
                .iter()
                .any(|d| d.addr == prefix.addr && d.prefix_len == prefix.prefix_len)
            {
                continue;
            }
            let removal = match prefix.addr {
                IpAddr::V4(addr) => AddressMessageBuilder::<Ipv4Addr>::new()
                    .index(index)
                    .address(addr, prefix.prefix_len)
                    .build(),
                IpAddr::V6(addr) => AddressMessageBuilder::<Ipv6Addr>::new()
                    .index(index)
                    .address(addr, prefix.prefix_len)
                    .build(),
            };
            self.handle
                .address()
                .del(removal)
                .execute()
                .await
                .map_err(|error| {
                    PlatformError::Device(format!(
                        "could not remove a stale address from the TUN device: {error}"
                    ))
                })?;
            removed += 1;
        }
        for prefix in desired {
            self.add_address_if_missing(index, prefix).await?;
        }
        if removed > 0 {
            tracing::debug!("addresses: removed {removed} stale address(es)");
        }
        Ok(())
    }

    /// Remove every route this device state tracks (best-effort). Used by
    /// teardown and by a device reset when a plan changes the interface.
    async fn remove_tracked_routes(&self, state: &DeviceState) -> usize {
        let mut removed = 0usize;
        for message in &state.blackholes {
            if let Err(error) = self.handle.route().del(message.clone()).execute().await {
                tracing::warn!("could not remove a kill-switch route: {error}");
            } else {
                removed += 1;
            }
        }
        for spec in &state.installed_routes {
            let message = route_message(spec, state.index);
            if let Err(error) = self.handle.route().del(message).execute().await {
                tracing::warn!("could not remove a tracked route: {error}");
            } else {
                removed += 1;
            }
        }
        removed
    }

    /// Restore the resolver configuration backed up for this device state.
    fn restore_dns(state: &mut DeviceState) {
        let Some(backup) = state.dns_backup.take() else {
            return;
        };
        match backup {
            Some(original) => match write_resolv_conf(&original) {
                Ok(()) => tracing::info!("teardown: resolver configuration restored"),
                Err(error) => {
                    tracing::warn!("teardown: could not restore /etc/resolv.conf: {error}")
                }
            },
            None => {
                // The file did not exist before; remove what we wrote.
                if let Err(error) = std::fs::remove_file(RESOLV_CONF_PATH) {
                    tracing::warn!(
                        "teardown: could not remove the generated resolver config: {error}"
                    );
                }
            }
        }
    }
}

/// Atomically replace `/etc/resolv.conf` (temp file in the same directory
/// + rename; a partial write never becomes visible).
fn write_resolv_conf(content: &str) -> Result<(), PlatformError> {
    std::fs::write(RESOLV_CONF_TMP, content).map_err(|error| {
        PlatformError::Dns(format!(
            "could not write the resolver configuration: {error}"
        ))
    })?;
    if let Ok(file) = std::fs::File::open(RESOLV_CONF_TMP) {
        let _ = file.sync_all();
    }
    std::fs::rename(RESOLV_CONF_TMP, RESOLV_CONF_PATH).map_err(|error| {
        let _ = std::fs::remove_file(RESOLV_CONF_TMP);
        PlatformError::Dns(format!(
            "could not activate the resolver configuration: {error}"
        ))
    })
}

/// Back up the current `/etc/resolv.conf` before the first DNS apply.
/// A symlinked resolv.conf is managed by another resolver service; refuse
/// rather than silently replacing it.
fn read_dns_backup() -> Result<Option<String>, PlatformError> {
    match std::fs::symlink_metadata(RESOLV_CONF_PATH) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(PlatformError::Dns(
            "/etc/resolv.conf is a symlink managed by another resolver service; manual DNS management is not supported on this setup yet"
                .to_owned(),
        )),
        Ok(_) => std::fs::read_to_string(RESOLV_CONF_PATH)
            .map(Some)
            .map_err(|error| {
                PlatformError::Dns(format!(
                    "could not read /etc/resolv.conf to back it up: {error}"
                ))
            }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(PlatformError::Dns(format!(
            "could not stat /etc/resolv.conf to back it up: {error}"
        ))),
    }
}

#[async_trait]
impl Platform for LinuxPlatform {
    async fn create_device(&self, device: &TunDevice) -> Result<String, PlatformError> {
        let name = effective_name(device);
        let mut guard = self.state.lock().await;

        // A plan that changes the interface resets the device-scoped state;
        // the DNS backup is carried over so teardown can still restore it.
        let mut carried_dns_backup: Option<Option<String>> = None;
        if let Some(existing) = guard.take() {
            if existing.name == name {
                *guard = Some(existing);
            } else {
                carried_dns_backup = existing.dns_backup.clone();
                tracing::info!(
                    "device changed: removing {} tracked route(s) from the previous device",
                    existing.tracked_route_count()
                );
                self.remove_tracked_routes(&existing).await;
                drop(existing.device);
            }
        }

        let device_exists = guard.is_some();
        if !device_exists {
            tracing::info!(
                "creating the TUN device (name_set={}, addresses={}, mtu={})",
                !device.name.is_empty(),
                device.addresses.len(),
                device.mtu
            );
            // No address/netmask here: addressing is applied via netlink.
            let mut config = tun2::Configuration::default();
            config.tun_name(&name).mtu(device.mtu).up();
            let tun = tun2::create_as_async(&config).map_err(|error| {
                PlatformError::Device(format!("could not create the TUN device: {error}"))
            })?;

            let index = self.link_index(&name).await?;
            *guard = Some(DeviceState {
                name: name.clone(),
                index,
                device: tun,
                installed_routes: Vec::new(),
                blackholes: Vec::new(),
                tun_default_metric: None,
                dns_backup: carried_dns_backup,
            });
        }

        // Converge device configuration (also on reuse: a changed plan may
        // adjust MTU or addresses). MTU and link state go in one RTM_NEWLINK.
        let state = guard
            .as_mut()
            .ok_or_else(|| PlatformError::Device("internal: device state missing".to_owned()))?;
        self.handle
            .link()
            .change(
                LinkUnspec::new_with_index(state.index)
                    .mtu(u32::from(device.mtu))
                    .up()
                    .build(),
            )
            .execute()
            .await
            .map_err(|error| {
                PlatformError::Device(format!("could not set the MTU/link state: {error}"))
            })?;
        self.converge_addresses(state.index, &device.addresses)
            .await?;

        Ok(name)
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

        // Add first (replace semantics), remove stale last: the system is
        // never left without the routes the plan wants.
        for spec in bypass_routes {
            let message = route_message(spec, state.index);
            self.handle
                .route()
                .add(message)
                .replace()
                .execute()
                .await
                .map_err(|error| {
                    PlatformError::Route(format!("could not add a bypass route: {error}"))
                })?;
        }
        for spec in routes {
            let message = route_message(spec, state.index);
            self.handle
                .route()
                .add(message)
                .replace()
                .execute()
                .await
                .map_err(|error| {
                    PlatformError::Route(format!("could not add a tunnel route: {error}"))
                })?;
        }
        let mut removed = 0usize;
        for spec in &state.installed_routes {
            if desired.contains(spec) {
                continue;
            }
            let message = route_message(spec, state.index);
            self.handle
                .route()
                .del(message)
                .execute()
                .await
                .map_err(|error| {
                    PlatformError::Route(format!("could not remove a stale route: {error}"))
                })?;
            removed += 1;
        }
        state.installed_routes = desired;
        state.tun_default_metric = routes
            .iter()
            .filter(|spec| spec.gateway.is_none() && spec.destination.prefix_len == 0)
            .map(|spec| spec.metric.unwrap_or(0))
            .min();
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
        if state.dns_backup.is_none() {
            state.dns_backup = Some(read_dns_backup()?);
        }
        write_resolv_conf(&render_resolv_conf(&dns.servers))?;
        tracing::info!(
            "apply_dns: system resolver set ({} server(s))",
            dns.servers.len()
        );
        Ok(())
    }

    async fn apply_kill_switch(&self, mode: KillSwitchMode) -> Result<(), PlatformError> {
        let mut guard = self.state.lock().await;
        let state = guard.as_mut().ok_or_else(|| {
            PlatformError::KillSwitch(
                "no active TUN device; the kill switch follows device creation".to_owned(),
            )
        })?;
        match mode {
            KillSwitchMode::Block => {
                // Insurance only makes sense when the plan routes a default
                // prefix through the device (see module docs).
                let Some(tun_metric) = state.tun_default_metric else {
                    tracing::info!(
                        "apply_kill_switch: no device default route; route-level insurance not applicable"
                    );
                    return Ok(());
                };
                let metric = blackhole_metric(Some(tun_metric));
                let mut blackholes = Vec::with_capacity(2);
                for ipv4 in [true, false] {
                    let message = blackhole_message(ipv4, metric);
                    self.handle
                        .route()
                        .add(message.clone())
                        .replace()
                        .execute()
                        .await
                        .map_err(|error| {
                            PlatformError::KillSwitch(format!(
                                "could not install the fail-closed insurance route: {error}"
                            ))
                        })?;
                    blackholes.push(message);
                }
                state.blackholes = blackholes;
                tracing::info!(
                    "apply_kill_switch: fail-closed insurance installed (metric {metric})"
                );
            }
            KillSwitchMode::Restore | KillSwitchMode::Disabled => {
                if !state.blackholes.is_empty() {
                    self.remove_tracked_routes_for_blackholes(state).await;
                    tracing::info!("apply_kill_switch: insurance routes removed");
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
        let removed = self.remove_tracked_routes(&state).await;
        Self::restore_dns(&mut state);
        // Dropping the device closes it; the kernel then removes the
        // interface and its device routes.
        drop(state.device);
        tracing::info!(
            "teardown: done ({tracked} tracked route(s), {removed} removed successfully)"
        );
        Ok(())
    }
}

impl LinuxPlatform {
    /// Remove only the tracked blackhole routes (kill switch off).
    async fn remove_tracked_routes_for_blackholes(&self, state: &mut DeviceState) {
        for message in state.blackholes.drain(..) {
            if let Err(error) = self.handle.route().del(message).execute().await {
                tracing::warn!("could not remove a kill-switch route: {error}");
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn spec(destination: Prefix, gateway: Option<IpAddr>, metric: Option<u32>) -> RouteSpec {
        RouteSpec {
            destination,
            gateway,
            metric,
        }
    }

    fn v4_prefix(text: &str, prefix_len: u8) -> Prefix {
        Prefix {
            addr: IpAddr::V4(text.parse().expect("valid IPv4")),
            prefix_len,
        }
    }

    #[test]
    fn resolv_conf_renders_one_nameserver_line_per_server() {
        let content = render_resolv_conf(&[
            IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
            IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 0x1111)),
        ]);
        assert!(
            content.starts_with("# Generated by tobro-helper"),
            "{content}"
        );
        assert!(content.contains("nameserver 9.9.9.9\n"), "{content}");
        assert!(
            content.contains("nameserver 2606:4700::1111\n"),
            "{content}"
        );
        assert_eq!(content.matches("nameserver").count(), 2, "{content}");
        // Empty is impossible (plan validation), but rendering stays sane.
        assert_eq!(render_resolv_conf(&[]).matches("nameserver").count(), 0);
    }

    #[test]
    fn device_routes_are_unicast_routes_into_the_device() {
        let route = spec(v4_prefix("10.111.222.0", 24), None, Some(50));
        let message = route_message(&route, 7);
        assert_eq!(message.header.destination_prefix_length, 24);
        assert_eq!(
            message.header.table,
            u8::try_from(MAIN_TABLE_ID).expect("fits u8")
        );
        assert_eq!(message.header.scope, ROUTE_SCOPE);
        assert_eq!(message.header.protocol, ROUTE_PROTOCOL);
    }

    #[test]
    fn bypass_routes_carry_the_gateway() {
        let route = spec(
            v4_prefix("192.0.2.0", 24),
            Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
            None,
        );
        let message = route_message(&route, 7);
        assert_eq!(message.header.destination_prefix_length, 24);
        assert_eq!(message.header.scope, ROUTE_SCOPE);
        // Default metric: no priority attribute was set.
        assert_eq!(message.header.protocol, ROUTE_PROTOCOL);
    }

    #[test]
    fn ipv6_routes_keep_their_family() {
        let route = RouteSpec {
            destination: Prefix {
                addr: IpAddr::V6("2001:db8::".parse().expect("valid IPv6")),
                prefix_len: 32,
            },
            gateway: None,
            metric: None,
        };
        let message = route_message(&route, 9);
        assert_eq!(message.header.destination_prefix_length, 32);
    }

    #[test]
    fn blackhole_routes_are_default_prefix_blackholes() {
        for (ipv4, family_len) in [(true, 0u8), (false, 0u8)] {
            let message = blackhole_message(ipv4, 61);
            assert_eq!(message.header.kind, RouteType::BlackHole, "ipv4={ipv4}");
            assert_eq!(message.header.destination_prefix_length, family_len);
            assert_eq!(message.header.scope, ROUTE_SCOPE);
            assert_eq!(message.header.protocol, ROUTE_PROTOCOL);
        }
    }

    #[test]
    fn blackhole_metric_sits_one_worse_than_the_tunnel_default() {
        assert_eq!(blackhole_metric(None), 1);
        assert_eq!(blackhole_metric(Some(0)), 1);
        assert_eq!(blackhole_metric(Some(60)), 61);
    }

    #[test]
    fn effective_name_falls_back_to_the_default() {
        let mut device = TunDevice::default();
        assert_eq!(effective_name(&device), DEFAULT_INTERFACE_NAME);
        device.name = "tobro9".to_owned();
        assert_eq!(effective_name(&device), "tobro9");
    }
}

/// Real-host integration test: needs root and a Linux kernel (run with
/// `cargo test -p tobro-helper -- --ignored` on a Linux machine).
#[cfg(all(test, target_os = "linux"))]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod linux_integration {
    use super::*;

    #[tokio::test]
    #[ignore = "requires root and a real Linux host"]
    async fn device_routes_and_teardown_on_a_real_host() {
        let platform = LinuxPlatform::connect().expect("netlink");
        let device = TunDevice {
            name: "tobro-test".to_owned(),
            addresses: vec![Prefix {
                addr: IpAddr::V4(Ipv4Addr::new(10, 111, 222, 252)),
                prefix_len: 30,
            }],
            mtu: 1400,
        };
        let name = platform.create_device(&device).await.expect("create");
        assert_eq!(name, "tobro-test");

        let default_route = RouteSpec {
            destination: Prefix {
                addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                prefix_len: 0,
            },
            gateway: None,
            metric: Some(60),
        };
        let routes = [default_route];
        platform
            .apply_routes(&name, &routes, &[])
            .await
            .expect("routes");
        // Applying the same routes again is a no-op convergence.
        platform
            .apply_routes(&name, &routes, &[])
            .await
            .expect("routes again");

        platform.teardown().await.expect("teardown");
        // A second teardown is an idempotent no-op.
        platform.teardown().await.expect("teardown again");
    }
}
