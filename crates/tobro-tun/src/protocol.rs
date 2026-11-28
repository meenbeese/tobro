//! Helper protocol message types and their validation.
//!
//! The types here are the entire privileged command surface. Anything a
//! request carries is validated by [`TunnelPlan::validate`] (client-side,
//! before sending) and again by the helper on receipt; the helper must treat
//! decoded values as untrusted until validated.

use std::net::{IpAddr, SocketAddr};

use serde::{Deserialize, Serialize};

use crate::HelperError;

/// Helper protocol version. Bumped on incompatible changes; the handshake
/// rejects mismatches instead of guessing.
///
/// v2 adds the routing engine's forwarding configuration to the plan
/// ([`TunnelPlan::forwarding`] / [`TunnelPlan::udp_policy`]): a v2 daemon
/// requires a v2 helper because a v1 helper would apply a plan it cannot
/// actually forward traffic for.
pub const PROTOCOL_VERSION: u32 = 2;

/// Largest number of routes (tunnel + bypass combined) accepted in a plan.
pub const MAX_ROUTES: usize = 512;

/// Largest number of addresses accepted on the TUN device.
pub const MAX_DEVICE_ADDRESSES: usize = 4;

/// Largest number of DNS servers accepted in a plan.
pub const MAX_DNS_SERVERS: usize = 8;

/// Minimum TUN interface MTU (IPv6 needs 1280; 576 keeps IPv4-only usable).
pub const MIN_TUN_MTU: u16 = 576;

/// Maximum TUN interface MTU (largest IP payload that fits the 16-bit IP
/// total-length field).
pub const MAX_TUN_MTU: u16 = 65521;

/// Default TUN interface MTU.
pub const DEFAULT_TUN_MTU: u16 = 1500;

/// Default TUN interface name the helper should use when the plan does not
/// name one. Platforms may adjust (macOS assigns `utunN`).
pub const DEFAULT_INTERFACE_NAME: &str = "tobro0";

/// The tunnel's reserved IPv4 addressing (`10.111.222.252/30`); the
/// interception DNS resolver at `10.111.222.254` sits inside it. Bypass
/// routes must never cover this subnet: its traffic belongs to the tunnel
/// itself.
pub const TUNNEL_PREFIX_V4: &str = "10.111.222.252/30";
/// The tunnel's reserved IPv6 addressing (`fd6b:626f:6272:6f::/64`,
/// containing the interception resolver at `...::2`).
pub const TUNNEL_PREFIX_V6: &str = "fd6b:626f:6272:6f::/64";

/// Longest accepted interface name (Linux `IFNAMSIZ - 1`).
pub const MAX_INTERFACE_NAME_LEN: usize = 15;

/// Numeric rejection codes carried by [`HelperResponse::Rejected`].
///
/// Keep this list closed and documented; unknown codes are a helper bug.
pub mod reject_codes {
    /// The request failed validation (bad prefix, interface name, counts...).
    pub const VALIDATION: u32 = 1;
    /// The helper build/platform cannot perform the requested operation.
    pub const UNSUPPORTED: u32 = 2;
    /// Creating/configuring the TUN device failed.
    pub const DEVICE_ERROR: u32 = 3;
    /// Installing or removing routes failed.
    pub const ROUTE_ERROR: u32 = 4;
    /// Applying or reverting DNS settings failed.
    pub const DNS_ERROR: u32 = 5;
    /// Installing or removing the kill switch failed.
    pub const KILL_SWITCH_ERROR: u32 = 6;
    /// The helper is busy (e.g. another client holds it) or shutting down.
    pub const BUSY: u32 = 7;
    /// Unexpected internal failure. Also used for unparseable requests.
    pub const INTERNAL: u32 = 8;
    /// The caller failed the peer-identity check (wrong user, no handshake).
    pub const UNAUTHORIZED: u32 = 9;
}

/// A request the daemon may send to the helper. This enum is the complete
/// command set; there is deliberately nothing else.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HelperRequest {
    /// Handshake: agree on the protocol version before anything privileged.
    Handshake {
        /// The client's [`PROTOCOL_VERSION`].
        protocol_version: u32,
    },
    /// Apply the full desired routing state. Idempotent: sending the same
    /// plan twice is a no-op, sending a changed plan converges to it.
    ApplyPlan {
        /// The complete desired state.
        plan: TunnelPlan,
    },
    /// Ask for the helper's current state (also serves as a heartbeat).
    Status {},
    /// Undo everything the helper did (device, routes, DNS, kill switch).
    Teardown {},
}

/// The helper's reply to exactly one request. Response tags never collide
/// with request tags (`status_ok` vs `status`) so both roles can be
/// decoded from one wire type without ambiguity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HelperResponse {
    /// Reply to [`HelperRequest::Handshake`].
    HandshakeOk {
        /// The helper's [`PROTOCOL_VERSION`].
        protocol_version: u32,
        /// Helper build version (informational).
        helper_version: String,
    },
    /// Reply to [`HelperRequest::ApplyPlan`].
    Applied {
        /// Monotonic generation counter, incremented on every applied plan
        /// and teardown. Lets the daemon detect helper restarts.
        generation: u64,
        /// Interface name of the TUN device carrying the plan.
        interface: String,
    },
    /// Reply to [`HelperRequest::Status`].
    #[serde(rename = "status_ok")]
    Status {
        /// Current helper state.
        state: HelperStatus,
    },
    /// Reply to [`HelperRequest::Teardown`].
    TornDown {
        /// Generation after the teardown (the counter still increments).
        generation: u64,
    },
    /// Refusal. The `code` is one of [`reject_codes`]; the message is
    /// human-readable and safe to surface (never contains packet data).
    Rejected {
        /// One of [`reject_codes`].
        code: u32,
        /// Human-readable explanation.
        message: String,
    },
}

/// Any helper wire message. The client asserts the role/shape of the
/// response it awaits; a mismatch is a protocol error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum HelperMessage {
    /// A daemon -> helper request.
    Request(HelperRequest),
    /// A helper -> daemon response.
    Response(HelperResponse),
}

/// Helper state reported by `status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HelperStatus {
    /// True while a plan is applied (device exists, routes/DNS live).
    pub active: bool,
    /// Current generation counter.
    pub generation: u64,
    /// Interface name of the active TUN device, when active.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
    /// Kill switch currently enforced by the active plan.
    pub kill_switch: KillSwitchMode,
    /// Unix timestamp (ms) of the last applied plan.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub applied_at_ms: Option<u64>,
}

impl Default for HelperStatus {
    fn default() -> Self {
        Self {
            active: false,
            generation: 0,
            interface: None,
            kill_switch: KillSwitchMode::Disabled,
            applied_at_ms: None,
        }
    }
}

/// Kill switch mode (F-20). Names mirror the `[tun]` config policy values
/// (`restore`/`block`); `disabled` covers plans that must not change the
/// system-wide fail state (used by diagnostics/tests only).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KillSwitchMode {
    /// No kill switch enforcement with this plan.
    #[default]
    Disabled,
    /// On tunnel failure, restore normal networking.
    Restore,
    /// Fail closed: on tunnel failure, block traffic until the tunnel is
    /// restored or the user disables TUN mode.
    Block,
}

impl KillSwitchMode {
    /// Whether a tunnel loss (the daemon or helper being killed, the device
    /// disappearing) must leave traffic **blocked** rather than restoring
    /// normal networking. This is the kill-switch policy reading of
    /// `Killing the daemon/helper restores networking or blocks it per the
    /// chosen policy`: `block` fails closed, `restore`/`disabled` restore.
    pub fn blocks_on_tunnel_loss(self) -> bool {
        matches!(self, KillSwitchMode::Block)
    }

    /// Whether a tunnel loss must restore pre-tunnel networking. Inverse of
    /// [`KillSwitchMode::blocks_on_tunnel_loss`]; `disabled` restores because
    /// no kill switch was installed to hold anything blocked.
    pub fn restores_on_tunnel_loss(self) -> bool {
        !self.blocks_on_tunnel_loss()
    }
}

/// A validated IP prefix (`addr/prefix_len`) with host bits zeroed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Prefix {
    /// Network address (host bits zeroed).
    pub addr: IpAddr,
    /// Prefix length in bits (<= 32 for IPv4, <= 128 for IPv6).
    pub prefix_len: u8,
}

impl Prefix {
    /// Parse `addr/prefix_len` with strict validation.
    pub fn parse(text: &str) -> Result<Self, HelperError> {
        let invalid =
            |reason: String| HelperError::Validation(format!("invalid prefix {text:?}: {reason}"));
        let Some((addr_raw, len_raw)) = text.split_once('/') else {
            return Err(invalid("expected the `addr/prefix_len` form".to_owned()));
        };
        let addr: IpAddr = addr_raw
            .parse()
            .map_err(|_| invalid("expected a literal IPv4/IPv6 address".to_owned()))?;
        let prefix_len: u8 = len_raw
            .parse()
            .map_err(|_| invalid("expected an integer prefix length".to_owned()))?;
        let prefix = Self { addr, prefix_len };
        prefix.validate().map_err(|_| {
            invalid(match prefix.max_prefix_len() {
                32 => "prefix length must be at most 32 and host bits must be zeroed".to_owned(),
                _ => "prefix length must be at most 128 and host bits must be zeroed".to_owned(),
            })
        })?;
        Ok(prefix)
    }

    /// Validate bounds and the host-bits-zeroed invariant.
    pub fn validate(&self) -> Result<(), HelperError> {
        let invalid =
            |reason: String| HelperError::Validation(format!("invalid prefix {self:?}: {reason}"));
        let max = self.max_prefix_len();
        if u32::from(self.prefix_len) > max {
            return Err(invalid(format!(
                "prefix length must be at most {max}, got {}",
                self.prefix_len
            )));
        }
        if self.host_bits_set() {
            return Err(invalid("host bits must be zeroed".to_owned()));
        }
        Ok(())
    }

    /// Maximum prefix length for the address family.
    pub fn max_prefix_len(&self) -> u32 {
        match self.addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        }
    }

    /// True when bits beyond the prefix are set.
    pub fn host_bits_set(&self) -> bool {
        match self.addr {
            IpAddr::V4(a) => {
                let mask = v4_mask(self.prefix_len);
                u32::from(a) & !mask != 0
            }
            IpAddr::V6(a) => {
                let mask = v6_mask(self.prefix_len);
                u128::from(a) & !mask != 0
            }
        }
    }

    /// The prefix in canonical `addr/prefix_len` text form.
    pub fn text(&self) -> String {
        format!("{}/{}", self.addr, self.prefix_len)
    }

    /// True when `ip` belongs to this prefix (same address family).
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(addr)) => {
                u32::from(addr) & v4_mask(self.prefix_len) == u32::from(net)
            }
            (IpAddr::V6(net), IpAddr::V6(addr)) => {
                u128::from(addr) & v6_mask(self.prefix_len) == u128::from(net)
            }
            _ => false, // different families never nest
        }
    }

    /// True when this prefix and `other` cover at least one shared address
    /// (same family, neither strictly disjoint).
    pub fn overlaps(&self, other: &Prefix) -> bool {
        match (self.addr, other.addr) {
            (IpAddr::V4(net), IpAddr::V4(other_net)) => {
                let mask = v4_mask(self.prefix_len.min(other.prefix_len));
                u32::from(net) & mask == u32::from(other_net) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(other_net)) => {
                let mask = v6_mask(self.prefix_len.min(other.prefix_len));
                u128::from(net) & mask == u128::from(other_net) & mask
            }
            _ => false, // different families never overlap
        }
    }
}

/// Dotted-quad mask for an IPv4 prefix length.
fn v4_mask(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        return 0;
    }
    u32::MAX << (32 - u32::from(prefix_len))
}

/// 128-bit mask for an IPv6 prefix length.
fn v6_mask(prefix_len: u8) -> u128 {
    if prefix_len == 0 {
        return 0;
    }
    u128::MAX << (128 - u32::from(prefix_len))
}

/// Validate an interface name: 1–[`MAX_INTERFACE_NAME_LEN`] characters from
/// `[A-Za-z0-9_-]`. An empty string means "helper's platform default".
pub fn validate_interface_name(name: &str) -> Result<(), HelperError> {
    let invalid = |reason: String| {
        HelperError::Validation(format!("invalid interface name {name:?}: {reason}"))
    };
    if name.len() > MAX_INTERFACE_NAME_LEN {
        return Err(invalid(format!(
            "must be at most {MAX_INTERFACE_NAME_LEN} characters"
        )));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(invalid(
            "must contain only ASCII letters, digits, hyphens, and underscores".to_owned(),
        ));
    }
    Ok(())
}

/// True when `addr` is a sane system-wide DNS resolver address: a global,
/// non-loopback, non-link-local, non-multicast unicast IP. Private ranges
/// are allowed on purpose (LAN resolvers reachable via bypass routes are a
/// legitimate setup); loopback is rejected because the helper never points
/// the system resolver at a service only the daemon should reach.
pub fn is_usable_dns_server(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(a) => {
            !a.is_loopback()
                && !a.is_unspecified()
                && !a.is_broadcast()
                && !a.is_multicast()
                && !a.is_link_local()
        }
        IpAddr::V6(a) => !a.is_loopback() && !a.is_unspecified() && !a.is_multicast(),
    }
}

/// Validate a split-tunnel bypass destination: it must be a real remote
/// range that can leave the host, and it must not cover the tunnel's own
/// wiring (the device's on-link subnets or the interception DNS servers).
fn validate_bypass_destination(
    index: usize,
    destination: Prefix,
    device_addresses: &[Prefix],
    dns: &DnsConfig,
) -> Result<(), HelperError> {
    let invalid =
        |reason: String| HelperError::Validation(format!("plan.bypass_routes[{index}]: {reason}"));
    // Loopback, link-local, unspecified, and multicast/broadcast never leave
    // the host, so "bypassing" them is either a no-op or a config bug.
    let rejected = match destination.addr {
        IpAddr::V4(a) => {
            a.is_loopback()
                || a.is_unspecified()
                || a.is_link_local()
                || a.is_multicast()
                || a.is_broadcast()
        }
        IpAddr::V6(a) => {
            a.is_loopback() || a.is_unspecified() || a.is_multicast() || a.is_unicast_link_local()
        }
    };
    if rejected {
        return Err(invalid(format!(
            "{} is loopback/link-local/multicast/broadcast and cannot be a split-tunnel bypass destination",
            destination.text()
        )));
    }
    // The destination must not cover the tunnel's on-link subnets: those
    // addresses belong to the tunnel device itself (including the reserved
    // tunnel prefixes and the interception DNS resolver inside them).
    for subnet in device_addresses {
        if destination.overlaps(subnet) {
            return Err(invalid(format!(
                "{} overlaps the tunnel subnet {} (the tunnel's own addresses cannot be bypassed)",
                destination.text(),
                subnet.text()
            )));
        }
    }
    // ... and must not cover any resolver the tunnel points the system at.
    for server in &dns.servers {
        if destination.contains(*server) {
            return Err(invalid(format!(
                "{} covers the tunnel DNS resolver {server}",
                destination.text()
            )));
        }
    }
    Ok(())
}

/// Validate a split-tunnel bypass gateway: it must sit outside the tunnel's
/// own subnets and must not be loopback. Link-local gateways are allowed
/// (IPv6 LANs commonly use them); the helper encodes the scope.
fn validate_bypass_gateway(
    index: usize,
    gateway: IpAddr,
    device_addresses: &[Prefix],
) -> Result<(), HelperError> {
    let invalid =
        |reason: String| HelperError::Validation(format!("plan.bypass_routes[{index}]: {reason}"));
    if gateway.is_loopback() {
        return Err(invalid(
            "the gateway must not be a loopback address".to_owned(),
        ));
    }
    for subnet in device_addresses {
        if subnet.contains(gateway) {
            return Err(invalid(format!(
                "gateway {gateway} is inside the tunnel subnet {} (bypass traffic must leave through the physical network)",
                subnet.text()
            )));
        }
    }
    Ok(())
}

/// The TUN device to create or reuse.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TunDevice {
    /// Interface name; empty means the helper's platform default. Non-empty
    /// names are validated by [`validate_interface_name`].
    pub name: String,
    /// Addresses assigned to the device (1..[`MAX_DEVICE_ADDRESSES`]; one per
    /// family at most in practice).
    pub addresses: Vec<Prefix>,
    /// Interface MTU.
    pub mtu: u16,
}

impl Default for TunDevice {
    fn default() -> Self {
        Self {
            name: String::new(),
            addresses: Vec::new(),
            mtu: DEFAULT_TUN_MTU,
        }
    }
}

/// One route entry: a destination prefix pointed at the TUN device itself
/// (`gateway: None`) or at a next-hop gateway (split-tunnel bypass routes
/// point at the pre-existing physical gateway).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteSpec {
    /// Destination prefix (host bits zeroed).
    pub destination: Prefix,
    /// Next-hop gateway; `None` routes via the TUN device itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway: Option<IpAddr>,
    /// Optional route metric.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metric: Option<u32>,
}

/// System-wide DNS settings applied while the tunnel is up.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsConfig {
    /// Resolver IP literals (1..[`MAX_DNS_SERVERS`]); DNS runs on port 53.
    pub servers: Vec<IpAddr>,
}

/// UDP handling policy for the routing engine (mirrors `[tun] udp_policy`).
///
/// Tor (Arti) carries no UDP, so UDP can only be intercepted locally (DNS) or
/// dropped. There is deliberately no "forward UDP directly" option: that
/// would leak destinations outside the tunnel and defeat the milestone goal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UdpPolicy {
    /// Intercept DNS queries (any UDP destination port 53) and relay them to
    /// the daemon's local DNS resolver ([`Forwarding::dns`]); drop all other
    /// UDP. QUIC/WebRTC-capable applications fall back to TCP. Default.
    #[default]
    DnsOnly,
    /// Drop all UDP, including DNS interception. Only TCP connections work.
    BlockAll,
}

/// Where the routing engine forwards the tunnel's traffic: the daemon's
/// local listeners, on loopback only.
///
/// The helper (running as root/system) never talks to the network directly;
/// every forwarded byte leaves through the unprivileged daemon's Tor
/// listeners. Loopback-only addresses are validated because a non-loopback
/// target would make the privileged helper an open proxy reachable from
/// other machines.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Forwarding {
    /// The daemon's local SOCKS5 listener (also carries HTTP CONNECT).
    /// TCP flows from the tunnel are forwarded here via SOCKS5 CONNECT.
    pub socks: SocketAddr,
    /// The daemon's local UDP DNS resolver. Required by
    /// [`UdpPolicy::DnsOnly`] plans (the interception target); absent for
    /// `BlockAll` plans, where nothing is relayed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<SocketAddr>,
}

impl Forwarding {
    /// Validate: loopback-only, non-zero ports. Decoded values are untrusted.
    pub fn validate(&self) -> Result<(), HelperError> {
        let invalid = |what: &str, reason: String| {
            HelperError::Validation(format!("plan.forwarding.{what}: {reason}"))
        };
        if !self.socks.ip().is_loopback() {
            return Err(invalid(
                "socks",
                format!(
                    "{} must be a loopback address (the helper only forwards to the local daemon)",
                    self.socks.ip()
                ),
            ));
        }
        if self.socks.port() == 0 {
            return Err(invalid("socks", "the port must not be 0".to_owned()));
        }
        if let Some(dns) = self.dns {
            if !dns.ip().is_loopback() {
                return Err(invalid(
                    "dns",
                    format!(
                        "{} must be a loopback address (the helper only forwards to the local daemon)",
                        dns.ip()
                    ),
                ));
            }
            if dns.port() == 0 {
                return Err(invalid("dns", "the port must not be 0".to_owned()));
            }
        }
        Ok(())
    }
}

/// The complete desired routing state. This is the only privileged payload:
/// the helper converges the system to it, so crash recovery is a plain
/// re-send rather than a replay of deltas.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunnelPlan {
    /// The TUN device to create/reuse.
    pub device: TunDevice,
    /// Routes pointed into the tunnel (typically the default route).
    pub routes: Vec<RouteSpec>,
    /// Routes pointed away from the tunnel at a real gateway (split
    /// tunneling; the daemon resolves domain rules to prefixes first).
    pub bypass_routes: Vec<RouteSpec>,
    /// DNS settings for the tunnel lifetime.
    pub dns: DnsConfig,
    /// Kill switch behavior for the tunnel lifetime.
    pub kill_switch: KillSwitchMode,
    /// UDP handling policy for the routing engine.
    #[serde(default, skip_serializing_if = "is_default_udp_policy")]
    pub udp_policy: UdpPolicy,
    /// Where the routing engine forwards the tunnel's traffic. `None` is a
    /// fail-closed plan: the device is up but nothing reads it, so traffic is
    /// dropped rather than forwarded (diagnostics/tests only; the daemon
    /// always sets forwarding).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forwarding: Option<Forwarding>,
}

/// Serde helper: serializes the default UDP policy as absent (wire noise).
fn is_default_udp_policy(policy: &UdpPolicy) -> bool {
    *policy == UdpPolicy::default()
}

impl TunnelPlan {
    /// Validate every field. Both sides run this: the client before sending,
    /// the helper after decoding (decoded values are untrusted).
    pub fn validate(&self) -> Result<(), HelperError> {
        if let Err(error) = validate_interface_name(&self.device.name) {
            return Err(HelperError::Validation(format!(
                "plan.device.name: {}",
                strip_prefix(error)
            )));
        }
        if self.device.addresses.is_empty() {
            return Err(HelperError::Validation(
                "plan.device.addresses must contain at least one address".to_owned(),
            ));
        }
        if self.device.addresses.len() > MAX_DEVICE_ADDRESSES {
            return Err(HelperError::Validation(format!(
                "plan.device.addresses must contain at most {MAX_DEVICE_ADDRESSES} addresses, got {}",
                self.device.addresses.len()
            )));
        }
        let mut families = std::collections::HashSet::new();
        for (i, address) in self.device.addresses.iter().enumerate() {
            address.validate().map_err(|e| {
                HelperError::Validation(format!("plan.device.addresses[{i}]: {}", strip_prefix(e)))
            })?;
            if !families.insert(address.addr) {
                return Err(HelperError::Validation(format!(
                    "plan.device.addresses[{i}]: duplicate address {}",
                    address.addr
                )));
            }
        }
        if !(MIN_TUN_MTU..=MAX_TUN_MTU).contains(&self.device.mtu) {
            return Err(HelperError::Validation(format!(
                "plan.device.mtu must be between {MIN_TUN_MTU} and {MAX_TUN_MTU}, got {}",
                self.device.mtu
            )));
        }
        let route_count = self.routes.len() + self.bypass_routes.len();
        if route_count > MAX_ROUTES {
            return Err(HelperError::Validation(format!(
                "plan routes must contain at most {MAX_ROUTES} entries (routes + bypass_routes), got {route_count}"
            )));
        }
        for (section, routes) in [
            ("routes", &self.routes),
            ("bypass_routes", &self.bypass_routes),
        ] {
            let bypass = section == "bypass_routes";
            for (i, route) in routes.iter().enumerate() {
                route.destination.validate().map_err(|e| {
                    HelperError::Validation(format!("plan.{section}[{i}]: {}", strip_prefix(e)))
                })?;
                if let Some(gateway) = route.gateway {
                    if gateway.is_unspecified() {
                        return Err(HelperError::Validation(format!(
                            "plan.{section}[{i}]: gateway must not be the unspecified address"
                        )));
                    }
                    if gateway_family(gateway) != gateway_family(route.destination.addr) {
                        return Err(HelperError::Validation(format!(
                            "plan.{section}[{i}]: gateway {gateway} must match the destination address family"
                        )));
                    }
                    if bypass {
                        validate_bypass_gateway(i, gateway, &self.device.addresses)?;
                    }
                }
                if bypass {
                    validate_bypass_destination(
                        i,
                        route.destination,
                        &self.device.addresses,
                        &self.dns,
                    )?;
                }
            }
        }
        let mut destinations = std::collections::HashSet::new();
        for (section, routes) in [
            ("routes", &self.routes),
            ("bypass_routes", &self.bypass_routes),
        ] {
            for (i, route) in routes.iter().enumerate() {
                if !destinations.insert(route.destination.text()) {
                    return Err(HelperError::Validation(format!(
                        "plan.{section}[{i}]: duplicate destination {}",
                        route.destination.text()
                    )));
                }
            }
        }
        if self.dns.servers.is_empty() {
            return Err(HelperError::Validation(
                "plan.dns.servers must contain at least one server".to_owned(),
            ));
        }
        if self.dns.servers.len() > MAX_DNS_SERVERS {
            return Err(HelperError::Validation(format!(
                "plan.dns.servers must contain at most {MAX_DNS_SERVERS} servers, got {}",
                self.dns.servers.len()
            )));
        }
        for (i, server) in self.dns.servers.iter().enumerate() {
            if !is_usable_dns_server(server) {
                return Err(HelperError::Validation(format!(
                    "plan.dns.servers[{i}]: {server} is not a usable system-wide resolver address (loopback/link-local/multicast/unspecified are rejected)"
                )));
            }
        }
        // Forwarding endpoints are loopback-only (the helper only ever talks
        // to the local daemon) and must be consistent with the UDP policy.
        if let Some(forwarding) = &self.forwarding {
            forwarding
                .validate()
                .map_err(|e| HelperError::Validation(strip_prefix(e)))?;
            if self.udp_policy == UdpPolicy::DnsOnly && forwarding.dns.is_none() {
                return Err(HelperError::Validation(
                    "plan.forwarding: a dns_only UDP policy requires a DNS forwarding target \
                     (the intercepted resolver traffic needs somewhere to go)"
                        .to_owned(),
                ));
            }
        }
        Ok(())
    }

    /// The interface the plan's device will use (the configured name, or the
    /// default when the plan leaves it empty).
    pub fn effective_interface(&self) -> &str {
        if self.device.name.is_empty() {
            DEFAULT_INTERFACE_NAME
        } else {
            &self.device.name
        }
    }
}

/// A gateway address's family marker, used for the same-family check.
fn gateway_family(addr: IpAddr) -> u8 {
    match addr {
        IpAddr::V4(_) => 4,
        IpAddr::V6(_) => 6,
    }
}

/// Validation errors are wrapped with context one level up; the inner
/// message already says "invalid prefix ...", so strip the wrapper for
/// cleaner nesting.
fn strip_prefix(error: HelperError) -> String {
    match error {
        HelperError::Validation(message) => message,
        other => other.to_string(),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn valid_prefix() -> Prefix {
        Prefix {
            addr: IpAddr::V4(Ipv4Addr::new(10, 111, 222, 0)),
            prefix_len: 24,
        }
    }

    fn route(destination: Prefix) -> RouteSpec {
        RouteSpec {
            destination,
            gateway: None,
            metric: None,
        }
    }

    #[test]
    fn prefix_parse_accepts_canonical_and_rejects_the_rest() {
        assert_eq!(
            Prefix::parse("10.111.222.0/24").expect("must parse"),
            valid_prefix()
        );
        assert_eq!(Prefix::parse("::/0").expect("must parse").prefix_len, 0);
        assert_eq!(
            Prefix::parse("2001:db8::/32").expect("must parse").addr,
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)),
        );
        // Host bits set are rejected.
        assert!(Prefix::parse("10.111.222.7/24").is_err());
        assert!(Prefix::parse("2001:db8::1/32").is_err());
        // Out-of-range lengths.
        assert!(Prefix::parse("10.0.0.0/33").is_err());
        assert!(Prefix::parse("::/129").is_err());
        // Not an address / no slash / not an integer.
        assert!(Prefix::parse("example.com/8").is_err());
        assert!(Prefix::parse("10.0.0.0").is_err());
        assert!(Prefix::parse("10.0.0.0/eight").is_err());
        // Round-trip through serde preserves the value.
        let json = serde_json::to_string(&valid_prefix()).expect("serialize");
        assert_eq!(
            serde_json::from_str::<Prefix>(&json).expect("deserialize"),
            valid_prefix()
        );
        // Host bits set via direct deserialization are caught by validate().
        let hostile: Prefix =
            serde_json::from_str(r#"{"addr":"10.111.222.7","prefix_len":24}"#).expect("parse");
        assert!(hostile.validate().is_err());
    }

    #[test]
    fn prefix_contains_and_overlaps() {
        let net = Prefix::parse("10.111.222.0/24").expect("parse");
        assert!(net.contains(IpAddr::V4(Ipv4Addr::new(10, 111, 222, 9))));
        assert!(!net.contains(IpAddr::V4(Ipv4Addr::new(10, 111, 223, 9))));
        assert!(!net.contains(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        let tunnel = Prefix::parse(TUNNEL_PREFIX_V4).expect("parse");
        assert!(tunnel.contains(IpAddr::V4(Ipv4Addr::new(10, 111, 222, 254))));
        // The tunnel's /30 sits inside the /24: they overlap.
        assert!(net.overlaps(&tunnel));

        let v6 = Prefix::parse("2001:db8::/32").expect("parse");
        assert!(v6.contains(IpAddr::V6(Ipv6Addr::new(
            0x2001, 0xdb8, 0xffff, 0, 0, 0, 0, 1
        ))));
        assert!(!v6.contains(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        let v6_tunnel = Prefix::parse(TUNNEL_PREFIX_V6).expect("parse");
        assert!(v6_tunnel.overlaps(&v6_tunnel));
        assert!(!v6.overlaps(&v6_tunnel));
        // Nested prefixes overlap.
        let narrow = Prefix::parse("10.111.222.64/26").expect("parse");
        assert!(narrow.overlaps(&net));
        assert!(net.overlaps(&narrow));
    }

    #[test]
    fn bypass_destinations_must_be_remote_ranges() {
        let sample = sample_plan();
        let addresses = sample.device.addresses.clone();
        let dns = sample.dns.clone();
        for (index, addr) in [
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V4(Ipv4Addr::new(169, 254, 9, 9)), // link-local
            IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)),   // multicast
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)), // link-local
            IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1)), // multicast
        ]
        .into_iter()
        .enumerate()
        {
            let destination = Prefix {
                addr,
                prefix_len: match addr {
                    IpAddr::V4(_) => 24,
                    IpAddr::V6(_) => 64,
                },
            };
            assert!(
                validate_bypass_destination(index, destination, &addresses, &dns).is_err(),
                "{addr} must be rejected"
            );
        }
        // A normal remote prefix is accepted.
        validate_bypass_destination(
            0,
            Prefix::parse("192.0.2.0/24").expect("parse"),
            &addresses,
            &dns,
        )
        .expect("documented TEST-NET range must be accepted");
    }

    #[test]
    fn bypass_destinations_must_not_cover_tunnel_wiring() {
        let sample = sample_plan();
        let addresses = sample.device.addresses.clone(); // 10.111.222.0/24
        let dns = sample.dns.clone();
        // Overlapping the device subnet is refused...
        assert!(
            validate_bypass_destination(
                0,
                Prefix::parse("10.111.0.0/16").expect("parse"),
                &addresses,
                &dns,
            )
            .is_err()
        );
        // ... as is covering a configured resolver (even outside the
        // device subnets).
        let dns_outside = DnsConfig {
            servers: vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))],
        };
        assert!(
            validate_bypass_destination(
                0,
                Prefix::parse("9.9.0.0/16").expect("parse"),
                &addresses,
                &dns_outside,
            )
            .is_err()
        );
        // A disjoint remote prefix is fine.
        validate_bypass_destination(
            0,
            Prefix::parse("198.51.100.0/24").expect("parse"),
            &addresses,
            &dns,
        )
        .expect("disjoint remote prefix must be accepted");
    }

    #[test]
    fn bypass_gateways_must_sit_outside_the_tunnel() {
        let sample = sample_plan();
        let addresses = sample.device.addresses.clone(); // 10.111.222.0/24
        // Inside the tunnel subnet.
        assert!(
            validate_bypass_gateway(0, IpAddr::V4(Ipv4Addr::new(10, 111, 222, 254)), &addresses)
                .is_err()
        );
        // Loopback.
        assert!(validate_bypass_gateway(0, IpAddr::V4(Ipv4Addr::LOCALHOST), &addresses).is_err());
        assert!(validate_bypass_gateway(0, IpAddr::V6(Ipv6Addr::LOCALHOST), &addresses).is_err());
        // Link-local LAN gateway: legitimate (IPv6 LANs), accepted.
        validate_bypass_gateway(
            0,
            IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
            &addresses,
        )
        .expect("link-local gateway must be accepted");
        validate_bypass_gateway(0, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), &addresses)
            .expect("ordinary LAN gateway must be accepted");
    }

    #[test]
    fn interface_names_validate() {
        assert!(validate_interface_name("").is_ok()); // platform default
        assert!(validate_interface_name("tobro0").is_ok());
        assert!(validate_interface_name("utun9").is_ok());
        assert!(validate_interface_name("a_b-c1").is_ok());
        assert!(validate_interface_name(&"a".repeat(16)).is_err()); // too long
        assert!(validate_interface_name("a".repeat(15).as_str()).is_ok());
        assert!(validate_interface_name("to bro0").is_err());
        assert!(validate_interface_name("tobro0;rm").is_err());
        assert!(validate_interface_name("tobroö").is_err());
    }

    #[test]
    fn dns_servers_must_be_sane() {
        assert!(is_usable_dns_server(&IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))));
        assert!(is_usable_dns_server(&IpAddr::V4(Ipv4Addr::new(
            10, 0, 0, 1
        )))); // LAN resolver: allowed
        assert!(is_usable_dns_server(&IpAddr::V6(Ipv6Addr::new(
            0x2606, 0x4700, 0, 0, 0, 0, 0, 0x1111
        ))));
        // Loopback, unspecified, broadcast, link-local, multicast rejected.
        assert!(!is_usable_dns_server(&IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(!is_usable_dns_server(&IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
        assert!(!is_usable_dns_server(&IpAddr::V4(Ipv4Addr::BROADCAST)));
        assert!(!is_usable_dns_server(&IpAddr::V4(Ipv4Addr::new(
            169, 254, 1, 1
        ))));
        assert!(!is_usable_dns_server(&IpAddr::V4(Ipv4Addr::new(
            224, 0, 0, 1
        ))));
        assert!(!is_usable_dns_server(&IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    fn sample_plan() -> TunnelPlan {
        TunnelPlan {
            device: TunDevice {
                name: "tobro0".to_owned(),
                addresses: vec![valid_prefix()],
                mtu: DEFAULT_TUN_MTU,
            },
            routes: vec![route(Prefix {
                addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                prefix_len: 0,
            })],
            bypass_routes: vec![RouteSpec {
                destination: Prefix {
                    addr: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)),
                    prefix_len: 24,
                },
                gateway: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
                metric: Some(50),
            }],
            dns: DnsConfig {
                servers: vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))],
            },
            kill_switch: KillSwitchMode::Block,
            udp_policy: UdpPolicy::default(),
            forwarding: Some(loopback_forwarding()),
        }
    }

    /// Loopback forwarding endpoints as the daemon sends them.
    fn loopback_forwarding() -> Forwarding {
        Forwarding {
            socks: "127.0.0.1:9050".parse().expect("valid socket address"),
            dns: Some("127.0.0.1:9053".parse().expect("valid socket address")),
        }
    }

    #[test]
    fn forwarding_endpoints_must_be_loopback_with_ports() {
        let mut plan = sample_plan();
        plan.validate().expect("loopback forwarding must validate");

        // Non-loopback SOCKS target: the helper must never act as a network
        // proxy for other machines.
        plan.forwarding = Some(Forwarding {
            socks: "192.0.2.1:9050".parse().expect("valid socket address"),
            dns: plan.forwarding.as_ref().and_then(|f| f.dns),
        });
        assert!(plan.validate().is_err());

        // Non-loopback DNS target.
        let mut plan = sample_plan();
        plan.forwarding = Some(Forwarding {
            socks: "127.0.0.1:9050".parse().expect("valid socket address"),
            dns: Some("192.0.2.1:53".parse().expect("valid socket address")),
        });
        assert!(plan.validate().is_err());

        // Port 0 is never a real listener.
        let mut plan = sample_plan();
        plan.forwarding = Some(Forwarding {
            socks: "127.0.0.1:0".parse().expect("valid socket address"),
            dns: plan.forwarding.as_ref().and_then(|f| f.dns),
        });
        assert!(plan.validate().is_err());
    }

    #[test]
    fn dns_only_policy_requires_a_dns_forwarding_target() {
        let mut plan = sample_plan();
        plan.forwarding = Some(Forwarding {
            socks: plan.forwarding.as_ref().expect("set").socks,
            dns: None,
        });
        let error = plan.validate().expect_err("dns_only without DNS target");
        assert!(error.to_string().contains("forwarding"), "{error}");

        // BlockAll plans may omit the DNS target: nothing is relayed anyway.
        plan.udp_policy = UdpPolicy::BlockAll;
        plan.validate().expect("block_all without DNS target");
    }

    #[test]
    fn plans_without_forwarding_still_validate() {
        // A fail-closed plan (device up, nothing reads it) is legal; the
        // daemon always sets forwarding, tests and diagnostics may not.
        let mut plan = sample_plan();
        plan.forwarding = None;
        plan.validate().expect("no forwarding must validate");
    }

    #[test]
    fn plan_wire_format_keeps_the_new_fields_optional() {
        // v2 JSON with forwarding round-trips.
        let plan = sample_plan();
        let json = serde_json::to_string(&plan).expect("serialize");
        let decoded: TunnelPlan = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded, plan);
        assert_eq!(decoded.udp_policy, UdpPolicy::DnsOnly);
        assert!(decoded.forwarding.is_some());
        // The default UDP policy is omitted from the wire, and a plan without
        // forwarding (v1-shaped, or a fail-closed diagnostic plan) still
        // decodes to the defaults.
        let mut value = serde_json::to_value(&plan).expect("to value");
        let object = value.as_object_mut().expect("a plan is an object");
        assert!(object.remove("forwarding").is_some());
        assert!(object.remove("udp_policy").is_none(), "{json}");
        let decoded: TunnelPlan =
            serde_json::from_value(value).expect("deserialize without forwarding");
        assert_eq!(decoded.forwarding, None);
        assert_eq!(decoded.udp_policy, UdpPolicy::DnsOnly);
    }

    #[test]
    fn plans_validate_end_to_end() {
        let mut plan = sample_plan();
        plan.validate().expect("sample plan must validate");
        assert_eq!(plan.effective_interface(), "tobro0");

        // Empty interface name falls back to the default.
        plan.device.name = String::new();
        plan.validate().expect("default name must validate");
        assert_eq!(plan.effective_interface(), DEFAULT_INTERFACE_NAME);

        // MTU bounds.
        plan.device.mtu = MIN_TUN_MTU - 1;
        assert!(plan.validate().is_err());
        plan.device.mtu = MAX_TUN_MTU + 1;
        assert!(plan.validate().is_err());
        plan.device.mtu = DEFAULT_TUN_MTU;

        // No device addresses.
        let mut plan = sample_plan();
        plan.device.addresses.clear();
        assert!(plan.validate().is_err());

        // A second (IPv6) address is fine; a fifth address is not.
        let mut plan = sample_plan();
        plan.device.addresses.push(Prefix {
            addr: IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0)),
            prefix_len: 64,
        });
        assert!(plan.validate().is_ok());
        plan.device.addresses = (0..5)
            .map(|i| Prefix {
                addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, i as u8)),
                prefix_len: 32,
            })
            .collect();
        assert!(plan.validate().is_err());

        // Too many routes.
        let mut plan = sample_plan();
        plan.bypass_routes = (0..MAX_ROUTES)
            .map(|i| {
                route(Prefix {
                    addr: IpAddr::V4(Ipv4Addr::new(10, (i / 256) as u8, (i % 256) as u8, 0)),
                    prefix_len: 24,
                })
            })
            .collect();
        assert!(plan.validate().is_err());

        // Gateway/destination family mismatch.
        let mut plan = sample_plan();
        plan.bypass_routes[0].gateway = Some(IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert!(plan.validate().is_err());

        // Unspecified gateway.
        let mut plan = sample_plan();
        plan.bypass_routes[0].gateway = Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert!(plan.validate().is_err());

        // Duplicate destinations across sections.
        let mut plan = sample_plan();
        plan.bypass_routes[0].destination = plan.routes[0].destination;
        assert!(plan.validate().is_err());

        // No DNS servers / loopback DNS.
        let mut plan = sample_plan();
        plan.dns.servers.clear();
        assert!(plan.validate().is_err());
        let mut plan = sample_plan();
        plan.dns.servers = vec![IpAddr::V4(Ipv4Addr::LOCALHOST)];
        assert!(plan.validate().is_err());

        // Deserialization from hostile JSON (host bits set) is caught on
        // receipt by the helper-side validate.
        let hostile: TunnelPlan = serde_json::from_str(
            r#"{
                "device": {
                    "name": "tobro0",
                    "addresses": [{"addr": "10.111.222.7", "prefix_len": 24}],
                    "mtu": 1500
                },
                "routes": [],
                "bypass_routes": [],
                "dns": {"servers": ["9.9.9.9"]},
                "kill_switch": "block"
            }"#,
        )
        .expect("decodes");
        assert!(hostile.validate().is_err());
    }

    #[test]
    fn kill_switch_policy_for_tunnel_loss() {
        assert!(KillSwitchMode::Block.blocks_on_tunnel_loss());
        assert!(!KillSwitchMode::Block.restores_on_tunnel_loss());
        assert!(!KillSwitchMode::Restore.blocks_on_tunnel_loss());
        assert!(KillSwitchMode::Restore.restores_on_tunnel_loss());
        assert!(!KillSwitchMode::Disabled.blocks_on_tunnel_loss());
        assert!(KillSwitchMode::Disabled.restores_on_tunnel_loss());
    }
}
