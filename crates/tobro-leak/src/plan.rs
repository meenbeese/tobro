//! Test plans: realistic [`TunnelPlan`] values built around reserved test
//! prefixes.
//!
//! The safe scenarios never touch the host's default route. Instead they
//! route the benchmarking range `198.18.0.0/15` (RFC 2544) and the
//! documentation range `2001:db8::/32` into the tunnel. Those prefixes are
//! never used by real networks, so the host stays connected even if the
//! harness dies, while the full TUN path (device, routes, DNS interception)
//! is exercised exactly as the daemon would exercise it.
//!
//! The intrusive scenarios opt into `0.0.0.0/0` + `::/0`, matching a real
//! TUN session; they are gated behind an explicit flag/env var and are meant
//! for a dedicated test host or network namespace.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use tobro_tun::{
    DnsConfig, Forwarding, KillSwitchMode, Prefix, RouteSpec, TunDevice, TunnelPlan, UdpPolicy,
};

/// RFC 2544 benchmarking range, used as the safe IPv4 "internet".
pub const TEST_PREFIX_V4: &str = "198.18.0.0/15";
/// RFC 3849 documentation range, used as the safe IPv6 "internet".
pub const TEST_PREFIX_V6: &str = "2001:db8::/32";

/// The resolver the daemon points the system at while the tunnel is up
/// (re-exported from the protocol for coherence with the helper).
pub const TUNNEL_DNS_V4: Ipv4Addr = Ipv4Addr::new(10, 111, 222, 254);
/// IPv6 counterpart of [`TUNNEL_DNS_V4`].
pub const TUNNEL_DNS_V6: Ipv6Addr = Ipv6Addr::new(0xfd6b, 0x626f, 0x6272, 0x6f, 0, 0, 0, 2);

/// A concrete destination inside the test range.
pub fn test_v4_host() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1))
}

/// A concrete IPv6 destination inside the test range.
pub fn test_v6_host() -> IpAddr {
    IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1))
}

/// The IPv4 test *network* address (for route deletes, which match the
/// prefix, not a host route).
pub fn test_v4_network() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(198, 18, 0, 0))
}

/// The IPv6 test network address.
pub fn test_v6_network() -> IpAddr {
    IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0))
}

/// Which prefixes the plan points into the tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Routing {
    /// Reserved test prefixes only: safe on a live workstation.
    TestPrefixes,
    /// The real default routes: captures all host traffic. Intrusive.
    DefaultRoutes,
}

/// How the plan handles UDP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpMode {
    /// Intercept DNS, drop everything else (the daemon default).
    DnsOnly,
    /// Drop all UDP, DNS included.
    BlockAll,
}

/// The tunnel device's IPv4 address (mirrors [`TUNNEL_PREFIX_V4`]).
const TUNNEL_V4_PREFIX: Prefix = Prefix {
    addr: IpAddr::V4(Ipv4Addr::new(10, 111, 222, 252)),
    prefix_len: 30,
};
/// The tunnel device's IPv6 address (mirrors [`TUNNEL_PREFIX_V6`]).
const TUNNEL_V6_PREFIX: Prefix = Prefix {
    addr: IpAddr::V6(Ipv6Addr::new(0xfd6b, 0x626f, 0x6272, 0x6f, 0, 0, 0, 0)),
    prefix_len: 64,
};
const TEST_V4_PREFIX: Prefix = Prefix {
    addr: IpAddr::V4(Ipv4Addr::new(198, 18, 0, 0)),
    prefix_len: 15,
};
const TEST_V6_PREFIX: Prefix = Prefix {
    addr: IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0)),
    prefix_len: 32,
};
const DEFAULT_V4: Prefix = Prefix {
    addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    prefix_len: 0,
};
const DEFAULT_V6: Prefix = Prefix {
    addr: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    prefix_len: 0,
};

/// Build a plan the way `trobod` builds one: tunnel device with the protocol
/// addresses, the chosen routes, the tunnel DNS servers, and forwarding to a
/// local daemon.
pub fn build(
    routing: Routing,
    udp: UdpMode,
    forwarding: Option<Forwarding>,
    kill_switch: KillSwitchMode,
) -> TunnelPlan {
    let device = TunDevice {
        name: String::new(), // the helper's platform default
        addresses: vec![TUNNEL_V4_PREFIX, TUNNEL_V6_PREFIX],
        mtu: tobro_tun::DEFAULT_TUN_MTU,
    };
    let routes = match routing {
        Routing::TestPrefixes => vec![route(TEST_V4_PREFIX), route(TEST_V6_PREFIX)],
        Routing::DefaultRoutes => vec![route(DEFAULT_V4), route(DEFAULT_V6)],
    };
    TunnelPlan {
        device,
        routes,
        bypass_routes: Vec::new(),
        dns: DnsConfig {
            servers: vec![IpAddr::V4(TUNNEL_DNS_V4), IpAddr::V6(TUNNEL_DNS_V6)],
        },
        kill_switch,
        udp_policy: match udp {
            UdpMode::DnsOnly => UdpPolicy::DnsOnly,
            UdpMode::BlockAll => UdpPolicy::BlockAll,
        },
        // `DnsOnly` requires a DNS target; `BlockAll` must not have one.
        forwarding: forwarding.map(|forwarding| Forwarding {
            dns: (udp == UdpMode::DnsOnly)
                .then_some(forwarding.dns)
                .flatten(),
            ..forwarding
        }),
    }
}

/// One device route for `prefix`.
fn route(destination: Prefix) -> RouteSpec {
    RouteSpec {
        destination,
        gateway: None,
        metric: None,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn forwarding() -> Forwarding {
        Forwarding {
            socks: SocketAddr::from(([127, 0, 0, 1], 1080)),
            dns: Some(SocketAddr::from(([127, 0, 0, 1], 5353))),
        }
    }

    #[test]
    fn safe_plans_validate_and_never_touch_the_default_route() {
        for udp in [UdpMode::DnsOnly, UdpMode::BlockAll] {
            let plan = build(
                Routing::TestPrefixes,
                udp,
                Some(forwarding()),
                KillSwitchMode::Disabled,
            );
            plan.validate().expect("the safe plan must validate");
            assert!(
                plan.routes
                    .iter()
                    .all(|route| route.destination.prefix_len != 0),
                "safe plans must not include a default route"
            );
            assert_eq!(
                plan.forwarding.as_ref().and_then(|f| f.dns).is_some(),
                udp == UdpMode::DnsOnly,
                "the DNS target must follow the UDP policy"
            );
        }
    }

    #[test]
    fn intrusive_plans_capture_both_default_routes() {
        let plan = build(
            Routing::DefaultRoutes,
            UdpMode::DnsOnly,
            Some(forwarding()),
            KillSwitchMode::Block,
        );
        plan.validate().expect("the intrusive plan must validate");
        let lengths: Vec<u8> = plan
            .routes
            .iter()
            .map(|route| route.destination.prefix_len)
            .collect();
        assert_eq!(lengths, vec![0, 0]);
        assert_eq!(plan.kill_switch, KillSwitchMode::Block);
    }

    #[test]
    fn device_prefixes_mirror_the_protocol_constants() {
        assert_eq!(
            TUNNEL_V4_PREFIX,
            Prefix::parse(tobro_tun::TUNNEL_PREFIX_V4).expect("valid")
        );
        assert_eq!(
            TUNNEL_V6_PREFIX,
            Prefix::parse(tobro_tun::TUNNEL_PREFIX_V6).expect("valid")
        );
    }

    #[test]
    fn test_hosts_are_inside_the_test_prefixes() {
        let v4 = Prefix::parse(TEST_PREFIX_V4).expect("valid");
        let v6 = Prefix::parse(TEST_PREFIX_V6).expect("valid");
        assert!(v4.contains(test_v4_host()));
        assert!(v6.contains(test_v6_host()));
        assert!(!v4.contains(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
    }
}
