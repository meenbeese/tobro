//! Route-table probes used by the leak assertions.
//!
//! A leak test needs ground truth about where the kernel *would* send a
//! packet, independent of what the helper believes it installed. These
//! lookups read the live routing table (no privileges required):
//!
//! - macOS: `PF_ROUTE` via [`tobro_osapi::bsd_route::route_lookup`].
//! - Windows: iphlpapi `GetBestRoute2` via
//!   [`tobro_osapi::win_route::best_route`].
//! - Linux: an `RTM_GETROUTE` netlink request (the same kernel interface
//!   the helper's backend uses for route convergence).
//!
//! Linux also exposes a route delete, used by the resume/sleep-wake
//! scenario to simulate kernel state loss (suspend drops route entries).

use std::net::IpAddr;

use anyhow::{Context, Result};

/// Where the kernel would send a packet for one destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Egress {
    /// A regular route through this interface index.
    Interface(u32),
    /// A blackhole route (Linux kill-switch insurance).
    Blackhole,
    /// No route at all (for example, an isolated network namespace).
    Unreachable,
}

/// Live route-table reader. On Linux the netlink connection must stay
/// alive for the handle to work, so the helper owns both.
pub struct Routes {
    #[cfg(target_os = "linux")]
    handle: rtnetlink::Handle,
    #[cfg(target_os = "linux")]
    connection: tokio::task::JoinHandle<()>,
}

impl std::fmt::Debug for Routes {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("Routes").finish_non_exhaustive()
    }
}

impl Routes {
    /// Open the platform route reader.
    pub async fn new() -> Result<Self> {
        #[cfg(target_os = "linux")]
        {
            let (connection, handle, _messages) =
                rtnetlink::new_connection().context("could not open a netlink route socket")?;
            let task = tokio::spawn(async move {
                let _ = connection.await;
            });
            Ok(Self {
                handle,
                connection: task,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            Ok(Self {})
        }
    }

    /// Resolve the egress for `destination` (longest-prefix match).
    pub async fn egress(&self, destination: IpAddr) -> Result<Egress> {
        #[cfg(target_os = "macos")]
        {
            let route = tobro_osapi::bsd_route::route_lookup(destination)
                .map_err(|error| anyhow::anyhow!("route lookup failed: {error}"))?;
            Ok(route
                .map(|route| Egress::Interface(route.interface_index))
                .unwrap_or(Egress::Unreachable))
        }

        #[cfg(target_os = "windows")]
        {
            let route = tobro_osapi::win_route::best_route(destination)
                .map_err(|error| anyhow::anyhow!("route lookup failed: {error}"))?;
            Ok(route
                .map(|route| Egress::Interface(route.interface_index))
                .unwrap_or(Egress::Unreachable))
        }

        #[cfg(target_os = "linux")]
        {
            use futures::TryStreamExt as _;
            use rtnetlink::packet_route::route::{RouteAttribute, RouteType};

            let prefix = match destination {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };
            let message = rtnetlink::RouteMessageBuilder::<IpAddr>::new()
                .destination_prefix(destination, prefix)
                .map_err(|error| anyhow::anyhow!("invalid route lookup: {error}"))?
                .build();
            let mut replies = self.handle.route().get(message).execute();
            let reply = match replies.try_next().await {
                Ok(Some(reply)) => reply,
                Ok(None) => return Ok(Egress::Unreachable),
                // The kernel reports "no route" as a netlink error rather
                // than an empty reply. That is exactly the isolated-network
                // case these assertions run in, not a probe failure.
                // `RTM_GETROUTE` also answers `-EINVAL` when the only
                // matching route is a blackhole/unreachable kill-switch
                // route; inspect the table to distinguish a kill-switch
                // blackhole from genuinely no route.
                Err(error) if is_no_route_error(&error) => {
                    return Ok(if ip_route_shows_blackhole(destination) {
                        Egress::Blackhole
                    } else {
                        Egress::Unreachable
                    });
                }
                Err(error) => {
                    return Err(anyhow::anyhow!("netlink route lookup failed: {error}"));
                }
            };
            if reply.header.kind == RouteType::BlackHole {
                return Ok(Egress::Blackhole);
            }
            if reply.header.kind == RouteType::Unreachable {
                return Ok(Egress::Unreachable);
            }
            let interface = reply
                .attributes
                .iter()
                .find_map(|attribute| match attribute {
                    RouteAttribute::Oif(index) => Some(*index),
                    _ => None,
                });
            Ok(interface
                .map(Egress::Interface)
                .unwrap_or(Egress::Unreachable))
        }
    }

    /// Delete one device route, simulating the kernel dropping a route
    /// across suspend/resume. Only used by the harness; no production path
    /// calls this.
    pub async fn delete_device_route(
        &self,
        destination: IpAddr,
        prefix_len: u8,
        interface_index: u32,
        metric: Option<u32>,
    ) -> Result<()> {
        #[cfg(target_os = "macos")]
        {
            let route = tobro_osapi::Route {
                destination,
                prefix_len,
                gateway: None,
                interface_index,
                metric,
            };
            tobro_osapi::bsd_route::delete_route(&route)
                .map_err(|error| anyhow::anyhow!("could not delete the test route: {error}"))
        }

        #[cfg(target_os = "windows")]
        {
            let route = tobro_osapi::Route {
                destination,
                prefix_len,
                gateway: None,
                interface_index,
                metric,
            };
            tobro_osapi::win_route::delete_route(&route)
                .map_err(|error| anyhow::anyhow!("could not delete the test route: {error}"))
        }

        #[cfg(target_os = "linux")]
        {
            use rtnetlink::packet_route::route::{RouteProtocol, RouteScope};

            let mut builder = rtnetlink::RouteMessageBuilder::<IpAddr>::new()
                .destination_prefix(destination, prefix_len)
                .map_err(|error| anyhow::anyhow!("invalid route delete: {error}"))?
                .table_id(254)
                .scope(RouteScope::Universe)
                .protocol(RouteProtocol::Static)
                .output_interface(interface_index);
            if let Some(metric) = metric {
                builder = builder.priority(metric);
            }
            self.handle
                .route()
                .del(builder.build())
                .execute()
                .await
                .map_err(|error| anyhow::anyhow!("could not delete the test route: {error}"))
        }

        #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
        {
            let _ = (destination, prefix_len, interface_index, metric);
            anyhow::bail!("route deletion is not implemented on this platform")
        }
    }
}

impl Drop for Routes {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        self.connection.abort();
    }
}

/// Resolve an interface name to its OS index.
pub fn interface_index(name: &str) -> Result<u32> {
    tobro_osapi::interface_index(name)
        .with_context(|| format!("could not look up the interface index for {name:?}"))?
        .ok_or_else(|| anyhow::anyhow!("the interface {name:?} does not exist"))
}

/// Human-readable name of an egress for check messages.
pub fn describe(egress: Egress) -> String {
    match egress {
        Egress::Interface(index) => format!("interface {index}"),
        Egress::Blackhole => "a blackhole route".to_owned(),
        Egress::Unreachable => "no route".to_owned(),
    }
}

/// True when a netlink lookup error means "the kernel has no route".
///
/// `RTM_GETROUTE` answers a routeless destination with `NLMSG_ERROR` carrying
/// `-ENETUNREACH` or `-EHOSTUNREACH` instead of an empty route dump. Those
/// values are the same on every Linux architecture.
#[cfg(target_os = "linux")]
fn is_no_route_error(error: &rtnetlink::Error) -> bool {
    const EINVAL: i32 = 22;
    const ENETUNREACH: i32 = 101;
    const EHOSTUNREACH: i32 = 113;
    match error {
        rtnetlink::Error::NetlinkError(message) => message.code.is_some_and(|code| {
            let code = code.get();
            code == -ENETUNREACH || code == -EHOSTUNREACH || code == -EINVAL
        }),
        _ => false,
    }
}

/// Best-effort: does the main table contain a `blackhole` route matching
/// `destination`? `RTM_GETROUTE` can return `-EINVAL` for a
/// blackhole-only match instead of a reply, so check `ip route show`.
/// Non-Linux or `ip`-absent hosts report `false`.
#[cfg(target_os = "linux")]
fn ip_route_shows_blackhole(destination: IpAddr) -> bool {
    let Ok(output) = std::process::Command::new("ip")
        .args(["route", "show", "table", "main"])
        .output()
    else {
        return false;
    };
    let text = String::from_utf8_lossy(&output.stdout);
    text.lines()
        .any(|line| blackhole_line_matches(line, destination))
}

#[cfg(target_os = "linux")]
fn blackhole_line_matches(line: &str, destination: IpAddr) -> bool {
    let line = line.trim();
    if !line.starts_with("blackhole") {
        return false;
    }
    // `blackhole default`, `blackhole 0.0.0.0/0`, `blackhole ::/0`, ...
    let rest = line["blackhole".len()..].trim();
    let prefix_token = rest.split_whitespace().next().unwrap_or("");
    if prefix_token == "default" {
        return true;
    }
    let (addr_str, len_str) = match prefix_token.split_once('/') {
        Some((a, l)) => (a, l),
        None => (
            prefix_token,
            match destination {
                IpAddr::V4(_) => "32",
                IpAddr::V6(_) => "128",
            },
        ),
    };
    let Ok(prefix_len) = len_str.parse::<u8>() else {
        return false;
    };
    let Ok(net_addr) = addr_str.parse::<IpAddr>() else {
        return false;
    };
    match (net_addr, destination) {
        (IpAddr::V4(net), IpAddr::V4(dest)) => ipv4_in_prefix(dest, net, prefix_len),
        (IpAddr::V6(net), IpAddr::V6(dest)) => ipv6_in_prefix(dest, net, prefix_len),
        _ => false,
    }
}

#[cfg(target_os = "linux")]
fn ipv4_in_prefix(dest: std::net::Ipv4Addr, net: std::net::Ipv4Addr, len: u8) -> bool {
    if len == 0 {
        return true;
    }
    if len > 32 {
        return false;
    }
    let shift = 32 - len;
    (u32::from(dest) >> shift) == (u32::from(net) >> shift)
}

#[cfg(target_os = "linux")]
fn ipv6_in_prefix(dest: std::net::Ipv6Addr, net: std::net::Ipv6Addr, len: u8) -> bool {
    if len == 0 {
        return true;
    }
    if len > 128 {
        return false;
    }
    let shift = 128 - len;
    (u128::from(dest) >> shift) == (u128::from(net) >> shift)
}
