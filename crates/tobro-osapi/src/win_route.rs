//! Windows routing-table manipulation via iphlpapi, plus a safe loader for
//! the wintun driver library.
//!
//! Routes are managed with `CreateIpForwardEntry2` / `DeleteIpForwardEntry2`
//! (`MIB_IPFORWARD_ROW2`): a row with an unspecified `NextHop` is an on-link
//! route into `InterfaceIndex`; a row with a gateway `NextHop` routes via
//! that gateway. `ERROR_NOT_FOUND` maps to [`RouteError::NotFound`] so
//! deletes are idempotent, and `ERROR_OBJECT_ALREADY_EXISTS` to
//! [`RouteError::Exists`] so callers can implement replace-on-add.
//!
//! Route metrics are interface-relative on Windows; [`Route::metric`] (or 0)
//! is stored directly.
//!
//! # Unsafe scope
//!
//! All `unsafe` here is the FFI: the two iphlpapi calls and zeroing/fields of
//! fixed-layout C structs. Every field is written from validated
//! `std::net`/`u32` inputs; no pointers beyond the (stack) row struct are
//! passed. `load_wintun` wraps the `unsafe` DLL load behind a safe function
//! so the rest of the workspace never needs `unsafe`.

use std::ffi::OsStr;
use std::io;

use windows_sys::Win32::Foundation::{
    ERROR_NOT_FOUND, ERROR_OBJECT_ALREADY_EXISTS, NO_ERROR, WIN32_ERROR,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    CreateIpForwardEntry2, DeleteIpForwardEntry2, IP_ADDRESS_PREFIX, MIB_IPFORWARD_ROW2,
};
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, IN_ADDR, IN_ADDR_0, IN6_ADDR, IN6_ADDR_0, NL_ROUTE_PROTOCOL, SOCKADDR_IN,
    SOCKADDR_IN6, SOCKADDR_IN6_0, SOCKADDR_INET,
};

use super::{Route, RouteError};

/// Lifetime "infinite" for route entries the helper installs.
const INFINITE_LIFETIME: u32 = u32::MAX;
/// The route protocol tag written on entries: `RouteProtocolNetMgmt` marks
/// them as locally managed (netsh/`route`-style) so they are clearly ours.
const ROUTE_PROTOCOL_NETMGMT: NL_ROUTE_PROTOCOL = 3;

/// Install a route. Fails with [`RouteError::Exists`] when an identical
/// entry already exists.
pub fn add_route(route: &Route) -> Result<(), RouteError> {
    let row = build_row(route)?;
    // SAFETY: `row` is a fully initialized, pointer-free struct on the stack.
    let result = unsafe { CreateIpForwardEntry2(&row) };
    check(result, RouteError::Exists)
}

/// Remove a route. Idempotent: removing a route that does not exist
/// (`ERROR_NOT_FOUND`) succeeds.
pub fn delete_route(route: &Route) -> Result<(), RouteError> {
    let row = build_row(route)?;
    // SAFETY: `row` is a fully initialized, pointer-free struct on the stack.
    let result = unsafe { DeleteIpForwardEntry2(&row) };
    check(result, RouteError::NotFound)
}

/// Map a `WIN32_ERROR` to a result, treating `not_found` as success (the
/// idempotent-delete case) and `already_exists` as the given error variant.
fn check(result: WIN32_ERROR, already_exists: RouteError) -> Result<(), RouteError> {
    match result {
        NO_ERROR => Ok(()),
        ERROR_NOT_FOUND => Ok(()),
        ERROR_OBJECT_ALREADY_EXISTS => Err(already_exists),
        other => Err(RouteError::Io(io::Error::from_raw_os_error(other as i32))),
    }
}

/// Build the `MIB_IPFORWARD_ROW2` for one route request.
fn build_row(route: &Route) -> Result<MIB_IPFORWARD_ROW2, RouteError> {
    let is_v4 = matches!(route.destination, std::net::IpAddr::V4(_));
    let max_prefix = if is_v4 { 32 } else { 128 };
    if u32::from(route.prefix_len) > max_prefix {
        return Err(RouteError::Invalid(format!(
            "prefix length {} does not fit a {}-bit destination",
            route.prefix_len,
            if is_v4 { 32 } else { 128 }
        )));
    }
    if let Some(gateway) = route.gateway {
        let gateway_v4 = matches!(gateway, std::net::IpAddr::V4(_));
        if gateway_v4 != is_v4 {
            return Err(RouteError::Invalid(
                "gateway and destination must use the same address family".to_owned(),
            ));
        }
    }

    // SAFETY: zeroing a pointer-free C struct.
    let mut row: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };
    // InterfaceLuid stays zeroed: iphlpapi resolves the interface by index.
    row.InterfaceIndex = route.interface_index;
    row.DestinationPrefix = IP_ADDRESS_PREFIX {
        Prefix: sockaddr_inet(route.destination)?,
        PrefixLength: route.prefix_len,
    };
    // An unspecified (zeroed) NextHop makes this an on-link route into the
    // interface; a gateway IP routes via that next hop.
    if let Some(gateway) = route.gateway {
        row.NextHop = sockaddr_inet(gateway)?;
    }
    row.SitePrefixLength = 0;
    row.ValidLifetime = INFINITE_LIFETIME;
    row.PreferredLifetime = INFINITE_LIFETIME;
    row.Metric = route.metric.unwrap_or(0);
    row.Protocol = ROUTE_PROTOCOL_NETMGMT;
    Ok(row)
}

/// Encode a destination/gateway address into a `SOCKADDR_INET`.
fn sockaddr_inet(address: std::net::IpAddr) -> Result<SOCKADDR_INET, RouteError> {
    // SAFETY: zeroing a pointer-free C union before filling the family-
    // specific arm below.
    let mut out: SOCKADDR_INET = unsafe { std::mem::zeroed() };
    match address {
        std::net::IpAddr::V4(addr) => {
            // SAFETY: writing the `Ipv4` arm of a `SOCKADDR_INET` union.
            unsafe {
                let mut sockaddr: SOCKADDR_IN = std::mem::zeroed();
                sockaddr.sin_family = AF_INET;
                sockaddr.sin_port = 0;
                sockaddr.sin_addr = IN_ADDR {
                    S_un: IN_ADDR_0 {
                        // Network byte order, per the Win32 `in_addr` contract.
                        S_addr: u32::from(addr).to_be(),
                    },
                };
                out.Ipv4 = sockaddr;
            }
        }
        std::net::IpAddr::V6(addr) => {
            // SAFETY: writing the `Ipv6` arm of a `SOCKADDR_INET` union.
            unsafe {
                let mut sockaddr: SOCKADDR_IN6 = std::mem::zeroed();
                sockaddr.sin6_family = AF_INET6;
                sockaddr.sin6_port = 0;
                sockaddr.sin6_flowinfo = 0;
                sockaddr.sin6_addr = IN6_ADDR {
                    u: IN6_ADDR_0 {
                        Byte: addr.octets(),
                    },
                };
                sockaddr.Anonymous = SOCKADDR_IN6_0 { sin6_scope_id: 0 };
                out.Ipv6 = sockaddr;
            }
        }
    }
    Ok(out)
}

/// Load the wintun driver library (`wintun.dll`) from `path`. Safe wrapper
/// over the `unsafe` DLL load; the returned handle is `Send + Sync`.
pub fn load_wintun(path: &OsStr) -> Result<wintun_bindings::Wintun, io::Error> {
    // SAFETY: the caller decides where the driver library is loaded from
    // (the helper ships/bundles its own copy; see the M7 packaging notes).
    // The loaded library is a table of well-known wintun entry points and is
    // released when the returned handle drops.
    let wintun = unsafe { wintun_bindings::load_from_path(path) };
    wintun.map_err(|error| io::Error::other(format!("wintun load failed: {error}")))
}

/// Convenience: the default driver path the helper bundles next to its
/// binary ("wintun.dll" resolved against the executable directory).
pub fn default_wintun_path() -> std::path::PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.to_path_buf()))
        .unwrap_or_default()
        .join("wintun.dll")
}
