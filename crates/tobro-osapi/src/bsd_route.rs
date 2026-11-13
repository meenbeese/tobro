//! macOS routing-table manipulation over a `PF_ROUTE` routing socket.
//!
//! BSD has no netlink: routes are changed by writing `RTM_ADD`/`RTM_DELETE`
//! messages to a raw `PF_ROUTE` socket and reading the kernel's
//! acknowledgement back. The message encoding follows the proven layout used
//! by Mullvad's `talpid-routing`:
//!
//! - destination and (IP) gateway are full `sockaddr_in`/`sockaddr_in6`
//!   structures (`sa_len` set);
//! - a route without a gateway points into an interface via a link-layer
//!   `sockaddr_dl` gateway carrying the interface index;
//! - network routes carry an explicit `sockaddr` netmask, except IPv4 /32
//!   host routes which use `RTF_HOST` without a netmask;
//! - each sockaddr in the payload is padded to a 4-byte boundary and they
//!   are ordered by their `RTA_*` bit value.
//!
//! The kernel's acknowledgement is matched by `rtm_pid`/`rtm_seq`; unrelated
//! messages the socket delivers (other processes' route changes) are skipped.
//! `ESRCH` maps to [`RouteError::NotFound`] and `EEXIST` to
//! [`RouteError::Exists`] so callers can implement idempotent deletes and
//! replace-on-add.
//!
//! BSD route metrics are not ordered, so [`Route::metric`] is ignored on
//! this platform.
//!
//! # Unsafe scope
//!
//! All `unsafe` here is the FFI itself: creating the socket, setting its
//! receive timeout, and copying fixed-size, pointer-free C structs. Buffers
//! are only written from validated `std::net` values and read back with
//! bounds checks before any unaligned struct read.

use std::fs::File;
use std::io::{self, Read, Write};
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::FromRawFd;
use std::sync::atomic::{AtomicI32, Ordering};

use libc::{
    EEXIST, ESRCH, PF_ROUTE, RTA_DST, RTA_GATEWAY, RTA_NETMASK, RTF_DONE, RTF_GATEWAY, RTF_HOST,
    RTF_STATIC, RTF_UP, RTM_ADD, RTM_DELETE, RTM_VERSION, SO_RCVTIMEO, SOCK_RAW, SOL_SOCKET,
};

use super::{Route, RouteError};

/// How long to wait for the kernel's acknowledgement (seconds).
const REPLY_TIMEOUT_SECS: i64 = 5;
/// Reply buffer: one routing message per read; plenty for `rt_msghdr` +
/// metrics + sockaddrs.
const REPLY_BUFFER_SIZE: usize = 4096;
/// Size of the fixed `rt_msghdr` header.
const HEADER_LEN: usize = mem::size_of::<libc::rt_msghdr>();
/// BSD `AF_INET`/`AF_INET6`/`AF_LINK` (from `libc`, spelled out for docs).
const AF_INET: u8 = libc::AF_INET as u8;
const AF_INET6: u8 = libc::AF_INET6 as u8;
const AF_LINK: u8 = libc::AF_LINK as u8;
/// The kernel identifies the requester by `rtm_pid`.
fn sender_pid() -> i32 {
    i32::try_from(std::process::id()).unwrap_or(i32::MAX)
}
/// Monotonic sequence counter so replies can be matched to requests.
static SEQ: AtomicI32 = AtomicI32::new(1);

/// Install a route. Fails with [`RouteError::Exists`] if an identical entry
/// already exists (the caller implements replace by deleting and re-adding).
pub fn add_route(route: &Route) -> Result<(), RouteError> {
    send_message(RTM_ADD, route)
}

/// Remove a route. Idempotent: removing a route that does not exist
/// (`ESRCH`) succeeds.
pub fn delete_route(route: &Route) -> Result<(), RouteError> {
    match send_message(RTM_DELETE, route) {
        Err(RouteError::NotFound) => Ok(()),
        other => other,
    }
}

fn send_message(kind: i32, route: &Route) -> Result<(), RouteError> {
    let mut socket = RouteSocket::open()?;
    let pid = sender_pid();
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let message = build_message(kind, seq, pid, route)?;
    socket.exchange(&message, seq, pid)
}

/// One `PF_ROUTE` socket, opened per operation and closed on drop.
struct RouteSocket(File);

impl RouteSocket {
    fn open() -> io::Result<Self> {
        // SAFETY: `socket` returns either a valid owned fd (-1 on failure) or
        // an error. The fd is immediately wrapped in an owning `File` so it
        // is closed on drop.
        let fd = unsafe { libc::socket(PF_ROUTE, SOCK_RAW, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let file = unsafe { File::from_raw_fd(fd) };
        let timeout = libc::timeval {
            tv_sec: REPLY_TIMEOUT_SECS as _,
            tv_usec: 0,
        };
        // SAFETY: `fd` is valid (just created), `timeout` is a valid timeval.
        let result = unsafe {
            libc::setsockopt(
                fd,
                SOL_SOCKET,
                SO_RCVTIMEO,
                std::ptr::addr_of!(timeout).cast::<libc::c_void>(),
                mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error()); // `file` drop closes the fd
        }
        Ok(Self(file))
    }

    /// Send one message and wait for the kernel's acknowledgement, matching
    /// it by pid and sequence number. Unrelated messages are skipped.
    fn exchange(&mut self, message: &[u8], seq: i32, pid: i32) -> Result<(), RouteError> {
        self.0.write_all(message).map_err(RouteError::Io)?;
        let mut buf = vec![0u8; REPLY_BUFFER_SIZE];
        loop {
            let read = match self.0.read(&mut buf) {
                Ok(0) => {
                    return Err(RouteError::Io(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "route socket closed while awaiting the reply",
                    )));
                }
                Ok(n) => n,
                // SO_RCVTIMEO expiry surfaces as EAGAIN/EWOULDBLOCK.
                Err(error)
                    if error.kind() == io::ErrorKind::WouldBlock
                        || error.kind() == io::ErrorKind::TimedOut =>
                {
                    return Err(RouteError::Timeout);
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(RouteError::Io(error)),
            };
            if let Some((reply_pid, reply_seq, errno)) = parse_reply(&buf[..read])
                && reply_pid == pid
                && reply_seq == seq
            {
                return errno_result(errno);
            }
            // Unrelated routing traffic: keep reading.
        }
    }
}

/// Map the kernel's `rtm_errno` to a result.
fn errno_result(errno: i32) -> Result<(), RouteError> {
    match errno {
        0 => Ok(()),
        e if e == ESRCH => Err(RouteError::NotFound),
        e if e == EEXIST => Err(RouteError::Exists),
        e => Err(RouteError::Io(io::Error::from_raw_os_error(e))),
    }
}

/// Parse the fixed `rt_msghdr` prefix of a routing message: `(pid, seq,
/// errno)`. Returns `None` for buffers too small or of a foreign version.
fn parse_reply(buf: &[u8]) -> Option<(i32, i32, i32)> {
    if buf.len() < HEADER_LEN {
        return None;
    }
    // SAFETY: the buffer holds at least `size_of::<rt_msghdr>()` initialized
    // bytes and `rt_msghdr` contains no pointers, so any bit pattern is valid.
    let header: libc::rt_msghdr =
        unsafe { std::ptr::read_unaligned(buf.as_ptr().cast::<libc::rt_msghdr>()) };
    if header.rtm_version != RTM_VERSION as u8 {
        return None;
    }
    Some((header.rtm_pid, header.rtm_seq, header.rtm_errno))
}

/// Build a complete `RTM_ADD`/`RTM_DELETE` message for `route`.
pub(crate) fn build_message(
    kind: i32,
    seq: i32,
    pid: i32,
    route: &Route,
) -> Result<Vec<u8>, RouteError> {
    let is_v4 = matches!(route.destination, IpAddr::V4(_));
    let max_prefix = if is_v4 { 32 } else { 128 };
    if u32::from(route.prefix_len) > max_prefix {
        return Err(RouteError::Invalid(format!(
            "prefix length {} does not fit a {}-bit destination",
            route.prefix_len,
            if is_v4 { 32 } else { 128 }
        )));
    }
    if let Some(gateway) = route.gateway {
        let gateway_v4 = matches!(gateway, IpAddr::V4(_));
        if gateway_v4 != is_v4 {
            return Err(RouteError::Invalid(
                "gateway and destination must use the same address family".to_owned(),
            ));
        }
    }

    // Sockaddr payload, ordered by RTA_* bit value: DST(1), GATEWAY(2),
    // NETMASK(4).
    let mut payload = Vec::with_capacity(16 + 28 + 28);
    match route.destination {
        IpAddr::V4(addr) => payload.extend_from_slice(&ipv4_sockaddr(addr)),
        IpAddr::V6(addr) => payload.extend_from_slice(&ipv6_sockaddr(addr)),
    }
    match route.gateway {
        // Route into a device: link-layer gateway carrying the interface
        // index (the kernel resolves the device).
        None => payload.extend_from_slice(&link_sockaddr(route.interface_index)),
        // Route via a next-hop gateway IP.
        Some(gateway) => match gateway {
            IpAddr::V4(addr) => payload.extend_from_slice(&ipv4_sockaddr(addr)),
            IpAddr::V6(addr) => payload.extend_from_slice(&ipv6_sockaddr(addr)),
        },
    }
    // IPv4 /32 entries are host routes (`RTF_HOST`, no netmask sockaddr);
    // everything else carries an explicit netmask, including default routes
    // (netmask 0.0.0.0 / ::).
    let host_route = is_v4 && route.prefix_len == 32 && route.gateway.is_none();
    let mut rtm_addrs = RTA_DST | RTA_GATEWAY;
    let mut rtm_flags = RTF_UP | RTF_STATIC | RTF_DONE | RTF_GATEWAY;
    if host_route {
        rtm_flags |= RTF_HOST;
    } else {
        rtm_addrs |= RTA_NETMASK;
        match route.destination {
            IpAddr::V4(_) => {
                payload.extend_from_slice(&ipv4_sockaddr(prefix_mask_v4(route.prefix_len)))
            }
            IpAddr::V6(_) => {
                payload.extend_from_slice(&ipv6_sockaddr(prefix_mask_v6(route.prefix_len)))
            }
        }
    }

    let total = HEADER_LEN + payload.len();
    let mut message = vec![0u8; total];
    let mut header: libc::rt_msghdr = unsafe { mem::zeroed() };
    header.rtm_msglen = total
        .try_into()
        .map_err(|_| RouteError::Invalid("route message too large".to_owned()))?;
    header.rtm_version = RTM_VERSION as u8;
    header.rtm_type = kind
        .try_into()
        .map_err(|_| RouteError::Invalid("bad message type".to_owned()))?;
    header.rtm_index = route.interface_index.try_into().unwrap_or(u16::MAX);
    header.rtm_flags = rtm_flags;
    header.rtm_addrs = rtm_addrs;
    header.rtm_pid = pid;
    header.rtm_seq = seq;
    // SAFETY: `header` contains no pointers; copying its representation into
    // the freshly allocated message buffer is a plain byte move of exactly
    // `size_of::<rt_msghdr>()` bytes.
    unsafe {
        let header_bytes =
            std::slice::from_raw_parts(std::ptr::addr_of!(header).cast::<u8>(), HEADER_LEN);
        message[..HEADER_LEN].copy_from_slice(header_bytes);
    }
    message[HEADER_LEN..].copy_from_slice(&payload);
    Ok(message)
}

/// Encode an IPv4 address as a `sockaddr_in` (16 bytes).
fn ipv4_sockaddr(addr: Ipv4Addr) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[0] = 16; // sin_len
    out[1] = AF_INET; // sin_family
    // sin_port (2 bytes) stays 0.
    out[4..8].copy_from_slice(&u32::from(addr).to_be_bytes()); // sin_addr
    out
}

/// Encode an IPv6 address as a `sockaddr_in6` (28 bytes).
fn ipv6_sockaddr(addr: Ipv6Addr) -> [u8; 28] {
    let mut out = [0u8; 28];
    out[0] = 28; // sin6_len
    out[1] = AF_INET6; // sin6_family
    // sin6_port (2), sin6_flowinfo (4) stay 0.
    out[8..24].copy_from_slice(&addr.octets()); // sin6_addr
    // sin6_scope_id (4) stays 0.
    out
}

/// Encode an interface route gateway as a `sockaddr_dl` (20 bytes) carrying
/// the interface index.
fn link_sockaddr(interface_index: u32) -> [u8; 20] {
    let mut out = [0u8; 20];
    out[0] = 20; // sdl_len
    out[1] = AF_LINK; // sdl_family
    out[2..4].copy_from_slice(&(interface_index.min(u16::MAX as u32) as u16).to_ne_bytes());
    out
}

/// The netmask of `prefix_len` for IPv4.
fn prefix_mask_v4(prefix_len: u8) -> Ipv4Addr {
    if prefix_len == 0 {
        Ipv4Addr::UNSPECIFIED
    } else {
        Ipv4Addr::from((u32::MAX) << (32 - u32::from(prefix_len)))
    }
}

/// The netmask of `prefix_len` for IPv6.
fn prefix_mask_v6(prefix_len: u8) -> Ipv6Addr {
    if prefix_len == 0 {
        Ipv6Addr::UNSPECIFIED
    } else {
        Ipv6Addr::from((u128::MAX) << (128 - u32::from(prefix_len)))
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn route(
        destination: IpAddr,
        prefix_len: u8,
        gateway: Option<IpAddr>,
        interface_index: u32,
    ) -> Route {
        Route {
            destination,
            prefix_len,
            gateway,
            interface_index,
            metric: None,
        }
    }

    fn payload(message: &[u8]) -> &[u8] {
        &message[HEADER_LEN..]
    }

    fn header_addrs(message: &[u8]) -> i32 {
        // rtm_addrs sits at offset 12 in rt_msghdr.
        i32::from_ne_bytes(message[12..16].try_into().expect("header bounds"))
    }

    fn header_flags(message: &[u8]) -> i32 {
        i32::from_ne_bytes(message[8..12].try_into().expect("header bounds"))
    }

    #[test]
    fn ipv4_sockaddr_encoding() {
        let bytes = ipv4_sockaddr("203.0.113.9".parse().expect("valid"));
        assert_eq!(bytes[0], 16); // sin_len
        assert_eq!(bytes[1], AF_INET);
        assert_eq!(&bytes[2..4], &[0, 0]); // port
        assert_eq!(&bytes[4..8], &[203, 0, 113, 9]); // address, network order
        assert!(bytes[8..].iter().all(|b| *b == 0));
    }

    #[test]
    fn ipv6_sockaddr_encoding() {
        let bytes = ipv6_sockaddr("2001:db8::1".parse().expect("valid"));
        assert_eq!(bytes[0], 28); // sin6_len
        assert_eq!(bytes[1], AF_INET6);
        assert_eq!(&bytes[2..8], &[0; 6]); // port + flowinfo
        assert_eq!(
            &bytes[8..24],
            &"2001:db8::1".parse::<Ipv6Addr>().expect("valid").octets()
        );
        assert_eq!(&bytes[24..], &[0; 4]); // scope id
    }

    #[test]
    fn link_sockaddr_carries_the_interface_index() {
        let bytes = link_sockaddr(31);
        assert_eq!(bytes[0], 20); // sdl_len
        assert_eq!(bytes[1], AF_LINK);
        assert_eq!(&bytes[2..4], &31u16.to_ne_bytes()); // sdl_index
        assert!(bytes[4..].iter().all(|b| *b == 0));
    }

    #[test]
    fn device_route_is_a_link_gateway_with_netmask() {
        let r = route(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0, None, 12);
        let message = build_message(RTM_ADD, 7, 4242, &r).expect("build");
        assert_eq!(
            header_flags(&message),
            RTF_UP | RTF_STATIC | RTF_DONE | RTF_GATEWAY
        );
        assert_eq!(header_addrs(&message), RTA_DST | RTA_GATEWAY | RTA_NETMASK);
        // DST (16) + link gateway (20) + netmask (16) = 52 bytes.
        assert_eq!(payload(&message).len(), 16 + 20 + 16);
        assert_eq!(&payload(&message)[16..36], &link_sockaddr(12));
    }

    #[test]
    fn gateway_route_points_at_the_gateway_ip() {
        let r = route(
            IpAddr::V4("192.0.2.0".parse().expect("valid")),
            24,
            Some(IpAddr::V4("198.51.100.1".parse().expect("valid"))),
            0,
        );
        let message = build_message(RTM_ADD, 1, 1, &r).expect("build");
        assert_eq!(header_addrs(&message), RTA_DST | RTA_GATEWAY | RTA_NETMASK);
        // DST (16) + gateway (16) + netmask (16).
        assert_eq!(payload(&message).len(), 48);
        let netmask = &payload(&message)[32..48];
        assert_eq!(&netmask[4..8], &u32::from(prefix_mask_v4(24)).to_be_bytes());
    }

    #[test]
    fn ipv4_host_route_uses_rtf_host_without_netmask() {
        let r = route(
            IpAddr::V4("10.111.222.252".parse().expect("valid")),
            32,
            None,
            3,
        );
        let message = build_message(RTM_ADD, 1, 1, &r).expect("build");
        assert_eq!(header_flags(&message) & RTF_HOST, RTF_HOST);
        assert_eq!(header_addrs(&message) & RTA_NETMASK, 0);
        // DST (16) + link gateway (20), no netmask.
        assert_eq!(payload(&message).len(), 36);
    }

    #[test]
    fn ipv6_routes_keep_their_family() {
        let r = route(
            IpAddr::V6("2001:db8::".parse().expect("valid")),
            32,
            None,
            5,
        );
        let message = build_message(RTM_ADD, 1, 1, &r).expect("build");
        // DST (28) + link gateway (20) + netmask (28).
        assert_eq!(payload(&message).len(), 76);
        assert_eq!(payload(&message)[1], AF_INET6);
        assert_eq!(payload(&message)[28 + 1], AF_LINK);
        assert_eq!(payload(&message)[48 + 1], AF_INET6);
    }

    #[test]
    fn family_mismatch_is_rejected() {
        let r = route(
            IpAddr::V4("192.0.2.0".parse().expect("valid")),
            24,
            Some(IpAddr::V6("2001:db8::1".parse().expect("valid"))),
            0,
        );
        assert!(matches!(
            build_message(RTM_ADD, 1, 1, &r),
            Err(RouteError::Invalid(_))
        ));
    }

    #[test]
    fn oversized_prefix_is_rejected() {
        let r = route(IpAddr::V4("192.0.2.0".parse().expect("valid")), 33, None, 0);
        assert!(matches!(
            build_message(RTM_ADD, 1, 1, &r),
            Err(RouteError::Invalid(_))
        ));
    }

    #[test]
    fn header_carries_pid_seq_and_version() {
        let r = route(IpAddr::V4("192.0.2.0".parse().expect("valid")), 24, None, 9);
        let message = build_message(RTM_ADD, 1234, 77, &r).expect("build");
        let (pid, seq, errno) = parse_reply(&message).expect("parses back");
        assert_eq!(pid, 77);
        assert_eq!(seq, 1234);
        assert_eq!(errno, 0);
        assert_eq!(
            u16::from_ne_bytes(message[0..2].try_into().expect("len")),
            message.len() as u16
        );
        assert_eq!(message[2], RTM_VERSION as u8);
        assert_eq!(message[3], RTM_ADD as u8);
    }

    #[test]
    fn parse_reply_rejects_short_and_foreign_buffers() {
        assert!(parse_reply(&[0u8; 8]).is_none());
        let mut foreign = vec![0u8; HEADER_LEN];
        foreign[2] = 99; // unknown rtm_version
        assert!(parse_reply(&foreign).is_none());
    }
}
