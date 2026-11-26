//! macOS interface address assignment via ioctl.
//!
//! `tun2` addresses a utun device at creation with one IPv4 address
//! (`SIOCAIFADDR`). The plan also carries the tunnel's IPv6 address, so the
//! helper adds it here through `SIOCAIFADDR_IN6`, giving the device the same
//! dual-stack addressing the Linux backend converges through netlink. macOS
//! skips duplicate address detection for utun interfaces (`IFNET_FAMILY_UTUN`
//! in `in6if_do_dad`), so the address is usable as soon as the ioctl returns.
//!
//! Addresses belong to the interface, not to this crate: closing the utun
//! removes them, which is exactly the teardown story the platform backend
//! relies on (every apply creates a fresh device, so no address convergence
//! or cleanup is needed).
//!
//! # Unsafe scope
//!
//! All `unsafe` here is the ioctl FFI: opening a `SOCK_DGRAM` socket,
//! zeroing one fixed-layout, pointer-free `struct in6_aliasreq`, copying a
//! validated interface name into it, and issuing the ioctl. libc exposes the
//! struct's members but not the composite type, so the layout is defined
//! here and checked against the SDK size at compile time. The ioctl number
//! encodes that size; every other field is written from a plain
//! `std::net`/`u8` input.

use std::ffi::CString;
use std::io;
use std::mem;
use std::net::Ipv6Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

/// `struct in6_aliasreq` from `<netinet6/in6_var.h>`: the payload of
/// `SIOCAIFADDR_IN6`.
#[repr(C)]
struct In6AliasReq {
    ifra_name: [libc::c_char; libc::IFNAMSIZ],
    ifra_addr: libc::sockaddr_in6,
    /// Peer address for point-to-point interfaces; a zeroed (family
    /// `AF_UNSPEC`) value means none, which is what the utun device uses.
    ifra_dstaddr: libc::sockaddr_in6,
    ifra_prefixmask: libc::sockaddr_in6,
    ifra_flags: libc::c_int,
    /// Only `ia6t_vltime`/`ia6t_pltime` are inputs; the expire fields are
    /// outputs the kernel fills in.
    ifra_lifetime: libc::in6_addrlifetime,
}

// The ioctl number encodes the payload size, so a layout mismatch must fail
// at compile time instead of sending a request of the wrong size.
const _: () = assert!(
    mem::size_of::<In6AliasReq>() == 128,
    "unexpected in6_aliasreq layout"
);

/// `SIOCAIFADDR_IN6`: `_IOW('i', 26, struct in6_aliasreq)`.
const SIOCAIFADDR_IN6: libc::c_ulong = 0x8000_0000
    | ((mem::size_of::<In6AliasReq>() as libc::c_ulong & 0x1fff) << 16)
    | ((b'i' as libc::c_ulong) << 8)
    | 26;

/// Assign `address/prefix_len` to the interface called `interface`.
///
/// Blocks on a synchronous ioctl; the kernel needs no extra privileges
/// beyond those the helper already holds. The destination is left as
/// `AF_UNSPEC`: the utun is point-to-point and has no IPv6 peer.
pub fn add_ipv6_address(interface: &str, address: Ipv6Addr, prefix_len: u8) -> io::Result<()> {
    let request = build_request(interface, address, prefix_len)?;
    // SAFETY: `socket` returns an owned descriptor or -1; the descriptor is
    // wrapped immediately so every return path closes it.
    let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a fresh descriptor we own and do not duplicate.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: the request is a fully initialized, pointer-free payload of
    // the size encoded in `SIOCAIFADDR_IN6`, and `fd` is a live socket.
    let result =
        unsafe { libc::ioctl(fd.as_raw_fd(), SIOCAIFADDR_IN6, std::ptr::addr_of!(request)) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Build the ioctl payload, rejecting values the syscall cannot express.
fn build_request(interface: &str, address: Ipv6Addr, prefix_len: u8) -> io::Result<In6AliasReq> {
    if prefix_len > 128 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("prefix length {prefix_len} does not fit an IPv6 address"),
        ));
    }
    let name = CString::new(interface).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "the interface name contains a NUL byte",
        )
    })?;
    let name = name.as_bytes();
    if name.len() >= libc::IFNAMSIZ {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the interface name is too long for IFNAMSIZ",
        ));
    }

    // SAFETY: zeroing a pointer-free C struct; the zeroed tail provides the
    // NUL terminator after the copied name and the `AF_UNSPEC` destination.
    let mut request: In6AliasReq = unsafe { mem::zeroed() };
    for (slot, byte) in request.ifra_name.iter_mut().zip(name.iter().copied()) {
        *slot = byte as libc::c_char;
    }
    request.ifra_addr = sockaddr_in6(address);
    request.ifra_prefixmask = prefix_mask(prefix_len);
    // ND6_INFINITE_LIFETIME: a device address must not age out.
    request.ifra_lifetime.ia6t_vltime = u32::MAX;
    request.ifra_lifetime.ia6t_pltime = u32::MAX;
    Ok(request)
}

/// One initialized `sockaddr_in6` (`sin6_len` must be set on BSD).
fn sockaddr_in6(address: Ipv6Addr) -> libc::sockaddr_in6 {
    // SAFETY: zeroing a pointer-free C struct.
    let mut sockaddr: libc::sockaddr_in6 = unsafe { mem::zeroed() };
    sockaddr.sin6_len = u8::try_from(mem::size_of::<libc::sockaddr_in6>()).unwrap_or(u8::MAX);
    sockaddr.sin6_family = libc::AF_INET6 as libc::sa_family_t;
    sockaddr.sin6_addr = libc::in6_addr {
        s6_addr: address.octets(),
    };
    sockaddr
}

/// The prefix mask as one initialized `sockaddr_in6`.
fn prefix_mask(prefix_len: u8) -> libc::sockaddr_in6 {
    let bits = if prefix_len == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(prefix_len))
    };
    sockaddr_in6(Ipv6Addr::from(bits))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// The hand-written layout and ioctl number must match the SDK (128-byte
    /// struct, `_IOW('i', 26, ...)`), because the kernel decodes both.
    #[test]
    fn the_ioctl_layout_matches_the_sdk() {
        assert_eq!(mem::size_of::<In6AliasReq>(), 128);
        assert_eq!(SIOCAIFADDR_IN6, 0x8080_691a);
    }

    #[test]
    fn the_request_carries_the_address_and_prefix() {
        let address = Ipv6Addr::new(0xfd6b, 0x626f, 0x6272, 0x6f, 0, 0, 0, 0);
        let request = build_request("utun7", address, 64).expect("valid request");

        let name: Vec<u8> = request
            .ifra_name
            .iter()
            .take_while(|byte| **byte != 0)
            .map(|byte| *byte as u8)
            .collect();
        assert_eq!(name, b"utun7");

        assert_eq!(
            request.ifra_addr.sin6_family,
            libc::AF_INET6 as libc::sa_family_t
        );
        assert_eq!(
            usize::from(request.ifra_addr.sin6_len),
            mem::size_of::<libc::sockaddr_in6>()
        );
        assert_eq!(request.ifra_addr.sin6_addr.s6_addr, address.octets());
        // No peer on the utun: the destination stays AF_UNSPEC.
        assert_eq!(request.ifra_dstaddr.sin6_family, 0);
        assert_eq!(
            request.ifra_prefixmask.sin6_addr.s6_addr,
            Ipv6Addr::new(0xffff, 0xffff, 0xffff, 0xffff, 0, 0, 0, 0).octets()
        );
        assert_eq!(request.ifra_lifetime.ia6t_vltime, u32::MAX);
        assert_eq!(request.ifra_lifetime.ia6t_pltime, u32::MAX);
    }

    #[test]
    fn the_prefix_mask_handles_the_edges() {
        assert_eq!(prefix_mask(0).sin6_addr.s6_addr, [0u8; 16]);
        assert_eq!(prefix_mask(128).sin6_addr.s6_addr, [0xffu8; 16]);
        assert_eq!(
            prefix_mask(64).sin6_addr.s6_addr,
            Ipv6Addr::new(0xffff, 0xffff, 0xffff, 0xffff, 0, 0, 0, 0).octets()
        );
    }

    #[test]
    fn invalid_requests_are_rejected() {
        let address = Ipv6Addr::LOCALHOST;
        assert!(build_request("utun0", address, 129).is_err());
        assert!(build_request(&"x".repeat(libc::IFNAMSIZ), address, 64).is_err());
        assert!(build_request("utun\0", address, 64).is_err());
    }
}
