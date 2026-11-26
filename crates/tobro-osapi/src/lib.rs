//! `tobro-osapi` — the minimal OS FFI layer for the TUN helper (M7 T4).
//!
//! # Why this crate exists
//!
//! There is no maintained, memory-safe Rust crate that can *modify* the
//! routing tables on macOS (PF_ROUTE sockets) or Windows (iphlpapi). The
//! existing options are either read-only (`netroute`, `getifs`) or too
//! limited (`arcbox-route`: interface routes only, IPv4 only). The standard
//! practice for TUN-based clients (Mullvad, Firezone) is a small, audited
//! FFI layer, and that is what this crate is.
//!
//! # Security scope (§10.5)
//!
//! This is the **only** crate in the workspace allowed to use `unsafe`
//! (see `Cargo.toml`'s lint table; the workspace default is
//! `unsafe_code = "forbid"`). The unsafe surface is deliberately tiny and
//! fully internal:
//!
//! - **macOS**: opening a `PF_ROUTE` routing socket, writing a request
//!   message, reading the reply; assigning the utun's IPv6 address through
//!   the `SIOCAIFADDR_IN6` ioctl ([`bsd_ifaddr`]). All message bytes are
//!   built from validated plain-data inputs (`std::net` types + interface
//!   indices); no attacker controlled lengths, pointers, or format strings
//!   exist. The kill switch additionally speaks `/dev/pf` ioctls with
//!   fixed-size structures ([`pf`]) — never `pfctl`, per §10.5's no-shell
//!   rule.
//! - **Windows**: calling the iphlpapi route functions
//!   (`CreateIpForwardEntry2` / `DeleteIpForwardEntry2`) and the unicast
//!   address call (`CreateUnicastIpAddressEntry`) with a zeroed-out struct
//!   filled from validated plain-data inputs, the handful of Windows
//!   Filtering Platform calls used by the kill switch ([`wfp`]), and the
//!   named-pipe security/token calls that scope the helper IPC endpoint to
//!   one user SID ([`win_pipe`]).
//!
//! Every public function is safe and takes plain `std::net` types. Nothing
//! here shells out, listens, or touches anything beyond the routing tables.
//! FFI targets are OS system libraries, and every buffer length is either
//! fixed at compile time or derived from a validated constant.
//!
//! The helpers never log and never return OS-level details beyond an
//! `io::Error`; the caller (privileged helper) owns logging policy.

#![allow(clippy::module_name_repetitions)]

#[cfg(target_os = "macos")]
pub mod bsd_ifaddr;

#[cfg(target_os = "macos")]
pub mod bsd_route;

/// macOS packet-filter (PF) kill-switch enforcement (M7 T4b).
#[cfg(target_os = "macos")]
pub mod pf;

#[cfg(target_os = "macos")]
pub mod sc_dns;

/// Unix uid/gid lookups and socket ownership for the helper install (M7).
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub mod unix_ids;

/// Windows Filtering Platform (WFP) kill-switch enforcement (M7 T4c).
#[cfg(target_os = "windows")]
pub mod wfp;

/// Windows named-pipe security: the helper IPC endpoint's DACL and the
/// connecting user's SID (M7 T4c).
#[cfg(target_os = "windows")]
pub mod win_pipe;

#[cfg(target_os = "windows")]
pub mod win_route;

use std::io;

/// OS interface index for `name`, or `None` when no such interface exists.
///
/// Used by the TUN leak harness (and useful for diagnostics): the routing
/// tables expose interface *indices*, while plans and status expose names.
/// This is a read-only lookup; it never creates or configures anything.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub fn interface_index(name: &str) -> io::Result<Option<u32>> {
    use std::ffi::CString;

    let name = CString::new(name).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "the interface name contains a NUL byte",
        )
    })?;
    // SAFETY: `name` is a valid NUL-terminated string. The call has no
    // pointer outputs and only reads the name and the kernel's interface
    // table; a zero return means the interface does not exist.
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    Ok((index != 0).then_some(index))
}

/// OS interface index for `name`, or `None` when no such interface exists.
///
/// Windows interface names in the TUN backend are adapter aliases (the
/// wintun adapter is named `tobro`), so the alias is converted to a LUID and
/// then to the index. A raw `if_nametoindex` fallback covers names that are
/// already in the OS's interface-name form.
#[cfg(target_os = "windows")]
pub fn interface_index(name: &str) -> io::Result<Option<u32>> {
    use std::os::windows::ffi::OsStrExt as _;

    use windows_sys::Win32::Foundation::NO_ERROR;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        ConvertInterfaceAliasToLuid, ConvertInterfaceLuidToIndex, if_nametoindex,
    };
    use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;

    let wide: Vec<u16> = std::ffi::OsStr::new(name)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: `wide` is NUL-terminated and lives for the call; `luid` is a
    // valid stack out-parameter. The function only reads the name.
    let mut luid = unsafe { std::mem::zeroed::<NET_LUID_LH>() };
    let result = unsafe { ConvertInterfaceAliasToLuid(wide.as_ptr(), &mut luid) };
    if result == NO_ERROR {
        let mut index = 0u32;
        // SAFETY: `luid` was initialized by the call above and `index` is a
        // valid stack out-parameter.
        let result = unsafe { ConvertInterfaceLuidToIndex(&luid, &mut index) };
        if result == NO_ERROR && index != 0 {
            return Ok(Some(index));
        }
    }

    // Fallback: the name may already be the OS interface name. The Windows
    // API takes a narrow (ANSI) C string.
    if name.as_bytes().contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the interface name contains a NUL byte",
        ));
    }
    let mut ansi = name.as_bytes().to_vec();
    ansi.push(0);
    // SAFETY: `ansi` is NUL-terminated and lives for the call.
    let index = unsafe { if_nametoindex(ansi.as_ptr()) };
    Ok((index != 0).then_some(index))
}

/// True when the current process can create TUN devices and change routes:
/// uid 0 on Unix, an elevated (administrator) token on Windows.
///
/// Read-only capability probe used to skip privileged scenarios with a clear
/// reason instead of failing to spawn the helper.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub fn is_elevated() -> bool {
    // SAFETY: `geteuid` has no arguments, cannot fail, and only reads the
    // process's effective uid.
    unsafe { libc::geteuid() == 0 }
}

/// True when the current process can create TUN devices and change routes.
///
/// On Windows this reads the *elevation* flag of the current process token
/// (`TokenElevation`), which is what the TUN backend and WFP require. A
/// standard user with an administrator account but no elevated token gets
/// `false` here, matching the helper's actual capability.
#[cfg(target_os = "windows")]
pub fn is_elevated() -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: `GetCurrentProcess` returns a pseudo-handle that needs no
    // cleanup; `token` is a valid out-parameter. The returned token handle,
    // when non-null, is closed on every path below.
    let opened = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
    if opened == 0 {
        return false;
    }
    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut returned = 0u32;
    // SAFETY: the buffer and its declared length match `TOKEN_ELEVATION`;
    // `returned` is a valid out-parameter.
    let result = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            std::ptr::addr_of_mut!(elevation).cast(),
            u32::try_from(std::mem::size_of::<TOKEN_ELEVATION>()).unwrap_or(0),
            &mut returned,
        )
    };
    // SAFETY: `token` came from `OpenProcessToken` and is ours to close; it
    // is not used afterwards.
    unsafe { CloseHandle(token) };
    result != 0 && elevation.TokenIsElevated != 0
}

/// Errors from route manipulation. `NotFound` and `Exists` are exposed so
/// callers can implement idempotent deletes and replace-on-add semantics.
#[derive(Debug, thiserror::Error)]
pub enum RouteError {
    /// The route entry does not exist (kernel replied `ESRCH`).
    #[error("the route entry does not exist")]
    NotFound,
    /// The route entry already exists (kernel replied `EEXIST`).
    #[error("the route entry already exists")]
    Exists,
    /// The kernel never acknowledged the request (read timeout).
    #[error("timed out waiting for the kernel route reply")]
    Timeout,
    /// The route request is invalid (family mismatch, bad prefix length).
    #[error("invalid route request: {0}")]
    Invalid(String),
    /// Any other OS error.
    #[error("route error: {0}")]
    Io(#[from] io::Error),
}

/// One route entry to install or remove: destination prefix pointed either
/// at a next-hop gateway IP (`gateway`) or directly at an interface
/// (`gateway: None` with `interface_index`, i.e. on-link).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Route {
    /// Destination prefix, host bits zeroed.
    pub destination: std::net::IpAddr,
    /// Prefix length (<= 32 IPv4, <= 128 IPv6).
    pub prefix_len: u8,
    /// Next-hop gateway IP, or `None` for on-link routes.
    pub gateway: Option<std::net::IpAddr>,
    /// Interface the route points into (its OS-level index).
    pub interface_index: u32,
    /// Optional route metric (macOS ignores metrics; Windows uses them).
    pub metric: Option<u32>,
}
