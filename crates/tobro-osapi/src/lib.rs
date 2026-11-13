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
//!   message, reading the reply. All message bytes are built from validated
//!   plain-data inputs (`std::net` types + interface indices); no attacker
//!   controlled lengths, pointers, or format strings exist.
//! - **Windows**: calling the two iphlpapi functions
//!   (`CreateIpForwardEntry2` / `DeleteIpForwardEntry2`) with a zeroed-out
//!   struct filled from validated plain-data inputs.
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
pub mod bsd_route;

#[cfg(target_os = "macos")]
pub mod sc_dns;

#[cfg(target_os = "windows")]
pub mod win_route;

use std::io;

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
