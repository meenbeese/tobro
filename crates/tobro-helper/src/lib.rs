//! `tobro-helper` — the privileged TUN helper (M7, plan §4.7/§10.5).
//!
//! The helper runs as root/system, owns the TUN device, routes, and DNS
//! settings, and serves exactly one unprivileged client (the `tobrod`
//! daemon) over the [`tobro_tun`] protocol.
//!
//! # Security posture (§10.5)
//!
//! - Separate minimal binary; no network listeners — only the local IPC
//!   endpoint ([`serve_unix`] / [`serve_windows`]).
//! - Fixed command set: whatever [`tobro_tun::HelperRequest`] allows, and
//!   nothing else. No shell, no arbitrary paths, no arguments passed to
//!   external programs.
//! - All plan inputs are re-validated on receipt
//!   ([`tobro_tun::TunnelPlan::validate`]); decoded values are untrusted.
//! - Peer-identity gating: on Unix the connecting user must match the user
//!   that performed the first handshake; unverifiable peers are denied.
//! - Logs contain operation kinds and counts only — never destinations,
//!   routes, or DNS servers.
//! - Logs go to stderr; the service manager captures them into the system
//!   log. The daemon-facing protocol carries no secrets.
//!
//! # Skeleton status
//!
//! The protocol loop, peer gating, state machine, and dispatch are complete.
//! The privileged platform backends ([`Platform`]) are per-OS: Linux has the
//! real TUN/netlink backend ([`LinuxPlatform`], T4a), macOS the utun
//! backend ([`MacosPlatform`], T4b), Windows the wintun backend
//! ([`WindowsPlatform`], T4c). Any other platform still gets
//! [`NullPlatform`], which rejects privileged operations with `UNSUPPORTED`.
//!
//! "Runs only while TUN is enabled" is honored by [`Args::idle_exit_secs`]:
//! the helper exits cleanly when no client connects within the window.

pub mod platform;
#[cfg(target_os = "linux")]
pub mod platform_linux;
#[cfg(target_os = "macos")]
pub mod platform_macos;
#[cfg(target_os = "windows")]
pub mod platform_windows;
pub mod service;
pub mod session;

pub use platform::{NullPlatform, Platform, PlatformError};
#[cfg(target_os = "linux")]
pub use platform_linux::LinuxPlatform;
#[cfg(target_os = "macos")]
pub use platform_macos::MacosPlatform;
#[cfg(target_os = "windows")]
pub use platform_windows::WindowsPlatform;
pub use service::HelperService;
#[cfg(unix)]
pub use session::serve_unix;
#[cfg(windows)]
pub use session::serve_windows;
pub use session::{PeerGate, PeerIdentity, ServeExit, shutdown_signal};

/// The platform backend selected at compile time. Linux, macOS, and Windows
/// have real backends (M7 T4); other platforms get the placeholder.
#[cfg(target_os = "linux")]
pub type ActivePlatform = LinuxPlatform;
#[cfg(target_os = "macos")]
pub type ActivePlatform = MacosPlatform;
#[cfg(target_os = "windows")]
pub type ActivePlatform = WindowsPlatform;
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub type ActivePlatform = NullPlatform;

/// Construct the active backend, failing fast on OS-level setup errors
/// (e.g. netlink unavailable).
#[cfg(target_os = "linux")]
pub fn new_active_platform() -> Result<ActivePlatform, PlatformError> {
    LinuxPlatform::connect()
}

#[cfg(target_os = "macos")]
pub fn new_active_platform() -> Result<ActivePlatform, PlatformError> {
    Ok(MacosPlatform::new())
}

#[cfg(target_os = "windows")]
pub fn new_active_platform() -> Result<ActivePlatform, PlatformError> {
    Ok(WindowsPlatform::new())
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub fn new_active_platform() -> Result<ActivePlatform, PlatformError> {
    Ok(NullPlatform)
}

use clap::Parser;

/// Command-line interface of the helper binary.
#[derive(Debug, Parser)]
#[command(
    name = "tobro-helper",
    about = "Privileged TUN helper for tobro (M7).",
    version
)]
pub struct Args {
    /// IPC endpoint to listen on (Unix socket path / Windows named pipe).
    /// Defaults to the platform endpoint from `tobro-tun`.
    #[arg(long)]
    pub socket: Option<String>,
    /// Exit cleanly after this many seconds without a client connection
    /// (0 = run until signaled). This keeps the helper running only while
    /// TUN mode needs it.
    #[arg(long, default_value_t = 0)]
    pub idle_exit_secs: u64,
}

/// Initialize stderr logging. EnvFilter honors `RUST_LOG`; never log
/// protocol payloads.
pub fn init_logging() {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
}
