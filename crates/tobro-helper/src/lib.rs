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
//! The protocol loop, peer gating, state machine, dispatch, the per-OS
//! privileged backends ([`Platform`]), and the routing engine ([`engine`])
//! are complete. Linux has the real TUN/netlink backend ([`LinuxPlatform`],
//! T4a), macOS the utun backend ([`MacosPlatform`], T4b), Windows the wintun
//! backend ([`WindowsPlatform`], T4c). Any other platform still gets
//! [`NullPlatform`], which rejects privileged operations with `UNSUPPORTED`.
//!
//! The engine ([`engine::EngineHandle`]) terminates the tunnel's TCP flows
//! through the daemon's loopback SOCKS5 listener, relays intercepted DNS to
//! the daemon's local resolver, and applies the plan's UDP policy.
//!
//! "Runs only while TUN is enabled" is honored by [`Args::idle_exit_secs`]:
//! the helper exits cleanly when no client connects within the window.

pub mod engine;
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
    /// Unix only: chgrp/chmod the IPC socket to this group with mode 0660
    /// after binding, so the named group (the daemon user's primary group,
    /// chosen by the installer) may connect to the root-owned socket. When
    /// unset the socket stays 0600 (owner-only). Required by the installed
    /// macOS LaunchDaemon; the Linux systemd socket unit handles its own
    /// permissions, and Windows named pipes do not use file modes.
    #[arg(long)]
    pub socket_group: Option<String>,
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

/// Prepare the Unix listener the serve loop accepts from (macOS/Linux).
///
/// Resolution order:
///
/// 1. A service-manager-passed listening socket (systemd socket activation,
///    the `LISTEN_PID`/`LISTEN_FDS` protocol), when present. The installed
///    Linux units activate the helper on demand this way; systemd owns the
///    socket inode and its permissions.
/// 2. Bind `endpoint` ourselves via [`tobro_tun::bind_listener`] (0600, with
///    stale-socket replacement) — the manual-run behavior.
///
/// Afterwards, when `socket_group` is set (the installed macOS LaunchDaemon
/// passes it), the socket file is chgrp'd to that group and chmod 0660 so
/// the unprivileged daemon can connect to the root-owned socket. This fails
/// closed: an unresolvable group is a hard error, because a silently
/// mis-permissioned socket would leave the installed daemon unable to
/// connect with nothing explaining why.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub async fn prepare_listener(
    endpoint: &std::path::Path,
    socket_group: Option<&str>,
) -> std::io::Result<tokio::net::UnixListener> {
    let listener = match tobro_osapi::unix_ids::take_inherited_listen_fd() {
        Some(std_listener) => {
            tracing::info!("using the service-manager passed listening socket");
            std_listener.set_nonblocking(true)?;
            tokio::net::UnixListener::from_std(std_listener)?
        }
        None => tobro_tun::bind_listener(endpoint)
            .await
            .map_err(|error| std::io::Error::other(error.to_string()))?,
    };
    if let Some(group) = socket_group {
        let Some(gid) = tobro_osapi::unix_ids::group_gid(group) else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("--socket-group {group:?} does not exist on this system"),
            ));
        };
        tobro_osapi::unix_ids::chown_group(endpoint, gid)?;
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(endpoint, std::fs::Permissions::from_mode(0o660))?;
        }
        tracing::info!("IPC socket group set to {group} (0660)");
    }
    Ok(listener)
}
