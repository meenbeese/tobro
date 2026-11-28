//! The privileged platform abstraction.
//!
//! [`Platform`] is the entire privileged surface of the helper: five
//! primitives, each taking validated `tobro-tun` types. Per-OS backends
//! (M7 T4) implement this trait; everything above it (dispatch, state,
//! rollback) is platform-independent and unit-tested here.
//!
//! Implementations must never shell out, must treat all inputs as already
//! validated (they are), and must be idempotent where the OS allows.

use async_trait::async_trait;

use tobro_tun::{DnsConfig, KillSwitchMode, RouteSpec, TunDevice, reject_codes};

/// What creating a TUN device produced.
///
/// The helper service owns the packet I/O and hands it to the routing engine
/// ([`crate::engine`]); the platform keeps only the bookkeeping teardown
/// needs (routes, DNS backup, kill switch). This split keeps the device's
/// lifetime in one place: stopping the engine closes it.
pub struct CreatedDevice {
    /// The actual interface name, which may differ from the requested one
    /// (macOS assigns `utunN`).
    pub interface: String,
    /// Packet I/O for the routing engine. `None` only in test backends: a
    /// real device is always returned so traffic has somewhere to go.
    pub packet_io: Option<tun2::AsyncDevice>,
}

impl std::fmt::Debug for CreatedDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print device handles; the name is not sensitive.
        f.debug_struct("CreatedDevice")
            .field("interface", &self.interface)
            .field("has_packet_io", &self.packet_io.is_some())
            .finish()
    }
}

/// Errors a privileged operation can produce, mapped to protocol rejection
/// codes so the client gets actionable answers.
#[derive(Debug, thiserror::Error)]
pub enum PlatformError {
    /// The build/platform cannot perform this operation yet.
    #[error("not implemented on this platform: {0}")]
    Unsupported(String),
    /// Creating/configuring the TUN device failed.
    #[error("TUN device error: {0}")]
    Device(String),
    /// Installing or removing routes failed.
    #[error("route error: {0}")]
    Route(String),
    /// Applying or reverting DNS settings failed.
    #[error("DNS error: {0}")]
    Dns(String),
    /// Installing or removing the kill switch failed.
    #[error("kill switch error: {0}")]
    KillSwitch(String),
}

impl PlatformError {
    /// The protocol rejection code for this error.
    pub fn reject_code(&self) -> u32 {
        match self {
            PlatformError::Unsupported(_) => reject_codes::UNSUPPORTED,
            PlatformError::Device(_) => reject_codes::DEVICE_ERROR,
            PlatformError::Route(_) => reject_codes::ROUTE_ERROR,
            PlatformError::Dns(_) => reject_codes::DNS_ERROR,
            PlatformError::KillSwitch(_) => reject_codes::KILL_SWITCH_ERROR,
        }
    }
}

/// The privileged primitives. Five calls, all taking validated types.
#[async_trait]
pub trait Platform: Send + Sync {
    /// Create a fresh TUN device and assign its addresses. Returns the actual
    /// interface name (which may differ from the requested one; macOS assigns
    /// `utunN`) and the packet I/O the service hands to the routing engine.
    ///
    /// The previous device is already closed when this is called: the service
    /// stops the engine (which owns packet I/O) before converging to a new
    /// plan, so backends always create a new device instead of reusing one.
    async fn create_device(&self, device: &TunDevice) -> Result<CreatedDevice, PlatformError>;

    /// Converge the route table: `routes` point into the tunnel at
    /// `interface`, `bypass_routes` point at real gateways.
    async fn apply_routes(
        &self,
        interface: &str,
        routes: &[RouteSpec],
        bypass_routes: &[RouteSpec],
    ) -> Result<(), PlatformError>;

    /// Apply system-wide DNS settings for the tunnel lifetime.
    async fn apply_dns(&self, dns: &DnsConfig) -> Result<(), PlatformError>;

    /// Install or adjust the kill switch enforcement for the given mode.
    /// `bypass_routes` are the plan's split-tunnel bypass destinations:
    /// enforcement must permit traffic to them even while everything else is
    /// blocked. Ignored by `Restore`.
    async fn apply_kill_switch(
        &self,
        mode: KillSwitchMode,
        bypass_routes: &[RouteSpec],
    ) -> Result<(), PlatformError>;

    /// Remove everything this helper set up: device, routes, DNS settings,
    /// kill switch. Must be safe to call repeatedly (idempotent) and must
    /// restore the pre-helper state even after partial failures.
    async fn teardown(&self) -> Result<(), PlatformError>;

    /// Recover after a killing process left state behind.
    ///
    /// Called on a freshly constructed backend at startup (a restarted
    /// helper) and from the watchdog child that survives a killed helper.
    /// Uses the persistent [`crate::recovery`] journal. Per the kill-switch
    /// policy recorded there, a tunnel lost because the daemon or helper was
    /// killed **restores** pre-tunnel networking (`restore`/`disabled`) or
    /// stays **blocked** (`block`); in-memory state is gone, but anything
    /// still applied in the kernel is only undone when restoring.
    ///
    /// Best-effort and idempotent; a no-op when nothing was left applied.
    async fn recover_on_startup(&self) -> Result<(), PlatformError> {
        Ok(())
    }
}

/// Placeholder backend (M7 T3): the protocol works end-to-end, but every
/// privileged operation is rejected with `UNSUPPORTED`. Replaced by the
/// per-OS backends in M7 T4.
#[derive(Debug, Default)]
pub struct NullPlatform;

const UNSUPPORTED_REASON: &str =
    "the TUN backend is not implemented in this build yet (planned in milestone M7)";

#[async_trait]
impl Platform for NullPlatform {
    async fn create_device(&self, _device: &TunDevice) -> Result<CreatedDevice, PlatformError> {
        Err(PlatformError::Unsupported(UNSUPPORTED_REASON.to_owned()))
    }

    async fn apply_routes(
        &self,
        _interface: &str,
        _routes: &[RouteSpec],
        _bypass_routes: &[RouteSpec],
    ) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported(UNSUPPORTED_REASON.to_owned()))
    }

    async fn apply_dns(&self, _dns: &DnsConfig) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported(UNSUPPORTED_REASON.to_owned()))
    }

    async fn apply_kill_switch(
        &self,
        _mode: KillSwitchMode,
        _bypass_routes: &[RouteSpec],
    ) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported(UNSUPPORTED_REASON.to_owned()))
    }

    async fn teardown(&self) -> Result<(), PlatformError> {
        // Nothing was ever applied: teardown succeeds as a no-op so the
        // client sees a clean, honest lifecycle.
        Ok(())
    }
}
