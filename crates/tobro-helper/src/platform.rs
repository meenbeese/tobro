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
    /// Create the TUN device (or reuse the existing one) and assign its
    /// addresses. Returns the actual interface name, which may differ from
    /// the requested one (macOS assigns `utunN`).
    async fn create_device(&self, device: &TunDevice) -> Result<String, PlatformError>;

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
    async fn apply_kill_switch(&self, mode: KillSwitchMode) -> Result<(), PlatformError>;

    /// Remove everything this helper set up: device, routes, DNS settings,
    /// kill switch. Must be safe to call repeatedly (idempotent) and must
    /// restore the pre-helper state even after partial failures.
    async fn teardown(&self) -> Result<(), PlatformError>;
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
    async fn create_device(&self, _device: &TunDevice) -> Result<String, PlatformError> {
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

    async fn apply_kill_switch(&self, _mode: KillSwitchMode) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported(UNSUPPORTED_REASON.to_owned()))
    }

    async fn teardown(&self) -> Result<(), PlatformError> {
        // Nothing was ever applied: teardown succeeds as a no-op so the
        // client sees a clean, honest lifecycle.
        Ok(())
    }
}
