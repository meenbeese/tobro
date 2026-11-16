//! Placeholder for platforms without a helper installer (anything that is
//! not Linux, macOS, or Windows). Everything reports unsupported.

use crate::elevate::Runner;
use crate::{InstallError, InstallReport, InstallSpec, InstallStatus, UninstallReport};

/// Platform name for status payloads.
pub const NAME: &str = "unsupported";

/// The install locations structure exists for signature parity; there is no
/// system location to use.
#[derive(Debug, Clone)]
pub struct Locations;

impl Locations {
    /// No system locations on unsupported platforms.
    #[must_use]
    pub fn system() -> Self {
        Self
    }
}

/// Unsupported: no installer.
pub fn install<R: Runner>(
    _runner: &R,
    _locations: &Locations,
    _spec: &InstallSpec,
    _sha256_hex: String,
) -> Result<InstallReport, InstallError> {
    Err(InstallError::Unsupported)
}

/// Unsupported: no uninstaller.
pub fn uninstall<R: Runner>(
    _runner: &R,
    _locations: &Locations,
    _spec: &InstallSpec,
) -> Result<UninstallReport, InstallError> {
    Err(InstallError::Unsupported)
}

/// Unsupported: nothing is known.
pub fn status<R: Runner>(
    _runner: &R,
    _locations: &Locations,
    _spec: &InstallSpec,
) -> InstallStatus {
    InstallStatus::invalid()
}
