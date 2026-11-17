//! `tobro-install` — installer/uninstaller for the privileged `tobro-helper`
//! (M7, plan §4.7/§10.5).
//!
//! The unprivileged daemon never spawns the helper; this crate integrates the
//! helper with the platform service managers instead, so the *OS* runs it as
//! root/system on demand:
//!
//! | OS | Binary target | Registration | Activation | Prompt |
//! |---|---|---|---|---|
//! | Linux | `/usr/local/bin/tobro-helper` | systemd system units | socket activation (`tobro-helper.socket` starts the helper on the first IPC connection; the idle window stops it again) | `pkexec` (polkit) |
//! | macOS | `/Library/PrivilegedHelperTools/tobro-helper` | LaunchDaemon plist | run-at-load + relaunch on crash; idle window stops it; re-start needs one elevated `launchctl kickstart` | `osascript` administrator prompt |
//! | Windows | `%ProgramFiles%\Tobro\helper\tobro-helper.exe` (+ `wintun.dll`) | Windows service (demand start) | the daemon starts/stops it (`SERVICE_START`/`SERVICE_STOP` granted to interactive users at install) | UAC via `Start-Process -Verb RunAs` |
//!
//! Every privileged step runs as **one generated script** through the
//! platform's elevation mechanism — the OS privilege prompt is the UI. The
//! daemon (unprivileged) only ever asks the user; it never holds elevated
//! rights itself.
//!
//! # Security posture
//!
//! - Scripts are generated here from validated constants and daemon-chosen
//!   paths only. No user input is interpolated: source/target paths are
//!   shell-quoted ([`elevate::sh_single_quote`]/[`elevate::powershell_quote`])
//!   and control characters are rejected up front ([`InstallSpec::validate`]).
//! - The optional SHA-256 pin (`tun.helper_sha256_hex`) is enforced against
//!   the *source* binary before anything is elevated, and re-checked
//!   informationally against the installed copy by [`status`].
//! - Elevation is always an explicit user-initiated action (IPC
//!   `tun.helper.install` / `tun.helper.uninstall`); nothing here prompts on
//!   its own.
//! - Idempotency: both directions converge (re-install refreshes the binary
//!   and re-registers; uninstall tolerates a half-installed state).
//! - Uninstall stops the service first (SIGTERM/service-stop makes the
//!   helper tear down its device, routes, and DNS — its own exit path), then
//!   removes the registration and binary, so no routes or DNS settings
//!   outlive the uninstall.
//!
//! # Not done here
//!
//! macOS `SMAppService`/SMJobBless registration (the plan's target design)
//! needs the signed GUI app bundle and lands with packaging (M8); the
//! LaunchDaemon plist is the audited interim. The Windows pipe DACL and
//! SID-based peer check remain documented interims in `tobro-helper`.

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
mod null;
#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "linux")]
use linux as platform;
#[cfg(target_os = "macos")]
use macos as platform;
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
use null as platform;
#[cfg(target_os = "windows")]
use windows as platform;

pub mod elevate;

use std::path::PathBuf;

/// Install the helper: copy the binary to the privileged location and
/// register it with the service manager, then ensure it is running.
///
/// Blocking; runs one elevated child process and waits for the user to
/// answer the OS privilege prompt (callers should wrap in a generous
/// timeout). Idempotent.
pub fn install(spec: &InstallSpec) -> Result<InstallReport, InstallError> {
    spec.validate()?;
    let sha256_hex = spec.verify_source_hash()?;
    platform::install(
        &elevate::ProcessRunner,
        &platform::Locations::system(),
        spec,
        sha256_hex,
    )
}

/// Uninstall the helper: stop and deregister the service, then remove the
/// binary. The helper's own stop path tears down device, routes, and DNS.
/// Blocking; idempotent (a clean system uninstalls successfully with no
/// actions).
pub fn uninstall(spec: &InstallSpec) -> Result<UninstallReport, InstallError> {
    spec.validate()?;
    platform::uninstall(
        &elevate::ProcessRunner,
        &platform::Locations::system(),
        spec,
    )
}

/// Best-effort, non-elevated install status (no prompts, no writes). Uses
/// the relaxed shape validation: a missing source binary does not hide a
/// previously installed helper at the privileged target.
pub fn status(spec: &InstallSpec) -> InstallStatus {
    match spec.validate_shapes() {
        Ok(()) => platform::status(
            &elevate::ProcessRunner,
            &platform::Locations::system(),
            spec,
        ),
        Err(_) => InstallStatus::invalid(),
    }
}

/// The platform installer name (for status/report payloads).
pub fn platform_name() -> &'static str {
    platform::NAME
}

// --- Spec ------------------------------------------------------------------

/// What to install: the located helper binary plus the knobs the generated
/// service definitions need.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallSpec {
    /// The `tobro-helper` binary to install (absolute path, must exist).
    pub source_binary: PathBuf,
    /// Unix only: group name for the IPC socket (mode 0660), so the
    /// unprivileged daemon may connect to the root-owned socket. Required on
    /// Unix; ignored elsewhere.
    pub socket_group: Option<String>,
    /// Optional SHA-256 pin (lowercase hex, as `tun.helper_sha256_hex`).
    /// Enforced against the source binary before elevating.
    pub sha256_hex: Option<String>,
}

impl InstallSpec {
    /// Validate the spec up front: absolute existing source, embeddable
    /// strings, group-name shape, hash-pin shape.
    pub fn validate(&self) -> Result<(), InstallError> {
        if !self.source_binary.is_absolute() {
            return Err(InstallError::SourceInvalid(
                "the helper binary path must be absolute".to_owned(),
            ));
        }
        let source = self
            .source_binary
            .to_str()
            .ok_or_else(|| InstallError::SourceInvalid("non-UTF-8 binary path".to_owned()))?;
        elevate::validate_embeddable(source, "source_binary")?;
        if !self.source_binary.is_file() {
            return Err(InstallError::SourceMissing(
                self.source_binary.display().to_string(),
            ));
        }
        self.validate_shapes()
    }

    /// Validate only the embeddable-value shapes (no source-binary lookup).
    /// Used by non-elevated [`status`] probes, which must work whether or not
    /// a source binary is present (a previous install may exist).
    pub fn validate_shapes(&self) -> Result<(), InstallError> {
        if let Some(group) = &self.socket_group
            && (!group
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '$'))
                || group.len() > 64)
        {
            return Err(InstallError::SourceInvalid(format!(
                "socket_group {group:?} is not a valid group name"
            )));
        }
        if let Some(hex) = &self.sha256_hex {
            let valid = hex.len() == 64
                && hex
                    .chars()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase());
            if !valid {
                return Err(InstallError::SourceInvalid(
                    "sha256_hex must be 64 lowercase hex characters".to_owned(),
                ));
            }
        }
        Ok(())
    }

    /// SHA-256 of the source binary; verifies the pin when one is set.
    fn verify_source_hash(&self) -> Result<String, InstallError> {
        let actual = sha256_file_hex(&self.source_binary).ok_or_else(|| {
            InstallError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "could not read the helper binary to hash it",
            ))
        })?;
        if let Some(expected) = &self.sha256_hex
            && &actual != expected
        {
            return Err(InstallError::HashMismatch {
                expected: expected.clone(),
                actual,
            });
        }
        Ok(actual)
    }
}

// --- Reports / status ------------------------------------------------------

/// What an install did (for status payloads and diagnostics).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallReport {
    /// Privileged location the binary was installed at.
    pub target_binary: String,
    /// Human-readable action names performed, in order (safe to show: these
    /// are fixed strings generated here, never paths or destinations).
    pub actions: Vec<String>,
    /// SHA-256 of the installed (source) binary, lowercase hex.
    pub sha256_hex: String,
}

/// What an uninstall did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UninstallReport {
    /// Human-readable action names performed, in order.
    pub actions: Vec<String>,
    /// True when nothing was installed to begin with.
    pub already_clean: bool,
}

/// Non-elevated install status (what `tun.status` reports).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallStatus {
    /// The helper binary exists at its privileged target.
    pub binary_installed: bool,
    /// The service definition is registered (unit file / plist / service).
    pub service_registered: bool,
    /// The service manager reports the service running. `None` when the
    /// service manager could not be consulted.
    pub service_running: Option<bool>,
    /// The privileged target path (informational).
    pub target_binary: String,
    /// When a pin is configured: whether the installed binary matches it.
    pub sha256_matches: Option<bool>,
    /// Windows only: whether `wintun.dll` is installed next to the helper.
    /// `None` on platforms that do not use the wintun driver.
    pub wintun_installed: Option<bool>,
}

impl InstallStatus {
    /// Status for an unvalidatable spec / unsupported platform: nothing
    /// known except that nothing was verified.
    pub fn invalid() -> Self {
        Self {
            binary_installed: false,
            service_registered: false,
            service_running: None,
            target_binary: String::new(),
            sha256_matches: None,
            wintun_installed: None,
        }
    }

    /// Installed end to end (binary present and registered).
    pub fn installed(&self) -> bool {
        self.binary_installed && self.service_registered
    }

    /// Whether the Windows wintun driver is installed (`false` when the
    /// platform does not use it).
    pub fn wintun_installed(&self) -> bool {
        self.wintun_installed.unwrap_or(false)
    }

    /// JSON form for the `tun.status` payload.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "platform": platform_name(),
            "installed": self.installed(),
            "binary_installed": self.binary_installed,
            "service_registered": self.service_registered,
            "service_running": self.service_running,
            "target_binary": self.target_binary,
            "sha256_matches": self.sha256_matches,
            "wintun_installed": self.wintun_installed,
        })
    }
}

// --- Shared helpers --------------------------------------------------------

/// SHA-256 of a file as lowercase hex; `None` when unreadable.
pub(crate) fn sha256_file_hex(path: &std::path::Path) -> Option<String> {
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(path).ok()?;
    let digest = Sha256::digest(&bytes);
    Some(hex::encode(digest))
}

/// Errors from install/uninstall.
#[derive(Debug, thiserror::Error)]
pub enum InstallError {
    /// The spec is invalid (bad path, bad group name, bad hash pin).
    #[error("invalid install specification: {0}")]
    SourceInvalid(String),
    /// The source helper binary does not exist.
    #[error("the helper binary was not found at {0}")]
    SourceMissing(String),
    /// The Windows wintun driver library is missing next to the source helper.
    #[error(
        "the wintun driver library was not found at {0}; packaged builds ship wintun.dll next to tobro-helper (Windows builds require it for TUN device creation)"
    )]
    WintunMissing(String),
    /// The source binary does not match the configured SHA-256 pin.
    #[error(
        "helper binary does not match the configured SHA-256 pin (expected {expected}, got {actual}); refusing to install a binary the user pinned"
    )]
    HashMismatch {
        /// Configured pin.
        expected: String,
        /// Actual hash of the source binary.
        actual: String,
    },
    /// The elevation prompt was declined, failed, or never completed.
    #[error("elevated install step failed: {0}")]
    Elevation(String),
    /// The elevated step ran but reported a failure of its own.
    #[error("the elevated installer reported a failure: {0}")]
    Script(String),
    /// No installer exists for this platform.
    #[error("there is no helper installer for this platform")]
    Unsupported,
    /// Local I/O (reading the binary, writing scripts, reading results).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn spec(source: &std::path::Path) -> InstallSpec {
        InstallSpec {
            source_binary: source.to_path_buf(),
            socket_group: if cfg!(unix) {
                Some("staff".to_owned())
            } else {
                None
            },
            sha256_hex: None,
        }
    }

    #[test]
    fn spec_rejects_relative_sources() {
        let error = InstallSpec {
            source_binary: PathBuf::from("relative/tobro-helper"),
            socket_group: None,
            sha256_hex: None,
        }
        .validate()
        .expect_err("relative paths must be rejected");
        assert!(error.to_string().contains("absolute"), "{error}");
    }

    #[test]
    fn spec_rejects_missing_sources() {
        let dir = tempfile::tempdir().unwrap();
        let error = spec(&dir.path().join("tobro-helper"))
            .validate()
            .expect_err("missing binaries must be rejected");
        assert!(matches!(error, InstallError::SourceMissing(_)), "{error}");
    }

    #[test]
    fn spec_allows_a_missing_socket_group_for_status_probes() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("tobro-helper");
        std::fs::write(&source, b"binary").unwrap();
        let mut checked = spec(&source);
        checked.socket_group = None;
        // The spec itself does not require the group (status probes run
        // without one); the per-platform install() functions do — covered by
        // the `plist_requires_the_socket_group` test in `macos.rs`.
        checked
            .validate()
            .expect("the spec validates without a group");
    }

    #[test]
    fn spec_rejects_bad_group_names_and_pins() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("tobro-helper");
        std::fs::write(&source, b"binary").unwrap();

        let mut checked = spec(&source);
        checked.socket_group = Some("bad group".to_owned());
        let error = checked.validate().expect_err("spaces are not a group name");
        assert!(error.to_string().contains("group name"), "{error}");

        let mut checked = spec(&source);
        checked.sha256_hex = Some("ABCD".to_owned());
        let error = checked
            .validate()
            .expect_err("pins must be 64 lowercase hex");
        assert!(error.to_string().contains("64 lowercase hex"), "{error}");
    }

    #[test]
    fn status_shapes_pass_without_a_source() {
        // Status probes must work when no source binary exists (a previous
        // install may still be present at the privileged target).
        let checked = InstallSpec {
            source_binary: PathBuf::from("/definitely/not/here/tobro-helper"),
            socket_group: if cfg!(unix) {
                Some(String::new())
            } else {
                None
            },
            sha256_hex: None,
        };
        assert!(checked.validate_shapes().is_ok());
        assert!(
            checked.validate().is_err(),
            "install still requires the source"
        );
        let status = status(&checked);
        assert!(!status.installed());
        assert_eq!(status.sha256_matches, None);
    }

    #[test]
    fn spec_enforces_the_hash_pin_before_installing() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("tobro-helper");
        std::fs::write(&source, b"binary").unwrap();
        let mut checked = spec(&source);
        checked.sha256_hex = Some("0".repeat(64));
        checked.validate().expect("the spec itself is fine");
        // The pin check happens in verify_source_hash (called by install).
        let error = checked.verify_source_hash().expect_err("pin mismatch");
        assert!(
            matches!(error, InstallError::HashMismatch { .. }),
            "{error}"
        );
    }

    #[test]
    fn spec_accepts_a_matching_pin() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("tobro-helper");
        std::fs::write(&source, b"binary").unwrap();
        let mut checked = spec(&source);
        checked.sha256_hex = Some(sha256_file_hex(&source).unwrap());
        checked.verify_source_hash().expect("matching pin passes");
    }

    #[test]
    fn status_without_a_source_still_probes_the_system_locations() {
        // Status probes use the relaxed shape validation, so a missing source
        // binary does not hide a previously installed helper. This must not
        // depend on host state: only internal consistency is asserted.
        let bad = spec(&std::path::PathBuf::from("/definitely/missing/helper"));
        assert!(bad.validate().is_err(), "install requires the source");
        let status = status(&bad);
        assert_eq!(
            status.installed(),
            status.binary_installed && status.service_registered
        );
        assert_eq!(status.sha256_matches, None, "no pin configured");
    }
}
