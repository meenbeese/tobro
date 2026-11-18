//! User-facing installer/uninstaller orchestration for the privileged
//! `tobro-helper` (M7: installer integration + privilege prompts).
//!
//! The daemon never spawns the helper; what it *can* do on explicit request
//! (IPC `tun.helper.install` / `tun.helper.uninstall`) is drive the platform
//! installer from [`tobro_install`]:
//!
//! 1. Locate the helper binary the daemon would otherwise run
//!    ([`crate::tun_manager::locate_helper_binary`]: config override, then
//!    sidecar/bundle locations).
//! 2. Enforce the configured SHA-256 pin (`tun.helper_sha256_hex`) on the
//!    source before anything elevated happens (supply chain, §10.6).
//! 3. Resolve the IPC access identity: the daemon user's primary group on
//!    Unix (the installed service runs as root, and its socket must be
//!    connectable by exactly this group), and the daemon user's SID on
//!    Windows (the named-pipe DACL, the service DACL, and the helper's
//!    `--allow-sid` gate are all scoped to it).
//! 4. Run the one elevated platform step (pkexec / osascript / UAC — the OS
//!    privilege prompt is the UI), inside a generous timeout because the
//!    user has to answer the prompt.
//! 5. On uninstall: best-effort [`TunManager::teardown`] first, so device,
//!    routes, and DNS are restored before the service is stopped (the stop
//!    itself also triggers the helper's own teardown path).
//!
//! [`tun.status`] reports the non-elevated [`tobro_install::InstallStatus`]
//! alongside the running-probe result so UIs can offer the right action.

use std::path::Path;
use std::time::Duration;

use serde_json::json;

use crate::tun_manager::TunManager;

/// How long the elevation prompt may stay open (the OS waits for the user to
/// answer; UAC dialogs time out on their own, polkit/osascript wait).
const ELEVATION_TIMEOUT: Duration = Duration::from_secs(300);

/// Build the install spec from config: locate the binary, resolve the socket
/// group, pass the pin through.
fn spec(config: &tobro_config::TunConfig) -> Result<tobro_install::InstallSpec, String> {
    let source_binary = crate::tun_manager::locate_helper_binary(config).ok_or_else(|| {
        "could not find the tobro-helper binary: set tun.helper_path / tun.helper_dir, or \
         place the helper next to the daemon"
            .to_owned()
    })?;
    Ok(tobro_install::InstallSpec {
        source_binary,
        socket_group: socket_group_for_daemon()?,
        sha256_hex: config.helper_sha256_hex.clone(),
        client_sid: client_sid_for_daemon()?,
    })
}

/// Install the helper. Long-running (the user answers an OS privilege
/// prompt); returns the report JSON for the IPC response.
pub async fn install(
    config_path: &Path,
    manager: &TunManager,
) -> Result<serde_json::Value, String> {
    let config = load_config(config_path).await?;
    let spec = spec(&config.tun)?;
    let started = std::time::Instant::now();
    let report = elevate(spec.clone(), |spec| tobro_install::install(&spec)).await?;
    manager.probe().await;
    Ok(json!({
        "ok": true,
        "action": "tun.helper.install",
        "platform": tobro_install::platform_name(),
        "source_binary": spec.source_binary.display().to_string(),
        "target_binary": report.target_binary,
        "sha256_hex": report.sha256_hex,
        "actions": report.actions,
        "elapsed_ms": u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        "note": "the helper was installed with an OS privilege prompt; the service is managed by the OS",
    }))
}

/// Uninstall the helper. Tears the tunnel down first (restoring routes and
/// DNS), then stops, deregisters, and removes the helper.
pub async fn uninstall(
    config_path: &Path,
    manager: &TunManager,
) -> Result<serde_json::Value, String> {
    let config = load_config(config_path).await?;
    let spec = spec(&config.tun)?;
    // Belt and suspenders: the tunnel comes down through the helper protocol
    // before the service is stopped (whose own stop path also tears down).
    manager.teardown("helper uninstall").await;
    let report = elevate(spec, |spec| tobro_install::uninstall(&spec)).await?;
    manager.probe().await;
    Ok(json!({
        "ok": true,
        "action": "tun.helper.uninstall",
        "platform": tobro_install::platform_name(),
        "actions": report.actions,
        "already_clean": report.already_clean,
        "note": if report.already_clean {
            "nothing was installed"
        } else {
            "the helper, its registration, and any applied system state were removed"
        },
    }))
}

/// Non-elevated install status for the `tun.status` payload.
pub fn status(config: &tobro_config::TunConfig) -> serde_json::Value {
    match spec(config) {
        Ok(spec) => tobro_install::status(&spec).to_json(),
        // Without a locatable binary the installer cannot run, but the
        // privileged target may still hold a previously installed helper:
        // probe it without a spec (no pin check possible).
        Err(_) => {
            let mut value = tobro_install::status(&spec_without_binary(config)).to_json();
            value["note"] = json!(
                "the helper binary to install was not found next to the daemon; set tun.helper_path or tun.helper_dir"
            );
            value
        }
    }
}

/// Status probe for the case where the *source* is missing but an install may
/// exist: same spec, empty source (only used for non-elevated status reads).
fn spec_without_binary(config: &tobro_config::TunConfig) -> tobro_install::InstallSpec {
    tobro_install::InstallSpec {
        source_binary: std::path::PathBuf::from("/nonexistent/tobro-helper"),
        socket_group: if cfg!(unix) {
            Some(String::new())
        } else {
            None
        },
        sha256_hex: config.helper_sha256_hex.clone(),
        // Status probes never install, so no access identity is embedded; a
        // missing SID must not hide a previously installed helper.
        client_sid: None,
    }
}

/// Run a blocking elevation step off the async core, bounded by
/// [`ELEVATION_TIMEOUT`] (the prompt waits for a human).
async fn elevate<T>(
    spec: tobro_install::InstallSpec,
    step: impl FnOnce(tobro_install::InstallSpec) -> Result<T, tobro_install::InstallError>
    + Send
    + 'static,
) -> Result<T, String>
where
    T: Send + 'static,
{
    let task = tokio::task::spawn_blocking(move || step(spec));
    let result = tokio::time::timeout(ELEVATION_TIMEOUT, task)
        .await
        .map_err(|_| {
            "the privilege prompt timed out; nothing was changed (run the operation again)"
                .to_owned()
        })?
        .map_err(|error| format!("the elevated install task failed: {error}"))?;
    result.map_err(|error| error.to_string())
}

/// The IPC socket group for the installed helper (Unix only): the daemon
/// user's primary group, because the installed service runs as root and its
/// socket must be connectable by exactly this group.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn socket_group_for_daemon() -> Result<Option<String>, String> {
    Ok(Some(
        tobro_osapi::unix_ids::primary_group_name().ok_or_else(|| {
            "could not resolve this user's primary group (needed for the helper's \
             IPC socket permissions)"
                .to_owned()
        })?,
    ))
}

/// Non-Unix: no group concept; the service DACL/pipe security handles access.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn socket_group_for_daemon() -> Result<Option<String>, String> {
    Ok(None)
}

/// The access identity for the installed helper (Windows only): this user's
/// SID. The installer scopes the named-pipe DACL, the service DACL, and the
/// helper's `--allow-sid` gate to it, so a failure to resolve it must fail the
/// install rather than fall back to a broader default DACL.
#[cfg(target_os = "windows")]
fn client_sid_for_daemon() -> Result<Option<String>, String> {
    Ok(Some(
        tobro_osapi::win_pipe::current_user_sid_string().ok_or_else(|| {
            "could not resolve this user's SID (needed to scope the helper's \
             IPC named pipe and service access)"
                .to_owned()
        })?,
    ))
}

/// Non-Windows: SIDs do not exist; the Unix socket group carries access.
#[cfg(not(target_os = "windows"))]
fn client_sid_for_daemon() -> Result<Option<String>, String> {
    Ok(None)
}

/// Load and validate the config (validation runs even with TUN disabled, so
/// a broken `tun.*` edit cannot reach the installer).
async fn load_config(config_path: &Path) -> Result<tobro_config::Config, String> {
    let path = config_path.to_path_buf();
    let config = tokio::task::spawn_blocking(move || tobro_config::Config::load_or_default(&path))
        .await
        .map_err(|error| format!("config load task failed: {error}"))?
        .map_err(|error| format!("failed to load config: {error}"))?;
    config
        .validate()
        .map_err(|error| format!("invalid config: {error}"))?;
    Ok(config)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn status_reports_a_missing_source_with_a_note() {
        let config = tobro_config::TunConfig::default();
        let value = status(&config);
        assert!(
            value["note"]
                .as_str()
                .unwrap_or_default()
                .contains("helper binary to install was not found"),
            "{value}"
        );
    }

    #[test]
    fn status_json_carries_platform_and_probe_fields() {
        let config = tobro_config::TunConfig::default();
        let value = status(&config);
        assert_eq!(value["platform"], tobro_install::platform_name());
        // Structural fields exist; the probed values depend on the host, so
        // only their types are checked.
        assert!(value["installed"].is_boolean());
        assert!(value["binary_installed"].is_boolean());
        assert!(value["target_binary"].is_string());
        assert!(
            value["service_running"].is_null() || value["service_running"].is_boolean(),
            "{value}"
        );
        assert!(
            value.get("wintun_installed").is_some(),
            "the status payload reports the Windows driver slot: {value}"
        );
    }
}
