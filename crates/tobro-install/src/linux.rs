//! Linux installer: systemd system units + `pkexec` elevation.
//!
//! Install = copy the binary to `/usr/local/bin/tobro-helper`, write
//! `tobro-helper.socket` + `tobro-helper.service` into
//! `/etc/systemd/system/`, and `enable --now` the socket unit. The socket
//! unit is the activation story: systemd owns `/run/tobro-helper.sock` and
//! starts the helper on the daemon's first connection, so the privileged
//! helper really does run only while it is being used; the helper's idle
//! window stops it again.
//!
//! Socket permissions: `SocketMode=0660` + `SocketGroup=<daemon user's
//! primary group>` so the unprivileged daemon can connect; the helper's
//! peer-credential gate remains the client check.

use std::path::{Path, PathBuf};

use crate::elevate::{self, Runner};
use crate::{InstallError, InstallReport, InstallSpec, InstallStatus, UninstallReport};

/// Platform name for status payloads.
pub const NAME: &str = "linux";

/// The helper's idle window when service-managed: long enough that a paused
/// daemon does not restart the unit constantly, short enough that the root
/// process is gone minutes after TUN mode stops being used.
const IDLE_EXIT_SECS: u64 = 900;

/// Where the pieces live. Production uses the system paths; tests point
/// every location at a temp directory so nothing here depends on the host.
#[derive(Debug, Clone)]
pub struct Locations {
    /// Privileged binary target.
    pub binary: PathBuf,
    /// systemd socket unit (the activation entry point).
    pub socket_unit: PathBuf,
    /// systemd service unit.
    pub service_unit: PathBuf,
    /// IPC socket the socket unit listens on (the daemon's endpoint).
    pub socket: PathBuf,
}

impl Locations {
    /// The production system locations.
    #[must_use]
    pub fn system() -> Self {
        Self {
            binary: PathBuf::from("/usr/local/bin/tobro-helper"),
            socket_unit: PathBuf::from("/etc/systemd/system/tobro-helper.socket"),
            service_unit: PathBuf::from("/etc/systemd/system/tobro-helper.service"),
            socket: PathBuf::from("/run/tobro-helper.sock"),
        }
    }
}

/// Install the helper (one elevated script): binary, units, socket enabled.
pub fn install<R: Runner>(
    runner: &R,
    locations: &Locations,
    spec: &InstallSpec,
    sha256_hex: String,
) -> Result<InstallReport, InstallError> {
    let group = spec
        .socket_group
        .as_deref()
        .ok_or_else(|| {
            InstallError::SourceInvalid(
                "socket_group is required on Unix (the IPC socket must be connectable by the \
                 unprivileged daemon)"
                    .to_owned(),
            )
        })?
        .to_owned();
    let script = install_script(
        locations,
        spec.source_binary.to_string_lossy().as_ref(),
        &group,
    );
    run_elevated_script(runner, &script)?;
    Ok(InstallReport {
        target_binary: locations.binary.display().to_string(),
        actions: vec![
            "binary".to_owned(),
            "socket-unit".to_owned(),
            "service-unit".to_owned(),
            "socket-enabled".to_owned(),
        ],
        sha256_hex,
    })
}

/// Stop, deregister, and remove the helper. Tolerates a clean system.
pub fn uninstall<R: Runner>(
    runner: &R,
    locations: &Locations,
    spec: &InstallSpec,
) -> Result<UninstallReport, InstallError> {
    let status = status(runner, locations, spec);
    if !status.binary_installed && !status.service_registered {
        return Ok(UninstallReport {
            actions: Vec::new(),
            already_clean: true,
        });
    }
    run_elevated_script(runner, &uninstall_script(locations))?;
    Ok(UninstallReport {
        actions: vec![
            "socket-disabled".to_owned(),
            "units-removed".to_owned(),
            "binary-removed".to_owned(),
        ],
        already_clean: false,
    })
}

/// Non-elevated status: file presence + `systemctl is-active` probe.
pub fn status<R: Runner>(runner: &R, locations: &Locations, spec: &InstallSpec) -> InstallStatus {
    let binary_installed = locations.binary.is_file();
    let service_registered = locations.socket_unit.is_file() && locations.service_unit.is_file();
    let service_running = systemctl_is_active(runner, "tobro-helper.socket");
    let sha256_matches = spec.sha256_hex.as_ref().map(|expected| {
        crate::sha256_file_hex(&locations.binary).is_some_and(|actual| &actual == expected)
    });
    InstallStatus {
        binary_installed,
        service_registered,
        service_running,
        target_binary: locations.binary.display().to_string(),
        sha256_matches,
    }
}

/// `systemctl is-active --quiet <unit>`: `Some(true)` when active,
/// `Some(false)` when not, `None` when systemctl is unavailable.
fn systemctl_is_active<R: Runner>(runner: &R, unit: &str) -> Option<bool> {
    let captured = runner
        .capture(
            "systemctl",
            &[
                "is-active".to_owned(),
                "--quiet".to_owned(),
                unit.to_owned(),
            ],
        )
        .ok()?;
    Some(captured.ok())
}

/// Run one generated script as root via pkexec (the polkit prompt is the
/// privilege UI). Fails with the command's stderr tail on refusal/failure.
fn run_elevated_script<R: Runner>(runner: &R, script: &str) -> Result<(), InstallError> {
    let args = vec!["/bin/sh".to_owned(), "-c".to_owned(), script.to_owned()];
    let captured = runner
        .capture("pkexec", &args)
        .map_err(|error| match error.kind() {
            std::io::ErrorKind::NotFound => InstallError::Elevation(
                "pkexec was not found; install polkit (or install the helper manually with sudo)"
                    .to_owned(),
            ),
            _ => InstallError::Elevation(format!("could not run pkexec: {error}")),
        })?;
    if captured.ok() {
        return Ok(());
    }
    let tail = captured.stderr_tail(200);
    Err(
        if tail.contains("not authorized")
            || tail.contains("interaction not allowed")
            || tail.contains("Dismissed")
        {
            InstallError::Elevation(
                "the privilege prompt was declined or not authorized".to_owned(),
            )
        } else {
            InstallError::Script(tail)
        },
    )
}

// --- Generated content -----------------------------------------------------

/// The systemd socket unit: the daemon's connection to the socket starts the
/// helper on demand. Permissions let only the daemon's group connect.
fn socket_unit(locations: &Locations, group: &str) -> String {
    format!(
        r#"[Unit]
Description=Tobro privileged helper IPC socket

[Socket]
ListenStream={}
SocketMode=0660
SocketGroup={group}
RemoveOnStop=true

[Install]
WantedBy=sockets.target
"#,
        locations.socket.display(),
    )
}

/// The systemd service unit: root helper with an idle window, plus interim
/// hardening (the full sandbox pass is the M7 security-review criterion).
fn service_unit(locations: &Locations) -> String {
    format!(
        r#"[Unit]
Description=Tobro privileged TUN helper

[Service]
Type=simple
ExecStart={} --idle-exit-secs {IDLE_EXIT_SECS}
Restart=on-failure
RestartSec=5s
# Interim hardening: filesystem write access is limited to /etc (DNS
# settings); the helper needs /dev/net/tun (PrivateDevices stays off).
ProtectSystem=strict
ReadWritePaths=/etc
ProtectHome=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictRealtime=true
LockPersonality=true
MemoryDenyWriteExecute=true
"#,
        locations.binary.display(),
    )
}

/// The elevated install script. Paths arrive validated and shell-quoted.
fn install_script(locations: &Locations, source: &str, group: &str) -> String {
    let bin = elevate::sh_single_quote(&locations.binary.display().to_string());
    let socket_unit_path = elevate::sh_single_quote(&locations.socket_unit.display().to_string());
    let service_unit_path = elevate::sh_single_quote(&locations.service_unit.display().to_string());
    let source = elevate::sh_single_quote(source);
    format!(
        r#"set -e
mkdir -p '{bin_dir}'
install -o root -g root -m 0755 {source} {bin}
cat > {socket_unit_path} <<'TOBRO_UNIT_EOF'
{}
TOBRO_UNIT_EOF
cat > {service_unit_path} <<'TOBRO_UNIT_EOF'
{}
TOBRO_UNIT_EOF
chmod 0644 {socket_unit_path} {service_unit_path}
systemctl daemon-reload
systemctl enable --now tobro-helper.socket
"#,
        socket_unit(locations, group).trim_end(),
        service_unit(locations).trim_end(),
        bin_dir = locations
            .binary
            .parent()
            .map_or_else(String::new, |p| p.display().to_string()),
    )
}

/// The elevated uninstall script. Every step tolerates a missing piece so a
/// half-installed state still converges to clean.
fn uninstall_script(locations: &Locations) -> String {
    let paths = [
        locations.socket_unit.as_os_str(),
        locations.service_unit.as_os_str(),
        locations.binary.as_os_str(),
    ]
    .map(|p| elevate::sh_single_quote(&p.to_string_lossy()))
    .join(" ");
    format!(
        r#"set -e
systemctl disable --now tobro-helper.socket tobro-helper.service 2>/dev/null || true
rm -f {paths}
systemctl daemon-reload 2>/dev/null || true
systemctl reset-failed 2>/dev/null || true
"#
    )
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Records every command; never spawns anything.
    #[derive(Default)]
    struct RecordingRunner {
        calls: Mutex<Vec<(String, Vec<String>)>>,
        response: Option<elevate::Captured>,
    }

    impl RecordingRunner {
        fn calls(&self) -> Vec<(String, Vec<String>)> {
            self.calls.lock().unwrap_or_else(|e| e.into_inner()).clone()
        }

        fn with_response(code: i32, stdout: &str, stderr: &str) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                response: Some(elevate::Captured {
                    code,
                    stdout: stdout.to_owned(),
                    stderr: stderr.to_owned(),
                }),
            }
        }
    }

    impl Runner for RecordingRunner {
        fn run(&self, program: &str, args: &[String]) -> std::io::Result<i32> {
            self.calls
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push((program.to_owned(), args.to_vec()));
            Ok(0)
        }

        fn capture(&self, program: &str, args: &[String]) -> std::io::Result<elevate::Captured> {
            self.calls
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push((program.to_owned(), args.to_vec()));
            Ok(self.response.clone().unwrap_or(elevate::Captured {
                code: 0,
                stdout: String::new(),
                stderr: String::new(),
            }))
        }
    }

    /// Hermetic locations (temp dir) + a real source binary.
    fn ctx() -> (tempfile::TempDir, Locations, std::path::PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let source = dir.path().join("source").join("tobro-helper");
        std::fs::create_dir_all(source.parent().expect("parent")).expect("source dir");
        std::fs::write(&source, b"helper binary").expect("write source");
        let locations = Locations {
            binary: dir.path().join("target/bin/tobro-helper"),
            socket_unit: dir.path().join("target/systemd/tobro-helper.socket"),
            service_unit: dir.path().join("target/systemd/tobro-helper.service"),
            socket: dir.path().join("target/run/tobro-helper.sock"),
        };
        (dir, locations, source)
    }

    fn spec(source: &Path) -> InstallSpec {
        InstallSpec {
            source_binary: source.to_path_buf(),
            socket_group: Some("adm".to_owned()),
            sha256_hex: None,
        }
    }

    #[test]
    fn install_script_contains_units_and_quoted_paths() {
        let (_dir, locations, source) = ctx();
        let script = install_script(&locations, source.display().to_string().as_str(), "adm");
        // The source path is single-quoted and the install goes to the target.
        assert!(
            script.contains(&format!(
                "install -o root -g root -m 0755 '{}' '{}'",
                source.display(),
                locations.binary.display()
            )),
            "{script}"
        );
        assert!(
            script.contains(&format!("ListenStream={}", locations.socket.display())),
            "{script}"
        );
        assert!(script.contains("SocketGroup=adm"), "{script}");
        assert!(script.contains("SocketMode=0660"), "{script}");
        assert!(
            script.contains(&format!(
                "ExecStart={} --idle-exit-secs 900",
                locations.binary.display()
            )),
            "{script}"
        );
        assert!(
            script.contains("systemctl enable --now tobro-helper.socket"),
            "{script}"
        );
        // Unit bodies are heredoc'd with a quoted delimiter (no expansion).
        assert!(script.contains("<<'TOBRO_UNIT_EOF'"), "{script}");
        // Interim hardening is present.
        assert!(script.contains("ProtectSystem=strict"), "{script}");
        // No unquoted embedding of any location path.
        assert!(
            !script.contains(&format!("cp {}", source.display())),
            "paths must arrive quoted"
        );
    }

    #[test]
    fn uninstall_script_removes_everything_and_tolerates_a_clean_system() {
        let (_dir, locations, _source) = ctx();
        let script = uninstall_script(&locations);
        assert!(
            script.contains("systemctl disable --now tobro-helper.socket"),
            "{script}"
        );
        assert!(
            script.contains(&format!(
                "rm -f '{}' '{}' '{}'",
                locations.socket_unit.display(),
                locations.service_unit.display(),
                locations.binary.display()
            )),
            "{script}"
        );
        assert!(script.contains("|| true"), "{script}");
    }

    #[test]
    fn install_runs_exactly_one_pkexec_script() {
        let (_dir, locations, source) = ctx();
        let runner = RecordingRunner::default();
        let report = install(&runner, &locations, &spec(&source), "cafe".to_owned())
            .expect("recording runner must succeed");
        assert_eq!(report.target_binary, locations.binary.display().to_string());
        assert_eq!(report.sha256_hex, "cafe");
        assert_eq!(report.actions.len(), 4);
        let calls = runner.calls();
        let (program, args) = calls.first().expect("one elevated call");
        assert_eq!(program, "pkexec");
        assert_eq!(&args[0], "/bin/sh");
        assert_eq!(&args[1], "-c");
        assert!(
            args[2].contains("SocketGroup=adm"),
            "the script carries the units"
        );
        assert_eq!(calls.len(), 1, "one elevation, no side probes");
    }

    #[test]
    fn declined_prompt_maps_to_a_clear_error() {
        let (_dir, locations, source) = ctx();
        let runner = RecordingRunner::with_response(
            126,
            "",
            "Error executing command as another user: Not authorized",
        );
        let error = install(&runner, &locations, &spec(&source), "cafe".to_owned())
            .expect_err("declined authorization must fail");
        assert!(matches!(error, InstallError::Elevation(_)), "{error}");
        assert!(error.to_string().contains("declined"), "{error}");
    }

    #[test]
    fn script_failure_surfaces_the_stderr_tail() {
        let (_dir, locations, source) = ctx();
        let runner = RecordingRunner::with_response(1, "", "cp: cannot stat 'x': No such file");
        let error = install(&runner, &locations, &spec(&source), "cafe".to_owned())
            .expect_err("failing scripts must fail");
        assert!(matches!(error, InstallError::Script(_)), "{error}");
        assert!(error.to_string().contains("cannot stat"), "{error}");
    }

    #[test]
    fn uninstall_on_a_clean_system_elevates_nothing() {
        let (_dir, locations, _source) = ctx();
        // Nothing was ever installed at these (temp) locations.
        let runner = RecordingRunner::default();
        let report = uninstall(&runner, &locations, &spec(Path::new("/nonexistent")))
            .expect("clean uninstall must succeed");
        assert!(report.already_clean);
        assert!(report.actions.is_empty());
        // The non-elevated `systemctl is-active` probe may appear, but never
        // an elevated pkexec call.
        assert!(
            runner
                .calls()
                .iter()
                .all(|(program, _)| program != "pkexec"),
            "the clean-system path never elevates: {:?}",
            runner.calls()
        );
    }

    #[test]
    fn uninstall_removes_an_installed_system() {
        let (_dir, locations, _source) = ctx();
        // Simulate a previous install: files exist.
        std::fs::create_dir_all(locations.binary.parent().expect("bin parent")).expect("dir");
        std::fs::write(&locations.binary, b"installed").expect("binary");
        std::fs::create_dir_all(locations.socket_unit.parent().expect("unit parent")).expect("dir");
        std::fs::write(&locations.socket_unit, b"unit").expect("unit");

        let runner = RecordingRunner::default();
        let report = uninstall(&runner, &locations, &spec(Path::new("/nonexistent")))
            .expect("uninstall must succeed");
        assert!(!report.already_clean);
        assert_eq!(report.actions.len(), 3);
        let (program, args) = runner.calls().first().expect("one elevated call");
        assert_eq!(program, "pkexec");
        assert!(args[2].contains("systemctl disable --now"), "{:?}", args[2]);
    }

    #[test]
    fn status_reports_file_presence_and_systemctl_probe() {
        let (_dir, locations, _source) = ctx();
        let runner = RecordingRunner::default();
        let status = status(&runner, &locations, &spec(Path::new("/nonexistent")));
        assert_eq!(
            status.service_running,
            Some(true),
            "recording runner exits 0"
        );
        assert!(
            !status.binary_installed,
            "nothing installed at the temp locations"
        );
        assert!(!status.service_registered);
        assert_eq!(status.target_binary, locations.binary.display().to_string());
        assert_eq!(status.sha256_matches, None, "no pin configured");
        assert!(!status.installed());
    }

    #[test]
    fn status_with_a_pin_compares_the_installed_binary() {
        let (_dir, locations, _source) = ctx();
        // Simulate an installed binary with a known hash, configured pin set.
        std::fs::create_dir_all(locations.binary.parent().expect("bin parent")).expect("dir");
        std::fs::write(&locations.binary, b"installed").expect("binary");
        let mut checked = spec(Path::new("/nonexistent"));
        checked.sha256_hex = Some(crate::sha256_file_hex(&locations.binary).expect("hash"));
        let runner = RecordingRunner::default();
        let status = status(&runner, &locations, &checked);
        assert_eq!(status.sha256_matches, Some(true));
        assert!(status.binary_installed);
        assert!(!status.installed(), "units are still missing");
    }
}
