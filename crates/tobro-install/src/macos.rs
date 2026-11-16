//! macOS installer: LaunchDaemon plist + `osascript` elevation.
//!
//! Install = copy the binary to `/Library/PrivilegedHelperTools/tobro-helper`
//! and write `/Library/LaunchDaemons/org.tobro.tobro-helper.plist`
//! (`RunAtLoad`, relaunch on crash), then bootstrap/kickstart the job so the
//! helper is running without a reboot. The helper binds its own IPC socket
//! with `--socket-group` (0660 to the daemon user's group) because the
//! daemon, unprivileged, would otherwise be unable to connect to a
//! root-owned 0600 socket.
//!
//! Interim note (audited): the plan's target design registers the helper via
//! `SMAppService` from the signed GUI bundle (M8 packaging); this plist is
//! the daemon-driven interim. The helper's idle window stops it when unused;
//! after an idle exit, the next TUN enable re-runs the (idempotent) install,
//! which asks for one administrator prompt to `launchctl kickstart` it.

use std::path::PathBuf;

use crate::elevate::{self, Runner};
use crate::{InstallError, InstallReport, InstallSpec, InstallStatus, UninstallReport};

/// Platform name for status payloads.
pub const NAME: &str = "macos";

/// The LaunchDaemon label (also the plist file stem).
pub const LABEL: &str = "org.tobro.tobro-helper";

/// The helper's idle window when service-managed (see the Linux unit notes).
const IDLE_EXIT_SECS: u64 = 900;

/// Where the pieces live. Production uses the system paths; tests point
/// every location at a temp directory so nothing here depends on the host.
#[derive(Debug, Clone)]
pub struct Locations {
    /// Privileged binary target.
    pub binary: PathBuf,
    /// LaunchDaemon plist.
    pub plist: PathBuf,
}

impl Locations {
    /// The production system locations.
    #[must_use]
    pub fn system() -> Self {
        Self {
            binary: PathBuf::from("/Library/PrivilegedHelperTools/tobro-helper"),
            plist: PathBuf::from(format!("/Library/LaunchDaemons/{LABEL}.plist")),
        }
    }
}

/// Install the helper (one elevated script): binary, plist, job started.
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
            "plist".to_owned(),
            "job-started".to_owned(),
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
        actions: vec!["job-stopped".to_owned(), "files-removed".to_owned()],
        already_clean: false,
    })
}

/// Non-elevated status: file presence + `launchctl print` probe.
pub fn status<R: Runner>(runner: &R, locations: &Locations, spec: &InstallSpec) -> InstallStatus {
    let binary_installed = locations.binary.is_file();
    let service_registered = locations.plist.is_file();
    let service_running = job_is_running(runner, &format!("system/{LABEL}"));
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

/// `launchctl print system/<label>`: `Some(true)` when the job is loaded and
/// running, `Some(false)` when known but not running, `None` when launchctl
/// could not be consulted.
fn job_is_running<R: Runner>(runner: &R, target: &str) -> Option<bool> {
    let captured = runner
        .capture("/bin/launchctl", &["print".to_owned(), target.to_owned()])
        .ok()?;
    if !captured.ok() {
        return Some(false); // job not loaded
    }
    Some(captured.stdout.contains("state = running"))
}

/// Run one generated script as root via the macOS administrator prompt.
///
/// `osascript -e 'do shell script "<script>" with administrator privileges'`
/// — the AppleScript string is escaped by [`elevate::apple_script_escape`];
/// the inner script itself uses sh single-quoting for every embedded path.
fn run_elevated_script<R: Runner>(runner: &R, script: &str) -> Result<(), InstallError> {
    let apple_script = format!(
        "do shell script \"{}\" with administrator privileges",
        elevate::apple_script_escape(script)
    );
    let captured = runner
        .capture("osascript", &["-e".to_owned(), apple_script])
        .map_err(|error| InstallError::Elevation(format!("could not run osascript: {error}")))?;
    if captured.ok() {
        return Ok(());
    }
    let tail = captured.stderr_tail(200);
    Err(if tail.contains("User canceled") || tail.contains("-128") {
        InstallError::Elevation("the administrator prompt was canceled".to_owned())
    } else {
        InstallError::Script(tail)
    })
}

// --- Generated content -----------------------------------------------------

/// The LaunchDaemon plist: run at load (boot/install), relaunch only on
/// crash, idle window stops the helper when TUN mode is not in use.
fn plist(locations: &Locations, group: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{}</string>
        <string>--idle-exit-secs</string>
        <string>{IDLE_EXIT_SECS}</string>
        <string>--socket-group</string>
        <string>{group}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>Crashed</key>
        <true/>
    </dict>
    <key>ProcessType</key>
    <string>Interactive</string>
</dict>
</plist>
"#,
        locations.binary.display(),
    )
}

/// The elevated install script. Paths arrive validated and shell-quoted.
fn install_script(locations: &Locations, source: &str, group: &str) -> String {
    let bin = elevate::sh_single_quote(&locations.binary.display().to_string());
    let plist_path = elevate::sh_single_quote(&locations.plist.display().to_string());
    let source = elevate::sh_single_quote(source);
    let bin_dir = elevate::sh_single_quote(
        &locations
            .binary
            .parent()
            .map_or_else(String::new, |p| p.display().to_string()),
    );
    let plist_dir = elevate::sh_single_quote(
        &locations
            .plist
            .parent()
            .map_or_else(String::new, |p| p.display().to_string()),
    );
    format!(
        r#"set -e
mkdir -p {bin_dir} {plist_dir}
install -o root -g wheel -m 0755 {source} {bin}
cat > {plist_path} <<'TOBRO_PLIST_EOF'
{}
TOBRO_PLIST_EOF
chown root:wheel {plist_path}
chmod 0644 {plist_path}
/bin/launchctl bootstrap system {plist_path} 2>/dev/null || /bin/launchctl kickstart -k system/{LABEL}
"#,
        plist(locations, group).trim_end(),
    )
}

/// The elevated uninstall script: stop the job (SIGTERM makes the helper tear
/// down device/routes/DNS), then remove the plist and binary.
fn uninstall_script(locations: &Locations) -> String {
    let bin = elevate::sh_single_quote(&locations.binary.display().to_string());
    let plist_path = elevate::sh_single_quote(&locations.plist.display().to_string());
    format!(
        r#"set -e
/bin/launchctl bootout system/{LABEL} 2>/dev/null || true
rm -f {plist_path} {bin}
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
            binary: dir.path().join("target/PrivilegedHelperTools/tobro-helper"),
            plist: dir
                .path()
                .join("target/LaunchDaemons/org.tobro.tobro-helper.plist"),
        };
        (dir, locations, source)
    }

    fn spec(source: &std::path::Path) -> InstallSpec {
        InstallSpec {
            source_binary: source.to_path_buf(),
            socket_group: Some("staff".to_owned()),
            sha256_hex: None,
        }
    }

    #[test]
    fn install_script_installs_the_binary_and_the_plist() {
        let (_dir, locations, source) = ctx();
        let script = install_script(&locations, source.display().to_string().as_str(), "staff");
        assert!(
            script.contains(&format!(
                "install -o root -g wheel -m 0755 '{}' '{}'",
                source.display(),
                locations.binary.display()
            )),
            "{script}"
        );
        assert!(
            script.contains("<string>org.tobro.tobro-helper</string>"),
            "{script}"
        );
        assert!(
            script.contains("<string>staff</string>"),
            "the socket group is passed on"
        );
        assert!(script.contains("<string>900</string>"), "{script}");
        assert!(script.contains("<key>RunAtLoad</key>"), "{script}");
        assert!(script.contains("bootstrap system"), "{script}");
        assert!(
            script.contains("kickstart -k system/org.tobro.tobro-helper"),
            "{script}"
        );
    }

    #[test]
    fn install_runs_one_osascript_with_the_script_escaped() {
        let (_dir, locations, source) = ctx();
        let runner = RecordingRunner::default();
        install(&runner, &locations, &spec(&source), "cafe".to_owned())
            .expect("recording runner must succeed");
        let (program, args) = runner.calls().first().expect("one elevated call").clone();
        assert_eq!(program, "osascript");
        assert_eq!(args[0], "-e");
        // The AppleScript wrapper + inner sh quoting.
        assert!(
            args[1].starts_with("do shell script \"set -e"),
            "{:?}",
            args[1]
        );
        assert!(
            args[1].ends_with("with administrator privileges"),
            "{:?}",
            args[1]
        );
        assert_eq!(runner.calls().len(), 1);
    }

    #[test]
    fn quoted_inner_script_survives_applescript_escaping() {
        // A source path containing both quote kinds must survive two layers
        // of quoting: sh single-quoting (inside the script) and AppleScript
        // string escaping (around the whole `do shell script` body).
        let weird_dir = tempfile::tempdir().expect("tempdir");
        let weird_source = weird_dir.path().join("it's a \"helper\"");
        std::fs::write(&weird_source, b"x").expect("write");

        let runner = RecordingRunner::default();
        let spec = InstallSpec {
            source_binary: weird_source.clone(),
            socket_group: Some("staff".to_owned()),
            sha256_hex: None,
        };
        install(&runner, &Locations::system(), &spec, "cafe".to_owned())
            .expect("recording runner must succeed");
        let (_program, args) = runner.calls().first().expect("one osascript call").clone();

        // Inner sh quoting of the source: 'it'\''s a "helper"'
        let sh_quoted = elevate::sh_single_quote(weird_source.to_str().expect("utf-8 path"));
        // AppleScript escaping turns `"` into `\"` (and `\` into `\\`):
        // 'it'\''s a \"helper\"'
        let expected = elevate::apple_script_escape(&sh_quoted);
        assert!(
            args[1].contains(&expected),
            "{:?}\nexpected to contain {expected:?}",
            args[1]
        );
        // And the osascript call must carry the administrator wrapper (the
        // AppleScript string literal closes right after the script).
        assert!(
            args[1].ends_with("with administrator privileges"),
            "{:?}",
            args[1]
        );
        drop(weird_dir);
    }

    #[test]
    fn canceled_prompt_maps_to_a_clear_error() {
        let (_dir, locations, source) = ctx();
        let runner =
            RecordingRunner::with_response(1, "", "execution error: User canceled. (-128)");
        let error = install(&runner, &locations, &spec(&source), "cafe".to_owned())
            .expect_err("canceled prompts must fail");
        assert!(matches!(error, InstallError::Elevation(_)), "{error}");
        assert!(error.to_string().contains("canceled"), "{error}");
    }

    #[test]
    fn script_failure_surfaces_the_stderr_tail() {
        let (_dir, locations, source) = ctx();
        let runner = RecordingRunner::with_response(1, "", "install: command failed");
        let error = install(&runner, &locations, &spec(&source), "cafe".to_owned())
            .expect_err("failing scripts must fail");
        assert!(matches!(error, InstallError::Script(_)), "{error}");
        assert!(error.to_string().contains("command failed"), "{error}");
    }

    #[test]
    fn uninstall_stops_the_job_and_removes_files() {
        let (_dir, locations, _source) = ctx();
        // Simulate a previous install.
        std::fs::create_dir_all(locations.binary.parent().expect("bin parent")).expect("dir");
        std::fs::write(&locations.binary, b"installed").expect("binary");
        std::fs::create_dir_all(locations.plist.parent().expect("plist parent")).expect("dir");
        std::fs::write(&locations.plist, b"plist").expect("plist");

        let runner = RecordingRunner::default();
        let report = uninstall(&runner, &locations, &spec(std::path::Path::new("/x")))
            .expect("uninstall must succeed");
        assert!(!report.already_clean);
        // The status probe (a `/bin/launchctl print`) also appears; find the
        // single elevated osascript call.
        let (_program, args) = runner
            .calls()
            .iter()
            .find(|(program, _)| program == "osascript")
            .expect("one elevated osascript call")
            .clone();
        assert!(
            args[1].contains("bootout system/org.tobro.tobro-helper"),
            "{:?}",
            args[1]
        );
        assert!(
            args[1].contains(&format!(
                "rm -f '{}' '{}'",
                locations.plist.display(),
                locations.binary.display()
            )),
            "{:?}",
            args[1]
        );
    }

    #[test]
    fn uninstall_on_a_clean_system_elevates_nothing() {
        let (_dir, locations, _source) = ctx();
        let runner = RecordingRunner::default();
        let report = uninstall(&runner, &locations, &spec(std::path::Path::new("/x")))
            .expect("clean uninstall must succeed");
        assert!(report.already_clean);
        assert!(
            runner
                .calls()
                .iter()
                .all(|(program, _)| program != "osascript"),
            "the clean-system path never elevates: {:?}",
            runner.calls()
        );
    }

    #[test]
    fn status_reports_files_and_the_launchctl_probe() {
        let (_dir, locations, _source) = ctx();
        let runner = RecordingRunner::with_response(0, "...\tstate = running\n", "");
        let running = status(&runner, &locations, &spec(std::path::Path::new("/x")));
        assert_eq!(
            running.service_running,
            Some(true),
            "state = running was printed"
        );
        assert!(!running.binary_installed && !running.service_registered);
        assert_eq!(
            running.target_binary,
            locations.binary.display().to_string()
        );

        let runner = RecordingRunner::with_response(0, "...\tstate = not running\n", "");
        let stopped = status(&runner, &locations, &spec(std::path::Path::new("/x")));
        assert_eq!(
            stopped.service_running,
            Some(false),
            "loaded but not running"
        );

        let runner = RecordingRunner::with_response(3, "", "Could not find service");
        let unloaded = status(&runner, &locations, &spec(std::path::Path::new("/x")));
        assert_eq!(unloaded.service_running, Some(false), "not loaded");
    }

    #[test]
    fn plist_requires_the_socket_group() {
        let (_dir, locations, source) = ctx();
        let mut checked = spec(&source);
        checked.socket_group = None;
        let runner = RecordingRunner::default();
        let error = install(&runner, &locations, &checked, "cafe".to_owned())
            .expect_err("unix installs require a socket group");
        assert!(error.to_string().contains("socket_group"), "{error}");
        assert!(runner.calls().is_empty(), "no elevation without a group");
    }
}
