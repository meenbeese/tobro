//! Windows installer: Windows service + UAC elevation.
//!
//! Install = stop any running `tobro-helper` service, copy the binary **and
//! the `wintun.dll` driver that sits next to it** into
//! `%ProgramFiles%\Tobro\helper\`, create the demand-start service (run as
//! `LocalSystem`), grant interactive users start/stop via the service DACL,
//! and start it. The DACL grant is what lets the *unprivileged daemon* start
//! and stop the helper with `sc` — no further prompts while TUN mode is
//! toggled. The driver copy is required because the privileged helper lives
//! outside the app bundle, while `wintun.dll` is loaded from the helper's own
//! directory.
//!
//! Elevation: the generated `.ps1` runs through `Start-Process -Verb RunAs`
//! (the UAC consent prompt). The elevated script writes a JSON result file
//! back, because the elevated process is a different terminal session; a
//! missing result file means the prompt was declined or dismissed.
//!
//! Interim note (audited): the pipe DACL hardening and the SID-based peer
//! check (vs. the `Unknown`-peer interim in `tobro-helper`) stay documented
//! interims; the helper service runs with the idle window disabled (the
//! daemon stops it when TUN mode is disabled — post-engine wiring).

use std::path::PathBuf;

use crate::elevate::{self, Runner};
use crate::{InstallError, InstallReport, InstallSpec, InstallStatus, UninstallReport};

/// Platform name for status payloads.
pub const NAME: &str = "windows";

/// The Windows service name.
pub const SERVICE_NAME: &str = "tobro-helper";

/// Where the pieces live. Production uses `%ProgramFiles%`; tests point the
/// location at a temp directory so nothing here depends on the host.
#[derive(Debug, Clone)]
pub struct Locations {
    /// Privileged binary target.
    pub binary: PathBuf,
    /// The wintun driver target (loaded from beside the helper binary).
    pub wintun: PathBuf,
}

impl Locations {
    /// The production system location.
    #[must_use]
    pub fn system() -> Self {
        let program_files = std::env::var("ProgramFiles").unwrap_or_else(|_| {
            // The standard fallback; only reachable with a broken environment.
            r"C:\Program Files".to_owned()
        });
        let helper_dir = PathBuf::from(program_files).join("Tobro").join("helper");
        Self {
            binary: helper_dir.join("tobro-helper.exe"),
            wintun: helper_dir.join("wintun.dll"),
        }
    }
}

/// The `wintun.dll` that must sit next to the source helper binary. Device
/// creation loads it from the helper's own directory, so packaging ships it
/// beside the sidecar and this installer carries it into the privileged
/// directory. Checked before anything is elevated so the failure is clear.
fn source_wintun(spec: &InstallSpec) -> Result<PathBuf, InstallError> {
    let dir = spec.source_binary.parent().ok_or_else(|| {
        InstallError::SourceInvalid("the helper binary path has no parent directory".to_owned())
    })?;
    let path = dir.join("wintun.dll");
    if path.is_file() {
        Ok(path)
    } else {
        Err(InstallError::WintunMissing(path.display().to_string()))
    }
}

/// Install the helper (one elevated script): binary, wintun driver, service,
/// DACL, started.
pub fn install<R: Runner>(
    runner: &R,
    locations: &Locations,
    spec: &InstallSpec,
    sha256_hex: String,
) -> Result<InstallReport, InstallError> {
    let source_wintun = source_wintun(spec)?;
    let source = spec.source_binary.to_string_lossy().into_owned();
    let wintun = source_wintun.to_string_lossy().into_owned();
    run_elevated_script(runner, "install", |result_path| {
        install_script(
            locations,
            &source,
            &wintun,
            &result_path.display().to_string(),
        )
    })?;
    Ok(InstallReport {
        target_binary: locations.binary.display().to_string(),
        actions: vec![
            "binary".to_owned(),
            "wintun".to_owned(),
            "service".to_owned(),
            "dacl".to_owned(),
            "started".to_owned(),
        ],
        sha256_hex,
    })
}

/// Stop, delete, and remove the helper service. Tolerates a clean system.
pub fn uninstall<R: Runner>(
    runner: &R,
    locations: &Locations,
    spec: &InstallSpec,
) -> Result<UninstallReport, InstallError> {
    let status = status(runner, locations, spec);
    if !status.binary_installed && !status.service_registered && !status.wintun_installed() {
        return Ok(UninstallReport {
            actions: Vec::new(),
            already_clean: true,
        });
    }
    run_elevated_script(runner, "uninstall", |_result_path| {
        uninstall_script(locations)
    })?;
    Ok(UninstallReport {
        actions: vec![
            "service-stopped".to_owned(),
            "service-deleted".to_owned(),
            "binary-removed".to_owned(),
            "wintun-removed".to_owned(),
        ],
        already_clean: false,
    })
}

/// Non-elevated status: file presence + `sc query` probe.
pub fn status<R: Runner>(runner: &R, locations: &Locations, spec: &InstallSpec) -> InstallStatus {
    let binary_installed = locations.binary.is_file();
    let (service_registered, service_running) = match query_service(runner) {
        Some(captured) => {
            if captured.ok() {
                (true, Some(captured.stdout.contains("RUNNING")))
            } else {
                (false, Some(false)) // 1060: service does not exist
            }
        }
        None => (false, None), // sc unavailable
    };
    let sha256_matches = spec.sha256_hex.as_ref().map(|expected| {
        crate::sha256_file_hex(&locations.binary).is_some_and(|actual| &actual == expected)
    });
    InstallStatus {
        binary_installed,
        service_registered,
        service_running,
        target_binary: locations.binary.display().to_string(),
        sha256_matches,
        wintun_installed: Some(locations.wintun.is_file()),
    }
}

/// `sc query tobro-helper` for status checks.
fn query_service<R: Runner>(runner: &R) -> Option<elevate::Captured> {
    runner
        .capture("sc.exe", &["query".to_owned(), SERVICE_NAME.to_owned()])
        .ok()
}

/// Run one generated `.ps1` through UAC (`Start-Process -Verb RunAs`).
///
/// The elevated child is a separate session: it reports back by writing a
/// JSON result file next to the script; a missing file means the prompt was
/// declined or dismissed. `build` receives the result path (the script writes
/// its outcome there). `kind` labels the temp script.
fn run_elevated_script<R: Runner, F>(runner: &R, kind: &str, build: F) -> Result<(), InstallError>
where
    F: FnOnce(&std::path::Path) -> String,
{
    // The script lives in the invoking user's temp dir; its content is
    // daemon-generated constants, so a same-user tamper grants no new
    // privilege. Both files are removed again afterwards.
    let temp = std::env::temp_dir();
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let script_path = temp.join(format!("tobro-{kind}-{}-{stamp}.ps1", std::process::id()));
    let result_path = script_path.with_extension("result.json");
    std::fs::write(&script_path, build(&result_path))?;

    let inner = format!(
        "-NoProfile -ExecutionPolicy Bypass -File {}",
        elevate::powershell_quote(&script_path.display().to_string())
    );
    // `Start-Process ... -Verb RunAs` triggers the UAC prompt; `-Wait` makes
    // the outer PowerShell block until the elevated child exits.
    let outer = format!(
        "Start-Process -FilePath 'powershell.exe' -ArgumentList {} -Verb RunAs -Wait",
        elevate::powershell_quote(&inner)
    );
    let args = vec![
        "-NoProfile".to_owned(),
        "-NonInteractive".to_owned(),
        "-Command".to_owned(),
        outer,
    ];
    let outcome = runner.capture("powershell.exe", &args);
    let _ = std::fs::remove_file(&script_path);

    let captured = outcome.map_err(|error| {
        let _ = std::fs::remove_file(&result_path);
        InstallError::Elevation(format!("could not run powershell: {error}"))
    })?;
    if !captured.ok() {
        let _ = std::fs::remove_file(&result_path);
        return Err(InstallError::Elevation(format!(
            "the UAC prompt was declined or the elevated step did not start ({})",
            captured.stderr_tail(120)
        )));
    }
    // The elevated child wrote its result.
    let result = std::fs::read_to_string(&result_path);
    let _ = std::fs::remove_file(&result_path);
    let Ok(result) = result else {
        return Err(InstallError::Elevation(
            "the UAC prompt was declined, dismissed, or the elevated step never ran".to_owned(),
        ));
    };
    parse_result(&result).map_or_else(
        || {
            Err(InstallError::Script(
                "the elevated step did not write a parseable result".to_owned(),
            ))
        },
        |value| {
            if value.ok {
                Ok(())
            } else {
                Err(InstallError::Script(
                    value.error.unwrap_or_else(|| "unknown error".to_owned()),
                ))
            }
        },
    )
}

/// One field of the elevated script's JSON result (hand-rolled: the result
/// is `{ "ok": bool, "error": string }` generated a few lines above).
#[derive(Debug, Clone, PartialEq, Eq)]
struct ScriptResult {
    ok: bool,
    error: Option<String>,
}

/// Parse the result JSON; `None` on any surprise. Tolerates a UTF-8 BOM
/// (PowerShell 5.1's `Set-Content -Encoding UTF8` writes one).
fn parse_result(text: &str) -> Option<ScriptResult> {
    let value: serde_json::Value =
        serde_json::from_str(text.trim_start_matches('\u{feff}')).ok()?;
    Some(ScriptResult {
        ok: value.get("ok")?.as_bool()?,
        error: value
            .get("error")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
            .filter(|e| !e.is_empty()),
    })
}

// --- Generated content -----------------------------------------------------

/// The elevated install script (PowerShell). Paths arrive validated and
/// PowerShell-quoted. `sc.exe` is invoked with the `.exe` suffix deliberately
/// (`sc` alone is the PowerShell `Set-Content` alias).
fn install_script(
    locations: &Locations,
    source: &str,
    source_wintun: &str,
    result_path: &str,
) -> String {
    let src = elevate::powershell_quote(source);
    let dst = elevate::powershell_quote(&locations.binary.display().to_string());
    let wintun_src = elevate::powershell_quote(source_wintun);
    let wintun_dst = elevate::powershell_quote(&locations.wintun.display().to_string());
    let dir = elevate::powershell_quote(
        &locations
            .binary
            .parent()
            .map_or_else(String::new, |p| p.display().to_string()),
    );
    let bin_value = elevate::powershell_quote(&format!(
        "\"{}\" --idle-exit-secs 0",
        locations.binary.display()
    ));
    let result_path = elevate::powershell_quote(result_path);
    format!(
        r#"$ErrorActionPreference = 'Stop'
$result = [ordered]@{{ ok = $false; error = ''; actions = @() }}
try {{
    New-Item -ItemType Directory -Force -Path {dir} | Out-Null
    $result.actions += 'dir'
    sc.exe stop {SERVICE_NAME} | Out-Null
    Start-Sleep -Milliseconds 800
    $copied = $false
    foreach ($try in 1..3) {{
        try {{ Copy-Item -Force {src} {dst}; $copied = $true; break }}
        catch {{ Start-Sleep -Milliseconds 600 }}
    }}
    if (-not $copied) {{ throw 'could not copy the helper binary (service still running?)' }}
    $result.actions += 'binary'
    Copy-Item -Force {wintun_src} {wintun_dst}
    $result.actions += 'wintun'
    sc.exe query {SERVICE_NAME} | Out-Null
    if ($LASTEXITCODE -ne 0) {{
        sc.exe create {SERVICE_NAME} binPath= {bin_value} start= demand obj= LocalSystem DisplayName= 'Tobro Helper' | Out-Null
        $result.actions += 'service'
    }}
    sc.exe sdset {SERVICE_NAME} 'D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWD;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;RPWP;;;AU)' | Out-Null
    if ($LASTEXITCODE -ne 0) {{ throw 'could not set the service DACL' }}
    $result.actions += 'dacl'
    sc.exe start {SERVICE_NAME} | Out-Null
    if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 1056) {{ throw 'could not start the helper service' }}
    $result.actions += 'start'
    $result.ok = $true
}} catch {{
    $result.error = $_.Exception.Message
}}
$result | ConvertTo-Json -Compress | Set-Content -LiteralPath {result_path} -Encoding UTF8
exit 0
"#
    )
}

/// The elevated uninstall script (PowerShell): stop + delete the service
/// (service stop makes the helper tear down device/routes/DNS), remove the
/// binary. Every step tolerates a missing piece.
fn uninstall_script(locations: &Locations) -> String {
    let dst = elevate::powershell_quote(&locations.binary.display().to_string());
    let wintun_dst = elevate::powershell_quote(&locations.wintun.display().to_string());
    format!(
        r#"$ErrorActionPreference = 'Continue'
sc.exe stop {SERVICE_NAME} | Out-Null
Start-Sleep -Milliseconds 800
sc.exe delete {SERVICE_NAME} | Out-Null
Remove-Item -Force {dst} -ErrorAction SilentlyContinue
Remove-Item -Force {wintun_dst} -ErrorAction SilentlyContinue
exit 0
"#
    )
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Records every command; never spawns anything. When `result` is set,
    /// `capture` fakes the elevated child by writing that content to the
    /// result file it can derive from the outer command's `-File` argument.
    #[derive(Default)]
    struct RecordingRunner {
        calls: Mutex<Vec<(String, Vec<String>)>>,
        response: Option<elevate::Captured>,
        result: Mutex<Option<String>>,
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
                result: Mutex::new(None),
            }
        }

        fn with_elevated_result(json: &str) -> Self {
            let runner = Self::with_response(0, "", "");
            *runner.result.lock().unwrap_or_else(|e| e.into_inner()) = Some(json.to_owned());
            runner
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
            if let Some(content) = self
                .result
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
                && let Some(script_path) = args.last().and_then(|arg| find_script_path(arg))
            {
                let result_path = script_path.with_extension("result.json");
                std::fs::write(&result_path, content).expect("write result file");
            }
            Ok(self.response.clone().unwrap_or(elevate::Captured {
                code: 0,
                stdout: String::new(),
                stderr: String::new(),
            }))
        }
    }

    /// Pull the (doubled-quoted) `.ps1` path out of the outer `Start-Process`
    /// command line: `... -File ''C:\Temp\tobro-install-1.ps1'' -Verb ...`.
    fn find_script_path(arg: &str) -> Option<PathBuf> {
        let end = arg.find(".ps1")? + 4;
        let start = arg[..end].rfind("''")? + 2;
        Some(PathBuf::from(&arg[start..end]))
    }

    /// Hermetic locations (temp dir) + a real source binary with its driver.
    fn ctx() -> (tempfile::TempDir, Locations, std::path::PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let source = dir.path().join("source").join("tobro-helper.exe");
        std::fs::create_dir_all(source.parent().expect("parent")).expect("source dir");
        std::fs::write(&source, b"helper binary").expect("write source");
        std::fs::write(
            source.parent().expect("parent").join("wintun.dll"),
            b"driver",
        )
        .expect("write wintun");
        let target = dir.path().join("target").join("Tobro");
        let locations = Locations {
            binary: target.join("tobro-helper.exe"),
            wintun: target.join("wintun.dll"),
        };
        (dir, locations, source)
    }

    fn spec(source: &std::path::Path) -> InstallSpec {
        InstallSpec {
            source_binary: source.to_path_buf(),
            socket_group: None,
            sha256_hex: None,
        }
    }

    #[test]
    fn install_script_creates_and_starts_the_service() {
        let (_dir, locations, source) = ctx();
        let source_wintun = source.parent().expect("parent").join("wintun.dll");
        let script = install_script(
            &locations,
            source.display().to_string().as_str(),
            source_wintun.display().to_string().as_str(),
            r"C:\Temp\result.json",
        );
        assert!(script.contains("sc.exe create"), "{script}");
        assert!(
            script.contains("binPath= '\""),
            "the binPath value must quote the binary path for sc: {script}"
        );
        assert!(script.contains("--idle-exit-secs 0"), "{script}");
        assert!(
            script.contains("start= demand obj= LocalSystem"),
            "{script}"
        );
        assert!(
            script.contains("(A;;RPWP;;;AU)"),
            "interactive users get start/stop"
        );
        assert!(script.contains("sc.exe start"), "{script}");
        assert!(script.contains("sc.exe sdset"), "{script}");
        assert!(
            script.contains("Set-Content -LiteralPath 'C:\\Temp\\result.json'"),
            "{script}"
        );
        // The source/binary paths arrive PowerShell-quoted.
        assert!(
            script.contains(&format!("Copy-Item -Force '{}'", source.display())),
            "{script}"
        );
        // The driver is copied into the privileged directory as well.
        assert!(
            script.contains(&format!(
                "Copy-Item -Force '{}' '{}'",
                source_wintun.display(),
                locations.wintun.display()
            )),
            "{script}"
        );
    }

    #[test]
    fn install_requires_the_wintun_driver_next_to_the_source() {
        let (_dir, locations, source) = ctx();
        std::fs::remove_file(source.parent().expect("parent").join("wintun.dll"))
            .expect("remove driver");
        let runner = RecordingRunner::default();
        let error = install(&runner, &locations, &spec(&source), "cafe".to_owned())
            .expect_err("a missing driver must fail before elevation");
        assert!(matches!(error, InstallError::WintunMissing(_)), "{error}");
        assert!(
            runner.calls().is_empty(),
            "nothing may be elevated when the driver is missing"
        );
    }

    #[test]
    fn uninstall_script_stops_and_deletes() {
        let (_dir, locations, _source) = ctx();
        let script = uninstall_script(&locations);
        assert!(script.contains("sc.exe stop"), "{script}");
        assert!(script.contains("sc.exe delete"), "{script}");
        assert!(script.contains("Remove-Item -Force"), "{script}");
        assert!(
            script.contains(&locations.wintun.display().to_string()),
            "the driver is removed too: {script}"
        );
    }

    #[test]
    fn install_writes_a_script_and_runs_the_uac_outer_command() {
        let (_dir, locations, source) = ctx();
        let runner = RecordingRunner::default();
        let report = install(&runner, &locations, &spec(&source), "cafe".to_owned())
            .expect("recording runner must succeed");
        assert_eq!(
            report.actions,
            vec!["binary", "wintun", "service", "dacl", "started"]
        );
        assert_eq!(report.sha256_hex, "cafe");
        let (program, args) = runner.calls().first().expect("one elevated call").clone();
        assert_eq!(program, "powershell.exe");
        assert_eq!(args[0], "-NoProfile");
        assert!(
            args.last().expect("command").contains("-Verb RunAs"),
            "{:?}",
            args
        );
        assert!(
            args.last().expect("command").contains("-File"),
            "{:?}",
            args
        );
        assert_eq!(runner.calls().len(), 1);
    }

    #[test]
    fn declined_uac_is_a_clear_error() {
        let (_dir, locations, source) = ctx();
        // The outer PS exits nonzero and no result file exists.
        let runner = RecordingRunner::with_response(1, "", "");
        let error = install(&runner, &locations, &spec(&source), "cafe".to_owned())
            .expect_err("declined UAC must fail");
        assert!(matches!(error, InstallError::Elevation(_)), "{error}");
        assert!(error.to_string().contains("declined"), "{error}");
    }

    #[test]
    fn elevated_script_errors_surface_the_message() {
        let (_dir, locations, source) = ctx();
        let runner = RecordingRunner::with_elevated_result(
            r#"{"ok":false,"error":"could not copy the helper binary (service still running?)"}"#,
        );
        let error = install(&runner, &locations, &spec(&source), "cafe".to_owned())
            .expect_err("failing scripts must fail");
        assert!(matches!(error, InstallError::Script(_)), "{error}");
        assert!(error.to_string().contains("could not copy"), "{error}");
    }

    #[test]
    fn successful_scripts_report_ok() {
        let (_dir, locations, source) = ctx();
        let runner = RecordingRunner::with_elevated_result(r#"{"ok":true,"error":""}"#);
        install(&runner, &locations, &spec(&source), "cafe".to_owned())
            .expect("a successful result must pass");
    }

    #[test]
    fn uninstall_stops_and_deletes_an_installed_service() {
        let (_dir, locations, _source) = ctx();
        std::fs::create_dir_all(locations.binary.parent().expect("parent")).expect("dir");
        std::fs::write(&locations.binary, b"installed").expect("binary");
        // `sc query` exit 0 = the service exists.
        let runner = RecordingRunner::with_response(
            0,
            "SERVICE_NAME: tobro-helper\n        STATE              : 4  RUNNING\n",
            "",
        );
        let report = uninstall(&runner, &locations, &spec(std::path::Path::new("/x")))
            .expect("uninstall must succeed");
        assert!(!report.already_clean);
        let (program, _) = runner.calls().first().expect("one elevated call").clone();
        assert_eq!(program, "powershell.exe");
    }

    #[test]
    fn uninstall_on_a_clean_system_elevates_nothing() {
        let (_dir, locations, _source) = ctx();
        // sc query fails: no service; no binary file.
        let runner = RecordingRunner::with_response(1060, "", "service does not exist");
        let report = uninstall(&runner, &locations, &spec(std::path::Path::new("/x")))
            .expect("clean uninstall must succeed");
        assert!(report.already_clean);
        assert!(runner.calls().is_empty());
    }

    #[test]
    fn status_reads_sc_query_state() {
        let (_dir, locations, _source) = ctx();
        let runner = RecordingRunner::with_response(
            0,
            "SERVICE_NAME: tobro-helper\n        STATE              : 4  RUNNING\n",
            "",
        );
        let running = status(&runner, &locations, &spec(std::path::Path::new("/x")));
        assert!(running.service_registered);
        assert_eq!(running.service_running, Some(true));
        assert!(!running.binary_installed);
        assert!(!running.wintun_installed(), "the driver was not installed");
        assert_eq!(
            running.target_binary,
            locations.binary.display().to_string()
        );

        let runner = RecordingRunner::with_response(1060, "", "service does not exist");
        let status = status(&runner, &locations, &spec(std::path::Path::new("/x")));
        assert!(!status.service_registered);
        assert_eq!(status.service_running, Some(false));
    }

    #[test]
    fn parse_result_tolerates_junk_and_a_bom() {
        assert_eq!(
            parse_result(r#"{"ok":true,"error":""}"#),
            Some(ScriptResult {
                ok: true,
                error: None
            })
        );
        assert_eq!(
            parse_result("\u{feff}{\"ok\":true,\"error\":\"\"}"),
            Some(ScriptResult {
                ok: true,
                error: None
            }),
            "PowerShell 5.1 writes a BOM"
        );
        assert_eq!(parse_result("not json"), None);
        assert_eq!(parse_result(r#"{"ok":"yes"}"#), None);
    }
}
