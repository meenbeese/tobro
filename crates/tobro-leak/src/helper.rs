//! Driving the real `tobro-helper` binary.
//!
//! The leak suite must exercise the *real* privileged backend, not a mock:
//! that is the only way to observe what the kernel actually does with the
//! routes, device, and resolver the helper installs. This module locates the
//! helper binary, launches it against a private IPC endpoint, and keeps a
//! client connection for plan control (the harness plays the daemon's role).

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tobro_tun::{AppliedPlan, HelperInfo, HelperStatus, TunHelperClient, TunnelPlan};
use tokio::process::{Child, Command};

/// How long the helper stays alive after the last client disconnects. The
/// daemon-crash scenario relies on this: a vanished daemon must end in a
/// teardown, not a permanently applied plan.
pub const IDLE_EXIT_SECS: u64 = 3;

/// A launched helper process plus the harness's client connection.
pub struct HelperProcess {
    child: Child,
    endpoint: PathBuf,
    log_path: PathBuf,
    client: Option<TunHelperClient>,
}

impl std::fmt::Debug for HelperProcess {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HelperProcess")
            .field("endpoint", &self.endpoint)
            .field("connected", &self.client.is_some())
            .finish_non_exhaustive()
    }
}

impl HelperProcess {
    /// Launch the helper at `binary` against `endpoint`.
    ///
    /// `log_path` receives the helper's stdout/stderr, which is the only
    /// diagnostic available when a privileged setup step fails in CI.
    pub async fn launch(binary: &Path, endpoint: &Path, log_path: &Path) -> Result<Self> {
        let log = std::fs::File::create(log_path)
            .with_context(|| format!("could not create the helper log {}", log_path.display()))?;
        let log_err = log
            .try_clone()
            .with_context(|| format!("could not clone the helper log {}", log_path.display()))?;

        let mut command = Command::new(binary);
        command
            .arg("--socket")
            .arg(endpoint)
            .arg("--idle-exit-secs")
            .arg(IDLE_EXIT_SECS.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(log_err))
            .kill_on_drop(true);
        #[cfg(windows)]
        {
            // The installed helper is scoped to the daemon user's SID; a
            // manually launched helper fails closed without it.
            let sid = tobro_osapi::win_pipe::current_user_sid_string().ok_or_else(|| {
                anyhow::anyhow!("could not resolve this user's SID for --allow-sid")
            })?;
            command.arg("--allow-sid").arg(sid);
        }

        let child = command.spawn().with_context(|| {
            format!(
                "could not launch the helper {} (is it built? try `cargo build -p tobro-helper`)",
                binary.display()
            )
        })?;
        let mut process = Self {
            child,
            endpoint: endpoint.to_path_buf(),
            log_path: log_path.to_path_buf(),
            client: None,
        };
        process.connect().await?;
        Ok(process)
    }

    /// The IPC endpoint this helper serves on.
    pub fn endpoint(&self) -> &Path {
        &self.endpoint
    }

    /// The helper's captured output, for failure messages.
    pub fn log_tail(&self) -> String {
        let Ok(content) = std::fs::read_to_string(&self.log_path) else {
            return format!("(no helper log at {})", self.log_path.display());
        };
        let start = content.len().saturating_sub(4096);
        // Move to a char boundary before slicing.
        let mut start = start;
        while start < content.len() && !content.is_char_boundary(start) {
            start += 1;
        }
        content[start..].trim_end().to_owned()
    }

    /// Remaining process id, for diagnostics.
    pub fn pid(&self) -> Option<u32> {
        self.child.id()
    }

    /// Connect (with bounded retries; the listener may not be bound yet) and
    /// perform the protocol handshake.
    async fn connect(&mut self) -> Result<()> {
        let client = self.connect_retry().await?;
        self.client = Some(client);
        let info: HelperInfo = self
            .client_mut()?
            .handshake()
            .await
            .context("the helper handshake failed")?;
        if info.protocol_version != tobro_tun::PROTOCOL_VERSION {
            bail!(
                "the helper speaks protocol {} but the harness expects {}",
                info.protocol_version,
                tobro_tun::PROTOCOL_VERSION
            );
        }
        Ok(())
    }

    async fn connect_retry(&mut self) -> Result<TunHelperClient> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        loop {
            if let Some(status) = self
                .child
                .try_wait()
                .context("could not poll the helper process")?
            {
                bail!(
                    "the helper exited with {status} before accepting a connection:\n{}",
                    self.log_tail()
                );
            }
            match TunHelperClient::connect(&self.endpoint).await {
                Ok(client) => return Ok(client),
                Err(_) if tokio::time::Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(error) => {
                    bail!(
                        "could not connect to the helper at {}: {error}\n{}",
                        self.endpoint.display(),
                        self.log_tail()
                    );
                }
            }
        }
    }

    /// The live client connection (panics only if the process was already
    /// disconnected/killed through this harness).
    fn client_mut(&mut self) -> Result<&mut TunHelperClient> {
        self.client
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("the harness has no helper connection"))
    }

    /// Apply `plan`, returning the helper's applied summary.
    pub async fn apply(&mut self, plan: &TunnelPlan) -> Result<AppliedPlan> {
        self.client_mut()?
            .apply_plan(plan)
            .await
            .context("the helper rejected the test plan")
    }

    /// Tear the current plan down.
    pub async fn teardown(&mut self) -> Result<u64> {
        self.client_mut()?
            .teardown()
            .await
            .context("the helper rejected the teardown")
    }

    /// Read the helper's current state.
    pub async fn status(&mut self) -> Result<HelperStatus> {
        self.client_mut()?
            .status()
            .await
            .context("the helper status request failed")
    }

    /// Drop the client connection without a teardown: the daemon crashed.
    pub async fn disconnect(&mut self) {
        // Dropping the framed stream closes the Unix socket / pipe handle;
        // the helper sees the disconnect and starts its idle window.
        self.client = None;
    }

    /// Kill the process abruptly (SIGKILL / TerminateProcess): the helper
    /// crash scenario. No cleanup runs inside the helper.
    pub async fn kill(&mut self) -> Result<()> {
        self.client = None;
        self.child
            .start_kill()
            .context("could not kill the helper process")?;
        Ok(())
    }

    /// Wait for the process to exit, bounded by `timeout`.
    pub async fn wait_exit(&mut self, timeout: Duration) -> Result<std::process::ExitStatus> {
        match tokio::time::timeout(timeout, self.child.wait()).await {
            Ok(result) => result.context("could not wait for the helper process"),
            Err(_) => bail!("the helper did not exit within {timeout:?}"),
        }
    }

    /// Best-effort graceful stop: tear down if connected, then kill.
    pub async fn shutdown(&mut self) {
        if self.client.is_some() {
            // Ignore failures: the scenario may have killed the helper or
            // already torn down; the process is killed below regardless.
            let _ = self.teardown().await;
        }
        let _ = self.kill().await;
        let _ = tokio::time::timeout(Duration::from_secs(5), self.child.wait()).await;
    }
}

/// Locate the helper binary.
///
/// Order: an explicit path (`--helper`), `TOBRO_HELPER_BIN`, the directory
/// of the running harness binary, the workspace target directories, and
/// finally `PATH`.
pub fn find_helper_binary(explicit: Option<&Path>) -> Result<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(explicit) = explicit {
        candidates.push(explicit.to_path_buf());
    }
    if let Some(env) = std::env::var_os("TOBRO_HELPER_BIN") {
        candidates.push(PathBuf::from(env));
    }
    let name = if cfg!(windows) {
        "tobro-helper.exe"
    } else {
        "tobro-helper"
    };
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        candidates.push(dir.join(name));
    }
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf);
    let target_dir = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .or_else(|| workspace.as_ref().map(|root| root.join("target")));
    if let Some(target) = target_dir {
        candidates.push(target.join("debug").join(name));
        candidates.push(target.join("release").join(name));
        // Cross-target builds (e.g. the CI matrix) live under triple dirs.
        for triple in [
            "aarch64-apple-darwin",
            "x86_64-apple-darwin",
            "x86_64-unknown-linux-gnu",
            "aarch64-unknown-linux-gnu",
            "x86_64-pc-windows-msvc",
        ] {
            candidates.push(target.join(triple).join("debug").join(name));
            candidates.push(target.join(triple).join("release").join(name));
        }
    }
    if let Some(path) = std::env::var_os("PATH") {
        candidates.extend(std::env::split_paths(&path).map(|dir| dir.join(name)));
    }

    let mut tried = Vec::new();
    for candidate in candidates {
        if candidate.is_file() {
            return Ok(candidate);
        }
        tried.push(candidate.display().to_string());
    }
    bail!(
        "could not find the helper binary; set TOBRO_HELPER_BIN or pass --helper. Tried:\n  {}",
        tried.join("\n  ")
    )
}

/// Build the private IPC endpoint path for one scenario.
///
/// Unix uses a file in the scenario's temp dir; Windows uses a named pipe
/// with a unique name (pipes are not filesystem paths).
pub fn endpoint_for(directory: &Path, name: &str) -> PathBuf {
    #[cfg(windows)]
    {
        let _ = directory;
        PathBuf::from(format!(
            r"\\.\pipe\tobro-leak-{}-{name}",
            std::process::id()
        ))
    }
    #[cfg(not(windows))]
    {
        directory.join(format!("{name}.sock"))
    }
}
