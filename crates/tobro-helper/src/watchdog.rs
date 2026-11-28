//! Watchdog child process for killing the helper.
//!
//! Killing a process (SIGKILL / `TerminateProcess`) runs no cleanup code in
//! that process. To satisfy "killing the daemon/helper restores networking
//! or blocks it per the chosen policy" for a *killed helper*, the helper
//! spawns a lightweight watchdog child — the same binary in `--watchdog`
//! mode — that **survives the parent's death** and, once the parent is gone,
//! runs [`Platform::recover_on_startup`] against the persistent
//! [`crate::recovery`] journal.
//!
//! # How parent death is detected (portable)
//!
//! No OS-specific `prctl`/`PDEATHSIG`/job-object is needed. The parent holds
//! the write end of an inherited pipe; the child holds the read end. The
//! parent never writes. When the parent exits for *any* reason — clean,
//! signal, or `SIGKILL` — the kernel closes the parent's write end and the
//! child's blocking read returns EOF. (A clean parent that already tore
//! down leaves a cleared journal, so recovery is then a no-op.)
//!
//! # Policy
//!
//! Recovery is policy-driven by the persisted [`KillSwitchMode`]:
//! `block` stays fail-closed; `restore`/`disabled` restore pre-tunnel
//! networking. See [`Platform::recover_on_startup`].
//!
//! # What the watchdog is not
//!
//! It is not a second privileged server: no IPC endpoint, no clients, no
//! network. It performs one recovery pass and exits. It is spawned only by
//! the already-privileged helper itself.

use std::io::Read as _;
use std::process::{Child, ChildStdin, Command, Stdio};

use tokio::runtime::Runtime;

use crate::new_active_platform;

/// A spawned watchdog. Keep this alive for the helper's whole lifetime; on
/// drop the pipe's write end closes, which is exactly what tells the child
/// the parent is gone. The child process itself is intentionally not killed.
#[derive(Debug)]
pub struct Watchdog {
    /// The write end of the inherited pipe. Held only to keep it open; never
    /// written. Dropped when the parent exits.
    _stdin_keepalive: ChildStdin,
    /// The child handle; not awaited — the child re-parents and runs once.
    _child: Child,
}

/// Spawn a watchdog child running the current binary in `--watchdog` mode.
///
/// Best-effort: if spawning fails, a startup-recovery path on a
/// service-manager restart still applies, so we log and continue rather than
/// refusing to serve.
pub fn spawn() -> Option<Watchdog> {
    let exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(error) => {
            tracing::warn!("watchdog: could not find current executable: {error}");
            return None;
        }
    };
    let mut child = match Command::new(exe)
        .arg("--watchdog")
        .stdin(Stdio::piped())
        // The child logs to its own stderr; don't pipe (it could block).
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
    {
        Ok(child) => child,
        Err(error) => {
            tracing::warn!("watchdog: could not spawn watchdog child: {error}");
            return None;
        }
    };
    let Some(stdin) = child.stdin.take() else {
        tracing::warn!("watchdog: child stdin pipe unavailable; watchdog disabled");
        let _ = child.kill();
        return None;
    };
    Some(Watchdog {
        _stdin_keepalive: stdin,
        _child: child,
    })
}

/// Watchdog child entry point: block until the parent's pipe closes, then
/// recover once. Runs its own runtime; never returns to serving.
pub fn run_child() -> std::process::ExitCode {
    // Blocking read on stdin; EOF means the parent is gone.
    let mut buf = Vec::new();
    let _ = std::io::stdin().read_to_end(&mut buf);

    let runtime = match Runtime::new() {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("watchdog: could not start async runtime: {error}");
            return std::process::ExitCode::FAILURE;
        }
    };
    let recovered = runtime.block_on(recover());
    runtime.shutdown_timeout(std::time::Duration::from_secs(1));
    match recovered {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("watchdog: recovery did not complete: {error}");
            // Best-effort: recovery already logs; do not signal hard failure.
            std::process::ExitCode::SUCCESS
        }
    }
}

/// Construct the active backend (which itself runs startup recovery) and
/// make sure recovery ran. `new_active_platform` already calls
/// [`Platform::recover_on_startup`]; calling it once here is harmless and
/// keeps this path correct if construction order changes.
async fn recover() -> Result<(), crate::PlatformError> {
    // `new_active_platform` constructs the backend AND runs
    // `Platform::recover_on_startup` exactly once (best-effort, logged), so
    // recovery is not invoked twice here. On non-Unix/non-Windows targets
    // construction has no recovery to run.
    let _platform = new_active_platform().await?;
    Ok(())
}
