//! `tobro-helper` binary entry point: parse args, bind the IPC endpoint,
//! run the serve loop, and exit 0/1. All real work lives in the library so
//! tests can drive it in-process.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;

use tobro_helper::{Args, HelperService, NullPlatform, ServeExit, init_logging};
use tobro_tun::default_endpoint;

fn main() -> ExitCode {
    let args = Args::parse();
    init_logging();
    let endpoint = args
        .socket
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(default_endpoint()));
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(error) => {
            tracing::error!("could not start the async runtime: {error}");
            return ExitCode::FAILURE;
        }
    };
    let exit = runtime.block_on(run(endpoint, args.idle_exit_secs));
    runtime.shutdown_timeout(std::time::Duration::from_secs(1));
    exit
}

/// Bind and serve until shutdown or the idle window expires.
async fn run(endpoint: PathBuf, idle_secs: u64) -> ExitCode {
    let idle = (idle_secs > 0).then(|| std::time::Duration::from_secs(idle_secs));
    let mut service = HelperService::new(NullPlatform);

    let exit = serve(endpoint, &mut service, idle).await;
    match exit {
        ServeExit::ShutdownSignal => {
            tracing::info!("shutting down on termination signal");
            ExitCode::SUCCESS
        }
        ServeExit::IdleTimeout => {
            tracing::info!("no client connected within the idle window; exiting");
            ExitCode::SUCCESS
        }
        ServeExit::BindError(error) => {
            tracing::error!("could not serve on the IPC endpoint: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Platform-specific bind + serve. Unix binds here (so startup failures are
/// reported before the loop starts); Windows binds inside the loop because
/// each pipe instance is consumed by a served client.
#[cfg(unix)]
async fn serve(
    endpoint: PathBuf,
    service: &mut HelperService<NullPlatform>,
    idle: Option<std::time::Duration>,
) -> ServeExit {
    let listener = match tobro_tun::bind_listener(&endpoint).await {
        Ok(listener) => listener,
        Err(error) => return ServeExit::BindError(error.to_string()),
    };
    tracing::info!("listening on {}", endpoint.display());
    let exit = tobro_helper::serve_unix(listener, service, idle).await;
    // Best-effort socket cleanup; a stale file is also handled by the next
    // helper's bind, so failure here is not fatal.
    let _ = std::fs::remove_file(&endpoint);
    exit
}

#[cfg(windows)]
async fn serve(
    endpoint: PathBuf,
    service: &mut HelperService<NullPlatform>,
    idle: Option<std::time::Duration>,
) -> ServeExit {
    tracing::info!("listening on {endpoint:?}");
    tobro_helper::serve_windows(&endpoint, service, idle).await
}
