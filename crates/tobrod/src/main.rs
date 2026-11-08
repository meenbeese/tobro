//! `tobrod` — the tobro daemon.
//!
//! M0 scaffold: a `spike` subcommand that bootstraps Arti, verifies a request
//! over Tor, and serves SOCKS/HTTP + DNS until shutdown. The JSON-RPC server,
//! lifecycle state machine, and configuration layer arrive in M1.

mod ipc;
mod lifecycle;
mod spike;
mod supervisor;

use std::path::{Path, PathBuf};

use anyhow::Context as _;
use clap::{Parser, Subcommand};
use directories::ProjectDirs;

#[derive(Debug, Parser)]
#[command(name = "tobrod", version, about = "tobro Tor daemon")]
struct Cli {
    /// State directory (defaults to the platform data directory).
    #[arg(long, global = true, value_name = "DIR")]
    state_dir: Option<PathBuf>,

    /// Arti cache directory (defaults to the platform cache directory).
    #[arg(long, global = true, value_name = "DIR")]
    cache_dir: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the supervised daemon (M1 control plane).
    Run(RunArgs),
    /// Bootstrap Arti, check a request over Tor, and serve SOCKS/HTTP/DNS.
    Spike(spike::SpikeArgs),
}

/// Arguments for `tobrod run`.
#[derive(Debug, clap::Args)]
struct RunArgs {
    /// Config file path (defaults to the platform config directory).
    #[arg(long, value_name = "PATH")]
    config: Option<PathBuf>,
    /// IPC socket/endpoint path override (defaults to `<state-dir>/tobrod.sock`).
    #[arg(long, value_name = "PATH")]
    socket: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    let cli = Cli::parse();
    let Some(command) = cli.command else {
        println!(
            "tobrod {} (run `tobrod run` for the M1 daemon, or `tobrod spike` for the M0 spike)",
            env!("CARGO_PKG_VERSION")
        );
        return Ok(());
    };

    let (state_dir, cache_dir) = resolve_dirs(cli.state_dir, cli.cache_dir)?;
    match command {
        Command::Run(args) => run_daemon(args, state_dir, cache_dir).await,
        Command::Spike(args) => spike::run(args, state_dir, cache_dir).await,
    }
}

async fn run_daemon(args: RunArgs, state_dir: PathBuf, cache_dir: PathBuf) -> anyhow::Result<()> {
    let config_path = args
        .config
        .or_else(|| tobro_config::default_path().ok())
        .context("could not determine config path")?;
    let config = tobro_config::Config::load_or_default(&config_path)
        .with_context(|| format!("failed to load config from {}", config_path.display()))?;
    config.validate().context("invalid config")?;

    std::fs::create_dir_all(&state_dir)
        .with_context(|| format!("failed to create state dir {}", state_dir.display()))?;
    let db_path = state_dir.join(tobro_store::DB_FILE_NAME);
    let _db = tobro_store::Db::open(&db_path)
        .await
        .with_context(|| format!("failed to open store at {}", db_path.display()))?;

    let (handle, supervisor_task) = supervisor::spawn();

    let socket_path = args
        .socket
        .unwrap_or_else(|| tobro_ipc::socket_path(&state_dir));
    let server = tobro_ipc::Server::bind(&socket_path)
        .await
        .with_context(|| format!("failed to bind IPC at {}", socket_path.display()))?;

    let default_listeners = tobro_tor::adapter::ListenerConfig {
        socks_port: config.proxy.socks_port,
        dns_port: config.proxy.dns_port,
    };
    let ipc_handle = handle.clone();
    let ipc_state = state_dir.clone();
    let ipc_cache = cache_dir.clone();
    let ipc_task = tokio::spawn(async move {
        if let Err(error) =
            ipc::serve_daemon(server, ipc_handle, ipc_state, ipc_cache, default_listeners).await
        {
            tracing::error!(%error, "IPC server failed");
        }
    });

    tracing::info!(
        config = %config_path.display(),
        db = %db_path.display(),
        socket = %socket_path.display(),
        socks_port = config.proxy.socks_port,
        dns_port = config.proxy.dns_port,
        "tobrod running (M1); waiting for daemon.connect"
    );

    tokio::signal::ctrl_c()
        .await
        .context("failed to listen for ctrl-c")?;
    tracing::info!("shutdown requested");
    let _ = handle.disconnect().await;
    let _ = handle.shutdown().await;
    ipc_task.abort();
    let _ = supervisor_task.await;
    Ok(())
}

fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn,tobro=info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}

/// Resolve user-supplied or platform-default state/cache directories.
///
/// Relative overrides are anchored at the current directory so that Arti's
/// `CfgPath` values stay absolute and unambiguous.
fn resolve_dirs(
    state_dir: Option<PathBuf>,
    cache_dir: Option<PathBuf>,
) -> anyhow::Result<(PathBuf, PathBuf)> {
    let project = ProjectDirs::from("", "", "tobro")
        .context("could not determine the platform data directory")?;
    let cwd = std::env::current_dir().context("could not determine the current directory")?;

    let state = state_dir.unwrap_or_else(|| project.data_dir().join("state"));
    let cache = cache_dir.unwrap_or_else(|| project.cache_dir().join("arti"));

    Ok((absolute(state, &cwd), absolute(cache, &cwd)))
}

fn absolute(path: PathBuf, cwd: &Path) -> PathBuf {
    if path.is_absolute() {
        path
    } else {
        cwd.join(path)
    }
}
