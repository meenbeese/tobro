//! `tobrod` — the tobro daemon.
//!
//! M0 scaffold: a `spike` subcommand that bootstraps Arti, verifies a request
//! over Tor, and serves SOCKS/HTTP + DNS until shutdown. The JSON-RPC server,
//! lifecycle state machine, and configuration layer arrive in M1.

mod spike;

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
    /// Bootstrap Arti, check a request over Tor, and serve SOCKS/HTTP/DNS.
    Spike(spike::SpikeArgs),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    let cli = Cli::parse();
    let Some(command) = cli.command else {
        println!(
            "tobrod {} (M0 scaffold: run `tobrod spike`)",
            env!("CARGO_PKG_VERSION")
        );
        return Ok(());
    };

    let (state_dir, cache_dir) = resolve_dirs(cli.state_dir, cli.cache_dir)?;
    match command {
        Command::Spike(args) => spike::run(args, state_dir, cache_dir).await,
    }
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
