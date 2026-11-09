//! `tobrod` — the tobro daemon.
//!
//! M0 scaffold: a `spike` subcommand that bootstraps Arti, verifies a request
//! over Tor, and serves SOCKS/HTTP + DNS until shutdown. The JSON-RPC server,
//! lifecycle state machine, and configuration layer arrive in M1.

mod ipc;
mod lifecycle;
pub(crate) mod onion;
pub(crate) mod outbound;
pub(crate) mod pt_supervisor;
pub(crate) mod redact;
mod spike;
mod supervisor;

use std::path::{Path, PathBuf};

use anyhow::Context as _;
use clap::{Parser, Subcommand};
use directories::ProjectDirs;

#[cfg(unix)]
fn ensure_private_dir(dir: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
    if dir.exists() {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("failed to set private permissions on {}", dir.display()))?;
    } else {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .with_context(|| format!("failed to create private directory {}", dir.display()))?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_private_dir(dir: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir)
        .with_context(|| format!("failed to create directory {}", dir.display()))?;
    Ok(())
}

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
    ensure_private_dir(&state_dir)?;
    ensure_private_dir(&cache_dir)?;
    if let Some(project) = ProjectDirs::from("", "", "tobro") {
        let _ = ensure_private_dir(project.data_dir());
    }
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

    ensure_private_dir(&state_dir)?;
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

    let bridge_settings = resolve_bridge_settings(&config.bridges, Some(&state_dir));
    let outbound_proxy = outbound::resolve_static_outbound_proxy(&config.outbound_proxy)
        .map_err(|e| anyhow::anyhow!(e))?;
    let listeners =
        std::sync::Arc::new(std::sync::RwLock::new(tobro_tor::adapter::ListenerConfig {
            socks_port: config.proxy.socks_port,
            http_port: config.proxy.effective_http_port(),
            dns_port: config.proxy.dns_port,
            bind_all_interfaces: config.proxy.bind_all_interfaces,
            stream_isolation: tobro_tor::adapter::StreamIsolationPolicy {
                isolate_destination: config.stream.isolate_destination,
                isolate_port: config.stream.isolate_port,
                isolate_protocol: config.stream.isolate_protocol,
                keep_alive_isolation: config.stream.keep_alive_isolation,
            },
            network_prefs: tobro_tor::adapter::NetworkStreamPrefs {
                exit_country: config.network.normalized_exit_country(),
                ip_version: match config.network.ip_version {
                    tobro_config::IpVersionPreference::Ipv4Preferred => {
                        tobro_tor::adapter::IpVersionPref::Ipv4Preferred
                    }
                    tobro_config::IpVersionPreference::Ipv6Preferred => {
                        tobro_tor::adapter::IpVersionPref::Ipv6Preferred
                    }
                    tobro_config::IpVersionPreference::Ipv4Only => {
                        tobro_tor::adapter::IpVersionPref::Ipv4Only
                    }
                    tobro_config::IpVersionPreference::Ipv6Only => {
                        tobro_tor::adapter::IpVersionPref::Ipv6Only
                    }
                },
            },
            bridges: bridge_settings,
            outbound_proxy,
        }));
    let ipc_control = ipc::SupervisorControl::new(
        handle.clone(),
        config_path.clone(),
        state_dir.clone(),
        std::sync::Arc::clone(&listeners),
    );
    let ipc_state = state_dir.clone();
    let ipc_cache = cache_dir.clone();
    let ipc_task = tokio::spawn(async move {
        if let Err(error) =
            ipc::serve_daemon(server, ipc_control, ipc_state, ipc_cache, listeners).await
        {
            tracing::error!(%error, "IPC server failed");
        }
    });

    tracing::info!(
        config = %config_path.display(),
        db = %db_path.display(),
        socket = %socket_path.display(),
        socks_port = config.proxy.socks_port,
        http_port = config.proxy.effective_http_port(),
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

fn resolve_pt_binary(
    explicit_path: Option<&str>,
    extra_dir: Option<&str>,
    state_dir: Option<&Path>,
    names: &[std::ffi::OsString],
    label: &str,
    config_hint: &str,
) -> Option<PathBuf> {
    if let Some(p) = explicit_path {
        let p = PathBuf::from(p);
        if p.exists() {
            return Some(p);
        }
        tracing::warn!(
            path = %p.display(),
            transport = label,
            "configured PT transport path does not exist; connect will fail until fixed"
        );
        return None;
    }
    let mut search_dirs = Vec::new();
    if let Some(d) = extra_dir {
        search_dirs.push(PathBuf::from(d));
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            search_dirs.push(dir.to_path_buf());
            search_dirs.push(dir.join("binaries"));
            search_dirs.push(dir.join("../Resources"));
            search_dirs.push(dir.join("../Resources/binaries"));
        }
    }
    if let Some(sd) = state_dir {
        search_dirs.push(sd.join("pt"));
        search_dirs.push(sd.join("sidecars"));
    }
    let opts = crate::pt_supervisor::LocateOptions {
        explicit_path: None,
        search_dirs,
        names: names.to_vec(),
    };
    match crate::pt_supervisor::locate(&opts) {
        Ok(found) => Some(found.path),
        Err(e) => {
            tracing::warn!(
                error = %format!("{e:#}"),
                transport = label,
                hint = config_hint,
                "bridges enabled but PT client was not found"
            );
            None
        }
    }
}

pub(crate) fn resolve_bridge_settings(
    cfg: &tobro_config::BridgesConfig,
    state_dir: Option<&Path>,
) -> tobro_tor::BridgeSettings {
    use std::ffi::OsString;

    let normalized_lines = cfg.normalized_lines();
    if !cfg.enabled || normalized_lines.is_empty() {
        return tobro_tor::BridgeSettings {
            enabled: cfg.enabled,
            lines: cfg.lines.clone(),
            lyrebird_protocols: cfg.lyrebird_transports.clone(),
            lyrebird_path: None,
            snowflake_path: None,
            dnstt_path: None,
            country: cfg.country.clone(),
        };
    }

    let protocols: std::collections::HashSet<String> = normalized_lines
        .iter()
        .filter_map(|l| tobro_tor::pt::bridge_line_protocol(l))
        .collect();
    let lyrebird_protos: std::collections::HashSet<String> = cfg
        .lyrebird_transports
        .iter()
        .map(|s| {
            let s = s.trim().to_ascii_lowercase();
            if s == "meek" {
                "meek_lite".to_owned()
            } else {
                s
            }
        })
        .collect();
    let needs_lyrebird = protocols.iter().any(|p| lyrebird_protos.contains(p));
    let needs_snowflake = protocols
        .iter()
        .any(|p| p == tobro_tor::pt::SNOWFLAKE_PROTOCOL);
    let needs_dnstt = protocols.iter().any(|p| p == tobro_tor::pt::DNSTT_PROTOCOL);

    let lyrebird_path = if needs_lyrebird {
        resolve_pt_binary(
            cfg.transport_path.as_deref(),
            cfg.transport_dir.as_deref(),
            state_dir,
            &[OsString::from("lyrebird"), OsString::from("lyrebird.exe")],
            "lyrebird",
            "bridges.transport_path/transport_dir",
        )
    } else {
        None
    };
    let snowflake_path = if needs_snowflake {
        resolve_pt_binary(
            cfg.snowflake_path.as_deref(),
            cfg.snowflake_dir.as_deref(),
            state_dir,
            &[
                OsString::from("snowflake-client"),
                OsString::from("snowflake-client.exe"),
            ],
            "snowflake-client",
            "bridges.snowflake_path/snowflake_dir",
        )
    } else {
        None
    };
    let dnstt_path = if needs_dnstt {
        resolve_pt_binary(
            cfg.dnstt_path.as_deref(),
            cfg.dnstt_dir.as_deref(),
            state_dir,
            &[
                OsString::from("dnstt-client"),
                OsString::from("dnstt-client.exe"),
                OsString::from("dnstt"),
            ],
            "dnstt-client",
            "bridges.dnstt_path/dnstt_dir",
        )
    } else {
        None
    };

    tobro_tor::BridgeSettings {
        enabled: true,
        lines: cfg.lines.clone(),
        lyrebird_path,
        lyrebird_protocols: cfg.lyrebird_transports.clone(),
        snowflake_path,
        dnstt_path,
        country: cfg.country.clone(),
    }
}
