//! `tobroctl` — command-line client for `tobrod`.

use std::path::PathBuf;

use anyhow::Context as _;
use clap::{Parser, Subcommand};
use directories::ProjectDirs;
use serde_json::{Value, json};

#[derive(Debug, Parser)]
#[command(
    name = "tobroctl",
    version,
    about = "Control the tobro daemon",
    long_about = "Control tobrod over local IPC.\n\nFor M1, `tobrod run` starts the daemon in a stopped state; use `tobroctl connect` to start Tor and `tobroctl stop` to disconnect. Output is JSON on stdout; diagnostics go to stderr. Exit code 0 on success, 1 on error."
)]
struct Cli {
    /// IPC socket/endpoint path (defaults to the platform state directory).
    #[arg(long, global = true, value_name = "PATH")]
    socket: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Print the daemon status as JSON.
    Status,
    /// Ask the daemon to connect/start Tor.
    Connect,
    /// Ask the daemon to stop/disconnect Tor.
    Stop,
    /// Request a new identity (new circuits; guard state preserved).
    NewIdentity,
    /// Reload and validate daemon configuration from disk.
    ReloadConfig,
    /// Read or modify daemon configuration via the daemon config API.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Parse, validate, import/export, or apply bridge lines and built-in sets.
    Bridges {
        #[command(subcommand)]
        command: BridgesCommand,
    },
    /// Manage hosted v3 onion services (create/edit/delete/enable/disable).
    Onion {
        #[command(subcommand)]
        command: OnionCommand,
    },
    /// Stream IPC notifications as JSON lines until Ctrl-C.
    Watch,
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    /// Get the current daemon configuration (redacted; no secrets).
    Get,
    /// Validate a JSON patch without persisting it.
    Validate {
        /// JSON patch object, `@path` to read a file, or `-` to read stdin.
        patch: String,
    },
    /// Validate, persist, and stage/apply a JSON patch.
    Apply {
        /// JSON patch object, `@path` to read a file, or `-` to read stdin.
        patch: String,
    },
}

#[derive(Debug, Subcommand)]
enum BridgesCommand {
    /// Validate bridge lines (local; does not require the daemon).
    Validate {
        /// Bridge lines text, `@path` to read a file, or `-` to read stdin.
        input: String,
    },
    /// Normalize/import bridge lines from text (local).
    Import {
        /// Bridge lines text, `@path` to read a file, or `-` to read stdin.
        input: String,
        /// Output normalized lines as a JSON array instead of text.
        #[arg(long)]
        json: bool,
    },
    /// Show lines from the embedded/bundled built-in bridge distribution (local).
    Builtin {
        /// Load a bridge distribution JSON file instead of the embedded default.
        #[arg(long, value_name = "PATH")]
        file: Option<PathBuf>,
        /// Filter by transport/type (e.g. obfs4, snowflake, webtunnel).
        #[arg(long)]
        transport: Option<String>,
        /// Filter by country (ISO 3166-1 alpha-2).
        #[arg(long)]
        country: Option<String>,
    },
    /// Export current bridge lines from the daemon config.
    Export {
        /// Redact sensitive bridge material (safe for sharing/diagnostics).
        #[arg(long)]
        redacted: bool,
    },
    /// Import bridge lines and apply them to the daemon config (replaces `bridges.lines`).
    Apply {
        /// Bridge lines text, `@path` to read a file, or `-` to read stdin.
        input: String,
        /// Set `bridges.enabled` (default: true when lines are present).
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        enabled: bool,
    },
    /// Test bridge/pluggable transport line(s) via the daemon (validation + PT/config diagnostics).
    Test {
        /// Bridge line text, `@path` to read a file, or `-` to read stdin.
        input: String,
    },
    /// Fetch bridges via Moat with country/transport selection and fallback (local network call).
    Moat {
        /// Country code (ISO 3166-1 alpha-2), e.g. `de`, `cn`. Optional.
        #[arg(long)]
        country: Option<String>,
        /// Preferred transport/type filter (e.g. obfs4, snowflake, webtunnel).
        #[arg(long)]
        transport: Option<String>,
        /// Moat base URL (defaults to Tor Project Moat). Useful for testing/mirrors.
        #[arg(long, value_name = "URL")]
        endpoint: Option<String>,
        /// Local built-in bridge distribution JSON file for fallback.
        #[arg(long, value_name = "PATH")]
        builtin: Option<PathBuf>,
        /// Output only bridge lines as text (default: JSON summary including source/fallback).
        #[arg(long)]
        lines_only: bool,
    },
}

#[derive(Debug, Subcommand)]
enum OnionCommand {
    /// List hosted onion services.
    List,
    /// Create a hosted onion service.
    Create {
        /// Human-readable service name.
        #[arg(long)]
        name: String,
        /// Port mapping `VIRT[:TARGET_HOST]:TARGET` (repeatable). Example: `--port 80:8080`.
        #[arg(long = "port", value_name = "VIRT[:HOST]:TARGET", required = true)]
        ports: Vec<String>,
        /// Create the service in disabled state.
        #[arg(long)]
        disabled: bool,
    },
    /// Update a hosted onion service (name, ports, enable/disable).
    Update {
        /// Service id.
        #[arg(long)]
        id: String,
        /// New human-readable name.
        #[arg(long)]
        name: Option<String>,
        /// Replace port mappings (repeatable). Same format as `onion create --port`.
        #[arg(long = "port", value_name = "VIRT[:HOST]:TARGET")]
        ports: Vec<String>,
        /// Enable the service.
        #[arg(long, conflicts_with = "disable")]
        enable: bool,
        /// Disable the service.
        #[arg(long, conflicts_with = "enable")]
        disable: bool,
    },
    /// Enable a hosted onion service.
    Enable {
        /// Service id.
        #[arg(long)]
        id: String,
    },
    /// Disable a hosted onion service.
    Disable {
        /// Service id.
        #[arg(long)]
        id: String,
    },
    /// Delete a hosted onion service and its managed key storage.
    Delete {
        /// Service id.
        #[arg(long)]
        id: String,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let code = match run(cli).await {
        Ok(()) => 0,
        Err(err) => {
            eprintln!("tobroctl: {err:#}");
            1
        }
    };
    std::process::exit(code);
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    let socket = match &cli.socket {
        Some(path) => path.clone(),
        None => default_socket()?,
    };

    // Local-only bridge commands do not require a running daemon.
    if let Command::Bridges { command } = &cli.command {
        match command {
            BridgesCommand::Validate { input } => return bridges_validate(input),
            BridgesCommand::Import { input, json } => return bridges_import(input, *json),
            BridgesCommand::Builtin {
                file,
                transport,
                country,
            } => {
                return bridges_builtin(file.as_deref(), transport.as_deref(), country.as_deref());
            }
            BridgesCommand::Moat {
                country,
                transport,
                endpoint,
                builtin,
                lines_only,
            } => {
                return bridges_moat(
                    country.as_deref(),
                    transport.as_deref(),
                    endpoint.as_deref(),
                    builtin.as_deref(),
                    *lines_only,
                )
                .await;
            }
            BridgesCommand::Export { .. }
            | BridgesCommand::Apply { .. }
            | BridgesCommand::Test { .. } => {}
        }
    }

    let mut client = tobro_ipc::Client::connect(&socket)
        .await
        .with_context(|| format!("could not connect to tobrod at {}", socket.display()))?;

    let hello = client.handshake().await.context("IPC handshake failed")?;
    eprintln!(
        "tobrod {} (rpc v{}, {}, arti {}), pid {}",
        hello.daemon_version, hello.rpc_version, hello.platform, hello.arti_version, hello.pid
    );

    match cli.command {
        Command::Status => {
            let status = client.call(tobro_ipc::methods::STATUS, None).await?;
            print_json(&status)?;
        }
        Command::Connect => {
            let result = client.call(tobro_ipc::methods::CONNECT, None).await?;
            print_json(&result)?;
        }
        Command::Stop => {
            let result = client.call(tobro_ipc::methods::STOP, None).await?;
            print_json(&result)?;
        }
        Command::NewIdentity => {
            let result = client.call(tobro_ipc::methods::NEW_IDENTITY, None).await?;
            print_json(&result)?;
        }
        Command::ReloadConfig => {
            let result = client.call(tobro_ipc::methods::RELOAD_CONFIG, None).await?;
            print_json(&result)?;
        }
        Command::Config { command } => match command {
            ConfigCommand::Get => {
                let result = client.call(tobro_ipc::methods::CONFIG_GET, None).await?;
                print_json(&result)?;
            }
            ConfigCommand::Validate { patch } => {
                let patch = read_patch(&patch)?;
                let result = client
                    .call(
                        tobro_ipc::methods::CONFIG_VALIDATE,
                        Some(json!({ "patch": patch })),
                    )
                    .await?;
                print_json(&result)?;
            }
            ConfigCommand::Apply { patch } => {
                let patch = read_patch(&patch)?;
                let result = client
                    .call(
                        tobro_ipc::methods::CONFIG_APPLY,
                        Some(json!({ "patch": patch })),
                    )
                    .await?;
                print_json(&result)?;
            }
        },
        Command::Bridges { command } => match command {
            BridgesCommand::Export { redacted } => bridges_export(&mut client, redacted).await?,
            BridgesCommand::Apply { input, enabled } => {
                bridges_apply(&mut client, &input, enabled).await?;
            }
            BridgesCommand::Test { input } => bridges_test(&mut client, &input).await?,
            BridgesCommand::Validate { .. }
            | BridgesCommand::Import { .. }
            | BridgesCommand::Builtin { .. }
            | BridgesCommand::Moat { .. } => unreachable!("handled above"),
        },
        Command::Onion { command } => match command {
            OnionCommand::List => {
                let result = client.call(tobro_ipc::methods::ONION_LIST, None).await?;
                print_json(&result)?;
            }
            OnionCommand::Create {
                name,
                ports,
                disabled,
            } => {
                let ports = parse_onion_ports(&ports)?;
                let result = client
                    .call(
                        tobro_ipc::methods::ONION_CREATE,
                        Some(json!({ "name": name, "ports": ports, "enabled": !disabled })),
                    )
                    .await?;
                print_json(&result)?;
            }
            OnionCommand::Update {
                id,
                name,
                ports,
                enable,
                disable,
            } => {
                let mut patch = serde_json::Map::new();
                patch.insert("id".to_owned(), Value::String(id));
                if let Some(name) = name {
                    patch.insert("name".to_owned(), Value::String(name));
                }
                if !ports.is_empty() {
                    patch.insert("ports".to_owned(), Value::Array(parse_onion_ports(&ports)?));
                }
                if enable {
                    patch.insert("enabled".to_owned(), Value::Bool(true));
                } else if disable {
                    patch.insert("enabled".to_owned(), Value::Bool(false));
                }
                let result = client
                    .call(tobro_ipc::methods::ONION_UPDATE, Some(Value::Object(patch)))
                    .await?;
                print_json(&result)?;
            }
            OnionCommand::Enable { id } => {
                let result = client
                    .call(
                        tobro_ipc::methods::ONION_UPDATE,
                        Some(json!({ "id": id, "enabled": true })),
                    )
                    .await?;
                print_json(&result)?;
            }
            OnionCommand::Disable { id } => {
                let result = client
                    .call(
                        tobro_ipc::methods::ONION_UPDATE,
                        Some(json!({ "id": id, "enabled": false })),
                    )
                    .await?;
                print_json(&result)?;
            }
            OnionCommand::Delete { id } => {
                let result = client
                    .call(tobro_ipc::methods::ONION_DELETE, Some(json!({ "id": id })))
                    .await?;
                print_json(&result)?;
            }
        },
        Command::Watch => watch(&mut client).await?,
    }

    Ok(())
}

async fn watch(client: &mut tobro_ipc::Client) -> anyhow::Result<()> {
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => return Ok(()),
            message = client.next_notification() => {
                match message? {
                    Some(notification) => {
                        let message = tobro_ipc::Message::Notification(notification);
                        println!("{}", serde_json::to_string(&message)?);
                    }
                    None => return Ok(()),
                }
            }
        }
    }
}

fn print_json(value: &Value) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

fn read_text_input(input: &str) -> anyhow::Result<String> {
    if input == "-" {
        use std::io::Read as _;
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .context("failed to read input from stdin")?;
        Ok(buf)
    } else if let Some(path) = input.strip_prefix('@') {
        std::fs::read_to_string(path).with_context(|| format!("failed to read input from {path}"))
    } else {
        Ok(input.to_owned())
    }
}

fn bridges_validate(input: &str) -> anyhow::Result<()> {
    let text = read_text_input(input)?;
    let lines = tobro_tor::import_bridge_lines(&text);
    let result = tobro_tor::validate_bridge_lines(&lines);
    print_json(&serde_json::to_value(&result)?)?;
    if !result.ok {
        anyhow::bail!("{} invalid bridge line(s)", result.invalid_count);
    }
    Ok(())
}

fn bridges_import(input: &str, as_json: bool) -> anyhow::Result<()> {
    let text = read_text_input(input)?;
    let lines = tobro_tor::import_bridge_lines(&text);
    if as_json {
        print_json(&serde_json::to_value(&lines)?)?;
    } else {
        print!("{}", tobro_tor::export_bridge_lines_text(&lines));
    }
    Ok(())
}

fn bridges_builtin(
    file: Option<&std::path::Path>,
    transport: Option<&str>,
    country: Option<&str>,
) -> anyhow::Result<()> {
    let dist = if let Some(path) = file {
        tobro_tor::BridgeDistribution::load(path).map_err(|e| anyhow::anyhow!(e))?
    } else {
        tobro_tor::builtin_bridges().map_err(|e| anyhow::anyhow!(e))?
    };
    let lines = dist.lines_for(transport, country);
    let out = json!({
        "version": dist.version,
        "updated": dist.updated,
        "match": { "transport": transport, "country": country },
        "count": lines.len(),
        "lines": lines,
    });
    print_json(&out)?;
    Ok(())
}

async fn bridges_export(client: &mut tobro_ipc::Client, redacted: bool) -> anyhow::Result<()> {
    let result = client.call(tobro_ipc::methods::CONFIG_GET, None).await?;
    let lines = result
        .get("config")
        .and_then(|c| c.get("bridges"))
        .and_then(|b| b.get("lines"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(ToOwned::to_owned))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if redacted {
        print!("{}", tobro_tor::export_bridge_lines_redacted(&lines));
    } else {
        print!("{}", tobro_tor::export_bridge_lines_text(&lines));
    }
    Ok(())
}

async fn bridges_apply(
    client: &mut tobro_ipc::Client,
    input: &str,
    enabled: bool,
) -> anyhow::Result<()> {
    let text = read_text_input(input)?;
    let lines = tobro_tor::import_bridge_lines(&text);
    let validation = tobro_tor::validate_bridge_lines(&lines);
    if !validation.ok {
        eprintln!(
            "warning: {} invalid bridge line(s)",
            validation.invalid_count
        );
        for err in validation.errors() {
            eprintln!("  {err}");
        }
        anyhow::bail!("refusing to apply invalid bridge lines; fix them or remove them");
    }
    let result = client
        .call(
            tobro_ipc::methods::CONFIG_APPLY,
            Some(json!({ "patch": { "bridges": { "enabled": enabled, "lines": lines } } })),
        )
        .await?;
    print_json(&result)?;
    Ok(())
}

async fn bridges_test(client: &mut tobro_ipc::Client, input: &str) -> anyhow::Result<()> {
    let text = read_text_input(input)?;
    let result = client
        .call(
            tobro_ipc::methods::BRIDGES_TEST,
            Some(json!({ "line": text })),
        )
        .await?;
    print_json(&result)?;
    if !result.get("ok").and_then(Value::as_bool).unwrap_or(false) {
        anyhow::bail!("bridge transport test reported issues (see diagnostics)");
    }
    Ok(())
}

async fn bridges_moat(
    country: Option<&str>,
    transport: Option<&str>,
    endpoint: Option<&str>,
    builtin: Option<&std::path::Path>,
    lines_only: bool,
) -> anyhow::Result<()> {
    use tobro_tor::moat::{self, MoatClient};

    let client = match endpoint {
        Some(url) => MoatClient::with_base_url(url).map_err(|e| anyhow::anyhow!(e))?,
        None => MoatClient::new().map_err(|e| anyhow::anyhow!(e))?,
    };
    let local_builtin = if let Some(path) = builtin {
        Some(tobro_tor::BridgeDistribution::load(path).map_err(|e| anyhow::anyhow!(e))?)
    } else {
        tobro_tor::builtin_bridges().ok()
    };
    let transports = transport.map(|t| vec![t.to_owned()]);
    let resolved = moat::fetch_bridges_with_fallback(
        &client,
        country,
        transports.as_deref(),
        local_builtin.as_ref(),
    )
    .await;

    if lines_only {
        print!("{}", tobro_tor::export_bridge_lines_text(&resolved.lines));
        return Ok(());
    }
    let out = json!({
        "ok": !resolved.lines.is_empty(),
        "source": resolved.source,
        "country": resolved.country,
        "transport": resolved.transport,
        "count": resolved.lines.len(),
        "note": resolved.note,
        "lines": resolved.lines,
    });
    print_json(&out)?;
    if resolved.lines.is_empty() {
        anyhow::bail!("no bridges resolved (Moat unavailable and no matching local built-ins)");
    }
    Ok(())
}

fn parse_onion_ports(specs: &[String]) -> anyhow::Result<Vec<Value>> {
    let mut out = Vec::with_capacity(specs.len());
    for spec in specs {
        let s = spec.trim();
        // Formats: VIRT:TARGET  |  VIRT:HOST:TARGET
        let parts: Vec<&str> = s.split(':').collect();
        let (virt_port, target_host, target_port) = match parts.as_slice() {
            [virt, target] => (
                virt.parse::<u16>()
                    .with_context(|| format!("invalid virtual port in {spec:?}"))?,
                "127.0.0.1".to_owned(),
                target
                    .parse::<u16>()
                    .with_context(|| format!("invalid target port in {spec:?}"))?,
            ),
            [virt, host, target] => (
                virt.parse::<u16>()
                    .with_context(|| format!("invalid virtual port in {spec:?}"))?,
                (*host).to_owned(),
                target
                    .parse::<u16>()
                    .with_context(|| format!("invalid target port in {spec:?}"))?,
            ),
            _ => anyhow::bail!(
                "invalid --port {spec:?}; expected VIRT:TARGET or VIRT:HOST:TARGET (e.g. 80:8080)"
            ),
        };
        if virt_port == 0 || target_port == 0 {
            anyhow::bail!("ports must be non-zero in {spec:?}");
        }
        out.push(json!({
            "virt_port": virt_port,
            "target_host": target_host,
            "target_port": target_port,
        }));
    }
    Ok(out)
}

fn read_patch(input: &str) -> anyhow::Result<Value> {
    let raw = if input == "-" {
        use std::io::Read as _;
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .context("failed to read patch from stdin")?;
        buf
    } else if let Some(path) = input.strip_prefix('@') {
        std::fs::read_to_string(path)
            .with_context(|| format!("failed to read patch from {path}"))?
    } else {
        input.to_owned()
    };
    let value: Value = serde_json::from_str(&raw).context("patch must be valid JSON")?;
    if !value.is_object() {
        anyhow::bail!("patch must be a JSON object");
    }
    Ok(value)
}

fn default_socket() -> anyhow::Result<PathBuf> {
    let project = ProjectDirs::from("", "", "tobro")
        .context("could not determine the platform data directory")?;
    Ok(tobro_ipc::socket_path(&project.data_dir().join("state")))
}
