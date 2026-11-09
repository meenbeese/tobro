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
            BridgesCommand::Export { .. } | BridgesCommand::Apply { .. } => {}
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
            BridgesCommand::Validate { .. }
            | BridgesCommand::Import { .. }
            | BridgesCommand::Builtin { .. } => unreachable!("handled above"),
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
