//! `tobroctl` — command-line client for `tobrod`.

use std::path::{Path, PathBuf};

use anyhow::Context as _;
use clap::{Parser, Subcommand};
use directories::ProjectDirs;
use serde_json::{Value, json};

#[derive(Debug, Parser)]
#[command(
    name = "tobroctl",
    version,
    about = "Control the tobro daemon",
    long_about = "Control the headless tobrod daemon over local IPC.\n\n\
Typical headless flow:\n  \
  tobroctl start        spawn `tobrod run` detached and wait until it is ready\n  \
  tobroctl status       current daemon state (JSON)\n  \
  tobroctl connect      start Tor (bootstrap)\n  \
  tobroctl stop         stop Tor (daemon keeps running)\n  \
  tobroctl logs         recent, redacted daemon logs (JSON)\n  \
  tobroctl shutdown     disconnect and exit the daemon process\n\n\
Output is JSON on stdout; diagnostics go to stderr. Exit code 0 on success, 1 on error."
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
    /// Launch the headless daemon (`tobrod run`) and wait until IPC is ready.
    Start {
        /// Path to the `tobrod` binary (defaults to a sibling of `tobroctl`).
        #[arg(long, value_name = "PATH")]
        daemon: Option<PathBuf>,
        /// Daemon log file (defaults to `<state-dir>/tobrod.log`).
        #[arg(long, value_name = "PATH")]
        log_file: Option<PathBuf>,
        /// Run the daemon in the foreground instead of spawning it detached.
        #[arg(long)]
        foreground: bool,
        /// Also start Tor once the daemon is ready.
        #[arg(long)]
        connect: bool,
        /// Seconds to wait for the daemon IPC endpoint to become ready.
        #[arg(long, default_value_t = 20)]
        wait: u64,
    },
    /// Ask the daemon to connect/start Tor.
    Connect,
    /// Ask the daemon to stop/disconnect Tor.
    Stop,
    /// Ask the daemon process to disconnect Tor and exit cleanly.
    Shutdown,
    /// Request a new identity (new circuits; guard state preserved).
    NewIdentity,
    /// Fetch recent daemon log lines (redacted ring buffer) as JSON.
    Logs {
        /// Maximum number of recent lines to return (1..=10000).
        #[arg(long, default_value_t = 200)]
        lines: u64,
        /// Print raw log lines instead of a JSON envelope.
        #[arg(long)]
        text: bool,
    },
    /// Collect or inspect daemon diagnostics.
    Diagnostics {
        #[command(subcommand)]
        command: DiagnosticsCommand,
    },
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
    /// Manage client authorization credentials for onion services (.auth_private).
    ClientAuth {
        #[command(subcommand)]
        command: ClientAuthCommand,
    },
    /// Stream IPC notifications as JSON lines until Ctrl-C.
    Watch,
}

#[derive(Debug, Subcommand)]
enum DiagnosticsCommand {
    /// Export a redacted diagnostics bundle (status, config, onion, kindness, logs).
    ///
    /// The bundle never contains key material, passwords, or raw bridge
    /// credentials: the config comes from the daemon's redacted view and log
    /// lines are redacted at capture time. Hosted `.onion` addresses are
    /// public by design and included; review the file before sharing it.
    Export {
        /// Write the bundle JSON to this path (0600) instead of stdout.
        #[arg(long, value_name = "PATH")]
        out: Option<PathBuf>,
        /// Maximum number of recent log lines to include (1..=10000).
        #[arg(long, default_value_t = 200)]
        lines: u64,
    },
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
    /// Create an encrypted backup bundle (onion services + client auth keys).
    ///
    /// The bundle contains private keys protected only by its passphrase.
    Backup {
        /// Write the bundle JSON to this path (0600) instead of stdout.
        #[arg(long, value_name = "PATH")]
        out: Option<PathBuf>,
        /// Encryption passphrase (prompted interactively when omitted).
        #[arg(long, value_name = "PASSPHRASE")]
        passphrase: Option<String>,
        /// Restrict the backup to these service ids (repeatable).
        #[arg(long = "id", value_name = "SERVICE_ID")]
        ids: Vec<String>,
    },
    /// Restore an encrypted backup bundle produced by `onion backup`.
    Restore {
        /// Bundle file path, or `-` to read from stdin.
        #[arg(long = "file", value_name = "PATH|-")]
        file: String,
        /// Decryption passphrase (prompted interactively when omitted).
        #[arg(long, value_name = "PASSPHRASE")]
        passphrase: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum ClientAuthCommand {
    /// List client authorization credentials.
    List,
    /// Generate a new x25519 client authorization credential.
    Generate {
        /// Human-readable nickname (a unique suffix is appended).
        #[arg(long)]
        nickname: Option<String>,
    },
    /// Import a `.auth_private` credential file.
    Import {
        /// Human-readable nickname.
        #[arg(long)]
        nickname: String,
        /// `.auth_private` file path, or `-` to read from stdin.
        #[arg(long = "file", value_name = "PATH|-")]
        file: String,
    },
    /// Export a credential as a standard `.auth_private` key file for a client.
    Export {
        /// Credential id (see `client-auth list`).
        #[arg(long)]
        id: String,
        /// Target `.onion` address (optional when the credential is attached to
        /// a service with a published address).
        #[arg(long)]
        onion_address: Option<String>,
        /// Write the key file to this path (0600) instead of stdout.
        #[arg(long, value_name = "PATH")]
        out: Option<PathBuf>,
    },
    /// Delete a credential and its managed key storage.
    Delete {
        /// Credential id.
        #[arg(long)]
        id: String,
    },
    /// Attach a credential to an onion service (restricted discovery).
    Attach {
        /// Credential id.
        #[arg(long)]
        id: String,
        /// Onion service id (see `onion list`).
        #[arg(long)]
        service: String,
    },
    /// Detach a credential from an onion service.
    Detach {
        /// Credential id.
        #[arg(long)]
        id: String,
        /// Onion service id.
        #[arg(long)]
        service: String,
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

    // Local-only bridge commands and `start` do not require a running daemon.
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

    // `start` may launch the daemon itself, so it runs before the connect.
    if let Command::Start {
        daemon,
        log_file,
        foreground,
        connect,
        wait,
    } = &cli.command
    {
        return start_daemon(
            &socket,
            daemon.as_deref(),
            log_file.as_deref(),
            *foreground,
            *connect,
            *wait,
        )
        .await;
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
        Command::Shutdown => {
            let result = client.call(tobro_ipc::methods::SHUTDOWN, None).await?;
            print_json(&result)?;
            // The daemon answers, then drops the socket while it exits; give
            // it a moment so callers can immediately observe a stopped daemon.
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }
        Command::NewIdentity => {
            let result = client.call(tobro_ipc::methods::NEW_IDENTITY, None).await?;
            print_json(&result)?;
        }
        Command::Logs { lines, text } => {
            let result = client
                .call(
                    tobro_ipc::methods::LOGS,
                    Some(json!({ "lines": clamp_log_lines(lines) })),
                )
                .await?;
            if text {
                if let Some(lines) = result.get("lines").and_then(Value::as_array) {
                    for line in lines.iter().filter_map(Value::as_str) {
                        println!("{line}");
                    }
                }
            } else {
                print_json(&result)?;
            }
        }
        Command::Diagnostics { command } => match command {
            DiagnosticsCommand::Export { out, lines } => {
                diagnostics_export(&mut client, out, clamp_log_lines(lines)).await?
            }
        },
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
            OnionCommand::Backup {
                out,
                passphrase,
                ids,
            } => {
                let passphrase = read_passphrase(passphrase, "backup")?;
                let mut params = serde_json::Map::new();
                params.insert("passphrase".to_owned(), Value::String(passphrase));
                if !ids.is_empty() {
                    params.insert(
                        "service_ids".to_owned(),
                        Value::Array(ids.into_iter().map(Value::String).collect()),
                    );
                }
                let result = client
                    .call(
                        tobro_ipc::methods::ONION_BACKUP,
                        Some(Value::Object(params)),
                    )
                    .await?;
                match out {
                    Some(path) => {
                        let bundle = result
                            .get("bundle")
                            .cloned()
                            .context("backup response is missing the bundle envelope")?;
                        write_bundle_file(&path, &serde_json::to_vec_pretty(&bundle)?)?;
                        print_json(&json!({
                            "ok": true,
                            "action": "onion.backup",
                            "counts": result.get("counts").cloned().unwrap_or(Value::Null),
                            "written": path.display().to_string(),
                            "warning": result.get("warning").cloned().unwrap_or(Value::Null),
                        }))?;
                    }
                    None => print_json(&result)?,
                }
            }
            OnionCommand::Restore { file, passphrase } => {
                let passphrase = read_passphrase(passphrase, "restore")?;
                let text = read_bundle_file(&file)?;
                let bundle: Value =
                    serde_json::from_str(&text).context("bundle file is not valid JSON")?;
                let result = client
                    .call(
                        tobro_ipc::methods::ONION_RESTORE,
                        Some(json!({ "passphrase": passphrase, "bundle": bundle })),
                    )
                    .await?;
                print_json(&result)?;
            }
        },
        Command::ClientAuth { command } => match command {
            ClientAuthCommand::List => {
                let result = client
                    .call(tobro_ipc::methods::CLIENT_AUTH_LIST, None)
                    .await?;
                print_json(&result)?;
            }
            ClientAuthCommand::Generate { nickname } => {
                let params = nickname
                    .as_deref()
                    .map(|n| json!({ "nickname": n.trim() }))
                    .filter(|p| {
                        !p.get("nickname")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .is_empty()
                    });
                let result = client
                    .call(tobro_ipc::methods::CLIENT_AUTH_GENERATE, params)
                    .await?;
                print_json(&result)?;
            }
            ClientAuthCommand::Import { nickname, file } => {
                let content = read_auth_private_file(&file)?;
                let result = client
                    .call(
                        tobro_ipc::methods::CLIENT_AUTH_IMPORT,
                        Some(json!({ "nickname": nickname, "content": content })),
                    )
                    .await?;
                print_json(&result)?;
            }
            ClientAuthCommand::Export {
                id,
                onion_address,
                out,
            } => client_auth_export(&mut client, &id, onion_address.as_deref(), out).await?,
            ClientAuthCommand::Delete { id } => {
                let result = client
                    .call(
                        tobro_ipc::methods::CLIENT_AUTH_DELETE,
                        Some(json!({ "id": id })),
                    )
                    .await?;
                print_json(&result)?;
            }
            ClientAuthCommand::Attach { id, service } => {
                let result = client
                    .call(
                        tobro_ipc::methods::CLIENT_AUTH_ATTACH,
                        Some(json!({ "service_id": service, "client_auth_id": id })),
                    )
                    .await?;
                print_json(&result)?;
            }
            ClientAuthCommand::Detach { id, service } => {
                let result = client
                    .call(
                        tobro_ipc::methods::CLIENT_AUTH_DETACH,
                        Some(json!({ "service_id": service, "client_auth_id": id })),
                    )
                    .await?;
                print_json(&result)?;
            }
        },
        Command::Start { .. } => unreachable!("handled before the IPC connection"),
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

/// Read `.auth_private` file contents from a path or stdin (`-`).
fn read_auth_private_file(input: &str) -> anyhow::Result<String> {
    if input == "-" {
        use std::io::Read as _;
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .context("failed to read .auth_private from stdin")?;
        Ok(buf)
    } else {
        std::fs::read_to_string(input)
            .with_context(|| format!("failed to read .auth_private from {input}"))
    }
}

/// Prompt for a hidden passphrase when not supplied on the command line.
fn read_passphrase(flag: Option<String>, action: &str) -> anyhow::Result<String> {
    if let Some(passphrase) = flag {
        return Ok(passphrase);
    }
    rpassword::prompt_password(format!("{action} passphrase: "))
        .context("failed to read passphrase")
}

/// Read a backup bundle from a file path, or `-` for stdin.
fn read_bundle_file(input: &str) -> anyhow::Result<String> {
    if input == "-" {
        use std::io::Read as _;
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .context("failed to read bundle from stdin")?;
        Ok(buf)
    } else {
        std::fs::read_to_string(input)
            .with_context(|| format!("failed to read bundle from {input}"))
    }
}

/// Write a bundle file with private-key-safe permissions (0600 on Unix).
fn write_bundle_file(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    std::fs::write(path, bytes).with_context(|| format!("failed to write {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("failed to set 0600 on {}", path.display()))?;
    }
    Ok(())
}

async fn client_auth_export(
    client: &mut tobro_ipc::Client,
    id: &str,
    onion_address: Option<&str>,
    out: Option<PathBuf>,
) -> anyhow::Result<()> {
    let mut params = serde_json::Map::new();
    params.insert("id".to_owned(), Value::String(id.to_owned()));
    if let Some(addr) = onion_address {
        params.insert("onion_address".to_owned(), Value::String(addr.to_owned()));
    }
    let result = client
        .call(
            tobro_ipc::methods::CLIENT_AUTH_EXPORT,
            Some(Value::Object(params)),
        )
        .await?;
    match out {
        Some(path) => {
            let content = result
                .get("content")
                .and_then(Value::as_str)
                .context("export response is missing key content")?;
            if let Some(parent) = path.parent()
                && !parent.as_os_str().is_empty()
            {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("failed to create {}", parent.display()))?;
            }
            std::fs::write(&path, content)
                .with_context(|| format!("failed to write {}", path.display()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                    .with_context(|| format!("failed to set 0600 on {}", path.display()))?;
            }
            print_json(&json!({
                "ok": true,
                "action": "client_auth.export",
                "id": result.get("id").cloned().unwrap_or(Value::Null),
                "nickname": result.get("nickname").cloned().unwrap_or(Value::Null),
                "filename": result.get("filename").cloned().unwrap_or(Value::Null),
                "written": path.display().to_string(),
                "warning": "This file contains a private key. Store and transmit it securely.",
            }))?;
        }
        None => print_json(&result)?,
    }
    Ok(())
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

/// Clamp `--lines` into the range the daemon accepts (1..=10000).
fn clamp_log_lines(lines: u64) -> u64 {
    lines.clamp(1, tobro_ipc::MAX_LOG_LINES_REQUEST)
}

/// Launch the headless daemon and wait for its IPC endpoint.
///
/// Detached spawn: the daemon runs in its own process group (Unix), so a
/// Ctrl-C on `tobroctl` never takes the daemon down with it.
async fn start_daemon(
    socket: &Path,
    daemon: Option<&Path>,
    log_file: Option<&Path>,
    foreground: bool,
    connect: bool,
    wait_secs: u64,
) -> anyhow::Result<()> {
    // Fast path: a daemon is already serving this endpoint.
    if let Ok(mut probe) = tobro_ipc::Client::connect(socket).await
        && probe.handshake().await.is_ok()
    {
        let status = probe
            .call(tobro_ipc::methods::STATUS, None)
            .await
            .unwrap_or(Value::Null);
        print_json(&json!({
            "ok": true,
            "action": "start",
            "spawned": false,
            "already_running": true,
            "socket": socket.display().to_string(),
            "status": status,
            "note": "a daemon is already running on this endpoint; nothing was launched",
        }))?;
        return Ok(());
    }

    let daemon_path = match daemon {
        Some(path) => path.to_path_buf(),
        None => locate_daemon_binary()?,
    };
    let log_path = match log_file {
        Some(path) => path.to_path_buf(),
        None => socket
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("tobrod.log"),
    };

    let mut command = tokio::process::Command::new(&daemon_path);
    command
        .arg("run")
        .arg("--socket")
        .arg(socket)
        .arg("--log-file")
        .arg(&log_path);

    if foreground {
        eprintln!(
            "running {} in the foreground (Ctrl-C to stop); logs go to stderr and {}",
            daemon_path.display(),
            log_path.display()
        );
        let status = command
            .status()
            .await
            .with_context(|| format!("failed to launch {}", daemon_path.display()))?;
        print_json(&json!({
            "ok": status.success(),
            "action": "start",
            "foreground": true,
            "exit_code": status.code(),
        }))?;
        return Ok(());
    }

    // Own process group so Ctrl-C on `tobroctl` never takes the daemon down.
    #[cfg(unix)]
    command.process_group(0);
    command.stdin(std::process::Stdio::null());
    command.stdout(std::process::Stdio::null());
    command.stderr(std::process::Stdio::null());
    let mut child = command
        .spawn()
        .with_context(|| format!("failed to spawn {}", daemon_path.display()))?;

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(wait_secs.max(1));
    loop {
        if child.try_wait()?.is_some() {
            anyhow::bail!(
                "tobrod exited during startup; run `tobroctl start --foreground` (or `tobrod run`) \
                 to see the failure, and check the log file {}",
                log_path.display()
            );
        }
        if let Ok(mut probe) = tobro_ipc::Client::connect(socket).await
            && probe.handshake().await.is_ok()
        {
            let status = probe
                .call(tobro_ipc::methods::STATUS, None)
                .await
                .unwrap_or(Value::Null);
            if connect {
                let result = probe.call(tobro_ipc::methods::CONNECT, None).await?;
                eprintln!("connect requested: {result}");
            }
            print_json(&json!({
                "ok": true,
                "action": "start",
                "spawned": true,
                "daemon": daemon_path.display().to_string(),
                "socket": socket.display().to_string(),
                "log_file": log_path.display().to_string(),
                "connect_requested": connect,
                "status": status,
            }))?;
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            anyhow::bail!(
                "tobrod did not become ready within {wait_secs}s (socket: {}); \
                 run `tobroctl start --foreground` for the daemon output",
                socket.display()
            );
        }
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    }
}

/// Find the `tobrod` binary next to the running `tobroctl` binary.
fn locate_daemon_binary() -> anyhow::Result<PathBuf> {
    let exe = std::env::current_exe().context("could not locate the tobroctl binary")?;
    let dir = exe
        .parent()
        .context("could not locate the tobroctl binary directory")?;
    let name = if cfg!(windows) {
        "tobrod.exe"
    } else {
        "tobrod"
    };
    let candidate = dir.join(name);
    if candidate.exists() {
        return Ok(candidate);
    }
    anyhow::bail!(
        "could not find the tobrod daemon binary next to tobroctl (expected {}); \
         build it with `cargo build -p tobrod` and pass --daemon PATH",
        candidate.display()
    )
}

/// Result wrapper for optional diagnostics sections: a failing section degrades
/// to `{"ok": false, "error": ...}` instead of failing the whole export.
async fn fetch_section(
    client: &mut tobro_ipc::Client,
    method: &str,
    params: Option<Value>,
) -> Value {
    match client.call(method, params).await {
        Ok(value) => json!({ "ok": true, "data": value }),
        Err(error) => json!({ "ok": false, "error": error.to_string() }),
    }
}

async fn diagnostics_export(
    client: &mut tobro_ipc::Client,
    out: Option<PathBuf>,
    lines: u64,
) -> anyhow::Result<()> {
    let hello = match client.handshake().await {
        Ok(hello) => serde_json::to_value(hello)?,
        Err(error) => Value::String(format!("handshake failed: {error}")),
    };
    let status = fetch_section(client, tobro_ipc::methods::STATUS, None).await;
    let config = fetch_section(client, tobro_ipc::methods::CONFIG_GET, None).await;
    let onion = fetch_section(client, tobro_ipc::methods::ONION_LIST, None).await;
    let kindness = fetch_section(client, tobro_ipc::methods::KINDNESS_STATUS, None).await;
    let client_auth = fetch_section(client, tobro_ipc::methods::CLIENT_AUTH_LIST, None).await;
    let logs = fetch_section(
        client,
        tobro_ipc::methods::LOGS,
        Some(json!({ "lines": lines })),
    )
    .await;

    let generated_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let bundle = json!({
        "format": "tobro-diagnostics",
        "version": 1,
        "generated_at": generated_at,
        "tool": { "name": "tobroctl", "version": env!("CARGO_PKG_VERSION") },
        "daemon": { "hello": hello, "status": status },
        "config": config,
        "onion": onion,
        "kindness": kindness,
        "client_auth": client_auth,
        "logs": logs,
        "notes": [
            "config is the daemon's redacted view: outbound proxy secrets are removed",
            "log lines are redacted at capture time (bridge material, credentials, client-auth keys)",
            "hosted .onion addresses are public by design and included; review before sharing",
            "no private keys, passwords, or .auth_private key material are ever included",
        ],
    });

    match out {
        Some(path) => {
            let bytes = serde_json::to_vec_pretty(&bundle)?;
            write_bundle_file(&path, &bytes)?;
            let sections = json!({
                "daemon.status": status.get("ok").and_then(Value::as_bool),
                "config": config.get("ok").and_then(Value::as_bool),
                "onion": onion.get("ok").and_then(Value::as_bool),
                "kindness": kindness.get("ok").and_then(Value::as_bool),
                "client_auth": client_auth.get("ok").and_then(Value::as_bool),
                "logs": logs.get("ok").and_then(Value::as_bool),
            });
            print_json(&json!({
                "ok": true,
                "action": "diagnostics.export",
                "written": path.display().to_string(),
                "bytes": bytes.len(),
                "sections": sections,
                "note": "no secrets are included; review the file before sharing it",
            }))?;
        }
        None => print_json(&bundle)?,
    }
    Ok(())
}

fn default_socket() -> anyhow::Result<PathBuf> {
    let project = ProjectDirs::from("", "", "tobro")
        .context("could not determine the platform data directory")?;
    Ok(tobro_ipc::socket_path(&project.data_dir().join("state")))
}
