//! `tobroctl` — command-line client for `tobrod`.

use std::path::PathBuf;

use anyhow::Context as _;
use clap::{Parser, Subcommand};
use directories::ProjectDirs;
use serde_json::Value;

#[derive(Debug, Parser)]
#[command(name = "tobroctl", version, about = "Control the tobro daemon")]
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
    /// Stream IPC notifications as JSON lines until Ctrl-C.
    Watch,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let socket = match cli.socket {
        Some(path) => path,
        None => default_socket()?,
    };

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

fn default_socket() -> anyhow::Result<PathBuf> {
    let project = ProjectDirs::from("", "", "tobro")
        .context("could not determine the platform data directory")?;
    Ok(tobro_ipc::socket_path(&project.data_dir().join("state")))
}
