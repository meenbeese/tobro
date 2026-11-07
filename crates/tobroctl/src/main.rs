//! `tobroctl` — command-line client for `tobrod`.
//!
//! M0: `status` and `watch` over the Unix-socket JSON-RPC endpoint.

use std::path::PathBuf;

#[cfg(unix)]
use anyhow::Context as _;
use clap::{Parser, Subcommand};
#[cfg(unix)]
use directories::ProjectDirs;

#[derive(Debug, Parser)]
#[command(name = "tobroctl", version, about = "Control the tobro daemon")]
struct Cli {
    /// IPC socket path (defaults to the platform state directory).
    #[arg(long, global = true, value_name = "PATH")]
    socket: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Print the daemon status as JSON.
    Status,
    /// Stream IPC notifications as JSON lines until Ctrl-C.
    Watch,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    #[cfg(unix)]
    {
        run(cli).await
    }

    #[cfg(not(unix))]
    {
        let _ = cli;
        anyhow::bail!(
            "tobroctl currently needs the Unix-socket IPC transport, which is not available on this platform"
        )
    }
}

#[cfg(unix)]
async fn run(cli: Cli) -> anyhow::Result<()> {
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
            println!("{}", serde_json::to_string_pretty(&status)?);
        }
        Command::Watch => watch(&mut client).await?,
    }

    Ok(())
}

#[cfg(unix)]
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

#[cfg(unix)]
fn default_socket() -> anyhow::Result<PathBuf> {
    let project = ProjectDirs::from("", "", "tobro")
        .context("could not determine the platform data directory")?;
    Ok(tobro_ipc::socket_path(&project.data_dir().join("state")))
}
