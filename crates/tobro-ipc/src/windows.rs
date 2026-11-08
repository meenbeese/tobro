//! Windows named-pipe transport for the local JSON-RPC protocol.
//!
//! The pipe name is derived from the same state path used on Unix, so
//! `tobrod` and `tobroctl` agree without a separate discovery file. The pipe
//! is created with the process default security descriptor, which grants the
//! creating user (plus SYSTEM/Administrators); a stricter ACL and peer
//! verification are M1 hardening items.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};

use futures::{SinkExt, StreamExt};
use serde_json::Value;
use tokio::net::windows::named_pipe::{
    ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions,
};
use tokio_util::codec::Framed;

use crate::{Hello, IpcError, JsonRpcCodec, Message, RPC_VERSION, RequestId, RpcRequest, methods};

/// A framed JSON-RPC connection on the server side.
pub type Connection = Framed<NamedPipeServer, JsonRpcCodec>;

/// Client side of the daemon pipe.
pub struct Client {
    framed: Framed<NamedPipeClient, JsonRpcCodec>,
    next_id: u64,
    pending: VecDeque<Message>,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client").finish_non_exhaustive()
    }
}

impl Client {
    /// Open the daemon pipe.
    ///
    /// The pipe only exists while `tobrod` runs; opening a missing pipe
    /// reads as "file not found" to the OS, which gets a clearer message.
    pub async fn connect(path: impl AsRef<Path>) -> Result<Self, IpcError> {
        let name = pipe_name(path.as_ref());
        let client = match ClientOptions::new().open(&name) {
            Ok(client) => client,
            // ERROR_FILE_NOT_FOUND (os error 2): no pipe instance exists.
            Err(error) if error.raw_os_error() == Some(2) => {
                return Err(IpcError::Protocol(format!(
                    "no daemon is listening on {name}: is tobrod running?"
                )));
            }
            Err(error) => return Err(error.into()),
        };
        Ok(Self {
            framed: Framed::new(client, JsonRpcCodec::new()),
            next_id: 0,
            pending: VecDeque::new(),
        })
    }

    /// Perform the `daemon.hello` handshake and check the RPC version.
    pub async fn handshake(&mut self) -> Result<Hello, IpcError> {
        let value = self.call(methods::HELLO, None).await?;
        let hello: Hello = serde_json::from_value(value)?;
        if hello.rpc_version != RPC_VERSION {
            return Err(IpcError::Protocol(format!(
                "daemon speaks RPC version {}, this client speaks {RPC_VERSION}",
                hello.rpc_version
            )));
        }
        Ok(hello)
    }

    /// Call `method` and wait for its response.
    pub async fn call(&mut self, method: &str, params: Option<Value>) -> Result<Value, IpcError> {
        self.next_id = self.next_id.wrapping_add(1);
        let id = RequestId::Number(self.next_id);
        let request = RpcRequest::new(id.clone(), method).with_params(params);
        self.framed.send(Message::Request(request)).await?;

        // Read from the wire rather than `next_message`, so a notification
        // that arrives while waiting is queued once instead of looping.
        loop {
            match self.framed.next().await {
                Some(Ok(Message::Response(response))) if response.id == id => {
                    return Ok(response.into_result()?);
                }
                Some(Ok(other)) => self.pending.push_back(other),
                Some(Err(error)) => return Err(error),
                None => return Err(IpcError::Closed),
            }
        }
    }

    /// Read the next message, draining any queued notifications first.
    pub async fn next_message(&mut self) -> Result<Option<Message>, IpcError> {
        if let Some(message) = self.pending.pop_front() {
            return Ok(Some(message));
        }
        match self.framed.next().await {
            Some(Ok(message)) => Ok(Some(message)),
            Some(Err(error)) => Err(error),
            None => Ok(None),
        }
    }

    /// Read the next notification, skipping anything else.
    pub async fn next_notification(&mut self) -> Result<Option<crate::RpcNotification>, IpcError> {
        loop {
            match self.next_message().await? {
                Some(Message::Notification(notification)) => return Ok(Some(notification)),
                Some(_) => {}
                None => return Ok(None),
            }
        }
    }
}

/// Server side of the daemon pipe.
pub struct Server {
    name: String,
    path: PathBuf,
    next: NamedPipeServer,
}

impl std::fmt::Debug for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Server")
            .field("name", &self.name)
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl Server {
    /// Create the first pipe instance.
    ///
    /// Unlike Unix sockets there is no file to clean up; the pipe disappears
    /// when its last instance is closed. A live daemon makes this fail.
    pub async fn bind(path: impl AsRef<Path>) -> Result<Self, IpcError> {
        let path = path.as_ref().to_path_buf();
        let name = pipe_name(&path);
        let next = create_instance(&name, true)?;
        Ok(Self { name, path, next })
    }

    /// Accept one connection and create the next pipe instance.
    pub async fn accept(&mut self) -> Result<Connection, IpcError> {
        self.next.connect().await?;
        let connected = std::mem::replace(&mut self.next, create_instance(&self.name, false)?);
        Ok(Framed::new(connected, JsonRpcCodec::new()))
    }

    /// State path this server was configured with.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

fn create_instance(name: &str, first: bool) -> Result<NamedPipeServer, IpcError> {
    ServerOptions::new()
        .first_pipe_instance(first)
        .create(name)
        .map_err(|error| IpcError::Protocol(format!("could not create named pipe {name}: {error}")))
}

/// Stable, user-specific pipe name derived from the state path.
fn pipe_name(path: &Path) -> String {
    // FNV-1a keeps the name deterministic across processes and Rust versions.
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in path.as_os_str().to_string_lossy().as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("\\\\.\\pipe\\tobro-{hash:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RpcNotification, RpcResponse, methods};

    #[tokio::test]
    async fn client_and_server_exchange_messages() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("tobrod.pipe");
        let mut server = Server::bind(&path).await?;

        let client = async {
            let mut client = Client::connect(&path).await?;
            let value = client.call(methods::STATUS, None).await?;
            let notification = client.next_notification().await?;
            Ok::<_, IpcError>((value, notification))
        };

        let daemon = async {
            let mut connection = server.accept().await?;
            match connection.next().await {
                Some(Ok(Message::Request(request))) => {
                    connection
                        .send(Message::Notification(RpcNotification::new(
                            "test.event",
                            None,
                        )))
                        .await?;
                    let response =
                        RpcResponse::success(request.id, serde_json::json!({"ok": true}));
                    connection.send(Message::Response(response)).await?;
                    Ok::<_, IpcError>(())
                }
                _ => Err(IpcError::Closed),
            }
        };

        let (client, daemon) = tokio::join!(client, daemon);
        daemon?;
        let (value, notification) = client?;
        assert_eq!(value, serde_json::json!({"ok": true}));
        assert_eq!(
            notification.map(|n| n.method),
            Some("test.event".to_owned())
        );
        Ok(())
    }
}
