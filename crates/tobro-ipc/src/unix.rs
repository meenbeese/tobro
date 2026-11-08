//! Unix-domain-socket transport for the local JSON-RPC protocol.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};

use futures::{SinkExt, StreamExt};
use serde_json::Value;
use tokio::net::{UnixListener, UnixStream};
use tokio_util::codec::Framed;

use crate::{Hello, IpcError, JsonRpcCodec, Message, RPC_VERSION, RequestId, RpcRequest, methods};

/// A framed JSON-RPC connection over a Unix socket.
pub type Connection = Framed<UnixStream, JsonRpcCodec>;

#[cfg(target_os = "macos")]
const MAX_SOCKET_PATH: usize = 103;
#[cfg(not(target_os = "macos"))]
const MAX_SOCKET_PATH: usize = 107;

/// Client side of the daemon socket.
#[derive(Debug)]
pub struct Client {
    framed: Connection,
    next_id: u64,
    pending: VecDeque<Message>,
}

impl Client {
    /// Connect to a daemon socket.
    pub async fn connect(path: impl AsRef<Path>) -> Result<Self, IpcError> {
        let path = path.as_ref();
        check_path_len(path)?;
        let stream = UnixStream::connect(path).await?;
        Ok(Self {
            framed: Framed::new(stream, JsonRpcCodec::new()),
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
    ///
    /// Notifications received while waiting are queued and returned by
    /// [`Client::next_message`] or [`Client::next_notification`].
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

/// Server side of the daemon socket.
#[derive(Debug)]
pub struct Server {
    listener: UnixListener,
    path: PathBuf,
}

impl Server {
    /// Bind the socket, creating its parent directory with `0700` permissions.
    ///
    /// A stale socket is replaced; a live one is an error.
    pub async fn bind(path: impl AsRef<Path>) -> Result<Self, IpcError> {
        let path = path.as_ref().to_path_buf();
        check_path_len(&path)?;

        if let Some(parent) = path.parent() {
            create_private_dir(parent)?;
        }

        if path.exists() {
            if UnixStream::connect(&path).await.is_ok() {
                return Err(IpcError::Protocol(format!(
                    "another daemon is already listening on {}",
                    path.display()
                )));
            }
            std::fs::remove_file(&path)?;
        }

        let listener = UnixListener::bind(&path)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }

        Ok(Self { listener, path })
    }

    /// Accept one connection.
    ///
    /// Takes `&mut self` to match the named-pipe transport, where accepting
    /// replaces the pending pipe instance.
    pub async fn accept(&mut self) -> Result<Connection, IpcError> {
        let (stream, _address) = self.listener.accept().await?;
        Ok(Framed::new(stream, JsonRpcCodec::new()))
    }

    /// Socket path this server is bound to.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn check_path_len(path: &Path) -> Result<(), IpcError> {
    use std::os::unix::ffi::OsStrExt as _;

    let len = path.as_os_str().as_bytes().len();
    if len > MAX_SOCKET_PATH {
        return Err(IpcError::Protocol(format!(
            "socket path is {len} bytes, this platform allows {MAX_SOCKET_PATH}: {}",
            path.display()
        )));
    }
    Ok(())
}

fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
    if dir.exists() {
        // Tighten existing directories: Arti/fs-mistrust rejects group/other access.
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        return Ok(());
    }
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RpcNotification, RpcResponse, methods};

    #[tokio::test]
    async fn client_and_server_exchange_messages() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("tobrod.sock");
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
                    // Send a notification before the response; the client must
                    // queue it rather than loop or drop it.
                    let notification = RpcNotification::new("test.event", None);
                    connection.send(Message::Notification(notification)).await?;
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

    #[tokio::test]
    async fn refuses_to_bind_over_a_live_socket() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("tobrod.sock");
        let _server = Server::bind(&path).await?;
        assert!(Server::bind(&path).await.is_err());
        Ok(())
    }
}
