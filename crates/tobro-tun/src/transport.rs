//! Local IPC transport for the helper protocol.
//!
//! Unix domain socket on macOS/Linux (created `0600`), Windows named pipe.
//! Both carry the same length-prefixed [`HelperMessage`] framing. This
//! module owns the *client-side* connection primitive; the listening side
//! lives in the helper binary (the [`crate::mock`] module is the prototype).
//!
//! Windows ACL hardening (restricting the pipe DACL) lands with the Windows
//! service install step (M7 T4c); the default DACL is used until then.

use tokio_util::codec::Framed;

use crate::{HelperCodec, HelperError};

/// A framed helper connection (client side).
#[cfg(unix)]
pub type HelperStream = Framed<tokio::net::UnixStream, HelperCodec>;
#[cfg(windows)]
pub type HelperStream = Framed<tokio::net::windows::named_pipe::NamedPipeClient, HelperCodec>;

/// Default helper IPC endpoint for this platform.
pub fn default_endpoint() -> &'static str {
    #[cfg(unix)]
    {
        "/var/run/tobro-helper.sock"
    }
    #[cfg(windows)]
    {
        r"\\.\pipe\tobro-helper"
    }
}

/// Connect a framed helper stream to `path`.
#[cfg(unix)]
pub async fn open_stream(path: &std::path::Path) -> Result<HelperStream, HelperError> {
    let stream = tokio::net::UnixStream::connect(path).await?;
    Ok(Framed::new(stream, HelperCodec::new()))
}

#[cfg(windows)]
pub async fn open_stream(path: &std::path::Path) -> Result<HelperStream, HelperError> {
    use tokio::net::windows::named_pipe::ClientOptions;
    let client = ClientOptions::new().open(path)?;
    Ok(Framed::new(client, HelperCodec::new()))
}

/// Bind a helper listener at `path`. Returns the platform listener; the
/// caller drives its accept loop.
#[cfg(unix)]
pub async fn bind_listener(
    path: &std::path::Path,
) -> Result<tokio::net::UnixListener, HelperError> {
    // Replace a stale socket from a crashed helper; a live one is an error.
    if path.exists() && tokio::net::UnixStream::connect(path).await.is_ok() {
        return Err(HelperError::Protocol(format!(
            "another helper is already listening on {}",
            path.display()
        )));
    }
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    let listener = tokio::net::UnixListener::bind(path)?;
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(listener)
}

#[cfg(windows)]
pub async fn bind_listener(
    path: &std::path::Path,
) -> Result<tokio::net::windows::named_pipe::NamedPipeServer, HelperError> {
    use tokio::net::windows::named_pipe::ServerOptions;
    // One pending pipe instance at a time; the accept loop re-opens after
    // each served client.
    let mut options = ServerOptions::new();
    options.first_pipe_instance(true);
    Ok(options.create(path)?)
}
