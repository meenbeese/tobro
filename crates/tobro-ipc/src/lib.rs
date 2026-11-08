//! Local JSON-RPC protocol shared by `tobrod`, the GUI, and `tobroctl`.
//!
//! # Wire format
//!
//! Every message is a 4-byte big-endian length followed by a UTF-8 JSON
//! document (JSON-RPC 2.0). Frames are capped at [`MAX_FRAME_LEN`].
//!
//! # Transport
//!
//! Unix domain socket on macOS/Linux, created with a `0600` socket in a
//! `0700` directory. Windows named pipes carry the same length-prefixed
//! JSON-RPC framing; the pipe name is derived from the socket path, so both
//! platforms share one endpoint convention.
//!
//! # M1/M2 surface
//!
//! Methods: `daemon.hello`, `daemon.status`, `daemon.connect`, `daemon.stop`,
//! `daemon.reload_config`, `daemon.new_identity`.
//! Notifications: `bootstrap.progress`, `daemon.state_changed`.
//! Servers enforce a method allowlist, version/hello preflight, explicit no-params
//! validation, peer-identity checks (platform-specific), and idle-connection timeouts.

use bytes::BytesMut;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio_util::codec::{Decoder, Encoder, LengthDelimitedCodec};

/// JSON-RPC protocol version carried in every envelope.
pub const JSONRPC_VERSION: &str = "2.0";

/// Version of the tobro RPC surface. Bumped on incompatible changes.
pub const RPC_VERSION: u32 = 1;

/// Largest accepted frame, in bytes.
pub const MAX_FRAME_LEN: usize = 1024 * 1024;

/// Standard JSON-RPC error codes.
pub mod codes {
    /// Invalid JSON.
    pub const PARSE_ERROR: i32 = -32700;
    /// Not a valid JSON-RPC request object.
    pub const INVALID_REQUEST: i32 = -32600;
    /// The method does not exist.
    pub const METHOD_NOT_FOUND: i32 = -32601;
    /// Parameters are wrong for the method.
    pub const INVALID_PARAMS: i32 = -32602;
    /// Unexpected daemon failure.
    pub const INTERNAL_ERROR: i32 = -32603;
    /// Handshake/version/authorization failure.
    pub const UNAUTHORIZED: i32 = -32001;
}

/// Method names used by the IPC surface.
pub mod methods {
    /// Handshake; returns [`Hello`].
    pub const HELLO: &str = "daemon.hello";
    /// Current daemon state; returns [`DaemonStatus`].
    pub const STATUS: &str = "daemon.status";
    /// Request that the daemon connect/start Tor.
    pub const CONNECT: &str = "daemon.connect";
    /// Request that the daemon stop/disconnect Tor.
    pub const STOP: &str = "daemon.stop";
    /// Reload and validate configuration from disk (apply semantics are method-specific).
    pub const RELOAD_CONFIG: &str = "daemon.reload_config";
    /// Request a new identity (restart Tor client/listeners for new circuits).
    pub const NEW_IDENTITY: &str = "daemon.new_identity";
    /// Get the current daemon configuration (redacted; no secrets).
    pub const CONFIG_GET: &str = "config.get";
    /// Validate a configuration patch without applying it.
    pub const CONFIG_VALIDATE: &str = "config.validate";
    /// Validate, persist, and apply a configuration patch.
    pub const CONFIG_APPLY: &str = "config.apply";

    /// Methods that may be called without a prior `daemon.hello` handshake.
    pub const PREFLIGHT: &[&str] = &[HELLO];
}

/// Returns true if `method` is in the supported method allowlist.
pub fn is_allowed_method(method: &str) -> bool {
    matches!(
        method,
        methods::HELLO
            | methods::STATUS
            | methods::CONNECT
            | methods::STOP
            | methods::RELOAD_CONFIG
            | methods::NEW_IDENTITY
            | methods::CONFIG_GET
            | methods::CONFIG_VALIDATE
            | methods::CONFIG_APPLY
    )
}

/// Validate JSON-RPC params for a method.
pub fn validate_params(method: &str, params: &Option<Value>) -> Result<(), RpcError> {
    match method {
        methods::HELLO
        | methods::STATUS
        | methods::CONNECT
        | methods::STOP
        | methods::RELOAD_CONFIG
        | methods::NEW_IDENTITY
        | methods::CONFIG_GET => validate_no_params(method, params),
        methods::CONFIG_VALIDATE | methods::CONFIG_APPLY => {
            let Some(Value::Object(map)) = params else {
                return Err(RpcError::invalid_params(
                    method,
                    "expected params object: {\"patch\": { ... }}",
                ));
            };
            match map.get("patch") {
                Some(Value::Object(_)) => Ok(()),
                Some(_) => Err(RpcError::invalid_params(
                    method,
                    "\"patch\" must be an object",
                )),
                None => Err(RpcError::invalid_params(
                    method,
                    "missing required \"patch\" object",
                )),
            }
        }
        _ => Ok(()),
    }
}

/// Validate that an M1/M2 method's params are absent/null/empty (no-params contract).
pub fn validate_no_params(method: &str, params: &Option<Value>) -> Result<(), RpcError> {
    let has_params = match params {
        None => false,
        Some(Value::Null) => false,
        Some(Value::Object(map)) => !map.is_empty(),
        Some(_) => true,
    };
    if has_params {
        return Err(RpcError::invalid_params(
            method,
            "this method takes no parameters",
        ));
    }
    Ok(())
}

/// Notification names used by the M0 IPC surface.
pub mod notifications {
    /// Bootstrap progress; payload is [`BootstrapProgress`].
    pub const BOOTSTRAP_PROGRESS: &str = "bootstrap.progress";
    /// State transition; payload is `{ "state": DaemonState }`.
    pub const STATE_CHANGED: &str = "daemon.state_changed";
}

/// Name of the IPC socket inside the daemon state directory.
pub const SOCKET_FILE_NAME: &str = "tobrod.sock";

/// Path of the IPC socket for a given state directory.
pub fn socket_path(state_dir: &std::path::Path) -> std::path::PathBuf {
    state_dir.join(SOCKET_FILE_NAME)
}

/// Errors produced by the IPC layer.
#[derive(Debug, thiserror::Error)]
pub enum IpcError {
    /// Socket or stream failure.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// Malformed JSON on the wire.
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// Well-formed JSON that is not a valid JSON-RPC message.
    #[error("protocol error: {0}")]
    Protocol(String),
    /// The daemon answered with a JSON-RPC error.
    #[error("daemon returned an error: {0}")]
    Rpc(#[from] RpcError),
    /// The peer closed the connection.
    #[error("connection closed")]
    Closed,
    /// This platform has no IPC transport yet.
    #[error("IPC over Unix sockets is not supported on this platform")]
    Unsupported,
}

/// JSON-RPC request identifier (number or string).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RequestId {
    /// Numeric id, as generated by [`Client`].
    Number(u64),
    /// String id, for clients that prefer names.
    String(String),
}

impl std::fmt::Display for RequestId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RequestId::Number(value) => write!(f, "{value}"),
            RequestId::String(value) => write!(f, "{value:?}"),
        }
    }
}

/// A JSON-RPC error object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[error("{message} (code {code})")]
pub struct RpcError {
    /// Numeric error code, see [`codes`].
    pub code: i32,
    /// Human-readable explanation.
    pub message: String,
    /// Optional structured detail.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl RpcError {
    /// Build an error with no structured data.
    pub fn new(code: i32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            data: None,
        }
    }

    /// `METHOD_NOT_FOUND` for `method`.
    pub fn method_not_found(method: &str) -> Self {
        Self::new(
            codes::METHOD_NOT_FOUND,
            format!("unknown method {method:?}"),
        )
    }

    /// `INVALID_PARAMS` for the given method.
    pub fn invalid_params(method: &str, detail: impl std::fmt::Display) -> Self {
        Self::new(
            codes::INVALID_PARAMS,
            format!("invalid parameters for {method:?}: {detail}"),
        )
    }

    /// `INTERNAL_ERROR`.
    pub fn internal(detail: impl Into<String>) -> Self {
        Self::new(codes::INTERNAL_ERROR, detail)
    }

    /// Authorization/handshake failure.
    pub fn unauthorized(detail: impl Into<String>) -> Self {
        Self::new(codes::UNAUTHORIZED, detail)
    }
}

/// A JSON-RPC request (expects a response with the same id).
#[derive(Debug, Clone, PartialEq)]
pub struct RpcRequest {
    /// Request identifier.
    pub id: RequestId,
    /// Method name.
    pub method: String,
    /// Optional parameters.
    pub params: Option<Value>,
}

impl RpcRequest {
    /// Build a request with no parameters.
    pub fn new(id: RequestId, method: impl Into<String>) -> Self {
        Self {
            id,
            method: method.into(),
            params: None,
        }
    }

    /// Attach parameters.
    #[must_use]
    pub fn with_params(mut self, params: Option<Value>) -> Self {
        self.params = params;
        self
    }
}

/// A JSON-RPC notification (no id, no response).
#[derive(Debug, Clone, PartialEq)]
pub struct RpcNotification {
    /// Notification name.
    pub method: String,
    /// Optional payload.
    pub params: Option<Value>,
}

impl RpcNotification {
    /// Build a notification.
    pub fn new(method: impl Into<String>, params: Option<Value>) -> Self {
        Self {
            method: method.into(),
            params,
        }
    }
}

/// A JSON-RPC response.
#[derive(Debug, Clone, PartialEq)]
pub struct RpcResponse {
    /// Id of the request being answered.
    pub id: RequestId,
    /// Successful result, if any.
    pub result: Option<Value>,
    /// Error, if the call failed.
    pub error: Option<RpcError>,
}

impl RpcResponse {
    /// Successful response carrying `result`.
    pub fn success(id: RequestId, result: Value) -> Self {
        Self {
            id,
            result: Some(result),
            error: None,
        }
    }

    /// Error response.
    pub fn error(id: RequestId, error: RpcError) -> Self {
        Self {
            id,
            result: None,
            error: Some(error),
        }
    }

    /// Convert into the call result.
    pub fn into_result(self) -> Result<Value, RpcError> {
        match (self.result, self.error) {
            (_, Some(error)) => Err(error),
            (Some(result), None) => Ok(result),
            (None, None) => Ok(Value::Null),
        }
    }
}

/// Any JSON-RPC message.
#[derive(Debug, Clone, PartialEq)]
pub enum Message {
    /// A request expecting a response.
    Request(RpcRequest),
    /// A one-way notification.
    Notification(RpcNotification),
    /// A response to a previous request.
    Response(RpcResponse),
}

#[derive(Serialize)]
struct WireRequest<'a> {
    jsonrpc: &'static str,
    id: &'a RequestId,
    method: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    params: Option<&'a Value>,
}

#[derive(Serialize)]
struct WireNotification<'a> {
    jsonrpc: &'static str,
    method: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    params: Option<&'a Value>,
}

#[derive(Serialize)]
struct WireResponse<'a> {
    jsonrpc: &'static str,
    id: &'a RequestId,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<&'a Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'a RpcError>,
}

impl Serialize for Message {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Message::Request(request) => WireRequest {
                jsonrpc: JSONRPC_VERSION,
                id: &request.id,
                method: &request.method,
                params: request.params.as_ref(),
            }
            .serialize(serializer),
            Message::Notification(notification) => WireNotification {
                jsonrpc: JSONRPC_VERSION,
                method: &notification.method,
                params: notification.params.as_ref(),
            }
            .serialize(serializer),
            Message::Response(response) => WireResponse {
                jsonrpc: JSONRPC_VERSION,
                id: &response.id,
                result: response.result.as_ref(),
                error: response.error.as_ref(),
            }
            .serialize(serializer),
        }
    }
}

#[derive(Deserialize)]
struct WireMessage {
    #[serde(default)]
    jsonrpc: Option<String>,
    #[serde(default)]
    id: Option<RequestId>,
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    params: Option<Value>,
    // `null` and an absent result both become `None`; see `classify`.
    #[serde(default)]
    result: Option<Value>,
    #[serde(default)]
    error: Option<RpcError>,
}

impl<'de> Deserialize<'de> for Message {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = WireMessage::deserialize(deserializer)?;
        classify(wire).map_err(serde::de::Error::custom)
    }
}

fn classify(wire: WireMessage) -> Result<Message, &'static str> {
    if wire.jsonrpc.as_deref() != Some(JSONRPC_VERSION) {
        return Err("missing or unsupported jsonrpc version");
    }

    match (wire.method, wire.id) {
        (Some(method), Some(id)) => {
            if wire.result.is_some() || wire.error.is_some() {
                return Err("request must not carry result or error");
            }
            Ok(Message::Request(RpcRequest {
                id,
                method,
                params: wire.params,
            }))
        }
        (Some(method), None) => {
            if wire.result.is_some() || wire.error.is_some() {
                return Err("notification must not carry result or error");
            }
            Ok(Message::Notification(RpcNotification {
                method,
                params: wire.params,
            }))
        }
        (None, Some(id)) => match (wire.result, wire.error) {
            (Some(result), None) => Ok(Message::Response(RpcResponse {
                id,
                result: Some(result),
                error: None,
            })),
            // A JSON `null` result is indistinguishable from an absent one
            // once deserialized into `Option<Value>`; both mean null success.
            (None, None) => Ok(Message::Response(RpcResponse {
                id,
                result: Some(Value::Null),
                error: None,
            })),
            (None, Some(error)) => Ok(Message::Response(RpcResponse {
                id,
                result: None,
                error: Some(error),
            })),
            _ => Err("response must not carry both result and error"),
        },
        (None, None) => Err("message has neither method nor id"),
    }
}

/// Length-delimited JSON codec used by both sides of the socket.
#[derive(Debug)]
pub struct JsonRpcCodec {
    inner: LengthDelimitedCodec,
}

impl JsonRpcCodec {
    /// Codec with the default 4-byte big-endian length field.
    pub fn new() -> Self {
        let mut inner = LengthDelimitedCodec::new();
        inner.set_max_frame_length(MAX_FRAME_LEN);
        Self { inner }
    }
}

impl Default for JsonRpcCodec {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder for JsonRpcCodec {
    type Item = Message;
    type Error = IpcError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let Some(frame) = self.inner.decode(src)? else {
            return Ok(None);
        };
        Ok(Some(serde_json::from_slice(&frame)?))
    }
}

impl Encoder<Message> for JsonRpcCodec {
    type Error = IpcError;

    fn encode(&mut self, item: Message, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let data = serde_json::to_vec(&item)?;
        if data.len() > MAX_FRAME_LEN {
            return Err(IpcError::Protocol(format!(
                "frame is {} bytes, limit is {MAX_FRAME_LEN}",
                data.len()
            )));
        }
        self.inner.encode(bytes::Bytes::from(data), dst)?;
        Ok(())
    }
}

/// Daemon lifecycle states exposed over IPC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DaemonState {
    /// Process started, Tor not yet started.
    Starting,
    /// Arti is bootstrapping.
    Bootstrapping,
    /// Arti is usable / listeners serving.
    Connected,
    /// Listeners are running.
    Serving,
    /// Stopping/disconnecting.
    Stopping,
    /// Cleanly stopped.
    Stopped,
    /// Failed; see the daemon logs.
    Error,
}

/// Bootstrap progress shown to clients.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootstrapProgress {
    /// Rough progress, 0-100.
    pub percent: u8,
    /// True once Tor can carry traffic.
    pub ready: bool,
    /// Arti's explanation when it believes it is stuck.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocked: Option<String>,
    /// Human-readable status detail.
    pub detail: String,
}

impl Default for BootstrapProgress {
    fn default() -> Self {
        Self {
            percent: 0,
            ready: false,
            blocked: None,
            detail: "not started".to_owned(),
        }
    }
}

/// Snapshot returned by `daemon.status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaemonStatus {
    /// Current lifecycle state.
    pub state: DaemonState,
    /// Latest bootstrap progress.
    pub bootstrap: BootstrapProgress,
    /// Local SOCKS port (combined SOCKS/HTTP listener in current builds).
    pub socks_port: u16,
    /// Local HTTP CONNECT port (same as `socks_port` while listeners are combined).
    pub http_port: u16,
    /// Local DNS port.
    pub dns_port: u16,
    /// Whether listeners bind all interfaces instead of loopback only (opt-in).
    #[serde(default)]
    pub bind_all_interfaces: bool,
    /// Daemon process id.
    pub pid: u32,
    /// Time since the daemon started.
    pub uptime_ms: u64,
}

/// Reply to `daemon.hello`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    /// `tobrod` package version.
    pub daemon_version: String,
    /// RPC surface version, see [`RPC_VERSION`].
    pub rpc_version: u32,
    /// Operating system name.
    pub platform: String,
    /// Arti release the daemon was built against.
    pub arti_version: String,
    /// Daemon process id.
    pub pid: u32,
}

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::{Client, Connection, Server};

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::{Client, Connection, Server};

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_util::codec::{Decoder, Encoder};

    fn round_trip(message: Message) {
        let mut codec = JsonRpcCodec::new();
        let mut buffer = BytesMut::new();
        assert!(codec.encode(message.clone(), &mut buffer).is_ok());
        assert_eq!(codec.decode(&mut buffer).ok().flatten(), Some(message));
    }

    #[test]
    fn codec_round_trips_request() {
        round_trip(Message::Request(
            RpcRequest::new(RequestId::Number(7), methods::STATUS)
                .with_params(Some(serde_json::json!({"redact": true}))),
        ));
    }

    #[test]
    fn codec_round_trips_notification() {
        round_trip(Message::Notification(RpcNotification::new(
            notifications::BOOTSTRAP_PROGRESS,
            Some(serde_json::json!({"percent": 42})),
        )));
    }

    #[test]
    fn codec_round_trips_null_result() {
        round_trip(Message::Response(RpcResponse::success(
            RequestId::String("abc".to_owned()),
            Value::Null,
        )));
    }

    #[test]
    fn rejects_message_without_jsonrpc() {
        assert!(serde_json::from_str::<Message>(r#"{"method":"daemon.status"}"#).is_err());
    }

    #[test]
    fn rejects_response_with_result_and_error() {
        let raw = r#"{"jsonrpc":"2.0","id":1,"result":{},"error":{"code":1,"message":"x"}}"#;
        assert!(serde_json::from_str::<Message>(raw).is_err());
    }

    #[test]
    fn parses_error_response() {
        let raw = r#"{"jsonrpc":"2.0","id":3,"error":{"code":-32601,"message":"nope"}}"#;
        match serde_json::from_str::<Message>(raw) {
            Ok(Message::Response(response)) => {
                assert_eq!(response.into_result(), Err(RpcError::new(-32601, "nope")));
            }
            other => assert!(other.is_err(), "expected a response, got {other:?}"),
        }
    }
}
