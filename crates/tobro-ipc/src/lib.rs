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
//! `daemon.reload_config`, `daemon.new_identity`, `daemon.logs`,
//! `daemon.shutdown`.
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
    /// Fetch recent daemon log lines from the in-memory ring buffer:
    /// optional params `{"lines": <1..=10000>}`. Lines are redacted at capture.
    pub const LOGS: &str = "daemon.logs";
    /// Ask the daemon to shut down cleanly (same as SIGINT to the process).
    /// No params; the response is sent before the daemon exits.
    pub const SHUTDOWN: &str = "daemon.shutdown";
    /// Get the current daemon configuration (redacted; no secrets).
    pub const CONFIG_GET: &str = "config.get";
    /// Validate a configuration patch without applying it.
    pub const CONFIG_VALIDATE: &str = "config.validate";
    /// Validate, persist, and apply a configuration patch.
    pub const CONFIG_APPLY: &str = "config.apply";
    /// Test a bridge/pluggable transport line and return diagnostics (no bridge material leaked).
    pub const BRIDGES_TEST: &str = "bridges.test";

    /// Store an outbound proxy secret in the OS keychain (`outbound_proxy.set_password`):
    /// `{"kind": "proxy"|"shadowsocks", "password": "..."}`. Also flips the
    /// config to keychain mode; the config file never receives the secret.
    pub const OUTBOUND_PROXY_SET_PASSWORD: &str = "outbound_proxy.set_password";
    /// Remove an outbound proxy secret from the OS keychain. Disables keychain
    /// mode when no keychain secret remains.
    pub const OUTBOUND_PROXY_CLEAR_PASSWORD: &str = "outbound_proxy.clear_password";

    /// Kindness Mode sidecar state + `[kindness]` config summary (no params,
    /// no secrets).
    pub const KINDNESS_STATUS: &str = "kindness.status";
    /// Run the Kindness eligibility report (STUN NAT detection, UPnP gateway
    /// discovery/mapping, broker reachability). Network-touching; may take
    /// seconds. No params.
    pub const KINDNESS_CHECK: &str = "kindness.check";
    /// Clear the stored Kindness served counters (weekly/all-time) and the
    /// volatile current-connections count. No params, no secrets.
    pub const KINDNESS_RESET_STATS: &str = "kindness.reset_stats";

    /// TUN mode and privileged-helper status (no params, no secrets).
    pub const TUN_STATUS: &str = "tun.status";

    /// List hosted onion services.
    pub const ONION_LIST: &str = "onion.list";
    /// Create a hosted onion service.
    pub const ONION_CREATE: &str = "onion.create";
    /// Update a hosted onion service (name, ports, enabled).
    pub const ONION_UPDATE: &str = "onion.update";
    /// Delete a hosted onion service.
    pub const ONION_DELETE: &str = "onion.delete";

    /// Create an encrypted backup bundle of onion services + client auth.
    pub const ONION_BACKUP: &str = "onion.backup";

    /// Restore an encrypted backup bundle produced by `onion.backup`.
    pub const ONION_RESTORE: &str = "onion.restore";

    /// List client authorization credentials.
    pub const CLIENT_AUTH_LIST: &str = "client_auth.list";
    /// Generate a client authorization credential/keypair.
    pub const CLIENT_AUTH_GENERATE: &str = "client_auth.generate";
    /// Import a `.auth_private` client authorization credential.
    pub const CLIENT_AUTH_IMPORT: &str = "client_auth.import";
    /// Export a `.auth_private` client authorization credential.
    pub const CLIENT_AUTH_EXPORT: &str = "client_auth.export";
    /// Delete a client authorization credential.
    pub const CLIENT_AUTH_DELETE: &str = "client_auth.delete";
    /// Attach a client authorization credential to an onion service.
    pub const CLIENT_AUTH_ATTACH: &str = "client_auth.attach";
    /// Detach a client authorization credential from an onion service.
    pub const CLIENT_AUTH_DETACH: &str = "client_auth.detach";

    /// Methods that may be called without a prior `daemon.hello` handshake.
    pub const PREFLIGHT: &[&str] = &[HELLO];
}

/// Largest `lines` count accepted by `daemon.logs`.
pub const MAX_LOG_LINES_REQUEST: u64 = 10_000;

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
            | methods::LOGS
            | methods::SHUTDOWN
            | methods::CONFIG_GET
            | methods::CONFIG_VALIDATE
            | methods::CONFIG_APPLY
            | methods::BRIDGES_TEST
            | methods::OUTBOUND_PROXY_SET_PASSWORD
            | methods::OUTBOUND_PROXY_CLEAR_PASSWORD
            | methods::KINDNESS_STATUS
            | methods::KINDNESS_CHECK
            | methods::KINDNESS_RESET_STATS
            | methods::TUN_STATUS
            | methods::ONION_LIST
            | methods::ONION_CREATE
            | methods::ONION_UPDATE
            | methods::ONION_DELETE
            | methods::ONION_BACKUP
            | methods::ONION_RESTORE
            | methods::CLIENT_AUTH_LIST
            | methods::CLIENT_AUTH_GENERATE
            | methods::CLIENT_AUTH_IMPORT
            | methods::CLIENT_AUTH_EXPORT
            | methods::CLIENT_AUTH_DELETE
            | methods::CLIENT_AUTH_ATTACH
            | methods::CLIENT_AUTH_DETACH
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
        | methods::SHUTDOWN
        | methods::CONFIG_GET
        | methods::KINDNESS_STATUS
        | methods::KINDNESS_CHECK
        | methods::KINDNESS_RESET_STATS
        | methods::TUN_STATUS
        | methods::ONION_LIST
        | methods::CLIENT_AUTH_LIST => validate_no_params(method, params),
        methods::LOGS => {
            if params.is_none() || matches!(params, Some(Value::Null)) {
                return Ok(());
            }
            let Some(Value::Object(map)) = params else {
                return Err(RpcError::invalid_params(
                    method,
                    "expected optional params object: {\"lines\": <1..=10000>}",
                ));
            };
            if let Some(lines) = map.get("lines") {
                let Some(count) = lines.as_u64() else {
                    return Err(RpcError::invalid_params(
                        method,
                        "\"lines\" must be a positive integer",
                    ));
                };
                if !(1..=MAX_LOG_LINES_REQUEST).contains(&count) {
                    return Err(RpcError::invalid_params(
                        method,
                        format!("\"lines\" must be between 1 and {MAX_LOG_LINES_REQUEST}"),
                    ));
                }
            }
            if let Some(key) = map.keys().find(|k| k.as_str() != "lines") {
                return Err(RpcError::invalid_params(
                    method,
                    format!("unknown parameter {key:?}; only \"lines\" is supported"),
                ));
            }
            Ok(())
        }
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
        methods::OUTBOUND_PROXY_SET_PASSWORD => {
            let Some(Value::Object(map)) = params else {
                return Err(RpcError::invalid_params(
                    method,
                    "expected params object: {\"password\": \"...\", \"kind\": \"proxy\"|\"shadowsocks\"}",
                ));
            };
            if !matches!(map.get("password"), Some(Value::String(p)) if !p.is_empty()) {
                return Err(RpcError::invalid_params(
                    method,
                    "missing required \"password\" (non-empty string)",
                ));
            }
            validate_outbound_key_kind(method, map.get("kind"))?;
            Ok(())
        }
        methods::OUTBOUND_PROXY_CLEAR_PASSWORD => {
            if params.is_none() {
                return Ok(());
            }
            let Some(Value::Object(map)) = params else {
                return Err(RpcError::invalid_params(
                    method,
                    "expected optional params object: {\"kind\": \"proxy\"|\"shadowsocks\"}",
                ));
            };
            validate_outbound_key_kind(method, map.get("kind"))?;
            Ok(())
        }
        methods::BRIDGES_TEST => {
            let Some(Value::Object(map)) = params else {
                return Err(RpcError::invalid_params(
                    method,
                    "expected params object: {\"line\": \"...\"} (or {\"lines\": [...]})",
                ));
            };
            let has_line = matches!(map.get("line"), Some(Value::String(_)));
            let has_lines = match map.get("lines") {
                Some(Value::Array(arr)) => arr.iter().all(|v| v.is_string()),
                Some(_) => {
                    return Err(RpcError::invalid_params(
                        method,
                        "\"lines\" must be an array of strings",
                    ));
                }
                None => false,
            };
            if !has_line && !has_lines {
                return Err(RpcError::invalid_params(
                    method,
                    "missing required \"line\" (string) or \"lines\" (string array)",
                ));
            }
            Ok(())
        }
        methods::ONION_CREATE => {
            let Some(Value::Object(map)) = params else {
                return Err(RpcError::invalid_params(
                    method,
                    "expected params object: {\"name\": \"...\", \"ports\": [{\"virt_port\":80,\"target_port\":8080}]}",
                ));
            };
            if !matches!(map.get("name"), Some(Value::String(_))) {
                return Err(RpcError::invalid_params(
                    method,
                    "missing required \"name\" (string)",
                ));
            }
            if !matches!(map.get("ports"), Some(Value::Array(_))) {
                return Err(RpcError::invalid_params(
                    method,
                    "missing required \"ports\" (array)",
                ));
            }
            Ok(())
        }
        methods::ONION_UPDATE => {
            let Some(Value::Object(map)) = params else {
                return Err(RpcError::invalid_params(
                    method,
                    "expected params object: {\"id\": \"...\", ...}",
                ));
            };
            if !matches!(map.get("id"), Some(Value::String(_))) {
                return Err(RpcError::invalid_params(
                    method,
                    "missing required \"id\" (string)",
                ));
            }
            Ok(())
        }
        methods::ONION_DELETE => {
            let Some(Value::Object(map)) = params else {
                return Err(RpcError::invalid_params(
                    method,
                    "expected params object: {\"id\": \"...\"}",
                ));
            };
            if !matches!(map.get("id"), Some(Value::String(_))) {
                return Err(RpcError::invalid_params(
                    method,
                    "missing required \"id\" (string)",
                ));
            }
            Ok(())
        }
        methods::CLIENT_AUTH_GENERATE => {
            if let Some(Value::Object(_)) = params {
                return Ok(());
            }
            if params.is_none() {
                return Ok(());
            }
            Err(RpcError::invalid_params(
                method,
                "expected optional params object: {\"nickname\"?: \"...\"}",
            ))
        }
        methods::CLIENT_AUTH_IMPORT => {
            let Some(Value::Object(map)) = params else {
                return Err(RpcError::invalid_params(
                    method,
                    "expected params object: {\"nickname\": \"...\", \"content\": \"...\"}",
                ));
            };
            if !matches!(map.get("nickname"), Some(Value::String(_))) {
                return Err(RpcError::invalid_params(
                    method,
                    "missing required \"nickname\" (string)",
                ));
            }
            if !matches!(map.get("content"), Some(Value::String(_))) {
                return Err(RpcError::invalid_params(
                    method,
                    "missing required \"content\" (string, .auth_private file contents)",
                ));
            }
            Ok(())
        }
        methods::CLIENT_AUTH_EXPORT => {
            let Some(Value::Object(map)) = params else {
                return Err(RpcError::invalid_params(
                    method,
                    "expected params object: {\"id\": \"...\", \"onion_address\"?: \"...\"}",
                ));
            };
            if !matches!(map.get("id"), Some(Value::String(_))) {
                return Err(RpcError::invalid_params(
                    method,
                    "missing required \"id\" (string)",
                ));
            }
            Ok(())
        }
        methods::CLIENT_AUTH_DELETE => {
            let Some(Value::Object(map)) = params else {
                return Err(RpcError::invalid_params(
                    method,
                    "expected params object: {\"id\": \"...\"}",
                ));
            };
            if !matches!(map.get("id"), Some(Value::String(_))) {
                return Err(RpcError::invalid_params(
                    method,
                    "missing required \"id\" (string)",
                ));
            }
            Ok(())
        }
        methods::CLIENT_AUTH_ATTACH | methods::CLIENT_AUTH_DETACH => {
            let Some(Value::Object(map)) = params else {
                return Err(RpcError::invalid_params(
                    method,
                    "expected params object: {\"service_id\": \"...\", \"client_auth_id\": \"...\"}",
                ));
            };
            if !matches!(map.get("service_id"), Some(Value::String(_))) {
                return Err(RpcError::invalid_params(
                    method,
                    "missing required \"service_id\" (string)",
                ));
            }
            if !matches!(map.get("client_auth_id"), Some(Value::String(_))) {
                return Err(RpcError::invalid_params(
                    method,
                    "missing required \"client_auth_id\" (string)",
                ));
            }
            Ok(())
        }
        methods::ONION_BACKUP | methods::ONION_RESTORE => {
            let Some(Value::Object(map)) = params else {
                return Err(RpcError::invalid_params(
                    method,
                    "expected params object: {\"passphrase\": \"...\"}",
                ));
            };
            if !matches!(map.get("passphrase"), Some(Value::String(_))) {
                return Err(RpcError::invalid_params(
                    method,
                    "missing required \"passphrase\" (string)",
                ));
            }
            if method == methods::ONION_RESTORE
                && !matches!(map.get("bundle"), Some(Value::Object(_)))
            {
                return Err(RpcError::invalid_params(
                    method,
                    "missing required \"bundle\" (object, envelope from onion.backup)",
                ));
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// Validate the optional `kind` selector ("proxy" | "shadowsocks") used by
/// the outbound proxy secret methods.
fn validate_outbound_key_kind(method: &str, kind: Option<&Value>) -> Result<(), RpcError> {
    match kind {
        None => Ok(()),
        Some(Value::String(s)) if s == "proxy" || s == "shadowsocks" => Ok(()),
        Some(Value::String(s)) => Err(RpcError::invalid_params(
            method,
            format!(
                "unknown outbound proxy secret kind {s:?}; expected \"proxy\" or \"shadowsocks\""
            ),
        )),
        Some(_) => Err(RpcError::invalid_params(
            method,
            "\"kind\" must be a string: \"proxy\" or \"shadowsocks\"",
        )),
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

/// Notification names used by the IPC surface.
pub mod notifications {
    /// Bootstrap progress; payload is [`BootstrapProgress`].
    pub const BOOTSTRAP_PROGRESS: &str = "bootstrap.progress";
    /// State transition; payload is `{ "state": DaemonState }`.
    pub const STATE_CHANGED: &str = "daemon.state_changed";
    /// Onion service published/updated; payload is an onion service object.
    pub const ONION_PUBLISHED: &str = "onion.published";
    /// Onion service error; payload contains `id` and a redacted `message`.
    pub const ONION_ERROR: &str = "onion.error";
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

/// Onion service port mapping (`virt_port` -> local target).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OnionServicePort {
    /// Virtual (onion-facing) port.
    pub virt_port: u16,
    /// Local target host, typically `127.0.0.1`.
    #[serde(default = "default_onion_target_host")]
    pub target_host: String,
    /// Local target port.
    pub target_port: u16,
}

fn default_onion_target_host() -> String {
    "127.0.0.1".to_owned()
}

/// Hosted onion service record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OnionService {
    /// Stable service identifier.
    pub id: String,
    /// Stable nickname/key identifier.
    pub nickname: String,
    /// Human-readable name.
    pub name: String,
    /// Desired enabled state.
    pub enabled: bool,
    /// Published `.onion` address, once known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub onion_address: Option<String>,
    /// Managed key/state directory path.
    pub key_dir: String,
    /// Unix timestamp in milliseconds.
    pub created_at: i64,
    /// Unix timestamp in milliseconds.
    pub updated_at: i64,
    /// Port mappings.
    pub ports: Vec<OnionServicePort>,
    /// Best-effort runtime status (`stopped`, `starting`, `published`, `error`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_status: Option<String>,
    /// Runtime error/detail, redacted/safe for UI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_detail: Option<String>,
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

    #[test]
    fn kindness_reset_stats_is_allowlisted_without_params() {
        assert!(is_allowed_method(methods::KINDNESS_RESET_STATS));
        assert!(validate_params(methods::KINDNESS_RESET_STATS, &None).is_ok());
        // Empty object still counts as "no params" for this method.
        assert!(
            validate_params(methods::KINDNESS_RESET_STATS, &Some(serde_json::json!({}))).is_ok()
        );
        assert!(
            validate_params(
                methods::KINDNESS_RESET_STATS,
                &Some(serde_json::json!({"x": 1}))
            )
            .is_err()
        );
        assert!(validate_params(methods::KINDNESS_STATUS, &None).is_ok());
    }

    #[test]
    fn logs_and_shutdown_are_allowlisted_and_validated() {
        assert!(is_allowed_method(methods::LOGS));
        assert!(is_allowed_method(methods::SHUTDOWN));
        assert!(validate_params(methods::SHUTDOWN, &None).is_ok());
        assert!(
            validate_params(methods::SHUTDOWN, &Some(serde_json::json!({"force": true}))).is_err()
        );

        for params in [
            None,
            Some(serde_json::json!(null)),
            Some(serde_json::json!({})),
            Some(serde_json::json!({"lines": 1})),
            Some(serde_json::json!({"lines": 500})),
            Some(serde_json::json!({"lines": 10_000})),
        ] {
            assert!(
                validate_params(methods::LOGS, &params).is_ok(),
                "should accept {params:?}"
            );
        }
        for params in [
            Some(serde_json::json!({"lines": 0})),
            Some(serde_json::json!({"lines": 10_001})),
            Some(serde_json::json!({"lines": -1})),
            Some(serde_json::json!({"lines": "many"})),
            Some(serde_json::json!({"since": 5})),
            Some(serde_json::json!(true)),
        ] {
            assert!(
                validate_params(methods::LOGS, &params).is_err(),
                "should reject {params:?}"
            );
        }
    }

    #[test]
    fn validates_backup_restore_params() {
        let ph = || Some(serde_json::json!({ "passphrase": "pw" }));
        // Backup requires a string passphrase; restore additionally requires
        // the bundle envelope object.
        assert!(validate_params(methods::ONION_BACKUP, &ph()).is_ok());
        assert!(validate_params(methods::ONION_BACKUP, &None).is_err());
        assert!(
            validate_params(
                methods::ONION_BACKUP,
                &Some(serde_json::json!({ "passphrase": 9 }))
            )
            .is_err()
        );

        assert!(validate_params(methods::ONION_RESTORE, &ph()).is_err());
        assert!(
            validate_params(
                methods::ONION_RESTORE,
                &Some(serde_json::json!({
                    "passphrase": "pw",
                    "bundle": { "format": "tobro-backup", "version": 1 }
                }))
            )
            .is_ok()
        );
    }
}
