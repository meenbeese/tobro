//! Configuration schema, loading, saving, and validation for tobro.
//!
//! M1 skeleton: typed TOML config with defaults and basic validation.
//! Expand with bridges, stream prefs, onion services, etc. in later milestones.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use directories::ProjectDirs;
use serde::{Deserialize, Serialize};

/// On-disk config file name.
pub const CONFIG_FILE_NAME: &str = "config.toml";

/// Errors produced by config loading, saving, or validation.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// Could not determine a platform config directory.
    #[error("could not determine the platform config directory")]
    NoConfigDir,
    /// Filesystem operation failed.
    #[error("I/O error at {path}: {source}")]
    Io {
        /// Path involved in the operation.
        path: PathBuf,
        /// Underlying error.
        #[source]
        source: std::io::Error,
    },
    /// TOML parsing failed.
    #[error("invalid TOML config at {path}: {source}")]
    Parse {
        /// Path of the config file.
        path: PathBuf,
        /// Underlying parse error.
        #[source]
        source: toml::de::Error,
    },
    /// TOML serialization failed.
    #[error("could not serialize config: {0}")]
    Serialize(#[from] toml::ser::Error),
    /// A config value failed validation.
    #[error("invalid config: {0}")]
    Invalid(String),
}

/// Top-level tobro configuration.
///
/// Fields default to values compatible with the M0 spike / Orbot-style defaults
/// where sensible; M1 hardens and exposes them through the daemon/GUI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Schema version for future migrations.
    pub version: u32,
    /// General application settings.
    pub general: GeneralConfig,
    /// Local proxy listener settings.
    pub proxy: ProxyConfig,
    /// Upstream/outbound proxy used by Tor to reach the network (F-18/F-19).
    pub outbound_proxy: OutboundProxyConfig,
    /// Network/stream defaults (M2): exit country, IPv6/StreamPrefs.
    pub network: NetworkConfig,
    /// Stream isolation and behavior settings (F-42/F-43).
    pub stream: StreamConfig,
    /// Bridge and pluggable transport settings (M3).
    pub bridges: BridgesConfig,
    /// Onion service hosting settings (M5). Dynamic services are managed via IPC/DB;
    /// this section reserves config compatibility.
    pub onion_services: OnionServicesConfig,
    /// Kindness Mode settings (M6, F-60): run a snowflake-proxy sidecar.
    pub kindness: KindnessConfig,
    /// Logging settings.
    pub logging: LoggingConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            version: 1,
            general: GeneralConfig::default(),
            proxy: ProxyConfig::default(),
            outbound_proxy: OutboundProxyConfig::default(),
            network: NetworkConfig::default(),
            stream: StreamConfig::default(),
            bridges: BridgesConfig::default(),
            onion_services: OnionServicesConfig::default(),
            kindness: KindnessConfig::default(),
            logging: LoggingConfig::default(),
        }
    }
}

/// Onion service hosting configuration (M5).
///
/// Dynamic onion services are created/edited/deleted/enabled via the daemon IPC
/// and persisted in the local store. Key material is stored on disk in the
/// managed onion-services directory (0700), never in config plaintext.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OnionServicesConfig {}

/// Bridge and pluggable transport configuration (M3).
///
/// Supports Tor/Arti bridge lines and external PT clients:
/// - lyrebird (`obfs4`, `meek_lite`/`meek`, `webtunnel`)
/// - snowflake-client (`snowflake`, including AMP/front/broker params in bridge lines)
/// - dnstt-client (`dnstt`)
///
/// Bridge material may be sensitive; avoid logging full lines.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BridgesConfig {
    /// Preferred circumvention transport/mode (`auto`, `obfs4`, `snowflake`,
    /// `webtunnel`, `meek`/`meek_lite`, `dnstt`, or `custom`). `auto` enables
    /// Smart Connect when `smart_connect` is true.
    #[serde(default)]
    pub transport: BridgeTransport,
    /// Enable Smart Connect fallback when `transport` is `auto` (or as a
    /// resilience policy). When false, use the configured transport/bridges directly.
    #[serde(default = "default_smart_connect")]
    pub smart_connect: bool,
    /// Total Smart Connect budget in seconds, divided across attempts.
    #[serde(default = "default_smart_connect_timeout_secs")]
    pub smart_connect_timeout_secs: u64,
    /// Enable bridge/PT usage. When false, `lines` are ignored for direct PT
    /// configuration (Smart Connect/Moat may still resolve bridges when active).
    pub enabled: bool,
    /// Bridge lines in Tor bridge format (e.g. `obfs4 ...`, `webtunnel ...`,
    /// `snowflake ...`, `dnstt ...`, or `Bridge <transport> ...`).
    #[serde(default)]
    pub lines: Vec<String>,
    /// Preferred lyrebird binary path override. When unset, tobro searches for
    /// lyrebird in sidecar/app locations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport_path: Option<String>,
    /// Extra directory to search for lyrebird/PT binaries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport_dir: Option<String>,
    /// Request lyrebird-managed transports for these protocols when bridge lines
    /// use them and no explicit transport config is provided. Defaults to lyrebird
    /// protocols supported by this build.
    #[serde(default = "default_lyrebird_transports")]
    pub lyrebird_transports: Vec<String>,
    /// Preferred `snowflake-client` binary path override. When unset, tobro
    /// searches for `snowflake-client` in sidecar/app locations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snowflake_path: Option<String>,
    /// Extra directory to search for `snowflake-client`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snowflake_dir: Option<String>,
    /// Preferred `dnstt-client` binary path override. When unset, tobro
    /// searches for `dnstt-client` in sidecar/app locations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dnstt_path: Option<String>,
    /// Extra directory to search for `dnstt-client`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dnstt_dir: Option<String>,
    /// Preferred country for bridge selection (ISO 3166-1 alpha-2), used for
    /// built-in/Moat bridge filtering when available. `"auto"`/empty means unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
}

/// Selected bridge/circumvention transport mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum BridgeTransport {
    /// Automatically select (Smart Connect / direct+fallback as configured).
    #[default]
    Auto,
    /// Use obfs4 bridges (lyrebird).
    Obfs4,
    /// Use Snowflake.
    Snowflake,
    /// Use WebTunnel (lyrebird).
    Webtunnel,
    /// Use meek/meek_lite (lyrebird).
    Meek,
    /// Use dnstt.
    Dnstt,
    /// Use user-provided custom bridge lines.
    Custom,
}

fn default_smart_connect() -> bool {
    true
}

/// Pause-on-metered defaults to true so Kindness Mode does not donate on
/// capped links unless detection is explicitly disabled.
fn default_kindness_pause_on_metered() -> bool {
    true
}

fn default_smart_connect_timeout_secs() -> u64 {
    30
}

fn default_lyrebird_transports() -> Vec<String> {
    vec![
        "obfs4".to_owned(),
        "meek_lite".to_owned(),
        "webtunnel".to_owned(),
    ]
}

impl Default for BridgesConfig {
    fn default() -> Self {
        Self {
            transport: BridgeTransport::Auto,
            smart_connect: default_smart_connect(),
            smart_connect_timeout_secs: default_smart_connect_timeout_secs(),
            enabled: false,
            lines: Vec::new(),
            transport_path: None,
            transport_dir: None,
            lyrebird_transports: default_lyrebird_transports(),
            snowflake_path: None,
            snowflake_dir: None,
            dnstt_path: None,
            dnstt_dir: None,
            country: None,
        }
    }
}

impl BridgesConfig {
    /// Normalized, non-empty bridge lines. Comments/blank lines removed.
    pub fn normalized_lines(&self) -> Vec<String> {
        self.lines
            .iter()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(ToOwned::to_owned)
            .collect()
    }

    /// True when bridges are enabled and at least one usable line is present.
    pub fn is_active(&self) -> bool {
        self.enabled && !self.normalized_lines().is_empty()
    }

    /// Normalized country code (`"auto"`/empty -> `None`).
    pub fn normalized_country(&self) -> Option<String> {
        self.country
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("auto"))
            .map(|s| s.to_ascii_lowercase())
    }

    /// True when Smart Connect should orchestrate fallback attempts.
    pub fn smart_connect_active(&self) -> bool {
        self.smart_connect && self.transport == BridgeTransport::Auto
    }
}

/// Network and default `StreamPrefs` settings (M2).
///
/// Controls exit-country selection, IPv6 preference, and default stream
/// behavior applied to proxied connections where supported by the Arti backend.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NetworkConfig {
    /// Preferred exit country as an ISO 3166-1 alpha-2 code (e.g. `"us"`, `"de"`).
    /// Empty/omitted means any exit country. Requires Arti geoip support.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_country: Option<String>,
    /// Default IPv6/IP version preference for streams (F-44).
    #[serde(default)]
    pub ip_version: IpVersionPreference,
}

impl NetworkConfig {
    /// True when any non-default network StreamPrefs are configured, requiring
    /// tobro's proxy path to apply them via `arti-client` StreamPrefs.
    pub fn has_stream_prefs(&self) -> bool {
        self.exit_country
            .as_deref()
            .is_some_and(|c| !c.trim().is_empty())
            || self.ip_version != IpVersionPreference::default()
    }

    /// Normalized exit country code, or `None` for "any".
    pub fn normalized_exit_country(&self) -> Option<String> {
        self.exit_country
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.to_ascii_lowercase())
    }
}

/// Default IP version preference for proxied streams (M2/F-44).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpVersionPreference {
    /// Prefer IPv4, allow IPv6 (Arti/Orbot-like default behavior).
    #[default]
    Ipv4Preferred,
    /// Prefer IPv6, allow IPv4.
    Ipv6Preferred,
    /// Only use IPv4.
    Ipv4Only,
    /// Only use IPv6.
    Ipv6Only,
}

/// Stream isolation and behavior settings.
///
/// These control how local proxy streams are isolated onto Tor circuits.
/// All flags default to off (matching Orbot's defaults).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StreamConfig {
    /// Isolate streams by destination address (F-42). Streams to different
    /// destination hosts/IPs do not share circuits when enabled.
    pub isolate_destination: bool,
    /// Isolate streams by destination port (F-42).
    pub isolate_port: bool,
    /// Isolate streams by client protocol (F-42). Arti's built-in proxy
    /// already separates HTTP CONNECT and SOCKS isolation contexts; this flag
    /// makes protocol separation explicit in tobro's isolation policy and is
    /// applied by the thin proxy front-end when destination/port isolation is
    /// active.
    pub isolate_protocol: bool,
    /// SOCKS auth keep-alive isolation (F-43). When enabled, SOCKS
    /// username/password credentials are treated as an isolation key and kept
    /// associated for the stream's lifetime. Arti's built-in SOCKS proxy
    /// isolates by SOCKS auth when different credentials are provided; this
    /// setting makes that behavior explicit in config and diagnostics.
    pub keep_alive_isolation: bool,
}

impl StreamConfig {
    /// True if any destination/port isolation flag requires the thin proxy
    /// front-end (beyond Arti's built-in SOCKS auth/header isolation).
    pub fn needs_isolation_frontend(&self) -> bool {
        self.isolate_destination || self.isolate_port
    }

    /// Human-readable summary of effective isolation behavior.
    pub fn isolation_summary(&self) -> String {
        let mut parts = Vec::new();
        if self.isolate_destination {
            parts.push("destination");
        }
        if self.isolate_port {
            parts.push("port");
        }
        if self.isolate_protocol {
            parts.push("protocol");
        }
        if self.keep_alive_isolation {
            parts.push("SOCKS auth keep-alive");
        }
        if parts.is_empty() {
            "off (Arti default isolation: SOCKS auth/HTTP headers when provided)".to_owned()
        } else {
            format!("on ({})", parts.join(", "))
        }
    }
}

/// General application settings.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GeneralConfig {
    /// Whether the user wants tobro started at login (wiring arrives in M4).
    pub start_on_login: bool,
}

/// Upstream/outbound proxy type used by Tor channels (F-18/F-19).
///
/// `Shadowsocks` is implemented by running a local `sslocal` sidecar and
/// pointing Arti's outbound channel proxy at its local SOCKS5 listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum OutboundProxyType {
    /// No outbound proxy (direct Tor connections).
    #[default]
    None,
    /// HTTP CONNECT proxy.
    Http,
    /// HTTPS alias treated as HTTP CONNECT (Arti channel proxy uses HTTP CONNECT).
    Https,
    /// SOCKS4 proxy.
    Socks4,
    /// SOCKS5 proxy.
    Socks5,
    /// Shadowsocks via local `sslocal` sidecar.
    Shadowsocks,
}

/// Outbound proxy configuration (F-18/F-19).
///
/// Sensitive fields (`password`, `shadowsocks_password`, `username`) must not be
/// logged or returned unredacted in diagnostics/IPC config responses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OutboundProxyConfig {
    /// Outbound proxy type/mode.
    pub proxy_type: OutboundProxyType,
    /// Proxy/remote server host (IP or hostname accepted by config; HTTP/SOCKS
    /// outbound parsing may require an IP/URL form depending on backend support).
    pub host: String,
    /// Proxy/remote server port.
    pub port: u16,
    /// Username for HTTP/SOCKS auth. Ignored for `none`/`shadowsocks` local hop.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub username: String,
    /// Password for HTTP/SOCKS auth, or unused for `none`. Sensitive.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub password: String,
    /// Shadowsocks encryption method (e.g. `aes-256-gcm`, `chacha20-ietf-poly1305`).
    #[serde(default = "default_shadowsocks_method")]
    pub shadowsocks_method: String,
    /// Shadowsocks remote password. Sensitive. Falls back to `password` when empty
    /// (`effective_shadowsocks_password`) for compatibility with simple clients.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub shadowsocks_password: String,
    /// When true, outbound proxy secrets (`password`, `shadowsocks_password`)
    /// live in the OS keychain instead of this config file. The on-disk
    /// password fields must be empty when enabled; the secret itself is set
    /// or cleared over IPC (`outbound_proxy.set_password` /
    /// `outbound_proxy.clear_password`), never included in config patches.
    #[serde(default)]
    pub password_keychain: bool,
    /// Optional `sslocal` binary path override.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sslocal_path: Option<String>,
    /// Optional extra directory to search for `sslocal`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sslocal_dir: Option<String>,
}

fn default_shadowsocks_method() -> String {
    "aes-256-gcm".to_owned()
}

impl Default for OutboundProxyConfig {
    fn default() -> Self {
        Self {
            proxy_type: OutboundProxyType::None,
            host: String::new(),
            port: 0,
            username: String::new(),
            password: String::new(),
            password_keychain: false,
            shadowsocks_method: default_shadowsocks_method(),
            shadowsocks_password: String::new(),
            sslocal_path: None,
            sslocal_dir: None,
        }
    }
}

impl OutboundProxyConfig {
    /// True when an outbound proxy is configured and should be applied.
    pub fn is_active(&self) -> bool {
        self.proxy_type != OutboundProxyType::None
    }

    /// Normalized host (trimmed).
    pub fn normalized_host(&self) -> &str {
        self.host.trim()
    }

    /// Effective Shadowsocks password (`shadowsocks_password` or fallback `password`).
    pub fn effective_shadowsocks_password(&self) -> &str {
        let p = self.shadowsocks_password.trim();
        if p.is_empty() {
            self.password.trim()
        } else {
            p
        }
    }

    /// Normalized proxy type (`https` treated as `http` for Arti HTTP CONNECT).
    pub fn normalized_proxy_type(&self) -> OutboundProxyType {
        match self.proxy_type {
            OutboundProxyType::Https => OutboundProxyType::Http,
            other => other,
        }
    }

    /// True when this config requires a local `sslocal` sidecar.
    pub fn needs_sslocal(&self) -> bool {
        self.is_active() && self.proxy_type == OutboundProxyType::Shadowsocks
    }

    /// Redacted clone safe for logs/IPC config display (secrets replaced).
    pub fn redacted(&self) -> Self {
        let mut c = self.clone();
        if !c.password.is_empty() {
            c.password = "[REDACTED]".to_owned();
        }
        if !c.shadowsocks_password.is_empty() {
            c.shadowsocks_password = "[REDACTED]".to_owned();
        }
        c
    }

    /// Validate outbound proxy settings.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !self.is_active() {
            return Ok(());
        }
        let host = self.normalized_host();
        if host.is_empty() {
            return Err(ConfigError::Invalid(
                "outbound_proxy.host must not be empty when outbound_proxy.proxy_type is set"
                    .to_owned(),
            ));
        }
        if host
            .chars()
            .any(|c| c.is_whitespace() || c == '/' || c == '@')
        {
            return Err(ConfigError::Invalid(format!(
                "outbound_proxy.host contains invalid characters: {host:?}"
            )));
        }
        if self.port == 0 {
            return Err(ConfigError::Invalid(
                "outbound_proxy.port must not be zero when outbound_proxy is enabled".to_owned(),
            ));
        }
        if let Some(p) = &self.sslocal_path
            && p.trim().is_empty()
        {
            return Err(ConfigError::Invalid(
                "outbound_proxy.sslocal_path must not be empty when set".to_owned(),
            ));
        }
        if let Some(p) = &self.sslocal_dir
            && p.trim().is_empty()
        {
            return Err(ConfigError::Invalid(
                "outbound_proxy.sslocal_dir must not be empty when set".to_owned(),
            ));
        }
        if self.password_keychain
            && (!self.password.trim().is_empty() || !self.shadowsocks_password.trim().is_empty())
        {
            return Err(ConfigError::Invalid(
                "outbound_proxy.password_keychain is enabled: remove the plaintext outbound_proxy.password/shadowsocks_password from the config; secrets live in the OS keychain and are set via outbound_proxy.set_password".to_owned(),
            ));
        }
        match self.normalized_proxy_type() {
            OutboundProxyType::None => {}
            OutboundProxyType::Http | OutboundProxyType::Socks4 | OutboundProxyType::Socks5 => {
                // tor-chanmgr 0.48 ProxyProtocol URL parsing accepts IP-literal hosts only.
                if host.parse::<std::net::IpAddr>().is_err() {
                    return Err(ConfigError::Invalid(format!(
                        "outbound_proxy.host must be an IP address for {kind} outbound proxies (hostname resolution is not supported by the current backend); got {host:?}",
                        kind = match self.normalized_proxy_type() {
                            OutboundProxyType::Http => "HTTP/HTTPS",
                            OutboundProxyType::Socks4 => "SOCKS4",
                            OutboundProxyType::Socks5 => "SOCKS5",
                            _ => "this",
                        }
                    )));
                }
                if self.normalized_proxy_type() == OutboundProxyType::Socks4
                    && !self.password.trim().is_empty()
                {
                    return Err(ConfigError::Invalid(
                        "outbound_proxy.password is not supported for SOCKS4; use SOCKS5 or HTTP if authentication is required".to_owned(),
                    ));
                }
            }
            OutboundProxyType::Https => unreachable!("normalized"),
            OutboundProxyType::Shadowsocks => {
                if self.shadowsocks_method.trim().is_empty() {
                    return Err(ConfigError::Invalid(
                        "outbound_proxy.shadowsocks_method must not be empty for Shadowsocks"
                            .to_owned(),
                    ));
                }
                if self.effective_shadowsocks_password().is_empty() && !self.password_keychain {
                    return Err(ConfigError::Invalid(
                        "outbound_proxy.shadowsocks_password (or password) must be set for Shadowsocks"
                            .to_owned(),
                    ));
                }
            }
        }
        Ok(())
    }
}

fn default_http_port_follow() -> u16 {
    0
}

/// Local proxy listener settings.
///
/// Arti 2.8 serves SOCKS5 and HTTP CONNECT on the same local TCP listener
/// (`ListenProtocols::SocksAndHttpConnect`). Until separate listeners are
/// supported, `http_port` must match `socks_port`; `0` means "use `socks_port`".
///
/// By default listeners bind to loopback only. `bind_all_interfaces` is an
/// explicit opt-in (M2/F-13) and exposes proxies to reachable networks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProxyConfig {
    /// SOCKS5 port (also carries HTTP CONNECT while listeners are combined).
    pub socks_port: u16,
    /// HTTP CONNECT port. Set to `0` or the same value as `socks_port` while
    /// Arti serves both protocols on one listener. When omitted from config, it
    /// follows `socks_port`.
    #[serde(default = "default_http_port_follow")]
    pub http_port: u16,
    /// UDP DNS proxy port.
    pub dns_port: u16,
    /// Bind proxy/DNS listeners on all interfaces instead of loopback only.
    ///
    /// Opt-in only. When enabled, other devices on reachable networks may be
    /// able to use your local Tor proxy; configure OS/router firewall rules and
    /// only enable on trusted networks.
    #[serde(default)]
    pub bind_all_interfaces: bool,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            socks_port: 9050,
            // Combined with SOCKS under Arti 2.8; keep explicit for config parity.
            http_port: 9050,
            dns_port: 9053,
            bind_all_interfaces: false,
        }
    }
}

impl ProxyConfig {
    /// Effective HTTP CONNECT port (follows `socks_port` when unset/combined).
    pub fn effective_http_port(&self) -> u16 {
        if self.http_port == 0 {
            self.socks_port
        } else {
            self.http_port
        }
    }
}

/// Logging settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LoggingConfig {
    /// Tracing filter / level (e.g. `info`, `debug`, `tobro=debug`).
    pub level: String,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_owned(),
        }
    }
}

/// Kindness Mode configuration (M6, §4.9, F-60).
///
/// Runs the upstream `snowflake-proxy` sidecar (not the client) so this
/// computer can serve as a Snowflake proxy for censored users. The proxy
/// speaks the WebSocket/WebRTC rendezvous protocol to a broker, not the Tor
/// PT line protocol, so supervisor readiness is simply "process started".
///
/// Overrides fall back to the binary's own defaults; tobro passes only the
/// flags explicitly configured, and unknown behaviors can be reached with
/// `extra_args`. See upstream `snowflake/proxy` (broker
/// `https://snowflake-broker.torproject.net/`, relay `wss://snowflake.torproject.net/`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct KindnessConfig {
    /// Run `snowflake-proxy` while the daemon runs.
    pub enabled: bool,
    /// Broker URL override.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub broker_url: Option<String>,
    /// Relay (server) URL override used when the broker does not specify one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_url: Option<String>,
    /// Comma-separated STUN URLs used for NAT discovery.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stun_url: Option<String>,
    /// Maximum concurrent clients to serve. Only forwarded as `-capacity`
    /// when set: current upstream releases derive capacity from the broker,
    /// while older releases accept the flag. This is the connection cap;
    /// upstream `snowflake-proxy` exposes no bandwidth-limit flag, so
    /// per-connection serving volume cannot be capped by binary release.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capacity: Option<u32>,
    /// Pause the proxy while a metered connection is detected (best effort:
    /// enforced only when the platform reports the link as metered; desktop
    /// platforms with no metered-link API stay unthrottled).
    #[serde(default = "default_kindness_pause_on_metered")]
    pub pause_on_metered: bool,
    /// Pause the proxy while the device runs on battery (best effort:
    /// enforced only when the platform reports battery charging state).
    #[serde(default)]
    pub pause_when_not_charging: bool,
    /// UDP port range for client connections, upstream format `<min>:<max>`
    /// (passed to the proxy as `-ephemeral-ports-range`). Optional: when
    /// unset the proxy picks ephemeral ports automatically.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ephemeral_ports: Option<String>,
    /// Report the NAT type as unrestricted without probing.
    #[serde(default)]
    pub nat_type_force_unrestricted: bool,
    /// Increase proxy log verbosity.
    #[serde(default)]
    pub verbose: bool,
    /// Expected SHA-256 of the `snowflake-proxy` binary (lowercase hex).
    /// When set, startup refuses to launch a binary that does not match.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256_hex: Option<String>,
    /// Explicit `snowflake-proxy` binary path override.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_path: Option<String>,
    /// Extra directory to search for `snowflake-proxy`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_dir: Option<String>,
    /// Extra raw arguments passed through to the proxy (power users only).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extra_args: Vec<String>,
}

impl Default for KindnessConfig {
    /// Hand-rolled so the two pause-limit defaults agree with serde: a missing
    /// key, `Config::default()`, and the TOML default fn all say the same
    /// thing (pause on metered yes, pause when not charging no).
    fn default() -> Self {
        Self {
            enabled: false,
            broker_url: None,
            relay_url: None,
            stun_url: None,
            capacity: None,
            pause_on_metered: true,
            pause_when_not_charging: false,
            ephemeral_ports: None,
            nat_type_force_unrestricted: false,
            verbose: false,
            sha256_hex: None,
            proxy_path: None,
            proxy_dir: None,
            extra_args: Vec::new(),
        }
    }
}

impl KindnessConfig {
    /// True when the snowflake-proxy sidecar should run.
    pub fn is_active(&self) -> bool {
        self.enabled
    }

    /// Parse `ephemeral_ports` in the upstream `<min>:<max>` format.
    /// Returns the inclusive port bounds.
    pub fn parse_ephemeral_ports(&self) -> Result<(u16, u16), String> {
        parse_ephemeral_ports(self.ephemeral_ports.as_deref())
    }

    fn normalized_url(name: &str, value: Option<&str>) -> Result<Option<String>, ConfigError> {
        let Some(raw) = value else {
            return Ok(None);
        };
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(ConfigError::Invalid(format!(
                "kindness.{name} must not be empty when set (omit the key to use the binary default)"
            )));
        }
        if trimmed.chars().any(char::is_whitespace) {
            return Err(ConfigError::Invalid(format!(
                "kindness.{name} must not contain whitespace: {trimmed:?}"
            )));
        }
        Ok(Some(trimmed.to_owned()))
    }

    /// Validate kindness settings.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if let Some(capacity) = self.capacity
            && capacity == 0
        {
            return Err(ConfigError::Invalid(
                "kindness.capacity must be greater than zero when set".to_owned(),
            ));
        }
        Self::normalized_url("broker_url", self.broker_url.as_deref())?;
        Self::normalized_url("relay_url", self.relay_url.as_deref())?;
        Self::normalized_url("stun_url", self.stun_url.as_deref())?;
        if let Some(raw) = self.ephemeral_ports.as_deref()
            && let Err(reason) = parse_ephemeral_ports(Some(raw))
        {
            return Err(ConfigError::Invalid(reason));
        }
        if let Some(hex) = &self.sha256_hex {
            let hex = hex.trim();
            if hex.len() != 64
                || !hex
                    .chars()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
            {
                return Err(ConfigError::Invalid(
                    "kindness.sha256_hex must be 64 lowercase hex characters".to_owned(),
                ));
            }
        }
        if let Some(p) = &self.proxy_path
            && p.trim().is_empty()
        {
            return Err(ConfigError::Invalid(
                "kindness.proxy_path must not be empty when set".to_owned(),
            ));
        }
        if let Some(p) = &self.proxy_dir
            && p.trim().is_empty()
        {
            return Err(ConfigError::Invalid(
                "kindness.proxy_dir must not be empty when set".to_owned(),
            ));
        }
        for (i, arg) in self.extra_args.iter().enumerate() {
            if arg.contains('\0') {
                return Err(ConfigError::Invalid(format!(
                    "kindness.extra_args[{i}] must not contain NUL"
                )));
            }
        }
        Ok(())
    }
}

/// Parse an `-ephemeral-ports-range` value in the upstream `<min>:<max>`
/// format. Shared by config validation and the Kindness diagnostics.
pub fn parse_ephemeral_ports(raw: Option<&str>) -> Result<(u16, u16), String> {
    let Some(raw) = raw else {
        return Err("ephemeral_ports is not set".to_owned());
    };
    let raw = raw.trim();
    let Some((min_raw, max_raw)) = raw.split_once(':') else {
        return Err(format!(
            "ephemeral_ports must use the upstream `<min>:<max>` format (for example \"30000:40000\"), got {raw:?}"
        ));
    };
    let parse_bound = |bound: &str| -> Result<u16, String> {
        bound
            .trim()
            .parse::<u16>()
            .map_err(|_| format!("ephemeral_ports bounds must be integers 1–65535, got {bound:?}"))
    };
    let min = parse_bound(min_raw)?;
    let max = parse_bound(max_raw)?;
    if min == 0 || max == 0 {
        return Err("ephemeral_ports bounds must be at least 1".to_owned());
    }
    if min > max {
        return Err(format!(
            "ephemeral_ports min ({min}) must not exceed max ({max})"
        ));
    }
    Ok((min, max))
}

/// Resolve the default config file path.
pub fn default_path() -> Result<PathBuf, ConfigError> {
    let project = ProjectDirs::from("", "", "tobro").ok_or(ConfigError::NoConfigDir)?;
    Ok(project.config_dir().join(CONFIG_FILE_NAME))
}

impl Config {
    /// Load config from `path`.
    ///
    /// Returns [`ConfigError::Io`] if the file cannot be read.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let config: Self = toml::from_str(&text).map_err(|source| ConfigError::Parse {
            path: path.to_path_buf(),
            source,
        })?;
        config.validate()?;
        Ok(config)
    }

    /// Load config from `path`, or return defaults if the file does not exist.
    pub fn load_or_default(path: &Path) -> Result<Self, ConfigError> {
        match fs::read_to_string(path) {
            Ok(text) => {
                let config: Self = toml::from_str(&text).map_err(|source| ConfigError::Parse {
                    path: path.to_path_buf(),
                    source,
                })?;
                config.validate()?;
                Ok(config)
            }
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(source) => Err(ConfigError::Io {
                path: path.to_path_buf(),
                source,
            }),
        }
    }

    /// Validate config values.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.version == 0 {
            return Err(ConfigError::Invalid(
                "version must be greater than zero".to_owned(),
            ));
        }
        validate_port("proxy.socks_port", self.proxy.socks_port)?;
        validate_port("proxy.dns_port", self.proxy.dns_port)?;
        let http_port = self.proxy.effective_http_port();
        validate_port("proxy.http_port", http_port)?;
        if self.proxy.http_port != 0 && self.proxy.http_port != self.proxy.socks_port {
            return Err(ConfigError::Invalid(format!(
                "proxy.http_port ({}) must match proxy.socks_port ({}) or be 0: Arti 2.8 serves SOCKS and HTTP CONNECT on the same local listener",
                self.proxy.http_port, self.proxy.socks_port
            )));
        }
        if self.proxy.socks_port == self.proxy.dns_port {
            return Err(ConfigError::Invalid(format!(
                "proxy.socks_port and proxy.dns_port must differ (both {})",
                self.proxy.socks_port
            )));
        }
        if http_port == self.proxy.dns_port {
            return Err(ConfigError::Invalid(format!(
                "proxy.http_port and proxy.dns_port must differ (both {})",
                http_port
            )));
        }
        if self.logging.level.trim().is_empty() {
            return Err(ConfigError::Invalid(
                "logging.level must not be empty".to_owned(),
            ));
        }
        if let Some(country) = self.network.normalized_exit_country()
            && (country.len() != 2 || !country.chars().all(|c| c.is_ascii_alphabetic()))
        {
            return Err(ConfigError::Invalid(format!(
                "network.exit_country must be an ISO 3166-1 alpha-2 code (two letters), got {:?}",
                self.network.exit_country.as_deref().unwrap_or("")
            )));
        }
        if self.bridges.enabled && self.bridges.normalized_lines().is_empty() {
            return Err(ConfigError::Invalid(
                "bridges.enabled is true but bridges.lines has no usable bridge lines (add bridge lines or disable bridges)".to_owned(),
            ));
        }
        for (i, line) in self.bridges.lines.iter().enumerate() {
            if line.contains('\0') || line.contains('\n') || line.contains('\r') {
                return Err(ConfigError::Invalid(format!(
                    "bridges.lines[{i}] must be a single line"
                )));
            }
        }
        if let Some(p) = &self.bridges.transport_path
            && p.trim().is_empty()
        {
            return Err(ConfigError::Invalid(
                "bridges.transport_path must not be empty when set".to_owned(),
            ));
        }
        if let Some(p) = &self.bridges.snowflake_path
            && p.trim().is_empty()
        {
            return Err(ConfigError::Invalid(
                "bridges.snowflake_path must not be empty when set".to_owned(),
            ));
        }
        if let Some(p) = &self.bridges.dnstt_path
            && p.trim().is_empty()
        {
            return Err(ConfigError::Invalid(
                "bridges.dnstt_path must not be empty when set".to_owned(),
            ));
        }
        if let Some(country) = self.bridges.country.as_deref() {
            let c = country.trim().to_ascii_lowercase();
            if !c.is_empty() && (c.len() != 2 || !c.chars().all(|ch| ch.is_ascii_alphabetic())) {
                return Err(ConfigError::Invalid(format!(
                    "bridges.country must be an ISO 3166-1 alpha-2 code (two letters), got {:?}",
                    self.bridges.country.as_deref().unwrap_or("")
                )));
            }
        }
        self.kindness.validate()?;
        self.outbound_proxy.validate()?;
        Ok(())
    }
}

/// Validate a configured TCP/UDP port number.
pub fn validate_port(name: &str, port: u16) -> Result<(), ConfigError> {
    if port == 0 {
        return Err(ConfigError::Invalid(format!("{name} must not be zero")));
    }
    Ok(())
}

/// Check whether a local TCP port appears available on loopback.
///
/// This performs a best-effort bind probe. It cannot guarantee availability
/// (TOCTOU), but it provides actionable feedback before Tor starts.
pub fn tcp_port_available(port: u16) -> bool {
    tcp_port_available_with(port, false)
}

/// Check whether a local UDP port appears available on loopback.
pub fn udp_port_available(port: u16) -> bool {
    udp_port_available_with(port, false)
}

/// Check whether a local TCP port appears available for the configured bind scope.
///
/// When `bind_all_interfaces` is true, probes `0.0.0.0` (best-effort; exposure
/// risk is reported separately via warnings).
pub fn tcp_port_available_with(port: u16, bind_all_interfaces: bool) -> bool {
    let addr = if bind_all_interfaces {
        std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
    } else {
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
    };
    std::net::TcpListener::bind((addr, port)).is_ok()
}

/// Check whether a local UDP port appears available for the configured bind scope.
pub fn udp_port_available_with(port: u16, bind_all_interfaces: bool) -> bool {
    let addr = if bind_all_interfaces {
        std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
    } else {
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
    };
    std::net::UdpSocket::bind((addr, port)).is_ok()
}

/// Best-effort description of the process occupying a local port.
///
/// Returns `None` when ownership cannot be determined. Never fails startup.
pub fn port_owner_hint(port: u16, protocol: &str) -> Option<String> {
    #[cfg(unix)]
    {
        let proto = if protocol.eq_ignore_ascii_case("udp") {
            "UDP"
        } else {
            "TCP"
        };
        let output = std::process::Command::new("lsof")
            .args(["-nP", &format!("-i{proto}:{port}"), "-sTCP:LISTEN"])
            .output()
            .ok()?;
        if !output.status.success() {
            // UDP listeners may not match -sTCP:LISTEN; retry without it.
            let output = std::process::Command::new("lsof")
                .args(["-nP", &format!("-i{proto}:{port}")])
                .output()
                .ok()?;
            if !output.status.success() {
                return None;
            }
            return summarize_lsof(&output.stdout);
        }
        summarize_lsof(&output.stdout)
    }
    #[cfg(windows)]
    {
        let output = std::process::Command::new("netstat")
            .args(["-aonp", protocol])
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        summarize_netstat(&output.stdout, port)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (port, protocol);
        None
    }
}

#[cfg(unix)]
fn summarize_lsof(stdout: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(stdout);
    let mut lines = text.lines();
    let _header = lines.next()?;
    let line = lines.find(|l| !l.trim().is_empty())?;
    let cols: Vec<&str> = line.split_whitespace().collect();
    if cols.len() >= 2 {
        Some(format!("owner: {} (pid {})", cols[0], cols[1]))
    } else {
        Some(line.trim().to_owned())
    }
}

#[cfg(windows)]
fn summarize_netstat(stdout: &[u8], port: u16) -> Option<String> {
    let text = String::from_utf8_lossy(stdout);
    let needle = format!(":{port} ");
    let line = text.lines().find(|l| l.contains(&needle))?;
    let cols: Vec<&str> = line.split_whitespace().collect();
    let pid = cols.last()?;
    Some(format!("owner pid: {pid}"))
}

/// Find the next available local port starting at `start` (wrapping within the
/// valid unprivileged range), using `is_available` to probe.
///
/// Returns `None` if no port is found after a bounded search.
pub fn next_available_port(start: u16, is_available: impl Fn(u16) -> bool) -> Option<u16> {
    const MAX_PROBE: u16 = 1024;
    let start = if start == 0 { 1024 } else { start };
    for offset in 0..MAX_PROBE {
        let port = start.saturating_add(offset);
        if port == 0 {
            continue;
        }
        if is_available(port) {
            return Some(port);
        }
    }
    // Wrap to unprivileged range if we started high.
    if start > 1024 {
        for port in 1024..start.min(1024 + MAX_PROBE) {
            if is_available(port) {
                return Some(port);
            }
        }
    }
    None
}

/// Report listener port conflicts with actionable suggestions.
/// Report listener port conflicts with actionable suggestions.
pub fn port_conflicts(proxy: &ProxyConfig) -> Vec<String> {
    let mut conflicts = Vec::new();
    let bind_all = proxy.bind_all_interfaces;
    let http_port = proxy.effective_http_port();
    let tcp_ok = |p: u16| tcp_port_available_with(p, bind_all);
    let udp_ok = |p: u16| udp_port_available_with(p, bind_all);
    let scope = if bind_all {
        "all interfaces"
    } else {
        "loopback"
    };
    if !tcp_ok(proxy.socks_port) {
        let owner = port_owner_hint(proxy.socks_port, "tcp")
            .map(|o| format!("; {o}"))
            .unwrap_or_default();
        let suggestion = next_available_port(proxy.socks_port.saturating_add(1), tcp_ok)
            .map(|p| format!("; next free TCP port: {p}"))
            .unwrap_or_default();
        conflicts.push(format!(
            "proxy.socks_port {} (SOCKS/HTTP TCP, {scope}) is already in use or unavailable{owner}{suggestion}. Change the port in config or stop the conflicting process.",
            proxy.socks_port
        ));
    }
    if http_port != proxy.socks_port && !tcp_ok(http_port) {
        let owner = port_owner_hint(http_port, "tcp")
            .map(|o| format!("; {o}"))
            .unwrap_or_default();
        let suggestion = next_available_port(http_port.saturating_add(1), tcp_ok)
            .map(|p| format!("; next free TCP port: {p}"))
            .unwrap_or_default();
        conflicts.push(format!(
            "proxy.http_port {http_port} (HTTP TCP, {scope}) is already in use or unavailable{owner}{suggestion}. Change the port in config or stop the conflicting process."
        ));
    }
    if !udp_ok(proxy.dns_port) {
        let owner = port_owner_hint(proxy.dns_port, "udp")
            .map(|o| format!("; {o}"))
            .unwrap_or_default();
        let suggestion = next_available_port(proxy.dns_port.saturating_add(1), udp_ok)
            .map(|p| format!("; next free UDP port: {p}"))
            .unwrap_or_default();
        conflicts.push(format!(
            "proxy.dns_port {} (DNS UDP, {scope}) is already in use or unavailable{owner}{suggestion}. Change the port in config or stop the conflicting process.",
            proxy.dns_port
        ));
    }
    conflicts
}

/// Security and firewall guidance when `bind_all_interfaces` is enabled.
pub fn bind_all_interfaces_warnings(proxy: &ProxyConfig) -> Vec<String> {
    if !proxy.bind_all_interfaces {
        return Vec::new();
    }
    vec![
        format!(
            "SECURITY WARNING: proxy.bind_all_interfaces is enabled. SOCKS ({}), HTTP CONNECT ({}), and DNS ({}, UDP) listeners may accept connections from other devices on reachable networks.",
            proxy.socks_port,
            proxy.effective_http_port(),
            proxy.dns_port
        ),
        "Only enable this on trusted networks. Configure your OS/router firewall to restrict who can reach these ports, and disable bind-all when not needed. Other hosts using these proxies can route traffic through Tor from your machine.".to_owned(),
    ]
}

/// All non-fatal proxy warnings: security guidance plus port conflicts.
pub fn proxy_warnings(proxy: &ProxyConfig) -> Vec<String> {
    let mut warnings = bind_all_interfaces_warnings(proxy);
    warnings.extend(port_conflicts(proxy));
    warnings
}

/// Explain a config knob path that is known but unsupported in this build.
///
/// Used to reject unsupported knobs explicitly (never silently ignored). Unknown
/// fields are still rejected by `deny_unknown_fields` during deserialization.
pub fn unsupported_knob_error(path: &str) -> Option<String> {
    let (knob, explanation) = match path {
        "network.geoip" | "network.stream_prefs" => (
            path,
            "this specific network sub-knob is not exposed; use supported [network] fields (exit_country, ip_version).",
        ),
        "tor" | "tor.entry_nodes" | "tor.exit_nodes" | "tor.exclude_nodes" | "tor.strict_nodes" => {
            (
                path,
                "C Tor-style node restriction lists (entry/exit/exclude/strict nodes) are not exposed by the pinned Arti 2.8/arti-client 0.48 APIs used by tobro. The supported subset is currently none for these knobs; unsupported options remain hidden.",
            )
        }
        "transports" => (
            path,
            "top-level `transports` is not a config section; use `[bridges]` (enabled, lines, transport_path/transport_dir for lyrebird, snowflake_path/snowflake_dir for snowflake-client, dnstt_path/dnstt_dir for dnstt-client, lyrebird_transports).",
        ),
        "onion_services.client_auth" => (
            path,
            "onion service client authorization is not exposed yet (planned). Use `onion.*` IPC methods for hosted service management.",
        ),
        _ => return None,
    };
    Some(format!(
        "unsupported config knob `{knob}`: {explanation} Unsupported knobs are rejected and never silently ignored; remove this field from the config/patch."
    ))
}

/// Reject known unsupported knobs in a JSON config patch with explicit errors.
pub fn check_unsupported_knobs(patch: &serde_json::Value) -> Result<(), String> {
    fn walk(prefix: &str, value: &serde_json::Value, matches: &mut Vec<(String, String)>) {
        if let Some(err) = unsupported_knob_error(prefix) {
            matches.push((prefix.to_owned(), err));
        }
        if let serde_json::Value::Object(map) = value {
            for (key, child) in map {
                let path = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                walk(&path, child, matches);
            }
        }
    }

    let mut matches = Vec::new();
    if let serde_json::Value::Object(map) = patch {
        for (key, child) in map {
            walk(key, child, &mut matches);
        }
    }
    // Keep the most specific match when one path is an ancestor of another.
    let errors = matches
        .iter()
        .filter(|(path, _)| {
            !matches
                .iter()
                .any(|(other, _)| other != path && other.starts_with(&format!("{path}.")))
        })
        .map(|(_, err)| err.clone())
        .collect::<Vec<_>>();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("\n"))
    }
}

/// Human-readable summary of node restriction and stream/network support (for UI/diagnostics).
pub fn node_restrictions_support_summary() -> &'static str {
    "Supported network controls (current build): stream isolation (F-42/F-43) in [stream]; exit country (ISO 3166-1 alpha-2, requires Arti geoip) and IPv6/IP version preference (F-44) as default StreamPrefs in [network]. C Tor-style entry/exit/exclude/strict node lists are not exposed by the pinned Arti APIs. Unsupported knobs are hidden in the UI and rejected by config validation/import (never silently ignored)."
}

impl Config {
    /// Save config to `path` atomically (write temp file, then rename).
    pub fn save(&self, path: &Path) -> Result<(), ConfigError> {
        self.validate()?;
        let parent = path.parent().ok_or_else(|| {
            ConfigError::Invalid(format!("config path has no parent: {}", path.display()))
        })?;
        fs::create_dir_all(parent).map_err(|source| ConfigError::Io {
            path: parent.to_path_buf(),
            source,
        })?;

        let text = toml::to_string_pretty(self)?;
        let tmp = path.with_extension("toml.tmp");
        {
            let mut file = fs::File::create(&tmp).map_err(|source| ConfigError::Io {
                path: tmp.clone(),
                source,
            })?;
            file.write_all(text.as_bytes())
                .map_err(|source| ConfigError::Io {
                    path: tmp.clone(),
                    source,
                })?;
            file.sync_all().map_err(|source| ConfigError::Io {
                path: tmp.clone(),
                source,
            })?;
        }
        fs::rename(&tmp, path).map_err(|source| ConfigError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn default_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        let dir = TempDir::new()?;
        let path = dir.path().join("config.toml");
        let config = Config::default();
        config.save(&path)?;
        let loaded = Config::load(&path)?;
        assert_eq!(loaded, config);
        Ok(())
    }

    #[test]
    fn load_missing_returns_default() -> Result<(), Box<dyn std::error::Error>> {
        let dir = TempDir::new()?;
        let path = dir.path().join("missing.toml");
        let loaded = Config::load_or_default(&path)?;
        assert_eq!(loaded, Config::default());
        Ok(())
    }

    #[test]
    fn outbound_keychain_mode_validates() {
        let mut config = Config::default();
        config.outbound_proxy.proxy_type = OutboundProxyType::Shadowsocks;
        config.outbound_proxy.host = "10.20.30.40".to_owned();
        config.outbound_proxy.port = 8388;
        // Shadowsocks without plaintext secret and without keychain → error.
        assert!(config.validate().is_err());
        // Keychain mode may omit the plaintext secret.
        config.outbound_proxy.password_keychain = true;
        assert!(config.validate().is_ok());
        // Keychain mode must not coexist with a plaintext secret.
        config.outbound_proxy.shadowsocks_password = "ss-pass".to_owned();
        assert!(config.validate().is_err());
        config.outbound_proxy.shadowsocks_password = String::new();
        config.outbound_proxy.password = "proxy-pass".to_owned();
        assert!(config.validate().is_err());
    }

    #[test]
    fn outbound_keychain_marker_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        let dir = TempDir::new()?;
        let path = dir.path().join("config.toml");
        let mut config = Config::default();
        config.outbound_proxy.proxy_type = OutboundProxyType::Socks5;
        config.outbound_proxy.host = "10.20.30.40".to_owned();
        config.outbound_proxy.port = 1080;
        config.outbound_proxy.password_keychain = true;
        config.save(&path)?;
        let loaded = Config::load(&path)?;
        assert!(loaded.outbound_proxy.password_keychain);
        Ok(())
    }

    #[test]
    fn kindness_defaults_are_disabled_and_validate() {
        let kindness = KindnessConfig::default();
        assert!(!kindness.is_active());
        assert!(kindness.validate().is_ok());
        // Limit defaults: metered pause on, charging pause off.
        assert!(kindness.pause_on_metered);
        assert!(!kindness.pause_when_not_charging);
    }

    #[test]
    fn kindness_limit_flags_parse_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let dir = TempDir::new()?;
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            "version = 1\n[kindness]\npause_on_metered = false\npause_when_not_charging = true\n",
        )?;
        let config = Config::load(&path)?;
        assert!(!config.kindness.pause_on_metered);
        assert!(config.kindness.pause_when_not_charging);
        // Older configs without limit keys get the defaults.
        std::fs::write(&path, "version = 1\n[kindness]\n")?;
        let legacy = Config::load(&path)?;
        assert!(legacy.kindness.pause_on_metered);
        assert!(!legacy.kindness.pause_when_not_charging);
        Ok(())
    }

    #[test]
    fn kindness_parses_section_and_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        let dir = TempDir::new()?;
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            r#"
version = 1
[kindness]
enabled = true
relay_url = "wss://relay.example.com/"
capacity = 5
verbose = true
extra_args = ["-allow-non-tls-relay"]
"#,
        )?;
        let config = Config::load(&path)?;
        assert!(config.kindness.is_active());
        assert_eq!(
            config.kindness.relay_url.as_deref(),
            Some("wss://relay.example.com/")
        );
        assert_eq!(config.kindness.capacity, Some(5));
        assert!(config.kindness.verbose);
        assert_eq!(config.kindness.extra_args, vec!["-allow-non-tls-relay"]);
        config.validate()?;
        // Section without `kindness` keys still loads (older configs).
        std::fs::write(&path, "version = 1\n")?;
        let minimal = Config::load(&path)?;
        assert!(!minimal.kindness.is_active());
        Ok(())
    }

    #[test]
    fn kindness_ephemeral_ports_validate_and_round_trip() -> Result<(), Box<dyn std::error::Error>>
    {
        let dir = TempDir::new()?;
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            "version = 1\n[kindness]\nephemeral_ports = \"30000:30999\"\n",
        )?;
        let config = Config::load(&path)?;
        assert_eq!(config.kindness.parse_ephemeral_ports(), Ok((30000, 30999)));
        config.validate()?;

        // Invalid values are rejected with the upstream format in the message.
        for bad in [
            "30000",
            "31000:30000",
            "abc:40000",
            "30000:abc",
            "0:40000",
            " ",
            "30000::40000",
        ] {
            let mut config = Config::default();
            config.kindness.ephemeral_ports = Some(bad.to_owned());
            let err = config
                .validate()
                .expect_err("invalid ephemeral_ports must be rejected");
            assert!(err.to_string().contains("ephemeral_ports"), "{bad}: {err}");
        }
        // Whitespace around bounds is accepted (trimmed upstream passthrough).
        let mut config = Config::default();
        config.kindness.ephemeral_ports = Some(" 30000 : 31000 ".to_owned());
        assert!(config.validate().is_ok());
        assert_eq!(config.kindness.parse_ephemeral_ports(), Ok((30000, 31000)));
        Ok(())
    }

    #[test]
    fn kindness_validates_capacity_and_digest_and_urls() {
        let mut config = Config::default();
        config.kindness.enabled = true;
        config.kindness.capacity = Some(0);
        assert!(config.validate().is_err());

        let mut config = Config::default();
        config.kindness.sha256_hex = Some("abc".to_owned());
        assert!(config.validate().is_err());

        let mut config = Config::default();
        config.kindness.sha256_hex = Some("ABC".repeat(21) + "d"); // 64 uppercase hex
        assert!(config.validate().is_err());

        let mut config = Config::default();
        config.kindness.relay_url = Some("wss://relay with space.example/".to_owned());
        assert!(config.validate().is_err());

        let mut config = Config::default();
        config.kindness.broker_url = Some(" ".to_owned());
        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_port_conflict() {
        let mut config = Config::default();
        config.proxy.dns_port = config.proxy.socks_port;
        let err = config.validate();
        assert!(matches!(err, Err(ConfigError::Invalid(_))));
        if let Err(ConfigError::Invalid(message)) = err {
            assert!(message.contains("must differ"));
        }
    }

    #[test]
    fn http_port_zero_follows_socks_port() -> Result<(), Box<dyn std::error::Error>> {
        let mut config = Config::default();
        config.proxy.socks_port = 19050;
        config.proxy.http_port = 0;
        config
            .validate()
            .map_err(|e| format!("valid when http follows socks: {e}"))?;
        assert_eq!(config.proxy.effective_http_port(), 19050);
        Ok(())
    }

    #[test]
    fn rejects_split_http_port_until_supported() {
        let mut config = Config::default();
        config.proxy.http_port = 8118;
        let err = config.validate();
        assert!(matches!(err, Err(ConfigError::Invalid(_))));
        if let Err(ConfigError::Invalid(message)) = err {
            assert!(message.contains("http_port"));
            assert!(message.contains("same local listener"));
        }
    }

    #[test]
    fn loads_config_without_http_port() -> Result<(), Box<dyn std::error::Error>> {
        let dir = TempDir::new()?;
        let path = dir.path().join("config.toml");
        fs::write(
            &path,
            r#"
version = 1

[general]
start_on_login = false

[proxy]
socks_port = 19050
dns_port = 19053

[logging]
level = "info"
"#,
        )?;
        let loaded = Config::load(&path)?;
        assert_eq!(loaded.proxy.socks_port, 19050);
        assert_eq!(loaded.proxy.dns_port, 19053);
        assert_eq!(loaded.proxy.effective_http_port(), 19050);
        Ok(())
    }

    #[test]
    fn next_available_port_finds_candidate() -> Result<(), Box<dyn std::error::Error>> {
        let port = next_available_port(65530, |p| p == 65531).ok_or("expected a candidate port")?;
        assert_eq!(port, 65531);
        Ok(())
    }

    #[test]
    fn udp_port_availability_reflects_bind() -> Result<(), Box<dyn std::error::Error>> {
        let socket = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
        let port = socket.local_addr()?.port();
        assert!(!udp_port_available(port));
        drop(socket);
        // After release the port should usually become available; this is a
        // best-effort check and not asserted to avoid flakiness on all OSes.
        let _ = udp_port_available(port);
        Ok(())
    }

    #[test]
    fn port_conflicts_reports_dns_udp_in_use() -> Result<(), Box<dyn std::error::Error>> {
        let socket = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
        let dns_port = socket.local_addr()?.port();
        // Keep socks/http on ports that are very likely free by probing.
        let socks_port = next_available_port(40000, tcp_port_available).unwrap_or(19050);
        let proxy = ProxyConfig {
            socks_port,
            http_port: 0,
            dns_port,
            bind_all_interfaces: false,
        };
        let conflicts = port_conflicts(&proxy);
        assert!(
            conflicts
                .iter()
                .any(|c| c.contains("proxy.dns_port") && c.contains("DNS UDP")),
            "expected DNS conflict, got: {conflicts:?}"
        );
        Ok(())
    }

    #[test]
    fn rejects_unknown_fields() -> Result<(), Box<dyn std::error::Error>> {
        let dir = TempDir::new()?;
        let path = dir.path().join("config.toml");
        fs::write(&path, "version = 1\nnope = true\n")?;
        let err = Config::load(&path);
        assert!(matches!(err, Err(ConfigError::Parse { .. })));
        Ok(())
    }

    #[test]
    fn rejects_known_unsupported_node_restriction_knobs() {
        let patch = serde_json::json!({ "tor": { "exit_nodes": "{us}" } });
        let err = check_unsupported_knobs(&patch).expect_err("must reject unsupported knob");
        assert!(err.contains("unsupported config knob"));
        assert!(err.contains("tor"));
        assert!(err.contains("never silently ignored"));
    }

    #[test]
    fn accepts_supported_network_patch() -> Result<(), Box<dyn std::error::Error>> {
        let patch = serde_json::json!({ "network": { "exit_country": "US", "ip_version": "ipv6_preferred" } });
        check_unsupported_knobs(&patch)
            .map_err(|e| format!("supported network patch rejected: {e}"))?;
        let mut cfg = Config::default();
        let merged = serde_json::json!({
            "version": cfg.version,
            "general": cfg.general,
            "proxy": cfg.proxy,
            "network": patch["network"].clone(),
            "stream": cfg.stream,
            "bridges": cfg.bridges,
            "onion_services": cfg.onion_services,
            "logging": cfg.logging,
        });
        cfg = serde_json::from_value(merged)?;
        cfg.validate()?;
        assert_eq!(cfg.network.normalized_exit_country().as_deref(), Some("us"));
        assert_eq!(cfg.network.ip_version, IpVersionPreference::Ipv6Preferred);
        assert!(cfg.network.has_stream_prefs());
        Ok(())
    }

    #[test]
    fn rejects_invalid_exit_country() {
        let mut cfg = Config::default();
        cfg.network.exit_country = Some("USA".to_owned());
        let err = cfg.validate();
        assert!(matches!(err, Err(ConfigError::Invalid(_))));
        if let Err(ConfigError::Invalid(msg)) = err {
            assert!(msg.contains("alpha-2"));
        }
    }

    #[test]
    fn normalizes_exit_country_and_network_stream_prefs() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut cfg = Config::default();
        assert!(!cfg.network.has_stream_prefs());
        cfg.network.exit_country = Some(" De ".to_owned());
        cfg.validate()?;
        assert_eq!(cfg.network.normalized_exit_country().as_deref(), Some("de"));
        assert!(cfg.network.has_stream_prefs());
        cfg.network.exit_country = Some("   ".to_owned());
        assert_eq!(cfg.network.normalized_exit_country(), None);
        assert!(!cfg.network.has_stream_prefs());
        cfg.network.ip_version = IpVersionPreference::Ipv6Only;
        assert!(cfg.network.has_stream_prefs());
        Ok(())
    }

    #[test]
    fn network_ip_version_variants_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let dir = TempDir::new()?;
        let path = dir.path().join("config.toml");
        for ip in [
            IpVersionPreference::Ipv4Preferred,
            IpVersionPreference::Ipv6Preferred,
            IpVersionPreference::Ipv4Only,
            IpVersionPreference::Ipv6Only,
        ] {
            let mut config = Config::default();
            config.network.ip_version = ip;
            config.network.exit_country = Some("nl".to_owned());
            config.save(&path)?;
            let loaded = Config::load(&path)?;
            assert_eq!(loaded.network.ip_version, ip);
            assert_eq!(
                loaded.network.normalized_exit_country().as_deref(),
                Some("nl")
            );
        }
        Ok(())
    }

    #[test]
    fn rejects_unsupported_network_sub_knobs_but_allows_network_section() {
        for key in ["network.geoip", "network.stream_prefs"] {
            let patch = match key {
                "network.geoip" => serde_json::json!({ "network": { "geoip": true } }),
                _ => serde_json::json!({ "network": { "stream_prefs": {} } }),
            };
            let err =
                check_unsupported_knobs(&patch).expect_err("must reject unsupported sub-knob");
            assert!(err.contains("unsupported config knob"), "{err}");
            assert!(err.contains("never silently ignored"), "{err}");
        }
        check_unsupported_knobs(&serde_json::json!({
            "network": { "exit_country": "US", "ip_version": "ipv4_only" }
        }))
        .expect("supported network fields must be accepted");
    }

    #[test]
    fn allows_supported_patch_fields() -> Result<(), Box<dyn std::error::Error>> {
        let patch =
            serde_json::json!({ "proxy": { "socks_port": 9050, "bind_all_interfaces": false } });
        check_unsupported_knobs(&patch).map_err(|e| format!("supported patch rejected: {e}"))?;
        Ok(())
    }

    #[test]
    fn accepts_stream_isolation_patch() -> Result<(), Box<dyn std::error::Error>> {
        let patch = serde_json::json!({
            "stream": {
                "isolate_destination": true,
                "isolate_port": true,
                "isolate_protocol": false,
                "keep_alive_isolation": true
            }
        });
        check_unsupported_knobs(&patch).map_err(|e| format!("stream patch rejected: {e}"))?;
        let dir = TempDir::new()?;
        let path = dir.path().join("config.toml");
        Config::default().save(&path)?;
        let mut merged = serde_json::to_value(Config::load(&path)?)?;
        if let (Some(base), Some(p)) = (merged.as_object_mut(), patch.as_object()) {
            base.insert("stream".to_owned(), p["stream"].clone());
        }
        let next: Config = serde_json::from_value(merged)?;
        next.validate()?;
        assert!(next.stream.isolate_destination);
        assert!(next.stream.isolate_port);
        assert!(next.stream.keep_alive_isolation);
        assert!(next.stream.needs_isolation_frontend());
        assert!(next.stream.isolation_summary().contains("destination"));
        Ok(())
    }

    #[test]
    fn stream_config_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        let dir = TempDir::new()?;
        let path = dir.path().join("config.toml");
        let mut config = Config::default();
        config.stream.isolate_destination = true;
        config.stream.keep_alive_isolation = true;
        config.save(&path)?;
        let loaded = Config::load(&path)?;
        assert_eq!(loaded.stream, config.stream);
        Ok(())
    }

    #[test]
    fn bridges_config_defaults_and_validation() -> Result<(), Box<dyn std::error::Error>> {
        let cfg = Config::default();
        assert!(!cfg.bridges.enabled);
        assert!(!cfg.bridges.is_active());
        assert!(cfg.bridges.lyrebird_transports.iter().any(|t| t == "obfs4"));
        assert!(
            cfg.bridges
                .lyrebird_transports
                .iter()
                .any(|t| t == "webtunnel")
        );
        assert!(
            cfg.bridges
                .lyrebird_transports
                .iter()
                .any(|t| t == "meek_lite")
        );
        Ok(())
    }

    #[test]
    fn bridges_enabled_requires_lines() {
        let mut cfg = Config::default();
        cfg.bridges.enabled = true;
        let err = cfg.validate().expect_err("must reject");
        match err {
            ConfigError::Invalid(msg) => assert!(msg.contains("bridges.enabled"), "{msg}"),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn bridges_round_trip_in_toml() -> Result<(), Box<dyn std::error::Error>> {
        let dir = TempDir::new()?;
        let path = dir.path().join("config.toml");
        let mut config = Config::default();
        config.bridges.enabled = true;
        config.bridges.lines = vec![
            "obfs4 192.0.2.1:443 316E643333645F6D79216558614D3931657A5F5F cert=abcd iat-mode=0".to_owned(),
            "Bridge webtunnel 192.0.2.2:443 316E643333645F6D79216558614D3931657A5F5F url=https://example.com/ ver=0.0.1".to_owned(),
        ];
        config.bridges.transport_path = Some("/usr/bin/lyrebird".to_owned());
        config.save(&path)?;
        let loaded = Config::load(&path)?;
        assert!(loaded.bridges.enabled);
        assert_eq!(loaded.bridges.normalized_lines().len(), 2);
        assert_eq!(
            loaded.bridges.transport_path.as_deref(),
            Some("/usr/bin/lyrebird")
        );
        Ok(())
    }
}
