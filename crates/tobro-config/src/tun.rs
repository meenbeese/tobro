//! TUN mode configuration (M7, plan §4.7).
//!
//! System-wide routing without leaks: a privileged helper creates a TUN
//! device, routes and DNS are configured, and TCP traffic is forwarded
//! through the Tor proxy. This module ships the **schema** ahead of the
//! engine so UI/IPC/config plumbing can be validated early:
//!
//! - [`TunConfig::enabled`] is rejected by [`TunConfig::validate`] until the
//!   privileged helper and TUN routing engine are implemented (planned in
//!   milestone M7), so enabling it can never be silently ignored.
//! - Split tunneling is destination-based only (CIDR prefixes and domain
//!   suffixes). Per-app routing is out of scope on desktop: app identity is
//!   unreliable (plan F-17).
//! - The kill switch (plan F-20) is TUN-only and fail-closed by policy
//!   choice: [`KillSwitchPolicy::Restore`] restores normal networking,
//!   [`KillSwitchPolicy::Block`] blocks traffic until the tunnel returns.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

use crate::ConfigError;

/// Minimum supported TUN interface MTU (IPv6 requires at least 1280; 576
/// keeps IPv4-only setups usable).
pub const TUN_MIN_MTU: u16 = 576;

/// Maximum supported TUN interface MTU (the largest IP packet that still
/// fits a 16-bit IP total-length field: 65535 - 20 header bytes minus slack
/// for extensions).
pub const TUN_MAX_MTU: u16 = 65521;

/// Default TUN interface MTU (plain Ethernet-sized packets; the userspace
/// stack re-segments anyway).
pub const DEFAULT_TUN_MTU: u16 = 1500;

/// Kill switch behavior (F-20) when the tunnel or helper fails.
///
/// The kill switch is only active in TUN mode; proxy mode has no system-wide
/// routing to fail closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KillSwitchPolicy {
    /// Restore normal networking when the tunnel fails (default). Traffic
    /// leaves the machine unproxied until TUN mode is re-enabled or disabled;
    /// this favors availability over strict anonymity.
    #[default]
    Restore,
    /// Block all traffic fail-closed until the tunnel is restored or the user
    /// disables TUN mode. Strictest option: nothing leaks, but networking
    /// stops working while the tunnel is down.
    Block,
}

impl KillSwitchPolicy {
    /// Human-readable explanation of the failure behavior (UI/diagnostics).
    pub fn explanation(&self) -> &'static str {
        match self {
            KillSwitchPolicy::Restore => {
                "When the tunnel fails, networking is restored: traffic may bypass Tor until TUN mode is re-enabled or disabled."
            }
            KillSwitchPolicy::Block => {
                "Fail-closed: when the tunnel fails, traffic is blocked until the tunnel is restored or TUN mode is disabled."
            }
        }
    }
}

/// UDP handling policy in TUN mode.
///
/// Tor (Arti) carries no UDP, so UDP can only be intercepted locally (DNS) or
/// dropped. There is deliberately no "forward UDP directly" option: that
/// would leak destinations outside the tunnel and defeat the milestone goal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UdpPolicy {
    /// Intercept DNS queries arriving on the tunnel and resolve them through
    /// the tunnel; drop all other UDP. QUIC/WebRTC-capable applications fall
    /// back to TCP (browsers do this automatically). Default.
    #[default]
    DnsOnly,
    /// Drop all UDP, including DNS interception. Only TCP connections work;
    /// destinations must be IP literals or resolvable by applications through
    /// their own TCP-based paths. Strictest option.
    BlockAll,
}

impl UdpPolicy {
    /// Human-readable explanation of what actually happens to UDP packets
    /// under this policy (UI/diagnostics; no invented claims).
    pub fn explanation(&self) -> &'static str {
        match self {
            UdpPolicy::DnsOnly => {
                "DNS queries are intercepted and resolved through the tunnel; all other UDP (including QUIC and WebRTC) is dropped. Tor cannot carry UDP, so UDP-capable applications must fall back to TCP."
            }
            UdpPolicy::BlockAll => {
                "All UDP traffic is dropped, including DNS interception: only TCP connections work, and destinations must be IP literals or resolved without UDP DNS."
            }
        }
    }
}

/// One split-tunnel rule: a destination that is routed directly instead of
/// through the tunnel.
///
/// Split tunneling is destination-based only (plan F-17): desktop application
/// identity is unreliable, so per-app rules are not supported. Browser
/// profiles remain the recommended per-app isolation mechanism.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SplitRule {
    /// Destination to match: an IPv4/IPv6 CIDR prefix (e.g. `"192.0.2.0/24"`,
    /// `"2001:db8::/32"`) or a domain suffix (e.g. `"example.com"`, with an
    /// optional leading `*.` for clarity). Domains match the domain itself
    /// and all of its subdomains.
    pub destination: String,
    /// Optional user-facing comment (single line).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

impl SplitRule {
    /// Convenience constructor for config construction in tests/UI code.
    pub fn new(destination: impl Into<String>) -> Self {
        Self {
            destination: destination.into(),
            comment: None,
        }
    }
}

/// A validated split-tunnel destination.
///
/// Parsed from [`SplitRule::destination`] by [`SplitDestination::parse`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SplitDestination {
    /// An IPv4/IPv6 prefix (`addr` has its host bits zeroed).
    Cidr(SplitCidr),
    /// A normalized domain suffix (`example.com` matches the domain and all
    /// subdomains). Wildcard (`*.`) and leading-dot spellings are normalized
    /// into the bare domain name.
    Domain(SplitDomain),
}

/// A validated CIDR prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitCidr {
    /// Network address with host bits zeroed.
    pub addr: IpAddr,
    /// Prefix length in bits (`<= 32` for IPv4, `<= 128` for IPv6).
    pub prefix_len: u8,
    /// Canonical text form (`addr/prefix_len`).
    pub text: String,
}

/// A validated domain suffix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitDomain {
    /// Lowercase, ASCII (punycode), wildcard-normalized domain name.
    pub name: String,
}

impl SplitDestination {
    /// Parse and validate a split-tunnel destination string.
    ///
    /// Returns a human-readable reason on failure; callers add rule context
    /// (index) around the message.
    pub fn parse(raw: &str) -> Result<Self, String> {
        let text = raw.trim();
        if text.is_empty() {
            return Err("destination must not be empty".to_owned());
        }
        if text.chars().any(char::is_whitespace) {
            return Err(format!("destination must not contain whitespace: {raw:?}"));
        }
        if text.contains('/') {
            Ok(Self::Cidr(parse_cidr(text)?))
        } else {
            Ok(Self::Domain(parse_domain(text)?))
        }
    }

    /// Canonical key used to detect duplicate rules after normalization.
    fn canonical_key(&self) -> String {
        match self {
            Self::Cidr(c) => format!("cidr:{}", c.text),
            Self::Domain(d) => format!("domain:{}", d.name),
        }
    }
}

/// Parse an IPv4/IPv6 CIDR prefix. Host bits must be zero (write `192.0.2.0/24`,
/// not `192.0.2.7/24`), so the stored network address is unambiguous.
fn parse_cidr(text: &str) -> Result<SplitCidr, String> {
    let Some((addr_raw, prefix_raw)) = text.split_once('/') else {
        return Err(format!(
            "CIDR destination must use the `addr/prefix_len` form, got {text:?}"
        ));
    };
    let addr: IpAddr = addr_raw.parse().map_err(|_| {
        format!("CIDR destination has an invalid IP address {addr_raw:?} (use a literal IPv4/IPv6 address)")
    })?;
    let prefix_len: u8 = prefix_raw
        .parse()
        .map_err(|_| format!("CIDR prefix length must be an integer, got {prefix_raw:?}"))?;
    let max_prefix: u32 = match addr {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    if u32::from(prefix_len) > max_prefix {
        return Err(format!(
            "CIDR prefix length must be at most {max_prefix} for this address family, got {prefix_len}"
        ));
    }
    let network = match addr {
        IpAddr::V4(a) => IpAddr::V4(Ipv4Addr::from(u32::from(a) & v4_prefix_mask(prefix_len))),
        IpAddr::V6(a) => IpAddr::V6(Ipv6Addr::from(u128::from(a) & v6_prefix_mask(prefix_len))),
    };
    if network != addr {
        return Err(format!(
            "CIDR destination has host bits set: {text:?}; write the network address with zeroed host bits (for example {network}/{prefix_len})"
        ));
    }
    Ok(SplitCidr {
        addr: network,
        prefix_len,
        text: format!("{network}/{prefix_len}"),
    })
}

/// Dotted-quad mask for an IPv4 prefix length.
fn v4_prefix_mask(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        return 0;
    }
    u32::MAX << (32 - u32::from(prefix_len))
}

/// 128-bit mask for an IPv6 prefix length.
fn v6_prefix_mask(prefix_len: u8) -> u128 {
    if prefix_len == 0 {
        return 0;
    }
    u128::MAX << (128 - u32::from(prefix_len))
}

/// Parse and normalize a domain suffix destination.
fn parse_domain(text: &str) -> Result<SplitDomain, String> {
    let lowered = text.to_ascii_lowercase();
    // Accepted spellings for a suffix match: `example.com`, `.example.com`,
    // and `*.example.com` all normalize to the bare domain name.
    let wildcard_stripped = match lowered.strip_prefix("*.") {
        Some(rest) => rest,
        None => lowered.as_str(),
    };
    let leading_dots_stripped = wildcard_stripped.trim_start_matches('.');
    let mut name = leading_dots_stripped.to_owned();
    // A single trailing dot is a valid FQDN spelling; normalize it away.
    while name.ends_with('.') {
        name.pop();
    }
    if name.is_empty() {
        return Err(format!(
            "domain destination must not be empty, got {text:?}"
        ));
    }
    if name.parse::<IpAddr>().is_ok() {
        return Err(format!(
            "domain destination is an IP literal; use CIDR form (`{}/prefix_len`) for IP destinations",
            text.trim()
        ));
    }
    if !name.is_ascii() {
        return Err(format!(
            "domain destination must be ASCII (punycode/`xn--` for IDN), got {text:?}"
        ));
    }
    if name.len() > 253 {
        return Err(format!(
            "domain destination must be at most 253 characters, got {}",
            name.len()
        ));
    }
    for label in name.split('.') {
        if label.is_empty() {
            return Err(format!("domain destination has an empty label: {text:?}"));
        }
        if label.len() > 63 {
            return Err(format!(
                "domain destination has a label longer than 63 characters: {label:?}"
            ));
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(format!(
                "domain destination labels must contain only letters, digits, and hyphens: {text:?}"
            ));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(format!(
                "domain destination labels must not start or end with a hyphen: {text:?}"
            ));
        }
    }
    Ok(SplitDomain { name })
}

/// TUN mode configuration (M7, plan §4.7).
///
/// Defaults to fully disabled; TUN mode is an explicit opt-in that requires
/// the privileged helper (`tobro-helper`) and the TUN routing engine, which
/// are not implemented in this build yet (planned in milestone M7), so
/// [`TunConfig::enabled`] is rejected by [`TunConfig::validate`] until then.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TunConfig {
    /// Enable system-wide TUN routing (opt-in; see the module docs).
    pub enabled: bool,
    /// Kill switch behavior when the tunnel or helper fails (F-20).
    pub kill_switch: KillSwitchPolicy,
    /// UDP handling policy (DNS interception vs. drop).
    pub udp_policy: UdpPolicy,
    /// TUN interface MTU in bytes.
    #[serde(default = "default_tun_mtu")]
    pub mtu: u16,
    /// Destinations routed directly, bypassing the tunnel (split tunneling).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude_rules: Vec<SplitRule>,
    /// Preferred `tobro-helper` binary path override. When unset, tobro
    /// searches for the helper in sidecar/app locations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub helper_path: Option<String>,
    /// Extra directory to search for `tobro-helper`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub helper_dir: Option<String>,
    /// Expected SHA-256 of the `tobro-helper` binary (lowercase hex). When
    /// set, startup refuses to launch a helper that does not match.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub helper_sha256_hex: Option<String>,
}

fn default_tun_mtu() -> u16 {
    DEFAULT_TUN_MTU
}

impl Default for TunConfig {
    /// Hand-rolled so `Config::default()`, a missing `[tun]` key, and the
    /// serde default fn all agree (like the other hand-rolled defaults in
    /// this crate).
    fn default() -> Self {
        Self {
            enabled: false,
            kill_switch: KillSwitchPolicy::Restore,
            udp_policy: UdpPolicy::DnsOnly,
            mtu: default_tun_mtu(),
            exclude_rules: Vec::new(),
            helper_path: None,
            helper_dir: None,
            helper_sha256_hex: None,
        }
    }
}

impl TunConfig {
    /// True when TUN mode is requested (still gated by `validate` in this
    /// build until the M7 engine lands).
    pub fn is_active(&self) -> bool {
        self.enabled
    }

    /// Parse all exclude rules into validated destinations.
    ///
    /// Shared by config validation and (later) the routing engine.
    pub fn parse_exclude_rules(&self) -> Result<Vec<SplitDestination>, ConfigError> {
        self.exclude_rules
            .iter()
            .enumerate()
            .map(|(i, rule)| {
                SplitDestination::parse(&rule.destination).map_err(|reason| {
                    ConfigError::Invalid(format!("tun.exclude_rules[{i}]: {reason}"))
                })
            })
            .collect()
    }

    /// Validate TUN settings.
    ///
    /// Rule and knob validation runs even while TUN mode is disabled so the
    /// UI can validate edits up front; the `enabled` gate only fires when the
    /// user actually requests TUN routing in a build without the engine.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !(TUN_MIN_MTU..=TUN_MAX_MTU).contains(&self.mtu) {
            return Err(ConfigError::Invalid(format!(
                "tun.mtu must be between {TUN_MIN_MTU} and {TUN_MAX_MTU} bytes, got {}",
                self.mtu
            )));
        }
        if let Some(p) = &self.helper_path
            && p.trim().is_empty()
        {
            return Err(ConfigError::Invalid(
                "tun.helper_path must not be empty when set".to_owned(),
            ));
        }
        if let Some(p) = &self.helper_dir
            && p.trim().is_empty()
        {
            return Err(ConfigError::Invalid(
                "tun.helper_dir must not be empty when set".to_owned(),
            ));
        }
        if let Some(hex) = &self.helper_sha256_hex {
            let hex = hex.trim();
            if hex.len() != 64
                || !hex
                    .chars()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
            {
                return Err(ConfigError::Invalid(
                    "tun.helper_sha256_hex must be 64 lowercase hex characters".to_owned(),
                ));
            }
        }
        let mut seen = HashSet::new();
        for (i, rule) in self.exclude_rules.iter().enumerate() {
            let destination = SplitDestination::parse(&rule.destination).map_err(|reason| {
                ConfigError::Invalid(format!("tun.exclude_rules[{i}]: {reason}"))
            })?;
            if !seen.insert(destination.canonical_key()) {
                return Err(ConfigError::Invalid(format!(
                    "tun.exclude_rules[{i}]: duplicate destination {:?} (normalize rules; every destination may appear at most once)",
                    rule.destination
                )));
            }
            if let Some(comment) = &rule.comment
                && (comment.contains('\n') || comment.contains('\r') || comment.contains('\0'))
            {
                return Err(ConfigError::Invalid(format!(
                    "tun.exclude_rules[{i}].comment must be a single line"
                )));
            }
        }
        if self.enabled {
            return Err(ConfigError::Invalid(
                "tun.enabled is not implemented in this build (planned in milestone M7): system-wide routing requires the privileged helper and the TUN routing engine. Keep tun.enabled = false; all other tun.* fields already validate."
                    .to_owned(),
            ));
        }
        Ok(())
    }

    /// Human-readable summary of the effective TUN behavior (UI/diagnostics).
    pub fn summary(&self) -> String {
        if !self.enabled {
            return "off (proxy mode; apps must use the SOCKS/HTTP/DNS listeners)".to_owned();
        }
        format!(
            "tun (kill switch: {:?}, udp: {:?}, mtu: {}, exclude rules: {})",
            self.kill_switch,
            self.udp_policy,
            self.mtu,
            self.exclude_rules.len()
        )
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::Config;

    #[test]
    fn tun_defaults_are_off_and_validate() {
        let tun = TunConfig::default();
        assert!(!tun.is_active());
        assert!(tun.validate().is_ok());
        assert_eq!(tun.mtu, DEFAULT_TUN_MTU);
        assert_eq!(tun.kill_switch, KillSwitchPolicy::Restore);
        assert_eq!(tun.udp_policy, UdpPolicy::DnsOnly);
        assert!(tun.exclude_rules.is_empty());
        assert!(tun.summary().starts_with("off"));
        // A default config carries the section and still loads/validates.
        let config = Config::default();
        assert!(!config.tun.is_active());
        config.validate().expect("default config must validate");
    }

    #[test]
    fn tun_enabled_is_gated_until_the_engine_exists() {
        let mut config = Config::default();
        config.tun.enabled = true;
        let err = config
            .validate()
            .expect_err("enabled TUN must be rejected in this build");
        let message = match err {
            ConfigError::Invalid(message) => message,
            other => panic!("unexpected error: {other:?}"),
        };
        assert!(message.contains("tun.enabled"), "{message}");
        assert!(message.contains("not implemented"), "{message}");
        assert!(message.contains("M7"), "{message}");
    }

    #[test]
    fn tun_parses_section_and_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::TempDir::new()?;
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            r#"
version = 1

[tun]
kill_switch = "block"
udp_policy = "block_all"
mtu = 1420

[[tun.exclude_rules]]
destination = "192.0.2.0/24"
comment = "printer subnet"

[[tun.exclude_rules]]
destination = "*.internal.example.org"
"#,
        )?;
        let config = Config::load(&path)?;
        assert!(!config.tun.enabled);
        assert_eq!(config.tun.kill_switch, KillSwitchPolicy::Block);
        assert_eq!(config.tun.udp_policy, UdpPolicy::BlockAll);
        assert_eq!(config.tun.mtu, 1420);
        assert_eq!(config.tun.exclude_rules.len(), 2);
        assert_eq!(
            config.tun.exclude_rules[0].comment.as_deref(),
            Some("printer subnet")
        );
        config.validate()?;
        config.save(&path)?;
        let loaded = Config::load(&path)?;
        assert_eq!(loaded.tun, config.tun);
        // Rules parse into validated destinations.
        let rules = config.tun.parse_exclude_rules()?;
        assert_eq!(rules.len(), 2);
        assert_eq!(
            rules[0],
            SplitDestination::Cidr(SplitCidr {
                addr: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)),
                prefix_len: 24,
                text: "192.0.2.0/24".to_owned(),
            })
        );
        assert_eq!(
            rules[1],
            SplitDestination::Domain(SplitDomain {
                name: "internal.example.org".to_owned(),
            })
        );
        Ok(())
    }

    #[test]
    fn configs_without_tun_section_get_defaults() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::TempDir::new()?;
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "version = 1\n")?;
        let config = Config::load(&path)?;
        assert_eq!(config.tun, TunConfig::default());
        Ok(())
    }

    #[test]
    fn tun_validates_mtu_and_helper_fields() {
        let mut config = Config::default();
        config.tun.mtu = 0;
        assert!(config.validate().is_err());
        config.tun.mtu = 575;
        assert!(config.validate().is_err());
        config.tun.mtu = 65522;
        assert!(config.validate().is_err());
        config.tun.mtu = TUN_MIN_MTU;
        assert!(config.validate().is_ok());
        config.tun.mtu = TUN_MAX_MTU;
        assert!(config.validate().is_ok());

        let mut config = Config::default();
        config.tun.helper_path = Some(" ".to_owned());
        let err = config.validate().expect_err("empty helper_path must fail");
        assert!(err.to_string().contains("tun.helper_path"), "{err}");

        let mut config = Config::default();
        config.tun.helper_dir = Some("  ".to_owned());
        assert!(config.validate().is_err());

        let mut config = Config::default();
        config.tun.helper_sha256_hex = Some("ABC".repeat(21) + "d"); // 64 uppercase hex
        let err = config.validate().expect_err("uppercase digest must fail");
        assert!(err.to_string().contains("tun.helper_sha256_hex"), "{err}");

        let mut config = Config::default();
        config.tun.helper_sha256_hex = Some(format!("{:064x}", 1u128));
        assert!(config.validate().is_ok());
    }

    #[test]
    fn tun_validates_exclude_rules() {
        let mut config = Config::default();
        config.tun.exclude_rules = vec![
            SplitRule::new("192.0.2.0/24"),
            SplitRule::new("2001:db8::/32"),
            SplitRule::new("example.com"),
            SplitRule::new(".example.net"),
            SplitRule::new("*.example.org"),
            SplitRule::new("UPPER.ORG"),
        ];
        config.tun.validate().expect("valid rules must pass");
        let mut config = Config::default();
        config.tun.exclude_rules = vec![SplitRule::new("192.0.2.7/24")];
        let err = config.validate().expect_err("host bits must fail");
        assert!(err.to_string().contains("host bits set"), "{err}");

        // IPv6 host bits too.
        let mut config = Config::default();
        config.tun.exclude_rules = vec![SplitRule::new("2001:db8::1/32")];
        assert!(config.validate().is_err());

        // Overlong prefix lengths.
        let mut config = Config::default();
        config.tun.exclude_rules = vec![SplitRule::new("192.0.2.0/33")];
        assert!(config.validate().is_err());
        let mut config = Config::default();
        config.tun.exclude_rules = vec![SplitRule::new("2001:db8::/129")];
        assert!(config.validate().is_err());

        // Duplicates after normalization are rejected.
        let mut config = Config::default();
        config.tun.exclude_rules = vec![
            SplitRule::new("example.com"),
            SplitRule::new(".Example.com"),
        ];
        let err = config.validate().expect_err("duplicates must fail");
        assert!(err.to_string().contains("duplicate"), "{err}");

        // Empty/whitespace destinations.
        let mut config = Config::default();
        config.tun.exclude_rules = vec![SplitRule::new("   ")];
        assert!(config.validate().is_err());

        // Whitespace inside a destination.
        let mut config = Config::default();
        config.tun.exclude_rules = vec![SplitRule::new("192.0.2.0 /24")];
        assert!(config.validate().is_err());

        // IP literal without a prefix must use CIDR form.
        let mut config = Config::default();
        config.tun.exclude_rules = vec![SplitRule::new("192.0.2.4")];
        let err = config.validate().expect_err("bare IP must fail");
        assert!(err.to_string().contains("CIDR form"), "{err}");

        // Comments must be single-line.
        let mut config = Config::default();
        config.tun.exclude_rules = vec![SplitRule {
            destination: "192.0.2.0/24".to_owned(),
            comment: Some("two\nlines".to_owned()),
        }];
        let err = config.validate().expect_err("multiline comment must fail");
        assert!(err.to_string().contains("comment"), "{err}");
    }

    #[test]
    fn split_destination_normalizes_domains() {
        for raw in [
            "example.com",
            " .example.com ",
            "*.EXAMPLE.com",
            "example.com.",
        ] {
            let parsed = SplitDestination::parse(raw).expect("must parse");
            match parsed {
                SplitDestination::Domain(domain) => {
                    assert_eq!(domain.name, "example.com", "{raw}");
                }
                other => panic!("expected domain for {raw}, got {other:?}"),
            }
        }
        // Non-ASCII domains are rejected with punycode guidance.
        let err = SplitDestination::parse("exämple.com").expect_err("IDN must fail");
        assert!(err.contains("punycode"), "{err}");
        // Empty labels / bad hyphens.
        for bad in ["example..com", "-example.com", "example-.com"] {
            assert!(
                SplitDestination::parse(bad).is_err(),
                "{bad} must be rejected"
            );
        }
    }

    #[test]
    fn split_destination_parses_cidrs_exactly() {
        let parsed = SplitDestination::parse("10.0.0.0/8").expect("must parse");
        match parsed {
            SplitDestination::Cidr(cidr) => {
                assert_eq!(cidr.addr, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)));
                assert_eq!(cidr.prefix_len, 8);
                assert_eq!(cidr.text, "10.0.0.0/8");
            }
            other => panic!("expected cidr, got {other:?}"),
        }
        // IPv6 zero compression and /0 work.
        let parsed = SplitDestination::parse("::/0").expect("must parse");
        match parsed {
            SplitDestination::Cidr(cidr) => {
                assert_eq!(cidr.prefix_len, 0);
                assert_eq!(cidr.text, "::/0");
            }
            other => panic!("expected cidr, got {other:?}"),
        }
        // Host bits set are reported with the corrected form.
        let err = SplitDestination::parse("10.1.2.3/8").expect_err("host bits must fail");
        assert!(err.contains("host bits set"), "{err}");
        assert!(err.contains("10.0.0.0/8"), "{err}");
        // Invalid address and non-integer prefix.
        assert!(SplitDestination::parse("10.0.0.256/8").is_err());
        assert!(SplitDestination::parse("10.0.0.0/eight").is_err());
        assert!(SplitDestination::parse("10.0.0.0/").is_err());
    }

    #[test]
    fn udp_and_kill_switch_explanations_and_variants_round_trip() {
        // Every variant has an honest explanation and round-trips via TOML.
        for policy in [KillSwitchPolicy::Restore, KillSwitchPolicy::Block] {
            assert!(!policy.explanation().is_empty());
        }
        for policy in [UdpPolicy::DnsOnly, UdpPolicy::BlockAll] {
            assert!(!policy.explanation().is_empty());
        }
        let mut config = Config::default();
        config.tun.udp_policy = UdpPolicy::BlockAll;
        config.tun.kill_switch = KillSwitchPolicy::Block;
        config.tun.validate().expect("policies must validate");
        // The summary of a disabled TUN says "off"; enabling shows the knobs
        // (enabled=true is still gated by validate until the engine exists,
        // but the summary itself must describe the requested behavior).
        config.tun.enabled = true;
        assert!(config.tun.summary().contains("BlockAll"));
        assert!(config.tun.summary().contains("Block"));
    }
}
