//! Pluggable transport / bridge configuration helpers (M3).
//!
//! Integrates external PT clients with Arti's `pt-client`/`tor-ptmgr`:
//! - **lyrebird**: `obfs4`, `meek_lite` (`meek` alias), `webtunnel`
//! - **snowflake-client**: `snowflake` (including AMP/front/rendezvous params
//!   carried in bridge-line settings, where supported by the client/Arti)

use std::path::PathBuf;

use anyhow::{Context as _, anyhow, bail};
use serde::{Deserialize, Serialize};

/// Known lyrebird protocol names supported by this integration.
pub const LYREBIRD_PROTOCOLS: &[&str] = &["obfs4", "meek_lite", "webtunnel"];
/// Snowflake protocol name.
pub const SNOWFLAKE_PROTOCOL: &str = "snowflake";
/// DNSTT protocol name.
pub const DNSTT_PROTOCOL: &str = "dnstt";

/// All PT protocols recognized by this build (not all require the same binary).
pub const KNOWN_PT_PROTOCOLS: &[&str] = &["obfs4", "meek_lite", "webtunnel", "snowflake", "dnstt"];

/// Safe, structured result of validating a single bridge line.
///
/// Does not contain the original bridge line or raw parse errors, to avoid
/// leaking bridge fingerprints, addresses, or parameters (certs, fronts, etc.).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeLineValidation {
    /// 1-based line/index in the input (when validating a set).
    pub index: usize,
    /// Detected/normalized transport protocol, if one could be inferred.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,
    /// Whether the line is syntactically valid for Arti's bridge parser.
    pub valid: bool,
    /// Whether the transport is recognized by this tobro build.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub known_transport: Option<bool>,
    /// Safe, user-facing error/warning message. Never includes bridge material.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Result of validating a collection of bridge lines.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct BridgeValidationResult {
    /// Per-line results (in input order; comments/blank lines may be skipped or marked).
    pub lines: Vec<BridgeLineValidation>,
    /// Number of valid, non-empty bridge lines.
    pub valid_count: usize,
    /// Number of invalid bridge lines.
    pub invalid_count: usize,
    /// Transports required by valid lines (normalized).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_transports: Vec<String>,
    /// True if all non-empty, non-comment lines are valid.
    pub ok: bool,
}

impl BridgeValidationResult {
    /// Collect safe error messages.
    pub fn errors(&self) -> Vec<String> {
        self.lines
            .iter()
            .filter_map(|l| {
                l.error.as_ref().map(|e| match &l.transport {
                    Some(t) => format!("line {} ({t}): {e}", l.index),
                    None => format!("line {}: {e}", l.index),
                })
            })
            .collect()
    }
}

/// Returns true if `transport` is recognized by this build.
pub fn is_known_protocol(transport: &str) -> bool {
    let n = normalize_protocol(transport);
    KNOWN_PT_PROTOCOLS.contains(&n.as_str())
}

/// Parse and validate a single bridge line using Arti's bridge parser.
///
/// Returns the detected transport on success. Errors are sanitized and never
/// include the bridge line contents (addresses, fingerprints, certs, params).
#[cfg(feature = "pt-client")]
pub fn parse_bridge_line(line: &str) -> Result<String, String> {
    parse_bridge_builder(line).map(|(t, _)| t)
}

#[cfg(feature = "pt-client")]
fn parse_bridge_builder(
    line: &str,
) -> Result<(String, arti_client::config::BridgeConfigBuilder), String> {
    use arti_client::config::BridgeConfigBuilder;
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Err("bridge line is empty".to_owned());
    }
    let transport = bridge_line_protocol(trimmed);
    // Parse for structural validity without leaking the Arti parse error (it may echo input).
    let parsed: Result<BridgeConfigBuilder, _> = trimmed.parse();
    match parsed {
        Ok(builder) => {
            let t = transport.ok_or_else(|| "could not determine bridge transport".to_owned())?;
            Ok((t, builder))
        }
        Err(_) => Err(match transport {
            Some(t) => format!("invalid {t} bridge line format"),
            None => "invalid bridge line format (expected e.g. 'obfs4 <addr:port> <fingerprint> <params>')".to_owned(),
        }),
    }
}

#[cfg(not(feature = "pt-client"))]
pub fn parse_bridge_line(line: &str) -> Result<String, String> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Err("bridge line is empty".to_owned());
    }
    bridge_line_protocol(trimmed).ok_or_else(|| {
        "could not determine bridge transport (pt-client validation unavailable)".to_owned()
    })
}

/// Validate a set of bridge lines.
///
/// Comments (`#`, `//`) and blank lines are ignored. Results are safe to display/log
/// (no bridge material). `1`-based indexes refer to positions in `lines`.
pub fn validate_bridge_lines(lines: &[impl AsRef<str>]) -> BridgeValidationResult {
    let mut result = BridgeValidationResult::default();
    let mut required: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for (i, line) in lines.iter().enumerate() {
        let idx = i + 1;
        let trimmed = line.as_ref().trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
            continue;
        }
        match parse_bridge_line(trimmed) {
            Ok(transport) => {
                let known = is_known_protocol(&transport);
                required.insert(transport.clone());
                result.valid_count += 1;
                result.lines.push(BridgeLineValidation {
                    index: idx,
                    transport: Some(transport),
                    valid: true,
                    known_transport: Some(known),
                    error: if known {
                        None
                    } else {
                        Some("transport is not managed by tobro's built-in PT integration; a matching PT may be required".to_owned())
                    },
                });
            }
            Err(error) => {
                let transport = bridge_line_protocol(trimmed);
                result.invalid_count += 1;
                result.lines.push(BridgeLineValidation {
                    index: idx,
                    transport,
                    valid: false,
                    known_transport: None,
                    error: Some(error),
                });
            }
        }
    }
    result.required_transports = required.into_iter().collect();
    result.ok = result.invalid_count == 0;
    result
}

/// Import bridge lines from freeform text.
///
/// Splits on newlines, trims, removes comments/blank lines, normalizes an
/// optional leading `Bridge` prefix as-is (Arti accepts both forms), and
/// deduplicates exact normalized lines while preserving order.
pub fn import_bridge_lines(input: &str) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for raw in input.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
            continue;
        }
        // Normalize internal whitespace for dedup comparison, but keep a stable form.
        let normalized = line.split_whitespace().collect::<Vec<_>>().join(" ");
        if seen.insert(normalized.clone()) {
            out.push(normalized);
        }
    }
    out
}

/// Export bridge lines as newline-delimited text.
pub fn export_bridge_lines_text(lines: &[impl AsRef<str>]) -> String {
    let mut out = String::new();
    for line in lines {
        let t = line.as_ref().trim();
        if t.is_empty() || t.starts_with('#') || t.starts_with("//") {
            continue;
        }
        out.push_str(t);
        out.push('\n');
    }
    out
}

/// Export bridge lines with sensitive material redacted (safe for sharing/diagnostics).
///
/// Keeps the transport and a placeholder; does not include addresses, fingerprints, or params.
pub fn export_bridge_lines_redacted(lines: &[impl AsRef<str>]) -> String {
    let mut out = String::new();
    for line in lines {
        let t = line.as_ref().trim();
        if t.is_empty() || t.starts_with('#') || t.starts_with("//") {
            continue;
        }
        if let Some(proto) = bridge_line_protocol(t) {
            out.push_str(&proto);
            out.push_str(" [REDACTED]\n");
        } else {
            out.push_str("[REDACTED]\n");
        }
    }
    out
}

/// A named set of bridges (for built-in sets, import/export, and selection).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct BridgeSet {
    /// Stable identifier (e.g. `obfs4`, `snowflake`, `custom`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Human-readable name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Primary transport/type hint (e.g. `obfs4`, `snowflake`, `webtunnel`).
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub transport_type: Option<String>,
    /// Bridge lines (full material; treat as sensitive).
    #[serde(default)]
    pub bridges: Vec<String>,
    /// Optional country codes this set is relevant to (ISO 3166-1 alpha-2).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub countries: Vec<String>,
    /// Optional source/provenance label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Optional last-updated timestamp or version string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated: Option<String>,
}

impl BridgeSet {
    /// Validate the bridge lines in this set.
    pub fn validate(&self) -> BridgeValidationResult {
        validate_bridge_lines(&self.bridges)
    }

    /// Normalized, non-empty, deduplicated bridge lines.
    pub fn normalized_bridges(&self) -> Vec<String> {
        import_bridge_lines(&self.bridges.join("\n"))
    }
}

/// Built-in/importable bridge distribution JSON format (F-30).
///
/// The file may be bundled with the app or loaded from disk. `signature` is
/// reserved for signed distribution verification (verification is applied when
/// configured; unsigned/local files may be accepted in development contexts).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeDistribution {
    /// Format version.
    #[serde(default = "bridge_distribution_version")]
    pub version: u32,
    /// When this distribution was generated/updated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated: Option<String>,
    /// Optional signature material (format defined by the update channel).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    /// Bridge sets.
    #[serde(default)]
    pub sets: Vec<BridgeSet>,
}

fn bridge_distribution_version() -> u32 {
    1
}

impl Default for BridgeDistribution {
    fn default() -> Self {
        Self {
            version: bridge_distribution_version(),
            updated: None,
            signature: None,
            sets: Vec::new(),
        }
    }
}

impl BridgeDistribution {
    /// Parse a bridge distribution from JSON.
    pub fn from_json(json: &str) -> Result<Self, String> {
        serde_json::from_str(json).map_err(|e| format!("invalid bridge JSON: {e}"))
    }

    /// Serialize to pretty JSON.
    pub fn to_json_pretty(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| format!("failed to serialize bridge JSON: {e}"))
    }

    /// Load from a file.
    pub fn load(path: &std::path::Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
        Self::from_json(&text)
    }

    /// Find sets matching `transport_type` (case-insensitive) and/or `country`.
    pub fn matching_sets<'a>(
        &'a self,
        transport_type: Option<&str>,
        country: Option<&str>,
    ) -> Vec<&'a BridgeSet> {
        let t = transport_type.map(|s| normalize_protocol(s));
        let c = country.map(|s| s.trim().to_ascii_lowercase());
        self.sets
            .iter()
            .filter(|s| {
                let type_ok = t.as_ref().is_none_or(|want| {
                    s.transport_type
                        .as_ref()
                        .is_some_and(|have| normalize_protocol(have) == *want)
                        || s.id
                            .as_ref()
                            .is_some_and(|have| normalize_protocol(have) == *want)
                });
                let country_ok = c.as_ref().is_none_or(|want| {
                    s.countries.is_empty()
                        || s.countries
                            .iter()
                            .any(|have| have.trim().eq_ignore_ascii_case(want))
                });
                type_ok && country_ok
            })
            .collect()
    }

    /// Collect normalized bridge lines from matching sets.
    pub fn lines_for(&self, transport_type: Option<&str>, country: Option<&str>) -> Vec<String> {
        let mut out = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for set in self.matching_sets(transport_type, country) {
            for line in set.normalized_bridges() {
                if seen.insert(line.clone()) {
                    out.push(line);
                }
            }
        }
        out
    }
}

/// Minimal embedded built-in bridge distribution.
///
/// Real deployments should ship a signed, updatable `bridges.json` (F-30/F-35).
/// This default is intentionally empty to avoid bundling stale/region-specific
/// bridge material in source; load a distribution file or use Moat/custom bridges.
pub const BUILTIN_BRIDGES_JSON: &str = r#"{
  "version": 1,
  "updated": null,
  "sets": []
}
"#;

/// Load the embedded built-in bridge distribution.
pub fn builtin_bridges() -> Result<BridgeDistribution, String> {
    BridgeDistribution::from_json(BUILTIN_BRIDGES_JSON)
}

/// Bridge/pluggable transport settings applied to an Arti client config.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct BridgeSettings {
    /// Use bridges/PTs. When false, bridge lines are ignored.
    pub enabled: bool,
    /// Bridge lines (Tor format). May include `Bridge` prefix.
    pub lines: Vec<String>,
    /// Path to the lyrebird (or compatible PT) binary. When `None`, Arti/ptmgr
    /// will resolve according to its own rules using the configured transport
    /// path only if provided elsewhere; prefer setting this to a located binary.
    pub lyrebird_path: Option<PathBuf>,
    /// Protocols provided by `lyrebird_path` (default: obfs4, meek_lite, webtunnel).
    pub lyrebird_protocols: Vec<String>,
    /// Path to `snowflake-client` (or compatible binary). Required when bridge
    /// lines use the `snowflake` transport.
    pub snowflake_path: Option<PathBuf>,
    /// Path to `dnstt-client` (or compatible binary). Required when bridge
    /// lines use the `dnstt` transport.
    pub dnstt_path: Option<PathBuf>,
    /// Preferred country for bridge selection (ISO 3166-1 alpha-2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
}

impl BridgeSettings {
    /// True when bridge/PT configuration should be applied.
    pub fn is_active(&self) -> bool {
        self.enabled && self.normalized_lines().next().is_some()
    }

    /// Normalized bridge lines (trimmed, non-empty, no comments).
    pub fn normalized_lines(&self) -> impl Iterator<Item = &str> {
        self.lines
            .iter()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty() && !s.starts_with('#') && !s.starts_with("//"))
    }

    fn effective_lyrebird_protocols(&self) -> Vec<String> {
        if self.lyrebird_protocols.is_empty() {
            LYREBIRD_PROTOCOLS.iter().map(|s| (*s).to_owned()).collect()
        } else {
            self.lyrebird_protocols
                .iter()
                .map(|s| normalize_protocol(s))
                .filter(|s| !s.is_empty())
                .collect()
        }
    }
}

fn normalize_protocol(p: &str) -> String {
    let p = p.trim().to_ascii_lowercase();
    match p.as_str() {
        "meek" => "meek_lite".to_owned(), // common alias; lyrebird uses meek_lite
        _ => p,
    }
}

/// Infer the PT protocol name from a bridge line, if present.
pub fn bridge_line_protocol(line: &str) -> Option<String> {
    let mut parts = line.trim().split_whitespace();
    let first = parts.next()?;
    let proto = if first.eq_ignore_ascii_case("bridge") {
        parts.next()?
    } else {
        first
    };
    let proto = normalize_protocol(proto);
    if proto.is_empty() { None } else { Some(proto) }
}

/// Check that bridge/PT settings can be applied to an Arti client config.
///
/// This performs the same validation as [`apply_to_builder`] (line parsing, PT
/// path/transport requirements) without starting Tor. Errors are safe to display
/// (they do not intentionally include bridge material such as certs/fingerprints/addresses).
pub fn check_bridge_settings(settings: &BridgeSettings) -> Result<(), String> {
    #[cfg(feature = "pt-client")]
    {
        let mut builder = arti_client::config::TorClientConfig::builder();
        apply_to_builder(&mut builder, settings).map_err(|e| format!("{e:#}"))?;
        // Building validates consistency in pt-client configurations.
        builder
            .build()
            .map_err(|e| format!("bridge/PT configuration is not usable: {e:#}"))?;
        Ok(())
    }
    #[cfg(not(feature = "pt-client"))]
    {
        if settings.is_active() {
            Err("bridge/PT configuration requires the `pt-client` feature".to_owned())
        } else {
            Ok(())
        }
    }
}

/// Apply bridge/PT settings to an Arti `TorClientConfigBuilder`.
///
/// Requires `arti-client`'s `pt-client` feature (enabled by default in tobro-tor).
#[cfg(feature = "pt-client")]
pub fn apply_to_builder(
    builder: &mut arti_client::config::TorClientConfigBuilder,
    settings: &BridgeSettings,
) -> anyhow::Result<()> {
    use arti_client::config::CfgPath;
    use arti_client::config::pt::TransportConfigBuilder;

    if !settings.is_active() {
        return Ok(());
    }

    let lyrebird_protocols = settings.effective_lyrebird_protocols();
    let lyrebird_set: std::collections::HashSet<String> =
        lyrebird_protocols.iter().cloned().collect();

    // Track which protocols are actually needed by bridge lines.
    let mut needed_lyrebird: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut needed_snowflake = false;
    let mut needed_dnstt = false;
    let mut unknown: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for line in settings.normalized_lines() {
        let (proto, parsed) = parse_bridge_builder(line).map_err(|e| anyhow!(e))?;
        if lyrebird_set.contains(&proto) {
            needed_lyrebird.insert(proto);
        } else if proto == SNOWFLAKE_PROTOCOL {
            needed_snowflake = true;
        } else if proto == DNSTT_PROTOCOL {
            needed_dnstt = true;
        } else {
            unknown.insert(proto);
        }
        builder.bridges().bridges().push(parsed);
    }

    if !needed_lyrebird.is_empty() {
        let lyrebird_path = settings.lyrebird_path.as_ref().ok_or_else(|| {
            anyhow!(
                "bridge lines require lyrebird-managed transports ({}) but no lyrebird binary path was configured/resolved",
                needed_lyrebird.iter().cloned().collect::<Vec<_>>().join(", ")
            )
        })?;
        if !lyrebird_path.exists() {
            bail!(
                "configured lyrebird transport binary does not exist: {}",
                lyrebird_path.display()
            );
        }
        let mut transport = TransportConfigBuilder::default();
        let protocols = needed_lyrebird
            .iter()
            .map(|s| {
                s.parse()
                    .with_context(|| format!("invalid PT protocol name: {s}"))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        transport
            .protocols(protocols)
            .path(CfgPath::new(lyrebird_path.to_string_lossy().into_owned()))
            .run_on_startup(true);
        builder.bridges().transports().push(transport);
    }

    if needed_snowflake {
        let snowflake_path = settings.snowflake_path.as_ref().ok_or_else(|| {
            anyhow!(
                "bridge lines require the `snowflake` transport but no snowflake-client binary path was configured/resolved (AMP/front/broker settings are passed via bridge-line parameters where supported)"
            )
        })?;
        if !snowflake_path.exists() {
            bail!(
                "configured snowflake-client binary does not exist: {}",
                snowflake_path.display()
            );
        }
        let mut transport = TransportConfigBuilder::default();
        transport
            .protocols(vec![
                SNOWFLAKE_PROTOCOL
                    .parse()
                    .context("invalid snowflake protocol name")?,
            ])
            .path(CfgPath::new(snowflake_path.to_string_lossy().into_owned()))
            .run_on_startup(true);
        builder.bridges().transports().push(transport);
    }

    if needed_dnstt {
        let dnstt_path = settings.dnstt_path.as_ref().ok_or_else(|| {
            anyhow!(
                "bridge lines require the `dnstt` transport but no dnstt-client binary path was configured/resolved"
            )
        })?;
        if !dnstt_path.exists() {
            bail!(
                "configured dnstt-client binary does not exist: {}",
                dnstt_path.display()
            );
        }
        let mut transport = TransportConfigBuilder::default();
        transport
            .protocols(vec![
                DNSTT_PROTOCOL
                    .parse()
                    .context("invalid dnstt protocol name")?,
            ])
            .path(CfgPath::new(dnstt_path.to_string_lossy().into_owned()))
            .run_on_startup(true);
        builder.bridges().transports().push(transport);
    }

    // Arti validates that configured bridges have matching transports at build
    // time. Unknown external transports (not managed here) are left for Arti to
    // diagnose with its own error if no matching transport is configured.
    let _ = unknown;

    Ok(())
}

#[cfg(not(feature = "pt-client"))]
pub fn apply_to_builder(
    _builder: &mut arti_client::config::TorClientConfigBuilder,
    settings: &BridgeSettings,
) -> anyhow::Result<()> {
    if settings.is_active() {
        bail!("bridge/PT configuration requires the `pt-client` feature");
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn infers_bridge_protocols() {
        assert_eq!(
            bridge_line_protocol("obfs4 1.2.3.4:1 fp cert=x"),
            Some("obfs4".to_owned())
        );
        assert_eq!(
            bridge_line_protocol("Bridge obfs4 1.2.3.4:1 fp cert=x"),
            Some("obfs4".to_owned())
        );
        assert_eq!(
            bridge_line_protocol("webtunnel 1.2.3.4:443 fp url=https://x/"),
            Some("webtunnel".to_owned())
        );
        assert_eq!(
            bridge_line_protocol("Bridge meek_lite 1.2.3.4:443 fp url=https://x/ front=x"),
            Some("meek_lite".to_owned())
        );
        assert_eq!(
            bridge_line_protocol("meek 1.2.3.4:443 fp url=https://x/"),
            Some("meek_lite".to_owned())
        );
    }

    #[test]
    fn inactive_settings_apply_cleanly() {
        let mut builder = arti_client::config::TorClientConfig::builder();
        apply_to_builder(&mut builder, &BridgeSettings::default()).expect("apply");
        let _cfg = builder.build().expect("build");
    }

    #[test]
    fn rejects_active_lyrebird_bridges_without_binary() {
        let settings = BridgeSettings {
            enabled: true,
            lines: vec![
                "obfs4 192.0.2.1:1 316E643333645F6D79216558614D3931657A5F5F cert=abcd iat-mode=0"
                    .to_owned(),
            ],
            lyrebird_path: None,
            lyrebird_protocols: vec![],
            snowflake_path: None,
            ..Default::default()
        };
        let mut builder = arti_client::config::TorClientConfig::builder();
        let err = apply_to_builder(&mut builder, &settings).expect_err("must fail");
        assert!(
            format!("{err:#}").contains("lyrebird binary path"),
            "{err:#}"
        );
    }

    #[test]
    fn rejects_invalid_bridge_line_without_leaking_material() {
        let settings = BridgeSettings {
            enabled: true,
            lines: vec!["obfs4 not-a-valid-bridge-line cert=SECRET123".to_owned()],
            lyrebird_path: Some(PathBuf::from("/nonexistent/lyrebird")),
            lyrebird_protocols: vec![],
            snowflake_path: None,
            ..Default::default()
        };
        let mut builder = arti_client::config::TorClientConfig::builder();
        let err = apply_to_builder(&mut builder, &settings).expect_err("must fail");
        let msg = format!("{err:#}");
        assert!(
            !msg.contains("SECRET123"),
            "must not leak bridge material: {msg}"
        );
    }

    #[test]
    fn applies_lyrebird_transport_for_supported_protocols() {
        let dir = tempfile::TempDir::new().expect("tmp");
        let bin = dir.path().join("lyrebird");
        std::fs::write(&bin, b"fake").expect("write");
        let settings = BridgeSettings {
            enabled: true,
            lines: vec![
                "obfs4 192.0.2.1:1 316E643333645F6D79216558614D3931657A5F5F cert=abcd iat-mode=0".to_owned(),
                "webtunnel 192.0.2.2:443 316E643333645F6D79216558614D3931657A5F5F url=https://example.com/path ver=0.0.1".to_owned(),
                "Bridge meek_lite 192.0.2.3:443 316E643333645F6D79216558614D3931657A5F5F url=https://meek.example/ front=cdn.example".to_owned(),
            ],
            lyrebird_path: Some(bin),
            lyrebird_protocols: vec![],
            snowflake_path: None,
            ..Default::default()
        };
        let mut builder = arti_client::config::TorClientConfig::builder();
        apply_to_builder(&mut builder, &settings).expect("apply");
        // Full build validates bridge/transport consistency in pt-client configs.
        let _cfg = builder.build().expect("config should build");
    }
}

#[test]
fn infers_snowflake_protocol() {
    assert_eq!(
        bridge_line_protocol("snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72"),
        Some("snowflake".to_owned())
    );
    assert_eq!(
        bridge_line_protocol(
            "Bridge snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 url=https://broker.example/"
        ),
        Some("snowflake".to_owned())
    );
}

#[test]
fn rejects_snowflake_bridge_without_binary() {
    let settings = BridgeSettings {
            enabled: true,
            lines: vec![
                "Bridge snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 url=https://snowflake-broker.torproject.net/ front=cdn.sstatic.net utls-imitate=hellorandomizedalpn".to_owned(),
            ],
            lyrebird_path: None,
            lyrebird_protocols: vec![],
            snowflake_path: None,
            ..Default::default()
        };
    let mut builder = arti_client::config::TorClientConfig::builder();
    let err = apply_to_builder(&mut builder, &settings).expect_err("must fail");
    assert!(format!("{err:#}").contains("snowflake-client"), "{err:#}");
}

#[test]
fn applies_snowflake_transport_including_amp_params() {
    let dir = tempfile::TempDir::new().expect("tmp");
    let bin = dir.path().join("snowflake-client");
    std::fs::write(&bin, b"fake").expect("write");
    // AMP rendezvous is conveyed via bridge-line parameters (e.g. ampcache/front)
    // where supported by snowflake-client/Arti; verify the full line is accepted.
    let settings = BridgeSettings {
            enabled: true,
            lines: vec![
                "Bridge snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 url=https://snowflake-broker.torproject.net.global.prod.fastly.net/ front=foursquare.com ice=stun:stun.l.google.com:19302,stun:stun.antisip.com:3478 utls-imitate=hellorandomizedalpn ampcache=https://cdn.ampproject.org/".to_owned(),
            ],
            lyrebird_path: None,
            lyrebird_protocols: vec![],
            snowflake_path: Some(bin),
            ..Default::default()
        };
    let mut builder = arti_client::config::TorClientConfig::builder();
    apply_to_builder(&mut builder, &settings).expect("apply");
    let _cfg = builder.build().expect("config should build");
}

#[test]
fn applies_mixed_lyrebird_and_snowflake_transports() {
    let dir = tempfile::TempDir::new().expect("tmp");
    let lyrebird = dir.path().join("lyrebird");
    let snowflake = dir.path().join("snowflake-client");
    std::fs::write(&lyrebird, b"fake").expect("write");
    std::fs::write(&snowflake, b"fake").expect("write");
    let settings = BridgeSettings {
            enabled: true,
            lines: vec![
                "obfs4 192.0.2.1:1 316E643333645F6D79216558614D3931657A5F5F cert=abcd iat-mode=0".to_owned(),
                "Bridge snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 url=https://snowflake-broker.torproject.net/ front=cdn.sstatic.net utls-imitate=hellorandomizedalpn".to_owned(),
            ],
            lyrebird_path: Some(lyrebird),
            lyrebird_protocols: vec![],
            snowflake_path: Some(snowflake),
            ..Default::default()
        };
    let mut builder = arti_client::config::TorClientConfig::builder();
    apply_to_builder(&mut builder, &settings).expect("apply");
    let _cfg = builder.build().expect("config should build");
}

#[test]
fn validates_valid_bridge_lines() {
    let lines = vec![
        "obfs4 192.0.2.1:1 316E643333645F6D79216558614D3931657A5F5F cert=abcd iat-mode=0".to_owned(),
        "# comment".to_owned(),
        "".to_owned(),
        "Bridge snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 url=https://snowflake-broker.torproject.net/ front=cdn.sstatic.net utls-imitate=hellorandomizedalpn".to_owned(),
    ];
    let result = validate_bridge_lines(&lines);
    assert!(result.ok, "{result:?}");
    assert_eq!(result.valid_count, 2);
    assert_eq!(result.invalid_count, 0);
    assert!(result.required_transports.contains(&"obfs4".to_owned()));
    assert!(result.required_transports.contains(&"snowflake".to_owned()));
}

#[test]
fn validates_invalid_bridge_lines_without_leaking_material() {
    let lines = vec!["obfs4 not-a-valid-bridge-line cert=SECRET123".to_owned()];
    let result = validate_bridge_lines(&lines);
    assert!(!result.ok);
    assert_eq!(result.invalid_count, 1);
    let msg = result.errors().join("\n");
    assert!(!msg.contains("SECRET123"), "{msg}");
    assert!(!msg.contains("192.0.2"), "{msg}");
}

#[test]
fn imports_and_dedupes_bridge_lines() {
    let input = "\n# a comment\nobfs4 1.2.3.4:1 AAAA cert=x\nobfs4  1.2.3.4:1  AAAA  cert=x\n  \nBridge snowflake 1.2.3.4:80 BBBB url=https://x/\n";
    let lines = import_bridge_lines(input);
    assert_eq!(lines.len(), 2);
    assert!(lines[0].starts_with("obfs4 "));
    assert!(lines[1].starts_with("Bridge snowflake "));
}

#[test]
fn exports_redacted_bridge_lines() {
    let lines = vec!["obfs4 192.0.2.1:1 AAAA cert=SECRET".to_owned()];
    let redacted = export_bridge_lines_redacted(&lines);
    assert!(!redacted.contains("SECRET"), "{redacted}");
    assert!(!redacted.contains("192.0.2.1"), "{redacted}");
    assert!(redacted.contains("obfs4 [REDACTED]"), "{redacted}");
}

#[test]
fn bridge_distribution_json_round_trip_and_match() {
    let dist = BridgeDistribution {
        version: 1,
        updated: Some("2026-01-01".to_owned()),
        signature: None,
        sets: vec![
            BridgeSet {
                id: Some("obfs4".to_owned()),
                name: Some("obfs4".to_owned()),
                transport_type: Some("obfs4".to_owned()),
                bridges: vec!["obfs4 1.2.3.4:1 AAAA cert=x".to_owned()],
                countries: vec!["us".to_owned()],
                source: Some("builtin".to_owned()),
                updated: None,
            },
            BridgeSet {
                id: Some("snowflake".to_owned()),
                name: Some("Snowflake".to_owned()),
                transport_type: Some("snowflake".to_owned()),
                bridges: vec!["Bridge snowflake 1.2.3.4:80 BBBB url=https://x/".to_owned()],
                countries: vec![],
                source: None,
                updated: None,
            },
        ],
    };
    let json = dist.to_json_pretty().expect("serialize");
    let parsed = BridgeDistribution::from_json(&json).expect("parse");
    assert_eq!(parsed, dist);
    assert_eq!(parsed.matching_sets(Some("obfs4"), None).len(), 1);
    assert_eq!(parsed.matching_sets(Some("obfs4"), Some("de")).len(), 0);
    assert_eq!(parsed.matching_sets(Some("obfs4"), Some("us")).len(), 1);
    assert_eq!(parsed.lines_for(Some("snowflake"), None).len(), 1);
}

#[test]
fn builtin_bridges_loads() {
    let b = builtin_bridges().expect("builtin");
    assert_eq!(b.version, 1);
}
