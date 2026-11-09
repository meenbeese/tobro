//! Pluggable transport / bridge configuration helpers (M3).
//!
//! Integrates lyrebird-managed transports (`obfs4`, `meek_lite`, `webtunnel`)
//! with Arti's `pt-client`/`tor-ptmgr` configuration APIs.

use std::path::PathBuf;

use anyhow::{Context as _, anyhow, bail};
use serde::{Deserialize, Serialize};

/// Known lyrebird protocol names supported by this integration.
pub const LYREBIRD_PROTOCOLS: &[&str] = &["obfs4", "meek_lite", "webtunnel"];

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

/// Apply bridge/PT settings to an Arti `TorClientConfigBuilder`.
///
/// Requires `arti-client`'s `pt-client` feature (enabled by default in tobro-tor).
#[cfg(feature = "pt-client")]
pub fn apply_to_builder(
    builder: &mut arti_client::config::TorClientConfigBuilder,
    settings: &BridgeSettings,
) -> anyhow::Result<()> {
    use arti_client::config::pt::TransportConfigBuilder;
    use arti_client::config::{BridgeConfigBuilder, CfgPath};

    if !settings.is_active() {
        return Ok(());
    }

    let lyrebird_protocols = settings.effective_lyrebird_protocols();
    let lyrebird_set: std::collections::HashSet<String> =
        lyrebird_protocols.iter().cloned().collect();

    // Track which lyrebird protocols are actually needed by bridge lines.
    let mut needed_lyrebird: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for line in settings.normalized_lines() {
        let parsed: BridgeConfigBuilder = line.parse().with_context(|| {
            // Do not include the full bridge line in errors (may be sensitive).
            format!(
                "invalid bridge line (protocol {:?})",
                bridge_line_protocol(line)
            )
        })?;
        if let Some(proto) = bridge_line_protocol(line) {
            if lyrebird_set.contains(&proto) {
                needed_lyrebird.insert(proto);
            }
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

    // Arti requires bridges to be enabled/used as configured by bridge config;
    // `BridgeConfigBuilder` parsing and presence in builder.bridges() is used by Arti.
    // (Exact toggle names vary; setting bridges is sufficient for pt-client configs.)
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
        };
        let mut builder = arti_client::config::TorClientConfig::builder();
        apply_to_builder(&mut builder, &settings).expect("apply");
        // Full build validates bridge/transport consistency in pt-client configs.
        let _cfg = builder.build().expect("config should build");
    }
}
