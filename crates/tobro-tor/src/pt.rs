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

    // Track which protocols are actually needed by bridge lines.
    let mut needed_lyrebird: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut needed_snowflake = false;
    let mut unknown: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
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
            } else if proto == SNOWFLAKE_PROTOCOL {
                needed_snowflake = true;
            } else {
                unknown.insert(proto);
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
        };
    let mut builder = arti_client::config::TorClientConfig::builder();
    apply_to_builder(&mut builder, &settings).expect("apply");
    let _cfg = builder.build().expect("config should build");
}
