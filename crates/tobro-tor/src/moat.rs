//! Moat circumvention/bridge-distribution client (M3, F-31/F-33).
//!
//! Implements the Tor Project Moat circumvention settings API (rdsys):
//! - `POST /circumvention/settings` — recommended settings/bridges by country/transports
//! - `POST /circumvention/defaults` — default settings when country is unknown
//! - `GET/POST /circumvention/builtin` — full built-in bridge list
//!
//! Moat is normally reached over domain fronting; this client uses HTTPS and
//! accepts a configurable endpoint (for testing with a mock server, or for
//! deployments that provide a fronted/proxied path).
//!
//! Bridge material is sensitive: responses may contain bridge lines; do not log
//! them.

use std::collections::BTreeMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::pt::{BridgeDistribution, import_bridge_lines};

/// Default Moat base URL (rdsys). Requests are made under `<base>/circumvention/...`.
pub const DEFAULT_MOAT_BASE_URL: &str = "https://bridges.torproject.org/moat";
/// Default request timeout.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Moat client configuration.
#[derive(Debug, Clone)]
pub struct MoatClient {
    http: reqwest::Client,
    base_url: String,
}

/// Error returned by Moat operations. Messages avoid leaking bridge material.
#[derive(Debug, thiserror::Error)]
pub enum MoatError {
    /// Network/HTTP transport failure.
    #[error("moat request failed: {0}")]
    Transport(String),
    /// Moat returned an API error payload.
    #[error("moat error {code}: {detail}")]
    Api {
        /// Moat error code (e.g. 400, 404, 406).
        code: i64,
        /// Human-readable detail from Moat.
        detail: String,
    },
    /// Response could not be decoded.
    #[error("invalid moat response: {0}")]
    Decode(String),
}

/// Country/transport selection for circumvention settings.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CircumventionRequest {
    /// ISO 3166-1 alpha-2 country code (e.g. `de`, `cn`). Optional; when omitted,
    /// Moat may geolocate by IP (not used if IP is unavailable/meaningless).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    /// Supported/plausible transports to request (e.g. `obfs4`, `snowflake`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transports: Option<Vec<String>>,
}

/// One circumvention setting entry.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CircumventionSetting {
    /// Bridge recommendation.
    #[serde(default)]
    pub bridges: CircumventionBridges,
}

/// Bridge details inside a circumvention setting.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CircumventionBridges {
    /// Transport type (e.g. `obfs4`, `snowflake`).
    #[serde(rename = "type", default)]
    pub transport_type: String,
    /// Source label (e.g. `builtin`, `bridgedb`).
    #[serde(default)]
    pub source: String,
    /// Bridge lines to use (sensitive). May be omitted in map responses.
    #[serde(default)]
    pub bridge_strings: Vec<String>,
}

/// Response from `/circumvention/settings` or `/circumvention/defaults`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CircumventionSettingsResponse {
    /// Recommended settings, ordered by usefulness.
    #[serde(default)]
    pub settings: Vec<CircumventionSetting>,
    /// Country code the settings apply to (if provided/known).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
}

impl CircumventionSettingsResponse {
    /// Collect all bridge lines from settings, preserving order and deduplicating.
    pub fn all_bridge_lines(&self) -> Vec<String> {
        let mut out = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for s in &self.settings {
            for line in import_bridge_lines(&s.bridges.bridge_strings.join("\n")) {
                if seen.insert(line.clone()) {
                    out.push(line);
                }
            }
        }
        out
    }

    /// Bridge lines for a specific transport type (normalized comparison).
    pub fn lines_for_transport(&self, transport: &str) -> Vec<String> {
        let want = crate::pt::bridge_line_protocol(transport)
            .unwrap_or_else(|| transport.trim().to_ascii_lowercase());
        let mut out = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for s in &self.settings {
            let t = s.bridges.transport_type.trim().to_ascii_lowercase();
            let t = if t == "meek-azure" || t == "meek_lite" {
                "meek_lite".to_owned()
            } else {
                t
            };
            let want_norm = if want == "meek" {
                "meek_lite".to_owned()
            } else {
                want.clone()
            };
            if t == want_norm {
                for line in import_bridge_lines(&s.bridges.bridge_strings.join("\n")) {
                    if seen.insert(line.clone()) {
                        out.push(line);
                    }
                }
            }
        }
        out
    }

    /// Recommended transport types in order.
    pub fn recommended_transports(&self) -> Vec<String> {
        self.settings
            .iter()
            .map(|s| s.bridges.transport_type.clone())
            .filter(|t| !t.trim().is_empty())
            .collect()
    }
}

/// Moat API error item.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct MoatApiError {
    #[serde(default)]
    code: i64,
    #[serde(default)]
    detail: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct MoatErrorResponse {
    #[serde(default)]
    errors: Vec<MoatApiError>,
}

/// Built-in bridges response: transport name -> bridge lines.
pub type BuiltinBridgesResponse = BTreeMap<String, Vec<String>>;

/// Helpers for `BuiltinBridgesResponse`.
pub trait BuiltinBridgesExt {
    /// Extract normalized lines, optionally filtered by transport type.
    fn lines_for_transport(&self, transport: Option<&str>) -> Vec<String>;
}

impl BuiltinBridgesExt for BuiltinBridgesResponse {
    fn lines_for_transport(&self, transport: Option<&str>) -> Vec<String> {
        let want = transport.map(normalize_transport_key);
        let mut out = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for (k, lines) in self {
            if let Some(ref w) = want {
                if normalize_transport_key(k) != *w {
                    continue;
                }
            }
            for line in import_bridge_lines(&lines.join("\n")) {
                if seen.insert(line.clone()) {
                    out.push(line);
                }
            }
        }
        out
    }
}

/// How a bridge set was obtained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeSource {
    /// Fetched from Moat circumvention settings.
    MoatSettings,
    /// Fetched from Moat defaults.
    MoatDefaults,
    /// Fetched from Moat builtin endpoint.
    MoatBuiltin,
    /// Loaded from a local/bundled bridge distribution.
    Builtin,
    /// Provided explicitly (custom/config).
    Custom,
}

/// Result of resolving bridges with fallback.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedBridges {
    /// Where the bridges came from.
    pub source: BridgeSource,
    /// Country used/requested, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    /// Transport selected/requested, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,
    /// Bridge lines (sensitive; redact before logging/sharing).
    pub lines: Vec<String>,
    /// Human-readable fallback/diagnostic note (no secrets).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl MoatClient {
    /// Create a client with the default Moat endpoint.
    pub fn new() -> Result<Self, MoatError> {
        Self::with_base_url(DEFAULT_MOAT_BASE_URL)
    }

    /// Create a client targeting `base_url` (e.g. a mock server or fronted URL).
    ///
    /// `base_url` should be the Moat root (requests append `/circumvention/...`).
    pub fn with_base_url(base_url: impl Into<String>) -> Result<Self, MoatError> {
        let http = reqwest::Client::builder()
            .timeout(DEFAULT_TIMEOUT)
            .user_agent(format!("tobro/{}", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| MoatError::Transport(e.to_string()))?;
        Ok(Self {
            http,
            base_url: base_url.into().trim_end_matches('/').to_owned(),
        })
    }

    /// Override the HTTP client (e.g. custom timeout/proxy/TLS settings).
    pub fn with_http_client(mut self, http: reqwest::Client) -> Self {
        self.http = http;
        self
    }

    /// Returns the configured base URL.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    fn endpoint(&self, path: &str) -> String {
        format!("{}/{}", self.base_url, path.trim_start_matches('/'))
    }

    async fn post_json<T: for<'de> Deserialize<'de>, B: Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, MoatError> {
        let url = self.endpoint(path);
        let resp = self
            .http
            .post(&url)
            .json(body)
            .send()
            .await
            .map_err(|e| MoatError::Transport(e.to_string()))?;
        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| MoatError::Transport(e.to_string()))?;
        // Moat typically returns 200 with either data or {"errors":[...]}.
        if let Ok(err) = serde_json::from_str::<MoatErrorResponse>(&text) {
            if let Some(e) = err.errors.first() {
                return Err(MoatError::Api {
                    code: if e.code != 0 {
                        e.code
                    } else {
                        status.as_u16() as i64
                    },
                    detail: e.detail.clone(),
                });
            }
        }
        if !status.is_success() {
            return Err(MoatError::Transport(format!("HTTP {}", status)));
        }
        serde_json::from_str(&text).map_err(|e| MoatError::Decode(e.to_string()))
    }

    async fn get_json<T: for<'de> Deserialize<'de>>(&self, path: &str) -> Result<T, MoatError> {
        let url = self.endpoint(path);
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| MoatError::Transport(e.to_string()))?;
        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| MoatError::Transport(e.to_string()))?;
        if let Ok(err) = serde_json::from_str::<MoatErrorResponse>(&text) {
            if let Some(e) = err.errors.first() {
                return Err(MoatError::Api {
                    code: if e.code != 0 {
                        e.code
                    } else {
                        status.as_u16() as i64
                    },
                    detail: e.detail.clone(),
                });
            }
        }
        if !status.is_success() {
            return Err(MoatError::Transport(format!("HTTP {}", status)));
        }
        serde_json::from_str(&text).map_err(|e| MoatError::Decode(e.to_string()))
    }

    /// Fetch circumvention settings for an optional country and transport list.
    pub async fn circumvention_settings(
        &self,
        country: Option<&str>,
        transports: Option<&[String]>,
    ) -> Result<CircumventionSettingsResponse, MoatError> {
        let body = CircumventionRequest {
            country: country
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|s| s.to_ascii_lowercase()),
            transports: transports.map(<[String]>::to_vec).filter(|t| !t.is_empty()),
        };
        self.post_json("circumvention/settings", &body).await
    }

    /// Fetch default circumvention settings (no country; optional transport filter).
    pub async fn circumvention_defaults(
        &self,
        transports: Option<&[String]>,
    ) -> Result<CircumventionSettingsResponse, MoatError> {
        #[derive(Serialize)]
        struct DefaultsRequest {
            #[serde(skip_serializing_if = "Option::is_none")]
            transports: Option<Vec<String>>,
        }
        let body = DefaultsRequest {
            transports: transports.map(<[String]>::to_vec).filter(|t| !t.is_empty()),
        };
        self.post_json("circumvention/defaults", &body).await
    }

    /// Fetch Moat's full built-in bridge list.
    pub async fn circumvention_builtin(&self) -> Result<BuiltinBridgesResponse, MoatError> {
        self.get_json("circumvention/builtin").await
    }
}

impl Default for MoatClient {
    fn default() -> Self {
        // Best-effort default; callers that need to handle builder errors should use `new()`.
        Self::new().unwrap_or_else(|_| Self {
            http: reqwest::Client::new(),
            base_url: DEFAULT_MOAT_BASE_URL.to_owned(),
        })
    }
}

fn normalize_transport_key(t: &str) -> String {
    let n = t.trim().to_ascii_lowercase();
    if n == "meek" || n == "meek-azure" {
        "meek_lite".to_owned()
    } else {
        n
    }
}

/// Fetch bridges from Moat with fallback to built-in/local distribution.
///
/// Order: `circumvention/settings` (country+transport) → `circumvention/defaults`
/// (transport) → `circumvention/builtin` (Moat's builtins) → local `builtin`
/// distribution matching transport/country. Returns the first non-empty result,
/// or an empty `Custom`/`Builtin` result with a note if everything fails.
///
/// Bridge lines are returned in full (sensitive); callers must redact before
/// logging or diagnostics export.
pub async fn fetch_bridges_with_fallback(
    moat: &MoatClient,
    country: Option<&str>,
    transports: Option<&[String]>,
    builtin: Option<&BridgeDistribution>,
) -> ResolvedBridges {
    let requested_transport = transports
        .and_then(|t| t.first())
        .map(|s| s.to_string())
        .or_else(|| transports.and_then(|t| t.get(0)).cloned());
    let country_norm = country
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_ascii_lowercase());

    // 1) Country-specific settings (Moat auto-config).
    match moat
        .circumvention_settings(country_norm.as_deref(), transports)
        .await
    {
        Ok(resp) => {
            let lines = if let Some(ref t) = requested_transport {
                let l = resp.lines_for_transport(t);
                if l.is_empty() {
                    resp.all_bridge_lines()
                } else {
                    l
                }
            } else {
                resp.all_bridge_lines()
            };
            if !lines.is_empty() {
                let transport = resp
                    .recommended_transports()
                    .first()
                    .cloned()
                    .or(requested_transport.clone());
                return ResolvedBridges {
                    source: BridgeSource::MoatSettings,
                    country: resp.country.clone().or(country_norm.clone()),
                    transport,
                    lines,
                    note: None,
                };
            }
            tracing::debug!("moat settings returned no bridge lines; trying defaults");
        }
        Err(e) => {
            tracing::debug!(error = %e, "moat settings request failed; trying defaults");
        }
    }

    // 2) Defaults.
    match moat.circumvention_defaults(transports).await {
        Ok(resp) => {
            let lines = if let Some(ref t) = requested_transport {
                let l = resp.lines_for_transport(t);
                if l.is_empty() {
                    resp.all_bridge_lines()
                } else {
                    l
                }
            } else {
                resp.all_bridge_lines()
            };
            if !lines.is_empty() {
                let transport = resp
                    .recommended_transports()
                    .first()
                    .cloned()
                    .or(requested_transport.clone());
                return ResolvedBridges {
                    source: BridgeSource::MoatDefaults,
                    country: country_norm.clone(),
                    transport,
                    lines,
                    note: Some(
                        "used Moat defaults (country-specific settings unavailable)".to_owned(),
                    ),
                };
            }
        }
        Err(e) => {
            tracing::debug!(error = %e, "moat defaults request failed; trying builtin endpoint");
        }
    }

    // 3) Moat builtin endpoint.
    match moat.circumvention_builtin().await {
        Ok(map) => {
            let lines = map.lines_for_transport(requested_transport.as_deref());
            let lines = if lines.is_empty() && requested_transport.is_none() {
                map.lines_for_transport(None)
            } else {
                lines
            };
            if !lines.is_empty() {
                return ResolvedBridges {
                    source: BridgeSource::MoatBuiltin,
                    country: country_norm,
                    transport: requested_transport,
                    lines,
                    note: Some(
                        "used Moat builtin bridges (settings/defaults unavailable)".to_owned(),
                    ),
                };
            }
        }
        Err(e) => {
            tracing::debug!(error = %e, "moat builtin request failed; falling back to local builtins");
        }
    }

    // 4) Local/bundled built-in distribution.
    if let Some(dist) = builtin {
        let lines = dist.lines_for(requested_transport.as_deref(), country_norm.as_deref());
        let lines = if lines.is_empty() {
            dist.lines_for(requested_transport.as_deref(), None)
        } else {
            lines
        };
        if !lines.is_empty() {
            return ResolvedBridges {
                source: BridgeSource::Builtin,
                country: country_norm,
                transport: requested_transport,
                lines,
                note: Some("Moat unavailable; used local built-in bridges".to_owned()),
            };
        }
    }

    ResolvedBridges {
        source: BridgeSource::Builtin,
        country: country_norm,
        transport: requested_transport,
        lines: Vec::new(),
        note: Some(
            "no bridges available: Moat failed and no matching local built-in bridges were found"
                .to_owned(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_circumvention_settings_response() {
        let json = r#"{
          "settings": [{
            "bridges": {
              "type": "obfs4",
              "source": "builtin",
              "bridge_strings": ["obfs4 1.2.3.4:443 AAAA cert=x iat-mode=0"]
            }
          }],
          "country": "de"
        }"#;
        let resp: CircumventionSettingsResponse = serde_json::from_str(json).expect("parse");
        assert_eq!(resp.country.as_deref(), Some("de"));
        assert_eq!(resp.all_bridge_lines().len(), 1);
        assert_eq!(resp.recommended_transports(), vec!["obfs4".to_owned()]);
    }

    #[test]
    fn parses_moat_error_response() {
        let json = r#"{"errors":[{"code":404,"detail":"No provided transport is available for this country"}]}"#;
        let err: MoatErrorResponse = serde_json::from_str(json).expect("parse");
        assert_eq!(err.errors[0].code, 404);
    }

    #[test]
    fn parses_builtin_response() {
        let json = r#"{"obfs4":["obfs4 1.2.3.4:1 A cert=x iat-mode=0"],"snowflake":["snowflake 192.0.2.3:1 B"]}"#;
        let map: BuiltinBridgesResponse = serde_json::from_str(json).expect("parse");
        assert_eq!(map.lines_for_transport(Some("obfs4")).len(), 1);
        assert_eq!(map.lines_for_transport(Some("snowflake")).len(), 1);
    }

    #[tokio::test]
    async fn fetches_settings_from_moat_mock() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/circumvention/settings"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "settings": [{
                    "bridges": {
                        "type": "obfs4",
                        "source": "builtin",
                        "bridge_strings": ["obfs4 1.2.3.4:443 316E643333645F6D79216558614D3931657A5F5F cert=abcd iat-mode=0"]
                    }
                }],
                "country": "de"
            })))
            .mount(&server)
            .await;

        let client = MoatClient::with_base_url(server.uri()).expect("client");
        let transports = vec!["obfs4".to_owned()];
        let resolved =
            fetch_bridges_with_fallback(&client, Some("de"), Some(&transports), None).await;
        assert_eq!(resolved.source, BridgeSource::MoatSettings);
        assert_eq!(resolved.country.as_deref(), Some("de"));
        assert_eq!(resolved.lines.len(), 1);
        assert!(resolved.lines[0].starts_with("obfs4 "));
    }

    #[tokio::test]
    async fn falls_back_to_local_builtin_when_moat_fails() {
        use wiremock::matchers::any;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        // All Moat endpoints fail.
        Mock::given(any())
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let local = BridgeDistribution {
            version: 1,
            updated: None,
            signature: None,
            sets: vec![crate::pt::BridgeSet {
                id: Some("obfs4".to_owned()),
                name: None,
                transport_type: Some("obfs4".to_owned()),
                bridges: vec!["obfs4 9.9.9.9:443 316E643333645F6D79216558614D3931657A5F5F cert=abcd iat-mode=0".to_owned()],
                countries: vec![],
                source: Some("local".to_owned()),
                updated: None,
            }],
        };

        let client = MoatClient::with_base_url(server.uri()).expect("client");
        let transports = vec!["obfs4".to_owned()];
        let resolved =
            fetch_bridges_with_fallback(&client, Some("cn"), Some(&transports), Some(&local)).await;
        assert_eq!(resolved.source, BridgeSource::Builtin);
        assert_eq!(resolved.lines.len(), 1);
        assert!(resolved.note.as_deref().unwrap_or("").contains("Moat"));
    }
}
