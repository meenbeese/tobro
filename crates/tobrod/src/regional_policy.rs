//! Kindness regional policy (M6, F-67): a data file, not hard-coded UI.
//!
//! Plan §4.9: *"Regionalization: reuse Orbot's country logic to disable or
//! warn in heavily censored regions; make it a policy file, not hard-coded
//! UI."* Orbot keys Kindness restrictions off the configured bridge country
//! (`Regionalization.isKindnessModeDisabledForCountry`), so tobro resolves
//! the region the same way, with an explicit override:
//!
//! 1. `kindness.region` in the config (explicit override),
//! 2. `bridges.country` (the Orbot-derived source),
//! 3. none — the policy cannot apply and is reported as such.
//!
//! The bundled [`REGIONAL_POLICY_JSON`] ships with the daemon and may be
//! replaced by `<state-dir>/[OVERRIDE_FILE_NAME]` (an update/signed channel
//! or an admin can vendor a newer file; parse or validation failures fall
//! back to the bundled copy rather than breaking the daemon).
//!
//! Every entry maps an ISO 3166-1 alpha-2 country to a policy action:
//! `allow` (default for unlisted countries), `warn`, or `disabled`.
//! Resolution is a pure function of (file, config) and is exhaustively
//! tested; nothing here performs lookups or network calls, which keeps the
//! local-first privacy promise intact (the user's location is never probed).

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// Name of the optional override file in the state directory. A newer
/// policy (e.g. from a future signed bridge-data-style update channel) can
/// be dropped there; it fully replaces the bundled copy.
pub(crate) const OVERRIDE_FILE_NAME: &str = "regional_policy.json";

/// The policy copy bundled into the daemon binary.
const REGIONAL_POLICY_JSON: &str = include_str!("../regional_policy.json");

/// Policy actions for a country. `as_str` is also the JSON label used in
/// `kindness.status` and in the file itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) enum RegionalAction {
    Allow,
    Warn,
    Disabled,
}

impl RegionalAction {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            RegionalAction::Allow => "allow",
            RegionalAction::Warn => "warn",
            RegionalAction::Disabled => "disabled",
        }
    }
}

/// Where the resolved region came from. Reported in `kindness.status` so
/// the UI/user can tell why a given policy applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) enum RegionSource {
    /// `kindness.region` was set explicitly.
    Config,
    /// Fell back to `bridges.country` (Orbot's source).
    Bridges,
    /// Neither is set; the policy does not apply.
    None,
}

impl RegionSource {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            RegionSource::Config => "config",
            RegionSource::Bridges => "bridges",
            RegionSource::None => "none",
        }
    }
}

/// The parsed policy file (bundled or override).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub(crate) struct PolicyDocument {
    /// File revision; bump when the entries change meaningfully.
    version: u32,
    /// ISO date of the last content update (informational).
    updated: Option<String>,
    /// Where the entries were derived from (informational).
    source: Option<String>,
    /// Notes per action label (`warn`, `disabled`) shown in status/check.
    notes: BTreeMap<String, String>,
    /// ISO 3166-1 alpha-2 country → action label (`allow`/`warn`/`disabled`).
    countries: BTreeMap<String, String>,
}

/// The outcome of applying the policy to a daemon config. Serialized into
/// `kindness.status` §region (field labels mirror [`RegionalAction`] /
/// [`RegionSource`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct RegionalOutcome {
    /// Resolved region (uppercase alpha-2), `None` when undetermined.
    pub(crate) country: Option<String>,
    pub(crate) source: &'static str,
    /// Policy action for the region (`allow` when unlisted or unresolved).
    pub(crate) policy: &'static str,
    /// The file's note for the action (`warn`/`disabled`); `None` for
    /// entries without a note.
    pub(crate) note: Option<String>,
}

/// Parse and validate a policy document from JSON text.
///
/// Validation is deliberately permissive about unknown fields (forward
/// compatibility for update channels) and strict about the values that
/// drive behavior: country keys must be uppercase ISO 3166-1 alpha-2
/// codes, action labels must be known, and notes for `warn`/`disabled`
/// must exist (or the action degrades to a bare label in copy).
pub(crate) fn parse(text: &str) -> Result<PolicyDocument, String> {
    let document: PolicyDocument = serde_json::from_str(text)
        .map_err(|e| format!("regional policy JSON is malformed: {e}"))?;
    if document.version == 0 {
        return Err("regional policy `version` must be a positive integer".to_owned());
    }
    for (country, action) in &document.countries {
        if country.len() != 2 || !country.chars().all(|c| c.is_ascii_uppercase()) {
            return Err(format!(
                "regional policy country key {country:?} must be an uppercase ISO 3166-1 alpha-2 code"
            ));
        }
        if !matches!(action.as_str(), "allow" | "warn" | "disabled") {
            return Err(format!(
                "regional policy entry {country:?} has unknown action {action:?} \
                 (expected allow/warn/disabled)"
            ));
        }
    }
    Ok(document)
}

/// The bundled policy. Returns a helpful error when the binary's own copy
/// is malformed (a build-time defect, not a user problem).
fn bundled() -> Result<PolicyDocument, String> {
    parse(REGIONAL_POLICY_JSON)
}

/// Load the effective policy: the state-dir override file when present and
/// valid, the bundled copy otherwise. Never fails the daemon — an unusable
/// override logs a warning and falls back to what shipped with the binary.
pub(crate) fn load(state_dir: Option<&Path>) -> PolicyDocument {
    let Some(dir) = state_dir else {
        return bundled().unwrap_or_default();
    };
    let path = dir.join(OVERRIDE_FILE_NAME);
    let Ok(text) = std::fs::read_to_string(&path) else {
        return bundled().unwrap_or_default();
    };
    match parse(&text) {
        Ok(document) => {
            tracing::info!(
                path = %path.display(),
                version = document.version,
                "loaded regional policy override"
            );
            document
        }
        Err(reason) => {
            tracing::warn!(
                path = %path.display(),
                %reason,
                "regional policy override is unusable; using the bundled policy"
            );
            bundled().unwrap_or_default()
        }
    }
}

/// Resolve the region for a daemon config and where it came from.
///
/// Precedence: `kindness.region` (explicit) → `bridges.country` (the
/// source Orbot itself uses) → none. Both are validated as ISO 3166-1
/// alpha-2 by the config layer; `auto`/empty normalizes to `None`.
pub(crate) fn effective_region(config: &tobro_config::Config) -> (Option<String>, RegionSource) {
    if let Some(region) = config.kindness.normalized_region() {
        return (Some(region), RegionSource::Config);
    }
    if let Some(country) = config.bridges.normalized_country() {
        return (Some(country.to_ascii_uppercase()), RegionSource::Bridges);
    }
    (None, RegionSource::None)
}

/// Apply the policy to a config: resolve the region, look it up, and
/// attach the action note. Unlisted countries and unresolved regions come
/// out as `allow` with no note.
pub(crate) fn outcome_for(
    policy: &PolicyDocument,
    config: &tobro_config::Config,
) -> RegionalOutcome {
    let (country, source) = effective_region(config);
    let (action, note) = match country.as_deref() {
        None => (RegionalAction::Allow, None),
        Some(code) => match policy.countries.get(code).map(String::as_str) {
            Some("warn") => (RegionalAction::Warn, policy.note_for("warn")),
            Some("disabled") => (RegionalAction::Disabled, policy.note_for("disabled")),
            // `allow` and unknown/unlisted codes.
            _ => (RegionalAction::Allow, None),
        },
    };
    RegionalOutcome {
        country,
        source: source.as_str(),
        policy: action.as_str(),
        note,
    }
}

impl PolicyDocument {
    /// Note text for an action label, when present.
    fn note_for(&self, action: &str) -> Option<String> {
        self.notes.get(action).cloned()
    }
}

/// The user-facing file location for messages (the documented override).
pub(crate) fn override_path(state_dir: &Path) -> std::path::PathBuf {
    state_dir.join(OVERRIDE_FILE_NAME)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn config_with(
        kindness: impl FnOnce(&mut tobro_config::KindnessConfig),
    ) -> tobro_config::Config {
        let mut config = tobro_config::Config::default();
        config.kindness.enabled = true;
        kindness(&mut config.kindness);
        config
    }

    #[test]
    fn bundled_policy_parses_and_contains_the_orbot_derived_entries() {
        let document = bundled().expect("bundled policy parses");
        assert!(document.version >= 1);
        assert!(document.source.as_deref().is_some());
        assert!(document.note_for("warn").is_some());
        assert!(document.note_for("disabled").is_some());
        // Orbot's exact disable list (Regionalization.kt).
        assert_eq!(
            document.countries.get("AF").map(String::as_str),
            Some("disabled")
        );
        assert_eq!(
            document.countries.get("IR").map(String::as_str),
            Some("disabled")
        );
        // Orbot's DNSTT-censored list warn, minus the disabled entries.
        for code in [
            "AE", "BD", "CN", "CO", "ID", "KW", "PK", "QA", "RU", "SY", "TR", "UG", "UZ",
        ] {
            assert_eq!(
                document.countries.get(code).map(String::as_str),
                Some("warn"),
                "{code} should be a warn entry"
            );
        }
        // Nothing else is restricted: an open-internet region stays allow.
        assert!(!document.countries.contains_key("DE"));
    }

    #[test]
    fn parse_rejects_broken_documents() {
        assert!(parse("{").is_err());
        assert!(parse("{}").is_err(), "missing version");
        assert!(parse("{\"version\":1}").is_ok(), "empty countries is valid");
        let bad_key = r#"{"version":1,"countries":{"ukr":"warn"}}"#;
        assert!(parse(bad_key).is_err(), "non alpha-2 keys are rejected");
        let bad_action = r#"{"version":1,"countries":{"UA":"block"}}"#;
        assert!(parse(bad_action).is_err(), "unknown actions are rejected");
        let lowercase = r#"{"version":1,"countries":{"ua":"warn"}}"#;
        assert!(parse(lowercase).is_err(), "keys must be uppercase");
    }

    #[test]
    fn effective_region_precedence_config_then_bridges_then_none() {
        // Explicit kindness.region wins.
        let config = config_with(|k| {
            k.region = Some(" ir ".to_owned());
        });
        assert_eq!(
            effective_region(&config),
            (Some("IR".to_owned()), RegionSource::Config)
        );
        // "auto" falls through to bridges.country (Orbot's source).
        let mut config = config_with(|k| k.region = Some("auto".to_owned()));
        config.bridges.country = Some("de".to_owned());
        assert_eq!(
            effective_region(&config),
            (Some("DE".to_owned()), RegionSource::Bridges)
        );
        // No region, no bridge country: unknown.
        let config = config_with(|_| {});
        assert_eq!(effective_region(&config), (None, RegionSource::None));
    }

    #[test]
    fn outcome_matrix() {
        let document = bundled().expect("bundled policy parses");

        // bridges.country=IR triggers the Orbot-style disable, with the note.
        let mut config = config_with(|k| k.region = None);
        config.bridges.country = Some("ir".to_owned());
        let outcome = outcome_for(&document, &config);
        assert_eq!(outcome.country.as_deref(), Some("IR"));
        assert_eq!(outcome.source, "bridges");
        assert_eq!(outcome.policy, "disabled");
        assert!(outcome.note.is_some());

        // kindness.region=CN warns, source is config.
        let config = config_with(|k| k.region = Some("cn".to_owned()));
        let outcome = outcome_for(&document, &config);
        assert_eq!(outcome.source, "config");
        assert_eq!(outcome.policy, "warn");
        assert!(outcome.note.is_some());

        // Unlisted country (DE): allow.
        let config = config_with(|k| k.region = Some("de".to_owned()));
        assert_eq!(outcome_for(&document, &config).policy, "allow");

        // Unknown region: allow, no note, source none.
        let config = config_with(|_| {});
        let outcome = outcome_for(&document, &config);
        assert_eq!(outcome.country, None);
        assert_eq!(outcome.source, "none");
        assert_eq!(outcome.policy, "allow");
        assert_eq!(outcome.note, None);
    }

    #[test]
    fn explicit_allow_entry_overrides_wording() {
        let document = parse(
            r#"{"version":2,"notes":{"disabled":"no kindness here"},"countries":{"AF":"disabled","IR":"allow"}}"#,
        )
        .expect("parses");
        let mut config = config_with(|_| {});
        config.bridges.country = Some("IR".to_owned());
        let outcome = outcome_for(&document, &config);
        assert_eq!(outcome.policy, "allow");
        assert_eq!(outcome.note, None, "allow entries carry no note");
        config.bridges.country = Some("AF".to_owned());
        assert_eq!(
            outcome_for(&document, &config).note.as_deref(),
            Some("no kindness here")
        );
        assert_eq!(document.version, 2);
    }

    #[test]
    fn override_file_replaces_bundled_entries() {
        let dir = tempfile::TempDir::new().expect("tmp");
        std::fs::write(
            dir.path().join(OVERRIDE_FILE_NAME),
            r#"{"version":9,"notes":{"warn":"custom"},"countries":{"UA":"warn"}}"#,
        )
        .expect("write override");
        let policy = load(Some(dir.path()));
        assert_eq!(policy.version, 9);
        let mut config = config_with(|k| k.region = Some("ua".to_owned()));
        config.bridges.country = None;
        let outcome = outcome_for(&policy, &config);
        assert_eq!(outcome.policy, "warn");
        assert_eq!(outcome.note.as_deref(), Some("custom"));
    }

    #[test]
    fn broken_override_falls_back_to_bundled() {
        let dir = tempfile::TempDir::new().expect("tmp");
        std::fs::write(dir.path().join(OVERRIDE_FILE_NAME), "not json").expect("write override");
        let policy = load(Some(dir.path()));
        assert_eq!(policy.version, 1, "bundled fallback used");
        // And the bundled behavior is intact.
        let config = config_with(|k| k.region = Some("ir".to_owned()));
        assert_eq!(outcome_for(&policy, &config).policy, "disabled");
    }

    #[test]
    fn missing_override_uses_bundled() {
        let dir = tempfile::TempDir::new().expect("tmp");
        assert_eq!(load(Some(dir.path())).version, 1);
        assert_eq!(load(None).version, 1);
    }

    #[test]
    fn overrides_path_is_state_dir_child() {
        let dir = tempfile::TempDir::new().expect("tmp");
        assert_eq!(
            override_path(dir.path()),
            dir.path().join("regional_policy.json")
        );
    }
}
