//! Persistent pre-tunnel state used to recover after helper crashes.
//!
//! The journal is root/service-owned and atomically replaced.  It is only
//! consulted by the platform backends on startup and removed after successful
//! teardown.  It never contains destinations or packet data.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use tobro_tun::KillSwitchMode;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryJournal {
    /// Linux `/etc/resolv.conf` content captured before the tunnel changed it.
    pub linux_resolv_conf: Option<Option<String>>,
    /// macOS global DNS XML property-list captured before the tunnel changed it.
    pub mac_dns_backup: Option<Option<Vec<u8>>>,
    /// Whether persistent block-all enforcement was requested.
    pub block_all: bool,
    /// The kill-switch policy of the applied plan, persisted so a killing
    /// process's recovery (a restarted helper or a watchdog child) knows
    /// whether a torn-down tunnel must restore networking or stay blocked.
    #[serde(default)]
    pub kill_switch: KillSwitchMode,
}

fn journal_path() -> Option<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        Some(PathBuf::from("/var/lib/tobro/helper-recovery.json"))
    }
    #[cfg(target_os = "macos")]
    {
        Some(PathBuf::from(
            "/Library/Application Support/tobro/helper-recovery.json",
        ))
    }
    #[cfg(target_os = "windows")]
    {
        std::env::var_os("ProgramData").map(|root| {
            PathBuf::from(root)
                .join("Tobro")
                .join("helper-recovery.json")
        })
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        None
    }
}

pub fn load() -> RecoveryJournal {
    let Some(path) = journal_path() else {
        return RecoveryJournal::default();
    };
    std::fs::read(&path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

pub fn save(journal: &RecoveryJournal) -> Result<(), String> {
    // Unit tests must never touch the real root-owned journal.
    if cfg!(test) {
        return Ok(());
    }
    let Some(path) = journal_path() else {
        return Ok(());
    };
    let parent = path
        .parent()
        .ok_or_else(|| "recovery journal has no parent directory".to_owned())?;
    std::fs::create_dir_all(parent)
        .map_err(|error| format!("could not create recovery journal directory: {error}"))?;
    let bytes = serde_json::to_vec(journal)
        .map_err(|error| format!("could not encode recovery journal: {error}"))?;

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    let tmp = parent.join(".helper-recovery.json.tmp");
    std::fs::write(&tmp, bytes)
        .map_err(|error| format!("could not write recovery journal: {error}"))?;
    #[cfg(unix)]
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))
        .map_err(|error| format!("could not secure recovery journal: {error}"))?;
    std::fs::rename(&tmp, &path)
        .map_err(|error| format!("could not atomically replace recovery journal: {error}"))
}

pub fn clear() -> Result<(), String> {
    // Unit tests must never remove a real root-owned journal.
    if cfg!(test) {
        return Ok(());
    }
    let Some(path) = journal_path() else {
        return Ok(());
    };
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("could not remove recovery journal: {error}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::expect_used)]
    fn kill_switch_policy_round_trips_and_defaults() {
        // New field; an old journal without it still loads as `disabled`.
        let old = r#"{"linux_resolv_conf":null,"mac_dns_backup":null,"block_all":true}"#;
        let parsed: RecoveryJournal = serde_json::from_str(old).expect("old journal loads");
        assert!(parsed.block_all);
        assert_eq!(parsed.kill_switch, KillSwitchMode::Disabled);

        let blocked = RecoveryJournal {
            block_all: true,
            kill_switch: KillSwitchMode::Block,
            ..RecoveryJournal::default()
        };
        let json = serde_json::to_string(&blocked).expect("serialize");
        let back: RecoveryJournal = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, blocked);
    }
}
