//! Onion service management: model mapping, key storage directories, and CRUD
//! operations backed by [`tobro_store`].
//!
//! Runtime hosting (Arti `launch_onion_service`) is wired separately by the
//! Tor service manager when a client is available. This module manages the
//! durable desired state and key directory layout.

use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use tobro_store::{NewOnionService, OnionService, OnionServicePatch, OnionServicePort};

#[derive(Debug, Deserialize)]
struct PortParams {
    virt_port: u16,
    #[serde(default = "default_target_host")]
    target_host: String,
    target_port: u16,
}

fn default_target_host() -> String {
    "127.0.0.1".to_owned()
}

#[derive(Debug, Deserialize)]
struct CreateParams {
    name: String,
    ports: Vec<PortParams>,
    #[serde(default = "default_enabled")]
    enabled: bool,
    #[serde(default)]
    nickname: Option<String>,
}

fn default_enabled() -> bool {
    true
}

#[derive(Debug, Deserialize)]
struct UpdateParams {
    id: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    ports: Option<Vec<PortParams>>,
}

#[derive(Debug, Deserialize)]
struct DeleteParams {
    id: String,
}

fn sanitize_nickname(base: &str) -> String {
    let mut out = String::with_capacity(base.len().min(48));
    for ch in base.chars() {
        let c = if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            ch
        } else if ch.is_whitespace() {
            '-'
        } else {
            '_'
        };
        out.push(c);
        if out.len() >= 48 {
            break;
        }
    }
    let out = out.trim_matches(|c: char| c == '-' || c == '_').to_owned();
    if out.is_empty() {
        "svc".to_owned()
    } else {
        out
    }
}

fn ports_from_params(params: Vec<PortParams>) -> Vec<OnionServicePort> {
    params
        .into_iter()
        .map(|p| OnionServicePort {
            virt_port: p.virt_port,
            target_host: if p.target_host.trim().is_empty() {
                "127.0.0.1".to_owned()
            } else {
                p.target_host.trim().to_owned()
            },
            target_port: p.target_port,
        })
        .collect()
}

fn service_to_json(svc: &OnionService, runtime_active: bool) -> Value {
    let (runtime_status, runtime_detail) = if !svc.enabled {
        ("disabled".to_owned(), None)
    } else if runtime_active {
        if svc.onion_address.is_some() {
            ("published".to_owned(), None)
        } else {
            (
                "pending".to_owned(),
                Some(
                    "Tor runtime is active; service publication is managed by the runtime"
                        .to_owned(),
                ),
            )
        }
    } else {
        (
            "stopped".to_owned(),
            Some("start/connect Tor to publish enabled onion services".to_owned()),
        )
    };
    json!({
        "id": svc.id,
        "nickname": svc.nickname,
        "name": svc.name,
        "enabled": svc.enabled,
        "onion_address": svc.onion_address,
        "key_dir": svc.key_dir,
        "created_at": svc.created_at,
        "updated_at": svc.updated_at,
        "ports": svc.ports.iter().map(|p| json!({
            "virt_port": p.virt_port,
            "target_host": p.target_host,
            "target_port": p.target_port,
        })).collect::<Vec<_>>(),
        "runtime_status": runtime_status,
        "runtime_detail": runtime_detail,
    })
}

async fn ensure_key_dir(path: &Path) -> Result<(), String> {
    tokio::fs::create_dir_all(path)
        .await
        .map_err(|e| format!("failed to create key dir {}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("failed to set key dir permissions {}: {e}", path.display()))?;
    }
    Ok(())
}

async fn remove_key_dir(path: &Path) -> Result<(), String> {
    if !path.exists() {
        return Ok(());
    }
    tokio::fs::remove_dir_all(path)
        .await
        .map_err(|e| format!("failed to remove key dir {}: {e}", path.display()))
}

pub async fn list(db_path: &Path, runtime_active: bool) -> Result<Value, String> {
    let db = tobro_store::Db::open(db_path)
        .await
        .map_err(|e| format!("failed to open store: {e}"))?;
    let services = db
        .list_onion_services()
        .await
        .map_err(|e| format!("failed to list onion services: {e}"))?;
    Ok(json!({
        "ok": true,
        "action": "onion.list",
        "services": services.iter().map(|s| service_to_json(s, runtime_active)).collect::<Vec<_>>(),
    }))
}

pub async fn create(
    db_path: &Path,
    onion_root: &Path,
    params: Value,
    runtime_active: bool,
) -> Result<Value, String> {
    let params: CreateParams =
        serde_json::from_value(params).map_err(|e| format!("invalid onion.create params: {e}"))?;
    if params.ports.is_empty() {
        return Err("at least one port mapping is required".to_owned());
    }
    let id = Uuid::new_v4().to_string();
    let base_nick = params
        .nickname
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or(&params.name);
    let mut nickname = sanitize_nickname(base_nick);
    // Keep nicknames stable and likely unique; append short id suffix.
    let suffix = id.replace('-', "");
    nickname = format!("{}-{}", nickname, &suffix[..8.min(suffix.len())]);
    let key_dir: PathBuf = onion_root.join(&id);
    ensure_key_dir(&key_dir).await?;

    let db = tobro_store::Db::open(db_path)
        .await
        .map_err(|e| format!("failed to open store: {e}"))?;
    let svc = db
        .create_onion_service(NewOnionService {
            id,
            nickname,
            name: params.name,
            enabled: params.enabled,
            key_dir: key_dir.to_string_lossy().to_string(),
            ports: ports_from_params(params.ports),
        })
        .await
        .map_err(|e| {
            // Best-effort cleanup of empty key dir on DB failure.
            let _ = std::fs::remove_dir(&key_dir);
            format!("failed to create onion service: {e}")
        })?;

    Ok(json!({
        "ok": true,
        "action": "onion.create",
        "service": service_to_json(&svc, runtime_active),
        "note": if svc.enabled {
            "service saved and enabled; connect/start Tor to publish it"
        } else {
            "service saved (disabled)"
        },
    }))
}

pub async fn update(db_path: &Path, params: Value, runtime_active: bool) -> Result<Value, String> {
    let params: UpdateParams =
        serde_json::from_value(params).map_err(|e| format!("invalid onion.update params: {e}"))?;
    let db = tobro_store::Db::open(db_path)
        .await
        .map_err(|e| format!("failed to open store: {e}"))?;
    let patch = OnionServicePatch {
        name: params.name,
        enabled: params.enabled,
        ports: params.ports.map(ports_from_params),
        onion_address: None,
    };
    let svc = db
        .update_onion_service(&params.id, patch)
        .await
        .map_err(|e| format!("failed to update onion service: {e}"))?;
    Ok(json!({
        "ok": true,
        "action": "onion.update",
        "service": service_to_json(&svc, runtime_active),
        "restart_required": runtime_active,
        "note": if runtime_active {
            "saved; active Tor runtime may require reconnect/restart to apply onion service changes"
        } else {
            "saved"
        },
    }))
}

pub async fn delete(db_path: &Path, params: Value) -> Result<Value, String> {
    let params: DeleteParams =
        serde_json::from_value(params).map_err(|e| format!("invalid onion.delete params: {e}"))?;
    let db = tobro_store::Db::open(db_path)
        .await
        .map_err(|e| format!("failed to open store: {e}"))?;
    let svc = db
        .get_onion_service(&params.id)
        .await
        .map_err(|e| format!("failed to load onion service: {e}"))?;
    db.delete_onion_service(&params.id)
        .await
        .map_err(|e| format!("failed to delete onion service: {e}"))?;
    remove_key_dir(Path::new(&svc.key_dir)).await?;
    Ok(json!({
        "ok": true,
        "action": "onion.delete",
        "id": params.id,
        "deleted": true,
        "key_storage_removed": true,
    }))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::json;

    fn base_params() -> Value {
        json!({
            "name": "web",
            "ports": [
                { "virt_port": 80, "target_host": "127.0.0.1", "target_port": 8080 }
            ],
            "enabled": true,
        })
    }

    /// M5 exit criterion: keys and records survive a daemon restart. Every
    /// operation opens the store per call, so a second `list` with a fresh
    /// store handle is equivalent to reopening after a restart.
    #[tokio::test]
    async fn record_and_key_dir_survive_restart() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("tobro.sqlite3");
        let onion_root = dir.path().join("onion-services");

        let created = create(&db_path, &onion_root, base_params(), false)
            .await
            .expect("create ok");
        let svc = &created["service"];
        let id = svc["id"].as_str().unwrap().to_owned();
        let key_dir = svc["key_dir"].as_str().unwrap().to_owned();
        // Simulate the Arti keystore writing identity keys after publishing.
        let key_file = std::path::Path::new(&key_dir).join("hs_ed25519_secret_key");
        std::fs::write(&key_file, "key-material").unwrap();

        // "Restart": fresh store handle, runtime now active.
        let after = list(&db_path, true).await.expect("list ok");
        let services = after["services"].as_array().unwrap();
        assert_eq!(services.len(), 1);
        assert_eq!(services[0]["id"].as_str().unwrap(), id);
        assert_eq!(services[0]["key_dir"].as_str().unwrap(), key_dir);
        // Runtime active but no published address yet after restart.
        assert_eq!(services[0]["runtime_status"].as_str().unwrap(), "pending");
        assert!(key_file.exists(), "key material must survive restart");
        assert_eq!(std::fs::read_to_string(&key_file).unwrap(), "key-material");

        // Changes made before the restart are also persisted.
        let renamed = update(
            &db_path,
            json!({ "id": id, "name": "renamed", "enabled": false }),
            true,
        )
        .await
        .expect("update ok");
        assert_eq!(renamed["service"]["name"].as_str().unwrap(), "renamed");
        let after2 = list(&db_path, false).await.expect("list ok");
        assert_eq!(after2["services"][0]["name"].as_str().unwrap(), "renamed");
        assert!(!after2["services"][0]["enabled"].as_bool().unwrap());
        assert!(
            std::path::Path::new(&after2["services"][0]["key_dir"].as_str().unwrap())
                .join("hs_ed25519_secret_key")
                .exists()
        );
    }

    /// M5 exit criterion: losing the managed key directory must be recoverable
    /// from an encrypted backup bundle without duplicating the record.
    #[tokio::test]
    async fn key_loss_is_recoverable_via_restore() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("tobro.sqlite3");
        let onion_root = dir.path().join("onion-services");
        let state_dir = dir.path();

        let created = create(&db_path, &onion_root, base_params(), false)
            .await
            .expect("create ok");
        let id = created["service"]["id"].as_str().unwrap().to_owned();
        let key_dir = created["service"]["key_dir"].as_str().unwrap().to_owned();
        std::fs::write(
            std::path::Path::new(&key_dir).join("hs_ed25519_secret_key"),
            "key-material",
        )
        .unwrap();

        // Backup while the key is still present.
        let backup_result =
            crate::backup::backup(&db_path, state_dir, json!({ "passphrase": "recover-me" }))
                .await
                .expect("backup ok");
        let bundle = backup_result["bundle"].clone();

        // Simulate catastrophic key loss.
        std::fs::remove_dir_all(&key_dir).unwrap();
        assert!(!std::path::Path::new(&key_dir).exists());

        // Record survives key loss; operations keep working.
        let after = list(&db_path, false).await.expect("list ok");
        assert_eq!(after["services"].as_array().unwrap().len(), 1);

        // Restore the bundle: the record id exists, so it must be skipped
        // (not duplicated) but the missing key files are recreated.
        let restore_result = crate::backup::restore(
            &db_path,
            state_dir,
            json!({ "passphrase": "recover-me", "bundle": bundle }),
            true,
        )
        .await
        .expect("restore ok");
        assert_eq!(restore_result["restored"]["services"], 0);
        assert_eq!(
            restore_result["skipped"]["services"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert!(restore_result["restart_required"].as_bool().unwrap());

        let key_file = std::path::Path::new(&key_dir).join("hs_ed25519_secret_key");
        assert!(key_file.exists(), "restore must recreate lost key files");
        assert_eq!(std::fs::read_to_string(&key_file).unwrap(), "key-material");

        // Exactly one record afterwards.
        let final_list = list(&db_path, false).await.expect("list ok");
        let services = final_list["services"].as_array().unwrap();
        assert_eq!(services.len(), 1);
        assert_eq!(services[0]["id"].as_str().unwrap(), id);
    }
}
