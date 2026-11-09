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
