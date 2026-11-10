//! Encrypted backup/restore bundles for onion services and client auth (M5).
//!
//! A bundle captures everything needed to move onion-service and client
//! authorization keys to another machine (or recover from key loss):
//!
//! - onion service records (metadata, ports, addresses) and their managed key
//!   directories (`onion-services/<id>/**`, including `authorized_clients`)
//! - client authorization credentials (metadata, public keys) and their
//!   managed key directories (`client-auth/<id>/**`)
//! - credential↔service attachments
//! - the Arti keystore files (`keys/**`) that hold the services' identity keys
//!
//! The payload is encrypted with AES-256-GCM under a key derived from a
//! passphrase with PBKDF2-HMAC-SHA256. The bundle never travels or rests on
//! disk unencrypted; the daemon returns/accepts the envelope inline over IPC
//! and callers handle file I/O.
//!
//! Warning copy (plan F-56): a bundle contains private keys protected only by
//! its passphrase — users must be told to keep it secure.

use std::path::{Path, PathBuf};

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit as _, Nonce};
use data_encoding::BASE64;
use pbkdf2::pbkdf2_hmac;
use rand::RngCore as _;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::Sha256;
use zeroize::Zeroizing;

use tobro_store::{NewClientAuthCredential, NewOnionService, OnionServicePort};

/// Bundle format identifier.
pub const BACKUP_FORMAT: &str = "tobro-backup";
/// Bundle format version (current).
pub const BACKUP_VERSION: u32 = 1;
/// KDF algorithm identifier.
const KDF_ALGORITHM: &str = "pbkdf2-hmac-sha256";
/// Cipher identifier.
const CIPHER: &str = "aes-256-gcm";
/// PBKDF2 iterations (matches the app-lock password verifier cost).
const PBKDF2_ITERATIONS: u32 = 600_000;
/// Default bundle filename (stamp is appended by callers when needed).
pub const BACKUP_FILENAME_BASE: &str = "tobro-onion-backup";

const BACKUP_WARNING: &str = "This bundle contains the private keys of your onion services and client credentials. It is protected only by its passphrase: use a strong passphrase, keep the file secure, and delete copies you no longer need.";
const RESTORE_WARNING: &str = "Restore added key material to this machine. Reconnect/restart Tor to apply it to running services. Restoring client credentials re-enables access for anyone still holding the exported .auth_private files.";

#[derive(Debug, Serialize, Deserialize)]
struct KdfParams {
    algorithm: String,
    iterations: u32,
    /// Hex-encoded salt.
    salt: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct BackupEnvelope {
    format: String,
    version: u32,
    /// Unix timestamp in milliseconds.
    created_at: i64,
    kdf: KdfParams,
    cipher: String,
    /// Hex-encoded 12-byte AES-GCM nonce.
    nonce: String,
    /// Base64-encoded ciphertext (AES-256-GCM, tag appended).
    ciphertext: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct FileBackup {
    /// Path relative to the collection root (e.g. `authorized_clients/x.auth`).
    path: String,
    /// Base64-encoded file contents.
    data: String,
    /// Unix permission bits (0 on non-Unix or when unavailable).
    #[serde(default)]
    mode: u32,
}

#[derive(Debug, Serialize, Deserialize)]
struct ServiceBackup {
    id: String,
    nickname: String,
    name: String,
    enabled: bool,
    onion_address: Option<String>,
    created_at: i64,
    updated_at: i64,
    ports: Vec<OnionServicePort>,
    files: Vec<FileBackup>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ClientAuthBackup {
    id: String,
    nickname: String,
    public_key: String,
    created_at: i64,
    updated_at: i64,
    files: Vec<FileBackup>,
}

#[derive(Debug, Serialize, Deserialize)]
struct AttachmentBackup {
    service_id: String,
    client_auth_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct BackupPayload {
    services: Vec<ServiceBackup>,
    client_auth: Vec<ClientAuthBackup>,
    attachments: Vec<AttachmentBackup>,
    /// Arti keystore files, relative to `<state_dir>/keys`.
    keystore_files: Vec<FileBackup>,
}

#[derive(Debug, Deserialize)]
struct BackupParams {
    passphrase: String,
    /// Optional service id filter (attachments follow their services).
    #[serde(default)]
    service_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RestoreParams {
    passphrase: String,
    /// The decrypted bundle envelope as produced by `onion.backup`.
    bundle: Value,
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn backup_stamp() -> String {
    now_ms().to_string()
}

/// Recursively collect regular files under `root` as [`FileBackup`] entries.
/// A missing root (e.g. the keystore before the first Tor launch) yields an
/// empty list.
async fn collect_files(root: &Path) -> Result<Vec<FileBackup>, String> {
    let mut out = Vec::new();
    if tokio::fs::metadata(root).await.is_err() {
        return Ok(out);
    }
    collect_files_inner(root, root, &mut out).await?;
    Ok(out)
}

/// Recursive walker body; boxed because it recurses into subdirectories.
fn collect_files_inner<'a>(
    root: &'a Path,
    dir: &'a Path,
    out: &'a mut Vec<FileBackup>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'a>> {
    Box::pin(async move {
        let mut read_dir = tokio::fs::read_dir(dir)
            .await
            .map_err(|e| format!("failed to read {}: {e}", dir.display()))?;
        let mut entries = Vec::new();
        while let Some(entry) = read_dir
            .next_entry()
            .await
            .map_err(|e| format!("failed to read directory entry: {e}"))?
        {
            entries.push(entry);
        }
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            let path = entry.path();
            let file_type = entry
                .file_type()
                .await
                .map_err(|e| format!("failed to stat {}: {e}", path.display()))?;
            if file_type.is_symlink() {
                // Never follow symlinks out of managed key directories.
                continue;
            }
            if file_type.is_dir() {
                collect_files_inner(root, &path, out).await?;
            } else if file_type.is_file() {
                let rel = path
                    .strip_prefix(root)
                    .map_err(|e| format!("failed to relativize {}: {e}", path.display()))?
                    .to_string_lossy()
                    .to_string();
                let data = tokio::fs::read(&path)
                    .await
                    .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
                #[cfg(unix)]
                let mode = {
                    let meta = entry
                        .metadata()
                        .await
                        .map_err(|e| format!("failed to stat {}: {e}", path.display()))?;
                    std::os::unix::fs::MetadataExt::mode(&meta) & 0o777
                };
                #[cfg(not(unix))]
                let mode = 0u32;
                out.push(FileBackup {
                    path: rel,
                    data: BASE64.encode(&data),
                    mode,
                });
            }
        }
        Ok(())
    })
}

/// Reject path traversal and absolute components in bundle file entries.
fn safe_rel_path(path: &str) -> Result<PathBuf, String> {
    let rel = Path::new(path);
    if rel.is_absolute()
        || path.contains("..")
        || path.starts_with('/')
        || path.contains('\\')
        || rel
            .components()
            .any(|c| matches!(c, std::path::Component::CurDir))
    {
        return Err(format!("unsafe path in bundle: {path:?}"));
    }
    Ok(rel.to_path_buf())
}

#[cfg(unix)]
fn apply_file_mode(path: &Path, mode: u32) {
    if mode != 0 {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode & 0o777));
    }
}

#[cfg(not(unix))]
fn apply_file_mode(_path: &Path, _mode: u32) {}

async fn write_private_dir(path: &Path) -> Result<(), String> {
    tokio::fs::create_dir_all(path)
        .await
        .map_err(|e| format!("failed to create {}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("failed to set permissions on {}: {e}", path.display()))?;
    }
    Ok(())
}

async fn write_backup_files(
    root: &Path,
    files: &[FileBackup],
    only_missing: bool,
) -> Result<usize, String> {
    let mut written = 0usize;
    for file in files {
        let rel = safe_rel_path(&file.path)?;
        let target = root.join(rel);
        if only_missing && target.exists() {
            continue;
        }
        if let Some(parent) = target.parent() {
            write_private_dir(parent).await?;
        }
        let bytes = BASE64
            .decode(file.data.as_bytes())
            .map_err(|_| format!("invalid base64 file data in bundle: {}", file.path))?;
        tokio::fs::write(&target, &bytes)
            .await
            .map_err(|e| format!("failed to write {}: {e}", target.display()))?;
        apply_file_mode(&target, file.mode);
        written += 1;
    }
    Ok(written)
}

fn derive_key(
    passphrase: &str,
    salt_hex: &str,
    iterations: u32,
) -> Result<Zeroizing<[u8; 32]>, String> {
    let salt = hex::decode(salt_hex)
        .map_err(|_| "invalid salt in bundle envelope".to_owned())
        .map(Zeroizing::new)?;
    if salt.len() < 16 {
        return Err("bundle salt is too short".to_owned());
    }
    let mut key = Zeroizing::new([0u8; 32]);
    pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), &salt, iterations, key.as_mut());
    Ok(key)
}

fn encrypt_payload(passphrase: &str, payload: &BackupPayload) -> Result<BackupEnvelope, String> {
    let mut salt = Zeroizing::new([0u8; 16]);
    rand::thread_rng().fill_bytes(salt.as_mut());
    let mut nonce_bytes = Zeroizing::new([0u8; 12]);
    rand::thread_rng().fill_bytes(nonce_bytes.as_mut());

    let key = derive_key(passphrase, &hex::encode(salt.as_ref()), PBKDF2_ITERATIONS)?;
    let cipher = Aes256Gcm::new_from_slice(key.as_ref())
        .map_err(|_| "backup key derivation failed".to_owned())?;
    let plaintext = serde_json::to_vec(payload)
        .map_err(|e| format!("failed to serialize backup payload: {e}"))?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(nonce_bytes.as_ref()), plaintext.as_ref())
        .map_err(|_| "backup encryption failed".to_owned())?;

    Ok(BackupEnvelope {
        format: BACKUP_FORMAT.to_owned(),
        version: BACKUP_VERSION,
        created_at: now_ms(),
        kdf: KdfParams {
            algorithm: KDF_ALGORITHM.to_owned(),
            iterations: PBKDF2_ITERATIONS,
            salt: hex::encode(salt.as_ref()),
        },
        cipher: CIPHER.to_owned(),
        nonce: hex::encode(nonce_bytes.as_ref()),
        ciphertext: BASE64.encode(&ciphertext),
    })
}

fn decrypt_payload(passphrase: &str, envelope: &BackupEnvelope) -> Result<BackupPayload, String> {
    if envelope.format != BACKUP_FORMAT {
        return Err(format!(
            "not a {BACKUP_FORMAT} bundle (format: {:?})",
            envelope.format
        ));
    }
    if envelope.version != BACKUP_VERSION {
        return Err(format!(
            "unsupported bundle version {} (expected {BACKUP_VERSION})",
            envelope.version
        ));
    }
    if envelope.cipher != CIPHER || envelope.kdf.algorithm != KDF_ALGORITHM {
        return Err("unsupported bundle cipher/kdf".to_owned());
    }
    let key = derive_key(passphrase, &envelope.kdf.salt, envelope.kdf.iterations)?;
    let ciphertext = BASE64
        .decode(envelope.ciphertext.as_bytes())
        .map_err(|_| "invalid ciphertext encoding in bundle".to_owned())?;
    let nonce_bytes =
        hex::decode(&envelope.nonce).map_err(|_| "invalid nonce encoding in bundle".to_owned())?;
    if nonce_bytes.len() != 12 {
        return Err("invalid nonce in bundle envelope".to_owned());
    }
    let cipher = Aes256Gcm::new_from_slice(key.as_ref())
        .map_err(|_| "bundle key derivation failed".to_owned())?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| "could not decrypt bundle: wrong passphrase or corrupted bundle".to_owned())?;
    serde_json::from_slice(&plaintext).map_err(|e| format!("bundle payload is not valid: {e}"))
}

/// Create an encrypted backup bundle.
///
/// Params: `{ "passphrase": "...", "service_ids"?: ["..."] }`. Returns the
/// bundle envelope inline (callers save it to a file); private keys are only
/// present inside the encrypted ciphertext.
pub async fn backup(db_path: &Path, state_dir: &Path, params: Value) -> Result<Value, String> {
    let params: BackupParams =
        serde_json::from_value(params).map_err(|e| format!("invalid onion.backup params: {e}"))?;
    if params.passphrase.is_empty() {
        return Err("a non-empty passphrase is required".to_owned());
    }
    let db = tobro_store::Db::open(db_path)
        .await
        .map_err(|e| format!("failed to open store: {e}"))?;

    let all_services = db
        .list_onion_services()
        .await
        .map_err(|e| format!("failed to list onion services: {e}"))?;
    let selected: Vec<_> = if params.service_ids.is_empty() {
        all_services
    } else {
        all_services
            .into_iter()
            .filter(|svc| params.service_ids.iter().any(|id| id == &svc.id))
            .collect()
    };

    let mut services = Vec::with_capacity(selected.len());
    let mut attachments = Vec::new();
    for svc in &selected {
        let files = collect_files(Path::new(&svc.key_dir)).await?;
        services.push(ServiceBackup {
            id: svc.id.clone(),
            nickname: svc.nickname.clone(),
            name: svc.name.clone(),
            enabled: svc.enabled,
            onion_address: svc.onion_address.clone(),
            created_at: svc.created_at,
            updated_at: svc.updated_at,
            ports: svc.ports.clone(),
            files,
        });
        let creds = db
            .list_client_auth_for_service(&svc.id)
            .await
            .map_err(|e| format!("failed to list client auth for service: {e}"))?;
        for cred in creds {
            attachments.push(AttachmentBackup {
                service_id: svc.id.clone(),
                client_auth_id: cred.id.clone(),
            });
        }
    }

    let mut client_auth = Vec::new();
    for cred in db
        .list_client_auth()
        .await
        .map_err(|e| format!("failed to list client auth: {e}"))?
    {
        // Only include credentials that are (or were) attached to a selected
        // service, or all of them when no filter was given. Simpler and safer:
        // include every credential — a credential alone grants nothing without
        // the service descriptor, and the user explicitly requested a backup.
        let files = collect_files(Path::new(&cred.key_dir)).await?;
        client_auth.push(ClientAuthBackup {
            id: cred.id,
            nickname: cred.nickname,
            public_key: cred.public_key,
            created_at: cred.created_at,
            updated_at: cred.updated_at,
            files,
        });
    }

    let keystore_files = collect_files(&state_dir.join("keys")).await?;

    let payload = BackupPayload {
        services,
        client_auth,
        attachments,
        keystore_files,
    };
    let summary = (
        payload.services.len(),
        payload.client_auth.len(),
        payload.attachments.len(),
        payload.keystore_files.len(),
    );
    let envelope = encrypt_payload(&params.passphrase, &payload)?;

    Ok(json!({
        "ok": true,
        "action": "onion.backup",
        "bundle": serde_json::to_value(&envelope).map_err(|e| format!("failed to serialize bundle: {e}"))?,
        "filename": format!("{BACKUP_FILENAME_BASE}-{}.json", backup_stamp()),
        "counts": {
            "services": summary.0,
            "client_auth": summary.1,
            "attachments": summary.2,
            "keystore_files": summary.3,
        },
        "warning": BACKUP_WARNING,
    }))
}

/// Restore a bundle.
///
/// Params: `{ "passphrase": "...", "bundle": { ...envelope... } }`.
/// Existing service/credential ids are skipped (never overwritten); missing
/// keystore files are added but existing ones are left untouched.
pub async fn restore(
    db_path: &Path,
    state_dir: &Path,
    params: Value,
    runtime_active: bool,
) -> Result<Value, String> {
    let params: RestoreParams =
        serde_json::from_value(params).map_err(|e| format!("invalid onion.restore params: {e}"))?;
    let envelope: BackupEnvelope = serde_json::from_value(params.bundle)
        .map_err(|e| format!("bundle envelope is not valid: {e}"))?;
    let payload = decrypt_payload(&params.passphrase, &envelope)?;

    let db = tobro_store::Db::open(db_path)
        .await
        .map_err(|e| format!("failed to open store: {e}"))?;

    let onion_root = state_dir.join("onion-services");
    let client_auth_root = state_dir.join("client-auth");
    let keystore_root = state_dir.join("keys");

    let mut restored = (0usize, 0usize, 0usize, 0usize);
    let mut skipped_services = Vec::new();
    let mut skipped_client_auth = Vec::new();

    // 1. Keystore files: add missing ones, never overwrite existing material.
    restored.3 = write_backup_files(&keystore_root, &payload.keystore_files, true).await?;

    // 2. Onion services: never overwrite records; re-target key dirs to this
    //    state dir. Existing ids are skipped, but their missing key files are
    //    recreated (never overwritten) so a bundle can repair key loss.
    for svc in &payload.services {
        let key_dir = onion_root.join(&svc.id);
        if db.get_onion_service(&svc.id).await.is_ok() {
            skipped_services.push(svc.id.clone());
            write_backup_files(&key_dir, &svc.files, true).await?;
            continue;
        }
        write_backup_files(&key_dir, &svc.files, false).await?;
        db.create_onion_service(NewOnionService {
            id: svc.id.clone(),
            nickname: svc.nickname.clone(),
            name: svc.name.clone(),
            enabled: svc.enabled,
            key_dir: key_dir.to_string_lossy().to_string(),
            ports: svc.ports.clone(),
        })
        .await
        .map_err(|e| format!("failed to restore onion service {}: {e}", svc.id))?;
        restored.0 += 1;
    }

    // 3. Client auth credentials: same skip-but-repair semantics.
    for cred in &payload.client_auth {
        let key_dir = client_auth_root.join(&cred.id);
        if db.get_client_auth(&cred.id).await.is_ok() {
            skipped_client_auth.push(cred.id.clone());
            write_backup_files(&key_dir, &cred.files, true).await?;
            continue;
        }
        write_backup_files(&key_dir, &cred.files, false).await?;
        db.create_client_auth(NewClientAuthCredential {
            id: cred.id.clone(),
            nickname: cred.nickname.clone(),
            key_dir: key_dir.to_string_lossy().to_string(),
            public_key: cred.public_key.clone(),
        })
        .await
        .map_err(|e| format!("failed to restore client credential {}: {e}", cred.id))?;
        restored.1 += 1;
    }

    // 4. Attachments (only when both sides were restored or already exist).
    for att in &payload.attachments {
        let both_known = db.get_onion_service(&att.service_id).await.is_ok()
            && db.get_client_auth(&att.client_auth_id).await.is_ok();
        if !both_known {
            continue;
        }
        if db
            .attach_client_auth(&att.service_id, &att.client_auth_id)
            .await
            .is_ok()
        {
            restored.2 += 1;
        }
    }

    // 5. Refresh authorized_clients dirs for all touched services.
    for svc in &payload.services {
        let _ = crate::client_auth::sync_service_authorized_clients(&db, &svc.id).await;
    }

    Ok(json!({
        "ok": true,
        "action": "onion.restore",
        "restored": {
            "services": restored.0,
            "client_auth": restored.1,
            "attachments": restored.2,
            "keystore_files": restored.3,
        },
        "skipped": {
            "services": skipped_services,
            "client_auth": skipped_client_auth,
        },
        "restart_required": runtime_active,
        "warning": RESTORE_WARNING,
    }))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::fs;

    fn service(id: &str, nickname: &str, name: &str) -> NewOnionService {
        NewOnionService {
            id: id.to_owned(),
            nickname: nickname.to_owned(),
            name: name.to_owned(),
            enabled: true,
            key_dir: String::new(),
            ports: vec![OnionServicePort {
                virt_port: 80,
                target_host: "127.0.0.1".to_owned(),
                target_port: 8080,
            }],
        }
    }

    async fn seed(dir: &Path) {
        let db_path = dir.join("state.sqlite3");
        let db = tobro_store::Db::open(&db_path).await.unwrap();
        let mut svc = service("11111111-1111-1111-1111-111111111111", "svc-a", "svc-a");
        let svc_id = svc.id.clone();
        svc.key_dir = dir
            .join("onion-services")
            .join(&svc_id)
            .display()
            .to_string();
        db.create_onion_service(svc).await.unwrap();
        db.create_client_auth(NewClientAuthCredential {
            id: "22222222-2222-2222-2222-222222222222".to_owned(),
            nickname: "client-a".to_owned(),
            key_dir: dir
                .join("client-auth")
                .join("22222222-2222-2222-2222-222222222222")
                .display()
                .to_string(),
            public_key:
                "descriptor:x25519:ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOPABCDEFGHIJKLMNOPAAAAAAAA"
                    .to_owned(),
        })
        .await
        .unwrap();
        db.attach_client_auth(
            "11111111-1111-1111-1111-111111111111",
            "22222222-2222-2222-2222-222222222222",
        )
        .await
        .unwrap();
        // Managed key material on disk.
        let cred_dir = dir
            .join("client-auth")
            .join("22222222-2222-2222-2222-222222222222");
        std::fs::create_dir_all(&cred_dir).unwrap();
        std::fs::write(
            cred_dir.join("credential.auth_private"),
            "descriptor:x25519:AAAA\n",
        )
        .unwrap();
        let svc_dir = dir
            .join("onion-services")
            .join(svc_id)
            .join("authorized_clients");
        std::fs::create_dir_all(&svc_dir).unwrap();
        std::fs::write(svc_dir.join("client-a.auth"), "descriptor:x25519:BBBB\n").unwrap();
        // Fake Arti keystore file.
        let keys = dir.join("keys").join("artisan").join("svc-a");
        std::fs::create_dir_all(&keys).unwrap();
        std::fs::write(keys.join("hs_ed25519_secret_key"), "fake-identity-key").unwrap();
    }

    #[tokio::test]
    async fn backup_restore_roundtrip_to_fresh_state() {
        let src = tempfile::tempdir().unwrap();
        seed(src.path()).await;

        let backup_result = backup(
            &src.path().join("state.sqlite3"),
            src.path(),
            json!({ "passphrase": "correct horse battery staple" }),
        )
        .await
        .expect("backup ok");
        assert_eq!(backup_result["counts"]["services"], 1);
        assert_eq!(backup_result["counts"]["client_auth"], 1);
        assert_eq!(backup_result["counts"]["attachments"], 1);
        assert_eq!(backup_result["counts"]["keystore_files"], 1);
        assert!(
            backup_result["warning"]
                .as_str()
                .unwrap()
                .contains("private keys")
        );

        // Envelope is encrypted: the passphrase and key material must not appear.
        let envelope_text = serde_json::to_string(&backup_result["bundle"]).unwrap();
        assert!(!envelope_text.contains("correct horse"));
        assert!(!envelope_text.contains("fake-identity-key"));

        // Restore into a fresh state dir (simulates a new machine).
        let dst = tempfile::tempdir().unwrap();
        let restore_result = restore(
            &dst.path().join("state.sqlite3"),
            dst.path(),
            json!({
                "passphrase": "correct horse battery staple",
                "bundle": backup_result["bundle"],
            }),
            false,
        )
        .await
        .expect("restore ok");
        assert_eq!(restore_result["restored"]["services"], 1);
        assert_eq!(restore_result["restored"]["client_auth"], 1);
        assert_eq!(restore_result["restored"]["attachments"], 1);
        assert_eq!(restore_result["restored"]["keystore_files"], 1);

        // Records and key material landed with re-targeted key dirs.
        let db = tobro_store::Db::open(&dst.path().join("state.sqlite3"))
            .await
            .unwrap();
        let svc = db
            .get_onion_service("11111111-1111-1111-1111-111111111111")
            .await
            .unwrap();
        assert_eq!(svc.nickname, "svc-a");
        assert!(
            svc.key_dir
                .starts_with(&dst.path().join("onion-services").display().to_string())
        );
        assert!(
            dst.path()
                .join("keys/artisan/svc-a/hs_ed25519_secret_key")
                .exists()
        );
        let auth_file = dst.path().join(
            "onion-services/11111111-1111-1111-1111-111111111111/authorized_clients/client-a.auth",
        );
        // Re-synced from DB attachments during restore (public key + newline).
        assert_eq!(
            fs::read_to_string(auth_file).unwrap(),
            "descriptor:x25519:ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOPABCDEFGHIJKLMNOPAAAAAAAA\n"
        );
        let cred = db
            .get_client_auth("22222222-2222-2222-2222-222222222222")
            .await
            .unwrap();
        assert!(
            cred.key_dir
                .starts_with(&dst.path().join("client-auth").display().to_string())
        );
        let attached = db
            .list_client_auth_for_service("11111111-1111-1111-1111-111111111111")
            .await
            .unwrap();
        assert_eq!(attached.len(), 1);
    }

    #[tokio::test]
    async fn restore_with_wrong_passphrase_fails() {
        let src = tempfile::tempdir().unwrap();
        seed(src.path()).await;
        let backup_result = backup(
            &src.path().join("state.sqlite3"),
            src.path(),
            json!({ "passphrase": "right" }),
        )
        .await
        .unwrap();
        let dst = tempfile::tempdir().unwrap();
        let err = restore(
            &dst.path().join("state.sqlite3"),
            dst.path(),
            json!({ "passphrase": "wrong", "bundle": backup_result["bundle"] }),
            false,
        )
        .await
        .unwrap_err();
        assert!(err.contains("wrong passphrase"), "unexpected: {err}");
    }

    #[tokio::test]
    async fn restore_rejects_tampered_ciphertext() {
        let src = tempfile::tempdir().unwrap();
        seed(src.path()).await;
        let mut backup_result = backup(
            &src.path().join("state.sqlite3"),
            src.path(),
            json!({ "passphrase": "right" }),
        )
        .await
        .unwrap();
        // Flip a character in the ciphertext.
        let ct = backup_result["bundle"]["ciphertext"]
            .as_str()
            .unwrap()
            .to_owned();
        let mut bytes = ct.into_bytes();
        let flip = bytes.iter().position(|b| *b != b'A').unwrap_or(0);
        bytes[flip] = if bytes[flip] == b'B' { b'C' } else { b'B' };
        backup_result["bundle"]["ciphertext"] = json!(String::from_utf8(bytes).unwrap());
        let dst = tempfile::tempdir().unwrap();
        let err = restore(
            &dst.path().join("state.sqlite3"),
            dst.path(),
            json!({ "passphrase": "right", "bundle": backup_result["bundle"] }),
            false,
        )
        .await
        .unwrap_err();
        assert!(
            err.contains("wrong passphrase or corrupted"),
            "unexpected: {err}"
        );
    }

    #[tokio::test]
    async fn restore_rejects_foreign_format_and_paths() {
        let dst = tempfile::tempdir().unwrap();
        let db_path = dst.path().join("state.sqlite3");

        // Foreign format.
        let err = restore(
            &db_path,
            dst.path(),
            json!({
                "passphrase": "x",
                "bundle": { "format": "other", "version": 1, "created_at": 0, "cipher": "aes-256-gcm",
                    "kdf": { "algorithm": "pbkdf2-hmac-sha256", "iterations": 1, "salt": "00" },
                    "nonce": "00", "ciphertext": "AAAA" }
            }),
            false,
        )
        .await
        .unwrap_err();
        assert!(err.contains("not a tobro-backup"), "unexpected: {err}");

        // Path traversal inside file entries.
        let payload = BackupPayload {
            services: vec![],
            client_auth: vec![],
            attachments: vec![],
            keystore_files: vec![FileBackup {
                path: "../escape.txt".to_owned(),
                data: BASE64.encode(b"x"),
                mode: 0,
            }],
        };
        let envelope = encrypt_payload("pw", &payload).unwrap();
        let err = restore(
            &db_path,
            dst.path(),
            json!({ "passphrase": "pw", "bundle": serde_json::to_value(&envelope).unwrap() }),
            false,
        )
        .await
        .unwrap_err();
        assert!(err.contains("unsafe path"), "unexpected: {err}");
        assert!(!dst.path().parent().unwrap().join("escape.txt").exists());
    }

    #[tokio::test]
    async fn restore_skips_existing_records_and_missing_keystore_files_only() {
        let src = tempfile::tempdir().unwrap();
        seed(src.path()).await;
        let backup_result = backup(
            &src.path().join("state.sqlite3"),
            src.path(),
            json!({ "passphrase": "pw" }),
        )
        .await
        .unwrap();

        // Restore twice into the same state dir.
        let dst = tempfile::tempdir().unwrap();
        for _ in 0..2 {
            restore(
                &dst.path().join("state.sqlite3"),
                dst.path(),
                json!({ "passphrase": "pw", "bundle": backup_result["bundle"] }),
                false,
            )
            .await
            .unwrap();
        }
        let db = tobro_store::Db::open(&dst.path().join("state.sqlite3"))
            .await
            .unwrap();
        assert_eq!(db.list_onion_services().await.unwrap().len(), 1);
        assert_eq!(db.list_client_auth().await.unwrap().len(), 1);

        // Keystore file was not overwritten (original content preserved after
        // an external modification).
        let key_file = dst.path().join("keys/artisan/svc-a/hs_ed25519_secret_key");
        fs::write(&key_file, "tampered").unwrap();
        restore(
            &dst.path().join("state.sqlite3"),
            dst.path(),
            json!({ "passphrase": "pw", "bundle": backup_result["bundle"] }),
            false,
        )
        .await
        .unwrap();
        assert_eq!(fs::read_to_string(&key_file).unwrap(), "tampered");
    }

    #[tokio::test]
    async fn backup_with_service_filter_and_empty_passphrase_rejected() {
        let src = tempfile::tempdir().unwrap();
        seed(src.path()).await;

        let err = backup(
            &src.path().join("state.sqlite3"),
            src.path(),
            json!({ "passphrase": "" }),
        )
        .await
        .unwrap_err();
        assert!(err.contains("passphrase"), "unexpected: {err}");

        // Filter that matches nothing yields empty counts.
        let filtered = backup(
            &src.path().join("state.sqlite3"),
            src.path(),
            json!({ "passphrase": "pw", "service_ids": ["nope"] }),
        )
        .await
        .unwrap();
        assert_eq!(filtered["counts"]["services"], 0);
        // Credentials are included unconditionally (they grant nothing without
        // the service descriptor); only the services are filtered.
        assert_eq!(filtered["counts"]["client_auth"], 1);
        assert_eq!(filtered["counts"]["attachments"], 0);
        // Keystore is still included (it holds identity keys).
        assert_eq!(filtered["counts"]["keystore_files"], 1);
    }
}
