//! Client authorization credential management for onion services.
//!
//! Supports generating/importing/exporting `.auth_private` credentials (x25519
//! descriptor keys) and attaching credentials to hosted onion services via
//! Arti's restricted discovery (`authorized_clients/<nickname>.auth`).

use std::path::{Path, PathBuf};

use data_encoding::BASE32_NOPAD;
use rand::RngCore as _;
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;
use x25519_dalek::{PublicKey, StaticSecret};

use tobro_store::NewClientAuthCredential;

#[derive(Debug, Deserialize)]
struct GenerateParams {
    #[serde(default)]
    nickname: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ImportParams {
    nickname: String,
    /// Full `.auth_private` file contents.
    content: String,
}

#[derive(Debug, Deserialize)]
struct ExportParams {
    id: String,
    /// Target onion address/hsid for the `.auth_private` line. If omitted, we try
    /// to infer from an attached service with a published onion address.
    #[serde(default)]
    onion_address: Option<String>,
}

#[derive(Debug, Deserialize)]
struct IdParams {
    id: String,
}

#[derive(Debug, Deserialize)]
struct AttachParams {
    service_id: String,
    client_auth_id: String,
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
        "client".to_owned()
    } else {
        out
    }
}

fn normalize_onion_hsid(input: &str) -> Result<String, String> {
    // Onion addresses are case-insensitive; normalize first so the `.onion`
    // suffix is stripped regardless of its case.
    let lower = input.trim().to_ascii_lowercase();
    let s = lower.strip_suffix(".onion").unwrap_or(lower.as_str());
    if s.is_empty() {
        return Err("onion address must not be empty".to_owned());
    }
    // Basic sanity: v3 onion service ids are 56 chars base32, but accept other
    // lengths for compatibility; reject whitespace/control chars.
    if s.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err("onion address contains invalid whitespace/control characters".to_owned());
    }
    Ok(s.to_owned())
}

fn public_key_from_secret_bytes(secret: &[u8; 32]) -> String {
    let secret = StaticSecret::from(*secret);
    let public = PublicKey::from(&secret);
    let encoded = BASE32_NOPAD.encode(public.as_bytes());
    format!("descriptor:x25519:{encoded}")
}

fn generate_secret_bytes() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    // Use thread-local CSPRNG; acceptable for local credential generation.
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut bytes);
    // Clamp for X25519 (defense in depth; dalek clamps during DH).
    bytes[0] &= 248;
    bytes[31] &= 127;
    bytes[31] |= 64;
    bytes
}

fn auth_private_line(hsid: &str, secret_b32: &str) -> String {
    // Common Tor client auth private format includes hsid prefix.
    // `1:` version prefix is accepted by C Tor key parsing variants.
    format!("1:{hsid}:descriptor:x25519:{secret_b32}")
}

fn parse_auth_private(content: &str) -> Result<(Option<String>, [u8; 32]), String> {
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Accept forms:
        // 1:<hsid>:descriptor:x25519:<key>
        // <hsid>:descriptor:x25519:<key>
        // descriptor:x25519:<key>
        let parts: Vec<&str> = line.split(':').collect();
        let (hsid, key_b32) = if parts.len() >= 5
            && parts[0] == "1"
            && parts[2] == "descriptor"
            && parts[3] == "x25519"
        {
            (Some(parts[1].to_owned()), parts[4])
        } else if parts.len() >= 4 && parts[1] == "descriptor" && parts[2] == "x25519" {
            (Some(parts[0].to_owned()), parts[3])
        } else if parts.len() >= 3 && parts[0] == "descriptor" && parts[1] == "x25519" {
            (None, parts[2])
        } else {
            continue;
        };
        let key_b32 = key_b32.trim();
        let decoded = BASE32_NOPAD
            .decode(key_b32.to_uppercase().as_bytes())
            .or_else(|_| {
                // Some files may use padded base32; try common padding.
                let mut padded = key_b32.to_uppercase();
                while padded.len() % 8 != 0 {
                    padded.push('=');
                }
                data_encoding::BASE32.decode(padded.as_bytes())
            })
            .map_err(|_| "invalid base32 key material in .auth_private".to_owned())?;
        let bytes: [u8; 32] = decoded
            .as_slice()
            .try_into()
            .map_err(|_| "x25519 key material must be 32 bytes".to_owned())?;
        let hsid = hsid.and_then(|h| normalize_onion_hsid(&h).ok());
        return Ok((hsid, bytes));
    }
    Err("no valid descriptor:x25519 key found in .auth_private content".to_owned())
}

async fn ensure_private_dir(path: &Path) -> Result<(), String> {
    tokio::fs::create_dir_all(path)
        .await
        .map_err(|e| format!("failed to create directory {}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("failed to set permissions on {}: {e}", path.display()))?;
    }
    Ok(())
}

async fn write_private_file(path: &Path, content: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        ensure_private_dir(parent).await?;
    }
    tokio::fs::write(path, content)
        .await
        .map_err(|e| format!("failed to write {}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("failed to set permissions on {}: {e}", path.display()))?;
    }
    Ok(())
}

fn secret_file_path(key_dir: &Path) -> PathBuf {
    key_dir.join("credential.auth_private")
}

fn service_authorized_clients_dir(service_key_dir: &Path) -> PathBuf {
    service_key_dir.join("authorized_clients")
}

async fn read_secret_b32(key_dir: &Path) -> Result<String, String> {
    let path = secret_file_path(key_dir);
    let content = tokio::fs::read_to_string(&path)
        .await
        .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    let (_hsid, bytes) = parse_auth_private(&content)?;
    Ok(BASE32_NOPAD.encode(&bytes))
}

/// Re-write the `authorized_clients/<nickname>.auth` files for a service from
/// its DB attachments. Used by attach/detach and by bundle restore.
pub async fn sync_service_authorized_clients(
    db: &tobro_store::Db,
    service_id: &str,
) -> Result<(), String> {
    let svc = db
        .get_onion_service(service_id)
        .await
        .map_err(|e| format!("failed to load onion service: {e}"))?;
    let creds = db
        .list_client_auth_for_service(service_id)
        .await
        .map_err(|e| format!("failed to list attached client auth: {e}"))?;
    let dir = service_authorized_clients_dir(Path::new(&svc.key_dir));
    if creds.is_empty() {
        if dir.exists() {
            // Keep directory tidy but don't fail hard.
            let _ = tokio::fs::remove_dir_all(&dir).await;
        }
        return Ok(());
    }
    ensure_private_dir(&dir).await?;
    // Remove stale .auth files first.
    if let Ok(mut rd) = tokio::fs::read_dir(&dir).await {
        while let Ok(Some(entry)) = rd.next_entry().await {
            let p = entry.path();
            if p.extension().and_then(|s| s.to_str()) == Some("auth") {
                let _ = tokio::fs::remove_file(p).await;
            }
        }
    }
    for cred in creds {
        let file = dir.join(format!("{}.auth", cred.nickname));
        write_private_file(&file, &format!("{}\n", cred.public_key)).await?;
    }
    Ok(())
}

fn credential_to_json(
    cred: &tobro_store::ClientAuthCredential,
    attached_services: Vec<String>,
) -> Value {
    json!({
        "id": cred.id,
        "nickname": cred.nickname,
        "key_dir": cred.key_dir,
        "public_key": cred.public_key,
        "created_at": cred.created_at,
        "updated_at": cred.updated_at,
        "attached_service_ids": attached_services,
    })
}

pub async fn list(db_path: &Path) -> Result<Value, String> {
    let db = tobro_store::Db::open(db_path)
        .await
        .map_err(|e| format!("failed to open store: {e}"))?;
    let creds = db
        .list_client_auth()
        .await
        .map_err(|e| format!("failed to list client auth: {e}"))?;
    let mut services = Vec::with_capacity(creds.len());
    for cred in &creds {
        let attached = db
            .list_services_for_client_auth(&cred.id)
            .await
            .unwrap_or_default();
        services.push(credential_to_json(cred, attached));
    }
    Ok(json!({
        "ok": true,
        "action": "client_auth.list",
        "credentials": services,
    }))
}

pub async fn generate(
    db_path: &Path,
    client_auth_root: &Path,
    params: Value,
) -> Result<Value, String> {
    let params: GenerateParams =
        serde_json::from_value(params).unwrap_or(GenerateParams { nickname: None });
    let id = Uuid::new_v4().to_string();
    let base = params
        .nickname
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or("client");
    let mut nickname = sanitize_nickname(base);
    let suffix = id.replace('-', "");
    nickname = format!("{}-{}", nickname, &suffix[..8.min(suffix.len())]);
    let secret = generate_secret_bytes();
    let secret_b32 = BASE32_NOPAD.encode(&secret);
    let public_key = public_key_from_secret_bytes(&secret);
    let key_dir = client_auth_root.join(&id);
    ensure_private_dir(&key_dir).await?;
    // Store as a portable .auth_private template (hsid placeholder not included in file;
    // export adds hsid). Keep the raw secret key in standard format.
    write_private_file(
        &secret_file_path(&key_dir),
        &format!("descriptor:x25519:{secret_b32}\n"),
    )
    .await?;

    let db = tobro_store::Db::open(db_path)
        .await
        .map_err(|e| format!("failed to open store: {e}"))?;
    let cred = db
        .create_client_auth(NewClientAuthCredential {
            id,
            nickname,
            key_dir: key_dir.to_string_lossy().to_string(),
            public_key,
        })
        .await
        .map_err(|e| {
            let _ = std::fs::remove_dir_all(&key_dir);
            format!("failed to create client auth credential: {e}")
        })?;
    let attached = db
        .list_services_for_client_auth(&cred.id)
        .await
        .unwrap_or_default();
    Ok(json!({
        "ok": true,
        "action": "client_auth.generate",
        "credential": credential_to_json(&cred, attached),
        "note": "Credential generated. Use Export to save a .auth_private file for a client (provide the target .onion address), then Attach to an onion service to enable restricted discovery.",
    }))
}

pub async fn import(
    db_path: &Path,
    client_auth_root: &Path,
    params: Value,
) -> Result<Value, String> {
    let params: ImportParams = serde_json::from_value(params)
        .map_err(|e| format!("invalid client_auth.import params: {e}"))?;
    let (_hsid, secret) = parse_auth_private(&params.content)?;
    let secret_b32 = BASE32_NOPAD.encode(&secret);
    let public_key = public_key_from_secret_bytes(&secret);
    let id = Uuid::new_v4().to_string();
    let mut nickname = sanitize_nickname(&params.nickname);
    let suffix = id.replace('-', "");
    nickname = format!("{}-{}", nickname, &suffix[..8.min(suffix.len())]);
    let key_dir = client_auth_root.join(&id);
    ensure_private_dir(&key_dir).await?;
    // Preserve original content for export fidelity where possible? we store normalized.
    write_private_file(
        &secret_file_path(&key_dir),
        &format!("descriptor:x25519:{secret_b32}\n"),
    )
    .await?;
    let db = tobro_store::Db::open(db_path)
        .await
        .map_err(|e| format!("failed to open store: {e}"))?;
    let cred = db
        .create_client_auth(NewClientAuthCredential {
            id,
            nickname,
            key_dir: key_dir.to_string_lossy().to_string(),
            public_key,
        })
        .await
        .map_err(|e| {
            let _ = std::fs::remove_dir_all(&key_dir);
            format!("failed to import client auth credential: {e}")
        })?;
    Ok(json!({
        "ok": true,
        "action": "client_auth.import",
        "credential": credential_to_json(&cred, vec![]),
    }))
}

pub async fn export(db_path: &Path, params: Value) -> Result<Value, String> {
    let params: ExportParams = serde_json::from_value(params)
        .map_err(|e| format!("invalid client_auth.export params: {e}"))?;
    let db = tobro_store::Db::open(db_path)
        .await
        .map_err(|e| format!("failed to open store: {e}"))?;
    let cred = db
        .get_client_auth(&params.id)
        .await
        .map_err(|e| format!("failed to load client auth: {e}"))?;
    let hsid = if let Some(addr) = params
        .onion_address
        .as_deref()
        .filter(|s| !s.trim().is_empty())
    {
        normalize_onion_hsid(addr)?
    } else {
        // Try to infer from an attached service with a published address.
        let svc_ids = db
            .list_services_for_client_auth(&cred.id)
            .await
            .unwrap_or_default();
        let mut found = None;
        for sid in svc_ids {
            if let Ok(svc) = db.get_onion_service(&sid).await
                && let Some(addr) = svc.onion_address
            {
                found = Some(normalize_onion_hsid(&addr)?);
                break;
            }
        }
        found.ok_or_else(|| {
            "onion_address is required for .auth_private export (no attached service with a published .onion address found)".to_owned()
        })?
    };
    let secret_b32 = read_secret_b32(Path::new(&cred.key_dir)).await?;
    let content = format!("{}\n", auth_private_line(&hsid, &secret_b32));
    let filename = format!("{hsid}.auth_private");
    Ok(json!({
        "ok": true,
        "action": "client_auth.export",
        "id": cred.id,
        "nickname": cred.nickname,
        "filename": filename,
        "content": content,
        "warning": "This file contains a private key. Store and transmit it securely.",
    }))
}

pub async fn delete(db_path: &Path, params: Value) -> Result<Value, String> {
    let params: IdParams = serde_json::from_value(params)
        .map_err(|e| format!("invalid client_auth.delete params: {e}"))?;
    let db = tobro_store::Db::open(db_path)
        .await
        .map_err(|e| format!("failed to open store: {e}"))?;
    let cred = db
        .get_client_auth(&params.id)
        .await
        .map_err(|e| format!("failed to load client auth: {e}"))?;
    let attached = db
        .list_services_for_client_auth(&params.id)
        .await
        .unwrap_or_default();
    db.delete_client_auth(&params.id)
        .await
        .map_err(|e| format!("failed to delete client auth: {e}"))?;
    // Best-effort resync attached services (CASCADE already removed links, but
    // if DB behavior differs, resync is harmless; after delete links are gone).
    for sid in attached {
        let _ = sync_service_authorized_clients(&db, &sid).await;
    }
    if Path::new(&cred.key_dir).exists() {
        tokio::fs::remove_dir_all(&cred.key_dir)
            .await
            .map_err(|e| format!("failed to remove key dir {}: {e}", cred.key_dir))?;
    }
    Ok(json!({
        "ok": true,
        "action": "client_auth.delete",
        "id": params.id,
        "deleted": true,
    }))
}

pub async fn attach(db_path: &Path, params: Value) -> Result<Value, String> {
    let params: AttachParams = serde_json::from_value(params)
        .map_err(|e| format!("invalid client_auth.attach params: {e}"))?;
    let db = tobro_store::Db::open(db_path)
        .await
        .map_err(|e| format!("failed to open store: {e}"))?;
    db.attach_client_auth(&params.service_id, &params.client_auth_id)
        .await
        .map_err(|e| format!("failed to attach client auth: {e}"))?;
    sync_service_authorized_clients(&db, &params.service_id).await?;
    Ok(json!({
        "ok": true,
        "action": "client_auth.attach",
        "service_id": params.service_id,
        "client_auth_id": params.client_auth_id,
        "restart_required": true,
        "note": "Client authorized. Restricted discovery files updated; reconnect/restart Tor to apply to a running service.",
    }))
}

pub async fn detach(db_path: &Path, params: Value) -> Result<Value, String> {
    let params: AttachParams = serde_json::from_value(params)
        .map_err(|e| format!("invalid client_auth.detach params: {e}"))?;
    let db = tobro_store::Db::open(db_path)
        .await
        .map_err(|e| format!("failed to open store: {e}"))?;
    db.detach_client_auth(&params.service_id, &params.client_auth_id)
        .await
        .map_err(|e| format!("failed to detach client auth: {e}"))?;
    // Best-effort sync even if service was removed; ignore not-found.
    let _ = sync_service_authorized_clients(&db, &params.service_id).await;
    Ok(json!({
        "ok": true,
        "action": "client_auth.detach",
        "service_id": params.service_id,
        "client_auth_id": params.client_auth_id,
        "restart_required": true,
        "note": "Client authorization removed; reconnect/restart Tor to apply to a running service. Removing authorized clients does not guarantee immediate revocation for an already-connected client.",
    }))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::fs;

    fn key_b32() -> String {
        BASE32_NOPAD.encode(&[7u8; 32])
    }

    fn key_b32_padded() -> String {
        let mut s = key_b32();
        while !s.len().is_multiple_of(8) {
            s.push('=');
        }
        s
    }

    #[test]
    fn parse_accepts_bare_descriptor_line() {
        let (hsid, bytes) =
            parse_auth_private(&format!("descriptor:x25519:{}\n", key_b32())).expect("parse ok");
        assert_eq!(hsid, None);
        assert_eq!(bytes, [7u8; 32]);
    }

    #[test]
    fn parse_accepts_hsid_prefixed_line() {
        let content = format!("exampleabcdefghi:descriptor:x25519:{}\n", key_b32());
        let (hsid, bytes) = parse_auth_private(&content).expect("parse ok");
        assert_eq!(hsid.as_deref(), Some("exampleabcdefghi"));
        assert_eq!(bytes, [7u8; 32]);
    }

    #[test]
    fn parse_accepts_version_prefixed_line() {
        let content = format!("1:example.onion:descriptor:x25519:{}\n", key_b32());
        let (hsid, bytes) = parse_auth_private(&content).expect("parse ok");
        assert_eq!(hsid.as_deref(), Some("example"));
        assert_eq!(bytes, [7u8; 32]);
    }

    #[test]
    fn parse_ignores_comments_and_blank_lines() {
        let content = format!(
            "# comment\n\n  \n1:example:descriptor:x25519:{}\n",
            key_b32()
        );
        let (hsid, bytes) = parse_auth_private(&content).expect("parse ok");
        assert_eq!(hsid.as_deref(), Some("example"));
        assert_eq!(bytes, [7u8; 32]);
    }

    #[test]
    fn parse_accepts_padded_base32() {
        let (hsid, bytes) =
            parse_auth_private(&format!("1:example:descriptor:x25519:{}", key_b32_padded()))
                .expect("parse ok");
        assert_eq!(hsid.as_deref(), Some("example"));
        assert_eq!(bytes, [7u8; 32]);
    }

    #[test]
    fn parse_rejects_invalid_base32() {
        let err =
            parse_auth_private("descriptor:x25519:!!!!MMMMMMMMMMMMMMMMMMMMMMMM!!!!").unwrap_err();
        assert!(err.contains("base32"), "unexpected error: {err}");
    }

    #[test]
    fn parse_rejects_wrong_key_length() {
        let short = BASE32_NOPAD.encode(&[7u8; 31]);
        let err = parse_auth_private(&format!("descriptor:x25519:{short}")).unwrap_err();
        assert!(err.contains("32 bytes"), "unexpected error: {err}");
    }

    #[test]
    fn parse_rejects_content_without_key() {
        let err = parse_auth_private("hello world\n").unwrap_err();
        assert!(
            err.contains("no valid descriptor"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn sanitize_nickname_variants() {
        assert_eq!(sanitize_nickname("My Client!"), "My-Client");
        assert_eq!(sanitize_nickname("   "), "client");
        assert_eq!(sanitize_nickname("--__--"), "client");
        assert_eq!(sanitize_nickname("alice"), "alice");
        // control characters and unicode become underscores
        assert_eq!(sanitize_nickname("a\tb\nc"), "a-b-c");
    }

    #[test]
    fn sanitize_nickname_length_limit() {
        let long = "a".repeat(200);
        let out = sanitize_nickname(&long);
        assert!(out.len() <= 48, "nickname too long: {}", out.len());
        assert_eq!(out, "a".repeat(48));
    }

    #[test]
    fn normalize_onion_hsid_strips_suffix_and_lowercases() {
        assert_eq!(
            normalize_onion_hsid("ExAmPle.ONION").expect("ok"),
            "example"
        );
        assert_eq!(
            normalize_onion_hsid("ExAmPle.Onion").expect("ok"),
            "example"
        );
        assert_eq!(
            normalize_onion_hsid("  example.onion  ").expect("ok"),
            "example"
        );
        assert_eq!(normalize_onion_hsid("  example  ").expect("ok"), "example");
        assert!(normalize_onion_hsid("").is_err());
        assert!(normalize_onion_hsid("bad\naddress").is_err());
    }

    #[test]
    fn auth_private_line_format() {
        let line = auth_private_line("example", "KEYMATERIAL");
        assert_eq!(line, "1:example:descriptor:x25519:KEYMATERIAL");
    }

    #[test]
    fn generated_secret_is_valid_x25519_material() {
        let secret = generate_secret_bytes();
        let public = public_key_from_secret_bytes(&secret);
        assert!(public.starts_with("descriptor:x25519:"));
        // public key encodes 32 bytes -> 52 base32 chars
        let encoded = public.trim_start_matches("descriptor:x25519:");
        assert_eq!(encoded.len(), 52);
        let decoded = BASE32_NOPAD.decode(encoded.as_bytes()).expect("base32");
        assert_eq!(decoded.len(), 32);
    }

    #[tokio::test]
    async fn generate_list_export_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let db_path = dir.path().join("state.sqlite3");
        let root = dir.path().join("client-auth");

        let result = generate(&db_path, &root, json!({ "nickname": "My Client" })).await?;
        assert_eq!(result["ok"], true);
        let cred = result["credential"].clone();
        assert!(
            cred["nickname"]
                .as_str()
                .expect("nickname")
                .starts_with("My-Client-")
        );
        let id = cred["id"].as_str().expect("id").to_owned();
        let public_key = cred["public_key"].as_str().expect("public key").to_owned();

        // Stored key file exists with private permissions and parses.
        let key_file = root.join(&id).join("credential.auth_private");
        assert!(key_file.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = fs::metadata(&key_file)?.permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
            let dir_mode = fs::metadata(root.join(&id))?.permissions().mode();
            assert_eq!(dir_mode & 0o777, 0o700);
        }

        // Listed credentials include attachment state (empty list here).
        let listed = list(&db_path).await?;
        let creds = listed["credentials"].as_array().expect("array");
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0]["id"].as_str().expect("id"), id);
        assert_eq!(creds[0]["public_key"].as_str().expect("pk"), public_key);

        // Export without an address or published service fails.
        let err = export(&db_path, json!({ "id": id })).await.unwrap_err();
        assert!(err.contains("onion_address"), "unexpected error: {err}");

        // Export with an explicit address produces the standard format.
        let exported = export(
            &db_path,
            json!({ "id": id, "onion_address": "ExAmPle.Onion" }),
        )
        .await?;
        assert_eq!(exported["filename"], "example.auth_private");
        let content = exported["content"].as_str().expect("content");
        let secret_b32 = fs::read_to_string(&key_file)?;
        let secret_b32 = secret_b32
            .trim()
            .trim_start_matches("descriptor:x25519:")
            .to_owned();
        assert_eq!(
            content,
            format!("1:example:descriptor:x25519:{secret_b32}\n")
        );
        // Exported content round-trips through the importer's parser.
        let (hsid, _bytes) = parse_auth_private(content).expect("reparse ok");
        assert_eq!(hsid.as_deref(), Some("example"));
        Ok(())
    }

    #[tokio::test]
    async fn import_validates_and_stores() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let db_path = dir.path().join("state.sqlite3");
        let root = dir.path().join("client-auth");

        let err = import(
            &db_path,
            &root,
            json!({ "nickname": "bad", "content": "not a key file" }),
        )
        .await
        .unwrap_err();
        assert!(
            err.contains("no valid descriptor"),
            "unexpected error: {err}"
        );

        let content = format!("1:example:descriptor:x25519:{}\n", key_b32());
        let result = import(
            &db_path,
            &root,
            json!({ "nickname": "Bob Phone", "content": content }),
        )
        .await?;
        let cred = result["credential"].clone();
        assert!(
            cred["nickname"]
                .as_str()
                .expect("nickname")
                .starts_with("Bob-Phone-")
        );
        assert!(
            cred["public_key"]
                .as_str()
                .expect("public key")
                .starts_with("descriptor:x25519:")
        );

        // delete removes the record and the key directory
        let id = cred["id"].as_str().expect("id").to_owned();
        let key_dir = root.join(&id);
        assert!(key_dir.exists());
        let deleted = delete(&db_path, json!({ "id": id })).await?;
        assert_eq!(deleted["deleted"], true);
        assert!(!key_dir.exists());
        let listed = list(&db_path).await?;
        assert_eq!(listed["credentials"].as_array().expect("array").len(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn attach_detach_updates_authorized_clients() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let db_path = dir.path().join("state.sqlite3");
        let root = dir.path().join("client-auth");
        let service_key_dir = dir.path().join("services").join("svc1");

        let generated = generate(&db_path, &root, json!({ "nickname": "client" })).await?;
        let cred = generated["credential"].clone();
        let cred_id = cred["id"].as_str().expect("id").to_owned();
        let public_key = cred["public_key"].as_str().expect("public key").to_owned();
        let nickname = cred["nickname"].as_str().expect("nickname").to_owned();

        let db = tobro_store::Db::open(&db_path).await?;
        db.create_onion_service(tobro_store::NewOnionService {
            id: "svc1".to_owned(),
            nickname: "svc".to_owned(),
            name: "svc".to_owned(),
            enabled: true,
            key_dir: service_key_dir.to_string_lossy().to_string(),
            ports: vec![],
        })
        .await?;
        drop(db);

        let attached = attach(
            &db_path,
            json!({ "service_id": "svc1", "client_auth_id": cred_id }),
        )
        .await?;
        assert_eq!(attached["restart_required"], true);

        let auth_file = service_key_dir
            .join("authorized_clients")
            .join(format!("{nickname}.auth"));
        let content = fs::read_to_string(&auth_file)?;
        assert_eq!(content, format!("{public_key}\n"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = fs::metadata(&auth_file)?.permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }

        let detached = detach(
            &db_path,
            json!({ "service_id": "svc1", "client_auth_id": cred_id }),
        )
        .await?;
        assert_eq!(detached["restart_required"], true);
        assert!(
            !service_key_dir.join("authorized_clients").exists(),
            "authorized_clients dir should be removed when no clients remain"
        );

        // Deleting the credential removes its key directory too.
        let key_dir = root.join(&cred_id);
        assert!(key_dir.exists());
        delete(&db_path, json!({ "id": cred_id })).await?;
        assert!(!key_dir.exists());
        Ok(())
    }
}
