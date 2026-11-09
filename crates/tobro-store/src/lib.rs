//! Local state storage (embedded libSQL/Turso-compatible) and secret storage
//! (OS keychain) for tobro.
//!
//! Database open/migrate and a keychain abstraction. Secrets must never be
//! stored in database plaintext or logs.

use std::path::{Path, PathBuf};

use directories::ProjectDirs;
use libsql::{Builder, Connection, Database, params};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// SQLite/libSQL database file name inside the data directory.
pub const DB_FILE_NAME: &str = "tobro.sqlite3";

/// Keychain service name used for tobro secrets.
pub const KEYCHAIN_SERVICE: &str = "org.tobro.app";

/// Consolidated idempotent schema (embedded, pre-1.0).
const SCHEMA: &str = include_str!("../schema.sql");

/// Errors produced by the store layer.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// Could not determine a platform data directory.
    #[error("could not determine the platform data directory")]
    NoDataDir,
    /// Filesystem operation failed.
    #[error("I/O error at {path}: {source}")]
    Io {
        /// Path involved in the operation.
        path: PathBuf,
        /// Underlying error.
        #[source]
        source: std::io::Error,
    },
    /// Database operation failed.
    #[error("database error: {0}")]
    Db(#[from] libsql::Error),
    /// Secret storage operation failed.
    #[error("keychain error: {0}")]
    Keychain(String),
    /// Requested record was not found.
    #[error("{kind} not found: {id}")]
    NotFound {
        /// Entity kind.
        kind: &'static str,
        /// Identifier.
        id: String,
    },
    /// Invalid input for a store operation.
    #[error("invalid {field}: {message}")]
    Invalid {
        /// Field name.
        field: &'static str,
        /// Explanation.
        message: String,
    },
}

/// Resolve the default database path.
pub fn default_db_path() -> Result<PathBuf, StoreError> {
    let project = ProjectDirs::from("", "", "tobro").ok_or(StoreError::NoDataDir)?;
    Ok(project.data_dir().join(DB_FILE_NAME))
}

/// Port mapping for a hosted onion service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OnionServicePort {
    /// Virtual (onion-facing) port.
    pub virt_port: u16,
    /// Local target host, typically `127.0.0.1`.
    pub target_host: String,
    /// Local target port.
    pub target_port: u16,
}

/// Stored onion service metadata and desired state.
///
/// Key material is managed on disk in `key_dir` (0700), not in the database.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OnionService {
    /// Stable service identifier.
    pub id: String,
    /// Stable Arti/internal nickname (filesystem-safe identifier).
    pub nickname: String,
    /// Human-readable name.
    pub name: String,
    /// Whether the service should be running when the Tor runtime is active.
    pub enabled: bool,
    /// Published `.onion` address, once known.
    pub onion_address: Option<String>,
    /// Managed key/state directory path.
    pub key_dir: String,
    /// Unix timestamp in milliseconds.
    pub created_at: i64,
    /// Unix timestamp in milliseconds.
    pub updated_at: i64,
    /// Port mappings (onion port -> local target).
    pub ports: Vec<OnionServicePort>,
}

/// Input for creating an onion service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewOnionService {
    /// Optional explicit id; generated when empty.
    pub id: String,
    /// Optional explicit nickname; derived/generated when empty.
    pub nickname: String,
    /// Human-readable name.
    pub name: String,
    /// Desired enabled state.
    pub enabled: bool,
    /// Managed key directory path.
    pub key_dir: String,
    /// Port mappings.
    pub ports: Vec<OnionServicePort>,
}

/// Patch for updating an onion service.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OnionServicePatch {
    /// New human-readable name.
    pub name: Option<String>,
    /// New enabled state.
    pub enabled: Option<bool>,
    /// Replace port mappings when provided.
    pub ports: Option<Vec<OnionServicePort>>,
    /// Set or clear the published onion address.
    pub onion_address: Option<Option<String>>,
}

/// Embedded libSQL store handle.
pub struct Db {
    _db: Database,
    conn: Connection,
}

impl std::fmt::Debug for Db {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Db").finish_non_exhaustive()
    }
}

impl Db {
    /// Open (and create if needed) the local libSQL database at `path`, then
    /// apply the idempotent schema.
    pub async fn open(path: &Path) -> Result<Self, StoreError> {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|source| StoreError::Io {
                    path: parent.to_path_buf(),
                    source,
                })?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
            }
        }

        let db = Builder::new_local(path).build().await?;
        let conn = db.connect()?;

        conn.execute_batch(
            "PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; PRAGMA foreign_keys = ON;",
        )
        .await?;
        Self::init_schema(&conn).await?;

        Ok(Self { _db: db, conn })
    }

    async fn init_schema(conn: &Connection) -> Result<(), StoreError> {
        conn.execute_batch(SCHEMA).await?;
        Ok(())
    }

    /// Access the underlying connection for queries.
    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    fn now_ms() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0)
    }

    fn validate_port(port: &OnionServicePort) -> Result<(), StoreError> {
        if port.virt_port == 0 {
            return Err(StoreError::Invalid {
                field: "virt_port",
                message: "virtual port must not be zero".to_owned(),
            });
        }
        if port.target_port == 0 {
            return Err(StoreError::Invalid {
                field: "target_port",
                message: "target port must not be zero".to_owned(),
            });
        }
        let host = port.target_host.trim();
        if host.is_empty() {
            return Err(StoreError::Invalid {
                field: "target_host",
                message: "target host must not be empty".to_owned(),
            });
        }
        if host.chars().any(|c| c.is_whitespace()) {
            return Err(StoreError::Invalid {
                field: "target_host",
                message: "target host must not contain whitespace".to_owned(),
            });
        }
        Ok(())
    }

    fn normalize_name(name: &str) -> Result<String, StoreError> {
        let name = name.trim();
        if name.is_empty() {
            return Err(StoreError::Invalid {
                field: "name",
                message: "name must not be empty".to_owned(),
            });
        }
        if name.len() > 200 {
            return Err(StoreError::Invalid {
                field: "name",
                message: "name is too long".to_owned(),
            });
        }
        Ok(name.to_owned())
    }

    fn normalize_nickname(nickname: &str) -> Result<String, StoreError> {
        let nick = nickname.trim();
        if nick.is_empty() {
            return Err(StoreError::Invalid {
                field: "nickname",
                message: "nickname must not be empty".to_owned(),
            });
        }
        let ok = nick
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
        if !ok {
            return Err(StoreError::Invalid {
                field: "nickname",
                message: "nickname may contain only ASCII letters, digits, '-' and '_'".to_owned(),
            });
        }
        if nick.len() > 64 {
            return Err(StoreError::Invalid {
                field: "nickname",
                message: "nickname is too long".to_owned(),
            });
        }
        Ok(nick.to_owned())
    }

    async fn load_ports(&self, service_id: &str) -> Result<Vec<OnionServicePort>, StoreError> {
        let mut rows = self
            .conn
            .query(
                "SELECT virt_port, target_host, target_port FROM onion_service_port WHERE service_id = ?1 ORDER BY virt_port ASC",
                params![service_id],
            )
            .await?;
        let mut ports = Vec::new();
        while let Some(row) = rows.next().await? {
            let virt_port: i64 = row.get(0)?;
            let target_host: String = row.get(1)?;
            let target_port: i64 = row.get(2)?;
            ports.push(OnionServicePort {
                virt_port: virt_port as u16,
                target_host,
                target_port: target_port as u16,
            });
        }
        Ok(ports)
    }

    async fn replace_ports(
        &self,
        service_id: &str,
        ports: &[OnionServicePort],
    ) -> Result<(), StoreError> {
        for port in ports {
            Self::validate_port(port)?;
        }
        self.conn
            .execute(
                "DELETE FROM onion_service_port WHERE service_id = ?1",
                params![service_id],
            )
            .await?;
        for port in ports {
            self.conn
                .execute(
                    "INSERT INTO onion_service_port (service_id, virt_port, target_host, target_port) VALUES (?1, ?2, ?3, ?4)",
                    params![
                        service_id,
                        i64::from(port.virt_port),
                        port.target_host.trim(),
                        i64::from(port.target_port)
                    ],
                )
                .await?;
        }
        Ok(())
    }

    /// Create an onion service record and its port mappings.
    pub async fn create_onion_service(
        &self,
        new: NewOnionService,
    ) -> Result<OnionService, StoreError> {
        let name = Self::normalize_name(&new.name)?;
        let nickname = Self::normalize_nickname(&new.nickname)?;
        if new.id.trim().is_empty() {
            return Err(StoreError::Invalid {
                field: "id",
                message: "id must not be empty".to_owned(),
            });
        }
        if new.key_dir.trim().is_empty() {
            return Err(StoreError::Invalid {
                field: "key_dir",
                message: "key_dir must not be empty".to_owned(),
            });
        }
        for port in &new.ports {
            Self::validate_port(port)?;
        }
        let now = Self::now_ms();
        self.conn
            .execute(
                "INSERT INTO onion_service (id, nickname, name, enabled, onion_address, key_dir, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, NULL, ?5, ?6, ?7)",
                params![
                    new.id.as_str(),
                    nickname.as_str(),
                    name.as_str(),
                    if new.enabled { 1_i64 } else { 0_i64 },
                    new.key_dir.as_str(),
                    now,
                    now
                ],
            )
            .await?;
        self.replace_ports(&new.id, &new.ports).await?;
        self.get_onion_service(&new.id).await
    }

    /// Get an onion service by id.
    pub async fn get_onion_service(&self, id: &str) -> Result<OnionService, StoreError> {
        let mut rows = self
            .conn
            .query(
                "SELECT id, nickname, name, enabled, onion_address, key_dir, created_at, updated_at FROM onion_service WHERE id = ?1",
                params![id],
            )
            .await?;
        let Some(row) = rows.next().await? else {
            return Err(StoreError::NotFound {
                kind: "onion service",
                id: id.to_owned(),
            });
        };
        let id: String = row.get(0)?;
        let nickname: String = row.get(1)?;
        let name: String = row.get(2)?;
        let enabled: i64 = row.get(3)?;
        let onion_address: Option<String> = row.get(4)?;
        let key_dir: String = row.get(5)?;
        let created_at: i64 = row.get(6)?;
        let updated_at: i64 = row.get(7)?;
        let ports = self.load_ports(&id).await?;
        Ok(OnionService {
            id,
            nickname,
            name,
            enabled: enabled != 0,
            onion_address,
            key_dir,
            created_at,
            updated_at,
            ports,
        })
    }

    /// List all onion services.
    pub async fn list_onion_services(&self) -> Result<Vec<OnionService>, StoreError> {
        let mut rows = self
            .conn
            .query(
                "SELECT id FROM onion_service ORDER BY created_at ASC, id ASC",
                params![],
            )
            .await?;
        let mut ids = Vec::new();
        while let Some(row) = rows.next().await? {
            ids.push(row.get::<String>(0)?);
        }
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            out.push(self.get_onion_service(&id).await?);
        }
        Ok(out)
    }

    /// Update an onion service (partial patch).
    pub async fn update_onion_service(
        &self,
        id: &str,
        patch: OnionServicePatch,
    ) -> Result<OnionService, StoreError> {
        let mut current = self.get_onion_service(id).await?;
        if let Some(name) = patch.name {
            current.name = Self::normalize_name(&name)?;
        }
        if let Some(enabled) = patch.enabled {
            current.enabled = enabled;
        }
        if let Some(addr) = patch.onion_address {
            current.onion_address = addr.map(|s| s.trim().to_owned()).filter(|s| !s.is_empty());
        }
        current.updated_at = Self::now_ms();
        self.conn
            .execute(
                "UPDATE onion_service SET name = ?2, enabled = ?3, onion_address = ?4, updated_at = ?5 WHERE id = ?1",
                params![
                    id,
                    current.name.as_str(),
                    if current.enabled { 1_i64 } else { 0_i64 },
                    current.onion_address.as_deref(),
                    current.updated_at
                ],
            )
            .await?;
        if let Some(ports) = patch.ports {
            self.replace_ports(id, &ports).await?;
        }
        self.get_onion_service(id).await
    }

    /// Delete an onion service and its port mappings.
    pub async fn delete_onion_service(&self, id: &str) -> Result<(), StoreError> {
        let changed = self
            .conn
            .execute("DELETE FROM onion_service WHERE id = ?1", params![id])
            .await?;
        if changed == 0 {
            return Err(StoreError::NotFound {
                kind: "onion service",
                id: id.to_owned(),
            });
        }
        Ok(())
    }
}

/// Abstraction over secret storage.
///
/// Production uses the OS keychain; tests can use an in-memory implementation.
pub trait SecretStore: Send + Sync + std::fmt::Debug {
    /// Store a secret under `key`, replacing any existing value.
    fn set(&self, key: &str, secret: &str) -> Result<(), StoreError>;
    /// Retrieve a secret, returning `Ok(None)` if absent.
    fn get(&self, key: &str) -> Result<Option<Zeroizing<String>>, StoreError>;
    /// Delete a secret. Missing keys are not an error.
    fn delete(&self, key: &str) -> Result<(), StoreError>;
}

/// OS keychain-backed secret store.
#[derive(Debug, Clone)]
pub struct KeychainStore {
    service: String,
}

impl KeychainStore {
    /// Create a keychain store using the default tobro service name.
    pub fn new() -> Self {
        Self {
            service: KEYCHAIN_SERVICE.to_owned(),
        }
    }

    /// Create a keychain store with a custom service name (useful for tests/instances).
    pub fn with_service(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }

    fn entry(&self, key: &str) -> Result<keyring::Entry, StoreError> {
        keyring::Entry::new(&self.service, key).map_err(|e| StoreError::Keychain(e.to_string()))
    }
}

impl Default for KeychainStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretStore for KeychainStore {
    fn set(&self, key: &str, secret: &str) -> Result<(), StoreError> {
        self.entry(key)?
            .set_password(secret)
            .map_err(|e| StoreError::Keychain(e.to_string()))
    }

    fn get(&self, key: &str) -> Result<Option<Zeroizing<String>>, StoreError> {
        match self.entry(key)?.get_password() {
            Ok(secret) => Ok(Some(Zeroizing::new(secret))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(StoreError::Keychain(e.to_string())),
        }
    }

    fn delete(&self, key: &str) -> Result<(), StoreError> {
        match self.entry(key)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(StoreError::Keychain(e.to_string())),
        }
    }
}

/// In-memory secret store for tests.
#[derive(Debug, Default)]
pub struct MemorySecretStore {
    inner: std::sync::Mutex<std::collections::HashMap<String, String>>,
}

impl SecretStore for MemorySecretStore {
    fn set(&self, key: &str, secret: &str) -> Result<(), StoreError> {
        let mut map = self
            .inner
            .lock()
            .map_err(|_| StoreError::Keychain("memory store lock poisoned".to_owned()))?;
        map.insert(key.to_owned(), secret.to_owned());
        Ok(())
    }

    fn get(&self, key: &str) -> Result<Option<Zeroizing<String>>, StoreError> {
        let map = self
            .inner
            .lock()
            .map_err(|_| StoreError::Keychain("memory store lock poisoned".to_owned()))?;
        Ok(map.get(key).cloned().map(Zeroizing::new))
    }

    fn delete(&self, key: &str) -> Result<(), StoreError> {
        let mut map = self
            .inner
            .lock()
            .map_err(|_| StoreError::Keychain("memory store lock poisoned".to_owned()))?;
        map.remove(key);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn open_db_runs_migrations() -> Result<(), Box<dyn std::error::Error>> {
        let dir = TempDir::new()?;
        let path = dir.path().join("test.sqlite3");
        let db = Db::open(&path).await?;
        let mut rows = db
            .conn()
            .query("SELECT COUNT(*) FROM meta", params![])
            .await?;
        let row = rows.next().await?.ok_or("expected a row from COUNT(*)")?;
        let count: i64 = row.get(0)?;
        assert_eq!(count, 0);
        Ok(())
    }

    #[test]
    fn memory_secret_store_round_trips() -> Result<(), StoreError> {
        let store = MemorySecretStore::default();
        assert!(store.get("k")?.is_none());
        store.set("k", "v")?;
        let got = store
            .get("k")?
            .ok_or_else(|| StoreError::Keychain("expected secret".to_owned()))?;
        assert_eq!(got.as_str(), "v");
        store.delete("k")?;
        assert!(store.get("k")?.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn onion_service_crud_and_enable_disable() -> Result<(), Box<dyn std::error::Error>> {
        let dir = TempDir::new()?;
        let path = dir.path().join("test.sqlite3");
        let db = Db::open(&path).await?;
        let key_dir = dir.path().join("onion-services").join("svc1");
        tokio::fs::create_dir_all(&key_dir).await?;

        let created = db
            .create_onion_service(NewOnionService {
                id: "svc1".to_owned(),
                nickname: "blog-abc12345".to_owned(),
                name: "My blog".to_owned(),
                enabled: true,
                key_dir: key_dir.to_string_lossy().to_string(),
                ports: vec![OnionServicePort {
                    virt_port: 80,
                    target_host: "127.0.0.1".to_owned(),
                    target_port: 8080,
                }],
            })
            .await?;
        assert_eq!(created.id, "svc1");
        assert!(created.enabled);
        assert_eq!(created.ports.len(), 1);

        let listed = db.list_onion_services().await?;
        assert_eq!(listed.len(), 1);

        let updated = db
            .update_onion_service(
                "svc1",
                OnionServicePatch {
                    name: Some("My site".to_owned()),
                    enabled: Some(false),
                    ports: Some(vec![
                        OnionServicePort {
                            virt_port: 80,
                            target_host: "127.0.0.1".to_owned(),
                            target_port: 8080,
                        },
                        OnionServicePort {
                            virt_port: 443,
                            target_host: "127.0.0.1".to_owned(),
                            target_port: 8443,
                        },
                    ]),
                    onion_address: None,
                },
            )
            .await?;
        assert_eq!(updated.name, "My site");
        assert!(!updated.enabled);
        assert_eq!(updated.ports.len(), 2);

        let enabled = db
            .update_onion_service(
                "svc1",
                OnionServicePatch {
                    enabled: Some(true),
                    ..Default::default()
                },
            )
            .await?;
        assert!(enabled.enabled);

        db.delete_onion_service("svc1").await?;
        let listed = db.list_onion_services().await?;
        assert!(listed.is_empty());
        Ok(())
    }
}
