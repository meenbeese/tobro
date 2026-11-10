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

/// A client authorization credential (x25519 descriptor keypair metadata).
/// Secret key material is stored on disk under `key_dir`, not in the database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientAuthCredential {
    pub id: String,
    pub nickname: String,
    pub key_dir: String,
    /// Public key in Tor format: `descriptor:x25519:<base32>`.
    pub public_key: String,
    pub created_at: i64,
    pub updated_at: i64,
}

/// Input for creating a client authorization credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewClientAuthCredential {
    pub id: String,
    pub nickname: String,
    pub key_dir: String,
    /// Public key in Tor format: `descriptor:x25519:<base32>`.
    pub public_key: String,
}

/// Stored Kindness Mode connection statistics (`kindness.stats`).
///
/// Counts only: no client addresses, labels, or countries are recorded.
/// `week_start` is the UTC date (YYYY-MM-DD) of the Monday that the
/// `week_served` counter applies to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KindnessStats {
    pub total_served: u64,
    pub week_start: String,
    pub week_served: u64,
    /// Unix timestamp in milliseconds, 0 when nothing was counted yet.
    pub updated_at: i64,
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

    /// Read the Kindness Mode connection statistics (`kindness.stats`).
    pub async fn kindness_stats(&self) -> Result<KindnessStats, StoreError> {
        let mut rows = self
            .conn
            .query(
                "SELECT total_served, week_start, week_served, updated_at FROM kindness_stats WHERE id = 1",
                params![],
            )
            .await?;
        let Some(row) = rows.next().await? else {
            // The row is seeded by the schema; a missing row still yields zeros.
            return Ok(KindnessStats {
                total_served: 0,
                week_start: String::new(),
                week_served: 0,
                updated_at: 0,
            });
        };
        Ok(KindnessStats {
            total_served: row.get::<Option<i64>>(0)?.unwrap_or_default().max(0) as u64,
            week_start: row.get::<Option<String>>(1)?.unwrap_or_default(),
            week_served: row.get::<Option<i64>>(2)?.unwrap_or_default().max(0) as u64,
            updated_at: row.get::<Option<i64>>(3)?.unwrap_or_default(),
        })
    }

    /// Record that `served` additional clients connected and add it to both
    /// counters. `week_start` is the caller's current ISO week start (UTC date
    /// of Monday): when the stored week differs, the weekly counter restarts
    /// at the new week, so the weekly number always covers exactly the stored
    /// week. Returns the updated row.
    pub async fn kindness_stats_record_served(
        &self,
        served: u64,
        week_start: &str,
        updated_at: i64,
    ) -> Result<KindnessStats, StoreError> {
        let current = self.kindness_stats().await?;
        let (week_start, week_increment) = if current.week_start == week_start {
            (current.week_start, current.week_served)
        } else {
            (week_start.to_owned(), 0)
        };
        let total = current.total_served.saturating_add(served);
        let week = week_increment.saturating_add(served);
        self.conn
            .execute(
                "INSERT INTO kindness_stats (id, total_served, week_start, week_served, updated_at) VALUES (1, ?1, ?2, ?3, ?4)
                 ON CONFLICT(id) DO UPDATE SET total_served = ?1, week_start = ?2, week_served = ?3, updated_at = ?4",
                params![
                    total as i64,
                    week_start.as_str(),
                    week as i64,
                    updated_at
                ],
            )
            .await?;
        Ok(KindnessStats {
            total_served: total,
            week_start,
            week_served: week,
            updated_at,
        })
    }

    /// Reset every stored Kindness Mode counter. Volatile state (current
    /// connections) is managed by the daemon, not the store.
    pub async fn kindness_stats_reset(&self) -> Result<(), StoreError> {
        self.conn
            .execute(
                "UPDATE kindness_stats SET total_served = 0, week_start = '', week_served = 0, updated_at = 0 WHERE id = 1",
                params![],
            )
            .await?;
        Ok(())
    }

    fn normalize_client_auth_nickname(nickname: &str) -> Result<String, StoreError> {
        let nickname = nickname.trim();
        if nickname.is_empty() {
            return Err(StoreError::Invalid {
                field: "nickname",
                message: "nickname must not be empty".to_owned(),
            });
        }
        if nickname.len() > 64 {
            return Err(StoreError::Invalid {
                field: "nickname",
                message: "nickname must be at most 64 characters".to_owned(),
            });
        }
        if !nickname
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Err(StoreError::Invalid {
                field: "nickname",
                message: "nickname may only contain ASCII letters, digits, '_' and '-'".to_owned(),
            });
        }
        Ok(nickname.to_owned())
    }

    fn normalize_public_key(public_key: &str) -> Result<String, StoreError> {
        let pk = public_key.trim();
        if !pk.starts_with("descriptor:x25519:") {
            return Err(StoreError::Invalid {
                field: "public_key",
                message: "public_key must be in descriptor:x25519:<base32> format".to_owned(),
            });
        }
        Ok(pk.to_owned())
    }

    /// Create a client authorization credential record.
    pub async fn create_client_auth(
        &self,
        new: NewClientAuthCredential,
    ) -> Result<ClientAuthCredential, StoreError> {
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
        let nickname = Self::normalize_client_auth_nickname(&new.nickname)?;
        let public_key = Self::normalize_public_key(&new.public_key)?;
        let now = Self::now_ms();
        self.conn
            .execute(
                "INSERT INTO onion_client_auth (id, nickname, key_dir, public_key, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    new.id.as_str(),
                    nickname.as_str(),
                    new.key_dir.as_str(),
                    public_key.as_str(),
                    now,
                    now
                ],
            )
            .await?;
        self.get_client_auth(&new.id).await
    }

    /// Get a client authorization credential by id.
    pub async fn get_client_auth(&self, id: &str) -> Result<ClientAuthCredential, StoreError> {
        let mut rows = self
            .conn
            .query(
                "SELECT id, nickname, key_dir, public_key, created_at, updated_at FROM onion_client_auth WHERE id = ?1",
                params![id],
            )
            .await?;
        let Some(row) = rows.next().await? else {
            return Err(StoreError::NotFound {
                kind: "client authorization credential",
                id: id.to_owned(),
            });
        };
        Ok(ClientAuthCredential {
            id: row.get(0)?,
            nickname: row.get(1)?,
            key_dir: row.get(2)?,
            public_key: row.get(3)?,
            created_at: row.get(4)?,
            updated_at: row.get(5)?,
        })
    }

    /// List client authorization credentials.
    pub async fn list_client_auth(&self) -> Result<Vec<ClientAuthCredential>, StoreError> {
        let mut rows = self
            .conn
            .query(
                "SELECT id FROM onion_client_auth ORDER BY created_at ASC, id ASC",
                params![],
            )
            .await?;
        let mut ids = Vec::new();
        while let Some(row) = rows.next().await? {
            ids.push(row.get::<String>(0)?);
        }
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            out.push(self.get_client_auth(&id).await?);
        }
        Ok(out)
    }

    /// Delete a client authorization credential.
    pub async fn delete_client_auth(&self, id: &str) -> Result<(), StoreError> {
        let changed = self
            .conn
            .execute("DELETE FROM onion_client_auth WHERE id = ?1", params![id])
            .await?;
        if changed == 0 {
            return Err(StoreError::NotFound {
                kind: "client authorization credential",
                id: id.to_owned(),
            });
        }
        Ok(())
    }

    /// Attach a client authorization credential to an onion service.
    pub async fn attach_client_auth(
        &self,
        service_id: &str,
        client_auth_id: &str,
    ) -> Result<(), StoreError> {
        self.get_onion_service(service_id).await?;
        self.get_client_auth(client_auth_id).await?;
        let now = Self::now_ms();
        self.conn
            .execute(
                "INSERT OR IGNORE INTO onion_service_client_auth (service_id, client_auth_id) VALUES (?1, ?2)",
                params![service_id, client_auth_id],
            )
            .await?;
        self.conn
            .execute(
                "UPDATE onion_service SET updated_at = ?2 WHERE id = ?1",
                params![service_id, now],
            )
            .await?;
        Ok(())
    }

    /// Detach a client authorization credential from an onion service.
    pub async fn detach_client_auth(
        &self,
        service_id: &str,
        client_auth_id: &str,
    ) -> Result<(), StoreError> {
        self.conn
            .execute(
                "DELETE FROM onion_service_client_auth WHERE service_id = ?1 AND client_auth_id = ?2",
                params![service_id, client_auth_id],
            )
            .await?;
        let now = Self::now_ms();
        self.conn
            .execute(
                "UPDATE onion_service SET updated_at = ?2 WHERE id = ?1",
                params![service_id, now],
            )
            .await?;
        Ok(())
    }

    /// List client authorization credentials attached to an onion service.
    pub async fn list_client_auth_for_service(
        &self,
        service_id: &str,
    ) -> Result<Vec<ClientAuthCredential>, StoreError> {
        self.get_onion_service(service_id).await?;
        let mut rows = self
            .conn
            .query(
                "SELECT client_auth_id FROM onion_service_client_auth WHERE service_id = ?1 ORDER BY client_auth_id ASC",
                params![service_id],
            )
            .await?;
        let mut ids = Vec::new();
        while let Some(row) = rows.next().await? {
            ids.push(row.get::<String>(0)?);
        }
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            if let Ok(cred) = self.get_client_auth(&id).await {
                out.push(cred);
            }
        }
        Ok(out)
    }

    /// List onion service ids a credential is attached to.
    pub async fn list_services_for_client_auth(
        &self,
        client_auth_id: &str,
    ) -> Result<Vec<String>, StoreError> {
        self.get_client_auth(client_auth_id).await?;
        let mut rows = self
            .conn
            .query(
                "SELECT service_id FROM onion_service_client_auth WHERE client_auth_id = ?1 ORDER BY service_id ASC",
                params![client_auth_id],
            )
            .await?;
        let mut ids = Vec::new();
        while let Some(row) = rows.next().await? {
            ids.push(row.get::<String>(0)?);
        }
        Ok(ids)
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

    #[tokio::test]
    async fn kindness_stats_start_at_zero_and_roll_over_weekly()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = TempDir::new()?;
        let db = Db::open(&dir.path().join("test.sqlite3")).await?;

        let empty = db.kindness_stats().await?;
        assert_eq!(empty.total_served, 0);
        assert_eq!(empty.week_served, 0);
        assert_eq!(empty.updated_at, 0);

        // First recording: totals and the week counter both move.
        let first = db
            .kindness_stats_record_served(3, "2026-11-09", 1_000)
            .await?;
        assert_eq!(first.total_served, 3);
        assert_eq!(first.week_start, "2026-11-09");
        assert_eq!(first.week_served, 3);
        assert_eq!(first.updated_at, 1_000);

        // Same week: counters accumulate, week start is retained.
        let second = db
            .kindness_stats_record_served(2, "2026-11-09", 2_000)
            .await?;
        assert_eq!(second.total_served, 5);
        assert_eq!(second.week_start, "2026-11-09");
        assert_eq!(second.week_served, 5);

        // New week: only the weekly counter restarts; the total survives.
        let rolled = db
            .kindness_stats_record_served(1, "2026-11-16", 3_000)
            .await?;
        assert_eq!(rolled.total_served, 6);
        assert_eq!(rolled.week_start, "2026-11-16");
        assert_eq!(rolled.week_served, 1);
        assert_eq!(rolled.updated_at, 3_000);

        // Reset: all counters zero, and the next week takes over cleanly.
        db.kindness_stats_reset().await?;
        let reset = db.kindness_stats().await?;
        assert_eq!(reset.total_served, 0);
        assert_eq!(reset.week_served, 0);
        assert_eq!(reset.updated_at, 0);
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
