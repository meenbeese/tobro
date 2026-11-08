//! Local state storage (embedded libSQL/Turso-compatible) and secret storage
//! (OS keychain) for tobro.
//!
//! M1 skeleton: database open/migrate and a keychain abstraction. Secrets must
//! never be stored in database plaintext or logs.

use std::path::{Path, PathBuf};

use directories::ProjectDirs;
use libsql::{Builder, Connection, Database, params};
use zeroize::Zeroizing;

/// SQLite/libSQL database file name inside the data directory.
pub const DB_FILE_NAME: &str = "tobro.sqlite3";

/// Keychain service name used for tobro secrets.
pub const KEYCHAIN_SERVICE: &str = "org.tobro.app";

/// Initial M1 migration (embedded).
const MIGRATION_M1_INITIAL: &str = include_str!("../migrations/20261108000000_m1_initial.sql");

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
}

/// Resolve the default database path.
pub fn default_db_path() -> Result<PathBuf, StoreError> {
    let project = ProjectDirs::from("", "", "tobro").ok_or(StoreError::NoDataDir)?;
    Ok(project.data_dir().join(DB_FILE_NAME))
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
    /// Open (and create if needed) the local libSQL database at `path`, then run migrations.
    pub async fn open(path: &Path) -> Result<Self, StoreError> {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|source| StoreError::Io {
                    path: parent.to_path_buf(),
                    source,
                })?;
        }

        let db = Builder::new_local(path).build().await?;
        let conn = db.connect()?;

        conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; PRAGMA foreign_keys = ON;")
            .await?;
        Self::migrate(&conn).await?;

        Ok(Self { _db: db, conn })
    }

    async fn migrate(conn: &Connection) -> Result<(), StoreError> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_migrations (name TEXT PRIMARY KEY NOT NULL);",
        )
        .await?;

        let mut rows = conn
            .query(
                "SELECT 1 FROM schema_migrations WHERE name = ?1",
                params!["20261108000000_m1_initial"],
            )
            .await?;
        let applied = rows.next().await?.is_some();
        if !applied {
            conn.execute_batch(MIGRATION_M1_INITIAL).await?;
            conn.execute(
                "INSERT INTO schema_migrations (name) VALUES (?1)",
                params!["20261108000000_m1_initial"],
            )
            .await?;
        }
        Ok(())
    }

    /// Access the underlying connection for queries.
    pub fn conn(&self) -> &Connection {
        &self.conn
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
    async fn open_db_runs_migrations() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("test.sqlite3");
        let db = Db::open(&path).await.expect("open db");
        let mut rows = db
            .conn()
            .query("SELECT COUNT(*) FROM meta", params![])
            .await
            .expect("query");
        let row = rows.next().await.expect("next").expect("row");
        let count: i64 = row.get(0).expect("count");
        assert_eq!(count, 0);
    }

    #[test]
    fn memory_secret_store_round_trips() {
        let store = MemorySecretStore::default();
        assert!(store.get("k").expect("get").is_none());
        store.set("k", "v").expect("set");
        let got = store.get("k").expect("get").expect("present");
        assert_eq!(got.as_str(), "v");
        store.delete("k").expect("delete");
        assert!(store.get("k").expect("get").is_none());
    }
}
