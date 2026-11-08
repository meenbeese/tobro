//! Configuration schema, loading, saving, and validation for tobro.
//!
//! M1 skeleton: typed TOML config with defaults and basic validation.
//! Expand with bridges, stream prefs, onion services, etc. in later milestones.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use directories::ProjectDirs;
use serde::{Deserialize, Serialize};

/// On-disk config file name.
pub const CONFIG_FILE_NAME: &str = "config.toml";

/// Errors produced by config loading, saving, or validation.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// Could not determine a platform config directory.
    #[error("could not determine the platform config directory")]
    NoConfigDir,
    /// Filesystem operation failed.
    #[error("I/O error at {path}: {source}")]
    Io {
        /// Path involved in the operation.
        path: PathBuf,
        /// Underlying error.
        #[source]
        source: std::io::Error,
    },
    /// TOML parsing failed.
    #[error("invalid TOML config at {path}: {source}")]
    Parse {
        /// Path of the config file.
        path: PathBuf,
        /// Underlying parse error.
        #[source]
        source: toml::de::Error,
    },
    /// TOML serialization failed.
    #[error("could not serialize config: {0}")]
    Serialize(#[from] toml::ser::Error),
    /// A config value failed validation.
    #[error("invalid config: {0}")]
    Invalid(String),
}

/// Top-level tobro configuration.
///
/// Fields default to values compatible with the M0 spike / Orbot-style defaults
/// where sensible; M1 hardens and exposes them through the daemon/GUI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Schema version for future migrations.
    pub version: u32,
    /// General application settings.
    pub general: GeneralConfig,
    /// Local proxy listener settings.
    pub proxy: ProxyConfig,
    /// Logging settings.
    pub logging: LoggingConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            version: 1,
            general: GeneralConfig::default(),
            proxy: ProxyConfig::default(),
            logging: LoggingConfig::default(),
        }
    }
}

/// General application settings.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GeneralConfig {
    /// Whether the user wants tobro started at login (wiring arrives in M4).
    pub start_on_login: bool,
}

/// Local proxy listener settings.
///
/// M0 uses a combined SOCKS + HTTP CONNECT listener and a UDP DNS listener.
/// Port policy is finalized before user-configurable ports are exposed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProxyConfig {
    /// Combined SOCKS5 + HTTP CONNECT port.
    pub socks_port: u16,
    /// UDP DNS proxy port.
    pub dns_port: u16,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            socks_port: 9050,
            dns_port: 9053,
        }
    }
}

/// Logging settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LoggingConfig {
    /// Tracing filter / level (e.g. `info`, `debug`, `tobro=debug`).
    pub level: String,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_owned(),
        }
    }
}

/// Resolve the default config file path.
pub fn default_path() -> Result<PathBuf, ConfigError> {
    let project = ProjectDirs::from("", "", "tobro").ok_or(ConfigError::NoConfigDir)?;
    Ok(project.config_dir().join(CONFIG_FILE_NAME))
}

impl Config {
    /// Load config from `path`.
    ///
    /// Returns [`ConfigError::Io`] if the file cannot be read.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let config: Self = toml::from_str(&text).map_err(|source| ConfigError::Parse {
            path: path.to_path_buf(),
            source,
        })?;
        config.validate()?;
        Ok(config)
    }

    /// Load config from `path`, or return defaults if the file does not exist.
    pub fn load_or_default(path: &Path) -> Result<Self, ConfigError> {
        match fs::read_to_string(path) {
            Ok(text) => {
                let config: Self = toml::from_str(&text).map_err(|source| ConfigError::Parse {
                    path: path.to_path_buf(),
                    source,
                })?;
                config.validate()?;
                Ok(config)
            }
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(source) => Err(ConfigError::Io {
                path: path.to_path_buf(),
                source,
            }),
        }
    }

    /// Validate config values.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.version == 0 {
            return Err(ConfigError::Invalid(
                "version must be greater than zero".to_owned(),
            ));
        }
        if self.proxy.socks_port == 0 {
            return Err(ConfigError::Invalid(
                "proxy.socks_port must not be zero".to_owned(),
            ));
        }
        if self.proxy.dns_port == 0 {
            return Err(ConfigError::Invalid(
                "proxy.dns_port must not be zero".to_owned(),
            ));
        }
        if self.proxy.socks_port == self.proxy.dns_port {
            return Err(ConfigError::Invalid(format!(
                "proxy.socks_port and proxy.dns_port must differ (both {})",
                self.proxy.socks_port
            )));
        }
        if self.logging.level.trim().is_empty() {
            return Err(ConfigError::Invalid(
                "logging.level must not be empty".to_owned(),
            ));
        }
        Ok(())
    }

    /// Save config to `path` atomically (write temp file, then rename).
    pub fn save(&self, path: &Path) -> Result<(), ConfigError> {
        self.validate()?;
        let parent = path.parent().ok_or_else(|| {
            ConfigError::Invalid(format!("config path has no parent: {}", path.display()))
        })?;
        fs::create_dir_all(parent).map_err(|source| ConfigError::Io {
            path: parent.to_path_buf(),
            source,
        })?;

        let text = toml::to_string_pretty(self)?;
        let tmp = path.with_extension("toml.tmp");
        {
            let mut file = fs::File::create(&tmp).map_err(|source| ConfigError::Io {
                path: tmp.clone(),
                source,
            })?;
            file.write_all(text.as_bytes())
                .map_err(|source| ConfigError::Io {
                    path: tmp.clone(),
                    source,
                })?;
            file.sync_all().map_err(|source| ConfigError::Io {
                path: tmp.clone(),
                source,
            })?;
        }
        fs::rename(&tmp, path).map_err(|source| ConfigError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn default_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        let dir = TempDir::new()?;
        let path = dir.path().join("config.toml");
        let config = Config::default();
        config.save(&path)?;
        let loaded = Config::load(&path)?;
        assert_eq!(loaded, config);
        Ok(())
    }

    #[test]
    fn load_missing_returns_default() -> Result<(), Box<dyn std::error::Error>> {
        let dir = TempDir::new()?;
        let path = dir.path().join("missing.toml");
        let loaded = Config::load_or_default(&path)?;
        assert_eq!(loaded, Config::default());
        Ok(())
    }

    #[test]
    fn rejects_port_conflict() {
        let mut config = Config::default();
        config.proxy.dns_port = config.proxy.socks_port;
        let err = config.validate();
        assert!(matches!(err, Err(ConfigError::Invalid(_))));
        if let Err(ConfigError::Invalid(message)) = err {
            assert!(message.contains("must differ"));
        }
    }

    #[test]
    fn rejects_unknown_fields() -> Result<(), Box<dyn std::error::Error>> {
        let dir = TempDir::new()?;
        let path = dir.path().join("config.toml");
        fs::write(&path, "version = 1\nnope = true\n")?;
        let err = Config::load(&path);
        assert!(matches!(err, Err(ConfigError::Parse { .. })));
        Ok(())
    }
}
