//! System resolver snapshots for DNS-leak assertions.
//!
//! The helper changes the system resolver for the tunnel lifetime. The leak
//! suite verifies two things: the resolver points at the tunnel while the
//! plan is active, and it is restored afterwards. The snapshot is also the
//! safety net for the helper-crash scenario: a killed helper loses its
//! in-memory backup, so the harness restores the value it captured before
//! the run.

use std::net::IpAddr;

use anyhow::{Context, Result};

/// One observed resolver configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsSnapshot {
    /// Server addresses, in OS order, deduplicated.
    pub servers: Vec<IpAddr>,
    /// Human-readable source (for report messages).
    pub source: String,
}

impl DnsSnapshot {
    /// True when `server` is one of the observed resolvers.
    pub fn contains(&self, server: IpAddr) -> bool {
        self.servers.contains(&server)
    }
}

/// A captured snapshot plus the platform-specific backup needed to restore
/// it after a killed helper.
#[derive(Debug, Clone)]
pub struct DnsBackup {
    /// The parsed snapshot.
    pub snapshot: DnsSnapshot,
    #[cfg(target_os = "linux")]
    raw: Option<String>,
    #[cfg(target_os = "macos")]
    plist: Option<Vec<u8>>,
}

/// Capture the current resolver configuration and a restoration handle.
pub async fn capture() -> Result<DnsBackup> {
    #[cfg(target_os = "linux")]
    {
        const RESOLV_CONF: &str = "/etc/resolv.conf";
        let raw = match std::fs::read_to_string(RESOLV_CONF) {
            Ok(content) => Some(content),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => {
                return Err(error).with_context(|| format!("could not read {RESOLV_CONF}"));
            }
        };
        let snapshot = parse_resolv_conf(raw.as_deref().unwrap_or(""));
        Ok(DnsBackup { snapshot, raw })
    }

    #[cfg(target_os = "macos")]
    {
        let plist = tokio::task::spawn_blocking(tobro_osapi::sc_dns::backup_dns)
            .await
            .context("the DNS backup task panicked")?
            .map_err(|error| anyhow::anyhow!("could not back up the system resolver: {error}"))?;
        let snapshot = snapshot(None).await?;
        Ok(DnsBackup { snapshot, plist })
    }

    #[cfg(target_os = "windows")]
    {
        let snapshot = snapshot(None).await?;
        Ok(DnsBackup { snapshot })
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        anyhow::bail!("resolver snapshots are not implemented on this platform")
    }
}

/// Restore a captured resolver configuration. Idempotent and best-effort by
/// design: the caller reports a failure but still terminates the helper.
pub async fn restore(backup: &DnsBackup) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        const RESOLV_CONF: &str = "/etc/resolv.conf";
        match &backup.raw {
            Some(content) => std::fs::write(RESOLV_CONF, content)
                .with_context(|| format!("could not restore {RESOLV_CONF}"))?,
            None => match std::fs::remove_file(RESOLV_CONF) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(error).with_context(|| format!("could not remove {RESOLV_CONF}"));
                }
            },
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    {
        let plist = backup.plist.clone();
        tokio::task::spawn_blocking(move || tobro_osapi::sc_dns::restore_dns(Some(plist)))
            .await
            .context("the DNS restore task panicked")?
            .map_err(|error| anyhow::anyhow!("could not restore the system resolver: {error}"))
    }

    #[cfg(target_os = "windows")]
    {
        // The Windows backend scopes DNS to the wintun adapter; closing the
        // adapter removes it with the device. There is no host-wide state
        // to restore.
        let _ = backup;
        Ok(())
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        anyhow::bail!("resolver restoration is not implemented on this platform")
    }
}

/// Read the live resolver configuration.
pub async fn snapshot(interface: Option<&str>) -> Result<DnsSnapshot> {
    #[cfg(target_os = "linux")]
    {
        let _ = interface;
        const RESOLV_CONF: &str = "/etc/resolv.conf";
        let content = std::fs::read_to_string(RESOLV_CONF)
            .with_context(|| format!("could not read {RESOLV_CONF}"))?;
        let mut snapshot = parse_resolv_conf(&content);
        snapshot.source = RESOLV_CONF.to_owned();
        Ok(snapshot)
    }

    #[cfg(target_os = "macos")]
    {
        let _ = interface;
        let output = tokio::process::Command::new("scutil")
            .arg("--dns")
            .output()
            .await
            .context("could not run `scutil --dns`")?;
        if !output.status.success() {
            anyhow::bail!("`scutil --dns` failed with {}", output.status);
        }
        let text = String::from_utf8_lossy(&output.stdout);
        let mut servers = Vec::new();
        for line in text.lines() {
            let Some((_, value)) = line.split_once(':') else {
                continue;
            };
            let value = value.trim();
            if let Ok(ip) = value.parse::<IpAddr>()
                && !servers.contains(&ip)
            {
                servers.push(ip);
            }
        }
        Ok(DnsSnapshot {
            servers,
            source: "scutil --dns".to_owned(),
        })
    }

    #[cfg(target_os = "windows")]
    {
        let mut script = String::from(
            "$ErrorActionPreference='Stop'; \
             Get-DnsClientServerAddress -AddressFamily IPv4,IPv6",
        );
        if let Some(interface) = interface {
            // Interface names are validated by the plan (`[A-Za-z0-9_-]`), so
            // the quoted value cannot inject PowerShell syntax.
            script.push_str(&format!(" -InterfaceAlias '{interface}'"));
        }
        script.push_str(" | ForEach-Object { $_.ServerAddresses } | Sort-Object -Unique");
        let output = tokio::process::Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .output()
            .await
            .context("could not run PowerShell to read the resolver configuration")?;
        if !output.status.success() {
            anyhow::bail!(
                "reading the resolver configuration failed with {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        let text = String::from_utf8_lossy(&output.stdout);
        let servers: Vec<IpAddr> = text
            .lines()
            .filter_map(|line| line.trim().parse::<IpAddr>().ok())
            .collect();
        Ok(DnsSnapshot {
            servers,
            source: match interface {
                Some(name) => format!("Get-DnsClientServerAddress -InterfaceAlias {name}"),
                None => "Get-DnsClientServerAddress".to_owned(),
            },
        })
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = interface;
        anyhow::bail!("resolver snapshots are not implemented on this platform")
    }
}

#[cfg(target_os = "linux")]
fn parse_resolv_conf(content: &str) -> DnsSnapshot {
    let mut servers = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("nameserver") else {
            continue;
        };
        let rest = rest.trim();
        // `nameserver` may carry a scope suffix (`fe80::1%eth0`); the
        // harness only needs the address, and the tunnel servers are global.
        let address = rest.split('%').next().unwrap_or(rest);
        if let Ok(ip) = address.parse::<IpAddr>()
            && !servers.contains(&ip)
        {
            servers.push(ip);
        }
    }
    DnsSnapshot {
        servers,
        source: "/etc/resolv.conf".to_owned(),
    }
}

/// True when the snapshot contains the given server.
pub fn contains(snapshot: &DnsSnapshot, server: IpAddr) -> bool {
    snapshot.contains(server)
}
