//! Stream isolation policy and keys for F-42/F-43.
//!
//! Arti's built-in SOCKS proxy isolates by SOCKS username/password (and HTTP
//! `Tor-Stream-Isolation` headers) when credentials/tokens differ. It does not
//! automatically apply C Tor-style `IsolateDestAddr`/`IsolateDestPort` flags.
//!
//! `tobro` applies a configurable isolation policy for proxy streams:
//! - **SOCKS auth keep-alive isolation (F-43):** SOCKS authentication material,
//!   when present, is part of the isolation key. This matches Arti's native
//!   behavior and keeps the association explicit in config/diagnostics.
//! - **Destination/port/protocol isolation (F-42):** when enabled, the
//!   destination address, destination port, and/or client protocol are included
//!   in the isolation key so unrelated streams do not share circuits.

use arti_client::isolation::IsolationHelper;

use crate::adapter::StreamIsolationPolicy;

/// Client protocol as seen by the local proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClientProtocol {
    /// SOCKS4/4a/5.
    Socks,
    /// HTTP CONNECT.
    HttpConnect,
}

impl ClientProtocol {
    fn as_u8(self) -> u8 {
        match self {
            Self::Socks => 1,
            Self::HttpConnect => 2,
        }
    }
}

/// Metadata used to compute an isolation key for a proxied stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamIsolationInput {
    /// Isolation policy from config.
    pub policy: StreamIsolationPolicy,
    /// Client protocol.
    pub protocol: ClientProtocol,
    /// Destination host/address as presented to the proxy (normalized string).
    pub destination: String,
    /// Destination port.
    pub port: u16,
    /// SOCKS username/authentication bytes, if any (F-43). Empty when absent.
    pub socks_auth: Vec<u8>,
}

/// Isolation key applied to `StreamPrefs` for F-42/F-43.
///
/// Two streams share a circuit only when their keys are equal under
/// [`IsolationHelper`]. Fields that are disabled by policy are normalized so
/// they do not affect equality.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TobroIsolationKey {
    protocol: Option<u8>,
    destination: Option<String>,
    port: Option<u16>,
    /// SOCKS auth is included when present; `keep_alive_isolation` makes the
    /// policy explicit. (Arti natively isolates by auth; we preserve that.)
    socks_auth: Option<Vec<u8>>,
}

impl TobroIsolationKey {
    /// Build an isolation key from policy and stream metadata.
    pub fn from_input(input: &StreamIsolationInput) -> Self {
        let protocol = if input.policy.isolate_protocol {
            Some(input.protocol.as_u8())
        } else {
            None
        };
        let destination = if input.policy.isolate_destination {
            Some(normalize_destination(&input.destination))
        } else {
            None
        };
        let port = if input.policy.isolate_port {
            Some(input.port)
        } else {
            None
        };
        let socks_auth = if input.socks_auth.is_empty() {
            None
        } else {
            Some(input.socks_auth.clone())
        };
        Self {
            protocol,
            destination,
            port,
            socks_auth,
        }
    }

    /// Encode as an opaque token suitable for SOCKS username/password or HTTP
    /// `Tor-Stream-Isolation`. Stable for equal keys.
    pub fn to_token(&self) -> String {
        // Simple deterministic encoding; avoids leaking raw destinations in logs
        // less than necessary while being stable. Not a secret.
        use std::fmt::Write as _;
        let mut out = String::from("tobro-iso1:");
        let _ = write!(out, "p={};", self.protocol.unwrap_or(0));
        let _ = write!(out, "port={};", self.port.unwrap_or(0));
        if let Some(d) = &self.destination {
            // hex-encode destination to keep token header-safe
            for b in d.as_bytes() {
                let _ = write!(out, "{b:02x}");
            }
        }
        out.push(';');
        if let Some(a) = &self.socks_auth {
            out.push_str("a=");
            for b in a.iter().take(64) {
                let _ = write!(out, "{b:02x}");
            }
            if a.len() > 64 {
                out.push_str("..");
            }
        }
        out
    }

    /// True if this key represents "no special isolation beyond defaults".
    pub fn is_default(&self) -> bool {
        self.protocol.is_none()
            && self.destination.is_none()
            && self.port.is_none()
            && self.socks_auth.is_none()
    }
}

impl IsolationHelper for TobroIsolationKey {
    fn compatible_same_type(&self, other: &Self) -> bool {
        self == other
    }

    fn join_same_type(&self, other: &Self) -> Option<Self> {
        if self == other {
            Some(self.clone())
        } else {
            None
        }
    }

    fn enables_long_lived_circuits(&self) -> bool {
        // SOCKS auth isolation (F-43) is an explicit isolation boundary and is
        // allowed to keep circuits alive for that boundary, matching Arti's
        // behavior for authenticated SOCKS streams.
        self.socks_auth.is_some() || self.destination.is_some() || self.port.is_some()
    }
}

fn normalize_destination(dest: &str) -> String {
    dest.trim().trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::StreamIsolationPolicy;

    fn policy(
        isolate_destination: bool,
        isolate_port: bool,
        isolate_protocol: bool,
        keep_alive_isolation: bool,
    ) -> StreamIsolationPolicy {
        StreamIsolationPolicy {
            isolate_destination,
            isolate_port,
            isolate_protocol,
            keep_alive_isolation,
        }
    }

    fn input(
        policy: StreamIsolationPolicy,
        protocol: ClientProtocol,
        destination: &str,
        port: u16,
        socks_auth: &[u8],
    ) -> StreamIsolationInput {
        StreamIsolationInput {
            policy,
            protocol,
            destination: destination.to_owned(),
            port,
            socks_auth: socks_auth.to_vec(),
        }
    }

    #[test]
    fn no_policy_ignores_dest_port_protocol() {
        let p = policy(false, false, false, false);
        let a =
            TobroIsolationKey::from_input(&input(p, ClientProtocol::Socks, "a.example", 80, &[]));
        let b = TobroIsolationKey::from_input(&input(
            p,
            ClientProtocol::HttpConnect,
            "b.example",
            443,
            &[],
        ));
        assert!(a.compatible_same_type(&b));
    }

    #[test]
    fn isolate_destination_separates_hosts() {
        let p = policy(true, false, false, false);
        let a =
            TobroIsolationKey::from_input(&input(p, ClientProtocol::Socks, "a.example", 80, &[]));
        let b =
            TobroIsolationKey::from_input(&input(p, ClientProtocol::Socks, "b.example", 80, &[]));
        assert!(!a.compatible_same_type(&b));
    }

    #[test]
    fn isolate_port_separates_ports() {
        let p = policy(false, true, false, false);
        let a =
            TobroIsolationKey::from_input(&input(p, ClientProtocol::Socks, "a.example", 80, &[]));
        let b =
            TobroIsolationKey::from_input(&input(p, ClientProtocol::Socks, "a.example", 443, &[]));
        assert!(!a.compatible_same_type(&b));
    }

    #[test]
    fn isolate_protocol_separates_protocols() {
        let p = policy(false, false, true, false);
        let a =
            TobroIsolationKey::from_input(&input(p, ClientProtocol::Socks, "a.example", 80, &[]));
        let b = TobroIsolationKey::from_input(&input(
            p,
            ClientProtocol::HttpConnect,
            "a.example",
            80,
            &[],
        ));
        assert!(!a.compatible_same_type(&b));
    }

    #[test]
    fn socks_auth_isolates_when_present() {
        let p = policy(false, false, false, true);
        let a = TobroIsolationKey::from_input(&input(
            p,
            ClientProtocol::Socks,
            "a.example",
            80,
            b"user1",
        ));
        let b = TobroIsolationKey::from_input(&input(
            p,
            ClientProtocol::Socks,
            "a.example",
            80,
            b"user2",
        ));
        let c = TobroIsolationKey::from_input(&input(
            p,
            ClientProtocol::Socks,
            "a.example",
            80,
            b"user1",
        ));
        assert!(!a.compatible_same_type(&b));
        assert!(a.compatible_same_type(&c));
        assert!(a.enables_long_lived_circuits());
    }

    #[test]
    fn destination_normalization_is_case_insensitive() {
        let p = policy(true, false, false, false);
        let a = TobroIsolationKey::from_input(&input(
            p,
            ClientProtocol::Socks,
            "EXAMPLE.ONION.",
            80,
            &[],
        ));
        let b = TobroIsolationKey::from_input(&input(
            p,
            ClientProtocol::Socks,
            "example.onion",
            80,
            &[],
        ));
        assert!(a.compatible_same_type(&b));
    }
}
