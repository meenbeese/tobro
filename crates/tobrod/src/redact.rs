//! Secret redaction for logs and diagnostics.
//!
//! M1 exit gate requires that logs contain no secrets in a redaction test.
//! This module provides conservative, pattern-based redaction for values that
//! must never appear in tracing output or exported diagnostics.

#![allow(dead_code)] // M1 utility surface and redaction tests; wired into logging/diagnostics as call sites adopt it.

/// Placeholder used when sensitive material is removed.
pub const REDACTED: &str = "[REDACTED]";

/// Redact common secret patterns from `input`.
///
/// This is intentionally conservative: it prefers false positives (over-redaction)
/// over leaking credentials, bridge material, or private keys.
#[must_use]
pub fn redact_secrets(input: &str) -> String {
    let mut out = input.to_owned();
    out = redact_labeled_secrets(&out);
    out = redact_url_credentials(&out);
    out = redact_private_key_blocks(&out);
    out = redact_bridge_like_lines(&out);
    out
}

fn redact_labeled_secrets(input: &str) -> String {
    const LABELS: &[&str] = &[
        "authorization",
        "cookie",
        "password",
        "passwd",
        "secret",
        "token",
        "credential",
        "credentials",
        "x25519",
        "client_auth",
        "client-auth",
        "auth_private",
    ];

    let mut out = String::with_capacity(input.len());
    let lower = input.to_ascii_lowercase();
    let mut i = 0;
    while i < input.len() {
        let mut matched = false;
        for label in LABELS {
            if !lower[i..].starts_with(label) {
                continue;
            }
            // Avoid matching label as part of a longer identifier.
            if i > 0 {
                let prev = input[..i].chars().next_back().unwrap_or(' ');
                if prev.is_ascii_alphanumeric() || prev == '_' || prev == '-' {
                    continue;
                }
            }
            let label_end = i + label.len();
            out.push_str(&input[i..label_end]);
            i = label_end;

            let rest = &input[i..];
            let sep_len = rest
                .chars()
                .take_while(|c| c.is_whitespace() || matches!(c, ':' | '=' | '"' | '\''))
                .map(char::len_utf8)
                .sum::<usize>();
            if sep_len == 0 {
                out.push_str(REDACTED);
                matched = true;
                break;
            }
            out.push_str(&input[i..i + sep_len]);
            i += sep_len;

            let header_style = matches!(*label, "authorization" | "cookie");
            let value_len = input[i..]
                .chars()
                .take_while(|c| {
                    if header_style {
                        !matches!(c, '\n' | '\r' | ',')
                    } else {
                        !c.is_whitespace()
                            && !matches!(c, '&' | ',' | ';' | '"' | '\'' | '\n' | '\r')
                    }
                })
                .map(char::len_utf8)
                .sum::<usize>();
            if value_len > 0 {
                out.push_str(REDACTED);
                i += value_len;
            }
            matched = true;
            break;
        }
        if !matched {
            let ch = input[i..].chars().next().unwrap_or('\0');
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}

fn redact_url_credentials(input: &str) -> String {
    let mut out = input.to_owned();
    for scheme in ["https://", "http://", "socks5://", "socks4://"] {
        let mut search = 0;
        while let Some(rel) = out[search..].find(scheme) {
            let start = search + rel + scheme.len();
            if let Some(at_rel) = out[start..].find('@') {
                let host_start = start + at_rel + 1;
                // Only treat as credentials if there's no '/' before '@' in authority.
                if !out[start..host_start].contains('/') {
                    out.replace_range(start..start + at_rel, REDACTED);
                    search = start + REDACTED.len() + 1;
                    continue;
                }
            }
            search = start;
        }
    }
    out
}

fn redact_private_key_blocks(input: &str) -> String {
    let mut out = input.to_owned();
    const BEGIN: &str = "-----BEGIN";
    const END: &str = "-----END";
    while let Some(begin) = out.find(BEGIN) {
        let Some(end_rel) = out[begin..].find(END) else {
            out.replace_range(begin.., "[REDACTED PRIVATE KEY]");
            break;
        };
        let end_start = begin + end_rel;
        let end_line = out[end_start..]
            .find('\n')
            .map(|n| end_start + n + 1)
            .unwrap_or(out.len());
        out.replace_range(begin..end_line, "[REDACTED PRIVATE KEY]\n");
    }
    // Onion client auth private material is often `descriptor:x25519:<base64>`.
    if out.contains(":descriptor:x25519:") {
        let mut redacted_lines = Vec::new();
        for line in out.lines() {
            if line.contains(":descriptor:x25519:") {
                if let Some(prefix) = line.split(":descriptor:x25519:").next() {
                    redacted_lines.push(format!("{prefix}:descriptor:x25519:{REDACTED}"));
                } else {
                    redacted_lines.push(REDACTED.to_owned());
                }
            } else {
                redacted_lines.push(line.to_owned());
            }
        }
        out = redacted_lines.join("\n");
        if input.ends_with('\n') {
            out.push('\n');
        }
    }
    out
}

fn redact_bridge_like_lines(input: &str) -> String {
    let mut changed = false;
    let mut out = Vec::new();
    for line in input.lines() {
        let trimmed = line.trim_start();
        let is_bridge = trimmed.starts_with("Bridge ")
            || trimmed.starts_with("obfs4 ")
            || trimmed.starts_with("snowflake ")
            || trimmed.starts_with("webtunnel ")
            || trimmed.starts_with("meek_lite ")
            || trimmed.starts_with("dnstt ");
        if is_bridge {
            let prefix = trimmed.split_whitespace().next().unwrap_or("Bridge");
            out.push(format!("{prefix} {REDACTED}"));
            changed = true;
        } else {
            out.push(line.to_owned());
        }
    }
    if !changed {
        return input.to_owned();
    }
    let mut joined = out.join("\n");
    if input.ends_with('\n') {
        joined.push('\n');
    }
    joined
}

/// Wrap a value so its `Display`/`Debug` output is redacted.
///
/// Use for fields that may carry secrets (paths/URLs/credentials) when they
/// might be logged.
#[derive(Clone)]
pub struct Redacted<T>(pub T);

impl<T> std::fmt::Debug for Redacted<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(REDACTED)
    }
}

impl<T> std::fmt::Display for Redacted<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(REDACTED)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn redacts_password_and_authorization_labels() {
        let input = "proxy password=hunter2 Authorization: Bearer abc.def token=xyz";
        let redacted = redact_secrets(input);
        assert!(!redacted.contains("hunter2"), "{redacted}");
        assert!(!redacted.contains("abc.def"), "{redacted}");
        assert!(!redacted.contains("xyz"), "{redacted}");
        assert!(redacted.contains("password="));
        assert!(redacted.contains("Authorization:"));
        assert!(redacted.contains(REDACTED));
    }

    #[test]
    fn redacts_url_credentials() {
        let input = "connecting via https://user:supersecret@example.com/path";
        let redacted = redact_secrets(input);
        assert!(!redacted.contains("supersecret"), "{redacted}");
        assert!(!redacted.contains("user:"), "{redacted}");
        assert!(redacted.contains("https://"));
        assert!(redacted.contains("@example.com/path"), "{redacted}");
    }

    #[test]
    fn redacts_bridge_lines() {
        let input = "Bridge obfs4 192.0.2.1:443 00112233445566778899AABBCCDDEEFF00112233 cert=abcd iat-mode=0\nok";
        let redacted = redact_secrets(input);
        assert!(
            !redacted.contains("00112233445566778899AABBCCDDEEFF00112233"),
            "{redacted}"
        );
        assert!(!redacted.contains("cert=abcd"), "{redacted}");
        assert!(redacted.contains("Bridge [REDACTED]"), "{redacted}");
        assert!(redacted.contains("\nok"), "{redacted}");
    }

    #[test]
    fn redacts_private_key_material() {
        let input = "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n";
        let redacted = redact_secrets(input);
        assert!(!redacted.contains("abc"), "{redacted}");
        assert!(redacted.contains("REDACTED PRIVATE KEY"), "{redacted}");
    }

    #[test]
    fn redacts_onion_client_auth_private() {
        let input = "exampleonionaddress.onion:descriptor:x25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let redacted = redact_secrets(input);
        assert!(!redacted.contains("AAAAAAAAAAAAAAAA"), "{redacted}");
        assert!(
            redacted.contains(":descriptor:x25519:[REDACTED]"),
            "{redacted}"
        );
    }

    #[test]
    fn keeps_non_sensitive_text() {
        let input = "bootstrap 50%: loading directory information";
        assert_eq!(redact_secrets(input), input);
    }

    #[test]
    fn redacted_wrapper_never_formats_inner() {
        let value = format!("{:?} {}", Redacted("topsecret"), Redacted("topsecret"));
        assert!(!value.contains("topsecret"), "{value}");
        assert!(value.contains(REDACTED));
    }
}
