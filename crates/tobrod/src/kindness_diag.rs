//! Kindness Mode eligibility diagnostics (M6, F-61/F-62/F-66).
//!
//! One pass, three probes, honest labels:
//! - **NAT detection (F-61)**: a minimal RFC 5389 STUN binding probe over UDP.
//!   With standard STUN servers a full RFC 4787/5780 behavior classification
//!   is not possible (behavior test 3 needs a second server port), so this
//!   reports exactly what was measured: whether a NAT sits between the
//!   machine and the internet, and whether the UDP mapping held when the same
//!   socket queried different addresses of the same server. No
//!   `endpoint_independent`/`full_cone` claims.
//! - **UPnP (F-62)**: IGD gateway discovery via `igd-next` (blocking client,
//!   run through `spawn_blocking`). When `kindness.ephemeral_ports` is
//!   configured and a NAT was detected, a bounded head of the range is
//!   mapped in (external → local, UDP, permanent lease) with an explicit
//!   count of what actually succeeded.
//! - **Bootstrap (F-66)**: the Snowflake broker is reached with a plain HTTPS
//!   GET from the daemon's direct network path, plus a binary-availability
//!   check using the same locate/verify strategy as the supervisor.
//!
//! The whole report is deliberately free of secrets and of the user's public
//! IP (the report tells the user whether a NAT exists; it does not need to
//! echo their address back).

use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::time::Duration;

use rand::{RngCore, thread_rng};
use serde::Serialize;

/// STUN servers used when `kindness.stun_url` is not configured. Upstream
/// snowflake defaults to `stun:stun.l.google.com:19302`.
pub(crate) const DEFAULT_STUN_URLS: &str =
    "stun:stun.l.google.com:19302,stun:stun1.l.google.com:19302";

/// Broker behind the built-in rendezvous of `snowflake-proxy` (upstream
/// default when `-broker` is not passed).
const DEFAULT_BROKER_URL: &str = "https://snowflake-broker.torproject.net/";

/// Single-probe/respond timeouts.
const STUN_TIMEOUT: Duration = Duration::from_secs(3);
const UPNP_SEARCH_TIMEOUT: Duration = Duration::from_secs(5);
const BROKER_TIMEOUT: Duration = Duration::from_secs(8);

/// Upper bound on ports mapped per run. Whole ephemeral ranges (upstream,
/// thousands of ports) cannot be negotiated port-by-port with every router;
/// the head of the range is mapped and the shortfall is reported.
const MAX_UPNP_MAPPINGS: u16 = 64;

const STUN_MAGIC: &[u8; 4] = &[0x21, 0x12, 0xA4, 0x42];

/// Item severity, rendered by the settings UI (`good`/`info`/`warn`/`error`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Default)]
#[serde(rename_all = "lowercase")]
pub(crate) enum DiagSeverity {
    Good,
    #[default]
    Info,
    Warn,
    Error,
}

/// One actionable line of the eligibility report.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct DiagItem {
    pub severity: DiagSeverity,
    /// Stable short identifier (`binary`, `nat`, `nat_force`, `upnp`,
    /// `upnp_mapping`, `broker`).
    pub code: &'static str,
    /// Human-readable outcome (no secrets).
    pub message: String,
    /// What to do when the check did not pass.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
}

/// NAT detection result (F-61). Field names state exactly what was
/// measured; the `mapping_consistency` note explains the approximation.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct StunResult {
    /// `direct` when the STUN server saw the local address itself, `nat`
    /// when it saw a different (translated) address, `unknown` when no
    /// server answered.
    pub state: &'static str,
    /// Whether the UDP mapping (from one local socket) held across two
    /// addresses of the same server: `same_across_server_ips`,
    /// `differs_across_server_ips`, or `unknown`.
    pub mapping_consistency: &'static str,
    /// Extra honest-labelling detail for the UI.
    pub note: Option<String>,
    /// How many configured/known STUN servers were contacted.
    pub servers_tried: usize,
}

impl Default for StunResult {
    fn default() -> Self {
        Self {
            state: "unknown",
            mapping_consistency: "unknown",
            note: None,
            servers_tried: 0,
        }
    }
}

/// UPnP result (F-62). Summary-level; `detail` carries what happened.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct UpnpResult {
    /// `available` when an IGD gateway answered, `unavailable` when no
    /// gateway responded, `unknown` on failure.
    pub state: &'static str,
    /// Ports added per this run (only when an explicit range is configured
    /// and a NAT was detected): `(mapped, requested_after_cap)`.
    pub ports_mapped: Option<(u16, u16)>,
    pub detail: Option<String>,
}

impl Default for UpnpResult {
    fn default() -> Self {
        Self {
            state: "unknown",
            ports_mapped: None,
            detail: None,
        }
    }
}

/// Aggregated eligibility report (F-66).
#[derive(Debug, Clone, Serialize)]
pub(crate) struct KindnessReport {
    /// True when no probe produced an `error`-severity item.
    pub ok: bool,
    pub items: Vec<DiagItem>,
    pub stun: StunResult,
    pub upnp: UpnpResult,
}

/// Parse a `kindness.stun_url` list value (comma-separated `stun:host[:port]`
/// URLs) into host/port pairs. Invalid entries are skipped; an unparseable
/// list falls back to the built-in defaults so the NAT probe still runs.
pub(crate) fn parse_stun_urls(raw: Option<&str>) -> Vec<(String, u16)> {
    let list = match raw {
        None => DEFAULT_STUN_URLS,
        Some(raw) if raw.trim().is_empty() => DEFAULT_STUN_URLS,
        Some(raw) => raw,
    };
    let mut out = Vec::new();
    for entry in list.split(',') {
        let entry = entry.trim();
        let Some(host) = entry
            .strip_prefix("stun:")
            .or_else(|| entry.strip_prefix("stun://"))
        else {
            continue;
        };
        let host = host.trim();
        if host.is_empty() {
            continue;
        }
        // Split the optional `:port`; brackets around v6 literals are not
        // supported by the upstream flag either (`-stun stun:host:port`).
        let (host, port) = match host.rsplit_once(':') {
            Some((h, p)) => match p.trim().parse::<u16>() {
                Ok(p) if p > 0 => (h.trim(), p),
                _ => (host, 3478),
            },
            None => (host, 3478),
        };
        if host.is_empty() || host.contains(':') {
            continue;
        }
        out.push((host.to_owned(), port));
    }
    if out.is_empty() {
        // Never let a bad configured list disable the NAT probe silently.
        parse_stun_urls(Some(DEFAULT_STUN_URLS))
    } else {
        out
    }
}

/// Build a minimal RFC 5389 Binding request. `rng` is test-pluggable via
/// [`build_binding_request`]'s sibling below; production uses OS randomness.
fn build_binding_request_with(mut fill_random: impl FnMut(&mut [u8])) -> ([u8; 20], [u8; 12]) {
    let mut request = [0u8; 20];
    // TCP/UDP distinction bit is 0; message type 0x0001 = Binding request.
    request[0] = 0x00;
    request[1] = 0x01;
    // Message length 0; magic cookie.
    request[4..8].copy_from_slice(STUN_MAGIC);
    fill_random(&mut request[8..20]);
    let mut txn = [0u8; 12];
    txn.copy_from_slice(&request[8..20]);
    (request, txn)
}

/// Bind a request with OS randomness.
fn build_binding_request() -> ([u8; 20], [u8; 12]) {
    build_binding_request_with(|buf| thread_rng().fill_bytes(buf))
}

/// Parse a STUN Binding success response into the mapped address. Prefers
/// XOR-MAPPED-ADDRESS and falls back to MAPPED-ADDRESS (RFC 5389 mirrors).
fn parse_binding_response(packet: &[u8], expected_txn: &[u8; 12]) -> Result<SocketAddr, String> {
    if packet.len() < 20 {
        return Err(format!("short packet ({} bytes)", packet.len()));
    }
    let is_binding_success = packet[0] == 0x01 && packet[1] == 0x01;
    if !is_binding_success {
        return Err(format!(
            "unexpected STUN message type 0x{:02x}{:02x}",
            packet[0], packet[1]
        ));
    }
    if packet[4..8] != *STUN_MAGIC {
        return Err("wrong STUN magic cookie".to_owned());
    }
    if packet[8..20] != *expected_txn {
        return Err("STUN transaction id mismatch".to_owned());
    }
    let msg_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if packet.len() < 20 + msg_len {
        return Err("truncated STUN attributes".to_owned());
    }
    let mut attrs = &packet[20..20 + msg_len];
    let mut xor_mapped: Option<SocketAddr> = None;
    let mut mapped: Option<SocketAddr> = None;
    while attrs.len() >= 4 {
        let attr_type = u16::from_be_bytes([attrs[0], attrs[1]]);
        let attr_len = u16::from_be_bytes([attrs[2], attrs[3]]) as usize;
        if attr_len > attrs.len().saturating_sub(4) {
            return Err("STUN attribute overruns the message".to_owned());
        }
        let value = &attrs[4..4 + attr_len];
        match attr_type {
            // XOR-MAPPED-ADDRESS (0x0020), MAPPED-ADDRESS (0x0001).
            0x0020 | 0x0001 => {
                let parsed = parse_address_attribute(value, attr_type == 0x0020, packet)
                    .map_err(|e| format!("bad STUN address attribute: {e}"))?;
                if attr_type == 0x0020 && xor_mapped.is_none() {
                    xor_mapped = Some(parsed);
                } else if attr_type == 0x0001 && mapped.is_none() {
                    mapped = Some(parsed);
                }
            }
            _ => {}
        }
        // Attributes are 32-bit aligned with padding.
        let padded = attr_len.div_ceil(4) * 4;
        attrs = &attrs[4 + padded..]
    }
    xor_mapped
        .or(mapped)
        .ok_or_else(|| "no mapped address attribute in STUN response".to_owned())
}

/// Parse the body of a MAPPED/XOR-MAPPED address attribute.
fn parse_address_attribute(value: &[u8], xored: bool, packet: &[u8]) -> Result<SocketAddr, String> {
    if value.len() < 8 {
        return Err("attribute too short".to_owned());
    }
    let family = value[1];
    let port_raw = u16::from_be_bytes([value[2], value[3]]);
    let port = if xored {
        port_raw ^ u16::from_be_bytes([STUN_MAGIC[0], STUN_MAGIC[1]])
    } else {
        port_raw
    };
    match family {
        0x01 => {
            if value.len() < 8 {
                return Err("IPv4 attribute too short".to_owned());
            }
            let mut addr_bytes = [0u8; 4];
            addr_bytes.copy_from_slice(&value[4..8]);
            let ip = if xored {
                let mut ip = addr_bytes;
                for (i, b) in ip.iter_mut().enumerate() {
                    *b ^= STUN_MAGIC[i];
                }
                IpAddr::V4(ip.into())
            } else {
                IpAddr::V4(addr_bytes.into())
            };
            Ok(SocketAddr::new(ip, port))
        }
        0x02 => {
            if value.len() < 20 {
                return Err("IPv6 attribute too short".to_owned());
            }
            let mut addr_bytes = [0u8; 16];
            addr_bytes.copy_from_slice(&value[4..20]);
            let ip = if xored {
                let mut ip = addr_bytes;
                // RFC 5389: XOR with the magic cookie concatenated with the
                // transaction id.
                let mut mask = [0u8; 16];
                mask[..4].copy_from_slice(STUN_MAGIC);
                mask[4..16].copy_from_slice(&packet[8..20]);
                for (b, m) in ip.iter_mut().zip(mask) {
                    *b ^= m;
                }
                IpAddr::V6(ip.into())
            } else {
                IpAddr::V6(addr_bytes.into())
            };
            Ok(SocketAddr::new(ip, port))
        }
        _ => Err(format!("unsupported address family 0x{family:02x}")),
    }
}

/// Send one binding request and wait for the (matched) response.
async fn stun_query(
    socket: &tokio::net::UdpSocket,
    server: SocketAddr,
) -> Result<SocketAddr, String> {
    let (request, txn) = build_binding_request();
    socket
        .send_to(&request, server)
        .await
        .map_err(|e| format!("send to {server} failed: {e}"))?;
    let mut buf = vec![0u8; 1024];
    let received = tokio::time::timeout(STUN_TIMEOUT, async {
        loop {
            match socket.recv_from(&mut buf).await {
                Ok((n, from)) if from == server => break Ok(n),
                Ok(_) => continue,
                Err(e) => return Err(format!("recv failed: {e}")),
            }
            // Ignore stray packets from other addresses (NAT helpers, peers).
        }
    })
    .await
    .map_err(|_| format!("no response from {server} within {STUN_TIMEOUT:?}"))?;
    let n = received?;
    parse_binding_response(&buf[..n], &txn)
}

/// Contact a single server (first resolvable IPv4 address) and return the
/// mapped address.
async fn stun_probe_server(
    socket: &tokio::net::UdpSocket,
    host: &str,
    port: u16,
) -> Result<SocketAddr, String> {
    let mut last_error = String::from("no IPv4 address resolved");
    for server in tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| format!("could not resolve {host}: {e}"))?
        .filter(|a| a.is_ipv4())
    {
        match stun_query(socket, server).await {
            Ok(mapped) => return Ok(mapped),
            Err(e) => last_error = e,
        }
    }
    Err(last_error)
}

/// F-61/F-66 STUN probe over one socket: NAT presence plus honest
/// mapping-consistency across two addresses of the same server.
async fn run_stun_probe(stun_urls: &[(String, u16)]) -> StunResult {
    let mut result = StunResult::default();
    let Ok(socket) = tokio::net::UdpSocket::bind("0.0.0.0:0").await else {
        result.note = Some("could not bind a local UDP socket for the STUN probe".to_owned());
        return result;
    };
    let local_addr = socket.local_addr().ok();
    let mut mapping: Option<SocketAddr> = None;

    for (host, port) in stun_urls {
        result.servers_tried = result.servers_tried.saturating_add(1);
        match stun_probe_server(&socket, host, *port).await {
            Ok(mapped) => {
                mapping = Some(mapped);
                break;
            }
            Err(error) => tracing::debug!(host, %error, "STUN server unavailable"),
        }
    }

    let Some(mapped) = mapping else {
        result.note = Some(
            "no configured STUN server answered; NAT detection needs reachable STUN (UDP 3478)"
                .to_owned(),
        );
        return result;
    };

    // NAT presence: did the server see us at the local address itself?
    if let Some(local) = local_addr
        && mapped.ip() == local.ip()
        && mapped.port() == local.port()
    {
        result.state = "direct";
        result.mapping_consistency = "unknown";
        result.note = Some(
            "the STUN server saw the local socket address unchanged; UDP traffic leaves NAT-free"
                .to_owned(),
        );
        return result;
    }
    result.state = "nat";

    // Mapping consistency (RFC 5780 behavior-2-style, same socket, two
    // addresses of the same server). Standard servers cannot answer
    // behavior-3 (second server port), so endpoint-independent vs
    // address-and-port-dependent mapping is *not* claimed here.
    for (host, port) in stun_urls {
        let resolved = match tokio::net::lookup_host((host.as_str(), *port)).await {
            Ok(list) => list,
            Err(_) => continue,
        };
        let mut distinct: Vec<SocketAddr> = Vec::new();
        for addr in resolved {
            if addr.is_ipv4() && !distinct.iter().any(|a| a.ip() == addr.ip()) {
                distinct.push(addr);
                if distinct.len() == 2 {
                    break;
                }
            }
        }
        let Some(second) = distinct.get(1).copied() else {
            continue;
        };
        return match stun_query(&socket, second).await {
            Ok(mapped2) if mapped2.port() == mapped.port() => {
                result.mapping_consistency = "same_across_server_ips";
                result.note = Some(
                    "the UDP mapping kept the same external port across two addresses of the \
                     same STUN server (mapping is at least independent of the destination \
                     address; standard servers cannot test destination ports, so a full \
                     classification is not claimed)"
                        .to_owned(),
                );
                result
            }
            Ok(mapped2) => {
                result.mapping_consistency = "differs_across_server_ips";
                result.note = Some(format!(
                    "the UDP mapping changed port between two addresses of the same STUN \
                     server ({}/{}) and is address-dependent; unrestricted-style serving \
                     relies on the proxy sending first or on explicit port forwarding",
                    mapped.port(),
                    mapped2.port()
                ));
                result
            }
            Err(error) => {
                result.mapping_consistency = "unknown";
                result.note = Some(format!(
                    "the second address of the STUN server did not answer ({error}); \
                     mapping consistency could not be checked"
                ));
                result
            }
        };
    }
    result.mapping_consistency = "unknown";
    result.note = Some(
        "no STUN server with two usable addresses answered; mapping consistency unknown".to_owned(),
    );
    result
}

/// F-62 UPnP gateway discovery + optional bounded range mapping. Blocking
/// `igd-next` only; called through `spawn_blocking`.
fn run_upnp_probe_blocking(nat_detected: bool, configured_range: Option<(u16, u16)>) -> UpnpResult {
    let mut options = igd_next::SearchOptions::default();
    options.timeout = Some(UPNP_SEARCH_TIMEOUT);
    options.single_search_timeout = Some(Duration::from_secs(2));
    let gateway = match igd_next::search_gateway(options) {
        Ok(gateway) => gateway,
        Err(_error) => {
            return UpnpResult {
                state: "unavailable",
                detail: Some(
                    "no UPnP/IGD gateway answered within the search window (optional)".to_owned(),
                ),
                ..UpnpResult::default()
            };
        }
    };
    let external_ip = match gateway.get_external_ip() {
        Ok(_ip) => {
            // The external IP is deliberately not echoed (privacy); it is
            // only a success signal.
            tracing::debug!("UPnP gateway reachable via IGD");
            Some(())
        }
        Err(error) => {
            tracing::debug!(%error, "UPnP gateway reachable but no external ip");
            None
        }
    };
    let mut result = UpnpResult {
        state: if external_ip.is_some() {
            "available"
        } else {
            "unknown"
        },
        ..UpnpResult::default()
    };

    // Map the configured ephemeral range head when this run found a NAT
    // (no NAT → nothing to forward; the gateway would reject it anyway).
    let Some((min, max)) = configured_range else {
        return result;
    };
    if !nat_detected {
        result.detail = Some(
            "ephemeral_ports are configured, but NAT detection saw a direct connection; \
             no mapping was attempted"
                .to_owned(),
        );
        return result;
    }
    // The mapping target is the LAN address traffic towards the gateway
    // leaves on (UDP "connect" sends nothing, it only selects the address).
    let local_ip: Option<std::net::IpAddr> = (|| -> std::io::Result<std::net::IpAddr> {
        let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
        socket.connect(gateway.addr)?;
        Ok(socket.local_addr()?.ip())
    })()
    .ok();
    let Some(local_ip) = local_ip else {
        result.ports_mapped = Some((0, 0));
        result.detail = Some(
            "could not determine the local LAN address for mapping; no ports were forwarded"
                .to_owned(),
        );
        return result;
    };
    let requested = (min..=max)
        .take(MAX_UPNP_MAPPINGS as usize)
        .collect::<Vec<u16>>();
    let total_requested = max - min + 1;
    let mut mapped = 0u16;
    let mut last_error = String::new();
    for port in &requested {
        match gateway.add_port(
            igd_next::PortMappingProtocol::UDP,
            *port,
            SocketAddr::new(local_ip, *port),
            // Permanent lease (0 = infinite per IGD): the mapping lives in
            // the router until it is removed there or by another client.
            0,
            "tobro snowflake-proxy (UDP)",
        ) {
            Ok(()) => mapped += 1,
            Err(error) if error.to_string().to_ascii_lowercase().contains("conflict") => {
                // Already-mapped ports count as "in place", not failures;
                // gateways reject duplicates.
                mapped += 1;
            }
            Err(error) => last_error = error.to_string(),
        }
    }
    result.ports_mapped = Some((mapped, requested.len() as u16));
    result.detail = Some(if mapped == requested.len() as u16 {
        format!(
            "mapped {mapped} UDP ports of the configured range head ({min}:{max}) inbound to \
             this machine; the full window would be {} ports (mapping is capped at \
             {MAX_UPNP_MAPPINGS} per run)",
            total_requested
        )
    } else if mapped > 0 {
        format!(
            "mapped {mapped} of {} requested UDP ports ({min}:{max} head); see the router \
             admin page for the rest ({last_error})",
            requested.len()
        )
    } else {
        format!(
            "no UDP ports of the configured range ({min}:{max}) could be forwarded ({last_error}); \
             manual router forwarding is the fallback"
        )
    });
    result
}

/// F-66 broker reachability over the daemon's direct network path.
/// Returns the HTTP status (headers already received by `send`).
pub(crate) async fn http_reachable(url: &str, timeout: Duration) -> Result<u16, String> {
    let client = reqwest::Client::builder()
        .timeout(timeout)
        .user_agent("tobro-kindness")
        .build()
        .map_err(|e| format!("could not build http client: {e}"))?;
    let response = client.get(url).send().await.map_err(|e| e.to_string())?;
    Ok(response.status().as_u16())
}

/// Run the full eligibility pass (F-61 + F-62 + F-66).
pub(crate) async fn run_eligibility(
    config: &tobro_config::KindnessConfig,
    state_dir: &Path,
) -> KindnessReport {
    let mut items = Vec::new();

    // 1. binary availability (F-60 prerequisite; same locate strategy as the
    //    supervisor, no verification repeated here).
    match crate::kindness::locate_binary(config, Some(state_dir)) {
        Ok(located) => items.push(DiagItem {
            severity: DiagSeverity::Good,
            code: "binary",
            message: format!("snowflake-proxy binary found at {}", located.path.display()),
            action: None,
        }),
        Err(error) => items.push(DiagItem {
            severity: DiagSeverity::Error,
            code: "binary",
            message: format!("could not locate the snowflake-proxy binary: {error:#}"),
            action: Some(
                "Install snowflake-proxy (Tor Browser/standalone download or package \
                 manager) or point kindness.proxy_path at it."
                    .to_owned(),
            ),
        }),
    }

    // 2. NAT detection (F-61).
    let stun_urls = parse_stun_urls(config.stun_url.as_deref());
    let stun = run_stun_probe(&stun_urls).await;
    match (stun.state, stun.mapping_consistency) {
        ("direct", _) => items.push(DiagItem {
            severity: DiagSeverity::Good,
            code: "nat",
            message: "NAT detection: no NAT seen between this machine and the STUN \
                      server; inbound UDP is not at risk from translation"
                .to_owned(),
            action: None,
        }),
        ("nat", "same_across_server_ips") => items.push(DiagItem {
            severity: DiagSeverity::Good,
            code: "nat",
            message: "NAT detection: a NAT was detected and the UDP mapping stayed \
                      consistent across server addresses (approximate; see the \
                      mapping note). The proxy should serve fine in this setup"
                .to_owned(),
            action: None,
        }),
        ("nat", "differs_across_server_ips") => items.push(DiagItem {
            severity: DiagSeverity::Warn,
            code: "nat",
            message: "NAT detection: a NAT was detected and the UDP mapping changes \
                      between server addresses (address-dependent mapping). Serving \
                      still works, but fewer clients can connect through this proxy"
                .to_owned(),
            action: Some(
                "If the router exposes one, prefer a UPnP port forward \
                 (kindness.ephemeral_ports) or a manual inbound UDP range forward."
                    .to_owned(),
            ),
        }),
        _ => items.push(DiagItem {
            severity: DiagSeverity::Warn,
            code: "nat",
            message: "NAT detection could not be completed (no server answered or no \
                      second server address was available)"
                .to_owned(),
            action: Some(
                "Check that outgoing UDP to port 3478 is allowed; the probe can also be \
                 re-run with a custom STUN server via kindness.stun_url."
                    .to_owned(),
            ),
        }),
    }
    if config.nat_type_force_unrestricted {
        items.push(DiagItem {
            severity: DiagSeverity::Info,
            code: "nat_force",
            message: "the proxy is configured to report unrestricted NAT \
                      (kindness.nat_type_force_unrestricted) regardless of measured \
                      network reality"
                .to_owned(),
            action: None,
        });
    }

    // 3. UPnP (F-62): discovery + bounded mapping when a range is configured.
    let configured_range = config.parse_ephemeral_ports().ok();
    let upnp = tokio::task::spawn_blocking(move || {
        run_upnp_probe_blocking(stun.state == "nat", configured_range)
    })
    .await
    .unwrap_or(UpnpResult::default());
    match upnp.state {
        "available" => items.push(DiagItem {
            severity: DiagSeverity::Good,
            code: "upnp",
            message: "UPnP gateway discovered and reachable (support for port \
                      mapping is what matters; the gateway address itself is not \
                      needed in the report)"
                .to_owned(),
            action: None,
        }),
        "unavailable" => items.push(DiagItem {
            severity: DiagSeverity::Info,
            code: "upnp",
            message: "no UPnP/IGD gateway answered (optional feature)".to_owned(),
            action: Some(
                "Enable UPnP on the router, or forward a UDP range manually; without \
                 it, NAT behavior stays as measured above."
                    .to_owned(),
            ),
        }),
        _ => items.push(DiagItem {
            severity: DiagSeverity::Info,
            code: "upnp",
            message: "UPnP gateway search ended without a clear result".to_owned(),
            action: Some(
                "Re-run the test, or check the router admin page for UPnP support.".to_owned(),
            ),
        }),
    }
    if let Some((mapped, requested)) = upnp.ports_mapped {
        let detail = upnp
            .detail
            .clone()
            .unwrap_or_else(|| "mapping attempted".to_owned());
        if mapped == requested && mapped > 0 {
            items.push(DiagItem {
                severity: DiagSeverity::Good,
                code: "upnp_mapping",
                message: detail,
                action: None,
            });
        } else if mapped > 0 {
            items.push(DiagItem {
                severity: DiagSeverity::Warn,
                code: "upnp_mapping",
                message: detail,
                action: Some(
                    "Check the router admin page; some gateways rate-limit or deny \
                     many mappings in quick succession."
                        .to_owned(),
                ),
            });
        } else {
            items.push(DiagItem {
                severity: DiagSeverity::Warn,
                code: "upnp_mapping",
                message: detail,
                action: Some(
                    "Enable UPnP on the router or forward the range manually \
                     (external UDP ports → this machine)."
                        .to_owned(),
                ),
            });
        }
    }

    // 4. broker reachability (F-66 bootstrap part).
    let broker_url = match config.broker_url.as_deref() {
        Some(url) if !url.trim().is_empty() => url.trim(),
        _ => DEFAULT_BROKER_URL,
    };
    match http_reachable(broker_url, BROKER_TIMEOUT).await {
        Ok(status) => {
            if matches!(status, 200..=499) {
                items.push(DiagItem {
                    severity: DiagSeverity::Good,
                    code: "broker",
                    message: format!(
                        "Snowflake broker at {broker_url} answered with HTTP {status} \
                         (reachability, not a full rendezvous handshake)"
                    ),
                    action: None,
                });
            } else {
                items.push(DiagItem {
                    severity: DiagSeverity::Warn,
                    code: "broker",
                    message: format!(
                        "Snowflake broker at {broker_url} answered with HTTP {status}"
                    ),
                    action: Some(
                        "Non-2xx/3xx broker answers usually mean a captive portal or \
                         a filtering middlebox; adjust kindness.broker_url or the \
                         network."
                            .to_owned(),
                    ),
                });
            }
        }
        Err(error) => items.push(DiagItem {
            severity: DiagSeverity::Warn,
            code: "broker",
            message: format!("could not reach the Snowflake broker at {broker_url}: {error}"),
            action: Some(
                "Check that this machine can reach the broker over HTTPS; note the \
                 eligibility test uses the daemon's direct network path, while the \
                 running proxy uses whatever path the browser rendezvous can reach."
                    .to_owned(),
            ),
        }),
    }

    let ok = !items
        .iter()
        .any(|item| item.severity == DiagSeverity::Error);
    KindnessReport {
        ok,
        items,
        stun,
        upnp,
    }
}

/// `kindness.status` payload helper: current supervisor state string.
pub(crate) fn sidecar_state_label(
    snapshot: &crate::pt_supervisor::SidecarSnapshot,
) -> &'static str {
    use crate::pt_supervisor::SidecarState;
    match snapshot.state {
        SidecarState::Stopped => "stopped",
        SidecarState::Starting => "starting",
        SidecarState::Ready => "running",
        SidecarState::Failed => "failed",
        SidecarState::Stopping => "stopping",
    }
}

// ---------------------------------------------------------------------------
// Tests (parsers and pure classification; no network).
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    const STUN_MAGIC: [u8; 4] = [0x21, 0x12, 0xA4, 0x42];

    #[test]
    fn stun_request_shape_and_txn_round_trip() {
        let (request, txn) = build_binding_request();
        assert_eq!(request[0], 0x00);
        assert_eq!(request[1], 0x01);
        assert_eq!(request[4..8], STUN_MAGIC);
        assert_eq!(request[8..20], txn);
    }

    #[test]
    fn parse_xor_mapped_v4() {
        // Server 203.0.113.7 replied; mapped address (XOR) 198.51.100.23:40000.
        let txn: [u8; 12] = core::array::from_fn(|i| i as u8);
        let mut packet = Vec::new();
        packet.extend_from_slice(&[0x01, 0x01]); // Binding success response
        packet.extend_from_slice(&[0x00, 0x0c]); // length: header + value
        packet.extend_from_slice(&STUN_MAGIC);
        packet.extend_from_slice(&txn);
        packet.extend_from_slice(&[0x00, 0x20, 0x00, 0x08]); // XOR-MAPPED-ADDRESS
        packet.extend_from_slice(&[0x00, 0x01, 0xbd, 0x52]); // port xor magic
        packet.extend_from_slice(&[0xe7, 0x21, 0xc0, 0x55]); // ip xor magic
        let mapped = parse_binding_response(&packet, &txn).expect("parse");
        assert_eq!(mapped.port(), 40000);
        assert_eq!(mapped.ip().to_string(), "198.51.100.23");
    }

    #[test]
    fn parse_mapped_fallback_and_rejects_mismatch() {
        let txn: [u8; 12] = [0u8; 12];
        let mut packet = Vec::new();
        packet.extend_from_slice(&[0x01, 0x01]);
        packet.extend_from_slice(&[0x00, 0x0c]);
        packet.extend_from_slice(&STUN_MAGIC);
        packet.extend_from_slice(&txn);
        packet.extend_from_slice(&[0x00, 0x01, 0x00, 0x08]); // MAPPED-ADDRESS
        packet.extend_from_slice(&[0x00, 0x01, 0x04, 0xd2]); // plain :1234
        packet.extend_from_slice(&[203, 0, 113, 7]);
        let mapped = parse_binding_response(&packet, &txn).expect("parse");
        assert_eq!(mapped.ip().to_string(), "203.0.113.7");
        assert_eq!(mapped.port(), 1234);

        let mut other_txn = txn;
        other_txn[0] = 1;
        let err = parse_binding_response(&packet, &other_txn).expect_err("txn mismatch");
        assert!(err.contains("transaction"), "{err}");
    }

    #[test]
    fn parse_rejects_garbage() {
        let txn = [5u8; 12];
        let ok_packet: Vec<u8> = {
            let mut p = Vec::new();
            p.extend_from_slice(&[0x01, 0x01, 0x00, 0x0c]);
            p.extend_from_slice(&STUN_MAGIC);
            p.extend_from_slice(&txn);
            p.extend_from_slice(&[0x00, 0x20, 0x00, 0x08]);
            p.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]);
            p.extend_from_slice(&[1, 2, 3, 4]);
            p
        };
        assert!(parse_binding_response(&ok_packet, &txn).is_ok());
        // Error response (0x0111) is not a success.
        let mut error_packet = ok_packet.clone();
        error_packet[1] = 0x11;
        let err = parse_binding_response(&error_packet, &txn).expect_err("error response");
        assert!(err.contains("unexpected"), "{err}");
        // Truncated.
        let short = parse_binding_response(&ok_packet[..8], &txn).expect_err("short");
        assert!(short.contains("short"), "{short}");
        // Wrong cookie.
        let mut bad_magic = ok_packet.clone();
        bad_magic[4] = 0;
        let err = parse_binding_response(&bad_magic, &txn).expect_err("magic");
        assert!(err.contains("magic"), "{err}");
    }

    #[test]
    fn stun_url_parsing() {
        assert_eq!(
            parse_stun_urls(None),
            vec![
                ("stun.l.google.com".to_owned(), 19302),
                ("stun1.l.google.com".to_owned(), 19302)
            ]
        );
        assert_eq!(
            parse_stun_urls(Some("")),
            parse_stun_urls(None),
            "empty configured list falls back to the defaults"
        );
        assert_eq!(
            parse_stun_urls(Some("stun:stun.example.net:3479, fake.example.com")),
            vec![("stun.example.net".to_owned(), 3479)]
        );
        assert_eq!(
            parse_stun_urls(Some("stun:host-a")),
            vec![("host-a".to_owned(), 3478)]
        );
        // Garbage list falls back to defaults.
        assert!(!parse_stun_urls(Some("stun:,:x, no:pe")).is_empty());
    }

    #[test]
    fn stun_state_default_is_unknown() {
        let stun = StunResult::default();
        assert_eq!(stun.state, "unknown");
        assert_eq!(stun.mapping_consistency, "unknown");
        assert_eq!(stun.servers_tried, 0);
    }
}
