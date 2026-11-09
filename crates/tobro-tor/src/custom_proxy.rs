use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use anyhow::{Context as _, Result};
use arti_client::{StreamPrefs, TorClient};
use futures::AsyncReadExt as _;
use futures::AsyncWriteExt as FuturesAsyncWriteExt;
// (hickory-proto kept as dep for compatibility; custom DNS uses minimal wire format)
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio_util::compat::TokioAsyncReadCompatExt;
use tor_rtcompat::PreferredRuntime;
use tor_socksproto::{
    Handshake, SocksAuth, SocksCmd, SocksProxyHandshake, SocksRequest, SocksStatus,
};
use tracing::debug;

use crate::adapter::{IpVersionPref, NetworkStreamPrefs, StreamIsolationPolicy};
use crate::isolation::{ClientProtocol, StreamIsolationInput, TobroIsolationKey};

type Client = Arc<TorClient<PreferredRuntime>>;

pub async fn serve(
    client: Client,
    socks_port: u16,
    dns_port: u16,
    bind_all_interfaces: bool,
    stream_isolation: StreamIsolationPolicy,
    network_prefs: NetworkStreamPrefs,
) -> Result<()> {
    let bind_ip = if bind_all_interfaces {
        IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
    } else {
        IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
    };
    let socks_addr = SocketAddr::new(bind_ip, socks_port);
    let dns_addr = SocketAddr::new(bind_ip, dns_port);

    let dns = run_dns(client.clone(), dns_addr, network_prefs.clone());
    let proxy = run_proxy(client, socks_addr, stream_isolation, network_prefs);

    tokio::select! {
        biased;
        res = proxy => res,
        res = dns => res,
    }
}

fn build_base_prefs(network: &NetworkStreamPrefs) -> Result<StreamPrefs> {
    let mut prefs = StreamPrefs::new();
    match network.ip_version {
        IpVersionPref::Ipv4Preferred => {
            prefs.ipv4_preferred();
        }
        IpVersionPref::Ipv6Preferred => {
            prefs.ipv6_preferred();
        }
        IpVersionPref::Ipv4Only => {
            prefs.ipv4_only();
        }
        IpVersionPref::Ipv6Only => {
            prefs.ipv6_only();
        }
    }
    if let Some(cc) = network.exit_country.as_deref().filter(|s| !s.is_empty()) {
        let code: arti_client::CountryCode = cc.parse().with_context(|| {
            format!("invalid exit country {cc:?}; expected ISO 3166-1 alpha-2 (e.g. us, de)")
        })?;
        prefs.exit_country(code);
    }
    Ok(prefs)
}

fn prefs_for(
    base: &NetworkStreamPrefs,
    isolation: StreamIsolationPolicy,
    protocol: ClientProtocol,
    destination: String,
    port: u16,
    socks_auth: Vec<u8>,
) -> Result<StreamPrefs> {
    let mut prefs = build_base_prefs(base)?;
    let input = StreamIsolationInput {
        policy: isolation,
        protocol,
        destination,
        port,
        socks_auth,
    };
    let key = TobroIsolationKey::from_input(&input);
    prefs.set_isolation(key);
    Ok(prefs)
}

async fn run_dns(
    client: Client,
    addr: SocketAddr,
    network_prefs: NetworkStreamPrefs,
) -> Result<()> {
    let socket = Arc::new(
        UdpSocket::bind(addr)
            .await
            .with_context(|| format!("bind DNS {addr}"))?,
    );
    debug!(%addr, "custom DNS proxy listening");
    let mut buf = vec![0u8; 1536];
    loop {
        let (n, peer) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                debug!(%e, "DNS recv failed");
                continue;
            }
        };
        let packet = buf[..n].to_vec();
        let client = client.clone();
        let socket = socket.clone();
        let prefs = build_base_prefs(&network_prefs).unwrap_or_else(|_| StreamPrefs::new());
        tokio::spawn(async move {
            if let Err(e) = handle_dns(&client, &socket, peer, &packet, &prefs).await {
                debug!(%peer, error=%format!("{e:#}"), "DNS query failed");
            }
        });
    }
}

#[derive(Debug, Clone, Copy)]
enum DnsQType {
    A,
    Aaaa,
    Ptr,
    Other(u16),
}

fn parse_dns_query_minimal(packet: &[u8]) -> Result<(u16, String, DnsQType, Vec<u8>)> {
    anyhow::ensure!(packet.len() >= 12, "short DNS query");
    let id = u16::from_be_bytes([packet[0], packet[1]]);
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    anyhow::ensure!(qdcount >= 1, "no DNS questions");
    let mut pos = 12usize;
    let mut labels = Vec::new();
    loop {
        anyhow::ensure!(pos < packet.len(), "truncated DNS name");
        let len = packet[pos] as usize;
        pos += 1;
        if len == 0 {
            break;
        }
        anyhow::ensure!((len & 0xC0) == 0, "DNS compression in query not supported");
        anyhow::ensure!(pos + len <= packet.len(), "truncated DNS label");
        labels.push(String::from_utf8_lossy(&packet[pos..pos + len]).to_ascii_lowercase());
        pos += len;
        anyhow::ensure!(labels.len() <= 64, "DNS name too long");
    }
    anyhow::ensure!(pos + 4 <= packet.len(), "truncated DNS question");
    let qtype = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
    // qclass at pos+2..+4 ignored
    let question_end = pos + 4;
    let qtype = match qtype {
        1 => DnsQType::A,
        28 => DnsQType::Aaaa,
        12 => DnsQType::Ptr,
        other => DnsQType::Other(other),
    };
    let name = labels.join(".");
    // keep original question bytes for response
    let question = packet[12..question_end.min(packet.len())].to_vec();
    let _ = id;
    Ok((id, name, qtype, question))
}

fn dns_response_header(id: u16, qdcount: u16, ancount: u16, rcode: u8) -> [u8; 12] {
    let flags: u16 = 0x8180 | (u16::from(rcode) & 0x000F); // QR,RD,RA
    let mut h = [0u8; 12];
    h[0..2].copy_from_slice(&id.to_be_bytes());
    h[2..4].copy_from_slice(&flags.to_be_bytes());
    h[4..6].copy_from_slice(&qdcount.to_be_bytes());
    h[6..8].copy_from_slice(&ancount.to_be_bytes());
    h
}

fn encode_dns_name(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() {
            continue;
        }
        let b = label.as_bytes();
        out.push(b.len().min(63) as u8);
        out.extend_from_slice(&b[..b.len().min(63)]);
    }
    out.push(0);
    out
}

async fn handle_dns(
    client: &Client,
    socket: &UdpSocket,
    peer: SocketAddr,
    packet: &[u8],
    prefs: &StreamPrefs,
) -> Result<()> {
    let (id, name, qtype, question) = match parse_dns_query_minimal(packet) {
        Ok(v) => v,
        Err(_) => return Ok(()),
    };
    let mut out = Vec::with_capacity(512);
    match qtype {
        DnsQType::A | DnsQType::Aaaa => {
            match client.resolve_with_prefs(&name, prefs).await {
                Ok(ips) => {
                    let ips: Vec<IpAddr> = ips;
                    let want_v4 = matches!(qtype, DnsQType::A);
                    let mut answers: Vec<IpAddr> = ips
                        .into_iter()
                        .filter(|ip| if want_v4 { ip.is_ipv4() } else { ip.is_ipv6() })
                        .collect();
                    answers.truncate(8);
                    out.extend_from_slice(&dns_response_header(id, 1, answers.len() as u16, 0));
                    out.extend_from_slice(&question);
                    let qtype_num: u16 = if want_v4 { 1 } else { 28 };
                    for ip in answers {
                        out.extend_from_slice(&[0xC0, 0x0C]); // pointer to question name
                        out.extend_from_slice(&qtype_num.to_be_bytes());
                        out.extend_from_slice(&1u16.to_be_bytes()); // IN
                        out.extend_from_slice(&60u32.to_be_bytes()); // TTL
                        match ip {
                            IpAddr::V4(v4) => {
                                out.extend_from_slice(&4u16.to_be_bytes());
                                out.extend_from_slice(&v4.octets());
                            }
                            IpAddr::V6(v6) => {
                                out.extend_from_slice(&16u16.to_be_bytes());
                                out.extend_from_slice(&v6.octets());
                            }
                        }
                    }
                }
                Err(_) => {
                    // NOERROR/NODATA-style for simplicity on resolve failure cases where appropriate?
                    // Use NXDOMAIN-ish behavior avoided; return SERVFAIL minimally.
                    out.extend_from_slice(&dns_response_header(id, 1, 0, 2));
                    out.extend_from_slice(&question);
                }
            }
        }
        DnsQType::Ptr => {
            // Best-effort PTR via resolve_ptr_with_prefs
            let addr = parse_arpa_name(&name);
            if let Some(addr) = addr {
                match client.resolve_ptr_with_prefs(addr, prefs).await {
                    Ok(names) => {
                        let mut answers: Vec<String> = names;
                        answers.truncate(4);
                        out.extend_from_slice(&dns_response_header(id, 1, answers.len() as u16, 0));
                        out.extend_from_slice(&question);
                        for host in answers {
                            let encoded = encode_dns_name(&host);
                            out.extend_from_slice(&[0xC0, 0x0C]);
                            out.extend_from_slice(&12u16.to_be_bytes()); // PTR
                            out.extend_from_slice(&1u16.to_be_bytes());
                            out.extend_from_slice(&60u32.to_be_bytes());
                            out.extend_from_slice(&(encoded.len() as u16).to_be_bytes());
                            out.extend_from_slice(&encoded);
                        }
                    }
                    Err(_) => {
                        out.extend_from_slice(&dns_response_header(id, 1, 0, 2));
                        out.extend_from_slice(&question);
                    }
                }
            } else {
                out.extend_from_slice(&dns_response_header(id, 1, 0, 1)); // FORMERR
                out.extend_from_slice(&question);
            }
        }
        DnsQType::Other(_) => {
            out.extend_from_slice(&dns_response_header(id, 1, 0, 4)); // NOTIMP
            out.extend_from_slice(&question);
        }
    }
    let _ = socket.send_to(&out, peer).await;
    Ok(())
}

fn parse_arpa_name(name: &str) -> Option<IpAddr> {
    let n = name.trim_end_matches('.');
    if let Some(rest) = n.strip_suffix(".in-addr.arpa") {
        let parts: Vec<&str> = rest.split('.').collect();
        if parts.len() == 4 {
            let o: Option<Vec<u8>> = parts.iter().rev().map(|p| p.parse().ok()).collect();
            let o = o?;
            return Some(IpAddr::V4(std::net::Ipv4Addr::new(o[0], o[1], o[2], o[3])));
        }
    }
    if let Some(rest) = n.strip_suffix(".ip6.arpa") {
        let nibbles: Vec<&str> = rest.split('.').collect();
        if nibbles.len() == 32 {
            let mut bytes = [0u8; 16];
            for (i, nib) in nibbles.iter().rev().enumerate() {
                let v = u8::from_str_radix(nib, 16).ok()?;
                if i % 2 == 0 {
                    bytes[i / 2] |= v;
                } else {
                    bytes[i / 2] |= v << 4;
                }
            }
            return Some(IpAddr::V6(std::net::Ipv6Addr::from(bytes)));
        }
    }
    None
}

async fn run_proxy(
    client: Client,
    addr: SocketAddr,
    stream_isolation: StreamIsolationPolicy,
    network_prefs: NetworkStreamPrefs,
) -> Result<()> {
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind proxy {addr}"))?;
    debug!(%addr, "custom proxy listening");
    loop {
        let (stream, peer) = listener.accept().await?;
        let client = client.clone();
        let np = network_prefs.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(stream, client, stream_isolation, np).await {
                debug!(%peer, error=%format!("{e:#}"), "proxy connection ended");
            }
        });
    }
}

async fn handle_conn(
    client_stream: TcpStream,
    client: Client,
    isolation: StreamIsolationPolicy,
    network: NetworkStreamPrefs,
) -> Result<()> {
    let mut first = [0u8; 1];
    let n = client_stream.peek(&mut first).await?;
    if n == 0 {
        return Ok(());
    }
    if first[0] == 0x04 || first[0] == 0x05 {
        handle_socks(client_stream, client, isolation, network).await
    } else {
        handle_http(client_stream, client, isolation, network).await
    }
}

async fn handle_socks(
    mut client_stream: TcpStream,
    client: Client,
    isolation: StreamIsolationPolicy,
    network: NetworkStreamPrefs,
) -> Result<()> {
    let mut hs = SocksProxyHandshake::new();
    let mut buf = vec![0u8; tor_socksproto::SOCKS_BUF_LEN];
    let mut filled = 0usize;
    let request = loop {
        if hs.finished() {
            break hs
                .into_request()
                .context("SOCKS finished without request")?;
        }
        if filled == buf.len() {
            buf.resize(buf.len() * 2, 0);
        }
        let n = client_stream.read(&mut buf[filled..]).await?;
        if n == 0 {
            anyhow::bail!("client closed during SOCKS handshake");
        }
        filled += n;
        let action = match hs.handshake(&buf[..filled]) {
            Ok(Ok(a)) => a,
            Ok(Err(e)) => return Err(anyhow::Error::new(e)).context("SOCKS handshake"),
            Err(_truncated) => continue,
        };
        if action.drain > 0 {
            let d = action.drain.min(filled);
            buf.copy_within(d..filled, 0);
            filled -= d;
        }
        if !action.reply.is_empty() {
            client_stream.write_all(&action.reply).await?;
            client_stream.flush().await?;
        }
        if action.finished {
            break hs
                .into_request()
                .context("SOCKS finished without request")?;
        }
    };
    let (dest, port) = target_of(&request)?;
    let auth = auth_bytes(request.auth());
    let prefs = prefs_for(
        &network,
        isolation,
        ClientProtocol::Socks,
        dest.clone(),
        port,
        auth,
    )?;
    match request.command() {
        SocksCmd::CONNECT => {
            let tor_addr = format!("{dest}:{port}");
            match client.connect_with_prefs(&tor_addr, &prefs).await {
                Ok(mut tor_stream) => {
                    let reply = request
                        .reply(SocksStatus::SUCCEEDED, None)
                        .context("encoding SOCKS reply")?;
                    client_stream.write_all(&reply).await?;
                    client_stream.flush().await?;
                    let mut client_compat = client_stream.compat();
                    let (mut cr, mut cw) = futures::AsyncReadExt::split(&mut client_compat);
                    let (mut tr, mut tw) = futures::AsyncReadExt::split(&mut tor_stream);
                    let c2t = futures::io::copy(&mut cr, &mut tw);
                    let t2c = futures::io::copy(&mut tr, &mut cw);
                    let _ = futures::future::select(Box::pin(c2t), Box::pin(t2c)).await;
                }
                Err(e) => {
                    if let Ok(reply) = request.reply(SocksStatus::GENERAL_FAILURE, None) {
                        let _ = client_stream.write_all(&reply).await;
                    }
                    return Err(anyhow::Error::new(e)).context("Tor connect failed");
                }
            }
        }
        SocksCmd::RESOLVE => match client.resolve_with_prefs(&dest, &prefs).await {
            Ok(ips) => {
                let ips: Vec<IpAddr> = ips;
                if let Some(ip) = ips.into_iter().next() {
                    let addr = tor_socksproto::SocksAddr::Ip(ip);
                    if let Ok(reply) = request.reply(SocksStatus::SUCCEEDED, Some(&addr)) {
                        let _ = client_stream.write_all(&reply).await;
                    }
                } else if let Ok(reply) = request.reply(SocksStatus::HOST_UNREACHABLE, None) {
                    let _ = client_stream.write_all(&reply).await;
                }
            }
            Err(_) => {
                if let Ok(reply) = request.reply(SocksStatus::HOST_UNREACHABLE, None) {
                    let _ = client_stream.write_all(&reply).await;
                }
            }
        },
        SocksCmd::RESOLVE_PTR => {
            let addr: IpAddr = dest.parse().context("RESOLVE_PTR needs IP")?;
            match client.resolve_ptr_with_prefs(addr, &prefs).await {
                Ok(names) => {
                    // Best-effort: callers needing PTR hostnames should use DNS.
                    let _ = names;
                    if let Ok(reply) = request.reply(SocksStatus::SUCCEEDED, None) {
                        let _ = client_stream.write_all(&reply).await;
                    }
                }
                Err(_) => {
                    if let Ok(reply) = request.reply(SocksStatus::HOST_UNREACHABLE, None) {
                        let _ = client_stream.write_all(&reply).await;
                    }
                }
            }
        }
        _ => {
            if let Ok(reply) = request.reply(SocksStatus::COMMAND_NOT_SUPPORTED, None) {
                let _ = client_stream.write_all(&reply).await;
            }
            anyhow::bail!("unsupported SOCKS command")
        }
    }
    Ok(())
}

async fn handle_http(
    mut client_stream: TcpStream,
    client: Client,
    isolation: StreamIsolationPolicy,
    network: NetworkStreamPrefs,
) -> Result<()> {
    let mut buf = vec![0u8; 16384];
    let mut filled = 0usize;
    let end = loop {
        if filled == buf.len() {
            anyhow::bail!("HTTP headers too large");
        }
        let n = client_stream.read(&mut buf[filled..]).await?;
        if n == 0 {
            anyhow::bail!("client closed");
        }
        filled += n;
        if let Some(p) = buf[..filled].windows(4).position(|w| w == b"\r\n\r\n") {
            break p + 4;
        }
    };
    let head = String::from_utf8_lossy(&buf[..end]).into_owned();
    let mut lines = head.lines();
    let req = lines.next().unwrap_or("");
    let mut parts = req.split_whitespace();
    let method = parts.next().unwrap_or("");
    let authority = parts.next().unwrap_or("");
    if !method.eq_ignore_ascii_case("CONNECT") {
        client_stream
            .write_all(b"HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n")
            .await?;
        return Ok(());
    }
    let (host, port) = parse_authority(authority)?;
    let existing_iso = lines.find_map(|line| {
        let (k, v) = line.split_once(':')?;
        let k = k.trim();
        if k.eq_ignore_ascii_case("Tor-Stream-Isolation")
            || k.eq_ignore_ascii_case("X-Tor-Stream-Isolation")
        {
            Some(v.trim().to_string())
        } else {
            None
        }
    });
    let prefs = prefs_for(
        &network,
        isolation,
        ClientProtocol::HttpConnect,
        host.clone(),
        port,
        existing_iso.unwrap_or_default().into_bytes(),
    )?;
    match client
        .connect_with_prefs(&format!("{host}:{port}"), &prefs)
        .await
    {
        Ok(mut tor_stream) => {
            client_stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await?;
            client_stream.flush().await?;
            if filled > end {
                FuturesAsyncWriteExt::write_all(&mut tor_stream, &buf[end..filled]).await?;
            }
            let (mut cr, mut cw) = client_stream.compat().split();
            let mut tor_stream = tor_stream;
            let (mut tr, mut tw) = futures::AsyncReadExt::split(&mut tor_stream);
            let c2t = futures::io::copy(&mut cr, &mut tw);
            let t2c = futures::io::copy(&mut tr, &mut cw);
            let _ = futures::future::select(Box::pin(c2t), Box::pin(t2c)).await;
        }
        Err(e) => {
            let _ = client_stream
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
                .await;
            return Err(anyhow::Error::new(e)).context("Tor connect failed");
        }
    }
    Ok(())
}

fn target_of(request: &SocksRequest) -> Result<(String, u16)> {
    let host = match request.addr() {
        tor_socksproto::SocksAddr::Ip(std::net::IpAddr::V4(v4)) => v4.to_string(),
        tor_socksproto::SocksAddr::Ip(std::net::IpAddr::V6(v6)) => v6.to_string(),
        tor_socksproto::SocksAddr::Hostname(name) => name.as_ref().to_string(),
        #[allow(unreachable_patterns)]
        other => anyhow::bail!("unsupported SOCKS addr {other:?}"),
    };
    Ok((host, request.port()))
}

fn auth_bytes(auth: &SocksAuth) -> Vec<u8> {
    match auth {
        SocksAuth::NoAuth => Vec::new(),
        SocksAuth::Socks4(id) => id.clone(),
        SocksAuth::Username(u, p) => {
            let mut v = u.clone();
            v.push(0);
            v.extend_from_slice(p);
            v
        }
        _ => Vec::new(),
    }
}

fn parse_authority(authority: &str) -> Result<(String, u16)> {
    if let Some(rest) = authority.strip_prefix('[') {
        let (h, p) = rest.split_once("]:").context("bad IPv6 authority")?;
        return Ok((h.to_string(), p.parse()?));
    }
    let (h, p) = authority
        .rsplit_once(':')
        .context("authority missing port")?;
    Ok((h.to_string(), p.parse()?))
}
