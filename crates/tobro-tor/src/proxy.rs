//! Isolation pre-proxy for F-42/F-43.
//!
//! When destination/port isolation flags are enabled, this front-end sits on the
//! user-facing SOCKS/HTTP port and forwards connections to a backend
//! `arti::run_proxy` listener, injecting an isolation token (via SOCKS
//! username/password or HTTP `Tor-Stream-Isolation`) so Arti's native
//! auth/header isolation separates streams as configured.
//!
//! This preserves `arti::run_proxy`'s proven SOCKS/HTTP/DNS implementation and
//! state-management model while adding configurable destination/port/protocol
//! isolation.

use std::net::{Ipv4Addr, SocketAddr};

use anyhow::Context as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tor_socksproto::{Handshake, SocksAuth, SocksCmd, SocksProxyHandshake, SocksRequest, SocksStatus, SocksVersion};
use tracing::{debug, warn};

use crate::adapter::StreamIsolationPolicy;
use crate::isolation::{ClientProtocol, StreamIsolationInput, TobroIsolationKey};

/// Run the isolation pre-proxy until `shutdown` resolves.
pub async fn run_isolation_frontend(
    policy: StreamIsolationPolicy,
    listen_addr: SocketAddr,
    backend_addr: SocketAddr,
    mut shutdown: oneshot::Receiver<()>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(listen_addr)
        .await
        .with_context(|| format!("could not bind isolation front-end at {listen_addr}"))?;
    debug!(%listen_addr, %backend_addr, ?policy, "isolation front-end listening");
    loop {
        tokio::select! {
            biased;
            _ = &mut shutdown => return Ok(()),
            accept = listener.accept() => {
                let (stream, peer) = match accept {
                    Ok(v) => v,
                    Err(err) => { warn!(%err, "isolation accept failed"); continue; }
                };
                tokio::spawn(async move {
                    if let Err(err) = handle(stream, peer, policy, backend_addr).await {
                        debug!(%peer, error = %format!("{err:#}"), "isolation connection ended");
                    }
                });
            }
        }
    }
}

async fn handle(
    client: TcpStream,
    _peer: SocketAddr,
    policy: StreamIsolationPolicy,
    backend: SocketAddr,
) -> anyhow::Result<()> {
    let mut first = [0u8; 1];
    let n = client.peek(&mut first).await?;
    if n == 0 {
        return Ok(());
    }
    if first[0] == 0x04 || first[0] == 0x05 {
        handle_socks(client, policy, backend).await
    } else {
        handle_http(client, policy, backend).await
    }
}

async fn handle_socks(
    mut client: TcpStream,
    policy: StreamIsolationPolicy,
    backend: SocketAddr,
) -> anyhow::Result<()> {
    let mut hs = SocksProxyHandshake::new();
    let mut buf = vec![0u8; tor_socksproto::SOCKS_BUF_LEN];
    let mut filled = 0usize;
    let request = loop {
        if hs.finished() {
            break hs.into_request().context("SOCKS finished without request")?;
        }
        if filled == buf.len() {
            buf.resize(buf.len() * 2, 0);
        }
        let n = client.read(&mut buf[filled..]).await?;
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
            client.write_all(&action.reply).await?;
            client.flush().await?;
        }
        if action.finished {
            break hs.into_request().context("SOCKS finished without request")?;
        }
    };

    if request.command() != SocksCmd::CONNECT {
        if let Ok(reply) = request.reply(SocksStatus::COMMAND_NOT_SUPPORTED, None) {
            let _ = client.write_all(&reply).await;
            let _ = client.flush().await;
        }
        anyhow::bail!("unsupported SOCKS command {:?}", request.command());
    }

    let (dest, port) = target_of(&request)?;
    let auth = auth_bytes(request.auth());
    let token = TobroIsolationKey::from_input(&StreamIsolationInput {
        policy,
        protocol: ClientProtocol::Socks,
        destination: dest.clone(),
        port,
        socks_auth: auth,
    })
    .to_token();

    let mut backend_stream = TcpStream::connect(backend)
        .await
        .context("could not connect to backend Tor proxy")?;
    if let Err(err) = socks5_backend_connect(&mut backend_stream, &dest, port, &token).await {
        if let Ok(reply) = request.reply(SocksStatus::GENERAL_FAILURE, None) {
            let _ = client.write_all(&reply).await;
            let _ = client.flush().await;
        }
        return Err(err).context("backend Tor proxy connect failed");
    }

    let reply = request
        .reply(SocksStatus::SUCCEEDED, None)
        .context("encoding SOCKS reply")?;
    client.write_all(&reply).await?;
    client.flush().await?;
    tokio::io::copy_bidirectional(&mut client, &mut backend_stream).await?;
    Ok(())
}

/* reply helpers removed: use SocksRequest::reply() */

async fn socks5_backend_connect(
    backend: &mut TcpStream,
    dest: &str,
    port: u16,
    isolation_token: &str,
) -> anyhow::Result<()> {
    // Method negotiation: offer username/password auth.
    backend.write_all(&[0x05, 0x01, 0x02]).await?;
    let mut method = [0u8; 2];
    backend.read_exact(&mut method).await?;
    anyhow::ensure!(method == [0x05, 0x02], "backend did not accept SOCKS5 username auth: {method:?}");
    // RFC 1929 username/password: ver=1, ulen, uname, plen, passwd.
    let uname = isolation_token.as_bytes();
    let uname = &uname[..uname.len().min(255)];
    let pass = b"t";
    let mut auth = Vec::with_capacity(3 + uname.len() + pass.len());
    auth.push(0x01);
    auth.push(uname.len() as u8);
    auth.extend_from_slice(uname);
    auth.push(pass.len() as u8);
    auth.extend_from_slice(pass);
    backend.write_all(&auth).await?;
    let mut auth_rep = [0u8; 2];
    backend.read_exact(&mut auth_rep).await?;
    anyhow::ensure!(auth_rep[1] == 0x00, "backend SOCKS auth rejected: {auth_rep:?}");

    // CONNECT request
    let dest_bytes = dest.as_bytes();
    anyhow::ensure!(dest_bytes.len() <= 255, "destination hostname too long");
    let mut req = Vec::with_capacity(7 + dest_bytes.len());
    req.extend_from_slice(&[0x05, 0x01, 0x00, 0x03, dest_bytes.len() as u8]);
    req.extend_from_slice(dest_bytes);
    req.extend_from_slice(&port.to_be_bytes());
    backend.write_all(&req).await?;
    backend.flush().await?;

    // Read reply
    let mut rep = [0u8; 4];
    backend.read_exact(&mut rep).await?;
    anyhow::ensure!(rep[0] == 0x05, "unexpected backend SOCKS version");
    anyhow::ensure!(rep[1] == 0x00, "backend SOCKS connect failed with status {}", rep[1]);
    drain_socks_addr(backend, rep[3]).await?;
    let mut bnd_port = [0u8; 2];
    backend.read_exact(&mut bnd_port).await?;
    Ok(())
}

async fn drain_socks_addr(stream: &mut TcpStream, atyp: u8) -> anyhow::Result<()> {
    match atyp {
        0x01 => { let mut a = [0u8; 4]; stream.read_exact(&mut a).await?; }
        0x03 => { let mut l = [0u8; 1]; stream.read_exact(&mut l).await?; let mut a = vec![0u8; l[0] as usize]; stream.read_exact(&mut a).await?; }
        0x04 => { let mut a = [0u8; 16]; stream.read_exact(&mut a).await?; }
        _ => anyhow::bail!("unsupported backend SOCKS ATYP {atyp}"),
    }
    Ok(())
}

fn target_of(request: &SocksRequest) -> anyhow::Result<(String, u16)> {
    let host = match request.addr() {
        tor_socksproto::SocksAddr::Ip(std::net::IpAddr::V4(v4)) => v4.to_string(),
        tor_socksproto::SocksAddr::Ip(std::net::IpAddr::V6(v6)) => format!("[{v6}]"),
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
        SocksAuth::Username(u, p) => { let mut v = u.clone(); v.push(0); v.extend_from_slice(p); v }
        _ => Vec::new(),
    }
}

async fn handle_http(
    mut client: TcpStream,
    policy: StreamIsolationPolicy,
    backend: SocketAddr,
) -> anyhow::Result<()> {
    let mut buf = vec![0u8; 16384];
    let mut filled = 0usize;
    let end = loop {
        if filled == buf.len() { anyhow::bail!("HTTP headers too large"); }
        let n = client.read(&mut buf[filled..]).await?;
        if n == 0 { anyhow::bail!("client closed"); }
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
    let version = parts.next().unwrap_or("HTTP/1.1");
    if !method.eq_ignore_ascii_case("CONNECT") {
        // For non-CONNECT HTTP methods, just forward as-is to backend (Arti handles HTTP CONNECT; plain HTTP proxying is limited)
        let mut backend_stream = TcpStream::connect(backend).await?;
        backend_stream.write_all(&buf[..filled]).await?;
        tokio::io::copy_bidirectional(&mut client, &mut backend_stream).await?;
        return Ok(());
    }
    let (host, port) = parse_authority(authority)?;
    let existing_iso = lines.clone().find_map(|line| {
        let (k, v) = line.split_once(':')?;
        let k = k.trim();
        if k.eq_ignore_ascii_case("Tor-Stream-Isolation") || k.eq_ignore_ascii_case("X-Tor-Stream-Isolation") {
            Some(v.trim().to_string())
        } else { None }
    });
    let token = TobroIsolationKey::from_input(&StreamIsolationInput {
        policy,
        protocol: ClientProtocol::HttpConnect,
        destination: host.clone(),
        port,
        socks_auth: existing_iso.unwrap_or_default().into_bytes(),
    }).to_token();

    // Rebuild request with Tor-Stream-Isolation header injected.
    let mut out = format!("{method} {authority} {version}\r\n");
    let mut wrote_iso = false;
    for line in head.lines().skip(1) {
        if line.is_empty() { break; }
        if let Some((k, _)) = line.split_once(':') {
            let kt = k.trim();
            if kt.eq_ignore_ascii_case("Tor-Stream-Isolation") || kt.eq_ignore_ascii_case("X-Tor-Stream-Isolation") {
                if !wrote_iso {
                    out.push_str(&format!("Tor-Stream-Isolation: {token}\r\n"));
                    wrote_iso = true;
                }
                continue;
            }
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    if !wrote_iso {
        out.push_str(&format!("Tor-Stream-Isolation: {token}\r\n"));
    }
    out.push_str("\r\n");

    let mut backend_stream = TcpStream::connect(backend).await.context("connect backend")?;
    backend_stream.write_all(out.as_bytes()).await?;
    // Forward any extra bytes read past headers
    if filled > end {
        backend_stream.write_all(&buf[end..filled]).await?;
    }
    backend_stream.flush().await?;
    tokio::io::copy_bidirectional(&mut client, &mut backend_stream).await?;
    Ok(())
}

fn parse_authority(authority: &str) -> anyhow::Result<(String, u16)> {
    if let Some(rest) = authority.strip_prefix('[') {
        let (h, p) = rest.split_once("]:").context("bad IPv6 authority")?;
        return Ok((h.to_string(), p.parse()?));
    }
    let (h, p) = authority.rsplit_once(':').context("authority missing port")?;
    Ok((h.to_string(), p.parse()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_host_port() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(parse_authority("example.com:443")?, ("example.com".into(), 443));
        assert_eq!(parse_authority("[::1]:9050")?, ("::1".into(), 9050));
        Ok(())
    }

    #[test]
    fn isolation_token_is_stable_and_distinct() {
        use crate::isolation::{ClientProtocol, StreamIsolationInput, TobroIsolationKey};
        let policy = StreamIsolationPolicy {
            isolate_destination: true,
            isolate_port: false,
            isolate_protocol: false,
            keep_alive_isolation: false,
        };
        let a = TobroIsolationKey::from_input(&StreamIsolationInput {
            policy,
            protocol: ClientProtocol::Socks,
            destination: "a.example".into(),
            port: 80,
            socks_auth: vec![],
        })
        .to_token();
        let b = TobroIsolationKey::from_input(&StreamIsolationInput {
            policy,
            protocol: ClientProtocol::Socks,
            destination: "b.example".into(),
            port: 80,
            socks_auth: vec![],
        })
        .to_token();
        assert_eq!(a, TobroIsolationKey::from_input(&StreamIsolationInput {
            policy,
            protocol: ClientProtocol::Socks,
            destination: "a.example".into(),
            port: 80,
            socks_auth: vec![],
        }).to_token());
        assert_ne!(a, b);
        assert!(a.starts_with("tobro-iso1:"));
    }
}