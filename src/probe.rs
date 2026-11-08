//! Banner grabbing and HTTP(S) probing.
//!
//! - Banner: read from the already-connected TCP stream (single connect) with short timeouts.
//! - HTTP(S): best-effort via reqwest; **TLS certificate validation is disabled** and any
//!   TLS/HTTP error is swallowed (never fails the scan). Body/headers are capped.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Clone, Debug)]
pub struct HttpInfo {
    /// `http` or `https` (which scheme succeeded)
    pub scheme: String,
    /// Full probed URL (kept for diagnostics; output shows scheme+status)
    pub _url: String,
    pub status: String,
    pub server: String,
    pub headers: String,
    pub body_excerpt: String,
}

pub fn sanitize(s: &str, max: usize) -> String {
    let mut out = String::with_capacity(s.len().min(max));
    for c in s.chars().take(max) {
        match c {
            '\n' | '\r' | '\t' => out.push(' '),
            c if c.is_control() => out.push('�'),
            c => out.push(c),
        }
    }
    let t = out.trim().to_string();
    if s.chars().count() > max { format!("{}…", t) } else { t }
}

/// Read an initial banner from an open stream.
/// 1) short read-first (catches immediate greetings like SMTP/SSH/MySQL/POP3),
/// 2) if empty, send a small probe and read again. All bounded by tight timeouts.
pub async fn read_banner(stream: &mut TcpStream, to: Duration) -> String {
    let cap = to.as_millis().min(450) as u64;
    let mut buf = vec![0u8; 512];
    // Read-first: many services greet on connect.
    if let Ok(Ok(n)) = timeout(Duration::from_millis(cap.min(220)), stream.read(&mut buf)).await {
        if n > 0 {
            return sanitize(&String::from_utf8_lossy(&buf[..n]), 220);
        }
    }
    // Probe then read for request-response protocols.
    let _ = timeout(Duration::from_millis(cap.min(300)), stream.write_all(b"\r\n")).await;
    let mut buf2 = vec![0u8; 512];
    match timeout(Duration::from_millis(cap), stream.read(&mut buf2)).await {
        Ok(Ok(n)) if n > 0 => sanitize(&String::from_utf8_lossy(&buf2[..n]), 220),
        _ => String::new(),
    }
}

/// Best-effort HTTP(S) probe. TLS certs ignored; all errors ignored.
pub async fn grab_http(client: &reqwest::Client, ip: IpAddr, port: u16, to: Duration) -> Option<HttpInfo> {
    let schemes = if matches!(port, 443 | 8443 | 4443 | 9443 | 10443 | 6443) { ["https", "http"] } else { ["http", "https"] };
    for scheme in schemes {
        let host = match ip { IpAddr::V6(v6) => format!("[{}]", v6), IpAddr::V4(v4) => v4.to_string() };
        let url = format!("{}://{}:{}/", scheme, host, port);
        let resp = match timeout(to, client.get(&url).header("User-Agent", concat!("svcscan/", env!("CARGO_PKG_VERSION"))).send()).await {
            Ok(Ok(r)) => r,
            _ => continue,
        };
        let status = format!("{}", resp.status());
        let server = resp.headers().get("server").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
        let mut hdrs = Vec::new();
        for (k, v) in resp.headers().iter().take(8) {
            if let Ok(val) = v.to_str() { hdrs.push(format!("{}: {}", k.as_str(), sanitize(val, 80))); }
        }
        let body = timeout(to, resp.bytes()).await.ok().and_then(|r| r.ok()).unwrap_or_default();
        let body_excerpt = sanitize(&String::from_utf8_lossy(&body[..body.len().min(300)]), 300);
        return Some(HttpInfo {
            scheme: scheme.to_string(),
            _url: url.clone(),
            status,
            server: sanitize(&server, 120),
            headers: sanitize(&hdrs.join(" | "), 400),
            body_excerpt,
        });
    }
    None
}

/// (unused helper kept for API clarity)
#[allow(dead_code)]
pub fn addr(ip: IpAddr, port: u16) -> SocketAddr { SocketAddr::new(ip, port) }
