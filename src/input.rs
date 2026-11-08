//! Input parsing (hosts/URLs/IPs) and DNS resolution.

use anyhow::{Context, Result};
use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::path::Path;

#[derive(Clone, Debug)]
pub struct Target {
    pub original: String,
    pub host: String,
    pub ip: IpAddr,
    #[allow(dead_code)]
    pub hint_port: Option<u16>,
}

pub fn vlog(v: bool, msg: impl AsRef<str>) {
    if v {
        eprintln!("🛠️  {}", msg.as_ref());
    }
}

/// Parse a line into (original, host, optional_port_hint). Accepts URLs, host:port, [v6]:port, bare.
pub fn parse_input_line(line: &str) -> Option<(String, String, Option<u16>)> {
    let s = line.trim();
    if s.is_empty() || s.starts_with('#') {
        return None;
    }
    let original = s.to_string();
    if let Ok(u) = url::Url::parse(s) {
        if let Some(h) = u.host_str() {
            return Some((original, h.to_string(), u.port_or_known_default().or(u.port())));
        }
    }
    // [::1]:port
    if let Some(rest) = s.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            let host = rest[..end].to_string();
            let port = rest[end + 1..]
                .strip_prefix(':')
                .and_then(|p| p.split('/').next())
                .and_then(|p| p.parse().ok());
            return Some((original, host, port));
        }
    }
    // host:port
    let mut parts = s.rsplitn(2, ':');
    let tail = parts.next().unwrap_or(s);
    let head = parts.next();
    if let (Some(h), Ok(p)) = (head, tail.split('/').next().unwrap_or(tail).parse::<u16>()) {
        if !h.is_empty() && !h.contains('/') {
            return Some((original, h.to_string(), Some(p)));
        }
    }
    Some((original, s.split('/').next().unwrap_or(s).to_string(), None))
}

/// Resolve all targets from a file, de-duplicating by IP. Hostnames/domains are resolved via system DNS.
pub async fn resolve_targets(path: &Path, verbose: bool) -> Result<Vec<Target>> {
    let text = tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("read {}", path.display()))?;
    let mut out = Vec::new();
    let mut seen: BTreeSet<IpAddr> = BTreeSet::new();

    for line in text.lines() {
        let Some((original, host, hint_port)) = parse_input_line(line) else { continue };
        let ip = if let Ok(ip) = host.parse::<IpAddr>() {
            ip
        } else {
            let h = host.trim_end_matches('.').to_string();
            vlog(verbose, format!("🌐 resolving {}", h));
            let h2 = h.clone();
            let addrs = tokio::task::spawn_blocking(move || (h2.as_str(), 0u16).to_socket_addrs())
                .await??;
            match addrs
                .map(|sa: SocketAddr| sa.ip())
                .find(|ip| ip.is_ipv4())
                .or_else(|| (h.as_str(), 0u16).to_socket_addrs().ok().and_then(|mut a| a.next().map(|s| s.ip())))
            {
                Some(ip) => { vlog(verbose, format!("🌐 {} -> {}", h, ip)); ip }
                None => { vlog(verbose, format!("⚠️  skip unresolved host: {}", host)); continue; }
            }
        };
        if seen.insert(ip) {
            out.push(Target { original, host, ip, hint_port });
        } else {
            vlog(verbose, format!("↪️  dupe ip {} (from {})", ip, original));
        }
    }
    Ok(out)
}
