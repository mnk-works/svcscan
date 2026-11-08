//! Async TCP connect scanner (all 65535 ports) with timeout + retry policy.
//!
//! # Design
//! - **Single connect per attempt**: on success we read the banner from that stream, then probe HTTP.
//! - **Refused (RST) = definitive**: return closed immediately (no retry).
//! - **Timeout = uncertain**: retry up to `cfg.retries` (catches slow-open ports under load).
//! - Filtered/drop hosts are inherently timeout-bound for connect scans; tune `timeout_ms`/`retries`.

use crate::config::ScanCfg;
use crate::input::Target;
use crate::probe::{grab_http, read_banner, HttpInfo};
use futures::stream::{self, StreamExt};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;

#[derive(Clone, Debug)]
pub struct PortFinding {
    pub port: u16,
    pub banner: String,
    pub http: Option<HttpInfo>,
}

async fn scan_port(ip: IpAddr, port: u16, cfg: &ScanCfg, http: &reqwest::Client) -> Option<PortFinding> {
    let addr = SocketAddr::new(ip, port);
    let attempts = cfg.retries.saturating_add(1);
    for attempt in 0..attempts {
        // Back off a bit on retry (helps when the first timeout was load-related).
        let t = if attempt == 0 { cfg.timeout } else { cfg.timeout.saturating_mul(2).min(std::time::Duration::from_millis(2500)) };
        match timeout(t, TcpStream::connect(addr)).await {
            Ok(Ok(mut stream)) => {
                let banner = read_banner(&mut stream, cfg.timeout).await;
                drop(stream);
                let http_info = grab_http(http, ip, port, cfg.timeout).await;
                return Some(PortFinding { port, banner, http: http_info });
            }
            Ok(Err(_e)) => {
                // Connection refused/reset -> definitive closed (fast path). No retry.
                return None;
            }
            Err(_elapsed) => {
                // Timeout -> uncertain (filtered, or slow under load). Retry if allowed.
            }
        }
    }
    None
}

/// Scan all TCP ports (1..=65535) for a target with bounded concurrency.
pub async fn scan_host(target: &Target, cfg: &ScanCfg, http: &reqwest::Client) -> Vec<PortFinding> {
    let sem = Arc::new(Semaphore::new(cfg.concurrency));
    let mut tasks = stream::iter(1u16..=65535u16)
        .map(|port| {
            let sem = sem.clone();
            let ip = target.ip;
            let cfg = cfg.clone();
            let http = http.clone();
            async move {
                let _permit = sem.acquire_owned().await.ok()?;
                scan_port(ip, port, &cfg, &http).await
            }
        })
        .buffer_unordered(cfg.concurrency);

    let mut found = Vec::new();
    while let Some(res) = tasks.next().await {
        if let Some(f) = res { found.push(f); }
    }
    found.sort_by_key(|f| f.port);
    found
}
