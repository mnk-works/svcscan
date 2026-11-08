use anyhow::{Context, Result};
use clap::Parser;
use futures::stream::{self, StreamExt};
use indicatif::{ProgressBar, ProgressStyle};
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::fs::OpenOptions;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, Semaphore};
use tokio::time::timeout;

#[derive(Parser, Debug, Clone)]
#[command(name = "svcscan", about = "🔎 Reliable async TCP port scan + banner/HTTP grab (all 65535). No external deps.", version)]
struct Args {
    /// Input .txt file with hosts/URLs/IPs (one per line)
    input: PathBuf,
    /// Output file (default: result_<unix_timestamp>.txt)
    output: Option<PathBuf>,
    /// Verbose/debug logs to stderr
    #[arg(short, long)]
    verbose: bool,
    /// Max concurrent probes (default: auto from ulimit)
    #[arg(long)]
    concurrency: Option<usize>,
    /// Connect/read timeout in milliseconds (default: 800, auto-reliable)
    #[arg(long)]
    timeout_ms: Option<u64>,
    /// Retries per port on connect timeout (default: 1; refused ports are not retried)
    #[arg(long)]
    retries: Option<u32>,
}

#[derive(Clone, Debug)]
struct Target {
    original: String,
    host: String,
    ip: IpAddr,
    _hint_port: Option<u16>,
}
#[derive(Clone, Debug)]
struct PortFinding {
    port: u16,
    banner: String,
    http: Option<HttpInfo>,
}
#[derive(Clone, Debug)]
struct HttpInfo {
    status: String,
    server: String,
    headers: String,
    body_excerpt: String,
}
#[derive(Clone, Debug)]
struct ScanCfg {
    concurrency: usize,
    timeout: Duration,
    retries: u32,
    verbose: bool,
}

fn unix_ts() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}
fn vlog(v: bool, msg: impl AsRef<str>) { if v { eprintln!("🛠️  {}", msg.as_ref()); } }

fn sanitize(s: &str, max: usize) -> String {
    let mut out = String::with_capacity(s.len().min(max));
    for c in s.chars().take(max) {
        match c { '\n' | '\r' | '\t' => out.push(' '), c if c.is_control() => out.push('�'), c => out.push(c) }
    }
    let t = out.trim().to_string();
    if s.chars().count() > max { format!("{}…", t) } else { t }
}

fn tune_ulimit_and_concurrency(requested: Option<usize>) -> (usize, u64, String) {
    let mut note = String::new();
    let (soft, hard) = rlimit::Resource::NOFILE.get().unwrap_or((1024, 1024));
    // try to raise soft limit to hard (helps; often possible as root)
    if soft < hard {
        let _ = rlimit::Resource::NOFILE.set(hard, hard);
    }
    let (soft2, hard2) = rlimit::Resource::NOFILE.get().unwrap_or((soft, hard));
    let auto = ((soft2 as usize).saturating_sub(128)).clamp(512, 4000);
    let c = requested.unwrap_or(auto).clamp(64, 10_000);
    let c = c.min((soft2 as usize).saturating_sub(64).max(64));
    note.push_str(&format!("nofile soft/hard={}/{} -> concurrency={}", soft2, hard2, c));
    (c, soft2, note)
}

fn parse_input_line(line: &str) -> Option<(String, String, Option<u16>)> {
    let s = line.trim();
    if s.is_empty() || s.starts_with('#') { return None; }
    let original = s.to_string();
    if let Ok(u) = url::Url::parse(s) {
        if let Some(h) = u.host_str() {
            return Some((original, h.to_string(), u.port_or_known_default().or(u.port())));
        }
    }
    if let Some(rest) = s.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            let host = rest[..end].to_string();
            let port = rest[end+1..].strip_prefix(':').and_then(|p| p.split('/').next()).and_then(|p| p.parse().ok());
            return Some((original, host, port));
        }
    }
    let mut parts = s.rsplitn(2, ':');
    let tail = parts.next().unwrap_or(s);
    let head = parts.next();
    if let (Some(h), Ok(p)) = (head, tail.split('/').next().unwrap_or(tail).parse::<u16>()) {
        if !h.is_empty() && !h.contains('/') { return Some((original, h.to_string(), Some(p))); }
    }
    Some((original, s.split('/').next().unwrap_or(s).to_string(), None))
}

async fn resolve_targets(path: &Path, verbose: bool) -> Result<Vec<Target>> {
    let text = tokio::fs::read_to_string(path).await.with_context(|| format!("read {}", path.display()))?;
    let mut out = Vec::new();
    let mut seen: BTreeSet<IpAddr> = BTreeSet::new();
    for line in text.lines() {
        let Some((original, host, hint_port)) = parse_input_line(line) else { continue };
        let ip = if let Ok(ip) = host.parse::<IpAddr>() { ip } else {
            let h = host.clone();
            let addrs = tokio::task::spawn_blocking(move || format!("{}:0", h).to_socket_addrs()).await??;
            match addrs.map(|sa| sa.ip()).find(|ip| ip.is_ipv4()).or_else(|| {
                format!("{}:0", host).to_socket_addrs().ok().and_then(|mut a| a.next().map(|s| s.ip()))
            }) { Some(ip) => ip, None => { vlog(verbose, format!("⚠️  skip unresolved host: {}", host)); continue; } }
        };
        if seen.insert(ip) { out.push(Target { original, host, ip, _hint_port: hint_port }); }
        else { vlog(verbose, format!("↪️  dupe ip {} (from {})", ip, original)); }
    }
    Ok(out)
}

async fn read_banner(stream: &mut TcpStream, to: Duration) -> String {
    let _ = timeout(Duration::from_millis(to.as_millis().min(350) as u64), stream.write_all(b"\r\n")).await;
    let mut buf = vec![0u8; 512];
    match timeout(Duration::from_millis(to.as_millis().min(450) as u64), stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => sanitize(&String::from_utf8_lossy(&buf[..n]), 220),
        _ => String::new(),
    }
}

async fn grab_http(client: &reqwest::Client, ip: IpAddr, port: u16, to: Duration) -> Option<HttpInfo> {
    let schemes = if matches!(port, 443|8443|4443|9443|10443|6443) { ["https","http"] } else { ["http","https"] };
    for scheme in schemes {
        let host = match ip { IpAddr::V6(v6) => format!("[{}]", v6), IpAddr::V4(v4) => v4.to_string() };
        let url = format!("{}://{}:{}/", scheme, host, port);
        let resp = match timeout(to, client.get(&url).header("User-Agent", "svcscan/0.1.1").send()).await {
            Ok(Ok(r)) => r, _ => continue,
        };
        let status = format!("{}", resp.status());
        let server = resp.headers().get("server").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
        let mut hdrs = Vec::new();
        for (k, v) in resp.headers().iter().take(8) {
            if let Ok(val) = v.to_str() { hdrs.push(format!("{}: {}", k.as_str(), sanitize(val, 80))); }
        }
        let body = timeout(to, resp.bytes()).await.ok().and_then(|r| r.ok()).unwrap_or_default();
        let body_excerpt = sanitize(&String::from_utf8_lossy(&body[..body.len().min(300)]), 300);
        return Some(HttpInfo { status, server: sanitize(&server, 120), headers: sanitize(&hdrs.join(" | "), 400), body_excerpt });
    }
    None
}

async fn scan_port(ip: IpAddr, port: u16, cfg: &ScanCfg, http: &reqwest::Client) -> Option<PortFinding> {
    let addr = SocketAddr::new(ip, port);
    let attempts = cfg.retries.saturating_add(1);
    for attempt in 0..attempts {
        let t = if attempt == 0 { cfg.timeout } else { cfg.timeout.saturating_mul(2).min(Duration::from_millis(2500)) };
        match timeout(t, TcpStream::connect(addr)).await {
            Ok(Ok(mut stream)) => {
                let banner = read_banner(&mut stream, cfg.timeout).await;
                drop(stream);
                let http_info = grab_http(http, ip, port, cfg.timeout).await;
                return Some(PortFinding { port, banner, http: http_info });
            }
            Ok(Err(_)) => { /* refused/reset - no retry helps */ return None; }
            Err(_) => { /* timeout - retry */ }
        }
    }
    None
}

async fn scan_host(target: &Target, cfg: &ScanCfg, http: &reqwest::Client) -> Vec<PortFinding> {
    let sem = Arc::new(Semaphore::new(cfg.concurrency));
    let mut tasks = stream::iter(1u16..=65535u16).map(|port| {
        let sem = sem.clone();
        let ip = target.ip;
        let cfg = cfg.clone();
        let http = http.clone();
        async move {
            let _p = sem.acquire_owned().await.ok()?;
            scan_port(ip, port, &cfg, &http).await
        }
    }).buffer_unordered(cfg.concurrency);
    let mut found = Vec::new();
    while let Some(res) = tasks.next().await { if let Some(f) = res { found.push(f); } }
    found.sort_by_key(|f| f.port);
    found
}

fn format_host_result(t: &Target, findings: &[PortFinding]) -> String {
    let mut s = String::new();
    s.push_str(&format!("\n=== 🔎 HOST {} ({}) original={} ===\n", t.ip, t.host, t.original));
    if findings.is_empty() { s.push_str("  (no open TCP ports found)\n"); return s; }
    s.push_str(&format!("  ✅ open ports: {}\n", findings.len()));
    for f in findings {
        s.push_str(&format!("  - {}/tcp open", f.port));
        if !f.banner.is_empty() { s.push_str(&format!(" | banner: {}", f.banner)); }
        if let Some(h) = &f.http {
            s.push_str(&format!(" | http: {}", h.status));
            if !h.server.is_empty() { s.push_str(&format!(" | server: {}", h.server)); }
            if !h.headers.is_empty() { s.push_str(&format!(" | headers: {}", h.headers)); }
            if !h.body_excerpt.is_empty() { s.push_str(&format!(" | body: {}", h.body_excerpt)); }
        }
        s.push('\n');
    }
    s
}

async fn append_file(path: &Path, lock: &Arc<Mutex<()>>, text: &str) -> Result<()> {
    let _g = lock.lock().await;
    let mut f = OpenOptions::new().create(true).append(true).open(path).await?;
    f.write_all(text.as_bytes()).await?;
    f.flush().await?;
    Ok(())
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let args = Args::parse();
    let (concurrency, _nofile, ulimit_note) = tune_ulimit_and_concurrency(args.concurrency);
    let timeout_ms = args.timeout_ms.unwrap_or(800);
    let retries = args.retries.unwrap_or(1);
    let cfg = ScanCfg { concurrency, timeout: Duration::from_millis(timeout_ms), retries, verbose: args.verbose };
    let out = args.output.clone().unwrap_or_else(|| PathBuf::from(format!("result_{}.txt", unix_ts())));
    let targets = resolve_targets(&args.input, args.verbose).await?;
    if targets.is_empty() { anyhow::bail!("no targets resolved from {}", args.input.display()); }

    let http = reqwest::Client::builder()
        .timeout(cfg.timeout)
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::limited(2))
        .pool_max_idle_per_host(cfg.concurrency.min(64))
        .build()?;
    let file_lock = Arc::new(Mutex::new(()));
    let start = unix_ts();
    let header = format!(
        "🔎 svcscan v{} results | start={} | targets={} | concurrency={} | timeout_ms={} | retries={} | {}\ninput={} \n{}\n",
        env!("CARGO_PKG_VERSION"), start, targets.len(), cfg.concurrency, timeout_ms, retries, ulimit_note, args.input.display(), "=".repeat(72)
    );
    tokio::fs::write(&out, &header).await?;
    eprintln!("🚀 svcscan v{}: {} targets → {} (append) | c={} t={}ms r={} | {}", env!("CARGO_PKG_VERSION"), targets.len(), out.display(), cfg.concurrency, timeout_ms, retries, ulimit_note);

    let pb = ProgressBar::new(targets.len() as u64);
    pb.set_style(ProgressStyle::with_template("⏳ {spinner} [{bar:30.cyan/blue}] {pos}/{len} hosts | {msg}").unwrap().tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"));
    pb.enable_steady_tick(Duration::from_millis(120));

    let mut total_open: usize = 0;
    let mut host_open: BTreeMap<String, usize> = BTreeMap::new();
    for (i, t) in targets.iter().enumerate() {
        pb.set_message(format!("scanning {} (all 65535 TCP)", t.ip));
        vlog(cfg.verbose, format!("▶️  [{}/{}] {}", i+1, targets.len(), t.ip));
        let findings = scan_host(t, &cfg, &http).await;
        total_open += findings.len();
        host_open.insert(t.ip.to_string(), findings.len());
        append_file(&out, &file_lock, &format_host_result(t, &findings)).await?;
        let mark = if findings.is_empty() { "⚠️" } else { "✅" };
        pb.println(format!("{} {} → {} open port(s) (appended)", mark, t.ip, findings.len()));
        pb.inc(1);
    }
    let end = unix_ts();
    let mut summary = format!("\n{}\n📊 SUMMARY | end={} | duration={}s | targets={} | total_open_ports={} | c={} t={}ms r={}\n",
        "=".repeat(72), end, end.saturating_sub(start), targets.len(), total_open, cfg.concurrency, timeout_ms, retries);
    for (ip, n) in &host_open { summary.push_str(&format!("  - {}: {} open\n", ip, n)); }
    summary.push_str(&format!("📄 output: {}\n", out.display()));
    append_file(&out, &file_lock, &summary).await?;
    pb.finish_with_message("done");
    eprintln!("{}", summary);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_url_line() {
        let (o, h, p) = parse_input_line("http://203.0.113.10:7777/").unwrap();
        assert_eq!(o, "http://203.0.113.10:7777/");
        assert_eq!(h, "203.0.113.10");
        assert_eq!(p, Some(7777));
    }

    #[test]
    fn parse_host_port_and_bare() {
        let (_, h, p) = parse_input_line("example.com:8080").unwrap();
        assert_eq!(h, "example.com");
        assert_eq!(p, Some(8080));
        let (_, h2, p2) = parse_input_line("192.0.2.5").unwrap();
        assert_eq!(h2, "192.0.2.5");
        assert_eq!(p2, None);
    }

    #[test]
    fn parse_skips_comments_blanks() {
        assert!(parse_input_line("").is_none());
        assert!(parse_input_line("   # hi").is_none());
    }

    #[test]
    fn sanitize_truncates_and_cleans() {
        let s = sanitize("a\nb\tc", 10);
        assert!(s.contains("a b c"));
        let long = "x".repeat(50);
        let t = sanitize(&long, 10);
        assert!(t.ends_with('…'));
    }

    #[test]
    fn ulimit_tuning_caps_safely() {
        let (c, _, note) = tune_ulimit_and_concurrency(None);
        assert!(c >= 256);
        assert!(c <= 4000);
        assert!(note.contains("nofile"));
    }
}

