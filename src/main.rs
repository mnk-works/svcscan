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
#[command(name = "svcscan", about = "🔎 Scan all TCP ports + grab banners/HTTP info from a host list")]
struct Args {
    /// Input .txt file with hosts/URLs/IPs (one per line)
    input: PathBuf,
    /// Output file (default: result_<unix_timestamp>.txt)
    output: Option<PathBuf>,
    /// Verbose/debug logs to stderr
    #[arg(short, long)]
    verbose: bool,
    /// Max concurrent port probes
    #[arg(long, default_value_t = 500)]
    concurrency: usize,
    /// Connect/read timeout in milliseconds
    #[arg(long, default_value_t = 1200)]
    timeout_ms: u64,
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

fn unix_ts() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

fn vlog(v: bool, msg: impl AsRef<str>) {
    if v {
        eprintln!("🛠️  {}", msg.as_ref());
    }
}

fn sanitize(s: &str, max: usize) -> String {
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

fn parse_input_line(line: &str) -> Option<(String, String, Option<u16>)> {
    let s = line.trim();
    if s.is_empty() || s.starts_with('#') { return None; }
    let original = s.to_string();
    // try URL
    if let Ok(u) = url::Url::parse(s) {
        if let Some(h) = u.host_str() {
            return Some((original, h.to_string(), u.port_or_known_default().or(u.port())));
        }
    }
    // host:port or bare
    if let Some(rest) = s.strip_prefix('[') { // [::1]:port (minimal)
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
        let host_for_lookup = if host.parse::<IpAddr>().is_ok() { format!("{}:0", host) } else { format!("{}:0", host) };
        let ip = match host.parse::<IpAddr>() {
            Ok(ip) => ip,
            Err(_) => {
                let addrs = tokio::task::spawn_blocking(move || host_for_lookup.to_socket_addrs()).await??;
                match addrs.filter_map(|sa: SocketAddr| Some(sa.ip())).find(|ip| ip.is_ipv4()).or_else(|| {
                    let host_for_lookup2 = format!("{}:0", host);
                    host_for_lookup2.to_socket_addrs().ok().and_then(|mut a| a.next().map(|s| s.ip()))
                }) {
                    Some(ip) => ip,
                    None => { vlog(verbose, format!("⚠️  skip unresolved host: {}", host)); continue; }
                }
            }
        };
        if seen.insert(ip) {
            out.push(Target { original, host, ip, _hint_port: hint_port });
        } else {
            vlog(verbose, format!("↪️  dupe ip {} (from {})", ip, original));
        }
    }
    Ok(out)
}

async fn grab_banner(addr: SocketAddr, to: Duration) -> String {
    let mut s = match timeout(to, TcpStream::connect(addr)).await { Ok(Ok(s)) => s, _ => return String::new() };
    let _ = timeout(Duration::from_millis(to.as_millis().min(400) as u64), s.write_all(b"\r\n")).await;
    let mut buf = vec![0u8; 512];
    match timeout(Duration::from_millis(to.as_millis().min(500) as u64), s.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => sanitize(&String::from_utf8_lossy(&buf[..n]), 220),
        _ => String::new(),
    }
}

async fn grab_http(ip: IpAddr, port: u16, to: Duration) -> Option<HttpInfo> {
    let client = reqwest::Client::builder()
        .timeout(to)
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::limited(3))
        .build().ok()?;
    let schemes = if matches!(port, 443|8443|4443|9443|10443|6443) { ["https","http"] } else { ["http","https"] };
    for scheme in schemes {
        let host = match ip { IpAddr::V6(v6) => format!("[{}]", v6), IpAddr::V4(v4) => v4.to_string() };
        let url = format!("{}://{}:{}/", scheme, host, port);
        let resp = match client.get(&url).header("User-Agent", "svcscan/0.1").send().await {
            Ok(r) => r,
            Err(_) => continue,
        };
        let status = format!("{}", resp.status());
        let server = resp.headers().get("server").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
        let mut hdrs = Vec::new();
        for (k, v) in resp.headers().iter().take(8) {
            if let Ok(val) = v.to_str() { hdrs.push(format!("{}: {}", k.as_str(), sanitize(val, 80))); }
        }
        let body = resp.bytes().await.unwrap_or_default();
        let body_excerpt = sanitize(&String::from_utf8_lossy(&body[..body.len().min(300)]), 300);
        return Some(HttpInfo { status, server: sanitize(&server, 120), headers: sanitize(&hdrs.join(" | "), 400), body_excerpt });
    }
    None
}

async fn scan_port(ip: IpAddr, port: u16, to: Duration) -> Option<PortFinding> {
    let addr = SocketAddr::new(ip, port);
    if timeout(to, TcpStream::connect(addr)).await.ok()?.is_err() { return None; }
    let banner = grab_banner(addr, to).await;
    let http = grab_http(ip, port, to).await;
    Some(PortFinding { port, banner, http })
}

async fn scan_host(target: &Target, args: &Args) -> Vec<PortFinding> {
    let sem = Arc::new(Semaphore::new(args.concurrency));
    let to = Duration::from_millis(args.timeout_ms);
    let mut tasks = stream::iter(1u16..=65535u16).map(|port| {
        let sem = sem.clone();
        let ip = target.ip;
        async move {
            let _p = sem.acquire_owned().await.ok()?;
            scan_port(ip, port, to).await
        }
    }).buffer_unordered(args.concurrency);
    let mut found = Vec::new();
    while let Some(res) = tasks.next().await {
        if let Some(f) = res { found.push(f); }
    }
    found.sort_by_key(|f| f.port);
    found
}

fn format_host_result(t: &Target, findings: &[PortFinding]) -> String {
    let mut s = String::new();
    s.push_str(&format!("\n=== 🔎 HOST {} ({}) original={} ===\n", t.ip, t.host, t.original));
    if findings.is_empty() {
        s.push_str("  (no open TCP ports found)\n");
        return s;
    }
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
    let out = args.output.clone().unwrap_or_else(|| PathBuf::from(format!("result_{}.txt", unix_ts())));
    let targets = resolve_targets(&args.input, args.verbose).await?;
    if targets.is_empty() { anyhow::bail!("no targets resolved from {}", args.input.display()); }

    let file_lock = Arc::new(Mutex::new(()));
    let start = unix_ts();
    let header = format!("🔎 svcscan results | start={} | targets={} | concurrency={} | timeout_ms={}ms | input={}\n{}\n",
        start, targets.len(), args.concurrency, args.timeout_ms, args.input.display(), "=".repeat(72));
    tokio::fs::write(&out, &header).await?;
    eprintln!("🚀 svcscan: {} targets → {} (append mode)", targets.len(), out.display());

    let pb = ProgressBar::new(targets.len() as u64);
    pb.set_style(ProgressStyle::with_template("⏳ {spinner} [{bar:30.cyan/blue}] {pos}/{len} hosts | {msg}").unwrap().tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"));
    pb.enable_steady_tick(Duration::from_millis(120));

    let mut total_open: usize = 0;
    let mut host_open: BTreeMap<String, usize> = BTreeMap::new();
    for (i, t) in targets.iter().enumerate() {
        pb.set_message(format!("scanning {} (all 65535 TCP)", t.ip));
        vlog(args.verbose, format!("▶️  [{}/{}] {}", i+1, targets.len(), t.ip));
        let findings = scan_host(t, &args).await;
        total_open += findings.len();
        host_open.insert(t.ip.to_string(), findings.len());
        let block = format_host_result(t, &findings);
        append_file(&out, &file_lock, &block).await?;
        let mark = if findings.is_empty() { "⚠️" } else { "✅" };
        pb.println(format!("{} {} → {} open port(s) (appended)", mark, t.ip, findings.len()));
        pb.inc(1);
    }
    let end = unix_ts();
    let mut summary = format!("\n{}\n📊 SUMMARY | end={} | duration={}s | targets={} | total_open_ports={}\n",
        "=".repeat(72), end, end.saturating_sub(start), targets.len(), total_open);
    for (ip, n) in &host_open { summary.push_str(&format!("  - {}: {} open\n", ip, n)); }
    summary.push_str(&format!("📄 output: {}\n", out.display()));
    append_file(&out, &file_lock, &summary).await?;
    pb.finish_with_message("done");
    eprintln!("{}", summary);
    Ok(())
}
