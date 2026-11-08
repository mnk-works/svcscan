//! svcscan — reliable async TCP port scanner + banner/HTTP grabber.
//!
//! Scans all 65,535 TCP ports per host (no external scanner binaries), grabs banners and
//! HTTP(S) metadata (TLS certs ignored), and writes navigable, append-safe results.
//! Defaults are auto-tuned (ulimit-aware concurrency, 800ms timeout, 1 retry on timeout).

mod cli;
mod config;
mod input;
mod output;
mod probe;
mod scan;

use anyhow::Result;
use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

use cli::Args;
use config::{tune_ulimit_and_concurrency, ScanCfg};
use input::{resolve_targets, vlog};
use output::{append_file, format_host_result};
use scan::scan_host;

fn unix_ts() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Smart defaults: ulimit-aware concurrency, 800ms timeout, 1 retry on timeout only.
    let (concurrency, _nofile, ulimit_note) = tune_ulimit_and_concurrency(args.concurrency);
    let timeout_ms = args.timeout_ms.unwrap_or(800);
    let retries = args.retries.unwrap_or(1);
    let cfg = ScanCfg { concurrency, timeout: Duration::from_millis(timeout_ms), retries, verbose: args.verbose };

    let out = args.output.clone().unwrap_or_else(|| PathBuf::from(format!("result_{}.txt", unix_ts())));
    let targets = resolve_targets(&args.input, args.verbose).await?;
    if targets.is_empty() { anyhow::bail!("no targets resolved from {}", args.input.display()); }

    // Shared HTTP client (TLS cert validation disabled; errors never fail the scan).
    let http = reqwest::Client::builder()
        .timeout(cfg.timeout)
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::limited(2))
        .pool_max_idle_per_host(cfg.concurrency.min(64))
        .user_agent(concat!("svcscan/", env!("CARGO_PKG_VERSION")))
        .build()?;

    let file_lock = Arc::new(Mutex::new(()));
    let start_wall = unix_ts();
    let start = Instant::now();
    let header = format!(
        "🔎 svcscan v{} results | start={} | targets={} | concurrency={} | timeout_ms={} | retries={} | {}\ninput={}\n{}\n",
        env!("CARGO_PKG_VERSION"), start_wall, targets.len(), cfg.concurrency, timeout_ms, retries, ulimit_note, args.input.display(), "=".repeat(72)
    );
    tokio::fs::write(&out, &header).await?;
    eprintln!("🚀 svcscan v{}: {} targets → {} (append) | c={} t={}ms r={} | {}", env!("CARGO_PKG_VERSION"), targets.len(), out.display(), cfg.concurrency, timeout_ms, retries, ulimit_note);

    let pb = ProgressBar::new(targets.len() as u64);
    pb.set_style(ProgressStyle::with_template("⏳ {spinner} [{bar:30.cyan/blue}] {pos}/{len} hosts | {msg}").unwrap().tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"));
    pb.enable_steady_tick(Duration::from_millis(120));

    let mut total_open: usize = 0;
    let mut host_open: BTreeMap<String, (usize, u128)> = BTreeMap::new();
    for (i, t) in targets.iter().enumerate() {
        pb.set_message(format!("scanning {} (all 65535 TCP)", t.ip));
        vlog(cfg.verbose, format!("▶️  [{}/{}] {}", i + 1, targets.len(), t.ip));
        let hstart = Instant::now();
        let findings = scan_host(t, &cfg, &http).await;
        let h_ms = hstart.elapsed().as_millis();
        total_open += findings.len();
        host_open.insert(t.ip.to_string(), (findings.len(), h_ms));
        append_file(&out, &file_lock, &format_host_result(t, &findings, h_ms)).await?;
        let mark = if findings.is_empty() { "⚠️" } else { "✅" };
        let rate = if h_ms > 0 { (65535.0 / (h_ms as f64 / 1000.0)) as u64 } else { 0 };
        pb.println(format!("{} {} → {} open (⏱️ {:.1}s, ~{} ports/s)", mark, t.ip, findings.len(), h_ms as f64 / 1000.0, rate));
        pb.inc(1);
    }

    let dur = start.elapsed();
    let dur_s = dur.as_secs_f64().max(0.001);
    let total_slots = 65535u64.saturating_mul(targets.len() as u64);
    let overall_rate = (total_slots as f64 / dur_s) as u64;
    let end_wall = unix_ts();
    let mut summary = format!(
        "\n{}\n📊 SUMMARY | end={} | duration={:.1}s | targets={} | total_open_ports={} | c={} t={}ms r={} | ⚡ ~{} ports/s (65535×hosts/duration)\n",
        "=".repeat(72), end_wall, dur_s, targets.len(), total_open, cfg.concurrency, timeout_ms, retries, overall_rate
    );
    for (ip, (n, ms)) in &host_open { summary.push_str(&format!("  - {}: {} open (⏱️ {:.1}s)\n", ip, n, *ms as f64 / 1000.0)); }
    summary.push_str(&format!("📄 output: {}\n", out.display()));
    summary.push_str("ℹ️  rate is an effective throughput (all 65,535 ports per host attempted; refused=fast, timeout=slow).\n");
    append_file(&out, &file_lock, &summary).await?;
    pb.finish_with_message("done");
    eprintln!("{}", summary);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::input::parse_input_line;
    use super::probe::sanitize;
    use super::config::tune_ulimit_and_concurrency;

    #[test]
    fn parse_url_line() {
        let (o, h, p) = parse_input_line("http://203.0.113.10:7777/").unwrap();
        assert_eq!(o, "http://203.0.113.10:7777/");
        assert_eq!(h, "203.0.113.10");
        assert_eq!(p, Some(7777));
        let (_, hd, pd) = parse_input_line("https://example.com/path").unwrap();
        assert_eq!(hd, "example.com");
        assert_eq!(pd, Some(443));
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
