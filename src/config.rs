//! Runtime config and system tuning (ulimit/nofile -> concurrency).
//!
//! # Tuning notes
//! - TCP `connect()` scanning is accurate but **timeout-bound** on filtered/drop hosts.
//! - `concurrency` is capped by `ulimit -n` (open FDs/sockets). We read RLIMIT_NOFILE and
//!   try to raise the soft limit to the hard limit (often allowed as root) for throughput.
//! - `retries` apply **only to timeouts**. A refused connection (RST) is definitive and fast,
//!   so retrying it wastes nothing and we skip it. This follows the same principle as RustScan.

use std::time::Duration;

#[derive(Clone, Debug)]
pub struct ScanCfg {
    pub concurrency: usize,
    pub timeout: Duration,
    pub retries: u32,
    pub verbose: bool,
}

/// Detect ulimit (nofile), try to raise soft limit, and compute safe concurrency.
/// Returns (concurrency, soft_nofile, human_note).
pub fn tune_ulimit_and_concurrency(requested: Option<usize>) -> (usize, u64, String) {
    let (soft, hard) = rlimit::Resource::NOFILE.get().unwrap_or((1024, 1024));
    // Raise soft limit up to hard limit to allow more concurrent sockets (best-effort).
    if soft < hard {
        let _ = rlimit::Resource::NOFILE.set(hard, hard);
    }
    let (soft2, hard2) = rlimit::Resource::NOFILE.get().unwrap_or((soft, hard));

    // Headroom for stdin/stdout/stderr, DNS, HTTP client pool, output file, etc.
    let headroom: usize = 128;
    let auto = ((soft2 as usize).saturating_sub(headroom)).clamp(512, 4000);
    let mut c = requested.unwrap_or(auto).clamp(64, 10_000);
    c = c.min((soft2 as usize).saturating_sub(64).max(64));

    let note = format!("nofile soft/hard={}/{} -> concurrency={}", soft2, hard2, c);
    (c, soft2, note)
}
