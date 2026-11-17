//! Result formatting and append-safe file output.
//!
//! Human-readable output modeled on a per-probe block style:
//! each open port gets its own indented block with the URL, status line,
//! headers (one per line), and body excerpt — instead of everything on one line.

use crate::input::Target;
use crate::scan::PortFinding;
use anyhow::Result;
use std::path::Path;
use std::sync::Arc;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

pub const SEP: &str = "======================================================================";

/// Format one host's scan results as a readable multi-line block.
///
/// `index`/`total` are the 1-based position of this host among all targets,
/// used for the `[N/T]` leader (mirrors the friendly probe-listing style).
pub fn format_host_result(t: &Target, findings: &[PortFinding], duration_ms: u128, index: usize, total: usize) -> String {
    let mut s = String::new();

    s.push_str(&format!("\n{}\n", SEP));
    s.push_str(&format!("[{}/{}] 🔎 {} (original: {}) | ⏱️ {}ms | {} open port(s)\n", index, total, t.ip, t.original, duration_ms, findings.len()));
    s.push_str(&format!("{}\n\n", SEP));

    if findings.is_empty() {
        s.push_str("  (no open TCP ports found)\n\n");
        return s;
    }

    for f in findings {
        s.push_str(&format!("  Port {}/tcp — open\n", f.port));

        if !f.banner.is_empty() {
            s.push_str(&format!("  banner: {}\n", f.banner));
        }

        if let Some(h) = &f.http {
            s.push_str(&format!("  └─ {}://{}:{}/\n", h.scheme, t.ip, f.port));
            s.push_str(&format!("     status: {}\n", h.status));

            if !h.server.is_empty() {
                s.push_str(&format!("     server: {}\n", h.server));
            }

            // Headers block: one header per line.
            s.push_str("     headers:\n");
            if h.headers.is_empty() {
                s.push_str("       (none)\n");
            } else {
                for header in &h.headers {
                    s.push_str(&format!("       {}\n", header));
                }
            }

            // Body excerpt block.
            s.push_str(&format!("     body ({} of {} chars shown):\n", h.body_excerpt.len(), h.body_total));
            if h.body_excerpt.is_empty() {
                s.push_str("       |\n");
            } else {
                s.push_str(&format!("       | {}\n", h.body_excerpt));
            }
        }

        s.push('\n');
    }

    s
}

/// Append text under a mutex so concurrent/streamed writes stay coherent, then flush.
pub async fn append_file(path: &Path, lock: &Arc<Mutex<()>>, text: &str) -> Result<()> {
    let _g = lock.lock().await;
    let mut f = OpenOptions::new().create(true).append(true).open(path).await?;
    f.write_all(text.as_bytes()).await?;
    f.flush().await?;
    Ok(())
}
