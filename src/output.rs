//! Result formatting and append-safe file output.

use crate::input::Target;
use crate::scan::PortFinding;
use anyhow::Result;
use std::path::Path;
use std::sync::Arc;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

pub fn format_host_result(t: &Target, findings: &[PortFinding], duration_ms: u128) -> String {
    let mut s = String::new();
    s.push_str(&format!("\n=== 🔎 HOST {} ({}) original={} | ⏱️ {}ms ===\n", t.ip, t.host, t.original, duration_ms));
    if findings.is_empty() {
        s.push_str("  (no open TCP ports found)\n");
        return s;
    }
    s.push_str(&format!("  ✅ open ports: {}\n", findings.len()));
    for f in findings {
        s.push_str(&format!("  - {}/tcp open", f.port));
        if !f.banner.is_empty() { s.push_str(&format!(" | banner: {}", f.banner)); }
        if let Some(h) = &f.http {
            s.push_str(&format!(" | {}: {}", h.scheme, h.status));
            if !h.server.is_empty() { s.push_str(&format!(" | server: {}", h.server)); }
            if !h.headers.is_empty() { s.push_str(&format!(" | headers: {}", h.headers)); }
            if !h.body_excerpt.is_empty() { s.push_str(&format!(" | body: {}", h.body_excerpt)); }
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
