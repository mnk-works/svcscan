//! Command-line interface (minimal args, smart defaults).

use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "svcscan",
    about = "🔎 Reliable async TCP port scan + banner/HTTP grab (all 65535). No external deps.",
    version
)]
pub struct Args {
    /// Input .txt file with hosts/URLs/IPs (one per line)
    pub input: PathBuf,

    /// Output file (default: result_<unix_timestamp>.txt)
    pub output: Option<PathBuf>,

    /// Verbose/debug logs to stderr
    #[arg(short, long)]
    pub verbose: bool,

    /// Max concurrent probes (default: auto-tuned from system ulimit/nofile)
    #[arg(long)]
    pub concurrency: Option<usize>,

    /// Connect/read timeout in milliseconds (default: 800)
    #[arg(long)]
    pub timeout_ms: Option<u64>,

    /// Retries per port on connect timeout only (default: 1). Refused (RST) is never retried.
    #[arg(long)]
    pub retries: Option<u32>,
}
