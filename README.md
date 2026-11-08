# svcscan 🔎

Simple, fast, **reliable** async TCP port scanner + banner/HTTP grabber in pure Rust.

- Reads a `.txt` of hosts/URLs/**domains** (one per line), resolves DNS, de-duplicates IPs
- Scans **all 65,535 TCP ports** per host (async `connect`, no external scanner binaries)
- Grabs **TCP banners** and **HTTP(S) info** (status, server, headers, capped body excerpt)
- **TLS certs ignored** and TLS/HTTP errors never fail the scan (best-effort fingerprinting)
- **Navigable, append-safe** results (check the file while it runs) + **speed stats** (per-host `⏱️`, `ports/s`)
- **Auto-tuned**: detects/raises `ulimit -n` (nofile) for concurrency; retries on connect timeout for reliability
- Modular, tested, commented codebase (`src/{cli,config,input,scan,probe,output}.rs`)

> Authorized security testing / inventory only. Scan hosts you own or have permission to assess.

## Install

```bash
cargo install svcscan --force
svcscan --version
```

Or build from source:

```bash
git clone https://github.com/mnk-works/svcscan
cd svcscan && cargo build --release
```

## Usage

```bash
svcscan <INPUT.txt> [OUTPUT] [--verbose] [--concurrency N] [--timeout-ms MS] [--retries N]
```

- `INPUT.txt` — hosts/URLs/IPs/domains (one per line):
  - `http://203.0.113.10:7777/` · `https://example.com/` · `example.com` · `198.51.100.5:8080`
- `OUTPUT` — optional; default `result_<unix_timestamp>.txt` (cwd)
- `--verbose, -v` — debug logs to stderr (resolution, progress details)
- `--concurrency` — max concurrent probes (**default: auto** from `ulimit -n`, raised when possible)
- `--timeout-ms` — connect/read timeout ms (**default: `800`**)
- `--retries` — retries per port on **connect timeout only** (**default: `1`**; refused/RST never retried)

## Example

```bash
svcscan hosts.txt
svcscan new_list.txt scan-results.txt -v
svcscan targets.txt --timeout-ms 1200 --retries 2   # higher reliability on lossy paths
```

## Output & speed stats
- Per-host blocks appended live: open ports, `banner`, `http` status/server/headers/body excerpt, per-host `⏱️` and `ports/s`.
- Final `📊 SUMMARY` with total duration, open ports, and effective `⚡ ~ports/s` (`65535 × hosts / duration`).
- Progress + emoji status on stderr.

## How it works (and why defaults are reliable)
- **TCP connect scan** (full handshake): accurate and needs no root/caps. One connect per attempt; banner read reuses that stream.
- **Refused (RST) is definitive** → no retry (fast). **Timeout is uncertain** (filtered/drop or slow under load) → retried (default 1x, with backoff). This avoids the false-negative miss caused by an overly tight timeout while keeping speed reasonable.
- **ulimit/nofile** limits open sockets; `svcscan` reads `RLIMIT_NOFILE`, raises the soft limit toward the hard limit when possible, and caps concurrency with headroom (prevents FD exhaustion/missed ports). (Same class of tuning emphasized by [RustScan](https://github.com/RustScan/RustScan/wiki/Increasing-Speed-%26-Accuracy).)
- **TLS**: cert validation disabled; probe errors swallowed.

## Performance tuning advice
| Symptom / goal | Knob | Guidance |
|---|---|---|
| Missed open ports / lossy or high-latency paths | `--timeout-ms`, `--retries` | Increase timeout (e.g. `1200–2000`) and/or retries (`2`). Improves reliability at a speed cost. |
| Filtered/drop-heavy hosts feel slow | (expected) | Timeouts dominate connect scans (inherent vs raw SYN like `masscan`). Keep defaults or lower timeout only if you accept risk. |
| `EMFILE` / too many open files / erratic misses | `--concurrency`, system `ulimit -n` | Let auto-tuning work, or lower `--concurrency`. Raise `ulimit -n` if very low. |
| Faster on mostly-closed (RST) hosts | defaults | Refused ports return instantly; concurrency + short timeouts help. |
| Accuracy vs speed | balance | Defaults target reliability+speed (`800ms`, 1 retry, auto concurrency). Tighten for speed, loosen for certainty. |

## Repo layout
- `src/main.rs` orchestration/stats · `cli.rs` args · `config.rs` ulimit+config · `input.rs` parse/resolve · `scan.rs` connect+retry · `probe.rs` banner/HTTP(TLS ignored) · `output.rs` append/format · `AGENTS.md` maintainer notes · tests via `cargo test`.

## License
MIT
