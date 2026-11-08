# svcscan 🔎

Simple, fast-enough **async TCP port scanner + banner/HTTP grabber** in pure Rust.

- Reads a `.txt` of hosts/URLs/IPs (one per line), like `hosts.txt` / `new_list.txt`
- Resolves hostnames, de-duplicates IPs
- Scans **all 65,535 TCP ports** per host (async connect)
- Grabs **TCP banners** and **HTTP(S) info** (status, server, headers, capped body excerpt)
- Writes **navigable, append-safe** results (check the file while it runs) + summary with emojis ✨
- **No external scanner binaries required** (no `masscan`/`nmap`/`zmap` dependency)

> Authorized security testing / inventory only. Scan hosts you own or have permission to assess.

## Install

```bash
cargo install svcscan
```

Or build from source:

```bash
git clone https://github.com/mnk-works/svcscan
cd svcscan
cargo build --release
```

## Usage

```bash
svcscan <INPUT.txt> [OUTPUT] [--verbose] [--concurrency N] [--timeout-ms MS]
```

- `INPUT.txt` — hosts/URLs/IPs (one per line). Examples:
  - `http://203.0.113.10:7777/`
  - `example.com`
  - `198.51.100.5:8080`
- `OUTPUT` — optional; default: `result_<unix_timestamp>.txt` in the current directory
- `--verbose, -v` — debug logs to stderr (result file stays clean)
- `--concurrency` — max concurrent port probes (**default: auto** from system `ulimit -n`, raised when possible)
- `--timeout-ms` — connect/read timeout in ms (**default: `800`**)
- `--retries` — retries per port on connect **timeout** only (**default: `1`**; refused ports are not retried)

Defaults are tuned for **reliability + speed** (auto concurrency from `ulimit`, `800ms` timeout, `1` retry on connect timeout). Filtered/drop-heavy hosts are slower (timeout-bound) — inherent to TCP connect scanning vs raw SYN (`masscan`). For maximum certainty on flaky paths, raise `--timeout-ms`/`--retries`.

## Example

```bash
svcscan hosts.txt
svcscan new_list.txt scan-results.txt -v --concurrency 800 --timeout-ms 1000
```

## Output

- Appended per-host blocks as scans complete: open ports, `banner`, `http` status/server/headers/body excerpt
- Final `📊 SUMMARY` with per-host open counts
- Progress spinner/emoji status on stderr

## Notes

- TCP connect scan (accurate, no root required). Auto-detects/raises `ulimit -n` for concurrency; retries on timeout for reliability. Full 65k scans take time on filtered/drop hosts (timeouts dominate) — tune `--timeout-ms`/`--retries`/`--concurrency` if needed.
- Inspired by ideas from [RustScan](https://github.com/RustScan/RustScan) (ulimit tuning, fast async scanning); implemented independently in pure Rust with in-process banner/HTTP grabbing.
- HTTP probing tries HTTP/HTTPS and accepts invalid certs for fingerprinting; body/headers are capped.
- v0.1.0 is intentionally simple/minimal.

## License

MIT
