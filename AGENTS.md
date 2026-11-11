# AGENTS.md — svcscan

Guidance for coding agents working in this repository.

## Project
`svcscan` is a small, pure-Rust CLI that scans **all 65,535 TCP ports** per target, grabs banners/HTTP(S) metadata, and writes navigable, append-safe results. It has **no external scanner binary dependencies** (no `masscan`/`nmap`/`rustscan`/`zmap`).

## Build / test / run
```bash
cargo test                  # unit tests (parsing, sanitize, ulimit tuning)
cargo build --release
./target/release/svcscan <INPUT.txt> [OUTPUT] [-v] [--concurrency N] [--timeout-ms MS] [--retries N]
```
- Default output: `scanned_<unix_timestamp>.txt` (append-as-it-goes).
- Smoke test: `printf 'localhost\n' > /tmp/t.txt && cargo run --release -- /tmp/t.txt /tmp/out.txt --timeout-ms 100 --concurrency 4000`

## Code layout (modular)
- `src/main.rs` — orchestration, progress/speed stats, summary.
- `src/cli.rs` — clap args (minimal; smart defaults).
- `src/config.rs` — `ScanCfg`, ulimit/nofile detection + soft-limit raise, auto concurrency.
- `src/input.rs` — line/URL/host parsing, DNS resolution, de-dupe.
- `src/scan.rs` — async connect scan (1..65535), timeout + retry-on-timeout policy.
- `src/probe.rs` — banner read (reuses open stream), HTTP(S) probe (**TLS certs ignored; errors never fail scan**), sanitization.
- `src/output.rs` — per-host formatting, append-safe file writes.

## Key invariants / decisions
- **TLS is best-effort:** cert validation disabled; any TLS/HTTP error is swallowed. Scans must not fail due to TLS.
- **Reliability over aggressive speed:** retry only on **connect timeout** (uncertain). **Connection refused (RST) is definitive** — never retried.
- **Single connect per attempt:** banner is read from the already-connected stream (no double-connect).
- **ulimit-aware:** detect/raise `RLIMIT_NOFILE` and cap concurrency; avoids `EMFILE`/missed ports.
- **Append-safe output:** results flushed per host so the file is useful while running.
- **Resilient input:** unresolvable/bad host entries and comments/blanks are skipped with a warning (never abort the whole scan).
- **Finish notification:** emits an OSC 99 desktop notification (`\x1b]99;...`) to stderr on completion (best-effort; harmless if unsupported).

## Performance tuning (when changing defaults/logic)
- Connect scans are **timeout-bound on filtered/drop hosts**; refused ports return fast. Lower timeout + bounded retries balances speed/reliability (defaults: 800ms, 1 retry). Raising `--timeout-ms`/`--retries` improves reliability on lossy/slow paths at a speed cost.
- `concurrency` must respect `nofile`; too high risks FD exhaustion. Auto-tune with headroom.
- Be careful not to reintroduce double-connects or blanket retries on refused ports.

## Publishing (maintainers)
- Bump `Cargo.toml` version, `cargo test`, update docs, commit/push to `mnk-works/svcscan`.
- `cargo publish` (use `CARGO_REGISTRY_TOKEN` via env; never commit secrets). Prefer `--version X.Y.Z --force` for `cargo install` right after publish if index lags. Run `hash -r` after updating an installed binary.

## Style
- Keep CLI minimal. Preserve navigable output + emojis/progress. Add clear comments for non-obvious scan/tuning behavior.
