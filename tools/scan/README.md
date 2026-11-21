# kb-scan

Continuous, host-side sync/scan engine for this knowledge base and the team's
Le Chonk pipeline. One static binary, zero external crates, no unsafe code.
See `ORCHESTRATION.md` for the pinned contract; this README covers usage and
the security model.

## Build and test

```bash
export PATH=$HOME/.cargo/bin:$PATH   # cargo is not on PATH in this environment
cd tools/scan
cargo test                                                            # unit + integration tests
cargo build --release --target x86_64-unknown-linux-musl
file target/x86_64-unknown-linux-musl/release/kb-scan   # static-pie linked, stripped
./target/x86_64-unknown-linux-musl/release/kb-scan self-test   # prints: ok
```

`.cargo/config.toml` pins the musl target and `linker = "rust-lld"` because
this machine has no `cc`/libc dev files. The result is a static PIE with no
dynamic loader.

## Usage

```
kb-scan version
kb-scan self-test
kb-scan feeds                                   # feed endpoints + host allowlist (JSON)
kb-scan sync   [--repo DIR] [--out FILE] [--pretty]
kb-scan scan   [--config FILE] [--inventory FILE] [--out FILE] [--pretty] [--max-filesize BYTES]
kb-scan watch  [--config FILE] [--interval SECS] [--max-runs N] [--out-dir DIR] [--pretty]
               [--force] [--stop-file FILE] [--max-filesize BYTES] [--shard NAME]
kb-scan swarm  [--config FILE] [--interval SECS] [--max-runs N] [--out-dir DIR] [--pretty]
               [--force] [--stop-file FILE]
kb-scan merge  [--out-dir DIR] [--out FILE] [--pretty]
```

- `sync` polls git (`fetch --prune`, `for-each-ref`, `rev-list --left-right
  --count`, `log`) and emits a `kb-scan-sync/1` report. It **never** merges,
  rebases or pushes — it only reports.
- `scan` queries the live feeds against an inventory and emits a
  `kb-scan-report/1` report, findings ranked by the triage order in
  `feeds.md` (1 malware → `malicious-dependency`, 2 KEV hit →
  `exploited-vulnerability`, 3 high/critical or EPSS ≥ threshold, 4 rest;
  package matches route to `advisory-fleet-triage`).
- `watch` loops: each cycle runs sync then scan and writes
  `<out-dir>/reports/<ts>-sync.json` and `<ts>-scan.json` plus atomically
  updated `latest-sync.json` / `latest.json`. Stop with the stop file
  (`<out-dir>/stop` by default, or `--stop-file`) or `--max-runs N`.
  With `--shard NAME` (`sync`, `kev`, `osv`, `github`, `epss`, `nvd`) it runs
  only that shard's work and writes only under its own out-dir.
- `swarm` is the polling agent as a swarm of isolated pollers: it derives the
  shard list (`["sync"]` + each enabled feed) and spawns one child of the
  current exe per shard — `<exe> watch --shard <name> --config <same>
  --interval <same> --max-runs <same> --out-dir <out-dir>/shards/<name>` with
  `KB_SCAN_SHARD=<name>` in its env. The supervisor holds
  `<out-dir>/swarm.lock` (exit 4 if a live instance holds it, `--force`
  overrides), respawns children that exit abnormally with exponential backoff
  capped at 60s, honors the stop file and `--max-runs`, and after each cycle
  merges the shard reports into `<out-dir>/latest.json` (schema
  `kb-scan-report/1`, with `engine.swarm: true` and a `shards` array),
  `<out-dir>/latest-sync.json`, plus timestamped copies under `reports/`.
- `merge` re-merges `<out-dir>/shards/*/latest.json` on demand: findings are
  concatenated and sorted by `(tier, id)`, per-shard feed statuses are
  preserved, stats are summed, missing shards are tolerated, and the sync
  shard's `latest-sync.json` is surfaced separately. The schema stays pinned at
  `kb-scan-report/1`.

### Swarm isolation model

Each shard is a separate OS process with its own out-dir
(`<out-dir>/shards/<name>/`), its own lock file (`kb-scan.lock` inside that
dir, so shards never collide), its own stop file, and its own report files —
two shards never write the same file. The supervisor never writes into a
shard dir; it only reads `shards/*/latest.json` and `shards/sync/latest-sync.json`
to merge, and writes only at the top of `<out-dir>`. All writes everywhere are
atomic (temp file + rename). A shard that is rate-limited (e.g. GitHub 403)
records that in its report status and keeps running; it does not crash the
swarm.

Exit codes: `0` ok · `2` usage/config error · `3` feed/git error (partial
results are still reported on stdout) · `4` lock held by another instance.
stdout carries only JSON; human-readable progress goes to stderr.

### Config (`--config FILE`, all keys optional)

```json
{
  "inventory": "tools/scan/inventory.json",
  "interval_secs": 3600,
  "max_runs": 0,
  "out_dir": "tools/scan/out",
  "git_remote": "origin",
  "http_timeout_secs": 60,
  "max_body_bytes": 8388608,
  "epss_threshold": 0.5,
  "kev_recent_days": 30,
  "feeds": { "kev": true, "osv": true, "github": true, "epss": true, "nvd": false }
}
```

Unknown keys are an error. Inventory shape:

```json
{
  "packages": [{ "ecosystem": "npm", "name": "lodash", "version": "4.17.20" }],
  "products": [{ "vendor": "Microsoft", "product": "Exchange Server" }],
  "cves": ["CVE-2021-44228"]
}
```

## Security model

- **`#![forbid(unsafe_code)]`** at the crate root and **zero dependencies**
  (`Cargo.toml` has an empty `[dependencies]`): memory safety is a
  compile-time guarantee and there is no dependency supply chain to attack.
- **All parsing is hand-written and strict**, with hard caps on input bytes,
  nesting depth, string length, and array/object sizes. The serializer escapes
  `"`, `\`, control characters, and additionally `<`, `>`, `&` as
  backslash-u escapes (u003c, u003e, u0026), so feed text cannot become
  markup when a report is rendered downstream.
- **Feed text is untrusted data.** It is sanitised on parse (control
  characters stripped, whitespace collapsed), never executed, never used as a
  format string, and never written into a shell command. The engine only
  writes reports and proposes; a person acts.
- **Network egress goes only through `curl` invoked as an argv array** —
  never a shell — with stdin null (or a piped POST body), stdout/stderr read
  under byte caps, `--max-time`/`--connect-timeout`, `--max-filesize`, no
  redirect following, and `--proto -all,https`. The host must exactly match
  the compiled-in allowlist from `feeds.md` (`www.cisa.gov`, `api.osv.dev`,
  `api.github.com`, `services.nvd.nist.gov`, `api.first.org`); query
  parameters are percent-encoded by the engine and no URL is ever built by
  concatenating feed-derived text.
- **No secrets are needed.** If `GITHUB_TOKEN` is set, it is forwarded to
  curl as a single `-H` argv element and is never logged, stored or printed.
- **One instance at a time:** a lock file (`<out-dir>/kb-scan.lock`) created
  with `create_new`, stale-lock detection via `/proc/<pid>`, `--force` to
  override. Reports are written to a temp file and atomically renamed.
- **Git is read-only reporting:** `fetch --prune`, `for-each-ref`,
  `rev-list`, `log` as argv arrays with capped output; never merge, rebase or
  push.
