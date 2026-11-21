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
               [--allow-unsandboxed]
kb-scan swarm  [--config FILE] [--interval SECS] [--max-runs N] [--out-dir DIR] [--pretty]
               [--force] [--stop-file FILE] [--run-id ID] [--allow-unsandboxed]
kb-scan merge  [--out-dir DIR] [--out FILE] [--pretty]
kb-scan serve  --out-dir DIR [--addr 127.0.0.1:8787] [--allow-non-localhost]
```

### Active querying: `serve` (localhost-only query loop)

`kb-scan serve` runs a read-only HTTP query loop over the report files
(std::net::TcpListener only, zero deps, one thread per connection, request
head capped at 8 KiB, read/write timeouts, response bodies capped):

- `GET /health` → `{"status":"ok"}`
- `GET /latest` → `<out-dir>/latest.json` bytes (`kb-scan-report/1`)
- `GET /sync` → `<out-dir>/latest-sync.json` bytes (`kb-scan-sync/1`)
- `GET /findings?tier=N` → latest.json filtered to that tier (parse + filter + re-serialise)
- `GET /brief` → ≤90-word `text/plain` brief rendered engine-side from
  latest.json (+ sync attention lines), ending with the standing closer
  "A person approves before anything is sent."

Unknown path or missing file → 404; non-GET → 405. Binds loopback only; a
non-loopback `--addr` is refused (exit 2) unless `--allow-non-localhost` is
passed (local debugging only). If `KB_SCAN_QUERY_TOKEN` is set, requests need
`Authorization: Bearer <token>` (constant-time-ish compare; the token is never
logged or written). The bound address is announced as JSON on stdout
(`{"listening":"127.0.0.1:8787"}`); progress goes to stderr. The main
workflow, a `/loop` cron, or an agent can poll these on any schedule.

### Explorer / verifier orchestration (the brain stays in Rust)

The swarm can also run two LLM-agent shard types; the Rust engine only
schedules, queues, spawns and merges — it never reads web content itself.
Enable them in the config (strict schema, unknown keys are an error):

```json
{
  "workflow_root": "runs",
  "explore": {
    "enabled": true, "max_per_cycle": 5, "queries_file": "tools/scan/explore-queries.txt",
    "agent_cmd": ["vibe", "-p"], "agent_prompt_file": "tools/scan/explore-prompt.md",
    "sandbox_cmd": ["bwrap", "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc"]
  },
  "verify": { "enabled": true, "max_per_cycle": 20,
    "agent_cmd": ["vibe", "-p"], "agent_prompt_file": "tools/scan/verify-prompt.md" }
}
```

- **explore shard** (`watch --shard explore`): each cycle rotates
  `explore-queries.txt` (round-robin + one jittered extra term per cycle from
  a small built-in list), writes `<out>/explore/queue-<ts>.json` (one
  `{id, query, sources_hint}` task per line), then spawns up to `max_per_cycle`
  agent processes — `agent_cmd + [prompt with task substituted]`, argv array
  only, never a shell, each under `sandbox_cmd` if set, cwd a fresh
  per-agent dir `<out>/explore/agents/<id>/`, env scrubbed (no inherited
  secrets), hard timeout `http_timeout_secs × 4` then kill. Each agent writes
  `results.json` (schema `kb-scan-leads/1`, leads `status: "unverified"`);
  leads accumulate in `<out>/leads.json`.
- **verify shard** (`watch --shard verify`): builds `<out>/verify/queue.json`
  from findings with tier ≤ 2 (in the supervisor's merged `latest.json`) plus
  all unverified leads, spawns verifier agents the same way; each writes
  `verdicts.json` (`{verdicts: [{id, status: confirmed|partial|unconfirmed,
  sources: [{url, read}]}]}`), accumulated in `<out>/verdicts.json`.
- **merge** folds leads into `kb-scan-report/1` as findings with
  `source: "explore"` and `status` from the verifier verdict (default
  `unverified`); tier ordering is preserved and unverified leads never outrank
  tier 1/2 feed-confirmed findings. Schema stays pinned at `kb-scan-report/1`.
- **Handoff:** the supervisor additionally writes the merged triage report
  atomically to `<workflow_root>/<run>/triage.json` (`run` = `--run-id` or
  `latest`) — that file is what the main Le Chonk workflow's step 0 reads.
  Gate rules are unchanged; a human approves. The engine never sends anything.

Tests and live demos use a **stub agent** (`tests/stub-agent.sh` writes canned
`results.json`/`verdicts.json`) — never a real model call, never a real
secret. Example:

```bash
kb-scan swarm --config tools/scan/out/orch-test-config.json \
  --interval 5 --max-runs 2 --out-dir tools/scan/out/orch-test
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

### Sandboxing is mandatory for network shards (fail-closed)

Every shard that performs network I/O — the `sync` shard (git fetch) and all
feed shards — **must** run inside the sandbox. Config gains a top-level
`sandbox_cmd` (array, e.g. the bwrap invocation from `bwrap.example.sh`, see
`config.example.json`). The swarm supervisor re-execs each network shard child
under `sandbox_cmd` (argv array, never a shell) with the same args plus
`--shard`.

**Fail-closed:** if any network shard is enabled and `sandbox_cmd` is empty,
`swarm` and `watch` exit **2** with
`network shards require sandbox_cmd (bwrap) — set it in config or pass --allow-unsandboxed for local debugging only`.
`--allow-unsandboxed` (on `swarm`, `watch`, and the one-shot `scan`/`sync`)
bypasses the check for local debugging only and logs a loud stderr warning;
the supervisor propagates it to shard children. When `sandbox_cmd` is set,
one-shot `scan`/`sync` re-exec themselves under the wrapper (argv array, no
shell, guarded by `KB_SCAN_IN_SANDBOX`). `explore`/`verify` agent spawning is
sandboxed separately via `explore.sandbox_cmd` / `verify.sandbox_cmd` and is
**fail-closed with no override**: if empty, the shard exits 2 with
`agent spawning requires sandbox_cmd — no override` (even with
`--allow-unsandboxed`), and agents are never wrapped by the top-level
`sandbox_cmd`. Tests prove wrapping with `tests/passthrough-sandbox.sh`, a
wrapper that logs its argv and execs.

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
