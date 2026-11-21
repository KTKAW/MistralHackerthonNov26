# kb-scan — orchestration document

Branch `scan-engine`. This document is the shared spec for the scan engine and for the
swarm of agents building it. Read it before writing code. It pins the CLI, the JSON
schemas, the file ownership and the security model so parallel work does not collide.

## What this component is

`kb-scan` is a continuous, host-side loop engine for the knowledge base and for the
team's Le Chonk pipeline (see `system.md`):

1. **Sync loop (first priority).** Poll `git fetch` so this checkout always knows what
   the other branches are doing — new commits on `origin/knowledge`, new
   `build/track-*` branches, whether our base is behind. Strategic compatibility:
   before trusting ingested pages (`system.md`, playbooks), we must know whether the
   design branches moved. Emits a `kb-scan-sync/1` JSON report.
2. **Scan loop.** Query the live feeds listed in `feeds.md` (CISA KEV, OSV,
   GitHub Advisory Database, EPSS; NVD optional) against an inventory of what we run
   (packages with versions, products, CVEs), rank findings by the triage order in
   `feeds.md`, and emit a `kb-scan-report/1` JSON report.
3. **Python plug.** `tools/scan.py` (stdlib only, like `tools/kev.py` and
   `tools/lint.py`) builds/locates the binary, runs it, and renders reports into
   lint-safe knowledge-base pages. The team's orchestrator (track C, `build/*`
   branches) consumes the same JSON: new KEV entries matching the fleet inventory are
   run candidates, and report fields mirror the advisory facts the "read advisory"
   step cross-checks against the feed (`system.md`, "Where the knowledge base plugs
   in").

## Why Rust, and why it cannot be compromised

- `#![forbid(unsafe_code)]` at the crate root: memory safety is a compile-time
  guarantee, not a convention.
- **Zero external crates.** `Cargo.toml` has no dependencies, so `Cargo.lock` is empty
  and there is no dependency supply chain to attack. Do not add any. If a feature seems
  to need a crate, hand-roll it in std instead.
- Static musl binary (`x86_64-unknown-linux-musl`, linked with the toolchain's
  `rust-lld` — this environment has no `cc`/libc dev files): one file, no dynamic
  loader, runs in a scratch container.
- All parsing (JSON, config, inventory, feed payloads) is hand-written and strict:
  hard caps on input bytes, nesting depth, string length, array/object sizes.
- Network goes only through `curl` invoked as an **argv array** (never a shell),
  stdin null, stdout/stderr read with byte caps, `--max-time`/`--connect-timeout`,
  `--max-filesize`, no redirect following, https only, and the host must exactly match
  a compiled-in allowlist taken from `feeds.md` (`www.cisa.gov`, `api.osv.dev`,
  `api.github.com`, `services.nvd.nist.gov`, `api.first.org`). Query parameters are
  percent-encoded by the engine. No URL is ever built by string concatenation of
  feed-derived text.
- Feed text is untrusted data: sanitised on parse (control chars stripped, whitespace
  collapsed), serialised with full JSON escaping (including `<`, `>`, `&` as
  `\u003c` etc.), never executed, never used as a format string, never written into a
  shell command. When Python renders it to markdown, use the same `clean()` as
  `tools/kev.py` (`[`→`(`, `]`→`)`).
- No secrets are needed (the feeds are keyless). If `GITHUB_TOKEN` is set, forward it
  to curl as a single `-H` argv element; never log, store or print it.
- One instance at a time: a lock file created with `create_new` in the out dir; stale
  lock detection via `/proc/<pid>`; `--force` to override. Reports are written to a
  temp file and atomically renamed.
- The loop never acts on what it finds — it writes reports and proposes; a person
  acts (per AGENTS.md "You propose; a person acts").

## CLI contract (pinned — do not deviate)

```
kb-scan version
kb-scan self-test
kb-scan feeds                                   # list feed endpoints + the host allowlist
kb-scan sync   [--repo DIR] [--out FILE] [--pretty]                 # one git poll → sync report JSON on stdout
kb-scan scan   [--config FILE] [--inventory FILE] [--out FILE] [--pretty]   # one scan pass → report JSON on stdout
kb-scan watch  [--config FILE] [--interval SECS] [--max-runs N] [--out-dir DIR] [--pretty]
                                                    # continuous: each cycle runs sync then scan,
                                                    # writes <out-dir>/reports/<ts>-sync.json and <ts>-scan.json
                                                    # plus atomically-updated latest-sync.json / latest.json
```

Exit codes: 0 ok · 2 usage/config error · 3 feed/git error (partial results still reported) · 4 lock held by another instance.
Human-readable progress lines go to **stderr**; stdout carries only JSON (or nothing).

## JSON schemas (pinned)

Config file (strict: unknown keys are an error; all keys optional, defaults apply):

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

Inventory file:

```json
{
  "packages": [{ "ecosystem": "npm", "name": "lodash", "version": "4.17.20" }],
  "products": [{ "vendor": "Microsoft", "product": "Exchange Server" }],
  "cves": ["CVE-2021-44228"]
}
```

Scan report (`schema: "kb-scan-report/1"`): `generated_at`, `engine {name, version, static_musl}`,
`feeds: [{name, status, detail?, entries?}]`, `findings: [{tier, kind, id, package?,
product?, cve?, summary, source, epss?, kev_date_added?, playbook}]`,
`stats {packages, cves, findings, errors[]}`.
Tiers follow `feeds.md` "Order of triage": 1 malware (`MAL-` ids / GitHub `type=malware`)
→ playbook `malicious-dependency`; 2 CVE in KEV touching the inventory →
`exploited-vulnerability`; 3 high/critical severity or EPSS ≥ threshold; 4 the rest.
When the match is a library/package rather than a product, `playbook` is
`advisory-fleet-triage` (the Le Chonk run).

Sync report (`schema: "kb-scan-sync/1"`): `generated_at`, `repo`, `remote`,
`branches: [{name, ahead, behind, new_commits: [{sha, subject}], moved: bool}]`,
`new_branches: [name]`, `attention: [string]` — human-readable warnings such as
"origin/knowledge moved 855f5a9..a9c0880: rebase before relying on ingested pages"
or "new branch origin/build/track-x appeared".

Sync implementation: run `git -C <repo> fetch <remote> --prune` (argv, no shell),
then `git for-each-ref refs/remotes/<remote>` and `git rev-list --left-right --count
local...remote` per branch, `git log --oneline` for new commits. Cap output sizes.
Never merge, rebase or push from the engine — it only reports.

## File ownership (swarm — do not touch another owner's files)

| Path | Owner |
|---|---|
| `tools/scan/ORCHESTRATION.md` | coordinator (this document) |
| `tools/scan/Cargo.toml`, `tools/scan/.cargo/config.toml`, `tools/scan/src/**`, `tools/scan/README.md`, `tools/scan/tests/**` | agent `rust-engine` |
| `tools/scan.py`, `tools/scan/config.example.json`, `tools/scan/inventory.example.json`, `.gitignore`, root docs (`AGENTS.md`, `README.md`, `feeds.md`, `index.md`, `log.md` via lint) | agent `python-plug` |
| `tools/scan/Dockerfile`, `tools/scan/containerisation.md`, `tools/scan/compose.example.yaml`, `tools/scan/bwrap.example.sh` | agent `container-strategy` |
| `tools/scan/out/**`, `tools/scan/target/**` | gitignored build/run output, anyone |
| everything else | coordinator |

## Python wrapper contract (`tools/scan.py`, stdlib only)

```
python3 tools/scan.py scan   [--config FILE] [--inventory FILE] [--out report.json]
python3 tools/scan.py sync   [--repo DIR] [--out sync.json]
python3 tools/scan.py loop   [--config FILE] [--interval SECS] [--max-runs N]   # streams the engine's watch mode
python3 tools/scan.py report --json REPORT [--out advisories/scan-latest.md] [--watch SECS]
python3 tools/scan.py selftest
python3 tools/scan.py feeds
```

- Binary resolution order: `$KB_SCAN_BIN` → `tools/scan/target/x86_64-unknown-linux-musl/release/kb-scan`
  → build it with `cargo build --release --target x86_64-unknown-linux-musl` (the
  crate ships `tools/scan/.cargo/config.toml` with `linker = "rust-lld"` because this
  machine has no `cc`) → if no cargo, exit 2 with install instructions.
- `report` renders a `kb-scan-report/1` JSON into a lint-safe `feed-snapshot` page
  (frontmatter `type/title/feed/fetched`, `generated: true`), sanitising all feed text
  with the same `clean()` as `tools/kev.py`, linking the playbooks named in findings
  and `../feeds.md`. `--watch` re-renders when the JSON file's mtime changes.
- After any wrapper-driven change to typed pages, run `python3 tools/lint.py --sync`
  and keep it green.

## Active querying: `kb-scan serve` (localhost-only query loop)

Alongside the file handoff, the swarm can answer queries live:
`kb-scan serve --out-dir DIR [--addr 127.0.0.1:8787]`. std `TcpListener` only, zero
deps, read-only GET endpoints: `/health`, `/latest` (merged kb-scan-report/1),
`/sync` (kb-scan-sync/1), `/findings?tier=N` (filtered), `/brief` (the ≤90-word
spoken-brief text, rendered engine-side). Binds loopback only; a non-loopback addr
is refused unless `--allow-non-localhost` is passed (local debugging only). If
`KB_SCAN_QUERY_TOKEN` is set, requests need `Authorization: Bearer <token>`; the
token is never logged or written. Responses are the JSON files' bytes with
`Content-Type: application/json`; unknown path → 404; method other than GET → 405.
The main workflow, a harness `/loop` cron, or an agent can poll these on any
schedule. `tools/scan.py` gains a thin `query` subcommand (health/latest/sync/
findings/brief) that GETs the local endpoint and prints JSON.

## Voice briefings (Mistral Voxtral)

`python3 tools/scan.py brief --json out/latest.json [--out brief.txt] [--speak]`
renders a ≤ 90-word, decision-ready spoken brief from a `kb-scan-report/1`: the top
verified tier 1/2 findings (id, what it is, what we run, patch target) plus any
sync `attention[]` lines, then the standing line "a person approves before anything
is sent". `--speak` posts the brief to Mistral's speech endpoint (Voxtral TTS — the
same model family as this harness's `active_tts_model = "voxtral-tts"`) using
`MISTRAL_API_KEY` from the environment only — the tool never prints, logs or stores
the key — writes `out/brief.wav`, and plays it if a player exists. Without the env
key, `--speak` exits 2 and tells the user to set their own key. The engine itself
stays model-free; brief text is rendered deterministically in Python.

## Sandboxing is mandatory for anything that touches the network

Rule (fail-closed): every shard that performs network I/O — all feed shards and the
`sync` shard — MUST run inside the sandbox. The supervisor re-execs each such shard
child under `sandbox_cmd` (bwrap locally, container in deploy). If a network shard
would start without a sandbox, the engine exits 2 with a clear message unless
`--allow-unsandboxed` is passed explicitly (for local debugging only; never in
production). Spawned LLM agents are always sandboxed, no override. `tools/scan.py`
additionally wraps the whole engine invocation in bwrap when bwrap is present.
The allowlist (5 compiled-in feed hosts + the git remote host) is enforced in code
*and* at the network layer where the platform allows it; bwrap containers rely on
the in-code allowlist plus process isolation.

## Containerisation strategy (decision)

- **Here and in dev:** the engine runs as an ordinary process on the host under
  `bwrap` (available in this environment; unprivileged user namespaces are enabled)
  with a read-only bind of the repo and a writable out dir — see
  `tools/scan/bwrap.example.sh`. The `docker` binary on PATH here is a Windows
  Docker-Desktop path and does not run in this sandbox; do not rely on it.
- **Deployment:** `tools/scan/Dockerfile` — multi-stage `rust:1-musl` build, final
  stage `FROM scratch`, copy only the static binary, `USER 65534:65534`, no shell in
  the image, read-only rootfs at runtime, dropped capabilities, resource limits, and an
  egress allowlist at the network layer matching the engine's host allowlist.
- **Boundary rule (matches `system.md` "In production" and track A):** the engine is
  host-side and needs egress to the feeds. The per-repository Le Chonk workers stay
  inside the sandbox (bwrap on Linux) with **no network**; they never run `kb-scan`.

## Verification (definition of done for this component)

1. `cargo test` green (unit tests for the JSON parser, sanitiser, URL encoder,
   allowlist, triage ranking, date math).
2. `cargo build --release --target x86_64-unknown-linux-musl` green; `file` shows a
   static binary.
3. `kb-scan self-test` prints ok; `python3 tools/scan.py selftest` exits 0.
4. Live run: `python3 tools/scan.py scan --inventory tools/scan/inventory.example.json`
   against the real feeds produces a valid `kb-scan-report/1`.
5. `python3 tools/scan.py sync` shows `origin/knowledge` and the `build/*` branches.
6. Short loop: `kb-scan watch --interval 5 --max-runs 2 --out-dir tools/scan/out`
   writes timestamped reports plus `latest.json` / `latest-sync.json`.
7. `python3 tools/scan.py report --json tools/scan/out/latest.json` writes
   `advisories/scan-latest.md`; `python3 tools/lint.py --sync --log "edit | …"` is green.
8. Everything committed on `scan-engine` with the Mistral Vibe commit trailer.

## Wiring into a Mistral Workflow (Le Chonk, track C)

The poller swarm is the deterministic layer; a Mistral Workflows run is the LLM
layer on top (pattern proven by the team on 21 Nov 2026: parallel activities via
`asyncio.gather`). Proposal for `orchestrator/` on the build branches:

- `threat_intake` workflow (or step 0 of `le_chonk_run`): activity `poll_feeds`
  runs/reads `out/latest.json`; one `verify_finding` activity per tier ≤ 2 finding,
  each a headless Vibe **host-side** (verifiers need network: NVD/EPSS/OSV/news —
  unlike the per-repo workers, which stay sandboxed and offline); each returns
  `{id, status: confirmed|partial|unconfirmed, sources:[{url, read}]}`.
- Results land in `runs/<run_id>/candidates.json`, validated like
  `schema/verdict.schema.json`; `gate.py` rules apply unchanged — an
  `unconfirmed` verdict may only be downgraded to `needs_human`.
- The approve-signal + 24 h timeout pattern is reused; a person submits anything
  to ENISA's platform. The engine and the workflow never send anything.
- Rate limits: GitHub ADP is 60 req/h unauthenticated — shards already degrade to
  `rate-limited`; verifiers should treat OSV/NVD/EPSS as primary and GitHub as
  best-effort. One attempt per activity, no retries on half-verified findings.

## Explorer / verifier orchestration (the brain stays in Rust)

The swarm gains two shard types, orchestrated by the Rust supervisor. The Rust
engine only schedules, queues, spawns and merges — it never reads web content.
The LLM agents it spawns are the untrusted-input readers, so **each spawned agent
runs in its own sandbox** (one sandbox per agent): bwrap locally, scratch container
in deploy; read-only FS except the agent's own result file; scrubbed env, no
secrets; network limited to the research hosts. The engine itself stays
minimal-privilege host-side.

Config additions (strict schema, unknown keys still an error):

```json
{
  "explore": {
    "enabled": true, "max_per_cycle": 5, "queries_file": "tools/scan/explore-queries.txt",
    "agent_cmd": ["vibe", "-p"], "agent_prompt_file": "tools/scan/explore-prompt.md",
    "sandbox_cmd": ["bwrap", "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc"]
  },
  "verify": { "enabled": true, "max_per_cycle": 20,
    "agent_cmd": ["vibe", "-p"], "agent_prompt_file": "tools/scan/verify-prompt.md" },
  "workflow_root": "runs"
}
```

Behaviour per cycle:

1. `explore` shard rotates the query list (round-robin + jittered pick of extra
   terms) and writes `out/explore/queue-<ts>.json` — one task per line:
   `{id, query, sources_hint}`. It then spawns up to `max_per_cycle` agent
   processes: `agent_cmd + [prompt with task substituted] `, each under
   `sandbox_cmd` (if set) with cwd = a per-agent dir under `out/explore/agents/<id>/`,
   env scrubbed, timeout from `http_timeout_secs` × 4. Each agent must write its
   findings to `results.json` in its own dir (schema `kb-scan-leads/1`:
   `{leads: [{query, summary, urls: [{url, read}], status: "unverified"}]}`).
2. `verify` shard builds `out/verify/queue.json` from findings with tier ≤ 2 plus
   all unverified leads, and spawns verifier agents the same way; each writes
   `verdicts.json` (`{verdicts: [{id, status: confirmed|partial|unconfirmed, sources: [{url, read}]}]}`).
3. `merge` folds everything into `kb-scan-report/1`: explorer leads appear as
   findings with `source: "explore"` and `status: "unverified"` until a verifier
   verdict arrives, which sets `status` and keeps tier ordering intact
   (unverified never outranks tier 1/2 feed-confirmed findings).
4. The supervisor additionally writes the triage report to
   `<workflow_root>/<run_id or "latest">/triage.json` (atomic) — that file is the
   handoff into the main `le_chonk_run` workflow (step 0 reads it; gate rules
   unchanged; human approves).

Tests must use a **stub agent command** (a shell script that writes canned
`results.json`/`verdicts.json`), never a real model call, and never a real secret.
Live demo with `vibe -p` is documented but not run in CI.
