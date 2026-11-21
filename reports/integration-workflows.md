# Integration workflows: kb-scan × adversarial simulator × Le Chonk

How the three workflows on branch `integration/scan-engine-le-chonk` form one system, as the code stands on 2026-11-21. This page documents the integration itself; the design it implements is on [System](../system.md) [System design, Nov 2026](../sources/team-system-design.md) [Project brief, Nov 2026](../sources/team-project-brief.md), and the engine's own contract is in `tools/scan/ORCHESTRATION.md`.

## The three workflows

| # | Workflow | Lives in | Job |
|---|---|---|---|
| 1 | **kb-scan engine** (continuous poller) | `tools/scan/` (Rust, zero-dep, static musl) + `tools/scan.py` | Poll CISA KEV, OSV, GitHub advisories and FIRST EPSS against the inventory in `tools/scan/inventory.json`, plus a git `sync` shard that reports branch drift. Emits `kb-scan-report/1` JSON. Deterministic, no model, never acts on what it finds. |
| 2 | **Adversarial simulator** | `tools/scan/simulate.py` | Fakes incidents (fake CVEs, fake MAL- ids, prompt-injection payloads, inventory-targeted fakes) to try to make the pipeline act, then asserts the defences held. Every document it writes is marked SIMULATED and `status: unverified`. |
| 3 | **Le Chonk run** (`le_chonk_run`) | `orchestrator/` + `web/` | One advisory in → one agent per repository → the gate → a draft early warning that waits for a person's approval within 24 hours. Hosted coordinator on Mistral Workflows; all steps run on this machine. [System design, Nov 2026](../sources/team-system-design.md) |

Workflows 1 and 2 are the scan side: they produce and stress-test feed data. Workflow 3 is the response side: it consumes that data as untrusted input and produces verdicts. They never call each other's code; they hand off through files under `runs/<run_id>/`.

## The handoff: `runs/<run_id>/`

One folder per run. The run id is the workflow execution id and the folder name. Everything crossing between workflows is a JSON (or markdown) file, written atomically (temp file + rename), and read size-capped (4 MiB max in `orchestrator/kbscan.py`); a malformed or oversized file is ignored, never fatal.

| File | Written by | Read by | Trust level |
|---|---|---|---|
| `runs/<run_id>/triage.json` | kb-scan swarm supervisor (`tools/scan/src/swarm.rs`), each cycle | Le Chonk step 0 (`kb_scan_watch`) and the report's feed-watch section, via `orchestrator/kbscan.py` | Untrusted feed data. Recorded, never a verdict |
| `runs/<run_id>/sim-triage.json` | adversarial simulator (`tools/scan/simulate.py run`) | The gate's `_apply_sim_triage()` | Untrusted, SIMULATED-marked. Can only cause a downgrade (below) |
| `runs/<run_id>/kb-scan.json` | Le Chonk step 0 (`orchestrator/steps.py::kb_scan_watch`, schema `kb-scan-watch/1`) | The web grid, the report | The run's own record of which feed findings name the advisory |
| `runs/<run_id>/<repo>/verdict.json` (+ `verdict.agent.json`) | Per-repo agent, then overwritten by the gate (`orchestrator/gate.py`) | The web grid, the report | The only verdicts that exist. Agent's original kept beside the gated one |
| `runs/<run_id>/early-warning.md` | `orchestrator/report.py`, from gate-passed verdicts only, no model call | The approver, via the web page | Draft; a person approves and submits, the tool never sends |
| `runs/<run_id>/run.json` + event log | `orchestrator/steps.py`, `orchestrator/events.py` | The web grid (tiles, activity feed, SSE stream) | The run's public state |
| `tools/scan/out/latest.json`, `latest-sync.json` | kb-scan engine (`watch`/`swarm`/`merge`) | Step 0, `kb-scan serve`, `tools/scan.py report/brief/audio-loop/query` | Untrusted feed data |

The flow inside one Le Chonk run (`orchestrator/workflow.py`): intake → read advisory (one model call) → **kb-scan step 0** records the feed findings naming this advisory into `kb-scan.json` before any triage → one agent per repository in parallel → gate per repository → report from gated verdicts only → wait for the `approve` signal, at most 24 hours. On this branch, `runs/latest/` and `runs/verify1/` hold the scan-side handoffs (`triage.json`, `sim-triage.json`); the verdicts and `early-warning.md` appear when a live run executes.

All scan documents are treated as untrusted input everywhere: size-capped parse, malformed → ignored, every string sanitised to one line with no markup before it is rendered or written into a report (`orchestrator/kbscan.py::text`).

## The gate's needs_human-only rule, including the sim downgrade

The gate (`orchestrator/gate.py`) has no model in it. It re-runs every claim on clean copies it builds itself from the wheelhouse, and **may change a verdict to `needs_human` and to nothing else**. A claim that fails any enforced rule, a timeout, a spent budget, or a gate error of its own all land in `needs_human` — never a guess, never "safe".

The one scan-side extension is `_apply_sim_triage()`: it reads `runs/<run_id>/sim-triage.json` (untrusted, size-capped, malformed → no-op). When the simulator's feedback flags an advisory id as a proposed gate rule that a human has **not** reviewed (`type: "gate-rule"`, `human_reviewed: false`), every verdict naming that advisory is downgraded to `needs_human`, with `gate.sim_triage` recording why. That downgrade is still the gate's only permitted change — the simulator proposes, a person decides. The patch spec for this is `tools/scan/patches/gate-sim-triage.patch.md`; the bridge tests are `orchestrator/tests/test_kbscan.py`.

## Hosting split

| Part | Where | Notes |
|---|---|---|
| Static UI (`web/page.html`) | Vercel | No backend logic; the page takes the API base from `?api=`, `window.KB_API_BASE`, else same-origin. Example in the page: `https://le-chonk.vercel.app/?api=https://1a2b3c.ngrok-free.app` |
| Backend + kb-scan (`web/app.py` FastAPI, default port 8000; `kb-scan serve` on 127.0.0.1:8787) | Fly.io or a VM | The worker (`orchestrator/workflow.py`) needs `MISTRAL_API_KEY` + `DEPLOYMENT_NAME` and `OTEL_ENABLED=false`; the engine needs egress only to the feed allowlist. The page reaches it via the `?api=` base |
| Dev tunnel | ngrok | `https://<id>.ngrok-free.app` pointed at the local backend, passed to the Vercel page as `?api=` |

The UI also reads kb-scan directly when it can: `GET /scan/latest` and `GET /runs/{run_id}/scan` on the backend return sanitised scan summaries, and the page falls back to `kb-scan serve` on `http://127.0.0.1:8787` (`window.KB_SCAN_BASE`) for live polling and `/brief`.

## Voice

Two paths, same brief text:

- **CLI (Voxtral).** `python3 tools/scan.py brief --json tools/scan/out/latest.json [--speak]` renders a ≤90-word decision-ready brief and, with `--speak`, posts it to Mistral's speech endpoint (Voxtral TTS) using `MISTRAL_API_KEY` from the environment only — never printed, logged or stored — writes `out/brief.wav` and plays it. `python3 tools/scan.py audio-loop --json ... [--once]` speaks an alert whenever a new *verified* finding appears (simulated/unverified findings never alert). `kb-scan serve` exposes the brief text at `GET /brief` on loopback.
- **GUI (browser).** `web/page.html` speaks with the Web Speech API (`speechSynthesis` / `SpeechSynthesisUtterance`, capped at 600 chars), fetching the text first from the backend's `/brief` proxy, else from `kb-scan serve`'s `/brief` on 127.0.0.1:8787. Microphone input uses `SpeechRecognition` where available, with a status line when the browser has no `speechSynthesis`.

Both paths carry the same standing line: a person approves before anything is sent.

## Notes

- `tools/scan/ORCHESTRATION.md` is the engine-side contract for this same integration ("Live integration" section); it is owned by the scan coordinator and was not edited here.
- Nothing in the integration lets feed or simulator data become a verdict; the only effect scan data can have on a run is the gate's downgrade to `needs_human`.

## Cross-run history index (`orchestrator/history.py`)

`rebuild(runs_root)` scans `runs/*/` (skipping `_`-prefixed folders), reads `run.json`, `events.jsonl`, every `<repo>/verdict.json` and `sim-triage.json` with kbscan-style capped reads, and writes `runs/_index/history.json` atomically (tmp + `os.replace`), size-capped at 512 KiB. All strings pass through `kbscan.text` (one line, markup escaped, capped); worker text in events is untrusted and never executed. The file holds four views: per-run state with verdicts and sim-triage breaches, per-advisory verdict distribution with gate/sim downgrades and breaches over time, per-repo verdict history, and a capped cross-run event timeline. It is read-only over the runs and is meant to be rebuilt after each run; TODO for the web agent: serve it as `GET /history`.
