# TRACK C — Orchestrator, gate, report, web UI

Branch: `build/track-c-orchestration-ui` · You are build agent **3 of 3**.
This track runs the model-heavy parts — use YOUR OWN `MISTRAL_API_KEY`.

## Launch

```sh
git checkout build/track-c-orchestration-ui
export MISTRAL_API_KEY=sk-...     # your own subscription key — never commit it
export OTEL_ENABLED=false
uv add mistralai-workflows fastapi uvicorn
vibe --prompt-file docs/prompts/track-c-orchestration-ui.md --workdir . --trust \
  --auto-approve --model mistral-large-4-0
```

## Read first

`PROJECT.md` ("How it works", "Things learned about Workflows") · `docs/architecture.html` ·
`docs/COORDINATION.md` (pinned contracts — you code against them) · `docs/build-prompt.md`
**Steps 6–9** contain the workflow / gate / report / web skeletons — reuse them verbatim as
starting points, following every `ADAPT` note against `mistralai-workflows` 3.20.0.

## You OWN — edit only these

- `orchestrator/workflow.py` — the `le_chonk_run` workflow + worker entrypoint
- `orchestrator/gate.py` — rules gate as code
- `orchestrator/report.py` — early-warning draft
- `web/app.py` — FastAPI grid on :8000
- `docs/BUILD-LOG.md`

## Do NOT touch

`sandbox/`, `worker/` (track A) · `fleet/` (track B) · `schema/`, `.gitignore` (on base).
**Stub strategy:** if `worker/run_repo.py` or `fleet/` are not merged yet, test against stubs
in `/tmp` (a fake `run_repo` returning canned verdicts, a fake repo list). Never create files
under `worker/` or `fleet/` on your branch — that is how merge conflicts start.

## Pinned contracts (tracks A and B implement exactly these)

```python
def run_repo(run_id, repo, *, fleet_root="fleet", runs_root="runs",
             vibe_home="vibe-home", heartbeat_fn=None) -> dict: ...
# -> {"repo", "rc", "verdict", "export"}; verdict at runs/<run_id>/<repo>/verdict.json

def gate(run_id, verdicts, *, runs_root="runs", wheelhouse="wheelhouse") -> list: ...
# fills verdict["gate"]; may ONLY downgrade verdict -> "needs_human"

def render_early_warning(run_id, gated_verdicts, *, runs_root="runs") -> str: ...
# writes runs/<run_id>/early-warning.md; NO model call

# workflow: name "le_chonk_run", input advisory_text: str,
#           pauses on signal "approve", 24 h timeout
# web: FastAPI :8000 — POST /runs, GET /runs/{id} (tiles only for gate-passed repos),
#      GET / (grid polling every 2 s + 24 h countdown), POST /runs/{id}/approve
```

## Non-negotiable rules

1. Never commit `.env`, `vibe-home/`, `runs/`, `wheelhouse/`.
2. The gate has **no model** in it. The report step makes **no model call** — it uses only
   gate-passed verdicts. `read_advisory` makes exactly **one** model call per run.
3. The gate may only downgrade a verdict to `needs_human`, never upgrade. Tiles render only
   after the gate. One attempt per activity (fresh work copy), heartbeat every 10 s.
4. The tool never sends anything to ENISA; the workflow pauses until a human sends `approve`.
5. `OTEL_ENABLED=false`; `MISTRAL_API_KEY` + `DEPLOYMENT_NAME` from your own env only.
6. Workflows is public preview — if it misbehaves, fall back to a plain Python orchestrator
   with the same contract (Step C8).
7. Commit after each step, heredoc format in `docs/COORDINATION.md`.

## Steps

- [ ] **C1 — `orchestrator/workflow.py`.** `le_chonk_run(advisory_text)` =
      intake (start 24 h clock) → `read_advisory` (ONE model call → `advisory.json`) →
      `triage` (`asyncio.gather`, one activity per repo; activity opts
      `start_to_close_timeout=900`, `heartbeat_timeout=60`, `retry_policy_max_attempts=1`;
      call `workflows.activity_heartbeat` every 10 s — pass it into `run_repo` as
      `heartbeat_fn`) → `verify` (gate) → `report` → `wait_for_signal("approve", 24 h)`.
      Worker entrypoint: `workflows.run_worker([...])`.
- [ ] **C2 — `orchestrator/gate.py`.** For each verdict: re-run every proof test ID **through
      the same sandbox** on the vulnerable version (must FAIL) and on the fixed version from
      the wheelhouse in a second venv (must PASS); test count must never drop
      (`after >= before`); `not_affected` ⇒ no diff in `src/` except agent-written files.
      Any failure ⇒ `verdict = "needs_human"` + per-rule results in `verdict["gate"]`.
      **Negative test:** a bogus proof that passes on the vulnerable version too must be
      downgraded.
- [ ] **C3 — `orchestrator/report.py`.** Fill `runs/<run>/early-warning.md` from gate-passed
      verdicts only: advisory ID, affected repos with evidence (proof IDs, path citations),
      fix status, minutes used against 24 h, CRA Art. 14 early-warning fields. Check
      Regulation (EU) 2024/2847 Art. 14 text before quoting it.
- [ ] **C4 — `web/app.py`.** FastAPI on `:8000`: `POST /runs` (advisory text → start run),
      `GET /runs/{run_id}` (tiles only for gate-passed repos), `GET /` (HTML grid polling every
      2 s + 24 h countdown), `POST /runs/{run_id}/approve` (sends the signal).
- [ ] **C5 — worker process.** `MISTRAL_API_KEY=... DEPLOYMENT_NAME=... OTEL_ENABLED=false uv run python orchestrator/workflow.py`.
- [ ] **C6 — stub test.** With /tmp stubs for `run_repo` and the repo list: 3 activities start
      within ~0.1 s of each other; the run stays RUNNING until the `approve` signal; record
      crash-resume behavior (kill the worker mid-run, restart — 21 Nov: resumed after about the
      activity timeout).
- [ ] **C7 — integration.** When tracks A and B are merged into `build/base`, rebase onto it
      and run the REAL end-to-end on the 3-service subset first: correct verdicts, 100%
      sandboxed shell commands, `verdict.json` + `export.json` per repo, parallel vs sequential
      wall time (21 Nov: 159 s vs 306 s). Then the full fleet. Log everything in
      `docs/BUILD-LOG.md`.
- [ ] **C8 — fallback.** If Workflows misbehaves, swap in a plain-Python orchestrator keeping
      the same contracts.

## Done when

C6 passes with stubs; after integration, C7 passes with real repos; the grid shows tiles only
post-gate; approve completes the run; `early-warning.md` contains only gated verdicts.

## Merge — LAST

Tracks A and B merge into `build/base` first (any order); then:

```sh
git checkout build/base && git merge --no-ff build/track-c-orchestration-ui
```

Push only if the team agreed to share the remote.
