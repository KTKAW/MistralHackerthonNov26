# Plan — Sandbox Audit Console (`worker/ui.py`)

A local web GUI for Track A: watch sandboxed per-repo workers, audit every hook
decision, inspect verdicts/proofs, and poke the sandbox from a playground.
Track C's grid (`web/app.py`, :8000) stays the outward-facing report UI; this
console is the *inside-the-sandbox* view and lives entirely in `worker/`
(track A's owned scope). Track C can later link to it per repo tile.

## 1. Goals / non-goals

Goals:
- See every run (`runs/<run_id>/<repo>/`) as a card: verdict, cost, duration, status.
- Live audit of `hook.log` (JSONL): every `bash`/`process_start` rewritten through
  `douane`, every `deny`, plus "douane coverage %" (A5 target: 100%).
- Verdict detail: reachability `path` as a clickable file:line chain, `proof` test
  IDs, `suite` before/after bars, `fix`, `follow_ups`, `vibe/export.json` stats.
- Work-copy integrity: `git status`/`git diff` of `src/` (flag deleted tests red —
  violates rule "never delete/weaken a test").
- Controls: start a self-test run, validate a verdict against the schema, SIGTERM
  a stuck run, and a **playground** that fires the A3 probes through `douane`.
- Policy viewer: the effective Seatbelt profile + `douane` source.

Non-goals: no report rendering/approve flow (track C), no model calls from the
UI, no writes into any work copy, no serving of `vibe-home/` or `.env`.

## 2. Stack & constraints

- **FastAPI + uvicorn + starlette only** — all already in `wheelhouse/`
  (offline `pip --no-index --find-links wheelhouse`). No textual/rich in the
  wheelhouse, so a TUI is out; web it is.
- Frontend: one static page (`worker/static/index.html` + `app.js` + `style.css`),
  vanilla JS, no CDN, no build step. 2 s polling for cards (same pattern as
  track C), **SSE** for the hook.log tail and run stdout.
- Port **8001** (track C owns 8000). Runs root from env `LE_CHONK_RUNS_ROOT`,
  default `<repo>/runs` — same variable name as track C for consistency.
- **Do not modify `worker/run_repo.py`** (pinned contract). The UI launches it as
  a subprocess (`python worker/run_repo.py <run_id> <repo>`) so the process can be
  signalled as a group.
- The UI applies the same confinement rules as `path_hook` to its own file
  endpoint: refuse any path containing `.env` / `secrets`, confine reads to the
  selected run's work dir under `runs/`.
- macOS-only playground (`sandbox-exec`); tests skip it off-darwin.

## 3. Data sources (all on disk already)

| Data | Path |
|---|---|
| Runs index | `runs/<run_id>/<repo>/` directories |
| Verdict | `runs/<run_id>/<repo>/verdict.json` (schema in `schema/verdict.schema.json`) |
| Tokens/cost/outcome | `runs/<run_id>/<repo>/vibe/export.json` |
| Hook audit | `runs/<run_id>/<repo>/hook.log` (JSONL: rewrite/allow/deny/error) |
| Advisory | `runs/<run_id>/<repo>/advisory.json` |
| Work copy + diff | `runs/<run_id>/<repo>/src/` (git repo, baseline commit) |
| Policy | `sandbox/profile.sb.template`, `sandbox/douane` |
| Run meta (UI-written) | `runs/<run_id>/run.json` — same key track C's `_run_meta` reads |

## 4. Backend API (`worker/ui.py`)

- `GET /` → static index page
- `GET /api/runs` → list of cards: `{run_id, repo, status, verdict, cost_usd,
  tokens, started_at, douane_pct, deny_count}`
- `GET /api/runs/{run_id}/{repo}` → full detail: advisory, verdict, export,
  hook stats, git status summary
- `GET /api/runs/{run_id}/{repo}/hooklog` → **SSE** stream of new hook.log lines
  (`?since=<byte-offset>` for resume)
- `GET /api/runs/{run_id}/{repo}/file?path=…` → file text, confined to the work
  copy; refuses `.env`/`secrets`/traversal (mirrors `path_hook`)
- `GET /api/runs/{run_id}/{repo}/diff` → `git status --porcelain` + `git diff` of `src/`
- `POST /api/runs` `{run_id?, repo}` → starts `python worker/run_repo.py …` in a
  background process group, writes `runs/<run_id>/run.json`
  `{run_id, repo, started_at, pid, status, ui:true}`; returns run_id
- `POST /api/runs/{run_id}/stop` → SIGTERM the process group (Vibe stops cleanly
  and still writes `export.json`)
- `POST /api/runs/{run_id}/{repo}/validate` → runs `python schema/validate.py
  …/verdict.json`, returns `{ok, output}`
- `POST /api/playground` `{cmd}` → runs `sandbox/douane '<cmd>'` with
  `SANDBOX_WORKDIR=runs/ui-scratch/<id>` (gitignored, under `runs/`), returns
  `{rc, stdout, stderr}`; canned A3 probes offered in the UI
- `GET /api/policy` → rendered Seatbelt profile (placeholders substituted against
  the scratch workdir) + `douane` source

In-memory registry maps run_id → {pid, proc, status, thread}; state is
recoverable on restart by scanning `runs/` + `run.json`.

## 5. Frontend views (tabs in one page)

1. **Runs** — card grid, polls `/api/runs` every 2 s; color-coded verdict badges;
   "douane 100%" chip per card.
2. **Run detail** — pipeline strip (advisory → work copy → .venv → vibe →
   verdict, status per stage), verdict panel (reason, path chain with file:line
   links → file viewer modal, proof IDs, before/after suite bars, fix,
   follow-ups, export stats), git diff panel (added/modified/deleted, deleted
   test files highlighted red), live hook audit table (original vs rewritten,
   deny rows red) fed by SSE, and buttons: Validate · Stop · Re-run.
3. **Playground** — command input + one-click A3 probes
   (`curl -s https://example.com` → denied, `touch ../escape` → denied,
   `cat .env` → denied, `touch /tmp/ok` → allowed, offline `pip --no-index` →
   works); result rendered with rc/stdout/stderr.
4. **Policy** — effective Seatbelt profile + `douane` source, syntax-tinted.

## 6. Implementation steps (commit after each, heredoc format from COORDINATION.md)

- [x] **G1 — skeleton.** `worker/ui.py` with app factory, `GET /api/health`,
      static mount, port 8001; `worker/static/index.html` placeholder. Run it with
      the wheelhouse venv; commit.
- [x] **G2 — runs scanner + read API.** `GET /api/runs`, `GET /api/runs/{id}/{repo}`
      (verdict/export/advisory/hook stats/git summary). Commit.
- [x] **G3 — frontend shell.** Tabs + runs grid with 2 s polling + verdict badges.
      Commit.
- [x] **G4 — live hook audit.** SSE endpoint tailing `hook.log`; audit table with
      original→rewritten, deny highlighting, douane-coverage % chip. Commit.
- [x] **G5 — verdict & diff views.** Run-detail tab: path chain, file viewer
      (confined, `.env` refused), suite bars, git diff panel. Commit.
- [x] **G6 — controls.** `POST /api/runs` (subprocess + `run.json` + pid),
      `/stop` (SIGTERM process group), `/validate`. Commit.
- [x] **G7 — playground + policy.** `POST /api/playground` via `douane` in
      `runs/ui-scratch/`, A3 probe buttons, `GET /api/policy`. Commit.
- [x] **G8 — tests + e2e.** `tests/test_ui.py` (starlette TestClient + httpx,
      both in wheelhouse): seed a fake `runs/` in tmp_path; assert card API,
      file-endpoint refusals (`.env`, `..` traversal), validate endpoint, playground
      deny of `curl` (skipUnless darwin). Then one real pass:
      start `selftest` from the UI, watch SSE, validate verdict, stop mid-run once
      to confirm clean SIGTERM + `export.json`. Record results per A6. Commit.

## 7. Verification / done-when

- `GET /api/runs` shows `runs/selftest/selftest` after the A5 self-test, with
  `douane_pct == 100` and the deny rows from A3-visible events.
- File endpoint refuses `advisory.json/../../vibe-home/.env` and any `.env` path.
- `POST …/validate` on `runs/selftest/selftest/verdict.json` returns ok (matches A5).
- Playground: `curl` denied, `touch ../escape` denied, `cat .env` denied,
  `touch /tmp/ok` allowed, offline pip works (mirrors A3).
- `tests/test_ui.py` passes with the wheelhouse venv.
- No changes to `run_repo.py`'s signature, `schema/`, `web/`, `fleet/`; nothing
  committed from `runs/`, `vibe-home/`, `wheelhouse/`, `.env`.

## 8. Demo script (hackathon, ~3 min)

1. Open :8001 → Runs tab → click the selftest card.
2. Run-detail tab: watch the hook audit stream live while the worker runs —
   point at a deny row ("the agent tried X, the sandbox refused").
3. Click a path-chain entry → file viewer shows the work-copy source at that line.
4. Playground tab → fire `curl -s https://example.com` → red "denied (network*)";
   `touch /tmp/ok` → green allowed.
5. Validate button → schema check passes; show cost/tokens from `export.json`.

## 9. Risks

- **Port clash with track C** → 8001 + env override `LE_CHONK_UI_PORT`.
- **Long runs block the UI thread** → run_repo always as a subprocess; UI never
  blocks; SSE tail is a non-blocking async generator.
- **hook.log grows unbounded** → SSE reads by byte offset; cap rendered rows in
  the frontend (last 500).
- **UI leaking secrets** → file endpoint mirrors path_hook denies; never mount
  `vibe-home/`; policy view renders the *scratch* workdir, not a real run.
- **run.json format drift with track C** → only write keys track C already reads
  (`run_id`, `started_at`) plus additive `ui` keys.
