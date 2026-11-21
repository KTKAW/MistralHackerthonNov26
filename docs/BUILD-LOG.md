# BUILD LOG — track A (sandbox + per-repo worker)

Branch `build/track-a-sandbox-worker`. Machine: macOS 26.3 (Darwin 25.3.0, arm64), 2026-11-21.
Repo: `/Users/kymani/Documents/nov26hack/track-a-sandbox-worker`.

## A1 — isolated Vibe home

- `vibe-home/` created (gitignored). Vibe **pinned to 3.1.3** by installing
  `mistral-vibe==3.1.3` into `vibe-home/tool-venv` (uv, python 3.14) and putting
  `vibe-home/tool-venv/bin` first on `PATH` in `run_repo.py`.
  `VIBE_HOME=$PWD/vibe-home PATH=... vibe --version` → **vibe 3.1.3**.
  (The machine-wide CLI is 3.1.4 — deliberately not used for workers.)
- API key: none pasted; Vibe reads `MISTRAL_API_KEY` from the **macOS Keychain** at
  startup, so `vibe-home/.env` was not needed on this machine and was not created.
  `enable_telemetry/enable_otel = false` in `vibe-home/config.toml`; `OTEL_ENABLED=false`
  in every worker env.
- vibe 3.1.3 migrated `config.toml` on first run (`bash_read_only_defaults_v1`): read-only
  commands are allowlisted by default; the absolute `sandbox/douane` path stays in
  `[tools.bash] allowlist` so rewritten commands never stop for approval.
- Worker model config: `mistral-large-4-0` with `thinking = "low"` (see A5 note).

## A2 — sandbox files + registration

- `sandbox/sandbox2.py` — `pre_tool` hook, `match = 're:bash|process_start|process\.start'`,
  `strict = true`. Reads the Vibe 3.1.3 wire protocol (JSON on stdin, `tool_name` qualified,
  `tool_input.command`), rewrites to `<abs douane> '<shquoted>'` via
  `{"decision":"allow","hook_specific_output":{"tool_input":...}}`; denies empty/unparseable
  (strict → deny on crash too). Logs every decision as a JSON line to `$HOOK_LOG`.
- `sandbox/douane` — `env -i` scrubbed env + `sandbox-exec -f <generated profile> /bin/bash -c "$*"`;
  substitutes `__WORKDIR__`, `__PYDIR__`, `__VIBEHOME__` (realpath-normalized — Seatbelt
  matches realpaths, `/tmp` → `/private/tmp`).
- `sandbox/profile.sb.template` — Seatbelt profile, **adapted to macOS 26.3** (see below).
- `sandbox/path_hook.py` — `pre_tool`, `match = 're:read_file|write_file|edit'`, `strict = true`.
  Writes only under `$SANDBOX_WORKDIR/src/` plus `$SANDBOX_WORKDIR/verdict.json`; reads never
  `.env` (anywhere) or `secrets/`, work copy + narrow system paths only. Same wire protocol.
- Registered in `vibe-home/hooks.toml` (both hooks) + `vibe-home/config.toml` (douane allowlist).

## A3 — manual sandbox tests (all pass)

With a scratch work copy (`SANDBOX_WORKDIR` pointed at it), via `sandbox/douane`:

| Test | Result |
|---|---|
| `curl -s https://example.com` | **denied** (network*) |
| `touch ../escape` | **denied** (write outside work copy, EPERM) |
| `cat .env` (in workdir) / `cat /tmp/x/.env` / vibe-home contents | **denied** |
| `touch /tmp/ok` | **allowed** |
| `cat README.md`, `touch inside.txt` in workdir | **allowed** |
| `pip install --no-index --find-links wheelhouse authlib==1.8.0` into the work venv, offline, in-sandbox | **works** (authlib 1.8.0 imports) |
| env scrubbed (`MISTRAL_API_KEY` empty inside) | **yes** |

Hook unit tests (payload piped on stdin, as Vibe does): bash/process_start rewritten,
non-shell pass-through, empty command denied; path_hook allows/denies per the table above.
Full suite in `tests/`: **80 passed**.

### macOS 26.3 Seatbelt adaptation (important)

- `(deny default)` + `(allow process-exec*)` + only narrow `file-read*` subpaths makes the
  sandboxed child **die with SIGABRT** at startup on this build. Multiple `(subpath ...)`
  filters in one rule are ANDed, so per-directory rules are required — and even then the
  child aborts unless reads are effectively broad. Final profile: `(allow file-read* (subpath "/"))`
  + deny rules carving out secrets (deny wins over allow):
  any `/.env` (regex), `$WORKDIR/secrets`, `$VIBE_HOME` (holds the key), `~/.vibe`,
  `/private/dev/urandom`. Writes remain confined: work copy + `/private/tmp` + `/private/var/tmp`
  + `/dev/null` only.
- Use realpaths in filters (`/private/tmp`, not `/tmp`).

## A4 — throwaway service + worker

- `runs/selftest/src/` (gitignored): tiny FastAPI service, `POST /token` →
  `auth.py::verify_token` → `JsonWebSignature.deserialize_json`, pinned `authlib==1.8.0`,
  one pytest test. Hand-verified on this machine: suite passes on 1.8.0; forged
  empty-`signatures` token → **200 on 1.8.0, 401 on 1.9.0**; suite passes on 1.9.0.
- `worker/prompt.md` — 3 rules + read→trace→prove→fix→re-verify + verdict contract;
  reads `../advisory.json`, writes `../verdict.json`; offline wheelhouse at `../wheelhouse`;
  efficiency note + "write verdict.json as soon as the verdict is decided".
- `worker/run_repo.py` — pinned signature kept:
  `run_repo(run_id, repo, *, fleet_root="fleet", runs_root="runs", vibe_home="vibe-home", heartbeat_fn=None)`.
  Produces `runs/<run>/<repo>/src` (fresh copy + git baseline), `.venv` (offline, py3.12),
  `wheelhouse/` + `schema/` copies, `advisory.json`, then runs the pinned vibe command line
  verbatim with `SANDBOX_WORKDIR=<work root>`, `HOOK_LOG`, `VIBE_HOME`, `OTEL_ENABLED=false`,
  `PATH` pinned to the 3.1.3 tool-venv; 10 s heartbeat thread; returns
  `{"repo","rc","verdict","export"}`.

## A5 — end-to-end self-test: `run_repo("selftest", "selftest")` — PASS

Result: `rc=0`, verdict **`affected_fixed`**, `export.json` outcome `finished` (vibe 3.1.3,
29 steps, 588k tokens, $0.08).

| Check | Result |
|---|---|
| shell commands through douane | **27/27 = 100%** (hook.log: every bash/process_start rewritten) |
| file-tool denials fired | yes — 1 in-vivo `path_hook` deny (read outside work copy); unit tests cover .env/secrets/outside writes |
| `schema/validate.py runs/selftest/selftest/verdict.json` | **OK** (valid vs verdict.schema.json) |
| `runs/selftest/selftest/vibe/export.json` | exists (tokens, cost, outcome, vibe_version 3.1.3) |
| work-copy `git status` | clean apart from agent-written `tests/test_proof.py` |
| proof test semantics | `tests/test_proof.py::test_empty_signatures_forged_token_rejected` **fails on authlib 1.8.0** (forged token → 200), **passes on 1.9.0** (401); suite 2 passed on 1.9.0 |
| verdict content | path entry point → `auth.py` → `authlib/jose/.../jws.py` flawed branch; fix upgrade authlib==1.9.0 from wheelhouse |

Notes / adaptations:
- First three runs hit the pinned `--time-limit 560` (outcome `deadline`) before writing
  verdict.json; fixed by (a) prompt: write `../verdict.json` immediately after the verdict
  decision + minimize tool calls, (b) `thinking = "low"` for the worker model in
  `vibe-home/config.toml`. The pinned vibe command line itself was kept verbatim.
- `SANDBOX_WORKDIR` = work-copy root `runs/<run>/<repo>` (contains `src/`); seatbelt confines
  shell writes to it, path_hook confines file tools to its `src/` + `verdict.json`.
- run_repo template resolution: `fleet/<repo>`, else a pre-seeded throwaway at
  `runs/<run_id>/src` (used by the selftest). Wheelhouse: copied from track B's local
  `wheelhouse/` (gitignored, per-machine) and hard-copied into each work root so it is
  readable inside the sandbox.

## A6 — this log. Done when: A3 + A5 pass and verdict.json validates — met.

## Not done / follow-ups

- Key never touched disk: workers authenticate via the macOS Keychain. On a machine without
  a keychain key, put `MISTRAL_API_KEY` in `vibe-home/.env` (gitignored) or export it.
- 10-parallel rate limits untested (out of track A scope).
- Linux `bwrap` out of scope per plan.
# BUILD LOG — track C (orchestrator, gate, report, web UI)

Branch: `build/track-c-orchestration-ui`. Owns `orchestrator/`, `web/`, `docs/BUILD-LOG.md`.

## 2026-11-21 — setup

- Cloned branch into `Documents/nov26hack/track-c-orchestration-ui` (single-branch, like tracks A/B).
- Env: `uv` project created (`pyproject.toml`, requires-python >=3.12,<3.15 —
  `mistralai-workflows==3.20.0` requires it). Added `mistralai-workflows==3.20.0`,
  `fastapi`, `uvicorn`, `jsonschema`.
- SDK check (3.20.0, Temporal-based): `@workflow.define(name=..., execution_timeout=...)`
  on a class with `@workflow.entrypoint`; `@workflow.signal(name="approve")`;
  `workflow.wait_condition(pred, timeout=...)`; `@activity(start_to_close_timeout=...,
  heartbeat_timeout=..., retry_policy_max_attempts=1)` on module-level functions —
  inside a workflow the decorated fn is awaited directly and starts the activity;
  `activity_heartbeat(...)`; worker entry `workflows.run_worker([LeChonkRun])`
  (needs `MISTRAL_API_KEY` + `DEPLOYMENT_NAME`, config discovery at startup).
  Client: `client.workflows.execute_workflow(workflow_identifier=..., execution_id=...,
  input={...}, deployment_name=...)`; signal via
  `client.executions.signal_workflow_execution(execution_id=..., name="approve")`.
- `MISTRAL_API_KEY` is NOT in the shell env; it lives in the macOS login keychain
  (service `ai.mistral.vibe`, account `MISTRAL_API_KEY`) and is exported inline when
  needed — never written to disk, never committed. `DEPLOYMENT_NAME` is unset, so the
  hosted worker cannot run here → local fallback orchestrator (C8) is the testable
  path; hosted path is implemented against the SDK above and runs at the venue.
- CRA Art. 14 checked against EUR-Lex consolidated 02024R2847-20241120:
  Art. 14(2)(a) early warning within 24 h indicates, where applicable, the Member
  States where the product has been made available; Art. 14(2)(b) 72 h notification
  adds product info, nature of exploit/vulnerability, corrective/mitigating measures
  taken and for users. Quoted in `orchestrator/report.py` accordingly.
- Remote state: `build/base` == track-c == track-a at 251be3a; track-b ahead at
  7b119b6. Tracks A and B are NOT merged into build/base yet → C7 integration is
  blocked; C6 runs against /tmp stubs per the prompt's stub strategy.

## Steps

- [x] C1 workflow.py — implemented (`define_hosted_workflow`, `run_local`, `resume_pending`)
- [x] C2 gate.py — implemented; unit-tested in `tests/test_gate.py`
- [x] C3 report.py — implemented; unit-tested in `tests/test_report.py`
- [x] C4 web/app.py — implemented; unit-tested in `tests/test_web_app.py`
- [ ] C5 worker process — pending (needs DEPLOYMENT_NAME at venue)
- [x] C6 stub test — `tests/test_workflow.py::TestRunLocal::test_full_local_run_with_stubs` drives the full local pipeline against /tmp stubs
- [ ] C7 integration (A/B merged into `build/base` @ 62c590c — blocker lifted; stub-precedence
  fix applied, see 2026-11-21 note below) — pending real e2e run
- [x] C8 fallback — implemented as `run_local` in workflow.py; exercised by C6

## Unit tests (2026-11-21)

- Added `pytest` + `httpx` as dev dependencies; `[tool.pytest.ini_options]` in `pyproject.toml`.
- `tests/` — 139 unit tests, all passing (`.venv/bin/python -m pytest tests/`):
  - `test_schema_validate.py` (32 tests) — schema contract: required fields, verdict enum,
    proof-must-be-a-list, path items, suite counts, fix field, CLI exit codes against
    `examples/verdict.example.json` (valid) and `examples/verdict.bad.json` (invalid).
  - `test_gate.py` (31 tests) — `_run` never raises; `_tree_digest` skips .venv/__pycache__/.git
    and allowlisted names; `_fixed_pins`; `gate_passed`; `gate()` for all four verdict types;
    downgrade-only invariant (needs_human stays needs_human, bogus proof that passes on the
    vulnerable version is downgraded); suite-count-not-dropped; no_src_changes for not_affected;
    verdict written back to disk.
  - `test_report.py` (22 tests) — `render_early_warning` writes early-warning.md; advisory info,
    24 h clock, member states, gate-passed-only filtering, needs_human in separate section,
    proof tests / fix status / evidence path rendered, timeline, human-review disclaimer,
    minutes-left clamped to 0 past 24 h.
  - `test_workflow.py` (24 tests) — `_write_json`/`_read_json`, `list_repos`, stub-mode
    `read_advisory` (CVE extraction, env override), `intake`, `_set_status`, `wait_for_approve`
    (file, status, timeout, mid-wait arrival), `_collect_verdicts`, `get_run_repo` stub loading,
    `triage_one` with heartbeat, full `run_local` end-to-end with stubs, `resume_pending`, CLI.
  - `test_web_app.py` (15 tests) — FastAPI TestClient: GET / HTML grid, POST /runs (validation,
    local-mode run dir creation), GET /runs/{id} (tiles only for gate-passed repos, reason
    truncated to 280 chars, tile fields), POST /runs/{id}/approve (local mode writes approved
    file + updates status), `_gate_ok` helper, `start_run` unit-level.

## 2026-11-21 — post-merge fix: stub precedence in `get_run_repo()`

Tracks A+B are merged into `build/base` (62c590c), so `from worker.run_repo import
run_repo` now succeeds and the old worker-first precedence broke 4 stub-assumption
tests in `tests/test_workflow.py` when run on the merged base
(`test_stub_run_repo_loaded`, `test_no_stub_raises`, `test_calls_run_repo_with_heartbeat`,
`test_full_local_run_with_stubs`). Fix: explicit stub mode (`LE_CHONK_STUBS=1` +
`LE_CHONK_STUB_RUN_REPO=<file>`) now **wins over** the real worker — the C6 stub tests
rely on that; worker-first applies only when stub mode is off. `test_no_stub_raises`
now simulates the unmerged state via `sys.modules` and matches the new error message;
added `test_worker_preferred_when_available` (runs only when worker/ is importable).
Verified both worlds: C clone 139 passed + 1 skip; simulated merge (base 62c590c +
orchestrator/+web/) 300 passed with 0 workflow failures (remaining 23 failures are the
known environmental ones needing gitignored vibe-home/ + wheelhouse/).
