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
- [ ] C7 integration (blocked: tracks A/B not merged into build/base) — blocked
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
