# Run contract (ticket 01)

This file is the single contract every other ticket codes against. The
executable form is the `vulnerability_agent` package (`src/vulnerability_agent/`):
`contract.py` pins the constants below, `schemas.py` loads/validates the JSON
schemas in `src/vulnerability_agent/schemas/`, and `runs.py` creates run
directories and work copies. Committed examples that validate against the
schemas live in `examples/contract/` and are exercised by `tests/`.

Do not redefine fields or locations in other tickets — reference this file.

## Layout

```
runs/                              git-ignored; committed fixtures live under fixtures/
└── <run>/                         run root
    ├── run.json                   run-level record (schema: run)
    ├── advisory.json              typed advisory (schema: advisory)
    ├── early-warning.md           report draft, filled from final states only
    └── <repo>/                    repo-run root
        ├── src/                   clean work copy of the fleet repository
        ├── proof/                 proof test(s), outside src/
        ├── venv/                  venv from the wheelhouse (worker env creates it)
        ├── gate/                  the gate's working folder, created fresh by the gate
        ├── verdict.json           agent-owned fields only (schema: verdict)
        ├── state.json             orchestrator-owned (schema: state)
        ├── fix.diff               computed by the orchestrator (diff of src/ vs the fleet copy)
        └── vibe/export.json       Vibe's own export (token usage, cost, outcome)
```

## run.json — run-level record (orchestrator-owned)

- `run_id`, `clock_start` (UTC, must end in `Z` — the 24 h clock starts here),
  `workflow_run_id` (the approve signal is sent to this ID),
- `paths`: `advisory` = `advisory.json`, `early_warning` = `early-warning.md`
  (relative to the run root),
- `fleet`: the manifest, one `{repo, source}` per repository; `source` is the
  read-only fleet copy the orchestrator clones work copies from (the agent
  cannot read it),
- `approved_at` / `expired_at` (nullable UTC timestamps). Approval belongs to
  the run, not to a repository; at 24 h without an approve signal the run is
  marked `expired` (via `expired_at`). These two fields live **only** in
  `run.json`.
- **No answer key in run.json** — the answer key is test-only and never wired
  into a run. The schema sets `additionalProperties: false`, and a test asserts
  that a document containing `answer_key` is rejected.

## advisory.json

`advisory_id`, `package`, `affected_version_range` (PEP 440 specifier set),
`fixed_version`, `flawed_function` (dotted path). Produced by the advisory
reader (one model call per run) and echoed verbatim into each `state.json`.

## verdict.json — agent-owned fields only

Written by the agent at `runs/<run>/<repo>/verdict.json`:

| Field | Holds |
| --- | --- |
| `verdict` | `not_affected` / `affected_proven` / `affected_fixed` / `needs_human` |
| `reason` | one paragraph; for `not_affected` it says "no reachable path found", never "safe" |
| `path` | list of `{file, line, note}` from the entry point to the flawed function, or to where the trail stops |
| `proof` | list of `{test_id, on_vulnerable, on_fixed}` (`fail`/`pass`); test IDs relative to the repo-run root |
| `fix` | `{kind: upgrade|patch|none, detail, diff_file: "fix.diff"}`; an upgrade changes the version pin inside `src/`, so `fix.diff` is not empty |
| `suite` | `{before: {passed, failed}, after: {passed, failed}}` |
| `follow_ups` | list of strings — other bugs found, never part of the verdict |

`additionalProperties: false` means the agent **cannot mark anything gated**:
no `status`, `gate`, `usage` or `final_at` may appear here (a test enforces
this). The grid and the report never read the verdict from this file.

## state.json — orchestrator-owned

Written at `runs/<run>/<repo>/state.json` by the orchestrator (or the gate for
the fields the gate sets):

- `status`: `running` | `final`
- `verdict`: the **final verdict** (required, with `final_at`, when `status` is
  `final`). The grid and the report read the verdict from `state.json`, never
  from `verdict.json`; `verdict.json` supplies only reason, path, proof, fix,
  suite and follow_ups.
- `repo`, `advisory` (echo of `advisory.json`, validated against the advisory
  schema)
- `gate`: per-rule results `[{rule, passed, detail}]`
- `final_at`: UTC timestamp set by whoever makes the state final — the gate,
  or the orchestrator for a `needs_human` it writes itself
- `usage`: copied from `vibe/export.json`
- `proof_output`: saved proof test output shown on the affected tile, keyed by
  test ID

The grid shows a tile only when `state.json` exists **and** its status is
`final`; the gate may set the verdict to `needs_human` and nothing else. If the
agent crashed and left no `verdict.json`, `state.json` alone is enough to render
a `needs_human` tile and a "not determined" report line (see
`examples/contract/search-svc/`, which has a `state.json` and no
`verdict.json`).

## Write locations and ownership

- The agent may write **only** inside `runs/<run>/<repo>/`: code changes under
  `src/`, proof test(s) under `proof/`, `verdict.json` at the repo-run root.
- `venv/` at `runs/<run>/<repo>/venv` (from the wheelhouse), so `src/` stays a
  clean copy and a `not_affected` no-diff check is "`src/` identical to the
  fleet copy".
- `runs/<run>/<repo>/gate/` is the gate's working folder, created fresh by the
  gate.
- `fix.diff` at the repo-run root is **computed by the orchestrator** (diff of
  `src/` vs the fleet copy; `src/` is not assumed to be a git repo, and the
  agent cannot read the fleet copy). When the fix is an upgrade, the agent
  changes the version pin inside `src/`, so `fix.diff` is not empty.

## Pinned proof-test invocation

- Command: `venv/bin/python -m pytest proof/ -q`
- Working directory: the repo-run root, `runs/<run>/<repo>/` (proofs live in
  `proof/`, outside `src/`).
- Proof test IDs (`verdict.json` `proof[].test_id`) and `path` entries
  (`verdict.json` `path[].file`) are **relative to the repo-run root** and may
  pass through the installed library (`venv/.../site-packages/...`), not only
  `src/`.

Pinned as `contract.PROOF_TEST_COMMAND` / `contract.PROOF_CWD`.

## Helper

`vulnerability_agent.runs` creates the layout and work copies:
`create_run(runs_root, run_id)` → `runs/<run>/`;
`create_repo_run(run_root, repo)` → `runs/<run>/<repo>/` with `src/` and
`proof/`; `make_work_copy(fleet_source, repo_run)` → copies the fleet repo
into `src/`; `write_run_json` / `write_advisory_json` / `write_verdict_json` /
`write_state_json` validate against the schemas before writing.

## Validating

```sh
uv run pytest          # examples validate against the schemas; helper behaviour
uv run mypy src/
```
