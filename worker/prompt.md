# Triage one repository against a security advisory

You are triaging ONE repository in an isolated, sandboxed work copy. Your working
directory IS the work copy: it contains the service source under `src/`, its tests
under `tests/`, and `requirements.txt`. Around it (readable, not writable except as
noted):

- `../advisory.json` — the advisory facts: `id`, `package`, `affected_range`, `flawed_function`
- `../schema/verdict.schema.json` — the verdict contract (a copy of the repo schema)
- `../.venv/` — the offline venv; use `../.venv/bin/python` and `../.venv/bin/pip`
- `../wheelhouse/` — the offline package wheelhouse

## Rules (non-negotiable)

1. If the flaw is NOT reachable, change NOTHING in the repository. Put upgrade advice in `follow_ups`.
2. Never delete or weaken an existing test.
3. Never edit the installed library (anything under `../.venv/.../site-packages/`).

## Stages

1. **READ** the advisory facts (`../advisory.json`) and the installed library's source (it is in your venv).
2. **TRACE** from the service's own entry point toward the flawed function.
3. If no outside-controlled input can reach the flaw → verdict `not_affected`. The `reason` must say
   "no reachable path found" and `path` must cite the code path you followed, up to where it stops.
4. If reachable → **PROVE** it: write a test under `tests/` that sends the malicious/forged input
   through the service's own entry point and FAILS on the vulnerable version. Proof inputs must be
   harmless (e.g. a forged token that is accepted, or an empty marker file).
5. **FIX** by upgrade or patch, using ONLY the local wheelhouse:
   `../.venv/bin/pip install --no-index --find-links ../wheelhouse <package>==<version>`
6. **RE-VERIFY**: run the suite with `../.venv/bin/python -m pytest tests/ -q` from the work copy.
   The proof test must now PASS and all pre-existing tests must still pass → `affected_fixed`.
   If no fix makes the proof pass → `affected_proven`.

## Output contract

Write `verdict.json` at the work-copy root (`../verdict.json` relative to your cwd) matching
`../schema/verdict.schema.json` exactly. **Write it as soon as you have reached a verdict
decision (after stage 4, or after stage 6), then update it if later steps change anything** —
do not leave it to the very end: if the run hits its time limit, a written verdict is still
returned, an unwritten one is not. `proof` is a LIST of test IDs (e.g.
`tests/test_proof.py::test_forged_token_rejected`), each of which must FAIL on the vulnerable
version and PASS on the fixed version. Record test counts in `suite.before` / `suite.after`
(`passed` / `failed`). Any timeout, budget exhaustion or failed rule → write `needs_human` with
the reason.

Web tools are disabled. Do not attempt network access; the sandbox blocks it.
