# simulate/ fixtures (SIMULATED test data only)

Fixtures for `tools/scan/simulate.py`, the adversarial-simulation agent for kb-scan.
Everything here is **SIMULATED** fake attack surface. Never point the real pipeline
at real feeds, `runs/` verdicts or `advisories/` with these.

- `adversarial_cases.json` — the fake findings (fake CVEs claiming ransomware,
  prompt-injection payloads, a bogus first-patched-version, a fake `MAL-` id), the
  fake sync doc claiming a branch moved, and a fake verdict mimicking
  `schema/verdict.schema.json` (as on `origin/build/base`). Loaded by
  `simulate.py generate`.
- `speak-stub.sh` — the `KB_SCAN_SPEAK_STUB` script: logs spoken text to
  `$SIM_STUB_LOG` instead of calling any model API.

## --from-inventory mode

`simulate.py generate/run/loop --from-inventory` reads `tools/scan/inventory.json`
(packages carry a `source` lockfile path) and adds high-fidelity fakes that mimic
attacks on our own stack: a fake `MAL-` id naming a real `package@version`, a fake
KEV entry for a plausible CVE affecting one of our products, and an injection
payload in a finding whose package matches a real inventory entry. Each keeps
`status:'unverified'` + a SIMULATED marker and points `source` at the real lockfile
it impersonates. Assertions (a)/(e)/(i) prove such fakes are never confirmed, never
alerted and never reach `serve /brief`; `sim-triage.json` gains a `feedback` section
of proposed, human-reviewed gate-rule/watchlist entries (`human_reviewed: false`).

Generated artifacts land only under the test out-dir (default
`tools/scan/out/simulate/`); the single workflow-facing output is the clearly
marked `runs/<run_id>/sim-triage.json`.

## Contract with the Le Chonk gate

`sim-triage.json` (schema `sim-triage/1`, written atomically) is consumed by
`orchestrator/gate.py::_apply_sim_triage` via `orchestrator/kbscan.sim_triage_for_run`,
which reads exactly `defenses.breaches[]` and `feedback.entries[]`
(`{type: gate-rule|watchlist, advisory_id, reason, proposed_by, human_reviewed}`).
`simulate.py` builds the document in `build_sim_triage_doc()`;
`tools/scan/tests/test_sim_contract.py` proves the contract against the real gate,
proves a 10k-entry oversized `sim-triage.json` is size-capped and ignored, and checks
the `watchlist.md` leads (general terms only). Run them with:

    uv run pytest -q tools/scan/tests/test_sim_contract.py
    python3 tools/scan/simulate.py selftest
