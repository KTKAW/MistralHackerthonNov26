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

Generated artifacts land only under the test out-dir (default
`tools/scan/out/simulate/`); the single workflow-facing output is the clearly
marked `runs/<run_id>/sim-triage.json`.
