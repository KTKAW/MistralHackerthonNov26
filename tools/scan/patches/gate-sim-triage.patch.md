# Patch spec for track C: gate reads adversarial-sim feedback

Applies to `orchestrator/gate.py` on the `build/track-c-orchestration-ui` branch.
The Le Chonk design has one feedback-shaped extension point: the gate, which may
ONLY downgrade a verdict to `needs_human`. This patch uses exactly that.

## Change

In `gate(run_id, verdicts, ...)`, before returning, load the simulator's feedback
document if present:

```python
sim_path = Path(runs_root) / run_id / "sim-triage.json"
if sim_path.exists():
    sim = json.loads(sim_path.read_text())          # untrusted input: size-capped parse, malformed → ignore + log
    defenses = sim.get("defenses") or {}
    breaches = defenses.get("breaches") or []        # entries: {kind, detail}
    # advisory ids the simulator flagged for gate rules live in feedback.entries
    flagged = {e["advisory_id"] for e in (sim.get("feedback") or {}).get("entries", [])
               if e.get("type") == "gate-rule" and e.get("advisory_id") and not e.get("human_reviewed")}
    for v in verdicts:
        if v.get("advisory", {}).get("id") in flagged and v["verdict"] != "needs_human":
            v["gate"] = {**(v.get("gate") or {}),
                         "sim_triage": f"downgraded: adversarial sim breach ({len(breaches)} breach(es))"}
            v["verdict"] = "needs_human"   # the ONLY change the gate may make
```

## Contract with kb-scan's simulator workflow

Verified against `orchestrator/gate.py::_apply_sim_triage` (integration/scan-engine-le-chonk):
the gate reads exactly two things from the simulator's document.

- Simulator (`tools/scan/simulate.py`, workflow `adversarial_sim`) writes
  `runs/<run_id>/sim-triage.json` atomically, schema `sim-triage/1`:
  `{schema, simulated: true, marker: "SIMULATED", run_id, generated_at, out_dir, note,
    assertions[], defenses, metrics, feedback}` where the gate consumes
  - `defenses.breaches[]` — list of `{kind, detail}` (only its length is used, in the
    downgrade note), and
  - `feedback.entries[]` — `{type: gate-rule|watchlist, advisory_id, reason,
    proposed_by, human_reviewed}`; only `type == "gate-rule"` entries with a string
    `advisory_id` and falsy `human_reviewed` flag a verdict. Nothing is applied
    without human review.
  The document is assembled by `build_sim_triage_doc()` in simulate.py (single source
  of truth); `tools/scan/tests/test_sim_contract.py` feeds its output through the real
  gate to prove the contract.
- `watchlist`-type entries additionally become leads in `watchlist.md` ("Open leads"),
  in general terms only — sanitised (no advisory/fake ids, URLs, payloads or markup),
  deduped, marked SIMULATED + human review pending. Gate-rule/watchlist proposals are
  never auto-applied.
- Two workflows share the `runs/<run_id>/` folder and documents; no other coupling.
- Flood-proofing (enforced in the simulator, not here): hard cap on fakes per cycle
  (`--max-fakes`, default 25, hard max 100, clamped inside `build_fake_findings` too),
  all fakes carry `status: "unverified"` + `SIMULATED`, the breaches/feedback written
  into `sim-triage.json` are capped (`MAX_TRIAGE_BREACHES`), and fakes are quarantined
  in `sim-triage.json` — NEVER merged into the real `latest.json` / `triage.json` —
  so a nefarious actor cannot overload the autonomous agent with fake vulnerabilities.
  The gate treats `sim-triage.json` as untrusted input: parsed with size caps
  (`kbscan.MAX_BYTES`, 4 MiB — a 10k-entry oversized file is refused and ignored),
  malformed file → ignored + logged.
