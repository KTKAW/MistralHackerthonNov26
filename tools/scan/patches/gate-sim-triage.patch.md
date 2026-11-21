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
    sim = json.loads(sim_path.read_text())
    breached = {b["advisory_id"] for b in sim.get("breaches", []) if b.get("advisory_id")}
    for v in verdicts:
        if v.get("advisory", {}).get("id") in breached and v["verdict"] != "needs_human":
            v["gate"] = {**(v.get("gate") or {}),
                         "sim_triage": "downgraded: adversarial simulator breached this advisory id"}
            v["verdict"] = "needs_human"   # the ONLY change the gate may make
```

## Contract with kb-scan's simulator workflow

- Simulator (`tools/scan/simulate.py`, workflow `adversarial_sim`) writes
  `runs/<run_id>/sim-triage.json` atomically, schema:
  `{schema: "sim-triage/1", run_id, generated_at, fake_count, rejected, downgraded,
    injected_payloads_neutralised, verdicts_validated, breaches: [{advisory_id, kind, detail}]}`.
- Two workflows share the `runs/<run_id>/` folder and documents; no other coupling.
- Flood-proofing (enforced in the simulator, not here): hard cap on fakes per cycle
  (`--max-fakes`, default 25), all fakes carry `status: "unverified"` + `SIMULATED`,
  they are quarantined in `sim-triage.json` and NEVER merged into the real
  `latest.json` / `triage.json`, so a nefarious actor cannot overload the
  autonomous agent with fake vulnerabilities. The gate treats `sim-triage.json`
  as untrusted input: parsed with size caps, malformed file → ignored + logged.
