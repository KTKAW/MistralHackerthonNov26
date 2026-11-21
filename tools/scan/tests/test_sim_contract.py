"""Simulator <-> gate contract tests (SIMULATED harness; tools/scan/tests/).

Proves, against the REAL orchestrator code (never a copy):
  1. the sim-triage.json document simulate.py writes is consumed by
     orchestrator/gate.py::_apply_sim_triage exactly as the contract says
     (defenses.breaches[], feedback.entries[] with type gate-rule|watchlist,
     advisory_id, human_reviewed) — zero drift between simulator and gate;
  2. flood-proofing: a 10 000-entry sim-triage.json pushed past the reader's size
     cap is ignored by the gate path entirely (no downgrade, no crash), and
     sim-triage content is never merged into latest.json/triage.json;
  3. watchlist-type entries become general-terms-only leads in watchlist.md.

Run: uv run pytest -q tools/scan/tests/test_sim_contract.py
"""
import json
from pathlib import Path

import pytest

import simulate  # tools/scan/simulate.py (sys.path set by conftest.py)
from orchestrator import gate, kbscan


def _verdict(advisory_id: str, verdict: str = "affected_proven") -> dict:
    return {"repo": "billing-api", "verdict": verdict,
            "advisory": {"id": advisory_id, "package": "authlib",
                         "affected_range": "<1.9.1", "flawed_function": "parse"},
            "gate": {"passed": True, "rules": {}}}


def _write(path: Path, data) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


# ---------------------------------------------------------------- contract

def test_simulator_triage_doc_is_consumed_by_the_real_gate(tmp_path):
    """build_sim_triage_doc() output -> runs/<run_id>/sim-triage.json -> the gate:
    an unreviewed gate-rule entry downgrades its advisory to needs_human (the only
    change the gate may make); human_reviewed and watchlist entries change nothing."""
    misses = [{"kind": "assertion-a", "detail": "fake MAL-2026-9999 confirmed"}]
    doc = simulate.build_sim_triage_doc(
        "run-sim", "/tmp/sim", [], misses, ["MAL-2026-9999"], ["MAL-2026-9998"],
        fakes_generated=1, rejected=1, downgraded=0, neutralised=4, verdicts_validated=0)
    # structural contract: exactly the keys the gate reads
    assert doc["schema"] == "sim-triage/1" and doc["simulated"] is True
    assert isinstance(doc["defenses"]["breaches"], list)
    assert all({"kind", "detail"} <= set(b) for b in doc["defenses"]["breaches"])
    entries = doc["feedback"]["entries"]
    assert all({"type", "advisory_id", "reason", "proposed_by", "human_reviewed"} <= set(e)
               for e in entries)
    assert {e["type"] for e in entries} == {"gate-rule", "watchlist"}

    # feed it through the real gate path
    run_dir = _write(tmp_path / "runs" / "run-sim" / "sim-triage.json", doc).parent
    assert kbscan.sim_triage_for_run("run-sim", tmp_path / "runs") == doc  # under cap: parsed
    gated = [_verdict("MAL-2026-9999"), _verdict("MAL-2026-9998"), _verdict("CVE-2026-1111")]
    gate._apply_sim_triage(run_dir, gated)
    # gate-rule entry (MAL-2026-9999, unreviewed) downgrades — and only that one
    assert gated[0]["verdict"] == "needs_human" and "sim_triage" in gated[0]["gate"]
    # watchlist-only entry (MAL-2026-9998) must NOT downgrade
    assert gated[1]["verdict"] == "affected_proven"
    assert gated[2]["verdict"] == "affected_proven"

    # a human-reviewed gate-rule entry is ignored by the gate
    doc2 = simulate.build_sim_triage_doc("run-sim", "/tmp/sim", [], [], [], [], 0, 0, 0, 0, 0)
    doc2["feedback"]["entries"] = [{"type": "gate-rule", "advisory_id": "CVE-2026-1111",
                                    "reason": "r", "proposed_by": "simulate", "human_reviewed": True}]
    run_dir2 = _write(tmp_path / "runs" / "run-sim2" / "sim-triage.json", doc2).parent
    gated2 = [_verdict("CVE-2026-1111")]
    gate._apply_sim_triage(run_dir2, gated2)
    assert gated2[0]["verdict"] == "affected_proven"


# ---------------------------------------------------------------- flood-proofing

def test_10k_entry_sim_triage_is_size_capped_and_ignored_by_gate_path(tmp_path):
    """A 10 000-entry sim-triage.json pushed past kbscan.MAX_BYTES is refused by the
    size-capped reader and therefore ignored by the gate: no verdict changes."""
    runs_root = tmp_path / "runs"
    run_dir = runs_root / "run-flood"
    run_dir.mkdir(parents=True)
    # 10 000 gate-rule entries, each padded so the file is well past the 4 MiB cap
    pad = "x" * 600
    entries = [{"type": "gate-rule", "advisory_id": f"CVE-2026-{i:04d}",
                "reason": pad, "proposed_by": "simulate", "human_reviewed": False}
               for i in range(10_000)]
    doc = {"schema": "sim-triage/1", "simulated": True, "marker": "SIMULATED", "run_id": "run-flood",
           "defenses": {"breaches": [{"kind": "flood", "detail": pad}] * 10_000},
           "feedback": {"entries": entries}}
    sim_path = _write(run_dir / "sim-triage.json", doc)
    assert sim_path.stat().st_size > kbscan.MAX_BYTES  # 10k entries blow past the 4 MiB cap

    # size-capped reader refuses it -> the gate sees nothing
    assert kbscan.sim_triage_for_run("run-flood", runs_root) == {}
    gated = [_verdict("CVE-2026-0000"), _verdict("CVE-2026-9999")]
    gate._apply_sim_triage(run_dir, gated)
    assert all(v["verdict"] == "affected_proven" for v in gated)
    assert all("sim_triage" not in (v.get("gate") or {}) for v in gated)

    # quarantine: sim-triage content is never merged into the real latest.json
    latest = _write(tmp_path / "scan-out" / "latest.json",
                    {"schema": "kb-scan-report/1", "findings": [{"cve": "CVE-2026-1111"}]})
    import os
    os.environ["KB_SCAN_OUT_DIR"] = str(latest.parent)
    try:
        merged = kbscan.latest()
    finally:
        os.environ.pop("KB_SCAN_OUT_DIR", None)
    assert [f.get("cve") for f in kbscan.findings(merged)] == ["CVE-2026-1111"]
    assert "SIMULATED" not in json.dumps(merged)


def test_simulator_never_writes_past_its_caps(tmp_path):
    """The simulator's own flood-proofing: --max-fakes clamps to the hard cap, every
    fake stays unverified+SIMULATED, and the written sim-triage doc stays small."""
    cases = simulate.load_cases()
    fakes = simulate.build_fake_findings(cases, 10_000, from_inventory=True)
    assert len(fakes) == simulate.MAX_FAKES_HARD_CAP  # clamped, not 10k
    assert all(f.get("status") == "unverified" and f.get("simulated") and f.get("marker") == simulate.MARKER
               for f in fakes)
    misses = [{"kind": f"k{i}", "detail": "d" * 200} for i in range(5_000)]
    doc = simulate.build_sim_triage_doc("run-cap", "/tmp/sim", [], misses, [], [],
                                        1, 1, 0, 0, 0)
    assert len(doc["defenses"]["breaches"]) == simulate.MAX_TRIAGE_BREACHES
    assert len(json.dumps(doc).encode("utf-8")) < kbscan.MAX_BYTES  # stays under the gate's cap
    # quarantine: generate writes only under the given out-dir
    out = tmp_path / "sim-out"
    assert simulate.cmd_generate(out, "run-cap", max_fakes=25, from_inventory=True) == 0
    written = {p for p in out.rglob("*") if p.is_file()}
    assert written and all(out in p.parents for p in written)
    for p in written:
        if p.suffix == ".json":
            assert simulate.MARKER in p.read_text(encoding="utf-8") or p.name == "manifest.json"
    assert not list(out.rglob("*.tmp"))  # atomic writes leave no temp files


# ---------------------------------------------------------------- watchlist leads

def test_watchlist_entries_become_general_terms_leads_only(tmp_path):
    wl = tmp_path / "watchlist.md"
    wl.write_text("# Watchlist\n\n## Open leads\n\n- **An existing lead.** Something.\n", encoding="utf-8")
    entries = [
        {"type": "watchlist", "human_reviewed": False,
         "reason": "SIMULATED high-fidelity fake MAL-2026-9998 targeted a real inventory entry at "
                   "http://evil-sim.invalid/p <script>alert(1)</script> [click](http://evil-sim.invalid) CVE-2026-99101"},
        {"type": "gate-rule", "advisory_id": "MAL-2026-9999", "human_reviewed": False},  # not a lead
        {"type": "watchlist", "advisory_id": "X", "human_reviewed": True},                # reviewed: skip
    ]
    added = simulate.append_watchlist_leads(entries, "run-wl", "2026-11-21T00:00:00Z", path=wl)
    assert added == 1
    text = wl.read_text(encoding="utf-8")
    leads_section = text.split("## Open leads", 1)[1]
    lead = next(l for l in leads_section.splitlines() if l.startswith(simulate.LEAD_PREFIX))
    # general terms only: no fake ids, no URLs, no markup, no link syntax
    for banned in ("MAL-", "CVE-", "http", "<script>", "[click]", "evil-sim.invalid"):
        assert banned not in lead
    assert "SIMULATED" in lead and "human review pending" in lead
    assert "- **An existing lead.**" in text  # existing content preserved
    # dedupe: a later run with a new stamp/run adds nothing
    assert simulate.append_watchlist_leads(entries, "run-wl2", "2026-11-22T00:00:00Z", path=wl) == 0
    assert wl.read_text(encoding="utf-8") == text


def test_watchlist_lead_keeps_lint_safe_markdown(tmp_path):
    """The appended lead must not introduce a markdown link (tools/lint.py checks
    links in root .md files) and must stay a single bullet line."""
    wl = tmp_path / "watchlist.md"
    wl.write_text("# Watchlist\n\n## Open leads\n", encoding="utf-8")
    entries = [{"type": "watchlist", "human_reviewed": False,
                "reason": "fake [link](http://evil-sim.invalid) pattern MAL-2026-9998"}]
    assert simulate.append_watchlist_leads(entries, "run-lint", "2026-11-21T00:00:00Z", path=wl) == 1
    lead = next(l for l in wl.read_text(encoding="utf-8").splitlines() if l.startswith(simulate.LEAD_PREFIX))
    assert lead.count("\n") == 0 and "](" not in lead and "](http" not in lead
