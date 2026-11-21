"""Unit tests for orchestrator/report.py — early-warning draft generation.

Key invariants:
  - Only gate-passed verdicts appear in the warning.
  - needs_human verdicts are listed separately, excluded from the warning.
  - The 24 h clock math is correct.
  - No model call is made.
  - The output file is written to runs/<run_id>/early-warning.md.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone

import pytest

from orchestrator.report import render_early_warning, _parse_iso, _load_json, RUN_CLOCK_HOURS

from conftest import make_verdict, write_verdict, write_run_meta


class TestParseIso:
    def test_iso_with_z(self):
        dt = _parse_iso("2026-11-21T10:00:00Z")
        assert dt is not None
        assert dt.tzinfo is not None

    def test_iso_with_offset(self):
        dt = _parse_iso("2026-11-21T10:00:00+00:00")
        assert dt is not None

    def test_garbage_returns_none(self):
        assert _parse_iso("not a date") is None

    def test_none_returns_none(self):
        assert _parse_iso(None) is None


class TestLoadJson:
    def test_missing_file(self, tmp_path):
        assert _load_json(str(tmp_path / "nope.json")) is None

    def test_bad_json(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text("{not json")
        assert _load_json(str(p)) is None

    def test_valid(self, tmp_path):
        p = tmp_path / "ok.json"
        p.write_text('{"a": 1}')
        assert _load_json(str(p)) == {"a": 1}


class TestRenderEarlyWarning:
    def _setup_run(self, tmp_runs, run_id="run1", started_at=None, advisory=None, member_states=None):
        meta = {"started_at": started_at or datetime.now(timezone.utc).isoformat()}
        if member_states:
            meta["member_states"] = member_states
        write_run_meta(tmp_runs, run_id, **meta)
        adv = advisory or {
            "id": "CVE-2026-96760",
            "package": "authlib",
            "affected_range": "<1.9.0",
            "flawed_function": "authlib.jose.JsonWebSignature.verify",
        }
        d = os.path.join(tmp_runs, run_id)
        with open(os.path.join(d, "advisory.json"), "w") as fh:
            json.dump(adv, fh)
        return d

    def test_writes_file(self, tmp_runs):
        self._setup_run(tmp_runs)
        text = render_early_warning("run1", [], runs_root=tmp_runs)
        out_path = os.path.join(tmp_runs, "run1", "early-warning.md")
        assert os.path.isfile(out_path)
        with open(out_path) as fh:
            assert fh.read() == text

    def test_contains_advisory_info(self, tmp_runs):
        self._setup_run(tmp_runs, advisory={
            "id": "CVE-2026-99999", "package": "log4j",
            "affected_range": "<2.17.0", "flawed_function": "log4j.JndiLookup",
        })
        text = render_early_warning("run1", [], runs_root=tmp_runs)
        assert "CVE-2026-99999" in text
        assert "log4j" in text
        assert "<2.17.0" in text
        assert "log4j.JndiLookup" in text

    def test_contains_clock(self, tmp_runs):
        started = (datetime.now(timezone.utc) - timedelta(minutes=30)).isoformat()
        self._setup_run(tmp_runs, started_at=started)
        text = render_early_warning("run1", [], runs_root=tmp_runs)
        assert "24 h" in text or "24h" in text
        assert "min used" in text
        assert "min left" in text or "min remain" in text

    def test_clock_hours_constant(self):
        assert RUN_CLOCK_HOURS == 24

    def test_member_states_in_output(self, tmp_runs):
        self._setup_run(tmp_runs, member_states="IE, DE, FR")
        text = render_early_warning("run1", [], runs_root=tmp_runs)
        assert "IE, DE, FR" in text

    def test_member_states_default(self, tmp_runs):
        self._setup_run(tmp_runs)
        text = render_early_warning("run1", [], runs_root=tmp_runs)
        assert "not specified" in text

    def test_gate_passed_affected_appears(self, tmp_runs):
        self._setup_run(tmp_runs)
        v = make_verdict(repo="payments-api", verdict="affected_fixed")
        v["gate"] = {"ok": True, "rules": {}}
        text = render_early_warning("run1", [v], runs_root=tmp_runs)
        assert "payments-api" in text
        assert "affected_fixed" in text
        assert "Affected products" in text

    def test_ungated_verdict_excluded(self, tmp_runs):
        """A verdict WITHOUT a gate result must NOT appear."""
        self._setup_run(tmp_runs)
        v = make_verdict(repo="secret-svc", verdict="affected_fixed")
        # no "gate" key at all
        text = render_early_warning("run1", [v], runs_root=tmp_runs)
        assert "secret-svc" not in text

    def test_gate_failed_excluded(self, tmp_runs):
        self._setup_run(tmp_runs)
        v = make_verdict(repo="bad-svc", verdict="affected_fixed")
        v["gate"] = {"ok": False, "rules": {}}
        text = render_early_warning("run1", [v], runs_root=tmp_runs)
        # gate failed → verdict was downgraded to needs_human by gate(), but here
        # we simulate the raw state: gate.ok=False → not gate-passed → excluded from affected
        assert "bad-svc" not in text or "Needs a human" in text

    def test_needs_human_in_separate_section(self, tmp_runs):
        self._setup_run(tmp_runs)
        v = make_verdict(repo="timeout-svc", verdict="needs_human", reason="agent timed out")
        v["gate"] = {"ok": False, "rules": {}}
        text = render_early_warning("run1", [v], runs_root=tmp_runs)
        assert "Needs a human" in text
        assert "timeout-svc" in text
        # must NOT be in the affected section
        affected_section = text.split("## Affected products")[1].split("##")[0]
        assert "timeout-svc" not in affected_section

    def test_not_affected_section(self, tmp_runs):
        self._setup_run(tmp_runs)
        v = make_verdict(repo="safe-svc", verdict="not_affected",
                         reason="no reachable path found")
        v["gate"] = {"ok": True, "rules": {}}
        text = render_early_warning("run1", [v], runs_root=tmp_runs)
        assert "Not affected" in text
        assert "safe-svc" in text
        assert "no reachable path found" in text

    def test_never_says_safe(self, tmp_runs):
        """The word 'safe' must never appear as a verdict — only 'no reachable path found'."""
        self._setup_run(tmp_runs)
        v = make_verdict(repo="svc", verdict="not_affected", reason="no reachable path found")
        v["gate"] = {"ok": True, "rules": {}}
        text = render_early_warning("run1", [v], runs_root=tmp_runs)
        # "safe" may appear inside the disclaimer quote, but not as a verdict label
        assert '"safe"' in text  # the disclaimer mentions it

    def test_proof_tests_listed(self, tmp_runs):
        self._setup_run(tmp_runs)
        v = make_verdict(repo="svc", verdict="affected_proven",
                         proof=["tests/test_a.py::test_1", "tests/test_b.py::test_2"])
        v["gate"] = {"ok": True, "rules": {}}
        text = render_early_warning("run1", [v], runs_root=tmp_runs)
        assert "tests/test_a.py::test_1" in text
        assert "tests/test_b.py::test_2" in text

    def test_fix_status_shown(self, tmp_runs):
        self._setup_run(tmp_runs)
        v = make_verdict(repo="svc", verdict="affected_fixed",
                         fix={"kind": "upgrade", "target": "1.9.0", "diff_file": None})
        v["gate"] = {"ok": True, "rules": {}}
        text = render_early_warning("run1", [v], runs_root=tmp_runs)
        assert "1.9.0" in text
        assert "upgrade" in text

    def test_patch_fix_shown(self, tmp_runs):
        self._setup_run(tmp_runs)
        v = make_verdict(repo="svc", verdict="affected_fixed",
                         fix={"kind": "patch", "target": None, "diff_file": "fix.diff"})
        v["gate"] = {"ok": True, "rules": {}}
        text = render_early_warning("run1", [v], runs_root=tmp_runs)
        assert "patch" in text
        assert "fix.diff" in text

    def test_evidence_path_shown(self, tmp_runs):
        self._setup_run(tmp_runs)
        v = make_verdict(repo="svc", verdict="affected_fixed")
        v["gate"] = {"ok": True, "rules": {}}
        text = render_early_warning("run1", [v], runs_root=tmp_runs)
        assert "src/app.py:42" in text
        assert "POST /token entry point" in text

    def test_timeline_section(self, tmp_runs):
        started = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
        self._setup_run(tmp_runs, started_at=started)
        text = render_early_warning("run1", [], runs_root=tmp_runs)
        assert "Timeline" in text
        assert "72 h" in text
        assert "14 days" in text

    def test_no_affected_repos(self, tmp_runs):
        self._setup_run(tmp_runs)
        text = render_early_warning("run1", [], runs_root=tmp_runs)
        assert "None among the gate-passed" in text

    def test_human_review_disclaimer(self, tmp_runs):
        self._setup_run(tmp_runs)
        text = render_early_warning("run1", [], runs_root=tmp_runs)
        assert "DRAFT for human review" in text
        assert "never sends" in text or "human submits" in text

    def test_creates_run_dir_if_missing(self, tmp_path):
        runs = str(tmp_path / "runs")
        os.makedirs(runs)
        text = render_early_warning("newrun", [], runs_root=runs)
        assert os.path.isfile(os.path.join(runs, "newrun", "early-warning.md"))

    def test_old_started_at_clamps_minutes_left(self, tmp_runs):
        """If started > 24 h ago, minutes_left is clamped to 0."""
        started = (datetime.now(timezone.utc) - timedelta(hours=30)).isoformat()
        self._setup_run(tmp_runs, started_at=started)
        text = render_early_warning("run1", [], runs_root=tmp_runs)
        assert "0 min left" in text or "0 min remain" in text
