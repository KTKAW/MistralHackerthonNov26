"""Unit tests for web/app.py — FastAPI grid endpoints.

Uses FastAPI's TestClient (httpx-based). All tests run against a temp
RUNS_ROOT so no real run artifacts are touched.
"""
from __future__ import annotations

import json
import os
from unittest import mock

import pytest
from fastapi.testclient import TestClient

from conftest import make_verdict, write_verdict, write_run_meta


@pytest.fixture
def client(tmp_path, monkeypatch):
    """A TestClient with RUNS_ROOT pointed at a temp dir, local mode (no DEPLOYMENT_NAME)."""
    runs = tmp_path / "runs"
    runs.mkdir()
    monkeypatch.setenv("DEPLOYMENT_NAME", "")  # local mode
    monkeypatch.setenv("LE_CHONK_RUNS_ROOT", str(runs))

    # Import web.app fresh with the patched env
    import importlib
    import web.app as app_mod
    importlib.reload(app_mod)
    app_mod.RUNS_ROOT = str(runs)
    # Re-mount artifacts if needed
    with TestClient(app_mod.app) as c:
        c.runs_root = str(runs)
        yield c


# ================================================================ GET /

class TestIndex:
    def test_index_returns_html(self, client):
        r = client.get("/")
        assert r.status_code == 200
        assert "text/html" in r.headers["content-type"]
        assert "le-chonk" in r.text
        assert "24" in r.text  # 24 h countdown

    def test_index_has_grid_and_approve(self, client):
        r = client.get("/")
        assert "grid" in r.text
        assert "Approve" in r.text


# ================================================================ POST /runs

class TestPostRuns:
    def test_start_run_returns_run_id(self, client):
        with mock.patch("web.app.start_run", return_value=("abc123", "2026-11-21T00:00:00+00:00")):
            r = client.post("/runs", json={"advisory_text": "CVE-2026-96760 affects authlib"})
        assert r.status_code == 200
        data = r.json()
        assert data["run_id"] == "abc123"
        assert "started_at" in data

    def test_start_run_requires_advisory_text(self, client):
        r = client.post("/runs", json={})
        assert r.status_code == 422  # validation error

    def test_start_run_local_mode_creates_run_dir(self, client):
        """In local mode, POST /runs creates runs/<run_id>/run.json and spawns a subprocess."""
        with mock.patch("web.app.subprocess.Popen") as mock_popen:
            r = client.post("/runs", json={"advisory_text": "test advisory"})
        assert r.status_code == 200
        run_id = r.json()["run_id"]
        run_dir = os.path.join(client.runs_root, run_id)
        assert os.path.isfile(os.path.join(run_dir, "run.json"))
        meta = json.load(open(os.path.join(run_dir, "run.json")))
        assert meta["status"] == "RUNNING"
        assert meta["mode"] == "local"
        assert meta["advisory_text"] == "test advisory"
        mock_popen.assert_called_once()


# ================================================================ GET /runs/{run_id}

class TestGetRun:
    def test_unknown_run(self, client):
        r = client.get("/runs/nonexistent")
        assert r.status_code == 200
        data = r.json()
        assert data["run_id"] == "nonexistent"
        assert data["status"] == "UNKNOWN"
        assert data["tiles"] == []
        assert data["clock_hours"] == 24

    def test_tiles_only_for_gate_passed(self, client):
        run_id = "r1"
        # gate-passed verdict
        v_passed = make_verdict(repo="svc-a", verdict="affected_fixed")
        v_passed["gate"] = {"ok": True, "rules": {}}
        # gate-failed verdict (should NOT appear)
        v_failed = make_verdict(repo="svc-b", verdict="needs_human")
        v_failed["gate"] = {"ok": False, "rules": {}}
        # no gate at all (should NOT appear)
        v_ungated = make_verdict(repo="svc-c", verdict="affected_proven")
        write_verdict(client.runs_root, run_id, "svc-a", v_passed)
        write_verdict(client.runs_root, run_id, "svc-b", v_failed)
        write_verdict(client.runs_root, run_id, "svc-c", v_ungated)
        write_run_meta(client.runs_root, run_id, status="AWAITING_APPROVAL")

        r = client.get(f"/runs/{run_id}")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "AWAITING_APPROVAL"
        tiles = data["tiles"]
        assert len(tiles) == 1
        assert tiles[0]["repo"] == "svc-a"
        assert tiles[0]["verdict"] == "affected_fixed"

    def test_tile_contains_expected_fields(self, client):
        run_id = "r2"
        v = make_verdict(repo="payments", verdict="not_affected", reason="no reachable path found here")
        v["gate"] = {"ok": True, "rules": {}}
        v["usage"] = {"cost_usd": 0.05}
        write_verdict(client.runs_root, run_id, "payments", v)
        write_run_meta(client.runs_root, run_id, status="RUNNING")

        r = client.get(f"/runs/{run_id}")
        tile = r.json()["tiles"][0]
        assert tile["repo"] == "payments"
        assert tile["verdict"] == "not_affected"
        assert "no reachable path" in tile["reason"]
        assert tile["proof"] == v["proof"]
        assert tile["verdict_url"] == f"/artifacts/{run_id}/payments/verdict.json"
        assert tile["usage"] == {"cost_usd": 0.05}

    def test_reason_truncated_to_280(self, client):
        run_id = "r3"
        v = make_verdict(repo="svc", verdict="affected_fixed",
                         reason="x" * 500)
        v["gate"] = {"ok": True, "rules": {}}
        write_verdict(client.runs_root, run_id, "svc", v)
        write_run_meta(client.runs_root, run_id)
        r = client.get(f"/runs/{run_id}")
        tile = r.json()["tiles"][0]
        assert len(tile["reason"]) == 280


# ================================================================ POST /runs/{run_id}/approve

class TestApprove:
    def test_approve_local_mode(self, client):
        run_id = "r-approve"
        write_run_meta(client.runs_root, run_id, status="AWAITING_APPROVAL")
        r = client.post(f"/runs/{run_id}/approve")
        assert r.status_code == 200
        data = r.json()
        assert data["approved"] is True
        assert data["mode"] == "local"
        # approved file created
        assert os.path.isfile(os.path.join(client.runs_root, run_id, "approved"))
        # run.json status updated
        meta = json.load(open(os.path.join(client.runs_root, run_id, "run.json")))
        assert meta["status"] == "APPROVED"


# ================================================================ _tiles / _gate_ok helpers

class TestHelpers:
    def test_gate_ok_true(self):
        from web.app import _gate_ok
        assert _gate_ok({"verdict": "affected_fixed", "gate": {"ok": True}}) is True

    def test_gate_ok_false_when_needs_human(self):
        from web.app import _gate_ok
        assert _gate_ok({"verdict": "needs_human", "gate": {"ok": True}}) is False

    def test_gate_ok_false_when_no_gate(self):
        from web.app import _gate_ok
        assert _gate_ok({"verdict": "affected_fixed"}) is False

    def test_tiles_empty_for_missing_run(self, client):
        r = client.get("/runs/does-not-exist")
        assert r.json()["tiles"] == []


# ================================================================ start_run (unit-level)

class TestStartRun:
    def test_local_mode_writes_run_json(self, tmp_path, monkeypatch):
        runs = str(tmp_path / "runs")
        os.makedirs(runs)
        monkeypatch.setenv("DEPLOYMENT_NAME", "")
        import web.app as app_mod
        app_mod.RUNS_ROOT = runs
        with mock.patch.object(app_mod.subprocess, "Popen"):
            run_id, started_at = app_mod.start_run("my advisory")
        assert len(run_id) == 12
        meta = json.load(open(os.path.join(runs, run_id, "run.json")))
        assert meta["advisory_text"] == "my advisory"
        assert meta["status"] == "RUNNING"
        assert "started_at" in meta
