"""Unit tests for orchestrator/workflow.py helpers.

Tests the pure/local-mode helpers without touching Mistral Workflows or
the hosted SDK. Uses stub mode (LE_CHONK_STUBS=1) where a model call would
otherwise happen.
"""
from __future__ import annotations

import json
import os
import sys
import threading
import time
from datetime import timedelta
from unittest import mock

import pytest

import orchestrator.workflow as wf
from conftest import make_verdict, write_verdict, write_run_meta


@pytest.fixture(autouse=True)
def _stub_env(monkeypatch, tmp_path):
    """Force stub mode and point all roots at a temp dir for every test."""
    runs = tmp_path / "runs"
    fleet = tmp_path / "fleet"
    wheelhouse = tmp_path / "wheelhouse"
    for d in (runs, fleet, wheelhouse):
        d.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("LE_CHONK_STUBS", "1")
    monkeypatch.setenv("LE_CHONK_RUNS_ROOT", str(runs))
    monkeypatch.setenv("LE_CHONK_FLEET_ROOT", str(fleet))
    monkeypatch.setenv("LE_CHONK_WHEELHOUSE", str(wheelhouse))
    monkeypatch.setattr(wf, "RUNS_ROOT", str(runs))
    monkeypatch.setattr(wf, "FLEET_ROOT", str(fleet))
    monkeypatch.setattr(wf, "WHEELHOUSE", str(wheelhouse))
    monkeypatch.setattr(wf, "STUBS", True)
    monkeypatch.setattr(wf, "STUB_RUN_REPO", "")
    return tmp_path


def _runs(tmp_path):
    return str(tmp_path / "runs")


# ================================================================ _now_iso / _write_json / _read_json

class TestJsonHelpers:
    def test_now_iso_is_utc(self):
        s = wf._now_iso()
        assert "+00:00" in s

    def test_write_read_json_roundtrip(self, tmp_path):
        p = str(tmp_path / "sub" / "x.json")
        wf._write_json(p, {"a": [1, 2, 3]})
        assert wf._read_json(p) == {"a": [1, 2, 3]}

    def test_write_json_atomic_no_tmp_left(self, tmp_path):
        p = str(tmp_path / "x.json")
        wf._write_json(p, {"k": "v"})
        assert not os.path.exists(p + ".tmp")

    def test_read_json_missing(self, tmp_path):
        assert wf._read_json(str(tmp_path / "nope.json")) is None

    def test_read_json_corrupt(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text("{oops")
        assert wf._read_json(str(p)) is None


# ================================================================ list_repos

class TestListRepos:
    def test_empty_when_no_fleet(self, tmp_path):
        assert wf.list_repos(str(tmp_path / "empty")) == []

    def test_lists_directories(self, tmp_path):
        fleet = tmp_path / "fleet"
        (fleet / "svc-b").mkdir(parents=True)
        (fleet / "svc-a").mkdir()
        (fleet / ".hidden").mkdir()
        (fleet / "afile.txt").write_text("x")
        repos = wf.list_repos(str(fleet))
        assert repos == ["svc-a", "svc-b"]  # sorted, no hidden, no files

    def test_stub_repos_env_override(self, monkeypatch):
        monkeypatch.setenv("LE_CHONK_STUB_REPOS", "alpha,beta,gamma")
        assert wf.list_repos("/nonexistent") == ["alpha", "beta", "gamma"]


# ================================================================ read_advisory (stub mode)

class TestReadAdvisoryStub:
    def test_extracts_cve_id(self, tmp_path):
        runs = _runs(tmp_path)
        text = "CVE-2026-96760 affects authlib before 1.9.0 in JsonWebSignature.verify"
        adv = wf.read_advisory(text, "r1", runs_root=runs)
        assert adv["id"] == "CVE-2026-96760"
        assert adv["package"] == "authlib"
        assert adv["source"] == "stub"

    def test_no_cve_gives_unknown(self, tmp_path):
        runs = _runs(tmp_path)
        adv = wf.read_advisory("some advisory with no CVE", "r2", runs_root=runs)
        assert adv["id"] == "CVE-UNKNOWN"

    def test_writes_advisory_json(self, tmp_path):
        runs = _runs(tmp_path)
        wf.read_advisory("CVE-2026-1234 blah", "r3", runs_root=runs)
        with open(os.path.join(runs, "r3", "advisory.json")) as fh:
            on_disk = json.load(fh)
        assert on_disk["id"] == "CVE-2026-1234"

    def test_stub_advisory_env_override(self, monkeypatch, tmp_path):
        runs = _runs(tmp_path)
        monkeypatch.setenv("LE_CHONK_STUB_ADVISORY",
                           json.dumps({"id": "CVE-X", "package": "p", "affected_range": "r",
                                       "flawed_function": "f"}))
        adv = wf.read_advisory("ignored", "r4", runs_root=runs)
        assert adv["id"] == "CVE-X"


# ================================================================ intake

class TestIntake:
    def test_creates_run_dir_and_meta(self, tmp_path):
        runs = _runs(tmp_path)
        meta = wf.intake("run42", "advisory text here", runs_root=runs, mode="local")
        assert meta["run_id"] == "run42"
        assert meta["status"] == "RUNNING"
        assert meta["mode"] == "local"
        assert meta["advisory_text"] == "advisory text here"
        assert "started_at" in meta
        with open(os.path.join(runs, "run42", "run.json")) as fh:
            disk = json.load(fh)
        assert disk["run_id"] == "run42"

    def test_preserves_existing_started_at(self, tmp_path):
        runs = _runs(tmp_path)
        original = "2026-11-21T00:00:00+00:00"
        write_run_meta(runs, "r1", started_at=original)
        meta = wf.intake("r1", "text", runs_root=runs)
        assert meta["started_at"] == original


# ================================================================ _set_status

class TestSetStatus:
    def test_updates_status(self, tmp_path):
        runs = _runs(tmp_path)
        wf.intake("r1", "text", runs_root=runs)
        wf._set_status("r1", "COMPLETED", runs_root=runs)
        meta = wf._read_json(os.path.join(runs, "r1", "run.json"))
        assert meta["status"] == "COMPLETED"
        assert "updated_at" in meta


# ================================================================ wait_for_approve

class TestWaitForApprove:
    def test_returns_true_when_approved_file_exists(self, tmp_path):
        runs = _runs(tmp_path)
        os.makedirs(os.path.join(runs, "r1"))
        open(os.path.join(runs, "r1", "approved"), "w").write("2026-11-21T12:00:00+00:00")
        assert wf.wait_for_approve("r1", runs_root=runs, timeout=timedelta(seconds=5), poll_s=0.05) is True

    def test_returns_true_when_status_approved(self, tmp_path):
        runs = _runs(tmp_path)
        write_run_meta(runs, "r1", status="APPROVED")
        assert wf.wait_for_approve("r1", runs_root=runs, timeout=timedelta(seconds=5), poll_s=0.05) is True

    def test_returns_false_on_timeout(self, tmp_path):
        runs = _runs(tmp_path)
        write_run_meta(runs, "r1", status="RUNNING")
        t0 = time.monotonic()
        result = wf.wait_for_approve("r1", runs_root=runs, timeout=timedelta(milliseconds=200), poll_s=0.05)
        elapsed = time.monotonic() - t0
        assert result is False
        assert elapsed < 2

    def test_approval_arrives_mid_wait(self, tmp_path):
        runs = _runs(tmp_path)
        write_run_meta(runs, "r1", status="RUNNING")

        def drop_file():
            time.sleep(0.15)
            open(os.path.join(runs, "r1", "approved"), "w").write("now")
        t = threading.Thread(target=drop_file)
        t.start()
        result = wf.wait_for_approve("r1", runs_root=runs, timeout=timedelta(seconds=5), poll_s=0.05)
        t.join()
        assert result is True


# ================================================================ _collect_verdicts

class TestCollectVerdicts:
    def test_collects_existing(self, tmp_path):
        runs = _runs(tmp_path)
        write_verdict(runs, "r1", "svc-a", make_verdict(repo="svc-a"))
        write_verdict(runs, "r1", "svc-b", make_verdict(repo="svc-b"))
        out = wf._collect_verdicts("r1", ["svc-a", "svc-b", "svc-c"], runs_root=runs)
        assert len(out) == 2
        assert {v["repo"] for v in out} == {"svc-a", "svc-b"}


# ================================================================ get_run_repo (stub)

class TestGetRunRepo:
    def test_stub_run_repo_loaded(self, tmp_path, monkeypatch):
        stub_file = tmp_path / "stub_run_repo.py"
        stub_file.write_text(
            "def run_repo(run_id, repo, **kw):\n"
            "    return {'repo': repo, 'rc': 0, 'verdict': {}, 'export': {}}\n"
        )
        monkeypatch.setattr(wf, "STUB_RUN_REPO", str(stub_file))
        fn, src = wf.get_run_repo()
        assert src == "stub"
        result = fn("r1", "svc-a")
        assert result["repo"] == "svc-a"

    def test_no_stub_raises(self, monkeypatch):
        # Simulate track A's worker/ not being merged: the import must fail.
        monkeypatch.setitem(sys.modules, "worker", None)
        monkeypatch.setitem(sys.modules, "worker.run_repo", None)
        monkeypatch.setattr(wf, "STUB_RUN_REPO", "")
        with pytest.raises(RuntimeError, match="no run_repo available"):
            wf.get_run_repo()

    def test_worker_preferred_when_available(self, monkeypatch):
        # When worker/ IS merged (track A on build/base) and stub mode is off,
        # the real run_repo wins over any stub.
        try:
            import worker.run_repo  # noqa: F401
        except Exception:
            pytest.skip("worker/run_repo not merged in this checkout")
        monkeypatch.setattr(wf, "STUBS", False)
        monkeypatch.setattr(wf, "STUB_RUN_REPO", "")
        fn, src = wf.get_run_repo()
        assert src == "worker"
        from worker.run_repo import run_repo
        assert fn is run_repo


# ================================================================ triage_one

class TestTriageOne:
    def test_calls_run_repo_with_heartbeat(self, tmp_path, monkeypatch):
        stub_file = tmp_path / "stub.py"
        stub_file.write_text(
            "def run_repo(run_id, repo, *, fleet_root, runs_root, vibe_home, heartbeat_fn=None):\n"
            "    assert callable(heartbeat_fn)\n"
            "    heartbeat_fn()\n"
            "    return {'repo': repo, 'rc': 0, 'verdict': {'repo': repo}, 'export': {}}\n"
        )
        monkeypatch.setattr(wf, "STUB_RUN_REPO", str(stub_file))
        record = []
        result = wf.triage_one("r1", "svc-a", runs_root=_runs(tmp_path),
                               fleet_root=str(tmp_path / "fleet"),
                               vibe_home=str(tmp_path / "vibe"),
                               record=record)
        assert result["repo"] == "svc-a"
        assert len(record) == 1
        assert record[0][0] == "svc-a"


# ================================================================ run_local (full local pipeline, stubbed)

class TestRunLocal:
    def test_full_local_run_with_stubs(self, tmp_path, monkeypatch):
        """End-to-end local run: stub run_repo writes a needs_human verdict,
        gate leaves it as-is, report renders, approval pre-dropped."""
        runs = _runs(tmp_path)
        fleet = str(tmp_path / "fleet")
        wheelhouse = str(tmp_path / "wheelhouse")

        # fleet with one repo
        svc = os.path.join(fleet, "svc-a")
        os.makedirs(os.path.join(svc, "src"), exist_ok=True)
        with open(os.path.join(svc, "src", "app.py"), "w") as fh:
            fh.write("# pristine\n")
        with open(os.path.join(svc, "requirements.txt"), "w") as fh:
            fh.write("authlib==1.8.0\n")

        # stub run_repo: writes a needs_human verdict
        stub_file = tmp_path / "stub_rr.py"
        stub_file.write_text(
            "import json, os\n"
            "def run_repo(run_id, repo, *, fleet_root, runs_root, vibe_home, heartbeat_fn=None):\n"
            "    d = os.path.join(runs_root, run_id, repo)\n"
            "    os.makedirs(d, exist_ok=True)\n"
            "    v = {\n"
            "        'repo': repo,\n"
            "        'advisory': {'id': 'CVE-2026-96760', 'package': 'authlib',\n"
            "                      'affected_range': '<1.9.0',\n"
            "                      'flawed_function': 'authlib.jose.JsonWebSignature.verify'},\n"
            "        'verdict': 'needs_human',\n"
            "        'reason': 'stub: timed out',\n"
            "        'path': [],\n"
            "        'proof': [],\n"
            "        'suite': {'before': {'passed': 0, 'failed': 0}, 'after': {'passed': 0, 'failed': 0}},\n"
            "        'follow_ups': [],\n"
            "    }\n"
            "    with open(os.path.join(d, 'verdict.json'), 'w') as fh:\n"
            "        json.dump(v, fh)\n"
            "    return {'repo': repo, 'rc': 0, 'verdict': v, 'export': {}}\n"
        )
        monkeypatch.setattr(wf, "STUB_RUN_REPO", str(stub_file))
        monkeypatch.setenv("LE_CHONK_STUB_REPOS", "svc-a")

        # Patch wait_for_approve to drop the approval file then return True quickly
        def fake_wait(run_id, *, runs_root, timeout=None, poll_s=0.01):
            d = os.path.join(runs_root, run_id)
            os.makedirs(d, exist_ok=True)
            with open(os.path.join(d, "approved"), "w") as fh:
                fh.write("ok")
            return True
        monkeypatch.setattr(wf, "wait_for_approve", fake_wait)

        run_id = wf.run_local("CVE-2026-96760 advisory text", run_id="testrun1",
                              runs_root=runs, fleet_root=fleet, wheelhouse=wheelhouse)

        assert run_id == "testrun1"
        meta = wf._read_json(os.path.join(runs, "testrun1", "run.json"))
        assert meta["status"] == "COMPLETED"
        assert os.path.isfile(os.path.join(runs, "testrun1", "advisory.json"))
        v = wf._read_json(os.path.join(runs, "testrun1", "svc-a", "verdict.json"))
        assert v is not None
        assert "gate" in v
        assert v["verdict"] == "needs_human"
        assert os.path.isfile(os.path.join(runs, "testrun1", "early-warning.md"))

    def test_run_local_generates_run_id(self, tmp_path, monkeypatch):
        runs = _runs(tmp_path)
        monkeypatch.setenv("LE_CHONK_STUB_REPOS", "")  # empty fleet → no triage

        def fake_wait(run_id, *, runs_root, timeout=None, poll_s=0.01):
            return True
        monkeypatch.setattr(wf, "wait_for_approve", fake_wait)

        run_id = wf.run_local("some advisory", runs_root=runs,
                              fleet_root=str(tmp_path / "fleet"),
                              wheelhouse=str(tmp_path / "wheelhouse"))
        assert run_id is not None
        assert len(run_id) == 12


# ================================================================ resume_pending

class TestResumePending:
    def test_resumes_running_runs(self, tmp_path, monkeypatch):
        runs = _runs(tmp_path)
        write_run_meta(runs, "r1", status="RUNNING", advisory_text="CVE-2026-1234 x")
        write_run_meta(runs, "r2", status="COMPLETED", advisory_text="done")
        write_run_meta(runs, "r3", status="AWAITING_APPROVAL", advisory_text="CVE-2026-5678 y")

        resumed_calls = []
        def fake_run_local(advisory_text, run_id=None, **kw):
            resumed_calls.append(run_id)
            return run_id
        monkeypatch.setattr(wf, "run_local", fake_run_local)
        out = wf.resume_pending(runs_root=runs)
        assert set(out) == {"r1", "r3"}
        assert set(resumed_calls) == {"r1", "r3"}

    def test_empty_runs_root(self, tmp_path):
        assert wf.resume_pending(runs_root=str(tmp_path / "nope")) == []


# ================================================================ main() CLI

class TestMainCLI:
    def test_no_args_local_mode(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setenv("DEPLOYMENT_NAME", "")
        monkeypatch.setattr(wf, "RUNS_ROOT", _runs(tmp_path))
        monkeypatch.setattr(wf, "resume_pending", lambda **kw: [])
        rc = wf.main([])
        assert rc == 0
        captured = capsys.readouterr()
        assert "local" in captured.out.lower() or "fallback" in captured.out.lower()

    def test_resume_flag(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setattr(wf, "RUNS_ROOT", _runs(tmp_path))
        monkeypatch.setattr(wf, "resume_pending", lambda **kw: ["r1"])
        rc = wf.main(["--resume"])
        assert rc == 0
        assert "r1" in capsys.readouterr().out
