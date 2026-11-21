"""Unit tests for orchestrator/gate.py — the rules gate as code.

Key invariants under test:
  - The gate may ONLY downgrade a verdict to "needs_human", never upgrade.
  - gate_passed() is true only when gate.ok AND verdict != needs_human.
  - _tree_digest skips .venv/__pycache__/.git and allowlisted basenames.
  - _fixed_pins derives wheelhouse pins from verdict.fix.
  - _run never raises.
"""
from __future__ import annotations

import hashlib
import json
import os
from unittest import mock

import pytest

from orchestrator import gate as gate_mod
from orchestrator.gate import gate, gate_passed, _tree_digest, _fixed_pins, _run

from conftest import make_verdict, write_verdict, write_run_meta


# ================================================================ _run

class TestRun:
    def test_run_success(self):
        rc, out = _run(["echo", "hello"])
        assert rc == 0
        assert "hello" in out

    def test_run_failure_rc(self):
        rc, out = _run(["false"])
        assert rc != 0

    def test_run_missing_binary_never_raises(self):
        rc, out = _run(["/nonexistent/binary-xyz"])
        assert rc == 127
        assert "gate:" in out

    def test_run_timeout_never_raises(self):
        rc, out = _run(["sleep", "5"], timeout=1)
        assert rc == 127
        assert "gate:" in out


# ================================================================ _tree_digest

class TestTreeDigest:
    def test_digest_basic(self, tmp_path):
        (tmp_path / "a.py").write_text("print(1)")
        (tmp_path / "b.txt").write_text("hello")
        d = _tree_digest(str(tmp_path))
        assert set(d.keys()) == {"a.py", "b.txt"}
        assert d["a.py"] == hashlib.sha256(b"print(1)").hexdigest()

    def test_digest_skips_venv_pycache_git(self, tmp_path):
        (tmp_path / "src.py").write_text("x")
        venv = tmp_path / ".venv" / "lib"
        venv.mkdir(parents=True)
        (venv / "dep.py").write_text("y")
        pyc = tmp_path / "__pycache__"
        pyc.mkdir()
        (pyc / "src.cpython-314.pyc").write_text("z")
        git = tmp_path / ".git"
        git.mkdir()
        (git / "HEAD").write_text("ref")
        (tmp_path / "mod.pyc").write_bytes(b"\x00\x01")
        d = _tree_digest(str(tmp_path))
        assert set(d.keys()) == {"src.py"}

    def test_digest_allow_names(self, tmp_path):
        (tmp_path / "app.py").write_text("original")
        (tmp_path / "test_proof.py").write_text("agent-written")
        d = _tree_digest(str(tmp_path), allow_names={"test_proof.py"})
        assert "test_proof.py" not in d
        assert "app.py" in d

    def test_digest_nested(self, tmp_path):
        sub = tmp_path / "pkg" / "mod"
        sub.mkdir(parents=True)
        (sub / "a.py").write_text("nested")
        d = _tree_digest(str(tmp_path))
        assert os.path.join("pkg", "mod", "a.py") in d


# ================================================================ _fixed_pins

class TestFixedPins:
    def test_upgrade_pin(self):
        v = make_verdict(verdict="affected_fixed",
                         fix={"kind": "upgrade", "target": "1.9.0", "diff_file": None})
        pins = _fixed_pins(v)
        assert pins == ["authlib==1.9.0"]

    def test_patch_returns_empty(self):
        v = make_verdict(fix={"kind": "patch", "target": None, "diff_file": "fix.diff"})
        assert _fixed_pins(v) == []

    def test_no_fix_returns_empty(self):
        v = make_verdict(fix=None)
        assert _fixed_pins(v) == []

    def test_upgrade_without_target_returns_empty(self):
        v = make_verdict(fix={"kind": "upgrade", "target": "", "diff_file": None})
        assert _fixed_pins(v) == []

    def test_upgrade_without_package_returns_empty(self):
        v = make_verdict(fix={"kind": "upgrade", "target": "1.9.0", "diff_file": None})
        v["advisory"]["package"] = ""
        assert _fixed_pins(v) == []


# ================================================================ gate_passed

class TestGatePassed:
    def test_gate_ok_and_not_needs_human(self):
        v = {"verdict": "affected_fixed", "gate": {"ok": True}}
        assert gate_passed(v) is True

    def test_gate_ok_but_needs_human(self):
        v = {"verdict": "needs_human", "gate": {"ok": True}}
        assert gate_passed(v) is False

    def test_gate_not_ok(self):
        v = {"verdict": "affected_fixed", "gate": {"ok": False}}
        assert gate_passed(v) is False

    def test_no_gate(self):
        v = {"verdict": "affected_fixed"}
        assert gate_passed(v) is False

    def test_empty_gate(self):
        v = {"verdict": "not_affected", "gate": {}}
        assert gate_passed(v) is False


# ================================================================ gate() — needs_human passthrough

class TestGateNeedsHuman:
    def test_needs_human_left_as_is(self, tmp_runs, tmp_wheelhouse, tmp_fleet):
        v = make_verdict(verdict="needs_human", reason="timed out")
        write_verdict(tmp_runs, "r1", "payments-api", v)
        out = gate("r1", [v], runs_root=tmp_runs, wheelhouse=tmp_wheelhouse, fleet_root=tmp_fleet)
        assert out[0]["verdict"] == "needs_human"
        assert out[0]["gate"]["ok"] is True
        assert "already_needs_human" in out[0]["gate"]["rules"]

    def test_verdict_written_back_to_disk(self, tmp_runs, tmp_wheelhouse, tmp_fleet):
        v = make_verdict(verdict="needs_human")
        write_verdict(tmp_runs, "r1", "payments-api", v)
        gate("r1", [v], runs_root=tmp_runs, wheelhouse=tmp_wheelhouse, fleet_root=tmp_fleet)
        with open(os.path.join(tmp_runs, "r1", "payments-api", "verdict.json")) as fh:
            on_disk = json.load(fh)
        assert "gate" in on_disk
        assert on_disk["gate"]["ok"] is True


# ================================================================ gate() — not_affected / no_src_changes

class TestGateNotAffected:
    """The gate compares _tree_digest(work/src) against _tree_digest(fleet/<repo>).
    So we set up fleet/<repo>/ to mirror exactly what is in work/src/."""

    REPO = "payments-api"

    @pytest.fixture
    def fleet_root(self, tmp_path):
        """A fleet root WITHOUT the conftest's pre-made repo, so we control the layout."""
        d = tmp_path / "fleet-na"
        d.mkdir()
        return str(d)

    def _setup(self, tmp_runs, fleet_root, run_id="r1", repo=None, fleet_files=None):
        """Create work/src AND fleet/<repo> with identical files."""
        repo = repo or self.REPO
        files = fleet_files if fleet_files is not None else {"app.py": "# pristine app\n"}
        work_src = os.path.join(tmp_runs, run_id, repo, "src")
        fleet_dir = os.path.join(fleet_root, repo)
        for d in (work_src, fleet_dir):
            os.makedirs(d, exist_ok=True)
        for name, content in files.items():
            with open(os.path.join(work_src, name), "w") as fh:
                fh.write(content)
            with open(os.path.join(fleet_dir, name), "w") as fh:
                fh.write(content)
        return work_src, fleet_dir

    def test_no_changes_passes(self, tmp_runs, tmp_wheelhouse, fleet_root):
        self._setup(tmp_runs, fleet_root)
        v = make_verdict(repo=self.REPO, verdict="not_affected", proof=[])
        write_verdict(tmp_runs, "r1", self.REPO, v)
        out = gate("r1", [v], runs_root=tmp_runs, wheelhouse=tmp_wheelhouse, fleet_root=fleet_root)
        assert out[0]["verdict"] == "not_affected"
        assert out[0]["gate"]["ok"] is True
        assert out[0]["gate"]["rules"]["no_src_changes"]["ok"] is True

    def test_src_changed_downgrades(self, tmp_runs, tmp_wheelhouse, fleet_root):
        work_src, _ = self._setup(tmp_runs, fleet_root)
        with open(os.path.join(work_src, "app.py"), "a") as fh:
            fh.write("# agent modified this\n")
        v = make_verdict(repo=self.REPO, verdict="not_affected", proof=[])
        write_verdict(tmp_runs, "r1", self.REPO, v)
        out = gate("r1", [v], runs_root=tmp_runs, wheelhouse=tmp_wheelhouse, fleet_root=fleet_root)
        assert out[0]["verdict"] == "needs_human"
        assert out[0]["gate"]["ok"] is False
        assert out[0]["gate"]["rules"]["no_src_changes"]["ok"] is False

    def test_agent_proof_file_allowed(self, tmp_runs, tmp_wheelhouse, fleet_root):
        work_src, _ = self._setup(tmp_runs, fleet_root)
        # agent wrote a proof test file — basename is in the proof list
        with open(os.path.join(work_src, "test_proof_x.py"), "w") as fh:
            fh.write("def test_x(): pass\n")
        v = make_verdict(repo=self.REPO, verdict="not_affected",
                         proof=["test_proof_x.py::test_x"])
        write_verdict(tmp_runs, "r1", self.REPO, v)
        out = gate("r1", [v], runs_root=tmp_runs, wheelhouse=tmp_wheelhouse, fleet_root=fleet_root)
        assert out[0]["verdict"] == "not_affected"
        assert out[0]["gate"]["rules"]["no_src_changes"]["ok"] is True

    def test_extra_file_in_src_downgrades(self, tmp_runs, tmp_wheelhouse, fleet_root):
        work_src, _ = self._setup(tmp_runs, fleet_root)
        with open(os.path.join(work_src, "sneaky.py"), "w") as fh:
            fh.write("# not allowed\n")
        v = make_verdict(repo=self.REPO, verdict="not_affected", proof=["test_proof.py::test_a"])
        write_verdict(tmp_runs, "r1", self.REPO, v)
        out = gate("r1", [v], runs_root=tmp_runs, wheelhouse=tmp_wheelhouse, fleet_root=fleet_root)
        assert out[0]["verdict"] == "needs_human"
        assert out[0]["gate"]["rules"]["no_src_changes"]["ok"] is False

    def test_fleet_unavailable_skips_check(self, tmp_runs, tmp_wheelhouse, tmp_path):
        missing_fleet = str(tmp_path / "no-such-fleet")
        work_src = os.path.join(tmp_runs, "r1", self.REPO, "src")
        os.makedirs(work_src)
        v = make_verdict(repo=self.REPO, verdict="not_affected", proof=[])
        write_verdict(tmp_runs, "r1", self.REPO, v)
        out = gate("r1", [v], runs_root=tmp_runs, wheelhouse=tmp_wheelhouse, fleet_root=missing_fleet)
        assert out[0]["gate"]["rules"]["no_src_changes"]["ok"] is True
        assert "skipped" in out[0]["gate"]["rules"]["no_src_changes"]["detail"]


# ================================================================ gate() — affected_proven / affected_fixed

class TestGateAffected:
    def _make_work(self, tmp_runs, run_id="r1", repo="payments-api"):
        work = os.path.join(tmp_runs, run_id, repo)
        src = os.path.join(work, "src")
        os.makedirs(src, exist_ok=True)
        with open(os.path.join(src, "requirements.txt"), "w") as fh:
            fh.write("authlib==1.8.0\n")
        return work, src

    def test_all_proofs_fail_on_vuln_and_pass_on_fixed(self, tmp_runs, tmp_wheelhouse, tmp_fleet):
        """Happy path: proofs FAIL on vulnerable, PASS on fixed, suite not dropped."""
        work, src = self._make_work(tmp_runs)
        v = make_verdict(verdict="affected_fixed",
                         proof=["tests/test_proof.py::test_a", "tests/test_proof.py::test_b"])
        write_verdict(tmp_runs, "r1", "payments-api", v)

        with mock.patch.object(gate_mod, "_ensure_venv", return_value="/fake/venv/python"), \
             mock.patch.object(gate_mod, "_pytest_one") as mock_pytest, \
             mock.patch.object(gate_mod, "venv") as mock_venv:
            # _pytest_one returns (passed, rc, out). On vulnerable: not passed.
            # On fixed: passed. Distinguish by the python path argument.
            def fake_pytest(py, src_dir, test_id, cwd):
                if "fixed" in str(py):
                    return True, 0, "PASSED"
                return False, 1, "FAILED"
            mock_pytest.side_effect = fake_pytest
            # Make the fixed venv "exist"
            mock_venv.EnvBuilder.return_value.create = lambda *a, **k: None

            # Patch os.path.isfile so .venv-fixed/bin/python appears to exist
            real_isfile = os.path.isfile
            def fake_isfile(p):
                if ".venv-fixed" in str(p) and str(p).endswith("python"):
                    return True
                if ".venv-fixed" in str(p) and str(p).endswith("pip"):
                    return True
                return real_isfile(p)

            with mock.patch.object(gate_mod.os.path, "isfile", side_effect=fake_isfile):
                out = gate("r1", [v], runs_root=tmp_runs, wheelhouse=tmp_wheelhouse, fleet_root=tmp_fleet)

        assert out[0]["verdict"] == "affected_fixed"  # not downgraded
        assert out[0]["gate"]["ok"] is True
        assert out[0]["gate"]["rules"]["proof_fails_on_vulnerable"]["ok"] is True
        assert out[0]["gate"]["rules"]["proof_passes_on_fixed"]["ok"] is True
        assert out[0]["gate"]["rules"]["suite_count_not_dropped"]["ok"] is True

    def test_bogus_proof_passing_on_vulnerable_downgrades(self, tmp_runs, tmp_wheelhouse, tmp_fleet):
        """A proof that PASSES on the vulnerable version is bogus → needs_human."""
        work, src = self._make_work(tmp_runs)
        v = make_verdict(verdict="affected_proven", proof=["tests/test_proof.py::test_a"])
        write_verdict(tmp_runs, "r1", "payments-api", v)

        with mock.patch.object(gate_mod, "_ensure_venv", return_value="/fake/venv/python"), \
             mock.patch.object(gate_mod, "_pytest_one") as mock_pytest:
            # The proof PASSES on the vulnerable version — bogus!
            mock_pytest.return_value = (True, 0, "PASSED")
            out = gate("r1", [v], runs_root=tmp_runs, wheelhouse=tmp_wheelhouse, fleet_root=tmp_fleet)

        assert out[0]["verdict"] == "needs_human"  # downgraded!
        assert out[0]["gate"]["ok"] is False
        assert out[0]["gate"]["rules"]["proof_fails_on_vulnerable"]["ok"] is False
        assert "bogus" in out[0]["gate"]["rules"]["proof_fails_on_vulnerable"]["detail"]

    def test_empty_proof_list_fails(self, tmp_runs, tmp_wheelhouse, tmp_fleet):
        work, src = self._make_work(tmp_runs)
        v = make_verdict(verdict="affected_proven", proof=[])
        write_verdict(tmp_runs, "r1", "payments-api", v)

        out = gate("r1", [v], runs_root=tmp_runs, wheelhouse=tmp_wheelhouse, fleet_root=tmp_fleet)
        assert out[0]["verdict"] == "needs_human"
        assert out[0]["gate"]["rules"]["proof_present"]["ok"] is False

    def test_proof_not_a_list_fails(self, tmp_runs, tmp_wheelhouse, tmp_fleet):
        work, src = self._make_work(tmp_runs)
        v = make_verdict(verdict="affected_proven")
        v["proof"] = "tests/test_proof.py::test_a"  # string, not list
        write_verdict(tmp_runs, "r1", "payments-api", v)

        out = gate("r1", [v], runs_root=tmp_runs, wheelhouse=tmp_wheelhouse, fleet_root=tmp_fleet)
        assert out[0]["verdict"] == "needs_human"
        assert out[0]["gate"]["rules"]["proof_present"]["ok"] is False

    def test_suite_count_dropped_downgrades(self, tmp_runs, tmp_wheelhouse, tmp_fleet):
        """If after < before in total test count, downgrade."""
        work, src = self._make_work(tmp_runs)
        v = make_verdict(verdict="affected_fixed",
                         proof=["tests/test_proof.py::test_a"],
                         suite={"before": {"passed": 20, "failed": 0},
                                "after": {"passed": 5, "failed": 0}})
        write_verdict(tmp_runs, "r1", "payments-api", v)

        with mock.patch.object(gate_mod, "_ensure_venv", return_value="/fake/venv/python"), \
             mock.patch.object(gate_mod, "_pytest_one") as mock_pytest:
            def fake_pytest(py, src_dir, test_id, cwd):
                if "fixed" in str(py):
                    return True, 0, "PASS"
                return False, 1, "FAIL"
            mock_pytest.side_effect = fake_pytest

            with mock.patch.object(gate_mod, "venv") as mock_venv:
                mock_venv.EnvBuilder.return_value.create = lambda *a, **k: None
                real_isfile = os.path.isfile
                def fake_isfile(p):
                    if ".venv-fixed" in str(p):
                        return True
                    return real_isfile(p)
                with mock.patch.object(gate_mod.os.path, "isfile", side_effect=fake_isfile):
                    out = gate("r1", [v], runs_root=tmp_runs, wheelhouse=tmp_wheelhouse, fleet_root=tmp_fleet)

        assert out[0]["gate"]["rules"]["suite_count_not_dropped"]["ok"] is False
        assert out[0]["verdict"] == "needs_human"

    def test_suite_count_equal_ok(self, tmp_runs, tmp_wheelhouse, tmp_fleet):
        work, src = self._make_work(tmp_runs)
        v = make_verdict(verdict="affected_fixed",
                         proof=["tests/test_proof.py::test_a"],
                         suite={"before": {"passed": 10, "failed": 0},
                                "after": {"passed": 10, "failed": 0}})
        write_verdict(tmp_runs, "r1", "payments-api", v)

        with mock.patch.object(gate_mod, "_ensure_venv", return_value="/fake/venv/python"), \
             mock.patch.object(gate_mod, "_pytest_one") as mock_pytest:
            def fake_pytest(py, src_dir, test_id, cwd):
                if "fixed" in str(py):
                    return True, 0, "PASS"
                return False, 1, "FAIL"
            mock_pytest.side_effect = fake_pytest
            with mock.patch.object(gate_mod, "venv") as mock_venv:
                mock_venv.EnvBuilder.return_value.create = lambda *a, **k: None
                real_isfile = os.path.isfile
                def fake_isfile(p):
                    if ".venv-fixed" in str(p):
                        return True
                    return real_isfile(p)
                with mock.patch.object(gate_mod.os.path, "isfile", side_effect=fake_isfile):
                    out = gate("r1", [v], runs_root=tmp_runs, wheelhouse=tmp_wheelhouse, fleet_root=tmp_fleet)

        assert out[0]["gate"]["rules"]["suite_count_not_dropped"]["ok"] is True

    def test_no_upgrade_target_means_no_fixed_venv(self, tmp_runs, tmp_wheelhouse, tmp_fleet):
        """affected_proven (no fix) → no pins → proof_passes_on_fixed fails → needs_human."""
        work, src = self._make_work(tmp_runs)
        v = make_verdict(verdict="affected_proven", fix=None, proof=["tests/test_proof.py::test_a"])
        write_verdict(tmp_runs, "r1", "payments-api", v)

        with mock.patch.object(gate_mod, "_ensure_venv", return_value="/fake/venv/python"), \
             mock.patch.object(gate_mod, "_pytest_one") as mock_pytest:
            mock_pytest.return_value = (False, 1, "FAILED on vuln")
            out = gate("r1", [v], runs_root=tmp_runs, wheelhouse=tmp_wheelhouse, fleet_root=tmp_fleet)

        assert out[0]["gate"]["rules"]["proof_passes_on_fixed"]["ok"] is False
        assert out[0]["verdict"] == "needs_human"


# ================================================================ gate() — downgrade-only invariant

class TestDowngradeOnly:
    def test_gate_never_upgrades(self, tmp_runs, tmp_wheelhouse, tmp_fleet):
        """A needs_human verdict must stay needs_human even if all rules pass."""
        v = make_verdict(verdict="needs_human", reason="run timed out")
        write_verdict(tmp_runs, "r1", "payments-api", v)
        out = gate("r1", [v], runs_root=tmp_runs, wheelhouse=tmp_wheelhouse, fleet_root=tmp_fleet)
        assert out[0]["verdict"] == "needs_human"

    def test_affected_proven_can_stay(self, tmp_runs, tmp_wheelhouse, tmp_fleet):
        """When rules pass for affected_proven (with fix pins), verdict is unchanged."""
        work = os.path.join(tmp_runs, "r1", "payments-api")
        src = os.path.join(work, "src")
        os.makedirs(src, exist_ok=True)
        with open(os.path.join(src, "requirements.txt"), "w") as fh:
            fh.write("authlib==1.8.0\n")
        v = make_verdict(verdict="affected_proven",
                         fix={"kind": "upgrade", "target": "1.9.0", "diff_file": None},
                         proof=["tests/test_proof.py::test_a"])
        write_verdict(tmp_runs, "r1", "payments-api", v)

        with mock.patch.object(gate_mod, "_ensure_venv", return_value="/fake/python"), \
             mock.patch.object(gate_mod, "_pytest_one") as mp:
            mp.side_effect = lambda py, s, t, c: (True, 0, "P") if "fixed" in str(py) else (False, 1, "F")
            with mock.patch.object(gate_mod, "venv") as mv:
                mv.EnvBuilder.return_value.create = lambda *a, **k: None
                real = os.path.isfile
                with mock.patch.object(gate_mod.os.path, "isfile",
                                       side_effect=lambda p: True if ".venv-fixed" in str(p) else real(p)):
                    out = gate("r1", [v], runs_root=tmp_runs, wheelhouse=tmp_wheelhouse, fleet_root=tmp_fleet)
        assert out[0]["verdict"] == "affected_proven"
        assert out[0]["gate"]["ok"] is True

    def test_multiple_verdicts_processed(self, tmp_runs, tmp_wheelhouse, tmp_fleet):
        """Gate handles a list of verdicts from multiple repos."""
        for repo in ["svc-a", "svc-b"]:
            write_verdict(tmp_runs, "r1", repo, make_verdict(repo=repo, verdict="needs_human"))
        verdicts = [
            json.load(open(os.path.join(tmp_runs, "r1", r, "verdict.json")))
            for r in ["svc-a", "svc-b"]
        ]
        out = gate("r1", verdicts, runs_root=tmp_runs, wheelhouse=tmp_wheelhouse, fleet_root=tmp_fleet)
        assert len(out) == 2
        assert all(v["verdict"] == "needs_human" for v in out)
        assert all(v["gate"]["ok"] for v in out)

    def test_gate_writes_verdict_back(self, tmp_runs, tmp_wheelhouse, tmp_fleet):
        v = make_verdict(repo="repo1", verdict="needs_human")
        write_verdict(tmp_runs, "rX", "repo1", v)
        gate("rX", [v], runs_root=tmp_runs, wheelhouse=tmp_wheelhouse, fleet_root=tmp_fleet)
        path = os.path.join(tmp_runs, "rX", "repo1", "verdict.json")
        with open(path) as fh:
            disk = json.load(fh)
        assert disk["gate"]["ok"] is True
        assert "rules" in disk["gate"]
