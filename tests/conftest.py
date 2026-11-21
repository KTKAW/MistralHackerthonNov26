"""Shared fixtures for track C unit tests.

All tests run against temporary directories — nothing touches the real
runs/, fleet/, or wheelhouse/ directories.
"""
from __future__ import annotations

import json
import os
import sys

import pytest

# Make the project root importable (orchestrator/, web/, schema/)
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


# ---------------------------------------------------------------- verdict factories

def make_advisory(**overrides):
    base = {
        "id": "CVE-2026-96760",
        "package": "authlib",
        "affected_range": "<1.9.0",
        "flawed_function": "authlib.jose.JsonWebSignature.verify",
    }
    base.update(overrides)
    return base


def make_verdict(repo="payments-api", verdict="affected_fixed", **overrides):
    """A fully valid verdict dict per schema/verdict.schema.json."""
    v = {
        "repo": repo,
        "advisory": make_advisory(),
        "verdict": verdict,
        "reason": "attacker-controlled input reaches the flawed function",
        "path": [
            {"file": "src/app.py", "line": 42, "note": "POST /token entry point"},
            {"file": "src/auth.py", "line": 17, "note": "calls verify_token"},
        ],
        "proof": ["tests/test_proof.py::test_forged_token"],
        "fix": {"kind": "upgrade", "target": "1.9.0", "diff_file": None},
        "suite": {
            "before": {"passed": 12, "failed": 0},
            "after": {"passed": 13, "failed": 0},
        },
        "follow_ups": [],
    }
    v.update(overrides)
    return v


@pytest.fixture
def advisory():
    return make_advisory()


@pytest.fixture
def valid_verdict():
    return make_verdict()


@pytest.fixture
def tmp_runs(tmp_path):
    """A temporary runs/ root directory."""
    d = tmp_path / "runs"
    d.mkdir()
    return str(d)


@pytest.fixture
def tmp_fleet(tmp_path):
    """A temporary fleet/ root with one pristine repo."""
    d = tmp_path / "fleet"
    repo = d / "payments-api"
    src = repo / "src"
    src.mkdir(parents=True)
    (src / "app.py").write_text("# pristine app\n")
    (repo / "requirements.txt").write_text("authlib==1.8.0\n")
    return str(d)


@pytest.fixture
def tmp_wheelhouse(tmp_path):
    d = tmp_path / "wheelhouse"
    d.mkdir()
    return str(d)


def write_verdict(runs_root, run_id, repo, verdict_dict):
    """Helper: write a verdict.json into runs/<run_id>/<repo>/verdict.json."""
    d = os.path.join(runs_root, run_id, repo)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "verdict.json"), "w") as fh:
        json.dump(verdict_dict, fh, indent=2)
    return d


def write_run_meta(runs_root, run_id, **fields):
    d = os.path.join(runs_root, run_id)
    os.makedirs(d, exist_ok=True)
    meta = {"run_id": run_id, "status": "RUNNING"}
    meta.update(fields)
    with open(os.path.join(d, "run.json"), "w") as fh:
        json.dump(meta, fh, indent=2)
    return meta
