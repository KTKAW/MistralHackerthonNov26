"""Shared test setup.

The tests need the demo fleet and a wheelhouse. Neither is in this repository:

    uv run python -m orchestrator.fetch_fleet     # the five apps, into runs/_fleet
    # wheelhouse/: build it as docs/FLEET.md says

Tests that need them are skipped when they are missing. The stand-in worker replaces track A.
"""
import os
import shutil
import uuid
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
FLEET = Path(os.environ.get("LE_CHONK_TEST_FLEET", REPO_ROOT / "runs" / "_fleet"))
WHEELHOUSE = Path(os.environ.get("LE_CHONK_TEST_WHEELHOUSE", REPO_ROOT / "wheelhouse"))
ADVISORY = Path(__file__).parent / "fixtures" / "advisory.json"

needs_fleet = pytest.mark.skipif(
    not (FLEET / "billing-api" / "requirements.txt").is_file() or not list(WHEELHOUSE.glob("authlib-1.9.0-*.whl")),
    reason="needs the demo fleet in runs/_fleet (python -m orchestrator.fetch_fleet) and a built wheelhouse/",
)


@pytest.fixture
def pipeline(tmp_path, monkeypatch):
    """A clean runs/ folder and the stand-in worker. Returns the runs folder."""
    runs = tmp_path / "runs"
    monkeypatch.setenv("LE_CHONK_RUNS_ROOT", str(runs))
    monkeypatch.setenv("LE_CHONK_FLEET_ROOT", str(FLEET))
    monkeypatch.setenv("LE_CHONK_WHEELHOUSE", str(WHEELHOUSE))
    monkeypatch.setenv("LE_CHONK_RUN_REPO", "orchestrator.stub_agent:run_repo")
    monkeypatch.setenv("LE_CHONK_ADVISORY_JSON", str(ADVISORY))
    monkeypatch.setenv("LE_CHONK_ALLOW_UNSANDBOXED", "1")
    monkeypatch.setenv("LE_CHONK_ADVISORY_LOOKUP", "0")  # no test goes to the network; the lookup has its own tests
    monkeypatch.setenv("LE_CHONK_SANDBOX", str(tmp_path / "no-sandbox-here"))
    for name in ("LE_CHONK_STUB_BOGUS", "LE_CHONK_STUB_CHEAT", "LE_CHONK_STUB_CRASH", "LE_CHONK_STUB_SECONDS"):
        monkeypatch.delenv(name, raising=False)
    return runs


@pytest.fixture
def small_fleet(tmp_path, monkeypatch, pipeline):
    """Three apps: two exposed (one through the hidden route) and one that is not."""
    fleet = tmp_path / "fleet"
    fleet.mkdir()
    for repo in ("auth-gateway", "billing-api", "session-service"):
        shutil.copytree(FLEET / repo, fleet / repo)
    monkeypatch.setenv("LE_CHONK_FLEET_ROOT", str(fleet))
    return fleet


@pytest.fixture
def run_id():
    return "test-" + uuid.uuid4().hex[:10]
