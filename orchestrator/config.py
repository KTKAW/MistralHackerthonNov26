"""Paths and names every step shares.

Everything is read from the environment when it is asked for, so a test can point a run at
other folders. Relative paths are taken from the repository root, not from the current folder.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOW_NAME = "le_chonk_run"
APPROVAL_HOURS = 24

# A run id or a repository name becomes a folder name, so it may hold nothing that moves up a path.
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,80}$")


def _path(variable: str, default: str) -> Path:
    path = Path(os.environ.get(variable, default))
    return path if path.is_absolute() else REPO_ROOT / path


def runs_root() -> Path:
    return _path("LE_CHONK_RUNS_ROOT", "runs")


def fleet_root() -> Path:
    """LE_CHONK_FLEET_ROOT if it is set. Otherwise the fetched demo apps if they are there, else fleet/."""
    if os.environ.get("LE_CHONK_FLEET_ROOT"):
        return _path("LE_CHONK_FLEET_ROOT", "fleet")
    fetched = REPO_ROOT / "runs" / "_fleet"  # where `python -m orchestrator.fetch_fleet` puts them
    return fetched if fetched.is_dir() else REPO_ROOT / "fleet"


def wheelhouse() -> Path:
    return _path("LE_CHONK_WHEELHOUSE", "wheelhouse")


def vibe_home() -> Path:
    return _path("LE_CHONK_VIBE_HOME", "vibe-home")


def sandbox_wrapper() -> Path:
    """The sandbox wrapper. The gate runs agent-written tests through it."""
    return _path("LE_CHONK_SANDBOX", "sandbox/douane")


def pull_requests() -> bool:
    """LE_CHONK_PULL_REQUESTS=draft: open a draft pull request for every fix the gate has verified. Off by default."""
    return os.environ.get("LE_CHONK_PULL_REQUESTS", "off").lower() == "draft"


def allow_unsandboxed() -> bool:
    """Only for tests against stand-in agents. Real runs must leave this off."""
    return os.environ.get("LE_CHONK_ALLOW_UNSANDBOXED", "") == "1"


def model() -> str:
    return os.environ.get("LE_CHONK_MODEL", "mistral-large-4-0")


def python_version() -> str:
    """The Python the wheelhouse was built for. The fleet's wheels are for 3.12."""
    return os.environ.get("LE_CHONK_PYTHON", "3.12")


def max_parallel() -> int:
    """How many repositories are worked on at once. The design's default is 10."""
    try:
        return max(1, int(os.environ.get("LE_CHONK_MAX_PARALLEL", "10")))
    except ValueError:
        return 10


def run_repo_target() -> str:
    """`module:function` of the per-repository worker. The Vibe worker by default."""
    return os.environ.get("LE_CHONK_RUN_REPO", "worker.run_repo:run_repo")


def check_name(value: object, what: str) -> str:
    if not isinstance(value, str) or not _NAME.match(value) or ".." in value:
        raise ValueError(f"not a usable {what}: {value!r}")
    return value


def run_dir(run_id: str, root: Path | str | None = None) -> Path:
    base = Path(root) if root is not None else runs_root()
    if not base.is_absolute():
        base = REPO_ROOT / base
    return base / check_name(run_id, "run id")
