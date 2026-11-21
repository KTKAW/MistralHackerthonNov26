"""Make the repo root (orchestrator package) and tools/scan (simulate module)
importable when running the sim tests directly, e.g.:

    uv run pytest -q tools/scan/tests/test_sim_contract.py

The default `uv run pytest -q` run only collects orchestrator/tests and web/tests
(pyproject.toml testpaths); these sim tests are run by path.
"""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
for _p in (str(REPO_ROOT), str(REPO_ROOT / "tools" / "scan")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
