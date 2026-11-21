"""Shared fixtures/paths for the repo-level test suite."""
import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
FLEET = REPO_ROOT / "fleet"
WHEELHOUSE = REPO_ROOT / "wheelhouse"
SCHEMA_PATH = REPO_ROOT / "schema" / "verdict.schema.json"
EXAMPLES = REPO_ROOT / "examples"

SERVICES = [f"svc-{i:02d}" for i in range(1, 9)]


@pytest.fixture(scope="session")
def repo_root() -> Path:
    return REPO_ROOT


@pytest.fixture(scope="session")
def schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text())


@pytest.fixture(scope="session")
def valid_verdict() -> dict:
    """A known-good verdict document (the shipped example)."""
    return json.loads((EXAMPLES / "verdict.example.json").read_text())


@pytest.fixture(scope="session")
def services() -> list[str]:
    return SERVICES
