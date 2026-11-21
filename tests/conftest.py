"""Shared fixtures/helpers for the repo-level test suites (tracks A + B).

Track A units under test: the two Vibe pre_tool hooks (sandbox/sandbox2.py,
sandbox/path_hook.py), the douane wrapper + Seatbelt profile, and
schema/validate.py. The hooks speak the Vibe 3.1.3 wire protocol: a JSON
payload on stdin, a JSON decision on stdout (empty stdout + exit 0 = pass
through). We exercise them as real subprocesses, exactly like Vibe does.

Track B units under test: the verdict schema, the validate CLI, the fleet
contract, and the CVE premise.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = REPO_ROOT / "examples"

# --- track A: sandbox / worker paths ----------------------------------------
SANDBOX_DIR = REPO_ROOT / "sandbox"
SANDBOX2 = SANDBOX_DIR / "sandbox2.py"
PATH_HOOK = SANDBOX_DIR / "path_hook.py"
DOUANE = SANDBOX_DIR / "douane"
PROFILE_TEMPLATE = SANDBOX_DIR / "profile.sb.template"
SCHEMA_DIR = REPO_ROOT / "schema"
VIBE_HOME = REPO_ROOT / "vibe-home"

# --- track B: fleet paths ----------------------------------------------------
FLEET = REPO_ROOT / "fleet"
WHEELHOUSE = REPO_ROOT / "wheelhouse"
SCHEMA_PATH = REPO_ROOT / "schema" / "verdict.schema.json"
SERVICES = [f"svc-{i:02d}" for i in range(1, 9)]


def run_hook(script: Path, payload, env: dict | None = None, stdin_text: str | None = None):
    """Run a hook script the way Vibe does: JSON payload on stdin.

    Returns (rc, stdout_text, parsed_stdout_json_or_None, env_used).
    """
    if stdin_text is None:
        stdin_text = json.dumps(payload)
    full_env = dict(os.environ)
    if env:
        full_env.update({k: str(v) for k, v in env.items()})
    proc = subprocess.run(
        [sys.executable, str(script)],
        input=stdin_text,
        capture_output=True,
        text=True,
        env=full_env,
    )
    parsed = None
    if proc.stdout.strip():
        parsed = json.loads(proc.stdout)
    return proc.returncode, proc.stdout, parsed, full_env


def shquote(s: str) -> str:
    """Independent re-implementation of POSIX single-quote quoting."""
    return "'" + s.replace("'", "'\\''") + "'"


# --- track A fixtures --------------------------------------------------------


@pytest.fixture
def workdir(tmp_path):
    """A fake work copy: runs/<run>/<repo> with src/, .env, secrets/, advisory.json."""
    work = (tmp_path / "work").resolve()
    (work / "src").mkdir(parents=True)
    (work / "secrets").mkdir()
    (work / "src" / "README.md").write_text("# fake service\n")
    (work / ".env").write_text("MISTRAL_API_KEY=sk-super-secret\n")
    (work / "secrets" / "key.pem").write_text("PRIVATE KEY\n")
    (work / "advisory.json").write_text('{"id": "CVE-2026-96760"}\n')
    return work


@pytest.fixture
def hook_log(tmp_path):
    return tmp_path / "hook.log"


# --- track B fixtures --------------------------------------------------------


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
