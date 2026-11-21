"""Shared fixtures/helpers for the track-A test suite.

The units under test are the two Vibe pre_tool hooks (sandbox/sandbox2.py,
sandbox/path_hook.py), the douane wrapper + Seatbelt profile, and
schema/validate.py. The hooks speak the Vibe 3.1.3 wire protocol: a JSON
payload on stdin, a JSON decision on stdout (empty stdout + exit 0 = pass
through). We exercise them as real subprocesses, exactly like Vibe does.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SANDBOX_DIR = REPO_ROOT / "sandbox"
SANDBOX2 = SANDBOX_DIR / "sandbox2.py"
PATH_HOOK = SANDBOX_DIR / "path_hook.py"
DOUANE = SANDBOX_DIR / "douane"
PROFILE_TEMPLATE = SANDBOX_DIR / "profile.sb.template"
SCHEMA_DIR = REPO_ROOT / "schema"
EXAMPLES = REPO_ROOT / "examples"
VIBE_HOME = REPO_ROOT / "vibe-home"


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
