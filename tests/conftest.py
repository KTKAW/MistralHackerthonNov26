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
"""Shared fixtures for track C unit tests.

All tests run against temporary directories — nothing touches the real
runs/, fleet/, or wheelhouse/ directories.
"""



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
