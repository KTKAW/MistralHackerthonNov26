"""Re-runnable proof of the demo's central premise: CVE-2026-96760.

Builds two throwaway venvs OFFLINE from the repo's wheelhouse (authlib 1.8.0
and 1.9.0) and asserts that the same forged general-JSON-serialization token
(empty `signatures` array — see fleet/*/proof/input.json) is ACCEPTED by
1.8.0 and REJECTED by 1.9.0. This automates the "hand-verified" claim in
fleet/README.md so it can be re-checked on any machine.

Skipped when `uv` is not on PATH.
"""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from conftest import FLEET, WHEELHOUSE

uv = shutil.which("uv")
pytestmark = pytest.mark.skipif(uv is None, reason="uv is required to build offline venvs")

VULNERABLE = "1.8.0"
FIXED = "1.9.0"

# Library-level probe: feed the forged token straight to the flawed entry path.
PROBE = r"""
import json, sys
from authlib.jose import JsonWebSignature
jws = JsonWebSignature(["HS256"])
forged = json.loads(sys.argv[1])
try:
    obj = jws.deserialize(forged, b"demo-hmac-secret-do-not-use-in-prod")
except Exception as e:
    print("REJECTED", type(e).__name__)
    sys.exit(2)
print("ACCEPTED", obj.payload)
"""


def _make_venv(base: Path, version: str) -> Path:
    venv = base / f"venv-authlib-{version}"
    # Python 3.12: the wheelhouse's binary wheels (cffi/cryptography) are
    # cp312, matching the version the fleet was hand-verified on.
    subprocess.run(
        [uv, "venv", "--python", "3.12", str(venv)],
        check=True, capture_output=True, text=True,
    )
    subprocess.run(
        [uv, "pip", "install", "--python", str(venv / "bin" / "python"),
         "--no-index", "--find-links", str(WHEELHOUSE), f"authlib=={version}"],
        check=True, capture_output=True, text=True,
    )
    return venv / "bin" / "python"


def _probe(python: Path, forged: dict) -> subprocess.CompletedProcess:
    return subprocess.run(
        [str(python), "-c", PROBE, json.dumps(forged)],
        capture_output=True, text=True,
    )


@pytest.fixture(scope="module")
def forged_token() -> dict:
    return json.loads((FLEET / "svc-01" / "proof" / "input.json").read_text())


@pytest.fixture(scope="module")
def venvs(tmp_path_factory) -> dict:
    base = tmp_path_factory.mktemp("wheelhouse-venvs")
    return {v: _make_venv(base, v) for v in (VULNERABLE, FIXED)}


def test_forged_token_accepted_on_vulnerable_1_8_0(venvs, forged_token):
    r = _probe(venvs[VULNERABLE], forged_token)
    assert r.returncode == 0, r.stderr
    assert r.stdout.startswith("ACCEPTED"), r.stdout


def test_forged_token_rejected_on_fixed_1_9_0(venvs, forged_token):
    r = _probe(venvs[FIXED], forged_token)
    assert r.returncode == 2, r.stderr
    assert r.stdout.startswith("REJECTED"), r.stdout
    assert "BadSignatureError" in r.stdout


def test_wheelhouse_installs_were_offline(venvs, forged_token):
    """Both probes ran against venvs built with --no-index; sanity-check the
    installed version inside each venv."""
    for version, python in venvs.items():
        r = subprocess.run(
            [str(python), "-c", "import authlib; print(authlib.__version__)"],
            capture_output=True, text=True,
        )
        assert r.stdout.strip() == version
