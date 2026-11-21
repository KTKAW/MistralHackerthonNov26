"""Structural/ground-truth tests for the demo fleet (docs/build-prompt.md Step 2).

These pin the fleet's contract without needing a per-service venv:
every service is complete, pinned to the vulnerable authlib, installable fully
offline from wheelhouse/, carries the harmless forged-token proof, and the
hidden-route service really is invisible to a grep for the flawed function.
"""
import base64
import json
import re
from pathlib import Path

import pytest

from conftest import FLEET, REPO_ROOT, SERVICES, WHEELHOUSE

EXPECTED_FILES = ["README.md", "requirements.txt"]


def _src_files(svc: str) -> list[Path]:
    return [p for p in (FLEET / svc / "src").rglob("*.py")]


class TestFleetLayout:
    def test_eight_services_exist(self):
        present = sorted(p.name for p in FLEET.iterdir() if p.is_dir())
        assert present == SERVICES

    @pytest.mark.parametrize("svc", SERVICES)
    def test_service_is_complete(self, svc):
        root = FLEET / svc
        for rel in EXPECTED_FILES:
            assert (root / rel).is_file(), f"{svc}: missing {rel}"
        assert (root / "tests" / "test_app.py").is_file(), f"{svc}: missing test suite"
        assert (root / "proof" / "input.json").is_file(), f"{svc}: missing proof input"
        assert (root / "proof" / "verify_trigger.py").is_file(), f"{svc}: missing trigger script"
        assert _src_files(svc), f"{svc}: no source under src/"

    @pytest.mark.parametrize("svc", SERVICES)
    def test_readme_states_ground_truth(self, svc):
        text = (FLEET / svc / "README.md").read_text().lower()
        assert "affected" in text, f"{svc}: README must state affected / not affected"


class TestPinning:
    @pytest.mark.parametrize("svc", SERVICES)
    def test_pinned_to_vulnerable_authlib(self, svc):
        req = (FLEET / svc / "requirements.txt").read_text()
        assert re.search(r"^authlib==1\.8\.0$", req, re.M), f"{svc}: must pin authlib==1.8.0"

    @pytest.mark.parametrize("svc", SERVICES)
    def test_every_requirement_resolves_offline_from_wheelhouse(self, svc):
        """Each `pkg==ver` in requirements.txt must have a wheel in wheelhouse/."""
        wheels = {p.name for p in WHEELHOUSE.glob("*.whl")}
        req = (FLEET / svc / "requirements.txt").read_text()
        for line in req.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = re.match(r"^([A-Za-z0-9_.\-]+)==([A-Za-z0-9.]+)$", line)
            assert m, f"{svc}: unpinned requirement {line!r}"
            name, version = m.group(1).replace("-", "_"), m.group(2)
            assert any(w.startswith(f"{name}-{version}-") for w in wheels), (
                f"{svc}: no wheel for {line!r} in wheelhouse/"
            )


class TestWheelhouse:
    def test_both_authlib_versions_present(self):
        wheels = {p.name for p in WHEELHOUSE.glob("authlib-*.whl")}
        assert any(w.startswith("authlib-1.8.0-") for w in wheels)
        assert any(w.startswith("authlib-1.9.0-") for w in wheels)


class TestProofInputs:
    @pytest.mark.parametrize("svc", SERVICES)
    def test_proof_input_is_the_harmless_forged_token(self, svc):
        """CVE-2026-96760 trigger shape: JSON serialization with EMPTY signatures
        array and an attacker-claims payload. Harmless: no network, no files."""
        raw = json.loads((FLEET / svc / "proof" / "input.json").read_text())
        assert raw.get("signatures") == [], f"{svc}: proof must use the empty-signatures bypass"
        payload = raw["payload"]
        pad = "=" * (-len(payload) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload + pad))
        assert claims.get("sub") == "attacker"
        assert claims.get("role") == "admin"

    @pytest.mark.parametrize("svc", SERVICES)
    def test_proof_input_is_json_serialization_shaped(self, svc):
        """Every proof input is a JWS general JSON serialization (dict with
        payload + signatures), never a compact string."""
        raw = json.loads((FLEET / svc / "proof" / "input.json").read_text())
        assert isinstance(raw, dict) and "payload" in raw and "signatures" in raw


class TestHiddenRoute:
    """svc-02 (billing) is the demo's centrepiece: it reaches the flawed
    function only through the general-purpose verify_bearer wrapper, so a text
    search for the flawed function's name finds nothing in the service."""

    def test_svc02_does_not_name_the_flawed_function(self):
        for p in _src_files("svc-02"):
            assert "deserialize_json" not in p.read_text(), f"hidden route broken: {p}"

    def test_svc02_goes_through_generic_wrapper(self):
        security = (FLEET / "svc-02" / "src" / "svc_02" / "security.py").read_text()
        assert "def verify_bearer" in security
        assert ".deserialize(" in security  # routes into the flawed path

    def test_svc01_calls_flawed_function_directly(self):
        app = (FLEET / "svc-01" / "src" / "svc_01" / "app.py").read_text()
        assert "deserialize_json" in app


class TestGroundTruthMatrix:
    def test_matrix_lists_all_eight_services(self):
        readme = (FLEET / "README.md").read_text()
        for svc in SERVICES:
            assert re.search(rf"^\| {svc} \|", readme, re.M), f"fleet/README.md: no matrix row for {svc}"

    def test_matrix_marks_four_affected_and_hidden_route(self):
        readme = (FLEET / "README.md").read_text()
        affected = [svc for svc in SERVICES
                    if re.search(rf"^\| {svc} \|[^|]*\|\s*\*\*YES\*\*", readme, re.M)]
        assert sorted(affected) == ["svc-01", "svc-02", "svc-03", "svc-08"]
        row02 = next(l for l in readme.splitlines() if l.startswith("| svc-02 |"))
        # hidden-route column is the 4th cell: **YES** via the verify_bearer wrapper
        cells = [c.strip() for c in row02.split("|")]
        assert cells[3].startswith("**YES**"), row02
        assert "verify_bearer" in row02
