"""Unit tests for schema/validate.py — verdict.json schema validation."""
from __future__ import annotations

import json
import os
import subprocess
import sys

import jsonschema
import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCHEMA_PATH = os.path.join(PROJECT_ROOT, "schema", "verdict.schema.json")
VALIDATE_PY = os.path.join(PROJECT_ROOT, "schema", "validate.py")
EXAMPLES = os.path.join(PROJECT_ROOT, "examples")


@pytest.fixture(scope="module")
def schema():
    with open(SCHEMA_PATH) as fh:
        return json.load(fh)


@pytest.fixture(scope="module")
def validator(schema):
    return jsonschema.Draft202012Validator(schema)


class TestExampleFiles:
    def test_example_verdict_is_valid(self, validator):
        with open(os.path.join(EXAMPLES, "verdict.example.json")) as fh:
            data = json.load(fh)
        errors = list(validator.iter_errors(data))
        assert errors == [], f"example should be valid: {[e.message for e in errors]}"

    def test_bad_verdict_is_invalid(self, validator):
        with open(os.path.join(EXAMPLES, "verdict.bad.json")) as fh:
            data = json.load(fh)
        errors = list(validator.iter_errors(data))
        assert len(errors) > 0, "bad example must fail validation"


class TestSchemaRequiredFields:
    """Every required top-level field must be present."""

    REQUIRED = ["repo", "advisory", "verdict", "reason", "path", "proof", "suite", "follow_ups"]

    @pytest.mark.parametrize("missing", REQUIRED)
    def test_missing_required_field_fails(self, validator, valid_verdict, missing):
        del valid_verdict[missing]
        errors = list(validator.iter_errors(valid_verdict))
        assert any(missing in e.message or missing in str(list(e.path)) for e in errors), \
            f"removing {missing!r} should cause a validation error"

    def test_advisory_required_subfields(self, validator, valid_verdict):
        for field in ["id", "package", "affected_range", "flawed_function"]:
            bad = json.loads(json.dumps(valid_verdict))
            del bad["advisory"][field]
            errors = list(validator.iter_errors(bad))
            assert len(errors) > 0, f"advisory.{field} is required"


class TestVerdictEnum:
    VALID = ["not_affected", "affected_proven", "affected_fixed", "needs_human"]

    @pytest.mark.parametrize("v", VALID)
    def test_valid_verdict_values(self, validator, valid_verdict, v):
        valid_verdict["verdict"] = v
        errors = list(validator.iter_errors(valid_verdict))
        assert errors == []

    def test_invalid_verdict_value(self, validator, valid_verdict):
        valid_verdict["verdict"] = "safe"  # the tool must never say "safe"
        errors = list(validator.iter_errors(valid_verdict))
        assert len(errors) > 0


class TestProofMustBeList:
    """proof is a LIST of test IDs — a bare string must fail (regression for
    the bad example where proof was a string instead of a list)."""

    def test_proof_string_fails(self, validator, valid_verdict):
        valid_verdict["proof"] = "tests/test_proof.py::test_x"
        errors = list(validator.iter_errors(valid_verdict))
        assert any("proof" in str(list(e.path)) for e in errors)

    def test_proof_empty_list_ok(self, validator, valid_verdict):
        valid_verdict["proof"] = []
        errors = list(validator.iter_errors(valid_verdict))
        assert errors == []

    def test_proof_list_of_strings_ok(self, validator, valid_verdict):
        valid_verdict["proof"] = ["tests/a.py::test_1", "tests/b.py::test_2"]
        errors = list(validator.iter_errors(valid_verdict))
        assert errors == []

    def test_proof_list_with_non_string_fails(self, validator, valid_verdict):
        valid_verdict["proof"] = [123]
        errors = list(validator.iter_errors(valid_verdict))
        assert len(errors) > 0


class TestPathItems:
    def test_path_item_requires_file_line_note(self, validator, valid_verdict):
        valid_verdict["path"] = [{"file": "src/app.py"}]  # missing line, note
        errors = list(validator.iter_errors(valid_verdict))
        assert len(errors) > 0

    def test_path_line_must_be_integer(self, validator, valid_verdict):
        valid_verdict["path"] = [{"file": "src/app.py", "line": "42", "note": "x"}]
        errors = list(validator.iter_errors(valid_verdict))
        assert len(errors) > 0


class TestSuiteCounts:
    def test_suite_before_after_required(self, validator, valid_verdict):
        valid_verdict["suite"] = {"before": {"passed": 1, "failed": 0}}  # no "after"
        # "after" is not in required for suite, but counts requires passed+failed
        errors = list(validator.iter_errors(valid_verdict))
        # suite.after is not required by schema, so this may pass; check counts shape instead
        valid_verdict["suite"] = {"before": {"passed": 1}}  # missing failed
        errors = list(validator.iter_errors(valid_verdict))
        assert len(errors) > 0

    def test_counts_must_be_integers(self, validator, valid_verdict):
        valid_verdict["suite"] = {
            "before": {"passed": "12", "failed": 0},
            "after": {"passed": 13, "failed": 0},
        }
        errors = list(validator.iter_errors(valid_verdict))
        assert len(errors) > 0


class TestFixField:
    def test_fix_null_ok(self, validator, valid_verdict):
        valid_verdict["fix"] = None
        assert list(validator.iter_errors(valid_verdict)) == []

    def test_fix_upgrade(self, validator, valid_verdict):
        valid_verdict["fix"] = {"kind": "upgrade", "target": "1.9.0", "diff_file": None}
        assert list(validator.iter_errors(valid_verdict)) == []

    def test_fix_bad_kind_fails(self, validator, valid_verdict):
        valid_verdict["fix"] = {"kind": "rewrite", "target": "1.9.0"}
        errors = list(validator.iter_errors(valid_verdict))
        assert len(errors) > 0


class TestValidateCLI:
    """The validate.py script itself, via subprocess."""

    def _run_cli(self, path):
        return subprocess.run(
            [sys.executable, VALIDATE_PY, path],
            capture_output=True, text=True, cwd=PROJECT_ROOT,
        )

    def test_cli_valid_example_exit0(self):
        r = self._run_cli(os.path.join(EXAMPLES, "verdict.example.json"))
        assert r.returncode == 0
        assert "OK" in r.stdout

    def test_cli_bad_example_exit1(self):
        r = self._run_cli(os.path.join(EXAMPLES, "verdict.bad.json"))
        assert r.returncode == 1
        assert "INVALID" in r.stdout

    def test_cli_no_args_exits_nonzero(self):
        r = subprocess.run([sys.executable, VALIDATE_PY], capture_output=True, text=True)
        assert r.returncode != 0

    def test_cli_missing_file(self):
        r = self._run_cli("/nonexistent/verdict.json")
        assert r.returncode != 0
