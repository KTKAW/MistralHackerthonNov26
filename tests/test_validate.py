"""Tests for schema/validate.py and the verdict schema itself: the shipped
examples must behave as advertised (good example valid, bad example invalid),
and the schema must enforce the pinned contract fields (proof is a LIST of
test IDs, verdict is one of the four enum values, suite counts are integers...).
"""
import json
import subprocess
import sys

import jsonschema
import pytest

from conftest import EXAMPLES, SCHEMA_DIR, REPO_ROOT

SCHEMA = json.loads((SCHEMA_DIR / "verdict.schema.json").read_text())
VALIDATOR = jsonschema.Draft202012Validator(SCHEMA)


def run_cli(path):
    return subprocess.run(
        [sys.executable, str(SCHEMA_DIR / "validate.py"), str(path)],
        capture_output=True, text=True,
    )


def valid_verdict():
    return json.loads((EXAMPLES / "verdict.example.json").read_text())


class TestCli:
    def test_example_verdict_is_valid(self):
        p = run_cli(EXAMPLES / "verdict.example.json")
        assert p.returncode == 0, p.stdout
        assert "OK" in p.stdout

    def test_bad_example_is_invalid(self):
        p = run_cli(EXAMPLES / "verdict.bad.json")
        assert p.returncode == 1
        assert "INVALID" in p.stdout

    def test_missing_argument_exits_nonzero(self):
        p = subprocess.run([sys.executable, str(SCHEMA_DIR / "validate.py")],
                           capture_output=True, text=True)
        assert p.returncode != 0


class TestSchemaContract:
    def test_example_validates_against_schema(self):
        assert VALIDATOR.is_valid(valid_verdict())

    def test_bad_example_fails(self):
        bad = json.loads((EXAMPLES / "verdict.bad.json").read_text())
        assert not VALIDATOR.is_valid(bad)

    @pytest.mark.parametrize("missing", ["repo", "advisory", "verdict", "reason",
                                         "path", "proof", "suite", "follow_ups"])
    def test_all_top_level_fields_required(self, missing):
        doc = valid_verdict()
        del doc[missing]
        errors = list(VALIDATOR.iter_errors(doc))
        assert errors, f"removing {missing!r} should invalidate the verdict"

    def test_proof_must_be_a_list_not_a_string(self):
        doc = valid_verdict()
        doc["proof"] = "tests/test_proof.py::test_x"  # the exact bad-example mistake
        assert not VALIDATOR.is_valid(doc)

    @pytest.mark.parametrize("v", ["not_affected", "affected_proven",
                                   "affected_fixed", "needs_human"])
    def test_verdict_enum_accepts_all_four(self, v):
        doc = valid_verdict()
        doc["verdict"] = v
        assert VALIDATOR.is_valid(doc)

    def test_verdict_enum_rejects_safe(self):
        # rule 5: "not affected" is a reachability statement, never "safe"
        doc = valid_verdict()
        doc["verdict"] = "safe"
        assert not VALIDATOR.is_valid(doc)

    def test_advisory_requires_four_fields(self):
        doc = valid_verdict()
        doc["advisory"] = {"id": "CVE-2026-96760"}
        assert not VALIDATOR.is_valid(doc)

    def test_path_entries_need_file_line_note(self):
        doc = valid_verdict()
        doc["path"] = [{"file": "src/app.py"}]
        assert not VALIDATOR.is_valid(doc)

    def test_suite_counts_require_passed_and_failed(self):
        doc = valid_verdict()
        doc["suite"] = {"before": {"passed": 12}, "after": {"passed": 13, "failed": 0}}
        assert not VALIDATOR.is_valid(doc)

    def test_fix_kind_enum(self):
        doc = valid_verdict()
        doc["fix"] = {"kind": "hotfix", "target": "1.9.0", "diff_file": None}
        assert not VALIDATOR.is_valid(doc)
        doc["fix"] = {"kind": "upgrade", "target": "1.9.0", "diff_file": None}
        assert VALIDATOR.is_valid(doc)
        doc["fix"] = None  # fix is nullable (e.g. not_affected)
        assert VALIDATOR.is_valid(doc)

    def test_gate_and_usage_are_orchestrator_writable(self):
        doc = valid_verdict()
        doc["gate"] = {"rule": "ok"}
        doc["usage"] = {"tokens": 1}
        assert VALIDATOR.is_valid(doc)
