"""Unit tests for the verdict contract (schema/verdict.schema.json).

These encode the rules from docs/build-prompt.md Step 1: every verdict.json
produced by a worker, the gate, the grid and the report must validate against
this schema. `proof` is a LIST of test IDs; the gate may only downgrade a
verdict to `needs_human`; `gate`/`usage` are written by the orchestrator only.
"""
import copy

import jsonschema
import pytest

REQUIRED_TOP_LEVEL = [
    "repo", "advisory", "verdict", "reason", "path", "proof", "suite", "follow_ups",
]
VERDICTS = ["not_affected", "affected_proven", "affected_fixed", "needs_human"]


def assert_valid(schema, doc):
    jsonschema.Draft202012Validator(schema).validate(doc)


def assert_invalid(schema, doc):
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(schema).validate(doc)


class TestShippedExamples:
    def test_example_is_valid(self, schema):
        import json
        from pathlib import Path
        doc = json.loads(
            (Path(__file__).resolve().parents[1] / "examples" / "verdict.example.json").read_text()
        )
        assert_valid(schema, doc)

    def test_bad_example_is_invalid(self, schema):
        """proof as a single string (not a list) must be rejected."""
        import json
        from pathlib import Path
        doc = json.loads(
            (Path(__file__).resolve().parents[1] / "examples" / "verdict.bad.json").read_text()
        )
        assert_invalid(schema, doc)


class TestRequiredFields:
    @pytest.mark.parametrize("field", REQUIRED_TOP_LEVEL)
    def test_missing_required_field_is_invalid(self, schema, valid_verdict, field):
        doc = copy.deepcopy(valid_verdict)
        del doc[field]
        assert_invalid(schema, doc)

    def test_minimal_valid_document(self, schema):
        doc = {
            "repo": "r",
            "advisory": {
                "id": "CVE-2026-96760",
                "package": "authlib",
                "affected_range": "<1.9.0",
                "flawed_function": "authlib.jose.JsonWebSignature.deserialize_json",
            },
            "verdict": "not_affected",
            "reason": "no reachable path found",
            "path": [],
            "proof": [],
            "suite": {"before": {"passed": 3, "failed": 0}},
            "follow_ups": [],
        }
        assert_valid(schema, doc)


class TestVerdictEnum:
    @pytest.mark.parametrize("verdict", VERDICTS)
    def test_each_enum_value_is_valid(self, schema, valid_verdict, verdict):
        doc = copy.deepcopy(valid_verdict)
        doc["verdict"] = verdict
        assert_valid(schema, doc)

    @pytest.mark.parametrize("bad", ["safe", "affected", "unknown", "", "NEEDS_HUMAN"])
    def test_non_enum_values_are_invalid(self, schema, valid_verdict, bad):
        """The gate may only downgrade to needs_human — 'safe' must not exist."""
        doc = copy.deepcopy(valid_verdict)
        doc["verdict"] = bad
        assert_invalid(schema, doc)


class TestProofContract:
    def test_proof_must_be_a_list(self, schema, valid_verdict):
        doc = copy.deepcopy(valid_verdict)
        doc["proof"] = "tests/test_x.py::test_y"  # string, not list
        assert_invalid(schema, doc)

    def test_proof_items_must_be_strings(self, schema, valid_verdict):
        doc = copy.deepcopy(valid_verdict)
        doc["proof"] = [42]
        assert_invalid(schema, doc)

    def test_proof_list_of_test_ids_is_valid(self, schema, valid_verdict):
        doc = copy.deepcopy(valid_verdict)
        doc["proof"] = ["tests/test_a.py::test_1", "tests/test_a.py::test_2"]
        assert_valid(schema, doc)


class TestAdvisory:
    @pytest.mark.parametrize("field", ["id", "package", "affected_range", "flawed_function"])
    def test_missing_advisory_field_is_invalid(self, schema, valid_verdict, field):
        doc = copy.deepcopy(valid_verdict)
        del doc["advisory"][field]
        assert_invalid(schema, doc)


class TestPath:
    @pytest.mark.parametrize("field", ["file", "line", "note"])
    def test_path_entry_missing_field_is_invalid(self, schema, valid_verdict, field):
        doc = copy.deepcopy(valid_verdict)
        del doc["path"][0][field]
        assert_invalid(schema, doc)

    def test_path_line_must_be_integer(self, schema, valid_verdict):
        doc = copy.deepcopy(valid_verdict)
        doc["path"][0]["line"] = "42"
        assert_invalid(schema, doc)


class TestSuiteCounts:
    @pytest.mark.parametrize("field", ["passed", "failed"])
    def test_counts_missing_field_is_invalid(self, schema, valid_verdict, field):
        doc = copy.deepcopy(valid_verdict)
        del doc["suite"]["before"][field]
        assert_invalid(schema, doc)

    def test_counts_must_be_integers(self, schema, valid_verdict):
        doc = copy.deepcopy(valid_verdict)
        doc["suite"]["after"]["passed"] = "13"
        assert_invalid(schema, doc)

    def test_suite_after_is_optional(self, schema, valid_verdict):
        doc = copy.deepcopy(valid_verdict)
        del doc["suite"]["after"]
        assert_valid(schema, doc)


class TestFix:
    @pytest.mark.parametrize("kind", ["upgrade", "patch"])
    def test_fix_kinds(self, schema, valid_verdict, kind):
        doc = copy.deepcopy(valid_verdict)
        doc["fix"] = {"kind": kind, "target": "1.9.0", "diff_file": None}
        assert_valid(schema, doc)

    def test_fix_kind_must_be_enum(self, schema, valid_verdict):
        doc = copy.deepcopy(valid_verdict)
        doc["fix"] = {"kind": "hotfix"}
        assert_invalid(schema, doc)

    def test_fix_may_be_null(self, schema, valid_verdict):
        doc = copy.deepcopy(valid_verdict)
        doc["fix"] = None
        assert_valid(schema, doc)


class TestOrchestratorFields:
    def test_gate_and_usage_are_accepted(self, schema, valid_verdict):
        """gate/usage are written by the orchestrator only — free-form objects."""
        doc = copy.deepcopy(valid_verdict)
        doc["gate"] = {"proof_rerun": "pass", "no_diff": "pass"}
        doc["usage"] = {"tokens": 12345, "cost_usd": 0.42, "seconds": 159, "steps": 12}
        assert_valid(schema, doc)
