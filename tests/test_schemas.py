"""The committed examples must validate against the contract schemas, and the
schemas must enforce the ownership rules the ticket pins."""

import copy
from pathlib import Path

import pytest

from vulnerability_agent import schemas

REPO_ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = REPO_ROOT / "examples" / "contract"


def _example(relative: str) -> object:
    return schemas.load_json(EXAMPLES / relative)


@pytest.mark.parametrize(
    "relative,schema_name",
    [
        ("run.json", "run"),
        ("advisory.json", "advisory"),
        ("payments-svc/verdict.json", "verdict"),
        ("payments-svc/state.json", "state"),
        ("catalog-svc/verdict.json", "verdict"),
        ("catalog-svc/state.json", "state"),
        # state.json alone (no verdict.json) is enough for a needs_human tile
        ("search-svc/state.json", "state"),
    ],
)
def test_committed_examples_validate(relative: str, schema_name: str) -> None:
    schemas.assert_valid(_example(relative), schema_name)


def test_run_json_rejects_an_answer_key() -> None:
    run = copy.deepcopy(_example("run.json"))
    assert isinstance(run, dict)
    run["answer_key"] = {"payments-svc": "affected_fixed"}
    with pytest.raises(schemas.ValidationError):
        schemas.validate(run, "run")


def test_run_json_clock_start_must_be_utc() -> None:
    run = copy.deepcopy(_example("run.json"))
    assert isinstance(run, dict)
    run["clock_start"] = "2026-11-21T09:00:00+01:00"
    with pytest.raises(schemas.ValidationError):
        schemas.validate(run, "run")


def test_verdict_json_is_agent_fields_only() -> None:
    verdict = copy.deepcopy(_example("payments-svc/verdict.json"))
    assert isinstance(verdict, dict)
    for gated_field in ("status", "gate", "usage", "final_at"):
        verdict[gated_field] = "running"
        with pytest.raises(schemas.ValidationError):
            schemas.validate(verdict, "verdict")
        del verdict[gated_field]


def test_verdict_json_rejects_unknown_verdict_value() -> None:
    verdict = copy.deepcopy(_example("payments-svc/verdict.json"))
    assert isinstance(verdict, dict)
    verdict["verdict"] = "safe"
    with pytest.raises(schemas.ValidationError):
        schemas.validate(verdict, "verdict")


def test_state_json_final_requires_verdict_and_final_at() -> None:
    state = copy.deepcopy(_example("catalog-svc/state.json"))
    assert isinstance(state, dict)
    del state["verdict"]
    with pytest.raises(schemas.ValidationError):
        schemas.validate(state, "state")
    state = copy.deepcopy(_example("catalog-svc/state.json"))
    assert isinstance(state, dict)
    state["final_at"] = None
    with pytest.raises(schemas.ValidationError):
        schemas.validate(state, "state")


def test_state_json_running_needs_no_verdict() -> None:
    state = copy.deepcopy(_example("catalog-svc/state.json"))
    assert isinstance(state, dict)
    state["status"] = "running"
    state["verdict"] = None
    state["final_at"] = None
    schemas.assert_valid(state, "state")


def test_state_json_advisory_echo_must_match_advisory_schema() -> None:
    state = copy.deepcopy(_example("payments-svc/state.json"))
    assert isinstance(state, dict)
    advisory = state["advisory"]
    assert isinstance(advisory, dict)
    del advisory["fixed_version"]
    with pytest.raises(schemas.ValidationError):
        schemas.validate(state, "state")
