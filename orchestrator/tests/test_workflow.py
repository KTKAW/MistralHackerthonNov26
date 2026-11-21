"""The real workflow class, run on Temporal's local test server through the SDK's own test helpers.

This checks the workflow's logic without Mistral's hosted service and without a key: the
fan-out, the pause for a person, the 24-hour timeout, and that an early approval is ignored.
It does not check anything about the hosted service itself. The first run downloads Temporal's
test server.
"""
import asyncio
import json
import time

import pytest
from temporalio.client import WorkflowExecutionStatus
from temporalio.converter import DataConverter
from temporalio.testing import WorkflowEnvironment

from mistralai.workflows.core.config.config import config as sdk_config
from mistralai.workflows.core.temporal.payload_converter import MistralWorkflowsPayloadConverter
from mistralai.workflows.testing import create_test_worker

from orchestrator import config, steps
from orchestrator.tests.conftest import needs_fleet
from orchestrator.workflow import ACTIVITIES, LeChonkRun

QUEUE = "le-chonk-test"
pytestmark = [needs_fleet, pytest.mark.asyncio]


@pytest.fixture
async def temporal(monkeypatch):
    monkeypatch.setattr(sdk_config.worker, "deployment_name", QUEUE)
    for name in ("mistral_workflows_otel_traces_export", "mistral_workflows_otel_metrics_export", "mistral_workflows_otel_logs_export"):
        monkeypatch.setattr(sdk_config.common, name, False)
    monkeypatch.setattr("mistralai.workflows.core.tracing.utils.temporalio.workflow.upsert_search_attributes", lambda *a, **k: None)
    converter = DataConverter(payload_converter_class=MistralWorkflowsPayloadConverter)
    async with await WorkflowEnvironment.start_time_skipping(data_converter=converter) as env:
        async with create_test_worker(env, [LeChonkRun], activities=ACTIVITIES, task_queue=QUEUE):
            yield env


def _unwrap(result: dict) -> dict:
    """The SDK returns a workflow's dict under "result"."""
    return result["result"] if set(result) == {"result"} else result


async def _until_stage(handle, stage: str, seconds: float = 120) -> dict:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        state = await handle.query("state")
        if state["stage"] == stage:
            return state
        await asyncio.sleep(0.3)
    raise AssertionError(f"the run never reached {stage!r}; last state {state}")


async def test_run_fans_out_pauses_and_completes_on_approve(temporal, small_fleet, run_id, monkeypatch):
    from orchestrator import pull_request

    proposed = []
    monkeypatch.setenv("LE_CHONK_STUB_SECONDS", "1.5")
    monkeypatch.setenv("LE_CHONK_PULL_REQUESTS", "draft")
    monkeypatch.setattr(pull_request, "open_fix_pr", lambda run, verdict, **kwargs: proposed.append(verdict["repo"]) or {
        "url": f"https://github.com/memlish/{verdict['repo']}/pull/1", "number": 1, "branch": "b", "title": "t", "draft": True})
    handle = await temporal.client.start_workflow(config.WORKFLOW_NAME, {"advisory_text": "CVE-2026-96760 in Authlib"}, id=run_id, task_queue=QUEUE)

    # An approval that arrives before the draft exists must change nothing.
    await handle.signal("approve", {"approved_by": "too early"})
    state = await _until_stage(handle, "awaiting_approval")
    assert state == {"stage": "awaiting_approval", "repos": 3, "gated": 3, "approved": False}

    # The three workers started together, not one after another.
    starts = [float((config.run_dir(run_id) / repo / "stub.started").read_text()) for repo in ("auth-gateway", "billing-api", "session-service")]
    assert max(starts) - min(starts) < 1.0

    # It stays running until a person approves.
    await asyncio.sleep(1)
    assert (await handle.describe()).status == WorkflowExecutionStatus.RUNNING
    assert steps.read_state(run_id)["stage"] == "awaiting_approval"

    await handle.signal("approve", {"approved_by": "a person"})
    result = _unwrap(await handle.result())
    assert result["outcome"] == "approved" and result["approved_by"] == "a person"
    assert result["counts"] == {"affected_fixed": 2, "not_affected": 1}
    assert steps.read_state(run_id)["stage"] == "approved"

    states = {repo: json.loads((config.run_dir(run_id) / repo / "state.json").read_text()) for repo in ("auth-gateway", "billing-api", "session-service")}
    assert all(s["status"] == "final" and all(rule["passed"] for rule in s["gate"]) for s in states.values())
    assert [states[repo]["verdict"] for repo in ("auth-gateway", "billing-api", "session-service")] == ["affected_fixed", "affected_fixed", "not_affected"]
    assert (config.run_dir(run_id) / "early-warning.md").is_file()
    record = json.loads((config.run_dir(run_id) / "run.json").read_text())
    assert record["workflow_run_id"] == run_id and record["approved_at"] and record["expired_at"] is None

    # A draft pull request for each verified fix, and only for those: the workflow ran that step for two repositories.
    assert sorted(proposed) == ["auth-gateway", "billing-api"]
    assert not (config.run_dir(run_id) / "session-service" / "pull_request.json").exists()
    assert "Draft pull request with this fix:** https://github.com/memlish/billing-api/pull/1" in (config.run_dir(run_id) / "early-warning.md").read_text()


async def test_run_expires_after_24_hours_without_approval(temporal, small_fleet, run_id):
    handle = await temporal.client.start_workflow(config.WORKFLOW_NAME, {"advisory_text": "CVE-2026-96760 in Authlib"}, id=run_id, task_queue=QUEUE)
    await _until_stage(handle, "awaiting_approval")
    result = _unwrap(await handle.result())  # the test server skips the 24 hours
    assert result["outcome"] == "expired"
    assert steps.read_state(run_id)["stage"] == "expired"
    record = json.loads((config.run_dir(run_id) / "run.json").read_text())
    assert record["expired_at"] and record["approved_at"] is None


async def test_failed_worker_becomes_needs_human_not_a_failed_run(temporal, small_fleet, run_id, monkeypatch):
    monkeypatch.setenv("LE_CHONK_STUB_CRASH", "auth-gateway")
    monkeypatch.setenv("LE_CHONK_STUB_BOGUS", "billing-api")
    handle = await temporal.client.start_workflow(config.WORKFLOW_NAME, {"advisory_text": "CVE-2026-96760 in Authlib"}, id=run_id, task_queue=QUEUE)
    await _until_stage(handle, "awaiting_approval")
    await handle.signal("approve", {"approved_by": "a person"})
    result = _unwrap(await handle.result())
    assert result["counts"] == {"needs_human": 2, "not_affected": 1}
    bogus = json.loads((config.run_dir(run_id) / "billing-api" / "state.json").read_text())
    assert bogus["verdict"] == "needs_human" and json.loads((config.run_dir(run_id) / "billing-api" / "verdict.json").read_text())["verdict"] == "affected_fixed"
    assert {rule["rule"]: rule["passed"] for rule in bogus["gate"]}["proof_fails_on_vulnerable"] is False
    # The worker that crashed left no verdict. The orchestrator wrote that repository's state itself.
    crashed = json.loads((config.run_dir(run_id) / "auth-gateway" / "state.json").read_text())
    assert crashed["status"] == "final" and crashed["verdict"] == "needs_human"
    assert [rule["rule"] for rule in crashed["gate"] if not rule["passed"]] == ["worker_finished"]
    assert not (config.run_dir(run_id) / "auth-gateway" / "verdict.json").exists()


async def test_a_lost_worker_is_named_without_repeating_any_error_text():
    from temporalio.exceptions import ActivityError, RetryState, TimeoutError as ActivityTimeout, TimeoutType

    from orchestrator.workflow import _why

    def failure(cause: BaseException | None) -> ActivityError:
        error = ActivityError("AGENT TEXT", scheduled_event_id=1, started_event_id=2, identity="", activity_type="le_chonk_triage_repo",
                              activity_id="1", retry_state=RetryState.MAXIMUM_ATTEMPTS_REACHED)
        error.__cause__ = cause
        return error

    lost = _why(failure(ActivityTimeout("AGENT TEXT", type=TimeoutType.HEARTBEAT, last_heartbeat_details=[])))
    assert "stopped responding" in lost
    assert "start to close" in _why(failure(ActivityTimeout("AGENT TEXT", type=TimeoutType.START_TO_CLOSE, last_heartbeat_details=[])))
    assert _why(failure(RuntimeError("AGENT TEXT"))) == "RuntimeError"
    assert _why(failure(None)) == "ActivityError"
    assert "AGENT TEXT" not in lost
