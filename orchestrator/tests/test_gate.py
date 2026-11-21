"""The gate against real fleet services. The stand-in worker writes the claims; the gate re-runs them."""
import json
import stat

import pytest

from orchestrator import config, stub_agent
from orchestrator.gate import gate
from orchestrator.tests.conftest import REPO_ROOT, needs_fleet

pytestmark = needs_fleet


def claim(run_id: str, repo: str) -> dict:
    return stub_agent.run_repo(run_id, repo, fleet_root=config.fleet_root(), runs_root=config.runs_root())["verdict"]


def gated(run_id: str, verdict: dict) -> dict:
    return gate(run_id, [verdict], runs_root=config.runs_root(), wheelhouse=config.wheelhouse())[0]


def failed_rules(verdict: dict) -> list[str]:
    return [name for name, rule in verdict["gate"]["rules"].items() if rule["enforced"] and rule["passed"] is not True]


def test_real_proof_on_the_hidden_route_passes(pipeline, run_id):
    result = gated(run_id, claim(run_id, "billing-api"))
    assert result["verdict"] == "affected_fixed" and result["gate"]["passed"] is True
    rules = result["gate"]["rules"]
    assert "exited 1" in rules["proof_fails_on_vulnerable"]["detail"]
    assert "exited 0" in rules["proof_passes_on_fixed"]["detail"]
    assert "collected 9 before and 10 after" in rules["test_count_never_drops"]["detail"]
    # The gated verdict is on disk for the grid, and the agent's own file is kept beside it.
    repo_dir = config.run_dir(run_id) / "billing-api"
    assert json.loads((repo_dir / "verdict.json").read_text())["gate"]["passed"] is True
    assert "gate" not in json.loads((repo_dir / "verdict.agent.json").read_text())
    assert not (repo_dir / "gate" / "vulnerable" / ".venv").exists()


def test_bogus_proof_that_passes_on_the_vulnerable_version_is_downgraded(pipeline, run_id, monkeypatch):
    monkeypatch.setenv("LE_CHONK_STUB_BOGUS", "session-service")
    result = gated(run_id, claim(run_id, "session-service"))
    assert result["verdict"] == "needs_human"
    assert result["gate"]["original_verdict"] == "affected_fixed"
    assert failed_rules(result) == ["proof_fails_on_vulnerable"]


def test_clean_not_affected_passes_without_running_any_code(pipeline, run_id):
    result = gated(run_id, claim(run_id, "session-service"))
    assert result["verdict"] == "not_affected" and result["gate"]["passed"] is True
    assert result["gate"]["sandboxed"] is None
    assert not (config.run_dir(run_id) / "session-service" / "gate").exists()


def test_not_affected_that_changed_a_file_is_downgraded(pipeline, run_id, monkeypatch):
    monkeypatch.setenv("LE_CHONK_STUB_CHEAT", "token-signer")
    result = gated(run_id, claim(run_id, "token-signer"))
    assert result["verdict"] == "needs_human" and failed_rules(result) == ["no_diff"]
    assert "changed: src/token_signer/app.py" in result["gate"]["rules"]["no_diff"]["detail"]


def test_a_file_missing_from_the_work_copy_is_a_change(pipeline, run_id):
    verdict = claim(run_id, "session-service")
    assert gated(run_id, verdict)["gate"]["passed"] is True
    (config.run_dir(run_id) / "session-service" / "src" / "README.md").unlink()
    result = gated(run_id, verdict)
    assert failed_rules(result) == ["no_diff"] and "deleted: README.md" in result["gate"]["rules"]["no_diff"]["detail"]


def test_the_case_that_depends_on_a_setting_goes_to_a_person_untouched(pipeline, run_id):
    verdict = claim(run_id, "profile-api")
    assert verdict["verdict"] == "needs_human" and "PROFILE_ACCEPT_JSON_TOKENS" in verdict["reason"]
    assert verdict["proof"] == [] and verdict["fix"] is None and len(verdict["path"]) == 4
    result = gated(run_id, verdict)
    assert result["verdict"] == "needs_human" and result["gate"]["original_verdict"] == "needs_human"
    assert not (config.run_dir(run_id) / "profile-api" / "gate").exists()  # nothing to re-run


def test_the_stand_ins_answers_cite_lines_that_exist():
    """Every step of every cited path must be on that line of the fetched app."""
    from orchestrator.tests.conftest import FLEET

    answers = stub_agent.ground_truth()
    assert sorted(answers) == ["auth-gateway", "billing-api", "profile-api", "session-service", "token-signer"]
    for app, answer in answers.items():
        for step in answer["path"]:
            line = (FLEET / app / step["file"]).read_text().splitlines()[step["line"] - 1]
            assert step["has"] in line, f"{app} {step['file']}:{step['line']} is {line.strip()!r}"


def test_the_hidden_route_app_never_names_the_flawed_function():
    from orchestrator.tests.conftest import FLEET

    assert not [p for p in (FLEET / "billing-api").rglob("*.py") if "deserialize_json" in p.read_text()]
    assert stub_agent.ground_truth()["billing-api"]["hidden_route"] is True


def test_not_affected_must_cite_a_path(pipeline, run_id):
    verdict = claim(run_id, "session-service")
    verdict["path"] = []
    assert failed_rules(gated(run_id, verdict)) == ["path_cited"]


def test_changing_an_existing_test_is_downgraded(pipeline, run_id):
    verdict = claim(run_id, "auth-gateway")
    test_file = config.run_dir(run_id) / "auth-gateway" / "src" / "tests" / "test_app.py"
    test_file.write_text(test_file.read_text() + "\n# weakened\n")
    result = gated(run_id, verdict)
    assert result["verdict"] == "needs_human" and "existing_tests_untouched" in failed_rules(result)


def test_requirements_that_could_run_code_are_refused(pipeline, run_id):
    verdict = claim(run_id, "auth-gateway")
    requirements = config.run_dir(run_id) / "auth-gateway" / "src" / "requirements.txt"
    requirements.write_text(requirements.read_text() + "-e ./anything\n")
    result = gated(run_id, verdict)
    assert result["verdict"] == "needs_human" and "fixed_state_built" in failed_rules(result)
    assert "will not install" in result["gate"]["rules"]["fixed_state_built"]["detail"]


def test_without_the_sandbox_the_gate_refuses_to_run_agent_tests(pipeline, run_id, monkeypatch):
    monkeypatch.delenv("LE_CHONK_ALLOW_UNSANDBOXED")
    result = gated(run_id, claim(run_id, "auth-gateway"))
    assert result["verdict"] == "needs_human" and failed_rules(result) == ["sandbox_available"]
    assert not (config.run_dir(run_id) / "auth-gateway" / "gate").exists()


def test_agent_tests_go_through_the_sandbox_wrapper(pipeline, run_id, monkeypatch, tmp_path):
    """A stand-in for track A's `douane`: same interface, no sandbox. It records how it was called."""
    calls = tmp_path / "wrapper-calls.txt"
    wrapper = tmp_path / "douane"
    wrapper.write_text(f'#!/bin/sh\necho "$SANDBOX_WORKDIR" >> {calls}\nexec /bin/bash -c "$*"\n')
    wrapper.chmod(wrapper.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("LE_CHONK_SANDBOX", str(wrapper))
    monkeypatch.delenv("LE_CHONK_ALLOW_UNSANDBOXED")
    result = gated(run_id, claim(run_id, "auth-gateway"))
    assert result["verdict"] == "affected_fixed" and result["gate"]["sandboxed"] is True
    workdirs = set(calls.read_text().split())
    gate_dir = config.run_dir(run_id) / "auth-gateway" / "gate"
    assert workdirs == {str(gate_dir / "vulnerable"), str(gate_dir / "fixed")}


def test_the_gate_never_upgrades(pipeline, run_id):
    verdict = claim(run_id, "billing-api")
    verdict["verdict"] = "needs_human"
    result = gated(run_id, verdict)
    assert result["verdict"] == "needs_human" and result["gate"]["original_verdict"] == "needs_human"


def test_a_verdict_that_breaks_the_schema_is_downgraded(pipeline, run_id):
    bad = json.loads((REPO_ROOT / "examples" / "verdict.bad.json").read_text())
    bad["repo"] = "auth-gateway"
    result = gated(run_id, bad)
    assert result["verdict"] == "needs_human" and failed_rules(result) == ["schema_valid"]


@pytest.mark.parametrize("repo", ["../auth-gateway", "auth-gateway/../../x", ""])
def test_a_repo_name_cannot_leave_the_run_folder(pipeline, run_id, repo):
    verdict = claim(run_id, "session-service")
    verdict["repo"] = repo
    result = gated(run_id, verdict)
    assert result["verdict"] == "needs_human" and result["gate"]["passed"] is False
