"""The gate against real fleet services. The stand-in worker writes the claims; the gate re-runs them.

Everything here follows the run contract (docs/contract.md): the worker leaves verdict.json with
agent-owned fields only, its proofs are under proof/, and the gate's outcome is state.json.
"""
import json
import shutil
import stat
import subprocess

import pytest

from orchestrator import config, gate, stub_agent
from orchestrator.gate import gate_repo
from orchestrator.tests.conftest import AUTHLIB, WHEELHOUSE, needs_fleet, write_advisory
from vulnerability_agent import schemas

pytestmark = needs_fleet


def claim(run_id: str, repo: str, advisory: dict | None = None) -> dict:
    """The stand-in's verdict.json for `repo`, in a run about `advisory` (the Authlib one unless given)."""
    write_advisory(run_id, advisory)
    return stub_agent.run_repo(run_id, repo, fleet_root=config.fleet_root(), runs_root=config.runs_root())["verdict"]


def gated(run_id: str, repo: str, **more) -> dict:
    return gate_repo(run_id, repo, runs_root=config.runs_root(), wheelhouse=config.wheelhouse(), **more)


def failed_rules(result: dict) -> list[str]:
    return [name for name, rule in result["gate"]["rules"].items() if rule["passed"] is not True]


def on_disk(run_id: str, repo: str, name: str) -> dict:
    return json.loads((config.run_dir(run_id) / repo / name).read_text())


def rewrite_verdict(run_id: str, repo: str, **changes) -> None:
    """Change the worker's verdict.json, as a worker could."""
    path = config.run_dir(run_id) / repo / "verdict.json"
    path.write_text(json.dumps({**json.loads(path.read_text()), **changes}))


def test_real_proof_on_the_hidden_route_passes(pipeline, run_id):
    told = claim(run_id, "billing-api")
    result = gated(run_id, "billing-api")
    assert result["verdict"] == "affected_fixed" and result["gate"]["passed"] is True
    rules = result["gate"]["rules"]
    proof = "proof/test_proof_cve_2026_96760.py::test_forged_token_is_rejected"
    assert f"{proof} exited 1" in rules["proof_fails_on_vulnerable"]["detail"]
    assert f"{proof} exited 0" in rules["proof_passes_on_fixed"]["detail"]
    assert rules["no_test_pass_to_fail_between_baselines"]["detail"] == "9 passed / 0 failed on vulnerable, 9 passed / 0 failed on fixed"
    # The outcome is the orchestrator's state.json. The worker's verdict.json is left exactly as it wrote it.
    state = on_disk(run_id, "billing-api", "state.json")
    schemas.validate(state, "state")
    assert state["status"] == "final" and state["verdict"] == "affected_fixed" and state["advisory"] == AUTHLIB
    assert {item["rule"] for item in state["gate"]} >= {"proof_fails_on_vulnerable", "proof_passes_on_fixed", "existing_tests_byte_identical"}
    assert all(set(item) == {"rule", "passed", "detail"} for item in state["gate"])
    assert "1 failed" in state["proof_output"][proof]  # the saved output of the proof on the vulnerable baseline
    assert on_disk(run_id, "billing-api", "verdict.json") == told and "gate" not in told and "repo" not in told
    schemas.validate(told, "verdict")
    # fix.diff is computed here, from the work copy and the fleet copy.
    diff = (config.run_dir(run_id) / "billing-api" / "fix.diff").read_text()
    assert "-authlib==1.8.0" in diff and "+authlib==1.9.0" in diff and "a/requirements.txt" in diff
    assert not (config.run_dir(run_id) / "billing-api" / "gate" / "vulnerable" / "venv").exists()


def test_bogus_proof_that_passes_on_the_vulnerable_version_is_downgraded(pipeline, run_id, monkeypatch):
    monkeypatch.setenv("LE_CHONK_STUB_BOGUS", "session-service")
    claim(run_id, "session-service")
    result = gated(run_id, "session-service")
    assert result["verdict"] == "needs_human"
    assert result["gate"]["original_verdict"] == "affected_fixed"
    assert failed_rules(result) == ["proof_fails_on_vulnerable"]
    assert on_disk(run_id, "session-service", "state.json")["verdict"] == "needs_human"
    assert on_disk(run_id, "session-service", "verdict.json")["verdict"] == "affected_fixed"  # the claim is kept, and is not a result


def test_clean_not_affected_passes_without_running_any_code(pipeline, run_id):
    claim(run_id, "session-service")
    result = gated(run_id, "session-service")
    assert result["verdict"] == "not_affected" and result["gate"]["passed"] is True
    assert result["gate"]["sandboxed"] is None
    assert "cited lines exist; the reasoning is not machine-checked" in result["gate"]["rules"]["cited_path_exists"]["detail"]
    repo_dir = config.run_dir(run_id) / "session-service"
    assert not (repo_dir / "gate").exists() and (repo_dir / "fix.diff").read_text() == ""


def test_not_affected_that_changed_a_file_is_downgraded(pipeline, run_id, monkeypatch):
    monkeypatch.setenv("LE_CHONK_STUB_CHEAT", "token-signer")
    claim(run_id, "token-signer")
    result = gated(run_id, "token-signer")
    assert result["verdict"] == "needs_human" and failed_rules(result) == ["no_diff_in_src"]
    assert "changed: src/token_signer/app.py" in result["gate"]["rules"]["no_diff_in_src"]["detail"]
    assert "+# edited although the verdict says not affected" in (config.run_dir(run_id) / "token-signer" / "fix.diff").read_text()


def test_a_file_missing_from_the_work_copy_is_a_change(pipeline, run_id):
    claim(run_id, "session-service")
    assert gated(run_id, "session-service")["gate"]["passed"] is True
    (config.run_dir(run_id) / "session-service" / "src" / "README.md").unlink()
    result = gated(run_id, "session-service")
    assert failed_rules(result) == ["no_diff_in_src"] and "deleted: README.md" in result["gate"]["rules"]["no_diff_in_src"]["detail"]


def test_the_case_that_depends_on_a_setting_goes_to_a_person_untouched(pipeline, run_id):
    told = claim(run_id, "profile-api")
    assert told["verdict"] == "needs_human" and "PROFILE_ACCEPT_JSON_TOKENS" in told["reason"]
    assert told["proof"] == [] and told["fix"]["kind"] == "none" and len(told["path"]) == 4
    result = gated(run_id, "profile-api")
    assert result["verdict"] == "needs_human" and result["gate"]["original_verdict"] == "needs_human" and result["gate"]["passed"] is True
    assert not (config.run_dir(run_id) / "profile-api" / "gate").exists()  # nothing to re-run


def test_the_stand_ins_answers_cite_lines_that_exist():
    """Every step of every cited path must be on that line of the fetched app."""
    from orchestrator.tests.conftest import FLEET

    answers = stub_agent.ground_truth()
    assert len(answers) == 11 and all(answer["advisories"] and answer["package"] for answer in answers.values())
    for app, answer in answers.items():
        for step in answer["path"]:
            line = (FLEET / app / step["file"]).read_text().splitlines()[step["line"] - 1]
            assert step["has"] in line, f"{app} {step['file']}:{step['line']} is {line.strip()!r}"


def test_the_hidden_route_app_never_names_the_flawed_function():
    from orchestrator.tests.conftest import FLEET

    assert not [p for p in (FLEET / "billing-api").rglob("*.py") if "deserialize_json" in p.read_text()]
    assert stub_agent.ground_truth()["billing-api"]["hidden_route"] is True


def test_not_affected_must_cite_a_path(pipeline, run_id):
    claim(run_id, "session-service")
    rewrite_verdict(run_id, "session-service", path=[])
    assert failed_rules(gated(run_id, "session-service")) == ["cited_path_exists"]


@pytest.mark.parametrize("step, said", [
    ({"file": "src/src/session_service/app.py", "line": 99999, "note": "no such line"}, "so there is no line 99999"),
    ({"file": "src/src/session_service/nothing.py", "line": 1, "note": "no such file"}, "does not exist"),
    ({"file": "../auth-gateway/src/requirements.txt", "line": 1, "note": "another repository's folder"}, "is not a path inside the run folder"),
])
def test_a_cited_line_that_does_not_exist_is_downgraded(pipeline, run_id, step, said):
    claim(run_id, "session-service")
    rewrite_verdict(run_id, "session-service", path=[step])
    result = gated(run_id, "session-service")
    assert result["verdict"] == "needs_human" and failed_rules(result) == ["cited_path_exists"]
    assert said in result["gate"]["rules"]["cited_path_exists"]["detail"]


def test_changing_an_existing_test_is_downgraded(pipeline, run_id):
    claim(run_id, "auth-gateway")
    test_file = config.run_dir(run_id) / "auth-gateway" / "src" / "tests" / "test_app.py"
    test_file.write_text(test_file.read_text() + "\n# weakened\n")
    result = gated(run_id, "auth-gateway")
    assert result["verdict"] == "needs_human" and "existing_tests_byte_identical" in failed_rules(result)


def test_a_proof_inside_the_work_copy_is_not_a_proof(pipeline, run_id):
    told = claim(run_id, "auth-gateway")
    repo_dir = config.run_dir(run_id) / "auth-gateway"
    shutil.copy(repo_dir / "proof" / "test_proof_cve_2026_96760.py", repo_dir / "src" / "tests" / "test_proof.py")
    rewrite_verdict(run_id, "auth-gateway", proof=[{**told["proof"][0], "test_id": "src/tests/test_proof.py::test_forged_token_is_rejected"}])
    result = gated(run_id, "auth-gateway")
    assert result["verdict"] == "needs_human" and failed_rules(result) == ["proof_in_proof_folder"]
    assert not (repo_dir / "gate").exists()


def test_a_proof_that_does_not_claim_to_fail_on_the_vulnerable_version_is_downgraded(pipeline, run_id):
    told = claim(run_id, "auth-gateway")
    rewrite_verdict(run_id, "auth-gateway", proof=[{**told["proof"][0], "on_vulnerable": "pass"}])
    result = gated(run_id, "auth-gateway")
    assert result["verdict"] == "needs_human" and failed_rules(result) == ["proof_fails_on_vulnerable"]


def test_requirements_that_could_run_code_are_refused(pipeline, run_id):
    claim(run_id, "auth-gateway")
    requirements = config.run_dir(run_id) / "auth-gateway" / "src" / "requirements.txt"
    requirements.write_text(requirements.read_text() + "-e ./anything\n")
    result = gated(run_id, "auth-gateway")
    assert result["verdict"] == "needs_human" and "fixed_baseline_built" in failed_rules(result)
    assert "will not install" in result["gate"]["rules"]["fixed_baseline_built"]["detail"]


def test_without_the_sandbox_the_gate_refuses_to_run_agent_tests(pipeline, run_id, monkeypatch):
    monkeypatch.delenv("LE_CHONK_ALLOW_UNSANDBOXED")
    claim(run_id, "auth-gateway")
    result = gated(run_id, "auth-gateway")
    assert result["verdict"] == "needs_human" and failed_rules(result) == ["sandbox_available"]
    assert not (config.run_dir(run_id) / "auth-gateway" / "gate").exists()


def test_agent_tests_go_through_the_sandbox_wrapper(pipeline, run_id, monkeypatch, tmp_path):
    """A stand-in for the `douane` wrapper: same interface, no sandbox. It records how it was called."""
    calls = tmp_path / "wrapper-calls.txt"
    wrapper = tmp_path / "douane"
    wrapper.write_text(f'#!/bin/sh\necho "$SANDBOX_WORKDIR" >> {calls}\nexec /bin/bash -c "$*"\n')
    wrapper.chmod(wrapper.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("LE_CHONK_SANDBOX", str(wrapper))
    monkeypatch.delenv("LE_CHONK_ALLOW_UNSANDBOXED")
    claim(run_id, "auth-gateway")
    result = gated(run_id, "auth-gateway")
    assert result["verdict"] == "affected_fixed" and result["gate"]["sandboxed"] is True
    workdirs = set(calls.read_text().split())
    gate_dir = config.run_dir(run_id) / "auth-gateway" / "gate"
    assert workdirs == {str(gate_dir / "vulnerable"), str(gate_dir / "fixed")}


def test_the_gate_never_upgrades(pipeline, run_id):
    claim(run_id, "billing-api")
    rewrite_verdict(run_id, "billing-api", verdict="needs_human")
    result = gated(run_id, "billing-api")
    assert result["verdict"] == "needs_human" and result["gate"]["original_verdict"] == "needs_human"


def test_a_verdict_that_marks_itself_gated_is_downgraded(pipeline, run_id):
    """verdict.json holds agent-owned fields only. A worker that adds a gate result or a status breaks the schema."""
    claim(run_id, "auth-gateway")
    rewrite_verdict(run_id, "auth-gateway", gate=[{"rule": "proof_fails_on_vulnerable", "passed": True, "detail": ""}], status="final")
    result = gated(run_id, "auth-gateway")
    assert result["verdict"] == "needs_human" and failed_rules(result) == ["verdict_valid"]
    assert not (config.run_dir(run_id) / "auth-gateway" / "gate").exists()


def test_no_verdict_file_is_a_state_the_orchestrator_writes_itself(pipeline, run_id):
    write_advisory(run_id)
    (config.run_dir(run_id) / "auth-gateway").mkdir()
    result = gated(run_id, "auth-gateway")
    assert result["verdict"] == "needs_human" and failed_rules(result) == ["verdict_file_present"] and result["gate"]["original_verdict"] is None
    state = on_disk(run_id, "auth-gateway", "state.json")
    schemas.validate(state, "state")
    assert state["status"] == "final" and state["verdict"] == "needs_human" and state["final_at"].endswith("Z")


def test_a_worker_that_did_not_finish_is_not_believed_even_if_it_left_a_verdict(pipeline, run_id):
    claim(run_id, "auth-gateway")  # a verdict.json is on disk, as a process that outlived its activity could leave one
    result = gated(run_id, "auth-gateway", problem="The worker's activity did not finish: it timed out", usage={"seconds": 900.0})
    assert result["verdict"] == "needs_human" and failed_rules(result) == ["worker_finished"]
    assert "it timed out" in result["gate"]["rules"]["worker_finished"]["detail"] and result["usage"] == {"seconds": 900.0}
    assert not (config.run_dir(run_id) / "auth-gateway" / "gate").exists()


@pytest.mark.parametrize("repo", ["../auth-gateway", "auth-gateway/../../x", ""])
def test_a_repo_name_cannot_leave_the_run_folder(pipeline, run_id, repo):
    write_advisory(run_id)
    with pytest.raises(ValueError):
        gated(run_id, repo)


def test_a_worker_venv_with_an_edited_library_is_downgraded(pipeline, run_id):
    """Rule 3 of the prompt: never edit the installed library. The gate compares the worker's venv/ with the wheel."""
    claim(run_id, "auth-gateway")
    venv = config.run_dir(run_id) / "auth-gateway" / "venv"
    uv = shutil.which("uv")
    if not uv:
        pytest.skip("needs uv to build the worker's venv")
    subprocess.run([uv, "venv", "--quiet", "--python", config.python_version(), str(venv)], check=True)
    subprocess.run([uv, "pip", "install", "--quiet", "--offline", "--python", str(venv / "bin" / "python"), "--no-index", "--find-links", str(WHEELHOUSE),
                    "--no-deps", "authlib==1.9.0"], check=True)
    ok, detail = gate._library_matches(venv, "authlib", WHEELHOUSE)
    assert ok and "authlib 1.9.0 in venv/ matches authlib-1.9.0-" in detail
    edited = next(venv.glob("lib/python*/site-packages/authlib/jose/__init__.py"))
    edited.write_text(edited.read_text() + "\n# patched in place\n")
    result = gated(run_id, "auth-gateway")
    assert result["verdict"] == "needs_human" and failed_rules(result) == ["installed_library_matches_wheelhouse"]
    assert "authlib/jose/__init__.py" in result["gate"]["rules"]["installed_library_matches_wheelhouse"]["detail"]


def test_a_test_that_passed_before_and_not_after_fails_the_rule():
    before = {"tests.test_app::test_a": "passed", "tests.test_app::test_b": "failed", "tests.test_app::test_c": "passed"}
    assert gate._compare_suites(before, dict(before)) == (True, "2 passed / 1 failed on vulnerable, 2 passed / 1 failed on fixed")
    ok, detail = gate._compare_suites(before, {**before, "tests.test_app::test_a": "failed"})
    assert not ok and detail.endswith("passed before and not after: tests.test_app::test_a")
    ok, detail = gate._compare_suites(before, {"tests.test_app::test_b": "failed", "tests.test_app::test_c": "passed"})
    assert not ok and "tests.test_app::test_a" in detail  # a test that disappeared did not pass
    assert gate._compare_suites(before, None) == (False, "the repository's own tests did not run cleanly on the fixed baseline")


# ---------------------------------------------------------------- the three advisories from November 2026

TORNADO = {"advisory_id": "CVE-2026-126347", "package": "tornado", "affected_version_range": "<6.6.1", "fixed_version": "6.6.1",
           "flawed_function": "tornado.web.RedirectHandler"}
SOUPSIEVE = {"advisory_id": "CVE-2026-126193", "package": "soupsieve", "affected_version_range": ">=0.4,<3.0.2", "fixed_version": "3.0.2",
             "flawed_function": "CSSParser.parse_pseudo_open"}
MAILPARSER = {"advisory_id": "CVE-2026-129300", "package": "mail-parser", "affected_version_range": ">=3.7.0,<4.6.3", "fixed_version": "4.6.3",
              "flawed_function": "mailparser.utils.receiveds_format"}


@pytest.mark.parametrize("repo, advisory, proof", [
    ("link-redirector", TORNADO, "proof/test_proof_cve_2026_126347.py::LegacyRedirectStaysOnSiteTest::test_legacy_redirect_does_not_leave_site"),
    ("html-extractor", SOUPSIEVE, "proof/test_proof_cve_2026_126193.py::test_deeply_nested_selector_is_handled"),
    ("mail-intake", MAILPARSER, "proof/test_proof_cve_2026_129300.py::test_message_with_out_of_range_received_date_is_still_accepted"),
])
def test_a_fresh_advisory_is_proven_and_fixed_on_the_app_that_is_exposed(pipeline, run_id, repo, advisory, proof):
    claim(run_id, repo, advisory)
    result = gated(run_id, repo)
    assert result["verdict"] == "affected_fixed" and result["gate"]["passed"] is True, result["gate"]["rules"]
    assert result["fix"]["kind"] == "upgrade" and result["fix"]["diff_file"] == "fix.diff"
    assert result["proof"] == [{"test_id": proof, "on_vulnerable": "fail", "on_fixed": "pass"}]
    rules = result["gate"]["rules"]
    assert f"{proof} exited 1" in rules["proof_fails_on_vulnerable"]["detail"]
    assert f"{proof} exited 0" in rules["proof_passes_on_fixed"]["detail"]
    assert rules["no_test_pass_to_fail_between_baselines"]["passed"] is True
    target = f"{advisory['package']}=={advisory['fixed_version']}"
    assert target in (config.run_dir(run_id) / repo / "src" / "requirements.txt").read_text()
    assert "+" + target in (config.run_dir(run_id) / repo / "fix.diff").read_text()


@pytest.mark.parametrize("repo, advisory, said", [
    ("docs-portal", TORNADO, "No capture group starts a target"),
    ("link-checker", SOUPSIEVE, "Every selector passed to select() and select_one() is a constant"),
    ("ticket-mailer", MAILPARSER, "no file imports it"),
])
def test_the_app_that_has_the_package_but_is_not_exposed_is_left_alone(pipeline, run_id, repo, advisory, said):
    claim(run_id, repo, advisory)
    result = gated(run_id, repo)
    assert result["verdict"] == "not_affected" and result["gate"]["passed"] is True and said in result["reason"]
    assert not (config.run_dir(run_id) / repo / "gate").exists()  # nothing was run, nothing was changed


def test_an_app_that_does_not_have_the_package_says_exactly_that(pipeline, run_id):
    claim(run_id, "auth-gateway", TORNADO)
    other = gated(run_id, "auth-gateway")
    assert other["verdict"] == "not_affected" and "requirements.txt does not list tornado" in other["reason"]
    assert other["path"] == [{"file": "src/requirements.txt", "line": 1, "note": "tornado is not among the pinned packages"}]
    claim(run_id + "b", "link-redirector")  # the Authlib advisory, on a Tornado app
    back = gated(run_id + "b", "link-redirector")
    assert back["verdict"] == "not_affected" and "does not list authlib" in back["reason"]


def test_the_stand_in_does_not_stretch_an_answer_to_another_advisory_for_the_same_package(pipeline, run_id):
    earlier = {**TORNADO, "advisory_id": "CVE-2026-116578"}  # another Tornado advisory: the stand-in has no answer for it
    told = claim(run_id, "link-redirector", earlier)
    assert told["verdict"] == "needs_human" and "has no answer for this repository and this advisory" in told["reason"]
    assert told["proof"] == [] and gated(run_id, "link-redirector")["verdict"] == "needs_human"
