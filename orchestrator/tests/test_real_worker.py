"""The real worker, the real sandbox and the gate, through the orchestrator's own steps.

Everything here is the code a real run uses, except the model. A scripted program stands in for the
`vibe` executable and does what an agent is asked to do: write a proof test, change the pin, install
the fixed version, write verdict.json. So this checks that the pieces fit: the layout the worker
builds is the layout the gate reads, the worker's venv/ passes the gate's library check, and the
gate's own test runs go through sandbox/douane with no waiver.

It does not check anything a model does.
"""
import json
import shutil
import sys

import pytest

from orchestrator import config, events, steps, stub_agent
from orchestrator.tests.conftest import AUTHLIB, REPO_ROOT, needs_fleet
from vulnerability_agent import schemas

pytestmark = [needs_fleet, pytest.mark.skipif(
    sys.platform != "darwin" or shutil.which("uv") is None or not (REPO_ROOT / "sandbox" / "douane").is_file(),
    reason="needs macOS, uv and sandbox/douane")]

PROOF = "proof/test_proof_cve_2026_96760.py"

# Stands in for `vibe`. It runs where Vibe itself runs: in the repo-run root, outside the sandbox.
FAKE_VIBE = r'''#!{python}
import json, os, subprocess, sys

args = sys.argv[1:]
out, workdir = args[args.index("--output-dir") + 1], args[args.index("--workdir") + 1]
mode = os.environ["FAKE_AGENT"]
if mode in ("fixes", "edits-library"):
    with open(os.path.join(workdir, "{proof}"), "w") as handle:
        handle.write(os.environ["FAKE_PROOF"])
    pins = os.path.join(workdir, "src", "requirements.txt")
    text = open(pins).read().replace("authlib==1.8.0", "authlib==1.9.0")
    open(pins, "w").write(text)
    subprocess.run(["uv", "pip", "install", "--quiet", "--python", os.path.join(workdir, "venv", "bin", "python"), "--offline", "--no-index",
                    "--find-links", os.environ["SANDBOX_WHEELHOUSE"], "--only-binary", ":all:", "authlib==1.9.0"], check=True)
if mode in ("fixes", "edits-library"):
    with open(os.path.join(workdir, "verdict.json"), "w") as handle:
        handle.write(os.environ["FAKE_VERDICT"])
if mode == "edits-library":
    import glob
    target = glob.glob(os.path.join(workdir, "venv", "lib", "python*", "site-packages", "authlib", "jose", "__init__.py"))[0]
    open(target, "a").write("\n# patched in place\n")
with open(os.path.join(out, "export.json"), "w") as handle:
    json.dump({{"outcome": "completed", "cost_usd": 0.05, "steps": 12, "usage": {{"total_tokens": 4321}}}}, handle)
'''


def verdict_for(told: dict) -> str:
    """The verdict a careful agent would write for billing-api, from the answer the tests keep."""
    return json.dumps({
        "verdict": "affected_fixed",
        "reason": f"The entry point {told['entry']} hands caller-controlled input to the flawed function. {told['why']}",
        "path": [{"file": f"src/{step['file']}", "line": step["line"], "note": step["note"]} for step in told["path"]],
        "proof": [{"test_id": f"{PROOF}::test_forged_token_is_rejected", "on_vulnerable": "fail", "on_fixed": "pass"}],
        "fix": {"kind": "upgrade", "detail": "Pinned authlib==1.9.0 in src/requirements.txt.", "diff_file": "fix.diff"},
        "suite": {"before": {"passed": 9, "failed": 0}, "after": {"passed": 10, "failed": 0}},
        "follow_ups": [],
    })


@pytest.fixture
def real_worker(pipeline, tmp_path, monkeypatch):
    """The worker and the sandbox as a real run has them, with the scripted program in place of `vibe`."""
    from worker import setup_vibe_home

    home = tmp_path / "vibe-home"
    setup_vibe_home.setup(home, install=False)
    fake = home / "tool-venv" / "bin" / "vibe"
    fake.parent.mkdir(parents=True)
    fake.write_text(FAKE_VIBE.format(python=sys.executable, proof=PROOF))
    fake.chmod(0o755)
    told = stub_agent.ground_truth()["billing-api"]
    monkeypatch.setenv("LE_CHONK_RUN_REPO", "worker.run_repo:run_repo")
    monkeypatch.setenv("LE_CHONK_VIBE_HOME", str(home))
    monkeypatch.setenv("LE_CHONK_SANDBOX", str(REPO_ROOT / "sandbox" / "douane"))
    monkeypatch.delenv("LE_CHONK_ALLOW_UNSANDBOXED")  # no waiver: agent-written tests run under sandbox-exec or not at all
    monkeypatch.setenv("FAKE_PROOF", stub_agent.proof_test(AUTHLIB["advisory_id"], told))
    monkeypatch.setenv("FAKE_VERDICT", verdict_for(told))
    return pipeline


def run_one(run_id: str, repo: str = "billing-api") -> dict:
    steps.intake(run_id, "CVE-2026-96760 in Authlib", "2026-11-21T10:00:00+00:00")
    steps.read_advisory(run_id, "CVE-2026-96760 in Authlib")
    return steps.verify_repo(run_id, steps.triage_repo(run_id, repo))


def test_a_fix_from_the_real_worker_passes_the_gate_inside_the_sandbox(real_worker, run_id, monkeypatch):
    monkeypatch.setenv("FAKE_AGENT", "fixes")
    result = run_one(run_id)
    rules = result["gate"]["rules"]
    assert result["verdict"] == "affected_fixed" and result["gate"]["passed"] is True, rules
    assert result["gate"]["sandboxed"] is True
    assert "authlib 1.9.0 in venv/ matches authlib-1.9.0-" in rules["installed_library_matches_wheelhouse"]["detail"]
    assert f"{PROOF}::test_forged_token_is_rejected exited 1" in rules["proof_fails_on_vulnerable"]["detail"]
    assert f"{PROOF}::test_forged_token_is_rejected exited 0" in rules["proof_passes_on_fixed"]["detail"]
    assert rules["no_test_pass_to_fail_between_baselines"]["passed"] is True
    assert result["usage"]["tokens"] == 4321 and result["usage"]["cost_usd"] == 0.05 and result["usage"]["steps"] == 12

    repo_dir = config.run_dir(run_id) / "billing-api"
    schemas.validate(json.loads((repo_dir / "state.json").read_text()), "state")
    schemas.validate(json.loads((repo_dir / "verdict.json").read_text()), "verdict")
    assert "+authlib==1.9.0" in (repo_dir / "fix.diff").read_text()
    # The layout is the contract's: the worker's folders, then what the gate and the orchestrator added.
    assert {"src", "proof", "venv", "gate", "vibe", "verdict.json", "state.json", "fix.diff"} <= {p.name for p in repo_dir.iterdir()}
    # What the worker said about its progress reached the run's event log, and none of it is the agent's prose.
    said = [event["text"] for event in events.read(run_id) if event["source"] == "worker"]
    assert any("building a fresh work copy" in text for text in said) and any("agent ended with exit code 0" in text for text in said)


def test_a_worker_that_edits_its_installed_library_is_sent_to_a_person(real_worker, run_id, monkeypatch):
    monkeypatch.setenv("FAKE_AGENT", "edits-library")
    result = run_one(run_id)
    failed = [name for name, rule in result["gate"]["rules"].items() if not rule["passed"]]
    # Its proof and its fix are real, and the gate's own clean baselines agree. The edited library alone decides.
    assert result["verdict"] == "needs_human" and failed == ["installed_library_matches_wheelhouse"]
    assert result["gate"]["rules"]["proof_passes_on_fixed"]["passed"] is True


def test_a_real_worker_that_leaves_no_verdict_becomes_a_state_the_orchestrator_writes(real_worker, run_id, monkeypatch):
    monkeypatch.setenv("FAKE_AGENT", "silent")
    result = run_one(run_id)
    assert result["verdict"] == "needs_human" and result["gate"]["original_verdict"] is None
    assert [name for name, rule in result["gate"]["rules"].items() if not rule["passed"]] == ["verdict_file_present"]
    state = json.loads((config.run_dir(run_id) / "billing-api" / "state.json").read_text())
    assert state["status"] == "final" and state["verdict"] == "needs_human"


def test_without_a_prepared_vibe_home_the_repository_goes_to_a_person(real_worker, run_id, monkeypatch, tmp_path):
    monkeypatch.setenv("LE_CHONK_VIBE_HOME", str(tmp_path / "no-such-home"))
    monkeypatch.setenv("FAKE_AGENT", "fixes")
    result = run_one(run_id)
    assert result["verdict"] == "needs_human"
    assert "worker_finished" in result["gate"]["rules"] and "setup_vibe_home" in result["gate"]["rules"]["worker_finished"]["detail"]
