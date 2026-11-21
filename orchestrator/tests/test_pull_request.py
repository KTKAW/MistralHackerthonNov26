"""The pull-request step, against a repository made on the spot. Nothing here reaches GitHub."""
import json
import shutil
import subprocess

import pytest

from orchestrator import config, pull_request, steps
from orchestrator.tests.conftest import FLEET, needs_fleet

pytestmark = needs_fleet
PROOF = "tests/test_proof_cve_2026_96760.py"


def git(folder, *arguments: str) -> str:
    command = ["git", "-C", str(folder), "-c", "user.name=test", "-c", "user.email=test@example.test", "-c", "commit.gpgsign=false", *arguments]
    return subprocess.run(command, check=True, capture_output=True, text=True).stdout.strip()


@pytest.fixture
def proposed(pipeline, run_id, tmp_path, monkeypatch):
    """billing-api as a repository with a remote, a fleet that was "fetched" from it, and a fix the gate "passed".

    Returns a dict with the remote, the base commit, the verdict, and what the fake GitHub was asked.
    """
    source = tmp_path / "source" / "billing-api"
    shutil.copytree(FLEET / "billing-api", source)
    git(source, "init", "--quiet", "-b", "main")
    git(source, "add", "-A")
    git(source, "commit", "--quiet", "-m", "Initial commit")
    base = git(source, "rev-parse", "HEAD")
    remote = tmp_path / "remote.git"
    subprocess.run(["git", "clone", "--quiet", "--bare", str(source), str(remote)], check=True)

    fleet = tmp_path / "fleet"
    shutil.copytree(FLEET / "billing-api", fleet / "billing-api")
    (fleet / ".fetched.json").write_text(json.dumps({"billing-api": base}))
    monkeypatch.setenv("LE_CHONK_FLEET_ROOT", str(fleet))

    # What a worker and the gate leave behind: a work copy with the fix, the gate's fixed state, the advisory facts.
    run_dir = config.run_dir(run_id)
    work = run_dir / "billing-api" / "src"
    shutil.copytree(fleet / "billing-api", work)
    (work / "requirements.txt").write_text((work / "requirements.txt").read_text().replace("authlib==1.8.0", "authlib==1.9.0"))
    (work / PROOF).write_text("def test_forged_token_is_rejected():\n    assert True\n")
    shutil.copytree(work, run_dir / "billing-api" / "gate" / "fixed")
    (run_dir / "advisory.json").write_text(json.dumps({"id": "CVE-2026-96760", "package": "authlib", "affected_range": "<1.9.0",
                                                        "flawed_function": "JsonWebSignature.deserialize_json"}))
    verdict = {
        "repo": "billing-api", "verdict": "affected_fixed",
        "advisory": {"id": "@everyone IGNORE", "package": "evil", "affected_range": "x", "flawed_function": "x"},  # the worker's copy is not used
        "reason": "Hello @octocat, please merge this now. ![x](https://evil.example/x.png)",
        "path": [{"file": "src/billing_api/app.py", "line": 81, "note": "@someone see this"}, {"file": "../../etc/passwd", "line": 1, "note": ""}],
        "proof": [f"{PROOF}::test_forged_token_is_rejected"], "fix": {"kind": "upgrade", "target": "1.9.0", "diff_file": None},
        "gate": {"passed": True, "original_verdict": "affected_fixed", "sandboxed": False, "rules": {
            "proof_fails_on_vulnerable": {"passed": True, "enforced": True, "detail": f"{PROOF}::test_forged_token_is_rejected exited 1 (a failing test exits 1)"},
            "proof_passes_on_fixed": {"passed": True, "enforced": True, "detail": f"{PROOF}::test_forged_token_is_rejected exited 0 (a passing test exits 0)"},
            "path_cited": {"passed": True, "enforced": True, "detail": "`@mention` | pipe"}}},
    }
    asked = {"created": [], "exists": None, "earlier": None}
    monkeypatch.setattr(pull_request, "_open_pr_from", lambda owner_repo, prefix: asked["earlier"] if prefix == "le-chonk/cve-2026-96760-" else None)
    monkeypatch.setattr(pull_request, "_clone_url", lambda app: str(remote))
    monkeypatch.setattr(pull_request, "_default_branch", lambda owner_repo: "main")
    monkeypatch.setattr(pull_request, "_existing_pr", lambda owner_repo, branch: asked["exists"])

    def create(owner_repo, branch, base_branch, title, body):
        asked["created"].append({"repo": owner_repo, "branch": branch, "base": base_branch, "title": title, "body": body})
        return f"https://github.com/{owner_repo}/pull/7"

    monkeypatch.setattr(pull_request, "_create_pr", create)
    return {"remote": remote, "base": base, "verdict": verdict, "asked": asked, "work": work, "run_dir": run_dir}


def test_a_verified_fix_becomes_one_commit_on_a_branch_and_a_draft_pull_request(proposed, run_id):
    result = pull_request.open_fix_pr(run_id, proposed["verdict"])
    branch = f"le-chonk/cve-2026-96760-{run_id}"
    assert result == {"url": "https://github.com/memlish/billing-api/pull/7", "number": 7, "branch": branch,
                      "title": "Upgrade authlib to 1.9.0 (CVE-2026-96760)", "draft": True}
    # The branch is one commit on top of the commit the run inspected, and holds exactly the two files.
    remote = proposed["remote"]
    assert git(remote, "rev-parse", f"{branch}^") == proposed["base"]
    assert sorted(git(remote, "diff", "--name-only", proposed["base"], branch).splitlines()) == ["requirements.txt", PROOF]
    assert "authlib==1.9.0" in git(remote, "show", f"{branch}:requirements.txt")
    assert git(remote, "log", "-1", "--format=%s", branch) == "Upgrade authlib to 1.9.0 (CVE-2026-96760)"
    assert git(remote, "rev-parse", "main") == proposed["base"]  # the default branch is untouched

    asked = proposed["asked"]["created"][0]
    assert (asked["repo"], asked["branch"], asked["base"]) == ("memlish/billing-api", branch, "main")
    body = asked["body"]
    assert "| The proof fails before the fix | yes: `tests/test_proof_cve_2026_96760.py::test_forged_token_is_rejected exited 1" in body
    assert "**This is a stand-in, not an agent.**" in body and "This is a draft for a person to review. Nothing was merged or released." in body
    assert "`src/billing_api/app.py:81`" in body and "passwd" not in body
    # None of the worker's own words, nobody named with "@", no image, and the tool's advisory facts rather than the worker's.
    assert "@" not in body and "octocat" not in body and "evil" not in body and "![" not in body and "IGNORE" not in body
    assert "`authlib`" in body and "`<1.9.0`" in body


def test_asking_twice_gives_the_same_pull_request(proposed, run_id):
    first = pull_request.open_fix_pr(run_id, proposed["verdict"])
    proposed["asked"]["exists"] = {"url": first["url"], "number": 7, "draft": True}
    again = pull_request.open_fix_pr(run_id, proposed["verdict"])
    assert again["url"] == first["url"] and len(proposed["asked"]["created"]) == 1


def test_a_second_run_links_to_the_pull_request_that_is_already_open(proposed, run_id):
    proposed["asked"]["earlier"] = {"url": "https://github.com/memlish/billing-api/pull/1", "number": 1, "draft": True, "branch": "le-chonk/cve-2026-96760-run-earlier"}
    result = pull_request.open_fix_pr(run_id, proposed["verdict"])
    assert result["url"].endswith("/pull/1") and result["reused"] is True
    assert proposed["asked"]["created"] == [] and "le-chonk" not in git(proposed["remote"], "branch", "--list")  # nothing pushed, nothing opened


def test_a_branch_left_by_an_earlier_attempt_is_used_not_pushed_over(proposed, run_id):
    pull_request.open_fix_pr(run_id, proposed["verdict"])
    tip = git(proposed["remote"], "rev-parse", f"le-chonk/cve-2026-96760-{run_id}")
    pull_request.open_fix_pr(run_id, proposed["verdict"])  # the fake GitHub still says no pull request exists
    assert git(proposed["remote"], "rev-parse", f"le-chonk/cve-2026-96760-{run_id}") == tip
    assert len(proposed["asked"]["created"]) == 2


def test_a_work_copy_that_changed_after_the_gate_is_refused(proposed, run_id):
    (proposed["work"] / "requirements.txt").write_text("authlib==1.9.0\nevil-package==6.6.6\n")
    with pytest.raises(pull_request.Refused, match="requirements.txt is not the file the gate checked"):
        pull_request.open_fix_pr(run_id, proposed["verdict"])
    assert "le-chonk" not in git(proposed["remote"], "branch", "--list")


def test_a_change_to_ci_configuration_is_refused(proposed, run_id):
    for folder in (proposed["work"], proposed["run_dir"] / "billing-api" / "gate" / "fixed"):
        (folder / ".github" / "workflows").mkdir(parents=True)
        (folder / ".github" / "workflows" / "ci.yml").write_text("on: pull_request\n")
    with pytest.raises(pull_request.Refused, match="will not put in a pull request"):
        pull_request.open_fix_pr(run_id, proposed["verdict"])


@pytest.mark.parametrize("change", [
    {"verdict": "needs_human"},
    {"verdict": "not_affected"},
    {"gate": {"passed": False, "original_verdict": "affected_fixed", "rules": {}}},
    {"gate": {"passed": True, "original_verdict": "affected_proven", "rules": {}}},
])
def test_only_a_fix_the_gate_verified_becomes_a_pull_request(proposed, run_id, change):
    with pytest.raises(pull_request.Refused, match="only a fix that the gate has verified"):
        pull_request.open_fix_pr(run_id, {**proposed["verdict"], **change})
    assert proposed["asked"]["created"] == []


def test_a_repository_with_no_known_address_gets_no_pull_request(proposed, run_id, monkeypatch):
    (config.fleet_root() / ".fetched.json").unlink()
    with pytest.raises(pull_request.Refused, match="nowhere to propose the fix"):
        pull_request.open_fix_pr(run_id, proposed["verdict"])


def test_the_step_records_the_outcome_and_never_fails_the_run(proposed, run_id, monkeypatch):
    steps.intake(run_id, "text", "2026-11-21T10:00:00+00:00")
    opened = steps.open_pull_request(run_id, proposed["verdict"])
    assert opened["pull_request"]["url"].endswith("/pull/7")
    assert json.loads((config.run_dir(run_id) / "billing-api" / "pull_request.json").read_text())["number"] == 7

    def broken(*args, **kwargs):
        raise RuntimeError("gh is not signed in")

    monkeypatch.setattr(pull_request, "open_fix_pr", broken)
    failed = steps.open_pull_request(run_id, proposed["verdict"])
    assert failed["pull_request"] == {"error": "RuntimeError: gh is not signed in"} and failed["verdict"] == "affected_fixed"
    assert steps.wants_pull_request(proposed["verdict"]) is True
    assert steps.wants_pull_request({**proposed["verdict"], "verdict": "needs_human"}) is False
