"""The grid's API, on the plain-Python fallback and the stand-in worker."""
import json
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from orchestrator import config, steps
from orchestrator.tests.conftest import AUTHLIB, needs_fleet
from web import app as web_app


@pytest.fixture
def client(pipeline, monkeypatch):
    monkeypatch.setenv("LE_CHONK_ORCHESTRATOR", "local")
    web_app.app.state.backend = None
    return TestClient(web_app.app)


def wait_for(client: TestClient, run_id: str, stage: str, seconds: float = 120) -> dict:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        run = client.get(f"/runs/{run_id}").json()
        if run["stage"] == stage:
            return run
        assert run["stage"] != "failed", run
        time.sleep(0.2)
    raise AssertionError(f"never reached {stage!r}: {run}")


def test_page_is_served_and_never_builds_html_from_data(client):
    page = client.get("/").text
    assert "24-hour vulnerability response" in page
    assert "innerHTML" not in page and "insertAdjacentHTML" not in page and "document.write" not in page


def test_posts_must_be_json(client):
    assert client.post("/runs", content="advisory_text=CVE-2026-96760 in authlib", headers={"Content-Type": "application/x-www-form-urlencoded"}).status_code == 415
    assert client.post("/runs/some-run/approve", content="{}", headers={"Content-Type": "text/plain"}).status_code == 415
    assert client.post("/runs", json={"advisory_text": "short"}).status_code == 422


@pytest.mark.parametrize("run_id", ["a..b", "x" * 200, "has space", ".hidden", "%2e%2e%2f%2e%2e"])
def test_run_ids_cannot_reach_other_folders(client, run_id):
    assert client.get(f"/runs/{run_id}").status_code == 404
    assert client.get(f"/runs/{run_id}/report").status_code == 404


@pytest.mark.parametrize("name", ["..", "../x", "a/b", "", "x" * 200])
def test_names_that_would_leave_the_runs_folder_are_refused(name):
    # An HTTP client folds a bare ".." away before it is sent, so check the guard itself too.
    with pytest.raises(ValueError):
        config.run_dir(name)


def test_a_verdict_the_gate_has_not_seen_is_never_a_tile(client, pipeline, run_id):
    steps.update_state(run_id, stage="triage", repos=["auth-gateway", "billing-api"], started_at="2026-11-21T10:00:00+00:00", deadline="2026-11-22T10:00:00+00:00")
    claimed = {"verdict": "affected_fixed", "reason": "UNCHECKED CLAIM", "path": [], "fix": {"kind": "upgrade", "detail": "x"}, "follow_ups": [],
               "proof": [{"test_id": "proof/x.py::t", "on_vulnerable": "fail", "on_fixed": "pass"}],
               "suite": {"before": {"passed": 1, "failed": 0}, "after": {"passed": 1, "failed": 0}}}
    for repo in ("auth-gateway", "billing-api"):
        (config.run_dir(run_id) / repo).mkdir(parents=True)
    # A claim with no state, and one whose state is still "running": neither is a result.
    (config.run_dir(run_id) / "auth-gateway" / "verdict.json").write_text(json.dumps(claimed))
    (config.run_dir(run_id) / "auth-gateway" / "state.json").write_text(json.dumps({"status": "running", "repo": "auth-gateway", "advisory": AUTHLIB}))
    # A claim the gate rejected: the verdict is state.json's, whatever verdict.json says.
    (config.run_dir(run_id) / "billing-api" / "verdict.json").write_text(json.dumps({**claimed, "reason": "REJECTED CLAIM"}))
    (config.run_dir(run_id) / "billing-api" / "state.json").write_text(json.dumps({
        "status": "final", "verdict": "needs_human", "repo": "billing-api", "advisory": AUTHLIB, "final_at": "2026-11-21T10:05:00Z",
        "gate": [{"rule": "proof_fails_on_vulnerable", "passed": False, "detail": ""}], "usage": {}, "proof_output": {}}))
    response = client.get(f"/runs/{run_id}")
    run = response.json()
    assert run["pending"] == ["auth-gateway"] and [t["repo"] for t in run["tiles"]] == ["billing-api"]
    assert "UNCHECKED CLAIM" not in response.text and "REJECTED CLAIM" not in response.text
    tile = run["tiles"][0]
    assert tile["verdict"] == "needs_human" and tile["proof"] == [] and tile["gate"]["failed_rules"] == ["proof_fails_on_vulnerable"]
    assert tile["gate"]["claimed"] == "affected_fixed" and tile["verdict_url"].endswith("/repos/billing-api/state.json")
    assert client.get(f"/runs/{run_id}/repos/auth-gateway/state.json").status_code == 404
    assert client.get(f"/runs/{run_id}/repos/billing-api/state.json").json()["verdict"] == "needs_human"
    assert client.post(f"/runs/{run_id}/approve", json={"approved_by": "x"}).status_code == 409  # no draft yet


@needs_fleet
def test_a_run_from_start_to_approval(client, small_fleet, monkeypatch):
    monkeypatch.setenv("LE_CHONK_STUB_SECONDS", "1")
    monkeypatch.setenv("LE_CHONK_STUB_BOGUS", "session-service")
    started = client.post("/runs", json={"advisory_text": "Authlib: empty signatures validation in JWS JSON deserialization (CVE-2026-96760)"})
    assert started.status_code == 200 and set(started.json()) == {"run_id", "started_at"}
    run_id = started.json()["run_id"]

    run = wait_for(client, run_id, "awaiting_approval")
    assert run["status"] == "RUNNING" and run["pending"] == [] and run["report_ready"] is True
    assert run["advisory"]["id"] == "CVE-2026-96760"
    tiles = {t["repo"]: t for t in run["tiles"]}
    assert tiles["billing-api"]["verdict"] == "affected_fixed" and tiles["billing-api"]["title"] == "Affected, proven and fixed"
    assert tiles["billing-api"]["gate"]["passed"] is True and tiles["billing-api"]["proof"]
    assert tiles["session-service"]["verdict"] == "needs_human" and tiles["session-service"]["proof"] == []
    assert run["counts"] == {"affected_fixed": 2, "needs_human": 1}
    assert "DRAFT early warning: CVE-2026-96760" in client.get(f"/runs/{run_id}/report").text

    assert client.post(f"/runs/{run_id}/approve", json={"approved_by": "a person"}).json() == {"run_id": run_id, "sent": "approve"}
    run = wait_for(client, run_id, "approved", 20)
    assert run["approved_by"] == "a person"
    assert client.post(f"/runs/{run_id}/approve", json={}).status_code == 409  # already closed
    assert run_id in [r["run_id"] for r in client.get("/runs").json()["runs"]]


@needs_fleet
def test_a_run_can_be_watched_and_looked_into(client, small_fleet, monkeypatch):
    monkeypatch.setenv("LE_CHONK_STUB_BOGUS", "session-service")
    run_id = client.post("/runs", json={"advisory_text": "Authlib: empty signatures validation in JWS JSON deserialization (CVE-2026-96760)"}).json()["run_id"]
    wait_for(client, run_id, "awaiting_approval")

    # The event log: three writers, in order, each numbered.
    found = client.get(f"/runs/{run_id}/events").json()["events"]
    assert [event["n"] for event in found] == list(range(1, len(found) + 1))
    assert {event["source"] for event in found} == {"orchestrator", "worker", "gate"}
    assert found[0]["text"].startswith("Run started with 3 repositories")
    billing = [event["text"] for event in found if event["repo"] == "billing-api"]
    assert any(text.startswith("stand-in: wrote the proof test") for text in billing)
    assert any("The proof fails before the fix: proof/test_proof_cve_2026_96760.py::test_forged_token_is_rejected exited 1" in text for text in billing)
    assert billing[-1] == "Gate finished: the claim of affected_fixed stands."
    assert client.get(f"/runs/{run_id}/events", params={"after": len(found) - 1}).json()["events"] == found[-1:]

    # Under the hood: every rule, what the worker changed, and links to the exact lines.
    detail = client.get(f"/runs/{run_id}/repos/billing-api/detail").json()
    assert detail["checked"] is True and detail["gate"]["passed"] is True and detail["claim"]["rejected"] is False
    assert [rule["name"] for rule in detail["gate"]["rules"]][:3] == ["verdict_file_present", "verdict_valid", "work_copy_present"]
    assert all(rule["label"] and rule["passed"] is True for rule in detail["gate"]["rules"])
    assert {(file["name"], file["change"]) for file in detail["files"]} == {("proof/test_proof_cve_2026_96760.py", "added"), ("requirements.txt", "changed")}
    assert "+authlib==1.9.0" in next(file["text"] for file in detail["files"] if file["name"] == "requirements.txt")
    assert "+authlib==1.9.0" in detail["fix_diff"] and detail["claim"]["fix"] == {"kind": "upgrade", "target": "1.9.0", "diff_file": "fix.diff"}
    assert "1 failed" in detail["proof_output"]["proof/test_proof_cve_2026_96760.py::test_forged_token_is_rejected"]
    assert "## " in detail["gate_log"] and detail["events"]

    # A rejected claim is in the inspector, marked as rejected, and still nowhere on the grid.
    rejected = client.get(f"/runs/{run_id}/repos/session-service/detail").json()
    assert rejected["verdict"] == "needs_human" and rejected["claim"]["rejected"] is True and rejected["claim"]["verdict"] == "affected_fixed"
    assert "stand-in bogus case" in rejected["claim"]["reason"]
    assert "stand-in bogus case" not in client.get(f"/runs/{run_id}").text
    assert client.get(f"/runs/{run_id}/repos/no-such-repo/detail").status_code == 404
    assert client.get(f"/runs/{run_id}/repos/..%2f..%2fx/detail").status_code == 404

    # The stream replays from where the page left off and ends once the run is closed.
    client.post(f"/runs/{run_id}/approve", json={"approved_by": "a person"})
    wait_for(client, run_id, "approved", 20)
    with client.stream("GET", f"/runs/{run_id}/stream", headers={"Last-Event-ID": str(len(found))}) as stream:
        lines = [line for line in stream.iter_lines() if line]
    assert lines[0] == f"id: {len(found) + 1}" and "Approved by a person" in lines[1]
    assert lines[-2:] == ["event: end", "data: {}"]


def test_code_path_links_point_at_the_pinned_commit_and_only_at_github(pipeline, run_id, tmp_path, monkeypatch):
    fleet = tmp_path / "linked-fleet"
    (fleet / "billing-api" / "src").mkdir(parents=True)
    (fleet / "billing-api" / "src" / "app.py").write_text("x = 1\n")
    # A cited file is named from the repo-run root, where the repository's own files are under src/.
    commit = "ee9ea0d7b18db020eeeb783ef6edad62570fada2"
    (fleet / ".fetched.json").write_text(json.dumps({"billing-api": commit, "session-service": "not-a-commit"}))
    monkeypatch.setenv("LE_CHONK_FLEET_ROOT", str(fleet))
    links = web_app._repo_links()
    assert list(links) == ["billing-api"] and links["billing-api"]["url"].startswith("https://github.com/")
    path = web_app._path("billing-api", [
        {"file": "src/src/app.py", "line": 1, "note": "real file"},
        {"file": "proof/test_proof.py", "line": 3, "note": "written by the worker, so not on GitHub"},
        {"file": "src/../../etc/passwd", "line": 1, "note": "not a path in the app"},
        {"file": "src/src/app.py", "line": "1); alert(1", "note": "not a line number"},
        {"file": "venv/lib/python3.12/site-packages/authlib/jose/__init__.py", "line": 5, "note": "the installed library, not the repository"},
    ], links["billing-api"])
    assert path[0]["href"] == f"{links['billing-api']['url']}/blob/{commit}/src/app.py#L1"
    assert [step["href"] for step in path[1:]] == [None, None, None, None]


@needs_fleet
def test_a_verified_fix_is_proposed_as_a_draft_pull_request_and_nothing_else_is(client, small_fleet, monkeypatch):
    from orchestrator import pull_request

    proposed = []
    monkeypatch.setenv("LE_CHONK_PULL_REQUESTS", "draft")
    monkeypatch.setenv("LE_CHONK_STUB_BOGUS", "auth-gateway")  # the gate rejects this claim, so it must get no pull request
    monkeypatch.setattr(pull_request, "open_fix_pr", lambda run, verdict, **kwargs: proposed.append(verdict["repo"]) or {
        "url": "https://github.com/memlish/billing-api/pull/3", "number": 3, "branch": "b", "title": "t", "draft": True})
    run_id = client.post("/runs", json={"advisory_text": "Authlib: empty signatures validation in JWS JSON deserialization (CVE-2026-96760)"}).json()["run_id"]
    run = wait_for(client, run_id, "awaiting_approval")
    assert proposed == ["billing-api"] and run["pull_requests"] is True
    tiles = {tile["repo"]: tile for tile in run["tiles"]}
    assert tiles["billing-api"]["pull_request"] == {"url": "https://github.com/memlish/billing-api/pull/3", "number": 3, "draft": True}
    assert tiles["auth-gateway"]["pull_request"] is None and tiles["session-service"]["pull_request"] is None
    assert "Draft pull request with this fix:** https://github.com/memlish/billing-api/pull/3. It is not merged." in client.get(f"/runs/{run_id}/report").text
    texts = [event["text"] for event in client.get(f"/runs/{run_id}/events").json()["events"] if event["repo"] == "billing-api"]
    assert texts[-1] == "Draft pull request opened: https://github.com/memlish/billing-api/pull/3"
    assert client.get(f"/runs/{run_id}/repos/billing-api/detail").json()["pull_request"]["number"] == 3


def test_what_the_pull_request_step_left_is_shown_only_as_a_github_pull_request_link(pipeline, run_id):
    repo_dir = config.run_dir(run_id) / "billing-api"
    repo_dir.mkdir(parents=True)
    for left, shown in [
        ({"url": "https://github.com/memlish/billing-api/pull/3", "number": 3, "draft": True}, {"url": "https://github.com/memlish/billing-api/pull/3", "number": 3, "draft": True}),
        ({"url": "javascript:alert(1)", "number": 3}, {"error": "the pull request step left no result"}),
        ({"url": "https://evil.example/memlish/billing-api/pull/3"}, {"error": "the pull request step left no result"}),
        ({"refused": "the work copy changed after the gate ran"}, {"refused": "the work copy changed after the gate ran"}),
    ]:
        (repo_dir / "pull_request.json").write_text(json.dumps(left))
        assert web_app._pull_request(config.run_dir(run_id), "billing-api") == shown
    (repo_dir / "pull_request.json").unlink()
    assert web_app._pull_request(config.run_dir(run_id), "billing-api") is None
