"""A stand-in for track A's `run_repo`. It is NOT an agent and finds nothing out.

It reads the answer for each app from orchestrator/stub_answers.json and writes the files a
real worker would leave behind, so that the gate, the report, the workflow and the grid can be
built and tested before the real worker exists. The apps themselves hold no answer.

Use it with:  LE_CHONK_RUN_REPO=orchestrator.stub_agent:run_repo  LE_CHONK_ALLOW_UNSANDBOXED=1

Knobs for tests, all optional:
    LE_CHONK_STUB_SECONDS   how long each "agent" pretends to work (default 0)
    LE_CHONK_STUB_BOGUS     a repo that claims "affected_fixed" with a proof that proves nothing
    LE_CHONK_STUB_CHEAT     a repo that claims "not_affected" but edits an application file
    LE_CHONK_STUB_CRASH     a repo whose worker raises
"""
from __future__ import annotations

import base64
import json
import os
import re
import shutil
import time
from pathlib import Path
from typing import Callable

from orchestrator import config

ANSWERS = Path(__file__).with_name("stub_answers.json")


def proof_test(advisory_id: str, answer: dict) -> str:
    """A test that sends a token with no signature to the app's own entry point and expects 401."""
    request = answer["request"]
    claims = json.dumps({"sub": answer.get("subject", "attacker"), "role": "admin"}, separators=(",", ":"))
    payload = base64.urlsafe_b64encode(claims.encode()).rstrip(b"=").decode()
    forged = json.dumps({"payload": payload, "signatures": []})
    body = dict(request.get("body") or {})
    if request["token_in"] == "body":
        sent = f"json={{**{body!r}, 'token': FORGED}}"
    else:
        sent = "headers={'Authorization': 'Bearer ' + FORGED}" + (f", json={body!r}" if body else "")
    return f'''"""Proof for {advisory_id}: {answer["entry"]} must reject a token that carries no signature."""
from fastapi.testclient import TestClient

from {answer["module"]} import app

# A JWS in JSON serialization whose signatures array is empty.
FORGED = {forged!r}


def test_forged_token_is_rejected():
    response = TestClient(app).request({request["method"]!r}, {request["path"]!r}, {sent})
    assert response.status_code == 401, "the token was accepted: " + response.text[:200]
'''


BOGUS_TEST = '''def test_proves_nothing():
    assert True
'''
def ground_truth() -> dict[str, dict]:
    """app -> its answer, from orchestrator/stub_answers.json."""
    return json.loads(ANSWERS.read_text(encoding="utf-8"))["apps"]


def run_repo(run_id: str, repo: str, *, fleet_root: str | Path = "fleet", runs_root: str | Path = "runs",
             vibe_home: str | Path = "vibe-home", heartbeat_fn: Callable[..., None] | None = None) -> dict:
    fleet = Path(fleet_root)
    work = Path(runs_root) / config.check_name(run_id, "run id") / config.check_name(repo, "repository name")
    src = work / "src"
    if work.exists():
        shutil.rmtree(work)
    shutil.copytree(fleet / repo, src, ignore=shutil.ignore_patterns(".venv", "__pycache__", ".pytest_cache", "*.pyc"))
    (work / "stub.started").write_text(f"{time.time():.3f}\n", encoding="utf-8")

    def say(text: str) -> None:
        """Report a step through the heartbeat function, as a real worker can. Only what this code really did."""
        if heartbeat_fn is not None:
            heartbeat_fn("stand-in: " + text)

    say(f"copied the app into a work copy ({sum(1 for p in src.rglob('*') if p.is_file())} files). No agent reads it.")
    seconds = float(os.environ.get("LE_CHONK_STUB_SECONDS", "0"))
    if seconds:
        say(f"waiting {seconds:g} s, the time set for it to stand in for a working agent")
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if heartbeat_fn is not None:
            heartbeat_fn()
        time.sleep(min(0.5, max(0.0, deadline - time.monotonic())))

    if os.environ.get("LE_CHONK_STUB_CRASH") == repo:
        raise RuntimeError("the stand-in worker was told to crash")

    advisory_file = work.parent / "advisory.json"
    advisory = json.loads(advisory_file.read_text(encoding="utf-8")) if advisory_file.is_file() else {
        "id": "CVE-2026-96760", "package": "authlib", "affected_range": "<1.9.0",
        "flawed_function": "authlib.jose.JsonWebSignature.deserialize_json",
    }
    advisory = {key: advisory[key] for key in ("id", "package", "affected_range", "flawed_function")}
    truth = ground_truth().get(repo)
    say("looked this app up in its answer file (orchestrator/stub_answers.json)" if truth else "found no answer for this app in its answer file")
    tests_before = sum(len(re.findall(r"^def test_", f.read_text(encoding="utf-8"), re.M)) for f in (src / "tests").glob("test_*.py"))
    app_files = sorted(p.relative_to(src).as_posix() for p in (src / "src").rglob("app.py"))
    entry_file = app_files[0] if app_files else "src"

    verdict: dict = {"repo": repo, "advisory": advisory, "path": [], "proof": [], "fix": None,
                     "suite": {"before": {"passed": tests_before, "failed": 0}, "after": {"passed": tests_before, "failed": 0}},
                     "follow_ups": []}

    if os.environ.get("LE_CHONK_STUB_BOGUS") == repo:
        (src / "tests" / "test_proof_bogus.py").write_text(BOGUS_TEST, encoding="utf-8")
        _upgrade(src, advisory["package"], "1.9.0")
        verdict.update(verdict="affected_fixed", reason="Claimed without a real proof (stand-in bogus case).",
                       path=[{"file": entry_file, "line": 1, "note": "claimed entry point"}],
                       proof=["tests/test_proof_bogus.py::test_proves_nothing"],
                       fix={"kind": "upgrade", "target": "1.9.0", "diff_file": None})
        verdict["suite"]["after"]["passed"] = tests_before + 1
    elif os.environ.get("LE_CHONK_STUB_CHEAT") == repo:
        with (src / entry_file).open("a", encoding="utf-8") as handle:
            handle.write("\n# edited although the verdict says not affected\n")
        verdict.update(verdict="not_affected", reason="No reachable path found (stand-in cheat case: it edited a file).",
                       path=[{"file": entry_file, "line": 1, "note": "entry point"}])
    elif truth is None:
        verdict.update(verdict="needs_human", reason="The stand-in has no answer for this repository.")
    elif truth["verdict"] == "affected_fixed":
        proof_name = "tests/test_proof_" + re.sub(r"[^a-z0-9]+", "_", advisory["id"].lower()) + ".py"
        (src / proof_name).write_text(proof_test(advisory["id"], truth), encoding="utf-8")
        say(f"wrote the proof test {proof_name}: it sends a token with no signature to {truth['entry']} and expects 401")
        _upgrade(src, advisory["package"], "1.9.0")
        say(f"changed requirements.txt to {advisory['package']}==1.9.0")
        verdict.update(
            verdict="affected_fixed",
            reason=f"The entry point {truth['entry']} hands caller-controlled input to the flawed function. {truth['why']}",
            path=_cited(truth),
            proof=[f"{proof_name}::test_forged_token_is_rejected"],
            fix={"kind": "upgrade", "target": "1.9.0", "diff_file": None},
        )
        verdict["suite"]["after"]["passed"] = tests_before + 1
        if truth.get("hidden_route"):
            verdict["follow_ups"].append("Reached through a wrapper: a text search for the flawed function finds nothing here.")
    elif truth["verdict"] == "not_affected":
        verdict.update(verdict="not_affected", reason=f"No reachable path found. {truth['why']}", path=_cited(truth))
        verdict["follow_ups"].append(f"Upgrade {advisory['package']} out of {advisory['affected_range']} at the next release.")
    else:
        verdict.update(verdict="needs_human", reason=truth["why"], path=_cited(truth))

    (work / "verdict.json").write_text(json.dumps(verdict, indent=2) + "\n", encoding="utf-8")
    say(f"wrote verdict.json claiming {verdict['verdict']}")
    export = {"outcome": "stand-in", "note": "written by orchestrator/stub_agent.py, not by an agent",
              "usage": {"tokens": 0, "cost_usd": 0.0, "steps": 0}}
    (work / "vibe").mkdir(exist_ok=True)
    (work / "vibe" / "export.json").write_text(json.dumps(export, indent=2) + "\n", encoding="utf-8")
    return {"repo": repo, "rc": 0, "verdict": verdict, "export": export}


def _cited(truth: dict) -> list[dict]:
    return [{"file": step["file"], "line": step["line"], "note": step["note"]} for step in truth["path"]]


def _upgrade(src: Path, package: str, version: str) -> None:
    requirements = src / "requirements.txt"
    text = requirements.read_text(encoding="utf-8")
    requirements.write_text(re.sub(rf"(?im)^{re.escape(package)}==.*$", f"{package}=={version}", text), encoding="utf-8")
