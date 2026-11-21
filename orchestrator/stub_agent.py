"""A stand-in for track A's `run_repo`. It is NOT an agent and finds nothing out.

It reads the answer for each app from orchestrator/stub_answers.json and writes the files a
real worker would leave behind, in the layout of the run contract (docs/contract.md): a work
copy in src/, proof tests in proof/, and a verdict.json with agent-owned fields only. That lets
the gate, the report, the workflow and the grid be tested without a model. The apps themselves
hold no answer.

Each answer belongs to one advisory. For any other advisory the stand-in does the one check it
can honestly do: it looks for the advisory's package in the app's requirements.txt. If the
package is not listed, it says so. If it is listed, it has no answer and asks for a person.

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
from vulnerability_agent import contract
from vulnerability_agent import runs as contract_runs

ANSWERS = Path(__file__).with_name("stub_answers.json")
PROOFS = Path(__file__).parent / "tests" / "fixtures" / "fleet_answers"


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

# Proof tests live in proof/, outside the work copy. This puts the app's own code on the import path.
PROOF_CONFTEST = '''import sys
from pathlib import Path

_APP = Path(__file__).resolve().parent.parent / "src"
for _folder in (_APP, _APP / "src"):
    if _folder.is_dir() and str(_folder) not in sys.path:
        sys.path.insert(0, str(_folder))
'''


def ground_truth() -> dict[str, dict]:
    """app -> its answer, from orchestrator/stub_answers.json."""
    return json.loads(ANSWERS.read_text(encoding="utf-8"))["apps"]


def run_repo(run_id: str, repo: str, *, fleet_root: str | Path = "fleet", runs_root: str | Path = "runs",
             vibe_home: str | Path = "vibe-home", heartbeat_fn: Callable[..., None] | None = None) -> dict:
    fleet = Path(fleet_root)
    run_root = Path(runs_root) / config.check_name(run_id, "run id")
    work = run_root / config.check_name(repo, "repository name")
    # One attempt on a fresh folder. state.json is the orchestrator's and stays.
    for left in work.iterdir() if work.is_dir() else []:
        if left.name != contract.STATE_JSON:
            shutil.rmtree(left) if left.is_dir() and not left.is_symlink() else left.unlink()
    src, proof_dir = work / contract.SRC_DIR, work / contract.PROOF_DIR
    shutil.copytree(fleet / repo, src, ignore=shutil.ignore_patterns(".venv", "__pycache__", ".pytest_cache", "*.pyc"))
    proof_dir.mkdir(parents=True)
    (proof_dir / "conftest.py").write_text(PROOF_CONFTEST, encoding="utf-8")
    (work / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")
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

    # The run's own facts, and nothing else: a run without advisory.json has not reached triage.
    advisory = json.loads((run_root / contract.ADVISORY_JSON).read_text(encoding="utf-8"))
    advisory_id, affected = advisory["advisory_id"], advisory["affected_version_range"]
    truth = ground_truth().get(repo)
    say("looked this app up in its answer file (orchestrator/stub_answers.json)" if truth else "found no answer for this app in its answer file")
    tests_before = sum(len(re.findall(r"^\s*(?:async )?def test_", f.read_text(encoding="utf-8"), re.M)) for f in (src / "tests").glob("test_*.py"))
    package = re.sub(r"[-_.]+", "-", advisory["package"]).lower()
    listed = _listed(src / "requirements.txt", package)
    for_this_advisory = bool(truth) and advisory_id.lower() in [name.lower() for name in truth.get("advisories", [])]
    app_files = sorted(p.relative_to(src).as_posix() for p in (src / "src").rglob("app.py"))
    entry_file = app_files[0] if app_files else "requirements.txt"
    requirements = f"{contract.SRC_DIR}/requirements.txt"  # paths in a verdict are relative to the repo-run root

    verdict: dict = {"verdict": "needs_human", "reason": "", "path": [], "proof": [],
                     "fix": {"kind": "none", "detail": "No change."},
                     "suite": {"before": {"passed": tests_before, "failed": 0}, "after": {"passed": tests_before, "failed": 0}},
                     "follow_ups": []}

    fix_version = str((truth or {}).get("fix_version", advisory["fixed_version"]))
    upgrade = {"kind": "upgrade", "detail": f"Pin {advisory['package']}=={fix_version} in {requirements}.", "diff_file": contract.FIX_DIFF}
    if os.environ.get("LE_CHONK_STUB_BOGUS") == repo:
        (proof_dir / "test_proof_bogus.py").write_text(BOGUS_TEST, encoding="utf-8")
        _upgrade(src, advisory["package"], fix_version)
        verdict.update(verdict="affected_fixed", reason="Claimed without a real proof (stand-in bogus case).",
                       path=[{"file": f"{contract.SRC_DIR}/{entry_file}", "line": 1, "note": "claimed entry point"}],
                       proof=[{"test_id": f"{contract.PROOF_DIR}/test_proof_bogus.py::test_proves_nothing", "on_vulnerable": "fail", "on_fixed": "pass"}],
                       fix=upgrade)
    elif os.environ.get("LE_CHONK_STUB_CHEAT") == repo:
        with (src / entry_file).open("a", encoding="utf-8") as handle:
            handle.write("\n# edited although the verdict says not affected\n")
        verdict.update(verdict="not_affected", reason="No reachable path found (stand-in cheat case: it edited a file).",
                       path=[{"file": f"{contract.SRC_DIR}/{entry_file}", "line": 1, "note": "entry point"}])
    elif not for_this_advisory and listed is None:
        say(f"looked for {package} in requirements.txt: it is not listed")
        verdict.update(verdict="not_affected",
                       reason=f"No reachable path found. requirements.txt does not list {package}, the package this advisory is about.",
                       path=[{"file": requirements, "line": 1, "note": f"{package} is not among the pinned packages"}])
    elif not for_this_advisory:
        say(f"found {package} in requirements.txt, and has no answer for this app and this advisory")
        verdict.update(verdict="needs_human", reason=f"requirements.txt lists {package}, and the stand-in has no answer for this repository and this advisory.",
                       path=[{"file": requirements, "line": listed, "note": f"{package} is pinned here"}])
    elif truth["verdict"] == "affected_fixed":
        proof_name = "test_proof_" + re.sub(r"[^a-z0-9]+", "_", advisory_id.lower()) + ".py"
        if truth.get("proof_test"):  # a proof test kept with the answers, written for this app
            (proof_dir / proof_name).write_text((PROOFS / repo / "proof.py").read_text(encoding="utf-8"), encoding="utf-8")
            test_name = truth["proof_test"]
        else:
            (proof_dir / proof_name).write_text(proof_test(advisory_id, truth), encoding="utf-8")
            test_name = "test_forged_token_is_rejected"
        say(f"wrote the proof test {contract.PROOF_DIR}/{proof_name} for {truth['entry']}")
        _upgrade(src, advisory["package"], fix_version)
        say(f"changed requirements.txt to {advisory['package']}=={fix_version}")
        verdict.update(
            verdict="affected_fixed",
            reason=f"The entry point {truth['entry']} hands caller-controlled input to the flawed function. {truth['why']}",
            path=_cited(truth),
            proof=[{"test_id": f"{contract.PROOF_DIR}/{proof_name}::{test_name}", "on_vulnerable": "fail", "on_fixed": "pass"}],
            fix=upgrade,
        )
        if truth.get("hidden_route"):
            verdict["follow_ups"].append("Reached through a wrapper: a text search for the flawed function finds nothing here.")
    elif truth["verdict"] == "not_affected":
        verdict.update(verdict="not_affected", reason=f"No reachable path found. {truth['why']}", path=_cited(truth))
        verdict["follow_ups"].append(f"Upgrade {advisory['package']} out of {affected} at the next release.")
    else:
        verdict.update(verdict="needs_human", reason=truth["why"], path=_cited(truth))

    contract_runs.write_verdict_json(work, verdict)  # checked against the contract's schema: agent-owned fields only
    say(f"wrote verdict.json claiming {verdict['verdict']}")
    export = {"outcome": "stand-in", "note": "written by orchestrator/stub_agent.py, not by an agent",
              "usage": {"tokens": 0, "cost_usd": 0.0, "steps": 0}}
    (work / "vibe").mkdir(exist_ok=True)
    (work / "vibe" / "export.json").write_text(json.dumps(export, indent=2) + "\n", encoding="utf-8")
    return {"repo": repo, "rc": 0, "verdict": verdict, "export": export}


def _cited(truth: dict) -> list[dict]:
    """The answer's code path. Its files are named from the app's root, which is src/ in a repo-run folder."""
    return [{"file": f"{contract.SRC_DIR}/{step['file']}", "line": step["line"], "note": step["note"]} for step in truth["path"]]


def _listed(requirements: Path, package: str) -> int | None:
    """The line of requirements.txt that pins `package`, or None."""
    try:
        lines = requirements.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    for number, line in enumerate(lines, start=1):
        name = re.split(r"[=<>!~\[; ]", line.strip(), maxsplit=1)[0]
        if name and re.sub(r"[-_.]+", "-", name).lower() == package:
            return number
    return None


def _upgrade(src: Path, package: str, version: str) -> None:
    requirements = src / "requirements.txt"
    wanted = re.sub(r"[-_.]+", "-", package).lower()
    lines = requirements.read_text(encoding="utf-8").splitlines()
    for index, line in enumerate(lines):
        name = line.split("==", 1)[0].strip()
        if "==" in line and re.sub(r"[-_.]+", "-", name).lower() == wanted:
            lines[index] = f"{name}=={version}"
    requirements.write_text("\n".join(lines) + "\n", encoding="utf-8")
