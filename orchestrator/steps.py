"""The steps of one run, as plain functions.

Both orchestrators call these: the Mistral Workflows workflow (workflow.py), where each step is
an activity, and the plain-Python fallback (local.py). All file and network work of a run is in
here, so the workflow code itself stays deterministic.

    intake -> read_advisory -> kb_scan_watch (step 0: feed matches, recorded before triage)
    -> triage_repo + verify_repo for each repository -> write_report
    -> (wait for a person) -> close_run

runs/<run_id>/run.json is the run's public state. The web grid reads it.
"""
from __future__ import annotations

import datetime as dt
import importlib
import json
import os
import threading
import time
from pathlib import Path
from typing import Any, Callable

from orchestrator import advisory as advisory_reader
from orchestrator import config, events, kbscan, pull_request
from orchestrator.gate import gate
from orchestrator.report import render_early_warning

_state_lock = threading.Lock()
VERDICTS = ("not_affected", "affected_proven", "affected_fixed", "needs_human")
MAX_WORKER_EVENTS = 300  # per repository: a worker cannot flood the log
MAX_KB_SCAN_MATCHES = 50  # feed findings recorded per run: a feed cannot flood the record


# ---------------------------------------------------------------- run state


def read_state(run_id: str) -> dict:
    try:
        data = json.loads((config.run_dir(run_id) / "run.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def update_state(run_id: str, **changes: Any) -> dict:
    run_dir = config.run_dir(run_id)
    run_dir.mkdir(parents=True, exist_ok=True)
    with _state_lock:
        state = read_state(run_id)
        state["run_id"] = config.check_name(run_id, "run id")
        state.update(changes)
        temporary = run_dir / f"run.json.{threading.get_ident()}.tmp"
        temporary.write_text(json.dumps(state, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        os.replace(temporary, run_dir / "run.json")
    return state


# ---------------------------------------------------------------- the steps


def list_repos() -> list[str]:
    """Every folder in the fleet that looks like a service."""
    root = config.fleet_root()
    if not root.is_dir():
        return []
    return sorted(p.name for p in root.iterdir() if p.is_dir() and (p / "requirements.txt").is_file() and not p.name.startswith("."))


def intake(run_id: str, advisory_text: str, started_at: str) -> dict:
    """The clock starts here. Returns {run_id, started_at, deadline, repos}."""
    started = dt.datetime.fromisoformat(started_at)
    if started.tzinfo is None:
        started = started.replace(tzinfo=dt.timezone.utc)
    repos = list_repos()
    state = update_state(
        run_id,
        started_at=started.isoformat(timespec="seconds"),
        deadline=(started + dt.timedelta(hours=config.APPROVAL_HOURS)).isoformat(timespec="seconds"),
        stage="reading_advisory",
        repos=repos,
        advisory_text=advisory_text[:20_000],
        advisory=None,
        approved_by=None,
        error=None,
        pull_requests=config.pull_requests(),
    )
    events.emit(run_id, "orchestrator", f"Run started with {len(repos)} repositories in the fleet. The 24-hour clock is running."
                + (" A verified fix will be proposed as a draft pull request." if state["pull_requests"] else ""), kind="start")
    # The switch is read once, here. The workflow acts on what this returned, so a replay decides the same way.
    return {key: state[key] for key in ("run_id", "started_at", "deadline", "repos", "pull_requests")}


def read_advisory(run_id: str, advisory_text: str) -> dict:
    """One model call. Stops the run if the answer is not four well-formed facts."""
    from_file = bool(os.environ.get("LE_CHONK_ADVISORY_JSON"))
    events.emit(run_id, "orchestrator", "Reading the advisory: " + ("four facts from a file, no model call." if from_file else f"one call to {config.model()}."))
    started = time.monotonic()
    try:
        facts = advisory_reader.read_advisory(run_id, advisory_text, lambda text, kind="step": events.emit(run_id, "orchestrator", text, kind=kind))
    except Exception as error:
        update_state(run_id, stage="failed", error=f"reading the advisory failed: {error}"[:500])
        events.emit(run_id, "orchestrator", f"Reading the advisory failed, so the run stops before any agent starts: {error}", kind="fail")
        raise
    update_state(run_id, stage="triage", advisory=facts, advisory_lookup=advisory_reader.looked_up(run_id))
    events.emit(run_id, "orchestrator",
                f"Advisory read in {time.monotonic() - started:.1f} s: {facts['id']} in {facts['package']} {facts['affected_range']}, "
                f"flawed function {facts['flawed_function']}. One worker per repository starts now.", kind="ok")
    return facts


def kb_scan_watch(run_id: str) -> dict:
    """Step 0, before any triage: record which kb-scan feed findings name this run's advisory.

    Reads the engine's merged scan (tools/scan/out/latest.json) and this run's triage handoff
    (runs/<run_id>/triage.json) through orchestrator/kbscan.py, and writes the matches to
    runs/<run_id>/kb-scan.json (schema kb-scan-watch/1, see schema/kb-scan-watch.schema.json).

    Engine output is untrusted feed data: it informs, it never becomes a verdict. This step
    changes no verdict and no gate rule — the only effect scan data can have on a verdict is
    the gate's own downgrade to "needs_human" (gate.py, unchanged). A missing, malformed or
    oversized scan document simply records no matches; this step never fails the run.
    """
    try:
        facts = read_state(run_id).get("advisory") or {}
        advisory_id = str(facts.get("id", ""))
        package = str(facts.get("package", ""))
        latest_doc = kbscan.latest()
        triage_doc = kbscan.triage_for_run(run_id, config.runs_root())
        latest_hits = kbscan.relevant_to_advisory(latest_doc, advisory_id, package)
        triage_hits = [f for f in kbscan.relevant_to_advisory(triage_doc, advisory_id, package) if f not in latest_hits]
        hits = latest_hits + triage_hits
        matches = ([_kb_scan_match(finding, "latest.json") for finding in latest_hits]
                   + [_kb_scan_match(finding, "triage.json") for finding in triage_hits])[:MAX_KB_SCAN_MATCHES]
        record = {
            "schema": "kb-scan-watch/1",
            "run_id": config.check_name(run_id, "run id"),
            "recorded_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
            "advisory": {"id": kbscan.text(advisory_id, 40), "package": kbscan.text(package, 80)},
            "untrusted": "feed data from the kb-scan engine; recorded before triage; not a verdict; the gate's rules are unchanged",
            "sources": {
                "latest": {"present": bool(latest_doc), "generated_at": kbscan.text(latest_doc.get("generated_at", ""), 40)},
                "triage": {"present": bool(triage_doc), "generated_at": kbscan.text(triage_doc.get("generated_at", ""), 40)},
            },
            "matches": matches,
            "total_matches": len(hits),
        }
        run_dir = config.run_dir(run_id)
        run_dir.mkdir(parents=True, exist_ok=True)
        temporary = run_dir / f"kb-scan.json.{threading.get_ident()}.tmp"
        temporary.write_text(json.dumps(record, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        os.replace(temporary, run_dir / "kb-scan.json")
        update_state(run_id, kb_scan_watch={"matches": len(hits), "path": "kb-scan.json"})
        events.emit(run_id, "orchestrator",
                    f"kb-scan step 0: {len(hits)} feed finding(s) in the engine's latest scan or this run's triage handoff name "
                    f"{kbscan.text(advisory_id, 40) or 'this advisory'} / {kbscan.text(package, 80)}. Recorded in kb-scan.json before any triage, "
                    "as unverified feed data. No verdict is based on it.", kind="ok")
        return {"path": str(run_dir / "kb-scan.json"), "matches": len(hits),
                "latest": bool(latest_doc), "triage": bool(triage_doc)}
    except Exception as error:
        events.emit(run_id, "orchestrator", f"kb-scan step 0 could not record feed matches: {type(error).__name__}. Continuing without them.", kind="fail")
        return {"path": None, "matches": 0, "error": type(error).__name__}


def _kb_scan_match(finding: dict, origin: str) -> dict:
    """One feed finding as a sanitised, one-line record. Feed text is untrusted; kbscan.text() cleans it."""
    return {
        "origin": origin,
        "tier": kbscan.text(finding.get("tier", "?"), 8),
        "cve": kbscan.text(finding.get("cve", finding.get("id", "")), 40),
        "package": kbscan.text(finding.get("package", ""), 80),
        "title": kbscan.text(finding.get("title", finding.get("summary", "")), 140),
        "source": kbscan.text(finding.get("source", ""), 60),
        "status": kbscan.text(finding.get("status", ""), 40),
    }


def triage_repo(run_id: str, repo: str, heartbeat_fn: Callable[..., None] | None = None) -> dict:
    """Run the per-repository worker once. A worker that fails yields "needs_human", never a crash."""
    config.check_name(repo, "repository name")
    started = time.monotonic()
    rc, verdict, export = -1, None, {}
    events.emit(run_id, "orchestrator", f"Worker started on a fresh copy of the repository ({config.run_repo_target()}).", repo=repo, kind="start")
    reported = 0

    def beat(*details: Any) -> None:
        """Keep the activity alive, and put whatever the worker says about its progress in the event log."""
        nonlocal reported
        words = " ".join(str(detail) for detail in details if isinstance(detail, (str, int, float))).strip()
        if words and reported < MAX_WORKER_EVENTS:
            reported += 1
            events.emit(run_id, "worker", words, repo=repo)
        if heartbeat_fn is not None:
            heartbeat_fn(*details)

    try:
        worker = _load_worker()
        result = worker(run_id, repo, fleet_root=str(config.fleet_root()), runs_root=str(config.runs_root()),
                        vibe_home=str(config.vibe_home()), heartbeat_fn=beat)
        rc = int(result.get("rc", -1))
        verdict = result.get("verdict")
        export = result.get("export") or {}
        problem = None if isinstance(verdict, dict) else "the worker returned no verdict"
    except Exception as error:
        problem = f"the worker failed: {type(error).__name__}: {error}"
    seconds = round(time.monotonic() - started, 1)
    if problem:
        verdict = _needs_human(run_id, repo, problem[:500])
        events.emit(run_id, "orchestrator", f"No verdict after {seconds} s: {problem}", repo=repo, kind="fail")
    else:
        claim = verdict.get("verdict") if verdict.get("verdict") in VERDICTS else "an unknown verdict"
        events.emit(run_id, "orchestrator", f"Worker returned after {seconds} s. It claims {claim}. Nothing is shown as a result until the gate has checked it.",
                    repo=repo, kind="ok", claim=claim)
    verdict["repo"] = repo  # the orchestrator names the repository, not the agent
    usage = _usage(export)
    usage["seconds"] = seconds
    return {"repo": repo, "rc": rc, "verdict": verdict, "usage": usage}


def verify_repo(run_id: str, result: dict) -> dict:
    """The gate, for one repository. Returns the gated verdict, which is also on disk by then."""
    verdict = dict(result["verdict"])
    verdict["usage"] = result.get("usage", {})
    return gate(run_id, [verdict], runs_root=config.runs_root(), wheelhouse=config.wheelhouse())[0]


def wants_pull_request(gated: dict) -> bool:
    """A fix the gate has verified. Plain data in, so the workflow can ask this without doing any I/O."""
    checked = gated.get("gate") or {}
    return gated.get("verdict") == "affected_fixed" and checked.get("passed") is True


def open_pull_request(run_id: str, gated: dict) -> dict:
    """Propose a verified fix as a draft pull request. A failure here never fails the run.

    Returns the gated verdict with "pull_request" added, and writes runs/<run>/<repo>/pull_request.json.
    """
    repo = config.check_name(gated.get("repo"), "repository name")
    events.emit(run_id, "orchestrator", "The gate verified this fix. Opening a draft pull request with it.", repo=repo, kind="start")
    try:
        outcome = pull_request.open_fix_pr(run_id, gated, runs_root=config.runs_root())
        events.emit(run_id, "orchestrator", (f"A pull request for this advisory is already open, so no second one was opened: {outcome['url']}"
                                             if outcome.get("reused") else f"Draft pull request opened: {outcome['url']}"), repo=repo, kind="done", url=outcome["url"])
    except pull_request.Refused as refusal:
        outcome = {"refused": str(refusal)[:300]}
        events.emit(run_id, "orchestrator", f"No pull request: {refusal}.", repo=repo, kind="info")
    except Exception as error:
        outcome = {"error": f"{type(error).__name__}: {error}"[:300]}
        events.emit(run_id, "orchestrator", f"Opening the pull request failed: {outcome['error']}", repo=repo, kind="fail")
    target = config.run_dir(run_id) / repo / "pull_request.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(outcome, indent=2) + "\n", encoding="utf-8")
    return {**gated, "pull_request": outcome}


def write_report(run_id: str, gated: list) -> dict:
    """Fill the draft from gated verdicts, then wait for a person."""
    text = render_early_warning(run_id, gated, runs_root=config.runs_root())
    counts: dict[str, int] = {}
    for verdict in gated:
        counts[verdict.get("verdict", "needs_human")] = counts.get(verdict.get("verdict", "needs_human"), 0) + 1
    update_state(run_id, stage="awaiting_approval", counts=counts, report="early-warning.md")
    summary = ", ".join(f"{count} {name}" for name, count in sorted(counts.items()))
    events.emit(run_id, "orchestrator", f"Draft early warning written from {len(gated)} gated verdicts ({summary}). No model wrote it. Waiting for a person.", kind="ok")
    return {"path": str(config.run_dir(run_id) / "early-warning.md"), "chars": len(text), "counts": counts}


def close_run(run_id: str, outcome: str, approved_by: str | None = None) -> dict:
    """`outcome` is "approved" or "expired". Nothing is sent anywhere: a person submits the report."""
    stage = "approved" if outcome == "approved" else "expired"
    state = update_state(run_id, stage=stage, approved_by=approved_by or None,
                         closed_at=dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"))
    events.emit(run_id, "orchestrator",
                ("Approved" + (f" by {approved_by}" if approved_by else "") + ". A person now submits the report. This tool sends nothing.")
                if stage == "approved" else "Nobody approved within 24 hours. The run is closed as expired.", kind="done")
    return {"run_id": run_id, "stage": state["stage"]}


# ---------------------------------------------------------------- helpers


def _load_worker() -> Callable[..., dict]:
    module_name, _, function_name = config.run_repo_target().partition(":")
    return getattr(importlib.import_module(module_name), function_name or "run_repo")


def _needs_human(run_id: str, repo: str, reason: str) -> dict:
    facts = read_state(run_id).get("advisory") or {}
    return {
        "repo": repo,
        "advisory": {key: str(facts.get(key, "")) for key in ("id", "package", "affected_range", "flawed_function")},
        "verdict": "needs_human",
        "reason": reason,
        "path": [], "proof": [], "fix": None,
        "suite": {}, "follow_ups": [],
    }


def _usage(export: dict) -> dict:
    """The few numbers the grid shows. Vibe's export format is not pinned, so look in likely places."""
    pools = [export] + [export[key] for key in ("usage", "stats", "summary") if isinstance(export.get(key), dict)]

    def first(*names: str) -> Any:
        for pool in pools:
            for name in names:
                if isinstance(pool.get(name), (int, float, str)):
                    return pool[name]
        return None

    return {
        "tokens": first("tokens", "total_tokens"),
        "cost_usd": first("cost_usd", "cost", "price", "total_cost"),
        "steps": first("steps", "turns", "num_turns"),
        "outcome": first("outcome", "status"),
    }
