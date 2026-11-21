"""The steps of one run, as plain functions.

Both orchestrators call these: the Mistral Workflows workflow (workflow.py), where each step is
an activity, and the plain-Python fallback (local.py). All file and network work of a run is in
here, so the workflow code itself stays deterministic.

    intake -> read_advisory -> triage_repo + verify_repo for each repository -> write_report
    -> (wait for a person) -> close_run

What a run leaves on disk follows the run contract (docs/contract.md): run.json, advisory.json
and early-warning.md at the run root, and per repository src/, proof/, verdict.json (the
worker's), state.json and fix.diff (the orchestrator's). Two files are this orchestrator's own
and are not part of the contract: orchestrator.json, the working state the page polls (stage,
counts, the advisory text), and events.jsonl.
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
from orchestrator import config, events, pull_request, record
from orchestrator import gate as gate_checks
from orchestrator.report import render_early_warning
from vulnerability_agent import contract
from vulnerability_agent import runs as contract_runs

_state_lock = threading.Lock()
VERDICTS = contract.VERDICTS
MAX_WORKER_EVENTS = 300  # per repository: a worker cannot flood the log
STATE_FILE = "orchestrator.json"  # this orchestrator's working state; run.json is the contract's record


# ---------------------------------------------------------------- run state


def read_state(run_id: str) -> dict:
    try:
        data = json.loads((config.run_dir(run_id) / STATE_FILE).read_text(encoding="utf-8"))
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
        temporary = run_dir / f"{STATE_FILE}.{threading.get_ident()}.tmp"
        temporary.write_text(json.dumps(state, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        os.replace(temporary, run_dir / STATE_FILE)
    return state


def _utc(moment: dt.datetime) -> str:
    """A time as the contract writes it: UTC, to the second, ending in Z."""
    return moment.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _fleet_source(repo: str) -> str:
    """Where a repository's read-only copy is, from the repository root when it is inside it."""
    source = config.fleet_root() / repo
    try:
        return source.resolve().relative_to(config.REPO_ROOT.resolve()).as_posix()
    except ValueError:
        return str(source)


def _update_run_record(run_id: str, **changes: Any) -> None:
    """Change fields of the contract's run.json, and check the result against its schema."""
    path = config.run_dir(run_id) / contract.RUN_JSON
    document = record.read_json(path)
    if document is not None:
        contract_runs.write_run_json(path.parent, {**document, **changes})


# ---------------------------------------------------------------- the steps


def list_repos() -> list[str]:
    """Every folder in the fleet that looks like a service."""
    root = config.fleet_root()
    if not root.is_dir():
        return []
    return sorted(p.name for p in root.iterdir() if p.is_dir() and (p / "requirements.txt").is_file() and not p.name.startswith("."))


def intake(run_id: str, advisory_text: str, started_at: str) -> dict:
    """The clock starts here. Returns {run_id, started_at, deadline, repos, pull_requests, max_parallel}."""
    started = dt.datetime.fromisoformat(started_at)
    if started.tzinfo is None:
        started = started.replace(tzinfo=dt.timezone.utc)
    repos = list_repos()
    if repos:  # the contract's record of the run; its schema wants at least one repository
        contract_runs.write_run_json(config.run_dir(run_id), {
            "run_id": config.check_name(run_id, "run id"),
            "clock_start": _utc(started),
            "workflow_run_id": run_id,  # a run's folder is named after the workflow execution that drives it
            "paths": {"advisory": contract.ADVISORY_JSON, "early_warning": contract.EARLY_WARNING_MD},
            "fleet": [{"repo": repo, "source": _fleet_source(repo)} for repo in repos],
            "approved_at": None,
            "expired_at": None,
        })
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
        max_parallel=config.max_parallel(),
    )
    events.emit(run_id, "orchestrator", f"Run started with {len(repos)} repositories in the fleet, at most {state['max_parallel']} at a time. The 24-hour clock is running."
                + (" A verified fix will be proposed as a draft pull request." if state["pull_requests"] else ""), kind="start")
    # The switches are read once, here. The workflow acts on what this returned, so a replay decides the same way.
    return {key: state[key] for key in ("run_id", "started_at", "deadline", "repos", "pull_requests", "max_parallel")}


def read_advisory(run_id: str, advisory_text: str) -> dict:
    """One model call. Stops the run if the answer is not the contract's five well-formed facts."""
    from_file = bool(os.environ.get("LE_CHONK_ADVISORY_JSON"))
    events.emit(run_id, "orchestrator", "Reading the advisory: " + ("five facts from a file, no model call." if from_file else f"one call to {config.model()}."))
    started = time.monotonic()
    try:
        facts = advisory_reader.read_advisory(run_id, advisory_text, lambda text, kind="step": events.emit(run_id, "orchestrator", text, kind=kind))
    except Exception as error:
        update_state(run_id, stage="failed", error=f"reading the advisory failed: {error}"[:500])
        events.emit(run_id, "orchestrator", f"Reading the advisory failed, so the run stops before any agent starts: {error}", kind="fail")
        raise
    update_state(run_id, stage="triage", advisory=facts, advisory_lookup=advisory_reader.looked_up(run_id))
    events.emit(run_id, "orchestrator",
                f"Advisory read in {time.monotonic() - started:.1f} s: {facts['advisory_id']} in {facts['package']} {facts['affected_version_range']}, "
                f"fixed in {facts['fixed_version']}, flawed function {facts['flawed_function']}. One worker per repository starts now.", kind="ok")
    return facts


def triage_repo(run_id: str, repo: str, heartbeat_fn: Callable[..., None] | None = None) -> dict:
    """Run the per-repository worker once. Returns {repo, rc, problem, usage}.

    The worker's verdict is not passed on from here. It is a file, verdict.json, and the gate
    reads it from disk. `problem` is set when the worker itself failed, and then nothing it left
    behind is trusted.
    """
    config.check_name(repo, "repository name")
    started = time.monotonic()
    rc, export, problem = -1, {}, None
    try:
        gate_checks.write_running_state(run_id, repo)
    except Exception:
        pass  # the placeholder is a courtesy; the final state is what counts
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
        export = result.get("export") or {}
    except Exception as error:
        problem = f"the worker failed: {type(error).__name__}: {error}"[:500]
    seconds = round(time.monotonic() - started, 1)
    if problem:
        events.emit(run_id, "orchestrator", f"No verdict after {seconds} s: {problem}", repo=repo, kind="fail")
    else:
        claim = (record.claim(config.run_dir(run_id) / repo) or {}).get("verdict")
        claim = claim if claim in VERDICTS else "no usable verdict"
        events.emit(run_id, "orchestrator", f"Worker returned after {seconds} s. It claims {claim}. Nothing is shown as a result until the gate has checked it.",
                    repo=repo, kind="ok", claim=claim)
    usage = _usage(export)
    usage["seconds"] = seconds
    return {"repo": repo, "rc": rc, "problem": problem, "usage": usage}


def verify_repo(run_id: str, result: dict) -> dict:
    """The gate, for one repository. It writes state.json and returns the joined record."""
    return gate_checks.gate_repo(run_id, result["repo"], problem=result.get("problem"), usage=result.get("usage") or {},
                                 runs_root=config.runs_root(), wheelhouse=config.wheelhouse())


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
    closed = dt.datetime.now(dt.timezone.utc)
    state = update_state(run_id, stage=stage, approved_by=approved_by or None, closed_at=closed.isoformat(timespec="seconds"))
    _update_run_record(run_id, **{"approved_at" if stage == "approved" else "expired_at": _utc(closed)})
    events.emit(run_id, "orchestrator",
                ("Approved" + (f" by {approved_by}" if approved_by else "") + ". A person now submits the report. This tool sends nothing.")
                if stage == "approved" else "Nobody approved within 24 hours. The run is closed as expired.", kind="done")
    return {"run_id": run_id, "stage": state["stage"]}


# ---------------------------------------------------------------- helpers


def _load_worker() -> Callable[..., dict]:
    module_name, _, function_name = config.run_repo_target().partition(":")
    return getattr(importlib.import_module(module_name), function_name or "run_repo")


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
