"""The grid: FastAPI on :8000.

    POST /runs {advisory_text}        start a run; returns {run_id, started_at}
    GET  /runs/{run_id}               tiles, only for repositories the gate has been through
    GET  /                            the page: polls every 2 s, shows the 24-hour clock
    POST /runs/{run_id}/approve       a person's approval, sent to the run as the "approve" signal
    GET  /runs/{run_id}/stream        the run's events as they happen (server-sent events)
    GET  /runs/{run_id}/events        the same events, as JSON
    GET  /runs/{run_id}/repos/{repo}/detail    under the hood for one repository: every gate rule,
                                      what the worker changed, the gate's log, the worker's raw claim

Start it with:

    MISTRAL_API_KEY=... DEPLOYMENT_NAME=... uv run python -m web.app

It starts and signals runs on Mistral Workflows. Set LE_CHONK_ORCHESTRATOR=local to use the
plain-Python fallback inside this process instead. Either way the page reads a run's state from
runs/<run_id>/ on this machine, where the worker writes it, so the web server and the worker
must share that folder.

There is no sign-in. It listens on 127.0.0.1 only, and every POST must be JSON, which a page on
another site cannot send here without this server's permission. Everything an agent wrote is
shown as plain text, never as HTML.
"""
from __future__ import annotations

import asyncio
import datetime as dt
import difflib
import json
import os
import re
import time
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, StreamingResponse
from pydantic import BaseModel, Field

from orchestrator import config, events, history, kbscan, steps
from orchestrator import gate as gate_checks
from orchestrator import fetch_fleet
from orchestrator.local import LOCAL, new_run_id

CLOSED = ("approved", "expired", "failed")
_PULL = re.compile(r"^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/pull/\d+$")
_FILE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_./-]{0,200}$")

TITLES = {
    "not_affected": "No reachable path found",
    "affected_proven": "Affected and proven",
    "affected_fixed": "Affected, proven and fixed",
    "needs_human": "Needs a human",
}


# ---------------------------------------------------------------- the two orchestrators


class WorkflowsBackend:
    """Starts and signals runs on Mistral Workflows. The worker process does the work."""

    name = "Mistral Workflows"

    def __init__(self) -> None:
        self._client = None
        self._status: dict[str, tuple[float, str]] = {}

    def _get(self):
        if self._client is None:
            key = os.environ.get("MISTRAL_API_KEY")
            if not key:
                raise HTTPException(503, "MISTRAL_API_KEY is not set for the web server. Set it, or start with LE_CHONK_ORCHESTRATOR=local.")
            from mistralai.client import Mistral

            self._client = Mistral(api_key=key)
        return self._client

    def start(self, advisory_text: str, run_id: str) -> dict:
        extra = {"deployment_name": os.environ["DEPLOYMENT_NAME"]} if os.environ.get("DEPLOYMENT_NAME") else {}
        response = self._get().workflows.execute_workflow(
            workflow_identifier=config.WORKFLOW_NAME, execution_id=run_id, input={"advisory_text": advisory_text}, **extra
        )
        return {"run_id": response.execution_id, "started_at": _now()}

    def approve(self, run_id: str, approved_by: str) -> None:
        self._get().workflows.executions.signal_workflow_execution(execution_id=run_id, name="approve", input={"approved_by": approved_by})

    def status(self, run_id: str) -> str:
        cached = self._status.get(run_id)
        if cached and time.monotonic() - cached[0] < 10:  # the page polls every 2 s; Mistral need not be asked that often
            return cached[1]
        try:
            status = str(self._get().workflows.executions.get_workflow_execution(execution_id=run_id).status)
        except HTTPException:
            raise
        except Exception as error:
            status = f"UNKNOWN ({type(error).__name__})"
        self._status[run_id] = (time.monotonic(), status)
        return status


class LocalBackend:
    """The plain-Python fallback, running inside this process."""

    name = "local fallback (no Mistral Workflows)"

    def start(self, advisory_text: str, run_id: str) -> dict:
        return LOCAL.start(advisory_text, run_id)

    def approve(self, run_id: str, approved_by: str) -> None:
        if not LOCAL.approve(run_id, approved_by):
            raise HTTPException(409, "This run is not held by this process any more, so it cannot be approved here.")

    def status(self, run_id: str) -> str:
        return LOCAL.status(run_id)


def make_backend() -> Any:
    return LocalBackend() if os.environ.get("LE_CHONK_ORCHESTRATOR", "workflows") == "local" else WorkflowsBackend()


# ---------------------------------------------------------------- the API


app = FastAPI(title="Le Chonk", docs_url=None, redoc_url=None)
app.state.backend = None


def backend() -> Any:
    if app.state.backend is None:
        app.state.backend = make_backend()
    return app.state.backend


def json_only(request: Request) -> None:
    """A form or a plain-text POST from another site is refused. Only this page sends JSON here."""
    if not request.headers.get("content-type", "").lower().startswith("application/json"):
        raise HTTPException(415, "Send JSON.")


class StartRun(BaseModel):
    advisory_text: str = Field(min_length=10, max_length=20_000)


class Approve(BaseModel):
    approved_by: str = Field(default="", max_length=120)


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def _run_dir(run_id: str) -> Path:
    try:
        return config.run_dir(run_id)
    except ValueError:
        raise HTTPException(404, "No such run.") from None


def _read(path: Path) -> dict | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _repo_links() -> dict[str, dict]:
    """name -> where an app came from, for apps fetched at a pinned commit. Only GitHub addresses pass."""
    return fetch_fleet.fetched_apps()


def _pull_request(run_dir: Path, repo: str) -> dict | None:
    """What the pull-request step left for a repository: a link, or why there is none."""
    left = _read(run_dir / repo / "pull_request.json")
    if left is None:
        return None
    if _PULL.match(str(left.get("url", ""))):
        return {"url": left["url"], "number": left.get("number") if isinstance(left.get("number"), int) else None, "draft": left.get("draft") is not False}
    if left.get("refused"):
        return {"refused": str(left["refused"])[:300]}
    return {"error": str(left.get("error", "the pull request step left no result"))[:300]}


def _path(repo: str, steps_cited: object, link: dict | None) -> list[dict]:
    """The cited code path, with a link to the exact line for files that are in the fetched app."""
    path = []
    for step in steps_cited if isinstance(steps_cited, list) else []:
        if not isinstance(step, dict):
            continue
        file, line = str(step.get("file", ""))[:200], step.get("line")
        entry = {"file": file, "line": line if isinstance(line, int) else None, "note": str(step.get("note", ""))[:240], "href": None}
        if link and entry["line"] and _FILE.match(file) and ".." not in file and (config.fleet_root() / repo / file).is_file():
            entry["href"] = f"{link['url']}/blob/{link['commit']}/{file}#L{entry['line']}"
        path.append(entry)
    return path[:12]


def _tile(run_id: str, repo: str, verdict: dict, link: dict | None = None) -> dict:
    gate = verdict.get("gate") or {}
    kind = verdict.get("verdict", "needs_human")
    rejected = gate.get("passed") is False and gate.get("original_verdict") not in (None, "needs_human")
    failed = [name for name, rule in (gate.get("rules") or {}).items() if rule.get("enforced") and rule.get("passed") is not True]
    tile = {
        "repo": repo,
        "verdict": kind if kind in TITLES else "needs_human",
        "title": TITLES.get(kind, TITLES["needs_human"]),
        "gate": {"passed": gate.get("passed"), "claimed": gate.get("original_verdict"), "failed_rules": failed,
                 "sandboxed": gate.get("sandboxed"), "checked_at": gate.get("checked_at")},
        "usage": verdict.get("usage") or {},
        "verdict_url": f"/runs/{run_id}/repos/{repo}/verdict.json",
        "link": link,
        "pull_request": _pull_request(_run_dir(run_id), repo),
    }
    if rejected:
        # A claim the gate rejected is not a result. Say what failed and repeat nothing the agent claimed.
        tile.update(reason=f"The gate rejected a claim of {TITLES.get(gate.get('original_verdict'), gate.get('original_verdict'))}.",
                    path=[], proof=[], fix=None, follow_ups=[])
    else:
        tile.update(reason=str(verdict.get("reason", ""))[:900], path=_path(repo, verdict.get("path"), link), proof=verdict.get("proof") or [],
                    fix=verdict.get("fix"), follow_ups=(verdict.get("follow_ups") or [])[:6])
    return tile


@app.post("/runs", dependencies=[Depends(json_only)])
def start_run(body: StartRun) -> dict:
    started = backend().start(body.advisory_text, new_run_id())
    return {"run_id": started["run_id"], "started_at": started["started_at"]}


@app.get("/runs")
def list_runs() -> dict:
    root = config.runs_root()
    runs = []
    for folder in sorted(root.iterdir(), reverse=True) if root.is_dir() else []:
        state = _read(folder / "run.json")
        if state and not folder.name.startswith("_"):
            runs.append({"run_id": folder.name, "stage": state.get("stage"), "started_at": state.get("started_at"),
                         "advisory": (state.get("advisory") or {}).get("id")})
    return {"runs": runs[:30]}


@app.get("/runs/{run_id}")
def get_run(run_id: str) -> dict:
    run_dir = _run_dir(run_id)
    state = _read(run_dir / "run.json")
    if state is None:
        # The run was accepted but its first step has not written anything yet.
        return {"run_id": run_id, "stage": "starting", "status": backend().status(run_id), "tiles": [], "pending": [], "repos_total": 0, "repos": [],
                "started_at": None, "deadline": None, "advisory": None, "counts": {}, "report_ready": False, "approved_by": None, "error": None}
    tiles, pending = [], []
    links = _repo_links()
    for repo in state.get("repos") or []:
        verdict = _read(run_dir / repo / "verdict.json")
        if verdict is not None and isinstance(verdict.get("gate"), dict):
            tiles.append(_tile(run_id, repo, verdict, links.get(repo)))
        else:
            pending.append(repo)  # the gate has not been through it: no verdict is shown
    counts: dict[str, int] = {}
    for tile in tiles:
        counts[tile["verdict"]] = counts.get(tile["verdict"], 0) + 1
    return {
        "run_id": run_id, "stage": state.get("stage"), "status": backend().status(run_id),
        "started_at": state.get("started_at"), "deadline": state.get("deadline"), "advisory": state.get("advisory"),
        "advisory_lookup": [item for item in state.get("advisory_lookup") or [] if isinstance(item, dict)
                            and str(item.get("url", "")).startswith("https://osv.dev/vulnerability/")][:4],
        "repos_total": len(state.get("repos") or []), "tiles": tiles, "pending": pending, "counts": counts,
        "repos": [{"name": repo, "link": links.get(repo)} for repo in state.get("repos") or []],
        "pull_requests": bool(state.get("pull_requests")),
        "report_ready": (run_dir / "early-warning.md").is_file(), "approved_by": state.get("approved_by"),
        "closed_at": state.get("closed_at"), "error": state.get("error"),
    }


@app.get("/runs/{run_id}/report", response_class=PlainTextResponse)
def get_report(run_id: str) -> str:
    try:
        return (_run_dir(run_id) / "early-warning.md").read_text(encoding="utf-8")
    except OSError:
        raise HTTPException(404, "The report has not been drafted yet.") from None


@app.get("/runs/{run_id}/repos/{repo}/verdict.json")
def get_verdict(run_id: str, repo: str) -> JSONResponse:
    try:
        config.check_name(repo, "repository name")
    except ValueError:
        raise HTTPException(404, "No such repository.") from None
    verdict = _read(_run_dir(run_id) / repo / "verdict.json")
    if verdict is None or not isinstance(verdict.get("gate"), dict):
        raise HTTPException(404, "No gated verdict for this repository yet.")
    return JSONResponse(verdict)


@app.get("/runs/{run_id}/events")
def get_events(run_id: str, after: int = 0) -> dict:
    _run_dir(run_id)
    found = events.read(run_id, max(0, after))
    return {"events": found, "next": found[-1]["n"] if found else max(0, after)}


@app.get("/history")
def get_history() -> dict:
    """The read-only cross-run history index (runs/_index/history.json), rebuilt on demand.

    Aggregates verdicts, gate/sim downgrades and breaches across all runs. Read-only over
    run history; never writes back into any decision.
    """
    try:
        index = history.rebuild(config.runs_root())
    except Exception:
        # fall back to the last index on disk, if any
        try:
            index = json.loads((config.runs_root() / "_index" / "history.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            index = {}
    return {"history": index}


@app.get("/scan/latest")
def scan_latest() -> dict:
    """The kb-scan continuous poller's merged feed scan, as a small sanitised summary.

    Read-only, and the document is untrusted feed data: size-capped parse, one-line markup-free
    strings, capped item list. Empty when the engine has not run yet.
    """
    return {"scan": kbscan.summary(kbscan.latest())}


@app.get("/runs/{run_id}/scan")
def scan_for_run(run_id: str) -> dict:
    """The kb-scan triage handoff for one run (runs/<run_id>/triage.json), sanitised the same way."""
    _run_dir(run_id)
    return {"run_id": run_id, "triage": kbscan.summary(kbscan.triage_for_run(run_id))}


@app.get("/runs/{run_id}/stream")
async def stream_events(run_id: str, request: Request, after: int = 0) -> StreamingResponse:
    """Server-sent events: each event of the run as it is written. Ends once the run is closed."""
    run_dir = _run_dir(run_id)
    resumed = request.headers.get("last-event-id", "")
    start = int(resumed) if resumed.isdigit() else max(0, after)

    async def generate():
        sent, quiet = start, 0.0
        while not await request.is_disconnected():
            batch = events.read(run_id, sent)
            for event in batch:
                sent = event["n"]
                yield f"id: {sent}\ndata: {json.dumps(event, ensure_ascii=False)}\n\n"
            if batch:
                quiet = 0.0
                continue
            if (_read(run_dir / "run.json") or {}).get("stage") in CLOSED:
                yield "event: end\ndata: {}\n\n"
                return
            quiet += 0.4
            if quiet >= 15:  # a comment line keeps the connection open through proxies
                quiet = 0.0
                yield ": still here\n\n"
            await asyncio.sleep(0.4)

    return StreamingResponse(generate(), media_type="text/event-stream", headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})


def _clip(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[:limit] + f"\n... cut: {len(text) - limit} more characters"


def _tidy(text: str) -> str:
    """Raw output with this machine's long folder names cut down to "." and "~"."""
    return text.replace(str(config.REPO_ROOT), ".").replace(str(Path.home()), "~")


def _file_text(path: Path, limit: int = 12_000) -> str:
    try:
        return _clip(path.read_text(encoding="utf-8", errors="replace"), limit)
    except OSError:
        return ""


@app.get("/runs/{run_id}/repos/{repo}/detail")
def get_detail(run_id: str, repo: str) -> dict:
    """Under the hood for one repository. This is for inspection: it includes what the worker claimed,
    even when the gate rejected it. The grid and the report never show a rejected claim."""
    try:
        config.check_name(repo, "repository name")
    except ValueError:
        raise HTTPException(404, "No such repository.") from None
    run_dir = _run_dir(run_id)
    state = _read(run_dir / "run.json") or {}
    if repo not in (state.get("repos") or []):
        raise HTTPException(404, "No such repository in this run.")
    repo_dir = run_dir / repo
    link = _repo_links().get(repo)
    on_disk = _read(repo_dir / "verdict.json")
    gated = on_disk if on_disk is not None and isinstance(on_disk.get("gate"), dict) else None
    claim = _read(repo_dir / "verdict.agent.json") or (on_disk if gated is None else None)

    gate = (gated or {}).get("gate") or {}
    rules = [{"name": name, "label": gate_checks.RULE_LABELS.get(name, name), "passed": rule.get("passed"),
              "enforced": bool(rule.get("enforced")), "detail": _tidy(str(rule.get("detail", "")))[:800]}
             for name, rule in (gate.get("rules") or {}).items() if isinstance(rule, dict)]
    rejected = gate.get("passed") is False and gate.get("original_verdict") not in (None, "needs_human")

    files, deleted = [], []
    changes = gate_checks.work_copy_changes(run_id, repo)
    if changes:
        original, work = config.fleet_root() / repo, repo_dir / "src"
        for name in changes["added"][:8]:
            files.append({"name": name, "change": "added", "text": _file_text(work / name)})
        for name in changes["changed"][:8]:
            before = _file_text(original / name, 200_000).splitlines()
            after = _file_text(work / name, 200_000).splitlines()
            diff = "\n".join(difflib.unified_diff(before, after, "original/" + name, "work copy/" + name, lineterm=""))
            files.append({"name": name, "change": "changed", "text": _clip(diff, 12_000)})
        deleted = changes["deleted"][:20]

    export = _read(repo_dir / "vibe" / "export.json")
    return {
        "run_id": run_id, "repo": repo, "link": link,
        "pull_request": _pull_request(run_dir, repo),
        "checked": gated is not None,
        "verdict": (gated or {}).get("verdict"),
        "title": TITLES.get((gated or {}).get("verdict"), None),
        "gate": {"passed": gate.get("passed"), "claimed": gate.get("original_verdict"), "sandboxed": gate.get("sandboxed"),
                 "checked_at": gate.get("checked_at"), "rules": rules} if gated else None,
        "claim": None if claim is None else {
            "rejected": rejected,
            "verdict": str(claim.get("verdict", ""))[:40],
            "reason": str(claim.get("reason", ""))[:1500],
            "path": _path(repo, claim.get("path"), link),
            "proof": [str(test)[:300] for test in (claim.get("proof") or [])][:10] if isinstance(claim.get("proof"), list) else [],
            "fix": claim.get("fix") if isinstance(claim.get("fix"), dict) else None,
            "follow_ups": [str(item)[:300] for item in (claim.get("follow_ups") or [])][:8] if isinstance(claim.get("follow_ups"), list) else [],
        },
        "files": files, "deleted": deleted,
        "gate_log": _tidy(_file_text(repo_dir / "gate" / "log.txt", 400_000))[-8000:],
        "export": _clip(json.dumps(export, indent=2, ensure_ascii=False), 6000) if export is not None else None,
        "usage": (gated or claim or {}).get("usage") or {},
        "events": [event for event in events.read(run_id) if event.get("repo") == repo],
    }


@app.post("/runs/{run_id}/approve", dependencies=[Depends(json_only)])
def approve_run(run_id: str, body: Approve) -> dict:
    state = _read(_run_dir(run_id) / "run.json") or {}
    if state.get("stage") != "awaiting_approval":
        raise HTTPException(409, f"Nothing to approve: the run is at stage {state.get('stage', 'starting')!r}.")
    backend().approve(run_id, body.approved_by.strip())
    return {"run_id": run_id, "sent": "approve"}


@app.get("/config")
def get_config() -> dict:
    worker = config.run_repo_target()
    return {"orchestrator": backend().name, "fleet": steps.list_repos(), "workflow": config.WORKFLOW_NAME,
            "worker": worker, "stand_in_worker": worker.startswith("orchestrator.stub_agent")}


@app.get("/", response_class=HTMLResponse)
def page() -> str:
    return (Path(__file__).parent / "page.html").read_text(encoding="utf-8")


def main() -> None:
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=int(os.environ.get("PORT", "8000")), log_level="info")


if __name__ == "__main__":
    main()
