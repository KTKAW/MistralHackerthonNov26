#!/usr/bin/env python3
"""ui.py — Sandbox Audit Console (Track A GUI).

Local web dashboard for watching the sandboxed per-repo workers: run cards,
live hook audit (hook.log over SSE), verdict/proof/diff views, a douane
playground and the effective Seatbelt policy. Read-only over runs/ except for
explicit control actions (start/stop a run, validate, playground).

Run:  .venv/bin/python worker/ui.py        # serves 127.0.0.1:8001
Env:  LE_CHONK_RUNS_ROOT (default <repo>/runs)   — same var name as track C
      LE_CHONK_UI_PORT   (default 8001; track C's grid owns 8000)

See worker/UI-PLAN.md for the full plan.
"""
import json
import os
import re
import subprocess
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

REPO_ROOT = Path(__file__).resolve().parent.parent
RUNS_ROOT = Path(os.environ.get("LE_CHONK_RUNS_ROOT", str(REPO_ROOT / "runs"))).resolve()
STATIC_DIR = Path(__file__).resolve().parent / "static"
PORT = int(os.environ.get("LE_CHONK_UI_PORT", "8001"))

# run_id / repo are single path components — never allow separators.
_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")

VERDICT_COLORS = {
    "not_affected": "green",
    "affected_proven": "red",
    "affected_fixed": "amber",
    "needs_human": "purple",
}


def _read_json(path: Path):
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None


def _safe_name(name: str) -> str:
    if not _SAFE_NAME.match(name or ""):
        raise HTTPException(status_code=404, detail="no such run")
    return name


def _pid_alive(pid) -> bool:
    try:
        os.kill(int(pid), 0)
        return True
    except (OSError, ValueError, TypeError):
        return False


def _hook_stats(hook_log: Path) -> dict:
    """Aggregate hook.log JSONL: douane coverage = sandbox2 rewrites / shell calls."""
    stats = {"lines": 0, "rewrite": 0, "deny": 0, "allow": 0, "error": 0,
             "shell_calls": 0, "douane_pct": None, "denies": []}
    if not hook_log.is_file():
        return stats
    with hook_log.open() as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            stats["lines"] += 1
            event = ev.get("event")
            stats[event] = stats.get(event, 0) + 1
            if ev.get("hook") == "sandbox2" and ev.get("tool") in ("bash", "process_start"):
                stats["shell_calls"] += 1
            if event == "deny":
                stats["denies"].append(ev)
    if stats["shell_calls"]:
        stats["douane_pct"] = round(100.0 * stats["rewrite"] / stats["shell_calls"])
    # keep the payload small — only the last 50 denies
    stats["denies"] = stats["denies"][-50:]
    return stats


def _git_summary(src: Path) -> dict:
    """Porcelain status of the work copy; deleted files flagged (rule: never delete tests)."""
    out = {"available": False, "entries": [], "deleted": [], "counts": {}}
    if not (src / ".git").exists():
        return out
    out["available"] = True
    try:
        res = subprocess.run(["git", "-C", str(src), "status", "--porcelain"],
                             capture_output=True, text=True, timeout=10)
        for line in res.stdout.splitlines():
            if not line.strip():
                continue
            code, _, path = line.partition(" ")
            entry = {"code": code.strip(), "path": path.strip()}
            out["entries"].append(entry)
            out["counts"][entry["code"]] = out["counts"].get(entry["code"], 0) + 1
            if "D" in entry["code"]:
                out["deleted"].append(entry["path"])
    except (OSError, subprocess.SubprocessError):
        pass
    return out


def _card(runs_root: Path, run_id: str, repo: str) -> dict:
    work = runs_root / run_id / repo
    verdict = _read_json(work / "verdict.json") or {}
    export = _read_json(work / "vibe" / "export.json") or {}
    usage = export.get("usage") or {}
    meta = _read_json(runs_root / run_id / "run.json") or {}
    status = meta.get("status")
    if status == "running" and not _pid_alive(meta.get("pid")):
        status = "stopped"
    if not status:
        status = "done" if (work / "verdict.json").is_file() else "partial"
    hook = _hook_stats(work / "hook.log")
    return {
        "run_id": run_id,
        "repo": repo,
        "status": status,
        "verdict": verdict.get("verdict"),
        "color": VERDICT_COLORS.get(verdict.get("verdict"), "gray"),
        "reason": verdict.get("reason"),
        "cost_usd": export.get("cost_usd") or export.get("cost"),
        "tokens": usage.get("total_tokens") or export.get("tokens"),
        "usage": usage,
        "outcome": export.get("outcome"),
        "started_at": meta.get("started_at"),
        "douane_pct": hook["douane_pct"],
        "deny_count": hook["deny"],
        "shell_calls": hook["shell_calls"],
    }


def scan_runs(runs_root: Path) -> list:
    """Every runs/<run_id>/<repo>/ directory becomes one card."""
    cards = []
    if not runs_root.is_dir():
        return cards
    for run_dir in sorted(runs_root.iterdir()):
        if not run_dir.is_dir() or run_dir.name.startswith("."):
            continue
        for repo_dir in sorted(run_dir.iterdir()):
            # a prepared work copy always has advisory.json; a raw pre-seeded
            # template (e.g. runs/selftest/src) does not and is not a run
            if repo_dir.is_dir() and (repo_dir / "src").is_dir() \
                    and (repo_dir / "advisory.json").is_file():
                cards.append(_card(runs_root, run_dir.name, repo_dir.name))
    return cards


def run_detail(runs_root: Path, run_id: str, repo: str) -> dict:
    work = runs_root / run_id / repo
    if not work.is_dir():
        raise HTTPException(status_code=404, detail="no such run")
    verdict = _read_json(work / "verdict.json")
    return {
        "run_id": run_id,
        "repo": repo,
        "card": _card(runs_root, run_id, repo),
        "advisory": _read_json(work / "advisory.json"),
        "verdict": verdict,
        "export": _read_json(work / "vibe" / "export.json"),
        "hook_stats": _hook_stats(work / "hook.log"),
        "git": _git_summary(work / "src"),
        "stages": {
            "advisory": (work / "advisory.json").is_file(),
            "work_copy": (work / "src").is_dir(),
            "venv": (work / ".venv").is_dir(),
            "wheelhouse": (work / "wheelhouse").is_dir(),
            "vibe_export": (work / "vibe" / "export.json").is_file(),
            "verdict": (work / "verdict.json").is_file(),
        },
    }


def create_app(runs_root=None) -> FastAPI:
    """App factory — tests pass a tmp runs_root."""
    app = FastAPI(title="le-chonk sandbox audit console")
    app.state.runs_root = Path(runs_root).resolve() if runs_root else RUNS_ROOT

    @app.get("/api/health")
    def health():
        return {"ok": True, "runs_root": str(app.state.runs_root)}

    @app.get("/api/runs")
    def list_runs():
        return {"runs": scan_runs(app.state.runs_root)}

    @app.get("/api/runs/{run_id}/{repo}")
    def get_run(run_id: str, repo: str):
        return run_detail(app.state.runs_root, _safe_name(run_id), _safe_name(repo))

    @app.get("/")
    def index():
        return FileResponse(STATIC_DIR / "index.html")

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=PORT, log_level="info")
