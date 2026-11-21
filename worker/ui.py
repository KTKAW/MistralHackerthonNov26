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

Start it with the project venv (auto re-execs if you use a bare python3):
    .venv/bin/python worker/ui.py        # or just: python3 worker/ui.py
"""
import asyncio
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path


def _ensure_deps():
    """Re-exec into the project .venv when started with a bare interpreter.

    fastapi/uvicorn live in .venv (installed offline from wheelhouse/), which
    is gitignored — a system python3 has neither them nor pytest.
    """
    try:
        import fastapi  # noqa: F401
        return
    except ImportError:
        pass
    venv_py = Path(__file__).resolve().parent.parent / ".venv" / "bin" / "python"
    if venv_py.exists() and Path(sys.executable).resolve() != venv_py.resolve():
        os.execv(str(venv_py), [str(venv_py), str(Path(__file__).resolve()), *sys.argv[1:]])
    sys.exit(
        "fastapi/uvicorn are not installed for this interpreter "
        f"({sys.executable}).\n"
        "Run with the project venv:  .venv/bin/python worker/ui.py\n"
        "If .venv is missing (fresh clone), create it offline:\n"
        "  uv venv .venv --python 3.12 && "
        "uv pip install --python .venv/bin/python --no-index --find-links wheelhouse "
        "fastapi uvicorn httpx pytest jsonschema\n"
        "(wheelhouse/ and .venv/ are gitignored, so a fresh clone needs them "
        "copied from a machine that has them.)"
    )


_ensure_deps()

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

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


def sys_executable() -> str:
    return sys.executable or "python3"


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


def _write_run_meta(runs_root: Path, run_id: str, **fields):
    meta_path = runs_root / run_id / "run.json"
    meta_path.parent.mkdir(parents=True, exist_ok=True)
    meta = _read_json(meta_path) or {}
    meta.update(fields)
    meta_path.write_text(json.dumps(meta, indent=2) + "\n")


def create_app(runs_root=None) -> FastAPI:
    """App factory — tests pass a tmp runs_root."""
    app = FastAPI(title="le-chonk sandbox audit console")
    app.state.runs_root = Path(runs_root).resolve() if runs_root else RUNS_ROOT
    app.state.procs = {}  # run_id -> subprocess.Popen of worker/run_repo.py

    @app.get("/api/health")
    def health():
        return {"ok": True, "runs_root": str(app.state.runs_root)}

    @app.get("/api/runs")
    def list_runs():
        return {"runs": scan_runs(app.state.runs_root)}

    @app.get("/api/runs/{run_id}/{repo}")
    def get_run(run_id: str, repo: str):
        return run_detail(app.state.runs_root, _safe_name(run_id), _safe_name(repo))

    @app.get("/api/runs/{run_id}/{repo}/hooklog")
    async def hooklog(run_id: str, repo: str, since: int = Query(0, ge=0)):
        """SSE stream of hook.log lines from byte offset `since` (0 = whole file)."""
        work = app.state.runs_root / _safe_name(run_id) / _safe_name(repo)
        if not work.is_dir():
            raise HTTPException(status_code=404, detail="no such run")
        log = work / "hook.log"

        async def gen():
            pos = since
            while True:
                try:
                    if log.is_file():
                        data = log.read_bytes()
                        if len(data) < pos:  # file was truncated (new run) — restart
                            pos = 0
                        if len(data) > pos:
                            chunk = data[pos:]
                            pos = len(data)
                            for line in chunk.splitlines():
                                if line.strip():
                                    yield "data: " + line.decode("utf-8", "replace") + "\n\n"
                except OSError:
                    pass
                await asyncio.sleep(1)

        return StreamingResponse(gen(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache"})

    def _work_dir(run_id: str, repo: str) -> Path:
        work = app.state.runs_root / _safe_name(run_id) / _safe_name(repo)
        if not work.is_dir():
            raise HTTPException(status_code=404, detail="no such run")
        return work

    @app.get("/api/runs/{run_id}/{repo}/file")
    def get_file(run_id: str, repo: str, path: str = Query(...)):
        """Read one file inside the work copy. Mirrors path_hook's denies:
        .env / secrets anywhere are refused; nothing outside the work copy."""
        work = _work_dir(run_id, repo)
        if not path or "\x00" in path:
            raise HTTPException(status_code=400, detail="bad path")
        p = Path(path)
        if not p.is_absolute():
            p = work / p
        try:
            rp = p.resolve(strict=True)
        except OSError:
            raise HTTPException(status_code=404, detail="no such file")
        parts = rp.parts
        if ".env" in parts or "secrets" in parts:
            raise HTTPException(status_code=403, detail="refused: secrets (.env / secrets/) are never served")
        if rp != work and work not in rp.parents:
            raise HTTPException(status_code=403, detail="refused: outside the work copy")
        if not rp.is_file():
            raise HTTPException(status_code=404, detail="not a file")
        data = rp.read_bytes()[:200_000]
        return {
            "path": str(rp), "rel": str(rp.relative_to(work)),
            "content": data.decode("utf-8", "replace"),
            "truncated": rp.stat().st_size > 200_000,
        }

    @app.get("/api/runs/{run_id}/{repo}/diff")
    def get_diff(run_id: str, repo: str):
        """git status + diff of the work copy vs its baseline commit."""
        work = _work_dir(run_id, repo)
        src = work / "src"
        out = {"available": False, "status": "", "diff": "", "entries": [], "deleted": []}
        if not (src / ".git").exists():
            return out
        out["available"] = True
        for args, key in ((["status", "--porcelain"], "status"), (["diff"], "diff")):
            try:
                res = subprocess.run(["git", "-C", str(src)] + args,
                                     capture_output=True, text=True, timeout=15)
                out[key] = res.stdout[:100_000]
            except (OSError, subprocess.SubprocessError) as e:
                out[key] = f"git error: {e}"
        for line in out["status"].splitlines():
            if line.strip():
                code, _, p = line.partition(" ")
                entry = {"code": code.strip(), "path": p.strip()}
                out["entries"].append(entry)
                if "D" in entry["code"]:
                    out["deleted"].append(entry["path"])
        return out

    # ---------- controls ----------

    class StartRun(BaseModel):
        repo: str
        run_id: str | None = None

    @app.post("/api/runs")
    def start_run(body: StartRun):
        """Start worker/run_repo.py as a subprocess (own process group, so it can
        be SIGTERMed). run_repo.py itself is untouched — pinned contract."""
        repo = _safe_name(body.repo)
        run_id = _safe_name(body.run_id) if body.run_id else \
            "ui-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
        if run_id in app.state.procs and app.state.procs[run_id].poll() is None:
            raise HTTPException(status_code=409, detail=f"run {run_id} already running")
        # the repo must exist as fleet/<repo> or a pre-seeded runs/<run_id>/src
        if not (REPO_ROOT / "fleet" / repo).is_dir() and \
                not (app.state.runs_root / run_id / "src").is_dir():
            raise HTTPException(status_code=404, detail=f"no such repo: {repo}")
        log_path = app.state.runs_root / run_id / "ui-run.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_fh = log_path.open("a")
        proc = subprocess.Popen(
            [sys_executable(), str(REPO_ROOT / "worker" / "run_repo.py"), run_id, repo],
            cwd=str(REPO_ROOT), stdout=log_fh, stderr=subprocess.STDOUT,
            start_new_session=True,  # own process group → clean SIGTERM to the tree
        )
        app.state.procs[run_id] = proc
        _write_run_meta(app.state.runs_root, run_id, repo=repo,
                        started_at=datetime.now(timezone.utc).isoformat(),
                        pid=proc.pid, status="running", ui=True)

        def waiter():
            rc = proc.wait()
            meta = _read_json(app.state.runs_root / run_id / "run.json") or {}
            if meta.get("status") == "running":  # don't clobber an explicit "stopped"
                _write_run_meta(app.state.runs_root, run_id,
                                status="done" if rc == 0 else "failed", rc=rc,
                                finished_at=datetime.now(timezone.utc).isoformat())
            log_fh.close()

        threading.Thread(target=waiter, daemon=True).start()
        return {"run_id": run_id, "repo": repo, "pid": proc.pid, "status": "running",
                "log": str(log_path)}

    @app.post("/api/runs/{run_id}/stop")
    def stop_run(run_id: str):
        run_id = _safe_name(run_id)
        proc = app.state.procs.get(run_id)
        pid = proc.pid if proc and proc.poll() is None else \
            (_read_json(app.state.runs_root / run_id / "run.json") or {}).get("pid")
        if not pid or not _pid_alive(pid):
            raise HTTPException(status_code=404, detail="no live run with that id")
        try:
            os.killpg(int(pid), signal.SIGTERM)  # Vibe stops cleanly, writes export.json
        except OSError:
            os.kill(int(pid), signal.SIGTERM)
        _write_run_meta(app.state.runs_root, run_id, status="stopped",
                        stopped_at=datetime.now(timezone.utc).isoformat())
        return {"run_id": run_id, "pid": pid, "signal": "SIGTERM"}

    @app.post("/api/runs/{run_id}/{repo}/validate")
    def validate_run(run_id: str, repo: str):
        work = _work_dir(run_id, repo)
        verdict = work / "verdict.json"
        if not verdict.is_file():
            raise HTTPException(status_code=404, detail="no verdict.json yet")
        try:
            res = subprocess.run([sys_executable(), str(REPO_ROOT / "schema" / "validate.py"),
                                  str(verdict)], capture_output=True, text=True, timeout=30)
            return {"ok": res.returncode == 0, "rc": res.returncode,
                    "output": (res.stdout + res.stderr).strip()}
        except (OSError, subprocess.SubprocessError) as e:
            raise HTTPException(status_code=500, detail=f"validator failed: {e}")

    # ---------- playground + policy ----------

    class Play(BaseModel):
        cmd: str

    def _scratch_dir() -> Path:
        scratch = app.state.runs_root / "ui-scratch" / "play"
        scratch.mkdir(parents=True, exist_ok=True)
        return scratch

    @app.post("/api/playground")
    def playground(body: Play):
        """Run one command through sandbox/douane with SANDBOX_WORKDIR at a scratch
        dir under runs/ — the same rewrite the worker's shell hook applies."""
        if not body.cmd or not body.cmd.strip():
            raise HTTPException(status_code=400, detail="empty command")
        if sys.platform != "darwin":
            raise HTTPException(status_code=501, detail="playground needs macOS sandbox-exec")
        douane = REPO_ROOT / "sandbox" / "douane"
        if not douane.is_file():
            raise HTTPException(status_code=500, detail="sandbox/douane missing")
        scratch = _scratch_dir()
        env = {
            "PATH": "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
            "HOME": os.environ.get("HOME", "/Users/" + os.getlogin()),
            "SANDBOX_WORKDIR": str(scratch),
            "SANDBOX_VIBE_HOME": str(REPO_ROOT / "vibe-home"),
            "SANDBOX_PYTHON_DIR": os.environ.get(
                "SANDBOX_PYTHON_DIR", str(Path.home() / ".local/share/uv/python")),
            "HOOK_LOG": str(scratch / "hook.log"),
        }
        try:
            res = subprocess.run([str(douane), body.cmd], env=env, cwd=str(scratch),
                                 capture_output=True, text=True, timeout=30)
            rc, out, err = res.returncode, res.stdout, res.stderr
        except subprocess.TimeoutExpired:
            rc, out, err = 124, "", "timed out after 30 s"
        # append to the playground's own audit log
        try:
            with (scratch / "playground.log").open("a") as fh:
                fh.write(json.dumps({"ts": datetime.now(timezone.utc).isoformat(),
                                     "cmd": body.cmd, "rc": rc}) + "\n")
        except OSError:
            pass
        blob = (err + out).lower()
        denied = rc != 0 and any(k in blob for k in (
            "denied", "deny", "not permitted", "sandbox", "could not resolve", "network"))
        return {"cmd": body.cmd, "rc": rc, "stdout": out[-20_000:], "stderr": err[-20_000:],
                "denied": denied}

    @app.get("/api/policy")
    def policy():
        """The effective Seatbelt profile (as douane renders it for the scratch
        dir) plus the douane wrapper source."""
        scratch = _scratch_dir()
        template = (REPO_ROOT / "sandbox" / "profile.sb.template").read_text()
        rendered = (template
                    .replace("__WORKDIR__", str(scratch))
                    .replace("__PYDIR__", os.environ.get(
                        "SANDBOX_PYTHON_DIR", str(Path.home() / ".local/share/uv/python")))
                    .replace("__VIBEHOME__", str(REPO_ROOT / "vibe-home")))
        douane_src = (REPO_ROOT / "sandbox" / "douane").read_text()
        return {"profile": rendered, "douane": douane_src, "scratch": str(scratch)}

    @app.get("/")
    def index():
        return FileResponse(STATIC_DIR / "index.html")

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=PORT, log_level="info")
