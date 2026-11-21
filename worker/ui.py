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
import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse

REPO_ROOT = Path(__file__).resolve().parent.parent
RUNS_ROOT = Path(os.environ.get("LE_CHONK_RUNS_ROOT", str(REPO_ROOT / "runs"))).resolve()
STATIC_DIR = Path(__file__).resolve().parent / "static"
PORT = int(os.environ.get("LE_CHONK_UI_PORT", "8001"))


def create_app(runs_root=None) -> FastAPI:
    """App factory — tests pass a tmp runs_root."""
    app = FastAPI(title="le-chonk sandbox audit console")
    app.state.runs_root = Path(runs_root).resolve() if runs_root else RUNS_ROOT

    @app.get("/api/health")
    def health():
        return {"ok": True, "runs_root": str(app.state.runs_root)}

    @app.get("/")
    def index():
        return FileResponse(STATIC_DIR / "index.html")

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=PORT, log_level="info")
