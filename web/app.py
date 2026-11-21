"""web/app.py — FastAPI grid on :8000. Track C (build/track-c-orchestration-ui).

  POST /runs                 {advisory_text} → {run_id, started_at}   (starts a run)
  GET  /runs/{run_id}        JSON tiles — ONLY for gate-passed repos
  GET  /                     HTML grid, polls every 2 s + 24 h countdown + approve
  POST /runs/{run_id}/approve  sends the "approve" signal (human, never automatic)
  GET  /artifacts/...        static run artifacts (verdict.json, early-warning.md)

Local mode (default, no DEPLOYMENT_NAME): runs are driven by a
`python -m orchestrator.workflow --run-local` subprocess, so killing the web app
does not kill runs; restart and they resume. Hosted mode: Mistral Workflows.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import uuid
from datetime import datetime, timezone

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUNS_ROOT = os.environ.get("LE_CHONK_RUNS_ROOT", os.path.join(REPO_ROOT, "runs"))
HOSTED = bool(os.environ.get("DEPLOYMENT_NAME"))
CLOCK_HOURS = 24

app = FastAPI(title="le-chonk grid")


class StartRun(BaseModel):
    advisory_text: str


def _read_json(path):
    try:
        with open(path) as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None


def _run_meta(run_id):
    return _read_json(os.path.join(RUNS_ROOT, run_id, "run.json")) or {}


def _gate_ok(v):
    g = v.get("gate") or {}
    return bool(g.get("ok")) and v.get("verdict") != "needs_human"


def _tiles(run_id):
    """Tiles ONLY for gate-passed repos — an unchecked claim never appears."""
    run_dir = os.path.join(RUNS_ROOT, run_id)
    tiles = []
    if not os.path.isdir(run_dir):
        return tiles
    for repo in sorted(os.listdir(run_dir)):
        v = _read_json(os.path.join(run_dir, repo, "verdict.json"))
        if not v or not _gate_ok(v):
            continue
        tiles.append({
            "repo": v.get("repo", repo),
            "verdict": v.get("verdict"),
            "reason": (v.get("reason") or "")[:280],
            "proof": v.get("proof") or [],
            "fix": v.get("fix"),
            "usage": v.get("usage"),
            "verdict_url": f"/artifacts/{run_id}/{repo}/verdict.json",
        })
    return tiles


def start_run(advisory_text: str):
    run_id = uuid.uuid4().hex[:12]
    started_at = datetime.now(timezone.utc).isoformat()
    if HOSTED:
        from mistralai import Mistral
        client = Mistral(api_key=os.environ.get("MISTRAL_API_KEY"))
        client.workflows.execute_workflow(
            workflow_identifier="le_chonk_run",
            execution_id=run_id,
            input={"advisory_text": advisory_text},
            deployment_name=os.environ["DEPLOYMENT_NAME"],
        )
    else:
        run_dir = os.path.join(RUNS_ROOT, run_id)
        os.makedirs(run_dir, exist_ok=True)
        with open(os.path.join(run_dir, "run.json"), "w") as fh:
            json.dump({"run_id": run_id, "started_at": started_at, "status": "RUNNING",
                       "mode": "local", "advisory_text": advisory_text}, fh, indent=2)
        env = dict(os.environ)
        env.setdefault("OTEL_ENABLED", "false")
        log = open(os.path.join(run_dir, "worker.log"), "ab")
        subprocess.Popen(
            [sys.executable, "-m", "orchestrator.workflow",
             "--run-local", advisory_text, "--run-id", run_id],
            cwd=REPO_ROOT, env=env, stdout=log, stderr=subprocess.STDOUT,
        )
    return run_id, started_at


@app.post("/runs")
async def post_run(body: StartRun):
    run_id, started_at = start_run(body.advisory_text)
    return {"run_id": run_id, "started_at": started_at}


@app.get("/runs/{run_id}")
async def get_run(run_id: str):
    meta = _run_meta(run_id)
    return {
        "run_id": run_id,
        "started_at": meta.get("started_at"),
        "status": meta.get("status", "UNKNOWN"),
        "clock_hours": CLOCK_HOURS,
        "tiles": _tiles(run_id),
    }


@app.post("/runs/{run_id}/approve")
async def approve_run(run_id: str):
    if HOSTED:
        from mistralai import Mistral
        client = Mistral(api_key=os.environ.get("MISTRAL_API_KEY"))
        client.executions.signal_workflow_execution(
            execution_id=run_id, name="approve")
        return {"run_id": run_id, "approved": True, "mode": "hosted"}
    run_dir = os.path.join(RUNS_ROOT, run_id)
    os.makedirs(run_dir, exist_ok=True)
    with open(os.path.join(run_dir, "approved"), "w") as fh:
        fh.write(datetime.now(timezone.utc).isoformat())
    meta = _run_meta(run_id)
    meta["status"] = "APPROVED"
    with open(os.path.join(run_dir, "run.json"), "w") as fh:
        json.dump(meta, fh, indent=2)
    return {"run_id": run_id, "approved": True, "mode": "local"}


INDEX_HTML = """<!doctype html>
<html><head><meta charset="utf-8"><title>le-chonk grid</title>
<style>
 body{font-family:-apple-system,Helvetica Neue,sans-serif;margin:2rem;background:#fffdf8;color:#1d1d1b}
 h1{font-size:1.3rem} textarea{width:100%;height:6rem;font-family:monospace}
 #clock{font-size:2rem;font-variant-numeric:tabular-nums;margin:.5rem 0}
 .grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:.8rem}
 .tile{border:1px solid #e4e0d6;border-radius:8px;padding:.7rem;background:#fff}
 .tile h3{margin:.1rem 0 .4rem;font-size:.95rem}
 .v-affected_fixed,.v-affected_proven{color:#8a2c1d;font-weight:600}
 .v-not_affected{color:#2c6e2c;font-weight:600}
 .v-needs_human{color:#8a6d1d;font-weight:600}
 button{padding:.4rem 1rem} .muted{color:#6b6b66;font-size:.8rem}
</style></head><body>
<h1>le-chonk — 24 h vulnerability response</h1>
<div class="muted">Paste an advisory to start a run. Tiles appear only after the gate passes.</div>
<textarea id="adv" placeholder="Security advisory text…"></textarea>
<button onclick="startRun()">Start run</button>
<div id="clock"></div>
<div class="grid" id="grid"></div>
<button id="approveBtn" onclick="approve()" disabled>Approve early warning</button>
<div class="muted" id="status"></div>
<script>
let runId = new URLSearchParams(location.search).get('run');
async function startRun(){
  const r = await fetch('/runs',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({advisory_text:document.getElementById('adv').value})});
  const j = await r.json(); runId = j.run_id;
  history.replaceState(null,'','?run='+runId);
  document.getElementById('approveBtn').disabled=false;
  poll();
}
async function poll(){
  if(!runId) return;
  const r = await fetch('/runs/'+runId); const j = await r.json();
  document.getElementById('status').textContent =
    'run '+j.run_id+' — status: '+j.status;
  const t = j.started_at ? new Date(j.started_at).getTime() : Date.now();
  const left = Math.max(0, 24*3600*1000 - (Date.now()-t));
  const h = Math.floor(left/3600000), m = Math.floor(left%3600000/60000), s = Math.floor(left%60000/1000);
  document.getElementById('clock').textContent =
    String(h).padStart(2,'0')+':'+String(m).padStart(2,'0')+':'+String(s).padStart(2,'0')+' of 24:00:00';
  document.getElementById('grid').innerHTML = j.tiles.map(t=>
    `<div class="tile"><h3>${t.repo}</h3>
     <div class="v-${t.verdict}">${t.verdict}</div>
     <div>${t.reason}</div>
     ${t.proof.length?`<div class="muted">proof: ${t.proof.join(', ')}</div>`:''}
     <div class="muted"><a href="${t.verdict_url}">verdict.json</a></div></div>`).join('');
  setTimeout(poll, 2000);   // poll every 2 s
}
async function approve(){
  if(!runId) return;
  await fetch('/runs/'+runId+'/approve',{method:'POST'});
  document.getElementById('status').textContent = 'approve signal sent — run completing';
}
if(runId){ document.getElementById('approveBtn').disabled=false; poll(); }
</script></body></html>"""


@app.get("/", response_class=HTMLResponse)
async def index():
    return INDEX_HTML


if os.path.isdir(RUNS_ROOT):
    app.mount("/artifacts", StaticFiles(directory=RUNS_ROOT), name="artifacts")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
