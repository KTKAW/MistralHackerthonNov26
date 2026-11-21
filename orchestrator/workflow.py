"""workflow.py — the le_chonk_run workflow + worker entrypoint. Track C.

Pipeline (one run):
    intake (24 h clock starts) → read_advisory (ONE model call → advisory.json)
    → triage (one activity per repo, asyncio.gather, heartbeat 10 s, ONE attempt,
      fresh work copy) → verify (rules gate as code, no model) → report
      (early-warning.md from gated verdicts only, no model)
    → wait for signal "approve" (24 h timeout) → complete.

Two execution modes, same contracts:
  - hosted:  mistralai-workflows 3.20.0, worker = `workflows.run_worker([LeChonkRun])`
             (needs MISTRAL_API_KEY + DEPLOYMENT_NAME; OTEL_ENABLED=false)
  - local:   plain-Python orchestrator (Step C8 fallback) — `python -m orchestrator.workflow
             --run-local "<advisory text>"`. Used by web/app.py and the C6 stub test,
             and automatically when DEPLOYMENT_NAME is unset.

Stub strategy (C6): LE_CHONK_STUBS=1 and LE_CHONK_STUB_RUN_REPO=/tmp/.../stub_run_repo.py
force a fake run_repo and a fake repo list — an explicit override that wins even now
that worker/ is merged into build/base. Never create files under worker/ or fleet/
on this branch.

Never commit .env, vibe-home/, runs/, wheelhouse/.
"""

from __future__ import annotations

import argparse
import asyncio
import importlib.util
import json
import os
import sys
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUNS_ROOT = os.environ.get("LE_CHONK_RUNS_ROOT", os.path.join(REPO_ROOT, "runs"))
FLEET_ROOT = os.environ.get("LE_CHONK_FLEET_ROOT", os.path.join(REPO_ROOT, "fleet"))
WHEELHOUSE = os.environ.get("LE_CHONK_WHEELHOUSE", os.path.join(REPO_ROOT, "wheelhouse"))
VIBE_HOME = os.environ.get("LE_CHONK_VIBE_HOME", os.path.join(REPO_ROOT, "vibe-home"))
STUBS = os.environ.get("LE_CHONK_STUBS", "") == "1"
STUB_RUN_REPO = os.environ.get("LE_CHONK_STUB_RUN_REPO", "")
CLOCK = timedelta(hours=24)


# ---------------------------------------------------------------- helpers

def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _write_json(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(obj, fh, indent=2)
    os.replace(tmp, path)


def _read_json(path):
    try:
        with open(path) as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None


def list_repos(fleet_root=FLEET_ROOT):
    """Fleet repositories = directories under fleet/ (or the stub list)."""
    stub_list = os.environ.get("LE_CHONK_STUB_REPOS", "")
    if stub_list:
        return [r for r in stub_list.split(",") if r]
    if not os.path.isdir(fleet_root):
        return []
    return sorted(d for d in os.listdir(fleet_root)
                  if os.path.isdir(os.path.join(fleet_root, d)) and not d.startswith("."))


def read_advisory(advisory_text, run_id, *, runs_root=RUNS_ROOT):
    """Exactly ONE model call per run → {id, package, affected_range, flawed_function}.
    Writes runs/<run_id>/advisory.json. In stub mode: canned parse, no model call."""
    run_dir = os.path.join(runs_root, run_id)
    if STUBS:
        stub_adv = os.environ.get("LE_CHONK_STUB_ADVISORY", "")
        if stub_adv:
            advisory = json.loads(stub_adv)
        else:
            import re
            m = re.search(r"(CVE-\d{4}-\d+)", advisory_text, re.I)
            advisory = {
                "id": m.group(1) if m else "CVE-UNKNOWN",
                "package": "authlib",
                "affected_range": "<1.9.0",
                "flawed_function": "authlib.jose.JsonWebSignature.verify",
                "source": "stub",
            }
    else:
        from mistralai import Mistral
        client = Mistral(api_key=os.environ.get("MISTRAL_API_KEY"))
        prompt = (
            "Extract from this security advisory, as JSON with keys id, package, "
            "affected_range, flawed_function: the advisory/CVE id, the affected package "
            "name, the affected version range, and the flawed function (module path).\n\n"
            + advisory_text
        )
        resp = client.chat.complete(
            model="mistral-large-4-0",
            messages=[{"role": "user", "content": prompt}],
            response_format={"type": "json_object"},
        )
        advisory = json.loads(resp.choices[0].message.content)
    _write_json(os.path.join(run_dir, "advisory.json"), advisory)
    return advisory


def _heartbeat_fn():
    """Passed into run_repo as heartbeat_fn; calls workflows.activity_heartbeat
    when running inside a hosted activity, no-op otherwise."""
    def beat():
        try:
            from mistralai.workflows import activity_heartbeat
            activity_heartbeat("alive")
        except Exception:
            pass
    return beat


def get_run_repo():
    """Resolve run_repo: track A's worker.run_repo.run_repo, or an explicit stub.

    Precedence:
      1. stub mode ON (STUBS and STUB_RUN_REPO set)  → stub. This is an explicit
         override and wins even when worker/ is merged into build/base — the C6
         stub tests rely on it.
      2. worker.run_repo importable (track A merged) → "worker"
      3. STUB_RUN_REPO set without STUBS             → stub (legacy manual runs)
      4. RuntimeError
    """
    def _load_stub():
        spec = importlib.util.spec_from_file_location("stub_run_repo", STUB_RUN_REPO)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod.run_repo, "stub"

    if STUBS and STUB_RUN_REPO and os.path.isfile(STUB_RUN_REPO):
        return _load_stub()
    try:
        from worker.run_repo import run_repo  # type: ignore
        return run_repo, "worker"
    except Exception:
        pass
    if STUB_RUN_REPO and os.path.isfile(STUB_RUN_REPO):
        return _load_stub()
    raise RuntimeError(
        "no run_repo available: worker.run_repo could not be imported (track A not "
        "merged?) and no stub is configured. Set LE_CHONK_STUBS=1 and "
        "LE_CHONK_STUB_RUN_REPO=/tmp/.../stub_run_repo.py"
    )


def intake(run_id, advisory_text, *, runs_root=RUNS_ROOT, mode="local"):
    run_dir = os.path.join(runs_root, run_id)
    os.makedirs(run_dir, exist_ok=True)
    meta = _read_json(os.path.join(run_dir, "run.json")) or {}
    meta.update({
        "run_id": run_id,
        "started_at": meta.get("started_at") or _now_iso(),
        "status": "RUNNING",
        "mode": mode,
        "advisory_text": advisory_text,
    })
    _write_json(os.path.join(run_dir, "run.json"), meta)
    return meta


def _set_status(run_id, status, *, runs_root=RUNS_ROOT):
    p = os.path.join(runs_root, run_id, "run.json")
    meta = _read_json(p) or {}
    meta["status"] = status
    meta["updated_at"] = _now_iso()
    _write_json(p, meta)


def triage_one(run_id, repo, *, runs_root=RUNS_ROOT, fleet_root=FLEET_ROOT,
               wheelhouse=WHEELHOUSE, vibe_home=VIBE_HOME, record=None):
    """One activity's work. Returns run_repo's dict {repo, rc, verdict, export}."""
    run_repo, _src = get_run_repo()
    if record is not None:
        record.append((repo, time.monotonic()))
    return run_repo(run_id, repo, fleet_root=fleet_root, runs_root=runs_root,
                    vibe_home=vibe_home, heartbeat_fn=_heartbeat_fn())


def _collect_verdicts(run_id, repos, *, runs_root=RUNS_ROOT):
    verdicts = []
    for repo in repos:
        v = _read_json(os.path.join(runs_root, run_id, repo, "verdict.json"))
        if v is not None:
            verdicts.append(v)
    return verdicts


def wait_for_approve(run_id, *, runs_root=RUNS_ROOT, timeout=CLOCK, poll_s=1.0):
    """Pause until a human drops runs/<run_id>/approved (or sets run.json status
    APPROVED), up to the 24 h clock. Returns True if approved, False on timeout."""
    deadline = time.monotonic() + timeout.total_seconds()
    while time.monotonic() < deadline:
        if os.path.isfile(os.path.join(runs_root, run_id, "approved")):
            return True
        meta = _read_json(os.path.join(runs_root, run_id, "run.json")) or {}
        if meta.get("status") == "APPROVED":
            return True
        time.sleep(poll_s)
    return False


# ---------------------------------------------------------------- local orchestrator (C8)

def run_local(advisory_text, run_id=None, *, runs_root=RUNS_ROOT, fleet_root=FLEET_ROOT,
              wheelhouse=WHEELHOUSE, vibe_home=VIBE_HOME, resume=False):
    """Plain-Python orchestrator with the SAME contracts as the hosted workflow.
    Blocking. Crash-resumable: existing verdicts/gate/report in runs/<run_id>
    are reused, missing steps are re-run."""
    from orchestrator.gate import gate
    from orchestrator.report import render_early_warning

    run_id = run_id or uuid.uuid4().hex[:12]
    meta = intake(run_id, advisory_text, runs_root=runs_root, mode="local")
    run_dir = os.path.join(runs_root, run_id)

    advisory = _read_json(os.path.join(run_dir, "advisory.json"))
    if advisory is None:
        advisory = read_advisory(advisory_text, run_id, runs_root=runs_root)

    repos = list_repos(fleet_root)
    # triage — one "activity" per repo, all in parallel, one attempt each.
    # Repos that already have a verdict (crash-resume) are skipped.
    todo = [r for r in repos
            if not os.path.isfile(os.path.join(run_dir, r, "verdict.json"))]
    if todo:
        started = []
        max_workers = len(todo)
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futs = {ex.submit(triage_one, run_id, r, runs_root=runs_root,
                              fleet_root=fleet_root, wheelhouse=wheelhouse,
                              vibe_home=vibe_home, record=started): r for r in todo}
            results = {r: f.result() for f, r in futs.items()}
        if started:
            t0 = min(t for _, t in started)
            spread = max(t for _, t in started) - t0
            meta["activities_start_spread_s"] = round(spread, 3)
            meta["activities_started"] = [r for r, _ in sorted(started, key=lambda x: x[1])]
            _write_json(os.path.join(run_dir, "run.json"), meta)

    verdicts = _collect_verdicts(run_id, repos, runs_root=runs_root)
    # verify — the gate, as code. Re-run if any verdict lacks a gate result.
    if any("gate" not in v for v in verdicts):
        verdicts = gate(run_id, verdicts, runs_root=runs_root,
                        wheelhouse=wheelhouse, fleet_root=fleet_root)
    # report — no model call, gated verdicts only.
    ew = os.path.join(run_dir, "early-warning.md")
    if not os.path.isfile(ew):
        render_early_warning(run_id, verdicts, runs_root=runs_root)
    # pause for a human.
    _set_status(run_id, "AWAITING_APPROVAL", runs_root=runs_root)
    ok = wait_for_approve(run_id, runs_root=runs_root)
    _set_status(run_id, "COMPLETED" if ok else "TIMED_OUT", runs_root=runs_root)
    return run_id


def resume_pending(*, runs_root=RUNS_ROOT, **kw):
    """Crash-resume: re-drive every RUNNING/AWAITING_APPROVAL run to completion."""
    resumed = []
    if not os.path.isdir(runs_root):
        return resumed
    for run_id in sorted(os.listdir(runs_root)):
        meta = _read_json(os.path.join(runs_root, run_id, "run.json"))
        if not meta or meta.get("status") not in ("RUNNING", "AWAITING_APPROVAL"):
            continue
        advisory_text = meta.get("advisory_text", "")
        run_local(advisory_text, run_id=run_id, runs_root=runs_root, resume=True, **kw)
        resumed.append(run_id)
    return resumed


# ---------------------------------------------------------------- hosted workflow (C1)

def define_hosted_workflow():
    """Build the mistralai-workflows class. Imported lazily so local mode never
    touches Temporal config discovery."""
    import temporalio
    from mistralai.workflows import activity, workflow, get_execution_id
    from orchestrator.gate import gate
    from orchestrator.report import render_early_warning

    @activity(start_to_close_timeout=timedelta(seconds=900),
              heartbeat_timeout=timedelta(seconds=60),
              retry_policy_max_attempts=1)
    def triage_repo_activity(run_id, repo):
        return triage_one(run_id, repo)

    @activity(start_to_close_timeout=timedelta(seconds=300),
              retry_policy_max_attempts=1)
    def read_advisory_activity(advisory_text, run_id):
        return read_advisory(advisory_text, run_id)

    @activity(start_to_close_timeout=timedelta(hours=2),
              heartbeat_timeout=timedelta(seconds=60),
              retry_policy_max_attempts=1)
    def verify_activity(run_id, verdicts):
        return gate(run_id, verdicts)

    @activity(start_to_close_timeout=timedelta(minutes=10),
              retry_policy_max_attempts=1)
    def report_activity(run_id, gated):
        return render_early_warning(run_id, gated)

    @workflow.define(name="le_chonk_run", execution_timeout=CLOCK)
    class LeChonkRun:
        def __init__(self):
            self.approved = False

        @workflow.signal(name="approve")
        def on_approve(self):
            self.approved = True

        @workflow.entrypoint
        async def run(self, advisory_text: str):
            run_id = get_execution_id() or uuid.uuid4().hex[:12]
            intake(run_id, advisory_text, mode="hosted")
            advisory = await read_advisory_activity(advisory_text, run_id)
            repos = list_repos()
            # triage: one activity per repo, all in parallel, one attempt each
            verdicts = list(await asyncio.gather(*[
                triage_repo_activity(run_id, r) for r in repos
            ]))
            gated = await verify_activity(run_id, verdicts)
            report = await report_activity(run_id, gated)
            # pause until a human sends "approve" (24 h timeout on the workflow)
            await workflow.wait_condition(lambda: self.approved, timeout=CLOCK,
                                          timeout_summary="approve_wait")
            _set_status(run_id, "COMPLETED")
            return {"run_id": run_id, "report": report}

    return LeChonkRun


# ---------------------------------------------------------------- entrypoint (C5)

def main(argv=None):
    os.environ.setdefault("OTEL_ENABLED", "false")
    ap = argparse.ArgumentParser(description="le_chonk_run worker / local orchestrator")
    ap.add_argument("--run-local", metavar="ADVISORY_TEXT",
                    help="run the local (fallback) orchestrator once, blocking")
    ap.add_argument("--run-id", default=None, help="run id for --run-local / --resume-run")
    ap.add_argument("--resume", action="store_true",
                    help="resume all pending local runs (crash recovery), then exit")
    ap.add_argument("--resume-run", metavar="RUN_ID", help="resume one pending run")
    args = ap.parse_args(argv)

    if args.resume:
        print("resumed:", resume_pending())
        return 0
    if args.resume_run:
        meta = _read_json(os.path.join(RUNS_ROOT, args.resume_run, "run.json")) or {}
        run_local(meta.get("advisory_text", ""), run_id=args.resume_run, resume=True)
        return 0
    if args.run_local is not None:
        run_id = run_local(args.run_local, run_id=args.run_id)
        print("run complete:", run_id)
        return 0

    # default: the worker process
    if os.environ.get("DEPLOYMENT_NAME"):
        import asyncio as _asyncio
        LeChonkRun = define_hosted_workflow()
        from mistralai.workflows import run_worker
        _asyncio.run(run_worker([LeChonkRun]))
        return 0
    # no deployment configured → local worker: resume anything pending, then exit
    print("DEPLOYMENT_NAME unset — running in local (fallback) mode. "
          "Resume pending runs: --resume. Start a run: --run-local \"<advisory>\". "
          "Hosted worker: set MISTRAL_API_KEY + DEPLOYMENT_NAME.")
    print("resumed:", resume_pending())
    return 0


if __name__ == "__main__":
    sys.exit(main())
