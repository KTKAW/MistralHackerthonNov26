#!/usr/bin/env python3
"""run_repo.py — prepare a fresh work copy and run one headless Vibe (3.1.3) against it.

Pinned interface contract (track C codes against this — do not change):

    def run_repo(run_id: str, repo: str, *, fleet_root="fleet", runs_root="runs",
                 vibe_home="vibe-home", heartbeat_fn=None) -> dict:
        # work copy:  runs/<run_id>/<repo>/src
        # outputs:    runs/<run_id>/<repo>/verdict.json        (valid vs schema/verdict.schema.json)
        #             runs/<run_id>/<repo>/vibe/export.json     (tokens, cost, outcome)
        # returns:    {"repo": repo, "rc": int, "verdict": dict, "export": dict}

Layout produced per run:

    runs/<run_id>/<repo>/src/          fresh copy of the repo (vibe --workdir)
    runs/<run_id>/<repo>/.venv/        offline venv, vulnerable version installed
    runs/<run_id>/<repo>/wheelhouse/   copy of the repo wheelhouse (readable in-sandbox)
    runs/<run_id>/<repo>/schema/       copy of the verdict schema (readable in-sandbox)
    runs/<run_id>/<repo>/advisory.json the advisory facts the worker prompt reads
    runs/<run_id>/<repo>/verdict.json  written by the agent (output)
    runs/<run_id>/<repo>/vibe/export.json  written by vibe --output-dir (output)
    runs/<run_id>/<repo>/hook.log      pre_tool hook decisions (sandbox audit)

SANDBOX_WORKDIR is the work-copy ROOT (runs/<run_id>/<repo>); the seatbelt profile
confines shell writes to it, and the path hook confines file tools to its src/ plus
verdict.json.
"""
import json
import os
import shutil
import subprocess
import sys
import threading
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

DEFAULT_ADVISORY = {
    "id": "CVE-2026-96760",
    "package": "authlib",
    "affected_range": "<1.9.0",
    "flawed_function": "authlib.jose.JsonWebSignature.deserialize_json",
}

COPY_IGNORE = shutil.ignore_patterns("__pycache__", ".pytest_cache", ".venv", "*.pyc")


def _log(msg):
    try:
        print(f"[run_repo] {msg}", flush=True)
    except (BrokenPipeError, OSError):
        pass  # Ignore pipe errors in Temporal sandbox


def _prepare_work_copy(run_id, repo, fleet_root, runs_root):
    """Fresh copy of the repo under runs/<run_id>/<repo>/src. One attempt only."""
    work = REPO_ROOT / runs_root / run_id / repo
    src = work / "src"
    if work.exists():
        shutil.rmtree(work)
    template = REPO_ROOT / fleet_root / repo
    if not template.is_dir():
        # A4 self-test: a throwaway service pre-seeded at runs/<run_id>/src
        template = REPO_ROOT / runs_root / run_id / "src"
    if not template.is_dir():
        raise FileNotFoundError(f"no such repo: {fleet_root}/{repo} (nor pre-seeded {runs_root}/{run_id}/src)")
    work.mkdir(parents=True, exist_ok=True)
    shutil.copytree(template, src, ignore=COPY_IGNORE)
    _log(f"work copy: {src} (from {template})")
    return work, src


def _write_advisory(work, run_id, runs_root, template_src):
    advisory = dict(DEFAULT_ADVISORY)
    for cand in (template_src / "advisory.json", REPO_ROOT / runs_root / run_id / "advisory.json"):
        if cand.is_file():
            advisory.update(json.loads(cand.read_text()))
            break
    (work / "advisory.json").write_text(json.dumps(advisory, indent=2) + "\n")
    return advisory


def _stage_sandbox_inputs(work):
    """wheelhouse + schema copies the sandboxed agent can read (reads confined by profile)."""
    wh_src = REPO_ROOT / "wheelhouse"
    if wh_src.is_dir():
        shutil.copytree(wh_src, work / "wheelhouse")
    schema_src = REPO_ROOT / "schema"
    if schema_src.is_dir():
        shutil.copytree(schema_src, work / "schema")


def _make_venv(work, src):
    venv = work / ".venv"
    uv = shutil.which("uv")
    if uv:
        subprocess.run([uv, "venv", "--python", "3.12", "--seed", str(venv)], check=True,
                       capture_output=True)
    else:
        subprocess.run([sys.executable, "-m", "venv", "--without-pip", str(venv)], check=True)
    wheelhouse = REPO_ROOT / "wheelhouse"
    reqs = src / "requirements.txt"
    pip = venv / "bin" / "pip"
    if pip.exists():
        subprocess.run([str(pip), "install", "--no-index", "--find-links", str(wheelhouse),
                        "-r", str(reqs)], check=True, capture_output=True)
    elif uv:
        subprocess.run([uv, "pip", "install", "--python", str(venv / "bin" / "python"),
                        "--no-index", "--find-links", str(wheelhouse), "-r", str(reqs)],
                       check=True, capture_output=True)
    else:
        raise RuntimeError("no pip in venv and no uv available")
    _log(f"venv ready: {venv} (offline install from {wheelhouse})")
    return venv


def _git_init(work_copy):
    """Make the work copy a git repo so 'git status' can prove no tampering."""
    env = dict(os.environ)
    for args in (["init", "-q"], ["add", "-A"],
                 ["-c", "user.name=le-chonk-worker", "-c", "user.email=worker@le-chonk.local",
                  "commit", "-q", "-m", "work copy baseline"]):
        subprocess.run(["git", "-C", str(work_copy)] + args, check=True, capture_output=True, env=env)


def run_repo(run_id: str, repo: str, *, fleet_root="fleet", runs_root="runs",
             vibe_home="vibe-home", heartbeat_fn=None) -> dict:
    work, src = _prepare_work_copy(run_id, repo, fleet_root, runs_root)
    _write_advisory(work, run_id, runs_root, src)
    _stage_sandbox_inputs(work)
    _make_venv(work, src)
    _git_init(src)

    vibe_home_abs = (REPO_ROOT / vibe_home).resolve()
    env = dict(os.environ)
    env.update({
        "VIBE_HOME": str(vibe_home_abs),
        "OTEL_ENABLED": "false",
        "SANDBOX_WORKDIR": str(work.resolve()),
        "SANDBOX_VIBE_HOME": str(vibe_home_abs),
        "HOOK_LOG": str(work / "hook.log"),
        # pin Vibe to 3.1.3: the isolated tool venv comes first on PATH
        "PATH": str(vibe_home_abs / "tool-venv" / "bin") + os.pathsep + env.get("PATH", ""),
    })
    cmd = [
        "vibe",
        "--workdir", str(src), "--trust",
        "--prompt-file", str(REPO_ROOT / "worker" / "prompt.md"),
        "--model", "mistral-large-4-0",
        "--output", "text", "--output-dir", str(work / "vibe"),
        "--max-turns", "80", "--max-price", "3", "--time-limit", "560",
        "--disabled-tools", "connector_web_search_web_search",
        "--disabled-tools", "connector_web_search_open_url",
        "--auto-approve",
    ]
    _log("starting headless vibe: " + " ".join(cmd))
    proc = subprocess.Popen(cmd, env=env, cwd=str(src))

    stop = threading.Event()

    def heartbeat():
        while not stop.wait(10):
            if heartbeat_fn is not None:
                try:
                    heartbeat_fn()  # e.g. workflows.activity_heartbeat(...)
                except Exception:
                    pass

    t = threading.Thread(target=heartbeat, daemon=True)
    t.start()
    rc = proc.wait()
    stop.set()
    _log(f"vibe exited rc={rc}")

    verdict_path = work / "verdict.json"
    if verdict_path.is_file():
        verdict = json.loads(verdict_path.read_text())
    else:
        verdict = {
            "repo": repo, "advisory": json.loads((work / "advisory.json").read_text()),
            "verdict": "needs_human",
            "reason": "worker did not produce verdict.json (rc=%d)" % rc,
            "path": [], "proof": [],
            "suite": {"before": {"passed": 0, "failed": 0}, "after": {"passed": 0, "failed": 0}},
            "follow_ups": [],
        }
    export_path = work / "vibe" / "export.json"
    export = json.loads(export_path.read_text()) if export_path.is_file() else {}
    return {"repo": repo, "rc": rc, "verdict": verdict, "export": export}


if __name__ == "__main__":
    run_id = sys.argv[1] if len(sys.argv) > 1 else "selftest"
    repo = sys.argv[2] if len(sys.argv) > 2 else "selftest"
    result = run_repo(run_id, repo)
    try:
        print(json.dumps({"repo": result["repo"], "rc": result["rc"],
                          "verdict": result["verdict"].get("verdict")}, indent=2))
    except (BrokenPipeError, OSError):
        pass
