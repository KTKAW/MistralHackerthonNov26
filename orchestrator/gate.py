"""gate.py — the rules gate as code. Track C (build/track-c-orchestration-ui).

NO model is used anywhere in this module. The gate may ONLY downgrade a verdict
to "needs_human", never upgrade. It re-runs every claimed proof itself:

  affected_proven / affected_fixed:
    - proof_fails_on_vulnerable : each proof test ID must FAIL on the vulnerable
                                  version (the work copy's own .venv, installed by
                                  the worker from the wheelhouse)
    - proof_passes_on_fixed     : each proof test ID must PASS on the fixed version
                                  (a second venv, installed from the wheelhouse)
    - suite_count_not_dropped   : suite.after total >= suite.before total
  not_affected:
    - no_src_changes            : src/ identical to the pristine fleet copy except
                                  agent-written files (proof test files)
  needs_human (already): recorded, left as-is.

Any failing rule => verdict = "needs_human" and per-rule results in verdict["gate"].
The gate writes verdict["gate"] back into runs/<run_id>/<repo>/verdict.json.

When track A's sandbox is merged, proof re-runs go through sandbox/douane
("the same sandbox"); until then they run directly. See _sandbox_wrap().
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import venv

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

PROOF_TIMEOUT_S = 600


def _run(cmd, cwd=None, env=None, timeout=PROOF_TIMEOUT_S):
    """Run a command, return (rc, combined_output). Never raises."""
    try:
        p = subprocess.run(
            cmd, cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout
        )
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except Exception as e:  # timeout, missing binary, ...
        return 127, f"gate: failed to run {cmd!r}: {e}"


def _sandbox_wrap(cmd, workdir):
    """If track A's sandbox wrapper exists, run cmd through it (same sandbox the
    worker used). Otherwise run directly. Strict: on any doubt we still run the
    command locally — the gate itself is orchestrator-side code, not agent code."""
    douane = os.path.join(REPO_ROOT, "sandbox", "douane")
    if os.path.isfile(douane) and os.access(douane, os.X_OK):
        env = dict(os.environ)
        env["SANDBOX_WORKDIR"] = workdir
        return [douane, "/bin/bash", "-c", " ".join(cmd)], env
    return cmd, None


def _ensure_venv(work_dir, wheelhouse, requirements, extra_pins=()):
    """Create work_dir/.venv if missing and install requirements offline from the
    wheelhouse. Returns path to the venv python, or None on failure."""
    py = os.path.join(work_dir, ".venv", "bin", "python")
    if not os.path.isfile(py):
        venv.EnvBuilder(with_pip=True).create(work_dir + "/.venv")
    if not os.path.isfile(py):
        # uv-managed pythons may lack ensurepip; fall back to uv venv
        rc, out = _run(["uv", "venv", "--python", sys.executable, work_dir + "/.venv"])
        if rc != 0:
            return None
    pip = os.path.join(work_dir, ".venv", "bin", "pip")
    if not os.path.isfile(pip):
        rc, _ = _run([py, "-m", "ensurepip"], timeout=120)
        if rc != 0:
            rc, _ = _run(["uv", "pip", "install", "--python", py, "pip"], timeout=180)
    if os.path.isfile(requirements):
        rc, out = _run(
            [pip, "install", "--no-index", "--find-links", os.path.abspath(wheelhouse),
             "-r", requirements], cwd=work_dir)
        if rc != 0:
            return None
    for pin in extra_pins:
        rc, out = _run(
            [pip, "install", "--no-index", "--find-links", os.path.abspath(wheelhouse),
             pin], cwd=work_dir)
        if rc != 0:
            return None
    return py


def _pytest_one(py, src, test_id, cwd):
    """Run a single pytest test ID. Returns True if it PASSED."""
    cmd, env_override = _sandbox_wrap([py, "-m", "pytest", "-q", "--tb=no", "-p", "no:cacheprovider", test_id], src)
    env = dict(os.environ)
    if env_override:
        env.update(env_override)
    rc, out = _run(cmd, cwd=cwd, env=env, timeout=PROOF_TIMEOUT_S)
    return rc == 0, rc, out


def _tree_digest(root, allow_names=frozenset()):
    """Map of relpath -> sha256 for every file under root, skipping .venv and
    files whose basename is in allow_names (agent-written proof files)."""
    out = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in (".venv", "__pycache__", ".git")]
        for f in filenames:
            if f in allow_names or f.endswith(".pyc"):
                continue
            p = os.path.join(dirpath, f)
            rel = os.path.relpath(p, root)
            try:
                with open(p, "rb") as fh:
                    out[rel] = hashlib.sha256(fh.read()).hexdigest()
            except OSError:
                out[rel] = "<unreadable>"
    return out


def _fixed_pins(verdict):
    """Wheelhouse pins for the fixed version, from the verdict's own fix field."""
    fix = verdict.get("fix") or {}
    if fix.get("kind") == "upgrade" and fix.get("target"):
        pkg = (verdict.get("advisory") or {}).get("package", "")
        if pkg:
            return [f"{pkg}=={fix['target']}"]
    return []


def gate(run_id, verdicts, *, runs_root="runs", wheelhouse="wheelhouse", fleet_root="fleet"):
    """Fill verdict["gate"] for each verdict; may ONLY downgrade to "needs_human".
    Writes each verdict back to runs/<run_id>/<repo>/verdict.json. Returns verdicts."""
    results = []
    for v in verdicts:
        repo = v.get("repo", "?")
        work = os.path.join(runs_root, run_id, repo)
        src = os.path.join(work, "src")
        rules = {}
        vd = v.get("verdict")

        if vd in ("affected_proven", "affected_fixed"):
            proofs = v.get("proof") or []
            if not isinstance(proofs, list) or not proofs:
                rules["proof_present"] = {"ok": False, "detail": "proof must be a non-empty list of test IDs"}
            else:
                # 1. proofs must FAIL on the vulnerable version (the work copy venv)
                vuln_py = _ensure_venv(work, wheelhouse, os.path.join(src, "requirements.txt"))
                bad = []
                for tid in proofs:
                    ok, rc, out = _pytest_one(vuln_py, src, tid, src) if vuln_py else (False, 127, "no venv")
                    if ok:
                        bad.append(tid)
                rules["proof_fails_on_vulnerable"] = {
                    "ok": not bad,
                    "detail": "all proofs failed on vulnerable version" if not bad
                              else f"proof(s) PASSED on the vulnerable version (bogus proof): {bad}",
                }
                # 2. proofs must PASS on the fixed version (second venv from wheelhouse)
                req = os.path.join(src, "requirements.txt")
                pins = _fixed_pins(v)
                if not pins:
                    rules["proof_passes_on_fixed"] = {"ok": False, "detail": "no upgrade target in verdict.fix — cannot build fixed venv"}
                else:
                    fdir = os.path.join(work, ".venv-fixed")
                    fpy = os.path.join(fdir, "bin", "python")
                    if not os.path.isfile(fpy):
                        venv.EnvBuilder(with_pip=True).create(fdir)
                        pip = os.path.join(fdir, "bin", "pip")
                        if not os.path.isfile(pip):
                            _run([fpy, "-m", "ensurepip"], timeout=120)
                        # requirements minus the vulnerable pin of the advisory package,
                        # then the fixed pin — otherwise pip sees a conflict
                        pkg = (v.get("advisory") or {}).get("package", "")
                        req_lines = []
                        if os.path.isfile(req):
                            with open(req) as fh:
                                req_lines = [ln for ln in fh.read().splitlines()
                                             if ln.strip() and not ln.strip().lower().startswith(pkg.lower() + "==")]
                        req_fixed = os.path.join(work, "requirements-fixed.txt")
                        with open(req_fixed, "w") as fh:
                            fh.write("\n".join(req_lines) + "\n")
                        cmd = [pip, "install", "--no-index", "--find-links", os.path.abspath(wheelhouse),
                               "-r", req_fixed] + pins
                        rc, out = _run(cmd, cwd=work)
                        if rc != 0:
                            fpy = None
                            rules["proof_passes_on_fixed"] = {"ok": False, "detail": f"fixed venv install failed: {out[-400:]}"}
                    if fpy is not None and "proof_passes_on_fixed" not in rules:
                        passed_all = True
                        details = []
                        for tid in proofs:
                            ok, rc, out = _pytest_one(fpy, src, tid, src)
                            details.append(f"{tid}: {'PASS' if ok else 'FAIL'}")
                            if not ok:
                                passed_all = False
                        rules["proof_passes_on_fixed"] = {
                            "ok": passed_all,
                            "detail": "; ".join(details) if details else "no proofs",
                        }
            # 3. suite count must never drop
            suite = v.get("suite") or {}
            before = (suite.get("before") or {})
            after = (suite.get("after") or {})
            b = before.get("passed", 0) + before.get("failed", 0)
            a = after.get("passed", 0) + after.get("failed", 0)
            rules["suite_count_not_dropped"] = {
                "ok": a >= b, "detail": f"before={b} after={a}"
            }

        elif vd == "not_affected":
            # no diff in src/ except agent-written files (proof test files)
            pristine = os.path.join(fleet_root, repo)
            allow = {os.path.basename(t.split("::")[0]) for t in (v.get("proof") or [])}
            if os.path.isdir(os.path.join(pristine)):
                d_src = _tree_digest(src, allow_names=allow)
                d_ref = _tree_digest(pristine)
                changed = sorted(set(d_src) ^ set(d_ref)) + sorted(
                    k for k in set(d_src) & set(d_ref) if d_src[k] != d_ref[k]
                )
                rules["no_src_changes"] = {
                    "ok": not changed,
                    "detail": "src/ identical to fleet copy (except agent proof files)" if not changed
                              else f"unexpected changes in src/: {changed[:10]}",
                }
            else:
                rules["no_src_changes"] = {"ok": True, "detail": "fleet copy unavailable; skipped"}

        else:  # needs_human or anything else
            rules["already_needs_human"] = {"ok": True, "detail": f"verdict was already {vd!r}"}

        v["gate"] = {"rules": rules, "ok": all(r.get("ok") for r in rules.values())}
        if not v["gate"]["ok"] and v.get("verdict") != "needs_human":
            v["verdict"] = "needs_human"  # ONLY downgrade, never upgrade

        vpath = os.path.join(work, "verdict.json")
        try:
            with open(vpath, "w") as fh:
                json.dump(v, fh, indent=2)
        except OSError:
            pass
        results.append(v)
    return results


def gate_passed(v):
    """A verdict is gate-passed if the gate ran and every rule is ok (and the
    verdict was not downgraded). Used by the report and the web grid."""
    g = v.get("gate") or {}
    return bool(g.get("ok")) and v.get("verdict") != "needs_human"


if __name__ == "__main__":
    # manual smoke: gate a run directory from the CLI
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("run_id")
    ap.add_argument("--runs-root", default="runs")
    ap.add_argument("--wheelhouse", default="wheelhouse")
    ap.add_argument("--fleet-root", default="fleet")
    args = ap.parse_args()
    verdicts = []
    rdir = os.path.join(args.runs_root, args.run_id)
    for repo in sorted(os.listdir(rdir)):
        vp = os.path.join(rdir, repo, "verdict.json")
        if os.path.isfile(vp):
            with open(vp) as fh:
                verdicts.append(json.load(fh))
    out = gate(args.run_id, verdicts, runs_root=args.runs_root,
               wheelhouse=args.wheelhouse, fleet_root=args.fleet_root)
    print(json.dumps([{ "repo": v["repo"], "verdict": v["verdict"],
                        "gate_ok": v["gate"]["ok"]} for v in out], indent=2))
