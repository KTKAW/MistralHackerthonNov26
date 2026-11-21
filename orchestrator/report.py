"""report.py — early-warning draft. Track C (build/track-c-orchestration-ui).

Makes NO model call. Fills runs/<run_id>/early-warning.md from GATE-PASSED
verdicts only (see gate.gate_passed). A human — never the tool — submits
anything to ENISA's Single Reporting Platform (CRA Art. 16).

CRA fields: Regulation (EU) 2024/2847, Art. 14(2)(a) — the early warning
(within 24 h of becoming aware of an actively exploited vulnerability)
indicates, where applicable, the Member States on whose territory the product
has been made available. Art. 14(2)(b) — the 72 h vulnerability notification
adds general information about the product, the nature of the exploit and of
the vulnerability, and corrective/mitigating measures taken and available to
users. Text checked against EUR-Lex consolidated 02024R2847-20241120.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone

RUN_CLOCK_HOURS = 24


def _load_json(path):
    try:
        with open(path) as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None


def _parse_iso(s):
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def render_early_warning(run_id, gated_verdicts, *, runs_root="runs"):
    """Write runs/<run_id>/early-warning.md from gate-passed verdicts only.
    Returns the markdown string."""
    run_dir = os.path.join(runs_root, run_id)
    os.makedirs(run_dir, exist_ok=True)
    run_meta = _load_json(os.path.join(run_dir, "run.json")) or {}
    advisory = _load_json(os.path.join(run_dir, "advisory.json")) or {}

    started = _parse_iso(run_meta.get("started_at")) or datetime.now(timezone.utc)
    now = datetime.now(timezone.utc)
    minutes_used = int((now - started).total_seconds() // 60)
    minutes_left = max(0, RUN_CLOCK_HOURS * 60 - minutes_used)

    passed = [v for v in gated_verdicts if _gate_ok(v)]
    affected = [v for v in passed if v.get("verdict") in ("affected_proven", "affected_fixed")]
    not_affected = [v for v in passed if v.get("verdict") == "not_affected"]
    needs_human = [v for v in gated_verdicts if v.get("verdict") == "needs_human"]

    adv_id = advisory.get("id", "unknown advisory")
    pkg = advisory.get("package", "unknown package")
    rng = advisory.get("affected_range", "unknown range")
    fn = advisory.get("flawed_function", "unknown function")
    member_states = run_meta.get("member_states") or "not specified (indicate where applicable per Art. 14(2)(a))"

    lines = []
    a = lines.append
    a(f"# Early warning — DRAFT for human review (CRA Art. 14(2)(a))")
    a("")
    a(f"- Run: `{run_id}` · started: {started.isoformat()} · "
      f"**{minutes_used} min used of the 24 h clock ({minutes_left} min left)**")
    a(f"- Advisory / vulnerability: **{adv_id}** — `{pkg}` {rng}, flawed function `{fn}`")
    a(f"- Member States where the product has been made available (Art. 14(2)(a)): {member_states}")
    a("")
    a("> This draft is produced from gate-passed verdicts only. The tool never sends "
      "anything to ENISA; a human submits via the Single Reporting Platform (Art. 16).")
    a("")
    a("## Affected products (evidence attached)")
    a("")
    if not affected:
        a("- None among the gate-passed repositories.")
    for v in affected:
        fix = v.get("fix") or {}
        fix_txt = (f"{fix.get('kind')} → {fix.get('target')}" if fix.get("kind") == "upgrade"
                   else f"patch ({fix.get('diff_file')})" if fix.get("kind") == "patch"
                   else "no fix applied")
        a(f"### {v.get('repo')} — {v.get('verdict')}")
        a(f"- Reason: {v.get('reason', '')}")
        a(f"- Proof tests (re-run by the gate: FAIL on vulnerable, PASS on fixed): "
          f"{', '.join(v.get('proof') or [])}")
        a(f"- Fix status: {fix_txt}")
        path = v.get("path") or []
        if path:
            a("- Evidence path:")
            for p in path:
                a(f"  - `{p.get('file')}:{p.get('line')}` — {p.get('note')}")
        a("")
    a("## Not affected (gate-passed)")
    a("")
    if not not_affected:
        a("- None.")
    for v in not_affected:
        a(f"- **{v.get('repo')}**: {v.get('reason', '')} "
          f"(worded \"no reachable path found\", never \"safe\")")
    a("")
    if needs_human:
        a("## Needs a human (excluded from the warning above)")
        a("")
        for v in needs_human:
            a(f"- **{v.get('repo')}**: {v.get('reason', '')}")
        a("")
    a("## Timeline")
    a("")
    a(f"- 24 h early-warning clock started at {started.isoformat()}.")
    a(f"- {minutes_used} min used at draft time; {minutes_left} min remain.")
    a(f"- Next statutory steps: vulnerability notification within 72 h (Art. 14(2)(b)); "
      f"final report within 14 days of a corrective measure (Art. 14(2)(c)).")
    a("")

    text = "\n".join(lines)
    out = os.path.join(run_dir, "early-warning.md")
    with open(out, "w") as fh:
        fh.write(text)
    return text


def _gate_ok(v):
    g = v.get("gate") or {}
    return bool(g.get("ok")) and v.get("verdict") != "needs_human"


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("run_id")
    ap.add_argument("--runs-root", default="runs")
    args = ap.parse_args()
    rdir = os.path.join(args.runs_root, args.run_id)
    verdicts = []
    for repo in sorted(os.listdir(rdir)):
        vp = os.path.join(rdir, repo, "verdict.json")
        if os.path.isfile(vp):
            verdicts.append(_load_json(vp))
    print(render_early_warning(args.run_id, verdicts, runs_root=args.runs_root))
