"""The report step. No model call: a template filled from verdicts that passed the gate.

It writes runs/<run_id>/early-warning.md, a DRAFT of the early warning under Article 14(2)(a)
of Regulation (EU) 2024/2847 (the Cyber Resilience Act). The tool never sends it anywhere. A
person reviews it and submits it through the CRA Single Reporting Platform.

What the three submissions must contain was read from the regulation's text on 21 November 2026:
    (a) early warning, within 24 hours of becoming aware: where applicable, the Member States in
        which the product is known to have been made available
    (b) notification, within 72 hours: general information about the product, the general nature
        of the exploit and of the vulnerability, corrective or mitigating measures taken, measures
        users can take, and how sensitive the manufacturer considers the information
    (c) final report, no later than 14 days after a corrective or mitigating measure is available
This is a drafting aid for engineers, not legal advice.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import re
from pathlib import Path

from orchestrator import config, kbscan

TITLES = {
    "affected_fixed": "Affected, proven and fixed",
    "affected_proven": "Affected and proven, no passing fix yet",
}
TO_COMPLETE = "**TO BE COMPLETED BY A PERSON**"


def render_early_warning(run_id: str, gated_verdicts: list, *, runs_root: str | Path = "runs") -> str:
    """Write runs/<run_id>/early-warning.md from gate-passed verdicts only and return its text."""
    run_dir = config.run_dir(run_id, runs_root)
    meta = _read_json(run_dir / "run.json")
    advisory = _read_json(run_dir / "advisory.json")
    now = dt.datetime.now(dt.timezone.utc)
    started = _parse_time(meta.get("started_at")) or now

    checked = [v for v in gated_verdicts if isinstance(v, dict) and (v.get("gate") or {}).get("passed") is True]
    affected = [v for v in checked if v.get("verdict") in TITLES]
    not_affected = [v for v in checked if v.get("verdict") == "not_affected"]
    undetermined = [v for v in gated_verdicts if isinstance(v, dict) and v not in affected and v not in not_affected]
    if not advisory and gated_verdicts:
        advisory = (gated_verdicts[0] or {}).get("advisory", {})

    used = max(0, int((now - started).total_seconds() // 60))
    lines = [
        f"# DRAFT early warning: {_text(advisory.get('id', 'advisory not read'))} in {_text(advisory.get('package', 'unknown package'))}",
        "",
        "> **Draft. Not submitted.** A tool produced this from verdicts that its gate re-checked.",
        "> A person must review it and submit it through the CRA Single Reporting Platform.",
        "> This tool never sends anything.",
        "",
        "## Clock",
        "",
        "| | |",
        "|---|---|",
        f"| Became aware (run started) | {_stamp(started)} |",
        f"| Early warning due, 24 hours | {_stamp(started + dt.timedelta(hours=24))} |",
        f"| Time used when this draft was written | {used} min of 1440 |",
        f"| Vulnerability notification due, 72 hours | {_stamp(started + dt.timedelta(hours=72))} |",
        "| Final report | no later than 14 days after a corrective or mitigating measure is available |",
        "",
        "## Early warning, Article 14(2)(a)",
        "",
        f"- **Vulnerability:** {_text(advisory.get('id', '?'))} in `{_code(advisory.get('package', '?'))}`, affected versions `{_code(advisory.get('affected_range', '?'))}`, flawed function `{_code(advisory.get('flawed_function', '?'))}`.",
        f"- **Products found affected, each with a proof that was re-run:** {', '.join('`' + _code(v['repo']) + '`' for v in affected) or 'none'}.",
        f"- **Member States in which these products have been made available:** {TO_COMPLETE}.",
        f"- **Basis for treating the vulnerability as actively exploited:** {TO_COMPLETE}. The tool establishes whether your code can be reached, not whether anyone is exploiting the flaw.",
        "",
        "## Evidence for each affected product",
        "",
    ]
    if not affected:
        lines += ["No product has a verdict of affected that passed the gate.", ""]
    for verdict in affected:
        gate = verdict["gate"]
        fix = verdict.get("fix") or {}
        lines += [
            f"### `{_code(verdict['repo'])}`: {TITLES[verdict['verdict']]}",
            "",
            f"- **Why:** {_text(verdict.get('reason', ''), 700)}",
            "- **Path from the entry point to the flawed function:**",
            *[f"  - `{_code(step.get('file'))}:{_text(step.get('line'))}` {_text(step.get('note'), 200)}" for step in verdict.get("path", [])],
            "- **Proof tests** (the gate re-ran them: each failed on the vulnerable state" + (" and passed on the fixed state" if verdict["verdict"] == "affected_fixed" else "") + "):",
            *[f"  - `{_code(test_id)}`" for test_id in verdict.get("proof", [])],
            f"- **Fix:** {_fix(fix)}",
            *_pull_request_line(verdict),
            f"- **Gate:** checked at {_text(gate.get('checked_at'))}; tests run inside the sandbox: {'yes' if gate.get('sandboxed') else 'NO'}.",
            "",
        ]

    lines += ["## No reachable path found", ""]
    if not not_affected:
        lines += ["None.", ""]
    for verdict in not_affected:
        trail = "; ".join(f"`{_code(s.get('file'))}:{_text(s.get('line'))}` {_text(s.get('note'), 160)}" for s in verdict.get("path", []))
        lines += [f"- `{_code(verdict['repo'])}`: no reachable path found. Path followed: {trail or 'not cited'}. The work copy was left unchanged."]
    lines += ["", "## Not determined: a person must look", ""]
    if not undetermined:
        lines += ["None.", ""]
    for verdict in undetermined:
        gate = verdict.get("gate") or {}
        failed = [name for name, rule in (gate.get("rules") or {}).items() if rule.get("enforced") and rule.get("passed") is not True]
        claim = gate.get("original_verdict")
        repo = f"`{_code(verdict.get('repo', '?'))}`"
        if failed:
            # A claim the gate rejected is not a result, so none of it is repeated.
            lines += [f"- {repo}: the gate rejected a claim of `{_code(claim)}` on: {', '.join(failed)}. Nothing it claimed is repeated here."]
        elif verdict.get("reason"):
            # The worker itself asked for a person, or never finished. Its reason is what the person needs.
            trail = "; ".join(f"`{_code(s.get('file'))}:{_text(s.get('line'))}` {_text(s.get('note'), 160)}" for s in verdict.get("path", []))
            lines += [f"- {repo}: no verdict for the gate to check. The reason given, which the gate did not verify: "
                      f"{_text(verdict['reason'], 400)}" + (f" Path followed: {trail}." if trail else "")]
        else:
            lines += [f"- {repo}: no verdict and no reason given."]

    measures = sorted({_fix(v.get("fix") or {}) for v in affected if v.get("verdict") == "affected_fixed"})
    lines += _feed_watch_section(run_id, advisory, runs_root)
    lines += [
        "",
        "## Notes for the 72-hour notification, Article 14(2)(b)",
        "",
        f"- **General nature of the vulnerability:** see `{_code(advisory.get('flawed_function', '?'))}` in the advisory {_text(advisory.get('id', '?'))}.",
        f"- **Corrective or mitigating measures taken:** {'; '.join(measures) or 'none yet'}. Each fix is a draft for review, not a release.",
        f"- **Measures users can take:** {TO_COMPLETE}.",
        f"- **How sensitive you consider this information:** {TO_COMPLETE}.",
        "",
        "## Before you submit",
        "",
        "- [ ] Check every affected product above against its proof and its fix diff.",
        "- [ ] Decide what to do about each product listed as not determined.",
        "- [ ] Confirm the basis for active exploitation, and the Member States.",
        "- [ ] Check Article 14 of Regulation (EU) 2024/2847 itself, and take legal advice, before filing.",
        "- [ ] Submit through the CRA Single Reporting Platform. It reaches the coordinating CSIRT and ENISA.",
        "- [ ] Tell the affected users in a timely manner, as Article 14(8) requires.",
        "",
        f"_Drafted at {_stamp(now)} for run `{_code(run_id)}`. {len(affected)} affected, {len(not_affected)} with no reachable path found, {len(undetermined)} not determined._",
        "",
    ]
    text = "\n".join(lines)
    run_dir.mkdir(parents=True, exist_ok=True)
    temporary = run_dir / "early-warning.md.tmp"
    temporary.write_text(text, encoding="utf-8")
    os.replace(temporary, run_dir / "early-warning.md")
    return text


def _feed_watch_section(run_id: str, advisory: dict, runs_root: str | Path) -> list[str]:
    """The kb-scan feed watch: what the continuous Rust poller saw that names this advisory.

    Feed data, not verdicts: the engine polls CISA KEV, OSV, GitHub and FIRST EPSS and matches
    them against this codebase's inventory. Nothing here was re-run by the gate; a person weighs it.
    """
    advisory_id = str(advisory.get("id", "")) if isinstance(advisory, dict) else ""
    package = str(advisory.get("package", "")) if isinstance(advisory, dict) else ""
    hits = kbscan.relevant_to_advisory(kbscan.latest(), advisory_id, package)
    triage = kbscan.triage_for_run(run_id, runs_root)
    if triage:
        hits += [f for f in kbscan.relevant_to_advisory(triage, advisory_id, package) if f not in hits]
    if not hits:
        return []
    lines = [
        "",
        "## Feed watch (kb-scan, continuous poller)",
        "",
        "> Feed matches from the Rust polling engine (KEV/OSV/GitHub/EPSS vs this repo's inventory).",
        "> Unverified feed data: the gate did not re-run any of it. Weigh it, do not rely on it.",
        "",
    ]
    for finding in hits[:10]:
        lines.append(
            f"- tier {kbscan.text(finding.get('tier', '?'), 8)} — "
            f"`{_code(finding.get('cve', finding.get('id', '?')))}` "
            f"{_code(finding.get('package', ''))} {_text(finding.get('title', finding.get('summary', '')), 140)} "
            f"(source: {_text(finding.get('source', ''), 60)})"
        )
    if len(hits) > 10:
        lines.append(f"- … and {len(hits) - 10} more in `tools/scan/out/latest.json`.")
    lines.append("")
    return lines


def _pull_request_line(verdict: dict) -> list[str]:
    """Where the fix was proposed. Only an address of a pull request on GitHub is printed as one."""
    left = verdict.get("pull_request")
    if not isinstance(left, dict):
        return []
    if re.fullmatch(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/pull/\d+", str(left.get("url", ""))):
        return [f"- **Draft pull request with this fix:** {left['url']}. It is not merged."]
    if left.get("refused"):
        return [f"- **Pull request:** not opened. {_text(left['refused'], 200)}"]
    return ["- **Pull request:** opening it failed. See the run's activity log."]


def _fix(fix: dict) -> str:
    if fix.get("kind") == "upgrade":
        return f"upgrade to {_text(fix.get('target', '?'))}"
    if fix.get("kind") == "patch":
        return f"patch, diff file `{_code(fix.get('diff_file') or 'not named')}`"
    return "none yet"


def _text(value: object, limit: int = 120) -> str:
    """Agent-written text is untrusted. Keep it on one line, without markup, and short."""
    text = re.sub(r"\s+", " ", str(value if value is not None else "")).strip()
    text = text.replace("<", "&lt;").replace(">", "&gt;").replace("`", "'").replace("|", "/")
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _code(value: object, limit: int = 160) -> str:
    """For inside `backticks`: one line, and nothing that could close the code span."""
    text = re.sub(r"\s+", " ", str(value if value is not None else "")).strip().replace("`", "'")
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _stamp(moment: dt.datetime) -> str:
    return moment.astimezone(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _parse_time(value: object) -> dt.datetime | None:
    try:
        moment = dt.datetime.fromisoformat(str(value))
    except ValueError:
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=dt.timezone.utc)


def _read_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}
