"""The kb-scan bridge: read-only access to the Rust scan engine's outputs.

kb-scan (tools/scan.py + tools/scan/) is the continuous polling swarm. It writes:

    tools/scan/out/latest.json        merged feed findings (all tiers)
    tools/scan/out/latest-sync.json   the git drift report (kb-scan-sync/1)
    runs/<run_id>/triage.json         the triage handoff for a Le Chonk run
    runs/<run_id>/sim-triage.json     the adversarial simulator's feedback (UNTRUSTED)

Everything read here is untrusted input: files are size-capped before parsing, a malformed
file is ignored (and logged through the run's event log when one is available), and every
string that leaves this module is sanitised for one-line, markup-free display. Nothing here
is ever executed or merged into agent-written verdicts; the only effect on a run is the
gate's downgrade rule (see gate.py), which may turn a verdict into "needs_human" and nothing else.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

from orchestrator import config

MAX_BYTES = 4 * 1024 * 1024  # feed/scan documents are small; anything bigger is refused


def scan_out_dir() -> Path:
    """KB_SCAN_OUT_DIR if set, else <repo>/tools/scan/out."""
    return config._path("KB_SCAN_OUT_DIR", "tools/scan/out")


def _read_capped(path: Path) -> dict | list | None:
    """Parse a JSON file only when it is within the size cap. Malformed or oversized -> None."""
    try:
        if path.stat().st_size > MAX_BYTES:
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, (dict, list)) else None


def _doc(path: Path) -> dict:
    data = _read_capped(path)
    return data if isinstance(data, dict) else {}


def latest() -> dict:
    """The engine's merged feed scan: tools/scan/out/latest.json ({schema, generated_at, findings[]})."""
    return _doc(scan_out_dir() / "latest.json")


def sync_latest() -> dict:
    """The engine's git drift report: tools/scan/out/latest-sync.json (kb-scan-sync/1)."""
    return _doc(scan_out_dir() / "latest-sync.json")


def triage_for_run(run_id: str, runs_root: str | Path | None = None) -> dict:
    """runs/<run_id>/triage.json: the engine's triage handoff for this run ({schema, run_id, tiers, ...})."""
    try:
        run_dir = config.run_dir(run_id, runs_root or config.runs_root())
    except ValueError:
        return {}
    return _doc(run_dir / "triage.json")


def sim_triage_for_run(run_id: str, runs_root: str | Path | None = None) -> dict:
    """runs/<run_id>/sim-triage.json: the adversarial simulator's feedback. Untrusted; capped; malformed -> {}."""
    try:
        run_dir = config.run_dir(run_id, runs_root or config.runs_root())
    except ValueError:
        return {}
    return _doc(run_dir / "sim-triage.json")


def triage_for_advisory(run_id: str, advisory_id: str = "", package: str = "", runs_root: str | Path | None = None) -> list[dict]:
    """The run's triage.json findings that name this advisory's CVE or package (any tier).

    Per-run triage lookup by advisory id; same matching rules as relevant_to_advisory().
    Feed data, not verdicts."""
    return relevant_to_advisory(triage_for_run(run_id, runs_root), advisory_id, package)


def _str_list(doc: dict, key: str, max_items: int) -> list[str]:
    raw = doc.get(key)
    if not isinstance(raw, list):
        return []
    return [text(item, 200) for item in raw[:max_items] if isinstance(item, (str, int, float))]


def drift_status(max_items: int = 20) -> dict:
    """A small, sanitised drift view of latest-sync.json for status lines and reports.

    {schema, generated_at, repo, remote, attention[], new_branches[], moved[], errors[], truncated}.
    Untrusted input: size-capped parse, every string one-line and markup-free."""
    doc = sync_latest()
    branches = doc.get("branches")
    moved = []
    if isinstance(branches, list):
        for branch in branches[:max_items]:
            if isinstance(branch, dict) and branch.get("moved"):
                moved.append(text(branch.get("name", "?"), 120))
    attention = _str_list(doc, "attention", max_items)
    new_branches = _str_list(doc, "new_branches", max_items)
    errors = _str_list(doc, "errors", max_items)
    return {
        "schema": text(doc.get("schema", ""), 40),
        "generated_at": text(doc.get("generated_at", ""), 40),
        "repo": text(doc.get("repo", ""), 160),
        "remote": text(doc.get("remote", ""), 40),
        "attention": attention,
        "new_branches": new_branches,
        "moved": moved,
        "errors": errors,
        "truncated": len(attention) == max_items or len(new_branches) == max_items or len(moved) == max_items,
    }


def findings(doc: dict) -> list[dict]:
    raw = doc.get("findings")
    return [f for f in raw if isinstance(f, dict)] if isinstance(raw, list) else []


def relevant_to_advisory(doc: dict, advisory_id: str = "", package: str = "") -> list[dict]:
    """Findings that name this advisory's CVE or package, any tier. Feed data, not verdicts."""
    wanted = {str(advisory_id).strip().upper(), str(package).strip().lower()}
    wanted.discard("")
    out = []
    for finding in findings(doc):
        haystack = " ".join(
            str(finding.get(key, "")) for key in ("cve", "id", "package", "packages", "title", "source")
        ).lower()
        cve = str(finding.get("cve", "")).upper()
        pkg = str(finding.get("package", "")).lower()
        if (cve and cve in wanted) or (pkg and pkg in wanted) or any(w in haystack for w in wanted):
            out.append(finding)
    return out


def text(value: object, limit: int = 160) -> str:
    """One line, no markup, capped — for anything that will be rendered or written into a report."""
    cleaned = re.sub(r"\s+", " ", str(value if value is not None else "")).strip()
    cleaned = cleaned.replace("<", "&lt;").replace(">", "&gt;").replace("`", "'").replace("|", "/")
    return cleaned if len(cleaned) <= limit else cleaned[: limit - 1] + "…"


def summary(doc: dict, *, max_items: int = 25) -> dict:
    """A small, sanitised view of a scan document for the web grid: counts by tier + item lines."""
    items = findings(doc)
    tiers: dict[str, int] = {}
    for finding in items:
        tier = str(finding.get("tier", "?"))
        tiers[tier] = tiers.get(tier, 0) + 1
    lines = [
        {
            "tier": text(finding.get("tier", "?"), 8),
            "cve": text(finding.get("cve", finding.get("id", "")), 40),
            "package": text(finding.get("package", ""), 80),
            "title": text(finding.get("title", finding.get("summary", "")), 140),
            "source": text(finding.get("source", ""), 60),
        }
        for finding in items[:max_items]
    ]
    return {
        "schema": text(doc.get("schema", ""), 40),
        "generated_at": text(doc.get("generated_at", ""), 40),
        "total": len(items),
        "tiers": tiers,
        "items": lines,
        "truncated": len(items) > max_items,
    }
