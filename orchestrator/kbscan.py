"""The kb-scan bridge: read-only access to the Rust scan engine's outputs.

kb-scan (tools/scan.py + tools/scan/) is the continuous polling swarm. It writes:

    tools/scan/out/latest.json        merged feed findings (all tiers)
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
