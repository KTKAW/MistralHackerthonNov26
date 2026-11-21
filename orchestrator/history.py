"""The cross-run history index: every run under runs/, aggregated into one queryable file.

Read-only. This module never writes inside a run folder; its only output is
runs/_index/history.json, written atomically (tmp + os.replace) and size-capped, so the web
page can fetch one JSON file and show the whole history of the fleet instead of walking
every run folder. TODO(web): expose it as GET /history serving runs/_index/history.json.

    rebuild(runs_root) -> dict     rebuild the index and write history.json; call after each run

Everything read here is untrusted input, exactly as in kbscan.py: files are parsed only
within the size cap (kbscan._read_capped), events.jsonl is read tail-capped and line by
line, malformed files are ignored, and every string that leaves this module goes through
kbscan.text — one line, no markup, capped. Worker text in events is never trusted.

The index holds three views over the same runs:

    runs        one entry per run: state, per-repo verdicts, sim-triage breaches, event count
    advisories  per advisory id: the runs that saw it, the verdict distribution, how often the
                gate downgraded a claim (including the sim-triage rule), breaches over time
    repos       per repository: its verdict history across runs
    timeline    the most recent events across all runs, sanitised
"""
from __future__ import annotations

import datetime as dt
import json
import os
from pathlib import Path
from typing import Any

from orchestrator import config, kbscan

SCHEMA = "le-chonk-history/1"
INDEX_DIR = "_index"
INDEX_FILE = "history.json"

MAX_INDEX_BYTES = 512 * 1024   # the written history.json never exceeds this
MAX_EVENTS_BYTES = 1024 * 1024  # how much of one events.jsonl is read (the tail)
MAX_TIMELINE = 400             # timeline entries kept, most recent first-class
MAX_RUNS = 200                 # runs indexed
MAX_PER_RUN_REPOS = 100
TEXT = 200


# ---------------------------------------------------------------- reading one run


def _read_events_tail(path: Path) -> list[dict]:
    """Parse events.jsonl within the byte cap, reading the tail when it is bigger. Bad lines are skipped."""
    try:
        size = path.stat().st_size
        if size <= MAX_EVENTS_BYTES:
            raw = path.read_text(encoding="utf-8", errors="replace")
        else:
            with path.open("rb") as handle:
                handle.seek(-MAX_EVENTS_BYTES, os.SEEK_END)
                raw = handle.read(MAX_EVENTS_BYTES).decode("utf-8", errors="replace").lstrip("\n")
                raw = raw.split("\n", 1)[1] if "\n" in raw else ""  # drop a half-written first line
    except OSError:
        return []
    found = []
    for line in raw.splitlines():
        try:
            record = json.loads(line)
        except ValueError:
            continue  # a line still being written
        if isinstance(record, dict):
            found.append(record)
    return found


def _verdict_view(verdict: dict) -> dict:
    """The parts of a gated verdict the history keeps. Untrusted: keys checked, strings sanitised."""
    gate = verdict.get("gate") if isinstance(verdict.get("gate"), dict) else {}
    advisory = verdict.get("advisory") if isinstance(verdict.get("advisory"), dict) else {}
    original = gate.get("original_verdict")
    final = verdict.get("verdict")
    return {
        "verdict": kbscan.text(final, 40),
        "original_verdict": kbscan.text(original, 40) if original is not None else "",
        "advisory_id": kbscan.text(advisory.get("id", ""), 60),
        "package": kbscan.text(advisory.get("package", ""), 80),
        "gate_passed": gate.get("passed") if isinstance(gate.get("passed"), bool) else None,
        "downgraded_by_gate": bool(original) and original != final,
        "sim_triage_downgrade": bool(gate.get("sim_triage")),
    }


def _sim_view(sim: dict) -> dict:
    """Breaches count and unreviewed gate-rule flags from sim-triage.json. Untrusted; capped; malformed -> empty."""
    defenses = sim.get("defenses") if isinstance(sim.get("defenses"), dict) else {}
    breaches = defenses.get("breaches")
    breach_count = len(breaches) if isinstance(breaches, list) else 0
    flagged: list[str] = []
    feedback = sim.get("feedback") if isinstance(sim.get("feedback"), dict) else {}
    entries = feedback.get("entries")
    if isinstance(entries, list):
        for entry in entries:
            if (
                isinstance(entry, dict)
                and entry.get("type") == "gate-rule"
                and isinstance(entry.get("advisory_id"), str)
                and not entry.get("human_reviewed")
            ):
                flagged.append(kbscan.text(entry["advisory_id"], 60))
    return {"breaches": breach_count, "flagged": sorted(set(flagged))}


def _index_run(run_dir: Path, run_id: str) -> dict:
    state = kbscan._read_capped(run_dir / "run.json")
    state = state if isinstance(state, dict) else {}
    advisory = state.get("advisory") if isinstance(state.get("advisory"), dict) else {}
    repos = state.get("repos") if isinstance(state.get("repos"), list) else []

    verdicts: dict[str, dict] = {}
    for child in sorted(run_dir.iterdir()) if run_dir.is_dir() else []:
        if not child.is_dir() or child.name.startswith(("_", ".")):
            continue
        try:
            repo = config.check_name(child.name, "repository name")
        except ValueError:
            continue
        if len(verdicts) >= MAX_PER_RUN_REPOS:
            break
        verdict = kbscan._read_capped(child / "verdict.json")
        if isinstance(verdict, dict):
            verdicts[repo] = _verdict_view(verdict)

    events = _read_events_tail(run_dir / "events.jsonl")
    sim = _sim_view(kbscan.sim_triage_for_run(run_id, run_dir.parent))

    return {
        "run_id": kbscan.text(run_id, 80),
        "started_at": kbscan.text(state.get("started_at", ""), 40),
        "deadline": kbscan.text(state.get("deadline", ""), 40),
        "stage": kbscan.text(state.get("stage", ""), 40),
        "advisory_id": kbscan.text(advisory.get("id", ""), 60),
        "package": kbscan.text(advisory.get("package", ""), 80),
        "repos": [kbscan.text(name, 120) for name in repos if isinstance(name, str)][:MAX_PER_RUN_REPOS],
        "approved_by": kbscan.text(state.get("approved_by", ""), 80),
        "error": kbscan.text(state.get("error", ""), TEXT) if state.get("error") else "",
        "verdicts": verdicts,
        "sim_breaches": sim["breaches"],
        "sim_flagged": sim["flagged"],
        "events": len(events),
        "_events": events,  # consumed by the timeline, never written out as-is
    }


# ---------------------------------------------------------------- aggregation


def rebuild(runs_root: str | Path | None = None) -> dict:
    """Rebuild the whole index from runs_root and write runs/_index/history.json. Returns the index."""
    root = Path(runs_root) if runs_root is not None else config.runs_root()
    if not root.is_absolute():
        root = config.REPO_ROOT / root

    runs: dict[str, dict] = {}
    timeline: list[dict] = []
    for child in sorted(root.iterdir()) if root.is_dir() else []:
        if not child.is_dir() or child.name.startswith(("_", ".")):
            continue
        try:
            run_id = config.check_name(child.name, "run id")
        except ValueError:
            continue
        runs[run_id] = _index_run(child, run_id)

    # Newest first, capped: a huge backlog must not grow the index without bound.
    ordered = sorted(runs.values(), key=lambda r: (r["started_at"], r["run_id"]), reverse=True)[:MAX_RUNS]
    runs = {r["run_id"]: r for r in ordered}

    for run in runs.values():
        for event in run.pop("_events"):
            timeline.append({
                "t": kbscan.text(event.get("t", ""), 40),
                "run": run["run_id"],
                "source": kbscan.text(event.get("source", ""), 20),
                "kind": kbscan.text(event.get("kind", ""), 20),
                "repo": kbscan.text(event.get("repo", ""), 120) if event.get("repo") else "",
                "text": kbscan.text(event.get("text", ""), TEXT),
            })
    timeline.sort(key=lambda e: (e["t"], e["run"]))
    timeline = timeline[-MAX_TIMELINE:]

    advisories: dict[str, dict] = {}
    repos: dict[str, list] = {}

    def advisory_entry(advisory_id: str) -> dict:
        if advisory_id not in advisories:
            advisories[advisory_id] = {
                "runs": [], "verdicts": {}, "gate_downgrades": 0, "sim_downgrades": 0, "breaches_over_time": [],
            }
        return advisories[advisory_id]

    for run in runs.values():
        if run["advisory_id"]:
            advisory_entry(run["advisory_id"])["runs"].append(run["run_id"])
        if run["sim_breaches"]:
            for advisory_id in (run["sim_flagged"] or [run["advisory_id"] or "?"]):
                advisory_entry(advisory_id)["breaches_over_time"].append(
                    {"run": run["run_id"], "t": run["started_at"], "breaches": run["sim_breaches"]}
                )
        for repo, view in run["verdicts"].items():
            advisory_id = view["advisory_id"] or run["advisory_id"]
            if advisory_id:
                entry = advisory_entry(advisory_id)
                entry["verdicts"][view["verdict"]] = entry["verdicts"].get(view["verdict"], 0) + 1
                if view["downgraded_by_gate"]:
                    entry["gate_downgrades"] += 1
                if view["sim_triage_downgrade"]:
                    entry["sim_downgrades"] += 1
            repos.setdefault(repo, []).append({
                "run": run["run_id"], "t": run["started_at"],
                "advisory_id": kbscan.text(advisory_id, 60), "verdict": view["verdict"],
            })

    for entry in advisories.values():
        entry["runs"] = sorted(set(entry["runs"]))
        entry["breaches_over_time"].sort(key=lambda b: (b["t"], b["run"]))
    for history in repos.values():
        history.sort(key=lambda h: (h["t"], h["run"]))

    index: dict[str, Any] = {
        "schema": SCHEMA,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "runs_root": kbscan.text(str(root), 200),
        "truncated": False,
        "caps": {"max_index_bytes": MAX_INDEX_BYTES, "max_runs": MAX_RUNS, "max_timeline": MAX_TIMELINE},
        "runs": runs,
        "advisories": dict(sorted(advisories.items())),
        "repos": dict(sorted(repos.items())),
        "timeline": timeline,
    }
    _fit_to_cap(index)
    _write(root / INDEX_DIR / INDEX_FILE, index)
    return index


def _serialise(index: dict) -> str:
    return json.dumps(index, ensure_ascii=False, default=str) + "\n"


def _fit_to_cap(index: dict) -> None:
    """Shrink the timeline, then the run list, until the serialised index fits the byte cap."""
    while len(_serialise(index).encode("utf-8")) > MAX_INDEX_BYTES and index["timeline"]:
        keep = max(1, len(index["timeline"]) // 2)
        if keep >= len(index["timeline"]):
            index["truncated"] = True
            index["timeline"] = index["timeline"][-1:]
            break
        index["truncated"] = True
        index["timeline"] = index["timeline"][-keep:]
    while len(_serialise(index).encode("utf-8")) > MAX_INDEX_BYTES and len(index["runs"]) > 1:
        index["truncated"] = True
        index["runs"].pop(next(reversed(index["runs"])))  # oldest last, runs are newest-first
    if index["truncated"]:
        index["caps"]["timeline_kept"] = len(index["timeline"])
        index["caps"]["runs_kept"] = len(index["runs"])


def _write(path: Path, index: dict) -> None:
    """Write history.json atomically: tmp file in the same folder, then os.replace."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + f".{os.getpid()}.tmp")
    temporary.write_text(_serialise(index), encoding="utf-8")
    os.replace(temporary, path)


def main() -> int:
    """CLI entry for a watcher or a cron: rebuild once, print where the index went. Not a daemon."""
    index = rebuild(config.runs_root())
    print(f"{config.runs_root() / INDEX_DIR / INDEX_FILE}: {len(index['runs'])} runs, "
          f"{len(index['advisories'])} advisories, {len(index['timeline'])} timeline events")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
