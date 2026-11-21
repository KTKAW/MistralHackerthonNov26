"""A run's event log: what happened, in order, as it happens.

runs/<run_id>/events.jsonl holds one JSON object per line and is only ever appended to. The web
page streams it, so a person can watch a run and see what each step did.

There are three writers, named in each event's "source":

    orchestrator   the steps of the run (steps.py)
    gate           the gate's own re-runs (gate.py)
    worker         what the per-repository worker reported through the heartbeat function

What a worker reports is untrusted text. It is stored as text, cut short, and shown as text.

Writing an event never fails a run: any error here is swallowed.
"""
from __future__ import annotations

import datetime as dt
import json
import os
from pathlib import Path
from typing import Any

from orchestrator import config

FILE = "events.jsonl"
MAX_TEXT = 400
SOURCES = ("orchestrator", "gate", "worker")
KINDS = ("start", "step", "ok", "fail", "done", "info")


def emit(run_id: str, source: str, text: object, *, repo: str | None = None, kind: str = "step",
         runs_root: str | Path | None = None, **data: Any) -> None:
    """Append one event to the run's log."""
    try:
        append(config.run_dir(run_id, runs_root), source, text, repo=repo, kind=kind, **data)
    except Exception:
        pass


def append(run_dir: Path, source: str, text: object, *, repo: str | None = None, kind: str = "step", **data: Any) -> None:
    try:
        record: dict[str, Any] = {
            "t": dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds"),
            "source": source if source in SOURCES else "orchestrator",
            "kind": kind if kind in KINDS else "step",
            "repo": repo,
            "text": " ".join(str(text).split())[:MAX_TEXT],
        }
        if data:
            record["data"] = data
        line = json.dumps(record, ensure_ascii=False, default=str) + "\n"
        run_dir.mkdir(parents=True, exist_ok=True)
        # One short write to a file opened for appending lands whole, even with several writers.
        descriptor = os.open(run_dir / FILE, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
        try:
            os.write(descriptor, line.encode("utf-8"))
        finally:
            os.close(descriptor)
    except Exception:
        pass


def read(run_id: str, after: int = 0, *, runs_root: str | Path | None = None) -> list[dict]:
    """The events after the first `after`. Each carries its number "n", counted from 1."""
    try:
        lines = (config.run_dir(run_id, runs_root) / FILE).read_text(encoding="utf-8").splitlines()
    except (OSError, ValueError):
        return []
    found = []
    for number, line in enumerate(lines, start=1):
        if number <= after:
            continue
        try:
            record = json.loads(line)
        except ValueError:
            continue  # a line still being written
        if isinstance(record, dict):
            record["n"] = number
            found.append(record)
    return found
