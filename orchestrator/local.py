"""The fallback: the same run in plain Python, with no Mistral Workflows.

Mistral Workflows is in public preview. If it misbehaves on the day, this runs the same steps
with the same contracts, in threads inside one process. What it does not give you is what
Workflows is for: a run here does not survive the process, and nothing records its history.

    from orchestrator.local import LOCAL
    run = LOCAL.start(advisory_text)          # returns at once; the run goes on in a thread
    LOCAL.approve(run["run_id"], "name")      # the person's approval
"""
from __future__ import annotations

import datetime as dt
import secrets
import threading
from concurrent.futures import ThreadPoolExecutor

from orchestrator import config, steps


def new_run_id() -> str:
    return "run-" + dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(3)


class LocalOrchestrator:
    def __init__(self, max_parallel: int | None = None) -> None:
        self.max_parallel = max_parallel  # None: the run's own cap, 10 unless LE_CHONK_MAX_PARALLEL says otherwise
        self._approvals: dict[str, threading.Event] = {}
        self._approved_by: dict[str, str] = {}
        self._threads: dict[str, threading.Thread] = {}

    def start(self, advisory_text: str, run_id: str | None = None) -> dict:
        run_id = config.check_name(run_id or new_run_id(), "run id")
        started_at = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
        meta = steps.intake(run_id, advisory_text, started_at)
        self._approvals[run_id] = threading.Event()
        cap = self.max_parallel or int(meta.get("max_parallel") or config.max_parallel())
        thread = threading.Thread(target=self._run, args=(run_id, advisory_text, meta["repos"], bool(meta.get("pull_requests")), cap), name=run_id, daemon=True)
        self._threads[run_id] = thread
        thread.start()
        return {"run_id": run_id, "started_at": meta["started_at"]}

    def approve(self, run_id: str, approved_by: str = "") -> bool:
        event = self._approvals.get(run_id)
        if event is None:
            return False
        self._approved_by[run_id] = approved_by
        event.set()
        return True

    def status(self, run_id: str) -> str:
        thread = self._threads.get(run_id)
        if thread is None:
            return "UNKNOWN"
        if thread.is_alive():
            return "RUNNING"
        return "FAILED" if steps.read_state(run_id).get("stage") == "failed" else "COMPLETED"

    def wait(self, run_id: str, timeout: float | None = None) -> None:
        thread = self._threads.get(run_id)
        if thread is not None:
            thread.join(timeout)

    def _one_repo(self, run_id: str, repo: str, pull_requests: bool = False) -> dict:
        gated = steps.verify_repo(run_id, steps.triage_repo(run_id, repo))
        if pull_requests and steps.wants_pull_request(gated):
            gated = steps.open_pull_request(run_id, gated)
        return gated

    def _run(self, run_id: str, advisory_text: str, repos: list[str], pull_requests: bool = False, cap: int = 10) -> None:
        try:
            steps.read_advisory(run_id, advisory_text)
            with ThreadPoolExecutor(max_workers=max(1, min(cap, len(repos) or 1))) as pool:
                gated = list(pool.map(lambda repo: self._one_repo(run_id, repo, pull_requests), repos))
            steps.write_report(run_id, gated)
            approved = self._approvals[run_id].wait(timeout=config.APPROVAL_HOURS * 3600)
            steps.close_run(run_id, "approved" if approved else "expired", self._approved_by.get(run_id))
        except Exception as error:
            steps.update_state(run_id, stage="failed", error=f"{type(error).__name__}: {error}"[:500])


LOCAL = LocalOrchestrator()
