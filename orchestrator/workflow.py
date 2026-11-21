"""le_chonk_run: one run, as one Mistral Workflows workflow.

    intake (the 24-hour clock starts)
    -> read advisory (exactly one model call)
    -> for every repository at once: triage (one agent, one attempt) then the gate
    -> report (a draft, from gated verdicts only)
    -> wait for a person's "approve" signal, for at most 24 hours

Mistral hosts the coordinator and keeps the run's history. This process is the worker: it
connects out to Mistral and runs every activity on this machine. Start it with:

    MISTRAL_API_KEY=... DEPLOYMENT_NAME=... OTEL_ENABLED=false uv run python -m orchestrator.workflow

The workflow class holds no I/O. Everything that touches files, the network or a clock is an
activity that calls a plain function in steps.py, so the plain-Python fallback in local.py runs
the very same steps. The run id is the workflow's execution id, and is also the folder name
under runs/.

Written against mistralai-workflows 3.20.0.
"""
import asyncio
import contextvars
import os
import sys
from datetime import timedelta

import mistralai.workflows as workflows
from mistralai.workflows import workflow

# The workflow sandbox re-imports this file for every run. These two modules do real I/O, so they
# are passed through from the host instead. Each must be named in full: `from orchestrator import
# config` would pass the package through and still re-import the submodule inside the sandbox.
with workflow.unsafe.imports_passed_through():
    import orchestrator.config as config
    import orchestrator.steps as steps

HEARTBEAT_SECONDS = 10
QUICK = timedelta(seconds=120)
LONG = timedelta(seconds=900)
BEAT = timedelta(seconds=60)


# ---------------------------------------------------------------- activities


def _beat_once(*details: object) -> None:
    try:
        workflows.activity_heartbeat(*details)
    except Exception:  # not inside an activity (a unit test), or the activity is over
        pass


async def _in_thread(function, *args, pass_heartbeat: bool = False):
    """Run a blocking step in a thread, so other activities keep starting, and heartbeat meanwhile.

    The heartbeat must be sent from this activity's own context. A ticker here sends one every
    10 seconds whatever the step does. A step that wants to heartbeat itself (the worker contract
    takes a `heartbeat_fn`) gets a function that is safe to call from its own thread.
    """
    loop = asyncio.get_running_loop()
    context = contextvars.copy_context()

    def heartbeat_fn(*details: object) -> None:
        loop.call_soon_threadsafe(_beat_once, *details, context=context)

    async def tick() -> None:
        while True:
            await asyncio.sleep(HEARTBEAT_SECONDS)
            _beat_once()

    ticker = asyncio.create_task(tick())
    try:
        extra = (heartbeat_fn,) if pass_heartbeat else ()
        return await asyncio.to_thread(function, *args, *extra)
    finally:
        ticker.cancel()


@workflows.activity(name="le_chonk_intake", start_to_close_timeout=QUICK, retry_policy_max_attempts=3)
async def intake(run_id: str, advisory_text: str, started_at: str) -> dict:
    return await asyncio.to_thread(steps.intake, run_id, advisory_text, started_at)


@workflows.activity(name="le_chonk_read_advisory", start_to_close_timeout=timedelta(seconds=180), retry_policy_max_attempts=1)
async def read_advisory(run_id: str, advisory_text: str) -> dict:
    """Exactly one model call per run, so exactly one attempt."""
    return await asyncio.to_thread(steps.read_advisory, run_id, advisory_text)


@workflows.activity(name="le_chonk_triage_repo", start_to_close_timeout=LONG, heartbeat_timeout=BEAT, retry_policy_max_attempts=1)
async def triage_repo(run_id: str, repo: str) -> dict:
    """One agent on a fresh work copy. One attempt: a retry would run on a half-changed copy."""
    return await _in_thread(steps.triage_repo, run_id, repo, pass_heartbeat=True)


@workflows.activity(name="le_chonk_verify_repo", start_to_close_timeout=LONG, heartbeat_timeout=BEAT, retry_policy_max_attempts=2)
async def verify_repo(run_id: str, result: dict) -> dict:
    """The gate. It rebuilds its own clean copies each time, so a second attempt is safe."""
    return await _in_thread(steps.verify_repo, run_id, result)


@workflows.activity(name="le_chonk_open_pull_request", start_to_close_timeout=timedelta(seconds=300), retry_policy_max_attempts=2)
async def open_pull_request(run_id: str, gated: dict) -> dict:
    """Propose a verified fix as a draft pull request. Calling it twice returns the same pull request."""
    return await asyncio.to_thread(steps.open_pull_request, run_id, gated)


@workflows.activity(name="le_chonk_write_report", start_to_close_timeout=QUICK, retry_policy_max_attempts=3)
async def write_report(run_id: str, gated: list) -> dict:
    return await asyncio.to_thread(steps.write_report, run_id, gated)


@workflows.activity(name="le_chonk_close_run", start_to_close_timeout=QUICK, retry_policy_max_attempts=3)
async def close_run(run_id: str, outcome: str, approved_by: str) -> dict:
    return await asyncio.to_thread(steps.close_run, run_id, outcome, approved_by)


ACTIVITIES = [intake, read_advisory, triage_repo, verify_repo, open_pull_request, write_report, close_run]


# ---------------------------------------------------------------- the workflow


@workflow.define(
    name=config.WORKFLOW_NAME,
    workflow_display_name="Le Chonk: 24-hour vulnerability response",
    workflow_description="One advisory in. One agent per repository, a gate with no model, and a draft early warning that waits for a person.",
    execution_timeout=timedelta(hours=config.APPROVAL_HOURS + 2),
)
class LeChonkRun:
    def __init__(self) -> None:
        self._stage = "intake"
        self._approved = False
        self._approved_by = ""
        self._repos = 0
        self._gated = 0
        self._pull_requests = False

    @workflow.signal(name="approve", description="A person approves the drafted early warning. Ignored until the draft exists.")
    async def approve(self, approved_by: str = "") -> None:
        if self._stage == "awaiting_approval":
            self._approved = True
            self._approved_by = approved_by

    @workflow.query(name="state", description="Stage of the run and how many repositories have passed through the gate.")
    def state(self) -> dict:
        return {"stage": self._stage, "repos": self._repos, "gated": self._gated, "approved": self._approved}

    @workflow.entrypoint
    async def run(self, advisory_text: str) -> dict:
        run_id = workflows.get_execution_id() or "run"
        meta = await intake(run_id, advisory_text, workflow.now().isoformat())
        self._repos = len(meta["repos"])
        self._pull_requests = bool(meta.get("pull_requests"))  # absent in runs started before this step existed

        self._stage = "reading_advisory"
        await read_advisory(run_id, advisory_text)

        self._stage = "triage"
        gated = list(await asyncio.gather(*[self._one_repo(run_id, repo) for repo in meta["repos"]]))

        self._stage = "report"
        report = await write_report(run_id, gated)

        self._stage = "awaiting_approval"
        try:
            await workflow.wait_condition(lambda: self._approved, timeout=timedelta(hours=config.APPROVAL_HOURS))
            outcome = "approved"
        except asyncio.TimeoutError:
            outcome = "expired"
        await close_run(run_id, outcome, self._approved_by)
        self._stage = outcome
        return {"run_id": run_id, "outcome": outcome, "approved_by": self._approved_by, "counts": report["counts"], "report": report["path"]}

    async def _one_repo(self, run_id: str, repo: str) -> dict:
        """Triage, then the gate. A triage that fails or times out becomes "needs_human", not a failed run."""
        try:
            result = await triage_repo(run_id, repo)
        except Exception as error:
            result = {
                "repo": repo, "rc": -1, "usage": {},
                "verdict": {
                    "repo": repo, "verdict": "needs_human",
                    "advisory": {"id": "", "package": "", "affected_range": "", "flawed_function": ""},
                    "reason": f"The worker's activity did not finish: {_why(error)}"[:300],
                    "path": [], "proof": [], "fix": None, "suite": {}, "follow_ups": [],
                },
            }
        gated = await verify_repo(run_id, result)
        self._gated += 1
        if self._pull_requests and steps.wants_pull_request(gated):
            gated = await open_pull_request(run_id, gated)
        return gated


def _why(error: BaseException) -> str:
    """Name what stopped an activity. Class and timeout kind only: an error's text may quote an agent."""
    cause = error.__cause__
    kind = getattr(getattr(cause, "type", None), "name", "")
    if kind == "HEARTBEAT":
        return "the worker process stopped responding (no heartbeat within the limit)"
    if kind:
        return "it timed out (" + kind.lower().replace("_", " ") + ")"
    return type(cause or error).__name__


# ---------------------------------------------------------------- the worker


def main() -> int:
    missing = [name for name in ("MISTRAL_API_KEY", "DEPLOYMENT_NAME") if not os.environ.get(name)]
    if missing:
        print("Set " + " and ".join(missing) + " in your own shell before starting the worker.", file=sys.stderr)
        return 2
    if os.environ.get("OTEL_ENABLED", "").lower() != "false":
        print("Set OTEL_ENABLED=false. Without it the worker sends its logs and traces to Mistral.", file=sys.stderr)
        return 2
    print(f"worker for {config.WORKFLOW_NAME!r} on deployment {os.environ['DEPLOYMENT_NAME']!r}; "
          f"fleet {config.fleet_root()}, runs {config.runs_root()}, worker {config.run_repo_target()}")
    asyncio.run(workflows.run_worker([LeChonkRun]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
