"""One repository's result, as the report, the page and the pull-request step read it.

On disk a result is two files (docs/contract.md):

    verdict.json   what the worker claimed: agent-owned fields only. Nothing here is a result.
    state.json     what the orchestrator decided: the final verdict and each gate rule's outcome.

This module joins the two into one record. The verdict always comes from state.json. The reason,
the path, the proofs, the fix, the test counts and the follow-ups come from verdict.json, and are
the worker's own words: whoever shows them must treat them as untrusted text.
"""
from __future__ import annotations

import json
from pathlib import Path

from vulnerability_agent import contract

# Two rules that record where agent-written tests ran. Exactly one is present when tests were run.
SANDBOX_RULE = "proofs_ran_in_sandbox"
WAIVED_RULE = "sandbox_waived_for_stand_in"


def read_json(path: Path) -> dict | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def claim(repo_dir: Path) -> dict | None:
    """The worker's verdict.json as it wrote it, or None. Not validated here."""
    return read_json(repo_dir / contract.VERDICT_JSON)


def build(state: dict, claimed: dict | None) -> dict:
    """Join a state.json document and a verdict.json document (or None) into one record."""
    told = claimed if isinstance(claimed, dict) else {}
    rules = {
        item["rule"]: {"passed": item.get("passed") is True, "enforced": True, "detail": str(item.get("detail", ""))}
        for item in state.get("gate") or []
        if isinstance(item, dict) and isinstance(item.get("rule"), str)
    }
    verdict = state.get("verdict") if state.get("verdict") in contract.VERDICTS else contract.VERDICT_NEEDS_HUMAN
    return {
        "repo": state.get("repo"),
        "advisory": state.get("advisory") if isinstance(state.get("advisory"), dict) else {},
        "verdict": verdict,
        "reason": told.get("reason") if isinstance(told.get("reason"), str) else "",
        "path": [step for step in told.get("path") or [] if isinstance(step, dict)] if isinstance(told.get("path"), list) else [],
        "proof": [proof for proof in told.get("proof") or [] if isinstance(proof, dict)] if isinstance(told.get("proof"), list) else [],
        "fix": told.get("fix") if isinstance(told.get("fix"), dict) else None,
        "suite": told.get("suite") if isinstance(told.get("suite"), dict) else {},
        "follow_ups": [item for item in told.get("follow_ups") or [] if isinstance(item, str)] if isinstance(told.get("follow_ups"), list) else [],
        "gate": {
            "passed": all(rule["passed"] for rule in rules.values()),
            "original_verdict": told.get("verdict") if told.get("verdict") in contract.VERDICTS else None,
            "checked_at": state.get("final_at"),
            "sandboxed": True if SANDBOX_RULE in rules else False if WAIVED_RULE in rules else None,
            "rules": rules,
        },
        "usage": state.get("usage") if isinstance(state.get("usage"), dict) else {},
        "proof_output": state.get("proof_output") if isinstance(state.get("proof_output"), dict) else {},
    }


def load(run_dir: Path, repo: str) -> dict | None:
    """The record for a repository whose state is final. None while it is running or absent."""
    state = read_json(run_dir / repo / contract.STATE_JSON)
    if state is None or state.get("status") != contract.STATE_FINAL:
        return None
    return build(state, claim(run_dir / repo))


def proof_ids(result: dict) -> list[str]:
    """The proof test IDs of a record, as plain strings."""
    return [str(proof.get("test_id", "")) for proof in result.get("proof") or [] if isinstance(proof, dict) and proof.get("test_id")]
