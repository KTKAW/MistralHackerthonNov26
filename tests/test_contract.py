"""The pinned constants: write locations, ownership, verdict values, and the
proof-test invocation. Other tickets code against these instead of redefining
them."""

from pathlib import Path

from vulnerability_agent import contract

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_agent_write_locations_are_only_src_proof_verdict() -> None:
    assert contract.AGENT_WRITABLE == ("src", "proof", "verdict.json")


def test_layout_constants() -> None:
    assert contract.RUNS_DIR == "runs"
    assert contract.RUN_JSON == "run.json"
    assert contract.ADVISORY_JSON == "advisory.json"
    assert contract.EARLY_WARNING_MD == "early-warning.md"
    assert contract.SRC_DIR == "src"
    assert contract.PROOF_DIR == "proof"
    assert contract.VENV_DIR == "venv"
    assert contract.GATE_DIR == "gate"
    assert contract.STATE_JSON == "state.json"
    assert contract.FIX_DIFF == "fix.diff"
    assert contract.VIBE_EXPORT_JSON == "vibe/export.json"


def test_verdict_values() -> None:
    assert contract.VERDICTS == (
        "not_affected",
        "affected_proven",
        "affected_fixed",
        "needs_human",
    )
    assert contract.STATE_STATUSES == ("running", "final")


def test_pinned_proof_test_invocation() -> None:
    # Proofs live in proof/, outside src/; the command runs from the repo-run
    # root so venv/.../site-packages is importable.
    assert contract.PROOF_TEST_COMMAND == ("venv/bin/python", "-m", "pytest", "proof/", "-q")
    assert "repo-run root" in contract.PROOF_CWD


def test_written_contract_exists_and_cross_references_the_package() -> None:
    contract_md = (REPO_ROOT / "docs" / "contract.md").read_text(encoding="utf-8")
    assert "runs/<run>/<repo>/" in contract_md
    assert "vulnerability_agent" in contract_md
    assert "state.json" in contract_md
    assert "verdict.json" in contract_md
