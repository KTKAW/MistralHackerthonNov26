"""The run-directory helper: create runs/<run>/<repo>/ and work copies, and
write schema-validated contract files at the pinned locations."""

import json
from pathlib import Path
from typing import Any

import pytest

from vulnerability_agent import contract, runs, schemas

EXAMPLES = Path(__file__).resolve().parents[1] / "examples" / "contract"


def _run_doc() -> Any:
    return schemas.load_json(EXAMPLES / "run.json")


def _advisory_doc() -> Any:
    return schemas.load_json(EXAMPLES / "advisory.json")


def test_create_run_makes_runs_root_and_refuses_to_clobber(tmp_path: Path) -> None:
    run_root = runs.create_run(tmp_path, "run-1")
    assert run_root == tmp_path / "run-1"
    assert run_root.is_dir()
    with pytest.raises(FileExistsError):
        runs.create_run(tmp_path, "run-1")


def test_create_repo_run_makes_src_and_proof(tmp_path: Path) -> None:
    run_root = runs.create_run(tmp_path, "run-1")
    repo_run = runs.create_repo_run(run_root, "payments-svc")
    assert repo_run == run_root / "payments-svc"
    assert (repo_run / contract.SRC_DIR).is_dir()
    assert (repo_run / contract.PROOF_DIR).is_dir()
    # venv/ and gate/ are not created here: venv by the worker env, gate fresh by the gate
    assert not (repo_run / contract.VENV_DIR).exists()
    assert not (repo_run / contract.GATE_DIR).exists()


def test_make_work_copy_copies_the_fleet_repo_into_src(tmp_path: Path) -> None:
    fleet = tmp_path / "fleet" / "payments-svc"
    (fleet / "src" / "payments").mkdir(parents=True)
    (fleet / "src" / "payments" / "routes.py").write_text("# routes\n", encoding="utf-8")
    (fleet / "tests").mkdir()
    (fleet / "tests" / "test_routes.py").write_text("# tests\n", encoding="utf-8")

    run_root = runs.create_run(tmp_path / "runs", "run-1")
    repo_run = runs.create_repo_run(run_root, "payments-svc")
    work_copy = runs.make_work_copy(fleet, repo_run)

    assert work_copy == repo_run / "src"
    assert (work_copy / "src" / "payments" / "routes.py").read_text(encoding="utf-8") == "# routes\n"
    assert (work_copy / "tests" / "test_routes.py").is_file()


def test_write_helpers_place_files_at_the_pinned_locations(tmp_path: Path) -> None:
    run_root = runs.create_run(tmp_path, "run-1")
    runs.write_run_json(run_root, _run_doc())
    runs.write_advisory_json(run_root, _advisory_doc())
    repo_run = runs.create_repo_run(run_root, "payments-svc")
    verdict = schemas.load_json(EXAMPLES / "payments-svc" / "verdict.json")
    state = schemas.load_json(EXAMPLES / "payments-svc" / "state.json")
    runs.write_verdict_json(repo_run, verdict)
    runs.write_state_json(repo_run, state)

    assert (run_root / "run.json").is_file()
    assert (run_root / "advisory.json").is_file()
    assert (repo_run / "verdict.json").is_file()
    assert (repo_run / "state.json").is_file()
    assert json.loads((repo_run / "state.json").read_text(encoding="utf-8"))["status"] == "final"


def test_write_json_validated_rejects_invalid_documents(tmp_path: Path) -> None:
    bad_verdict = {"verdict": "safe"}
    with pytest.raises(schemas.ValidationError):
        runs.write_json_validated(tmp_path / "verdict.json", bad_verdict, "verdict")
    assert not (tmp_path / "verdict.json").exists()
