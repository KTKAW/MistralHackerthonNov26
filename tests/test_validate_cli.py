"""CLI tests for schema/validate.py (docs/build-prompt.md Step 1 'done when')."""
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
VALIDATE = REPO_ROOT / "schema" / "validate.py"


def run_cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(VALIDATE), *args],
        capture_output=True, text=True, cwd=REPO_ROOT,
    )


def test_valid_example_exits_zero():
    r = run_cli("examples/verdict.example.json")
    assert r.returncode == 0, r.stderr
    assert "OK" in r.stdout


def test_bad_example_exits_one_and_names_the_problem():
    """proof-as-a-single-string must fail (the shipped broken example)."""
    r = run_cli("examples/verdict.bad.json")
    assert r.returncode == 1
    assert "INVALID" in r.stdout
    assert "proof" in r.stdout


def test_no_arguments_prints_usage_and_fails():
    r = run_cli()
    assert r.returncode != 0
    assert "Usage" in (r.stderr + r.stdout)


def test_missing_file_fails():
    r = run_cli("examples/does-not-exist.json")
    assert r.returncode != 0


def test_malformed_json_fails(tmp_path):
    bad = tmp_path / "broken.json"
    bad.write_text("{not json")
    r = run_cli(str(bad))
    assert r.returncode != 0
