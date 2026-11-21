"""The fleet fetcher, against a repository made on the spot. No network."""
import subprocess

import pytest

from orchestrator import fetch_fleet, stub_agent


def git(folder, *arguments: str) -> str:
    command = ["git", "-C", str(folder), "-c", "user.name=test", "-c", "user.email=test@example.test", "-c", "commit.gpgsign=false", *arguments]
    return subprocess.run(command, check=True, capture_output=True, text=True).stdout.strip()


@pytest.fixture
def upstream(tmp_path):
    """A repository with two commits. Returns (path, first commit, second commit)."""
    repo = tmp_path / "upstream" / "tiny-app"
    (repo / "src").mkdir(parents=True)
    (repo / "requirements.txt").write_text("authlib==1.8.0\n")
    (repo / "src" / "app.py").write_text("x = 1\n")
    git(repo, "init", "--quiet", "-b", "main")
    git(repo, "add", "-A")
    git(repo, "commit", "--quiet", "-m", "first")
    first = git(repo, "rev-parse", "HEAD")
    (repo / "src" / "app.py").write_text("x = 2\n")
    git(repo, "commit", "--quiet", "-am", "second")
    return repo, first, git(repo, "rev-parse", "HEAD")


def test_fetch_takes_the_pinned_commit_not_the_newest(upstream, tmp_path):
    repo, first, second = upstream
    target = tmp_path / "fleet"
    pinned = [{"name": "tiny-app", "url": str(repo), "commit": first}]
    assert fetch_fleet.fetch(pinned, target) == [f"tiny-app: fetched {first[:7]}"]
    assert (target / "tiny-app" / "src" / "app.py").read_text() == "x = 1\n"
    assert not (target / "tiny-app" / ".git").exists()  # plain files: the worker copies the folder as it is
    assert fetch_fleet.fetch(pinned, target) == [f"tiny-app: already at {first[:7]}"]
    # A folder that came from another commit is never overwritten.
    with pytest.raises(SystemExit, match="Remove it"):
        fetch_fleet.fetch([{**pinned[0], "commit": second}], target)
    assert (target / "tiny-app" / "src" / "app.py").read_text() == "x = 1\n"


def test_fetch_refuses_a_commit_the_repository_does_not_have(upstream, tmp_path):
    repo, _, _ = upstream
    with pytest.raises(SystemExit, match="is not in"):
        fetch_fleet.fetch([{"name": "tiny-app", "url": str(repo), "commit": "0" * 40}], tmp_path / "fleet")
    assert not (tmp_path / "fleet" / "tiny-app").exists()


def test_the_manifest_pins_every_app_the_stand_in_can_answer_for():
    apps = fetch_fleet.load_manifest()
    assert sorted(app["name"] for app in apps) == sorted(stub_agent.ground_truth())
    assert all(len(app["commit"]) == 40 for app in apps)


def test_a_branch_name_is_not_a_pin(tmp_path):
    manifest = tmp_path / "fleet.json"
    manifest.write_text('{"apps": [{"name": "tiny-app", "url": "x", "commit": "main"}]}')
    with pytest.raises(ValueError, match="full 40-character id"):
        fetch_fleet.load_manifest(manifest)
