"""Fetch the demo fleet: five small services, each in its own repository.

    uv run python -m orchestrator.fetch_fleet              # into runs/_fleet
    uv run python -m orchestrator.fetch_fleet --to fleet

orchestrator/fleet.json lists each app with its repository and the commit to take. The commit
is pinned because these apps get installed and their tests get run: what is fetched must be
what was reviewed.

Each app lands as plain files, without its .git folder. The worker copies an app's folder as
it is, and the gate compares that copy with this original.

An app folder that is already there is left alone. If it did not come from the pinned commit,
this stops and says so. Remove that folder yourself and run this again.
"""
from __future__ import annotations

import argparse
import io
import json
import os
import re
import subprocess
import tarfile
import tempfile
from pathlib import Path

from orchestrator import config

MANIFEST = Path(__file__).with_name("fleet.json")
DEFAULT_TARGET = "runs/_fleet"
RECORD = ".fetched.json"
_GITHUB = re.compile(r"^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")


def load_manifest(path: Path = MANIFEST) -> list[dict]:
    apps = json.loads(path.read_text(encoding="utf-8"))["apps"]
    for app in apps:
        config.check_name(app["name"], "app name")
        if not re.fullmatch(r"[0-9a-f]{40}", app["commit"]):
            raise ValueError(f"{app['name']}: the commit must be a full 40-character id, not a branch or a short id")
    return apps


def fetched_apps(fleet_root: Path | None = None) -> dict[str, dict]:
    """name -> {url, commit, commit_url} for the apps in the fleet folder that were fetched at a pinned commit.

    Only GitHub addresses pass. An app that is in the folder but not in its record gets no entry.
    """
    root = fleet_root or config.fleet_root()
    try:
        fetched = json.loads((root / RECORD).read_text(encoding="utf-8"))
        manifest = {app["name"]: app["url"] for app in json.loads(MANIFEST.read_text(encoding="utf-8"))["apps"]}
    except (OSError, ValueError, KeyError, TypeError):
        return {}
    apps = {}
    for name, commit in fetched.items() if isinstance(fetched, dict) else []:
        url = str(manifest.get(name, "")).removesuffix(".git")
        if _GITHUB.match(url) and _COMMIT.match(str(commit)):
            apps[name] = {"url": url, "commit": commit, "commit_url": f"{url}/tree/{commit}"}
    return apps


def fetch(apps: list[dict], target: Path) -> list[str]:
    """Fetch every app that is missing from `target`. Returns one line per app saying what happened."""
    target.mkdir(parents=True, exist_ok=True)
    record_file = target / RECORD
    record = json.loads(record_file.read_text(encoding="utf-8")) if record_file.is_file() else {}
    done = []
    for app in apps:
        name, commit = app["name"], app["commit"]
        folder = target / name
        if folder.exists():
            if record.get(name) != commit:
                raise SystemExit(f"{folder} is already there, but not from commit {commit[:7]}. Remove it and run this again.")
            done.append(f"{name}: already at {commit[:7]}")
            continue
        with tempfile.TemporaryDirectory() as scratch:
            clone = Path(scratch) / "clone"
            _git("clone", "--quiet", "--no-checkout", app["url"], str(clone))
            try:
                found = _git("-C", str(clone), "rev-parse", "--verify", "--quiet", commit + "^{commit}").strip()
            except subprocess.CalledProcessError:
                found = ""
            if found != commit:
                raise SystemExit(f"{name}: commit {commit[:7]} is not in {app['url']}")
            archive = subprocess.run(["git", "-C", str(clone), "archive", "--format=tar", commit], check=True, capture_output=True).stdout
        folder.mkdir()
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            tar.extractall(folder, filter="data")  # "data": no absolute paths, no links out of the folder
        record[name] = commit
        record_file.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
        done.append(f"{name}: fetched {commit[:7]}")
    return done


def _git(*arguments: str) -> str:
    # Never stop to ask for a password: a repository this cannot read is an error to report.
    environment = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    return subprocess.run(["git", *arguments], check=True, capture_output=True, text=True, env=environment).stdout


def main() -> None:
    parser = argparse.ArgumentParser(description="Fetch the demo fleet at the commits pinned in orchestrator/fleet.json.")
    parser.add_argument("--to", default=DEFAULT_TARGET, help=f"folder to fetch into (default {DEFAULT_TARGET})")
    arguments = parser.parse_args()
    target = Path(arguments.to)
    target = target if target.is_absolute() else config.REPO_ROOT / target
    for line in fetch(load_manifest(), target):
        print(line)
    if target == config.REPO_ROOT / DEFAULT_TARGET:
        print(f"The tool now uses {target} as its fleet, unless LE_CHONK_FLEET_ROOT says otherwise.")
    else:
        print(f"Use it with LE_CHONK_FLEET_ROOT={target}")


if __name__ == "__main__":
    main()
