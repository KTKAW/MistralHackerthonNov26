"""Open a draft pull request with a fix the gate has verified.

This is the last step for a repository whose verdict is "affected and fixed" and whose gate
passed. It puts the worker's change on a branch of the repository and opens a draft pull request
for a person to review. It never merges anything.

What may go into a pull request:

- Only what the gate checked. Every changed or added file must be byte-for-byte the file in the
  gate's fixed state. A work copy that changed after the gate ran is refused.
- Nothing under .github/. A pull request from this tool must not change what CI runs.
- No free text from the worker. The title, the commit message and the body are built from
  checked values: package, version, advisory identifier, file names, test names, exit codes.
  A worker's own words are untrusted, and GitHub notifies anyone a pull request names with "@".

Credentials: this uses the `git` and `gh` commands as they are signed in on the machine that
runs the step. It never reads or handles a token. The worker never gets near them: it has
finished, inside its sandbox, before this step starts.

One risk stays with whoever turns this on. Opening a pull request can start the repository's CI,
and CI then runs the worker's proof test. On a branch of the same repository, CI may have the
repository's secrets. Turn this on only for repositories where that is acceptable.

LE_CHONK_PULL_REQUESTS=draft turns it on. It is off by default.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from orchestrator import config, fetch_fleet, record
from orchestrator import gate as gate_checks
from vulnerability_agent import contract

MAX_FILES = 20
MAX_BYTES = 200_000
_FILE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_./-]{0,200}$")
_VERSION = re.compile(r"^[0-9][0-9A-Za-z.+!-]{0,40}$")
_ADVISORY = re.compile(r"^(CVE-\d{4}-\d{4,7}|GHSA(-[0-9a-z]{4}){3})$", re.I)
_PACKAGE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,80}$")
_BRANCH = re.compile(r"^le-chonk/[a-z0-9][A-Za-z0-9._-]{0,140}$")
_PULL = re.compile(r"^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/pull/(\d+)$")
_PLAIN = re.compile(r"[^A-Za-z0-9_.:/=<>,;()\[\] +*!~^-]")


class Refused(Exception):
    """No pull request was opened, and this says why."""


def open_fix_pr(run_id: str, verdict: dict, *, runs_root: str | Path | None = None) -> dict:
    """Open the draft pull request for one record (orchestrator/record.py). Returns {url, number, branch, title, draft}.

    Raises Refused when this verdict must not become a pull request. Safe to call again: a
    pull request that already exists for this run and repository is returned, not duplicated.
    If an earlier run's pull request for the same advisory is still open, that one is returned
    with "reused": True and nothing is pushed.
    """
    repo = config.check_name(verdict.get("repo"), "repository name")
    checked = verdict.get("gate") or {}
    if verdict.get("verdict") != "affected_fixed" or checked.get("passed") is not True or checked.get("original_verdict") != "affected_fixed":
        raise Refused("only a fix that the gate has verified becomes a pull request")
    app = fetch_fleet.fetched_apps().get(repo)
    if not app:
        raise Refused("this repository was not fetched from a GitHub address at a pinned commit, so there is nowhere to propose the fix")

    run_dir = config.run_dir(run_id, runs_root)
    try:  # the facts the tool itself read and checked
        advisory = json.loads((run_dir / contract.ADVISORY_JSON).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise Refused("the run has no advisory facts on disk") from None
    advisory_id = str(advisory.get("advisory_id", ""))
    if not _ADVISORY.match(advisory_id):
        raise Refused("the advisory identifier is not a CVE or GHSA identifier")

    # The change is what fix.diff holds: the work copy against the fleet copy. The proof tests are
    # in proof/, outside the work copy, so they stay with the run and are not part of the proposal.
    work, fixed = run_dir / repo / contract.SRC_DIR, run_dir / repo / contract.GATE_DIR / "fixed" / contract.SRC_DIR
    changes = gate_checks.work_copy_changes(run_id, repo, runs_root=runs_root)
    if changes is None:
        raise Refused("the work copy or the original is missing")
    files, deleted = changes["changed"] + changes["added"], changes["deleted"]
    if not files and not deleted:
        raise Refused("the work copy holds no change to propose")
    if len(files) + len(deleted) > MAX_FILES:
        raise Refused(f"the change touches more than {MAX_FILES} files: a person should look at it first")
    for name in files + deleted:
        parts = name.split("/")
        if not _FILE.match(name) or ".." in parts or parts[0] in (".github", ".git") or name.endswith("/"):
            raise Refused(f"the change touches {_plain(name)}, which this tool will not put in a pull request")
    for name in files:
        data = (work / name).read_bytes()
        if len(data) > MAX_BYTES:
            raise Refused(f"{name} is larger than {MAX_BYTES} bytes")
        if not (fixed / name).is_file() or (fixed / name).read_bytes() != data:
            raise Refused(f"{name} is not the file the gate checked: the work copy changed after the gate ran")
    for name in deleted:
        if (fixed / name).exists():
            raise Refused(f"{name} was deleted after the gate ran")

    branch = f"le-chonk/{advisory_id.lower()}-{run_id}"
    if not _BRANCH.match(branch) or ".." in branch or branch.endswith((".lock", ".", "/")):
        raise Refused("the run identifier cannot be used in a branch name")
    owner_repo = app["url"].removeprefix("https://github.com/")
    title = _title(repo, advisory, verdict, gate_checks.pinned_version(work / "requirements.txt", str(advisory.get("package", ""))))

    existing = _existing_pr(owner_repo, branch)
    if existing:
        return {**existing, "branch": branch, "title": title}
    # An earlier run may already have proposed a fix for this advisory. One open proposal is enough:
    # a second run links to it instead of opening another.
    earlier = _open_pr_from(owner_repo, f"le-chonk/{advisory_id.lower()}-")
    if earlier:
        return {**earlier, "title": title, "reused": True}
    _push_branch(app, branch, title, run_id, work, files, deleted)
    body = _body(run_id, repo, advisory, verdict, app, changes)
    url = _create_pr(owner_repo, branch, _default_branch(owner_repo), title, body)
    return {"url": url, "number": int(_PULL.match(url).group(1)), "branch": branch, "title": title, "draft": True}


# ---------------------------------------------------------------- what the pull request says


def _plain(text: object, limit: int = 300) -> str:
    """Text cut down to harmless characters: no "@", no backtick, no pipe, no line break."""
    return _PLAIN.sub("", " ".join(str(text).split()))[:limit]


def _code(text: object, limit: int = 300) -> str:
    return "`" + (_plain(text, limit) or "?") + "`"


def _title(repo: str, advisory: dict, verdict: dict, pinned: str | None) -> str:
    """`pinned` is the version the work copy's requirements.txt pins the package to, read by this tool."""
    fix = verdict.get("fix") or {}
    package, target = str(advisory.get("package", "")), str(pinned or "")
    if fix.get("kind") == "upgrade" and _PACKAGE.match(package) and _VERSION.match(target):
        return f"Upgrade {package} to {target} ({advisory['advisory_id']})"
    return f"Fix {advisory['advisory_id']} in {repo}"


def _body(run_id: str, repo: str, advisory: dict, verdict: dict, app: dict, changes: dict) -> str:
    checked = verdict.get("gate") or {}
    stand_in = config.run_repo_target().startswith("orchestrator.stub_agent")
    lines = [
        "## What this changes",
        "",
        *[f"- {_code(name)} changed" for name in changes["changed"]],
        *[f"- {_code(name)} added" for name in changes["added"]],
        *[f"- {_code(name)} deleted" for name in changes["deleted"]],
        "",
        f"It is the fix for {_plain(advisory.get('advisory_id'))}: {_code(advisory.get('package'))}, affected versions {_code(advisory.get('affected_version_range'))}, "
        f"fixed in {_code(advisory.get('fixed_version'))}, flawed function {_code(advisory.get('flawed_function'))}.",
        "",
        "## What was checked before this was opened",
        "",
        "A gate with no model in it re-ran everything on clean copies: the repository as it is at "
        f"{_code(str(app['commit'])[:12])}, and the same with this change.",
        "",
        "| Check | Result |",
        "|---|---|",
    ]
    for name, rule in (checked.get("rules") or {}).items():
        if not isinstance(rule, dict):
            continue
        outcome = "yes" if rule.get("passed") is True else "no" if rule.get("enforced") else "no (recorded, not enforced)"
        detail = _plain(rule.get("detail", ""), 240) if name in gate_checks.MEASURED else ""
        lines.append(f"| {_plain(gate_checks.RULE_LABELS.get(name, name))} | {outcome}{': ' + _code(detail, 240) if detail else ''} |")
    proofs = record.proof_ids(verdict)
    if proofs:
        lines += ["", "The proof test is kept with the run, outside the repository, and is not in this pull request: "
                  + ", ".join(_code(test) for test in proofs[:5]) + ". It fails on the base commit and passes with this change."]
    cited = [f"{_plain(step.get('file'))}:{step.get('line')}" for step in verdict.get("path") or []
             if isinstance(step, dict) and isinstance(step.get("line"), int) and _FILE.match(str(step.get("file", "")))]
    if cited:
        lines += ["", "Code path the worker cited (the gate does not check this): " + ", ".join(_code(step) for step in cited[:8]) + "."]
    lines += [
        "",
        "## How it was produced",
        "",
        f"- Run {_code(run_id)} of ChonkDefendor, a tool that checks a fleet of repositories against one security advisory.",
        f"- Worker: {_code(config.run_repo_target())}." + (" **This is a stand-in, not an agent.** It took this change from an answer file. The checks above are real." if stand_in else ""),
        "- Agent-written tests ran " + ("inside the sandbox." if checked.get("sandboxed") is True else "outside the sandbox."),
        "",
        "This is a draft for a person to review. Nothing was merged or released.",
    ]
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------- git and GitHub


def _run(command: list[str], **environment: str) -> str:
    quiet = {"GIT_TERMINAL_PROMPT": "0", "GH_PROMPT_DISABLED": "1", "NO_COLOR": "1"}
    done = subprocess.run(command, capture_output=True, text=True, timeout=120, env={**os.environ, **quiet, **environment})
    if done.returncode != 0:
        raise RuntimeError(f"{command[0]} {command[1] if len(command) > 1 else ''} failed: {(done.stderr or done.stdout).strip()[-300:]}")
    return done.stdout


def _clone_url(app: dict) -> str:
    return app["url"] + ".git"


def _push_branch(app: dict, branch: str, title: str, run_id: str, work: Path, files: list[str], deleted: list[str]) -> None:
    """Put the change on a new branch, on top of the commit the run inspected."""
    with tempfile.TemporaryDirectory() as scratch:
        clone = Path(scratch) / "repo"
        _run(["git", "clone", "--quiet", "--no-checkout", _clone_url(app), str(clone)])
        if _run(["git", "-C", str(clone), "ls-remote", "--heads", "origin", branch]).strip():
            return  # an earlier attempt pushed it and stopped before the pull request
        _run(["git", "-C", str(clone), "checkout", "--quiet", "-b", branch, app["commit"]])
        root = clone.resolve()
        for name in files:
            target = clone / name
            target.parent.mkdir(parents=True, exist_ok=True)
            if not target.parent.resolve().is_relative_to(root) or target.is_symlink():
                raise Refused(f"{name} would be written outside the repository")
            shutil.copyfile(work / name, target)
        if deleted:
            _run(["git", "-C", str(clone), "rm", "--quiet", "--", *deleted])
        if files:
            _run(["git", "-C", str(clone), "add", "--", *files])
        message = f"{title}\n\nProposed by ChonkDefendor, run {run_id}. A gate re-ran the proof on clean copies:\nit fails before this change and passes after it."
        _run(["git", "-C", str(clone), "commit", "--quiet", "-m", message])
        _run(["git", "-C", str(clone), "push", "--quiet", "origin", f"{branch}:refs/heads/{branch}"])


def _existing_pr(owner_repo: str, branch: str) -> dict | None:
    found = json.loads(_run(["gh", "pr", "list", "--repo", owner_repo, "--head", branch, "--state", "all", "--json", "url,number,isDraft"]) or "[]")
    for item in found if isinstance(found, list) else []:
        if isinstance(item, dict) and _PULL.match(str(item.get("url", ""))):
            return {"url": item["url"], "number": int(item["number"]), "draft": bool(item.get("isDraft"))}
    return None


def _open_pr_from(owner_repo: str, branch_prefix: str) -> dict | None:
    """An open pull request whose branch this tool made for the same advisory, if there is one."""
    found = json.loads(_run(["gh", "pr", "list", "--repo", owner_repo, "--state", "open", "--limit", "100", "--json", "url,number,isDraft,headRefName"]) or "[]")
    for item in found if isinstance(found, list) else []:
        if isinstance(item, dict) and str(item.get("headRefName", "")).startswith(branch_prefix) and _PULL.match(str(item.get("url", ""))):
            return {"url": item["url"], "number": int(item["number"]), "draft": bool(item.get("isDraft")), "branch": item["headRefName"]}
    return None


def _default_branch(owner_repo: str) -> str:
    name = json.loads(_run(["gh", "repo", "view", owner_repo, "--json", "defaultBranchRef"]))["defaultBranchRef"]["name"]
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,100}", str(name)):
        raise RuntimeError("the repository's default branch has an unexpected name")
    return name


def _create_pr(owner_repo: str, branch: str, base: str, title: str, body: str) -> str:
    with tempfile.TemporaryDirectory() as scratch:
        body_file = Path(scratch) / "body.md"
        body_file.write_text(body, encoding="utf-8")
        printed = _run(["gh", "pr", "create", "--repo", owner_repo, "--head", branch, "--base", base, "--draft", "--title", title, "--body-file", str(body_file)])
    url = (printed.strip().splitlines() or [""])[-1].strip()
    if not _PULL.match(url):
        raise RuntimeError("GitHub did not return a pull request address")
    return url
