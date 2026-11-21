"""The rules gate. There is no model in here.

A worker's verdict.json is a claim. Before a claim may be shown, the gate re-runs it on clean
baselines that the worker never touched, and writes the outcome to the orchestrator-owned
state.json (docs/contract.md). It never changes verdict.json.

    gate/vulnerable/   src/    the repository as the fleet holds it
                       proof/  the worker's proof tests
                       venv/   built here, offline, from the fleet copy's own requirements
    gate/fixed/        src/    the worker's work copy ("affected_fixed"), else the fleet's copy
                       proof/  the same proof tests
                       venv/   built here from that copy's requirements

Each baseline has the layout of a repo-run root, so the contract's pinned command works in it:
`venv/bin/python -m pytest proof/ -q`, with the baseline as the working directory.

Rules for "affected_proven" and "affected_fixed":
    existing_tests_byte_identical           no test file from the fleet copy was changed or deleted
    proof_in_proof_folder                   every proof is a test under proof/, outside src/
    installed_library_matches_wheelhouse    the worker's own venv/ holds the library as its wheel ships it
    proof_fails_on_vulnerable               every proof fails on the vulnerable baseline, as claimed
    proof_passes_on_fixed                   every proof passes on the fixed baseline ("affected_fixed")
    no_test_pass_to_fail_between_baselines  no test of the repository passes before and not after ("affected_fixed")
Rules for "not_affected":
    no_diff_in_src                          src/ is the fleet's copy, file for file
    cited_path_exists                       every cited file and line exists

A rule that fails turns the verdict into "needs_human". That is the only change the gate can make.
It also computes fix.diff (src/ against the fleet copy), which the contract gives to the
orchestrator, not to the worker.

Agent-written tests run through the sandbox wrapper. Without the wrapper the gate refuses to run
them unless LE_CHONK_ALLOW_UNSANDBOXED=1, which is for tests against stand-in workers.
"""
from __future__ import annotations

import datetime as dt
import difflib
import os
import re
import shlex
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ElementTree
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, Callable

from orchestrator import config, events, record
from vulnerability_agent import contract, schemas
from vulnerability_agent import runs as contract_runs

IGNORED_DIRS = {".venv", "venv", "__pycache__", ".pytest_cache", ".git", ".mypy_cache", ".ruff_cache", "node_modules"}
IGNORED_FILES = {".DS_Store"}
IGNORED_SUFFIXES = (".pyc", ".pyo")
PYTEST_TIMEOUT = 180
INSTALL_TIMEOUT = 300
MAX_DIFF_BYTES = 400_000

_REQUIREMENT = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._-]*(\[[A-Za-z0-9._,-]+\])?"
    r"(\s*(==|>=|<=|~=|!=|<|>)\s*[A-Za-z0-9.*+!_-]+(\s*,\s*(==|>=|<=|~=|!=|<|>)\s*[A-Za-z0-9.*+!_-]+)*)?$"
)

RULE_LABELS = {
    "worker_finished": "The worker finished",
    "verdict_file_present": "The worker left a verdict",
    "verdict_valid": "The verdict has the agreed shape",
    "work_copy_present": "The original and the work copy are both there",
    "no_diff_in_src": "Nothing in the work copy was changed",
    "cited_path_exists": "Every cited file and line exists",
    "existing_tests_byte_identical": "No earlier test was changed or deleted",
    "proof_in_proof_folder": "The proof tests are in proof/, outside the work copy",
    "installed_library_matches_wheelhouse": "The worker's installed library is the wheel, unedited",
    "sandbox_available": "The sandbox is there to run agent-written tests in",
    record.SANDBOX_RULE: "Agent-written tests ran inside the sandbox",
    record.WAIVED_RULE: "Tests ran outside the sandbox, allowed for a stand-in only",
    "vulnerable_baseline_built": "The vulnerable baseline was built",
    "proof_fails_on_vulnerable": "The proof fails before the fix",
    "fixed_baseline_built": "The fixed baseline was built",
    "proof_passes_on_fixed": "The proof passes after the fix",
    "no_test_pass_to_fail_between_baselines": "No test passes before the fix and fails after it",
    "gate_error": "The gate ran without an error of its own",
}
VERDICTS = contract.VERDICTS
MEASURED = {"vulnerable_baseline_built", "proof_fails_on_vulnerable", "fixed_baseline_built", "proof_passes_on_fixed",
            "no_test_pass_to_fail_between_baselines", "installed_library_matches_wheelhouse", "cited_path_exists"}


# ---------------------------------------------------------------- the contract


def gate_repo(run_id: str, repo: str, *, problem: str | None = None, usage: dict | None = None,
              runs_root: str | Path | None = None, wheelhouse: str | Path | None = None) -> dict:
    """Decide one repository's final state, write state.json, and return the joined record.

    `problem` says the worker never finished (a crash or a timeout). Nothing it left is trusted then.
    `usage` is what the orchestrator measured for the worker; it is stored as given.
    """
    run_dir = config.run_dir(run_id, runs_root)
    repo = config.check_name(repo, "repository name")
    wheels = Path(wheelhouse) if wheelhouse is not None else config.wheelhouse()
    if not wheels.is_absolute():
        wheels = config.REPO_ROOT / wheels
    advisory = record.read_json(run_dir / contract.ADVISORY_JSON)
    schemas.validate(advisory, "advisory")  # a run that reached triage has its five facts on disk

    def say(text: str, kind: str = "step", **data: Any) -> None:
        events.append(run_dir, "gate", text, repo=repo, kind=kind, **data)

    rules = _Rules(say)
    proof_output: dict[str, str] = {}
    claimed = None
    try:
        claimed = _judge(run_dir, repo, advisory, problem, wheels, rules, proof_output, say)
    except Exception as error:  # a broken claim must never take the run down
        rules.add("gate_error", False, f"{type(error).__name__}: {error}")
    passed = rules.all_passed()
    final = claimed if claimed in VERDICTS and passed else contract.VERDICT_NEEDS_HUMAN
    state = {
        "status": contract.STATE_FINAL,
        "verdict": final,
        "repo": repo,
        "advisory": advisory,
        "gate": rules.listed(),
        "final_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "usage": dict(usage or {}),
        "proof_output": proof_output,
    }
    contract_runs.write_state_json(run_dir / repo, state)
    if claimed is None or claimed == contract.VERDICT_NEEDS_HUMAN:
        say("Gate finished: it stays with a person.", "done", passed=passed)
    elif passed:
        say(f"Gate finished: the claim of {claimed} stands.", "done", passed=True)
    else:
        say(f"Gate finished: the claim of {claimed} is rejected. It goes to a person. Failed: {', '.join(rules.failed())}.", "done", passed=False)
    return record.build(state, record.claim(run_dir / repo))


def gate(run_id: str, repos: list[str], *, runs_root: str | Path | None = None, wheelhouse: str | Path | None = None) -> list[dict]:
    """The gate for several repositories, one after another."""
    return [gate_repo(run_id, repo, runs_root=runs_root, wheelhouse=wheelhouse) for repo in repos]


def write_running_state(run_id: str, repo: str, *, runs_root: str | Path | None = None) -> None:
    """Mark a repository as being worked on. The page shows a placeholder for it, never a verdict."""
    run_dir = config.run_dir(run_id, runs_root)
    advisory = record.read_json(run_dir / contract.ADVISORY_JSON)
    state = {"status": contract.STATE_RUNNING, "repo": config.check_name(repo, "repository name"), "advisory": advisory}
    contract_runs.write_state_json(run_dir / repo, state)


# ---------------------------------------------------------------- one claim


class _Rules:
    def __init__(self, say: Callable[..., None] | None = None) -> None:
        self.rules: dict[str, dict[str, Any]] = {}
        self.say = say or (lambda *args, **kwargs: None)

    def add(self, name: str, passed: bool, detail: str = "") -> bool:
        """Record an enforced rule. Every rule in state.json decides the verdict."""
        self.rules[name] = {"passed": passed is True, "detail": detail[:800]}
        label = RULE_LABELS.get(name, name)
        if passed is True:
            # A passed rule's detail is repeated only where it holds a measurement.
            self.say(f"{label}: {detail[:240]}." if name in MEASURED and detail else f"{label}.", "ok", rule=name)
        else:
            self.say(f"{label}: NO. {detail[:240]}".strip(), "fail", rule=name)
        return passed is True

    def note(self, text: str) -> None:
        """Something worth a person's eye that does not decide the verdict. It goes to the event log only."""
        self.say("Recorded, not enforced: " + text[:300], "info")

    def all_passed(self) -> bool:
        return all(rule["passed"] for rule in self.rules.values())

    def failed(self) -> list[str]:
        return [name for name, rule in self.rules.items() if not rule["passed"]]

    def listed(self) -> list[dict]:
        return [{"rule": name, "passed": rule["passed"], "detail": rule["detail"]} for name, rule in self.rules.items()]


def _short(path: Path) -> str:
    """A path as a person would say it: from the repository root when it is inside it."""
    try:
        return path.resolve().relative_to(config.REPO_ROOT.resolve()).as_posix()
    except ValueError:
        return "/".join(path.parts[-3:])


def _judge(run_dir: Path, repo: str, advisory: dict, problem: str | None, wheels: Path, rules: _Rules,
           proof_output: dict[str, str], say: Callable[..., None]) -> str | None:
    """Run every rule that applies. Returns the verdict the worker claimed, or None if there is no usable claim."""
    repo_dir = run_dir / repo
    if problem:
        say("The worker did not finish. There is no claim to re-run.", "start")
        rules.add("worker_finished", False, problem)
        return None
    claim = record.claim(repo_dir)
    if not rules.add("verdict_file_present", claim is not None,
                     "verdict.json is there" if claim is not None else "the worker left no verdict.json, or it does not hold a JSON object"):
        return None
    errors = _schema_errors(claim)
    if not rules.add("verdict_valid", not errors, "; ".join(errors) or "agent-owned fields only, as the contract asks"):
        return None
    claimed = claim["verdict"]
    if claimed == contract.VERDICT_NEEDS_HUMAN:
        say("The worker asked for a person. There is no claim to re-run.", "start")
        return claimed
    say(f"The gate starts on a claim of {claimed}. It trusts nothing in it and re-runs everything itself.", "start")

    original = config.fleet_root() / repo
    src = repo_dir / contract.SRC_DIR
    if not rules.add("work_copy_present", original.is_dir() and src.is_dir(), f"original: {_short(original)}, work copy: {_short(src)}"):
        return claimed
    diff = _compare(original, src)
    _write_fix_diff(original, src, diff, repo_dir / contract.FIX_DIFF)
    if claimed == contract.VERDICT_NOT_AFFECTED:
        _check_not_affected(rules, claim, diff, repo_dir)
    else:
        _check_affected(rules, claim, advisory, diff, original, repo_dir, wheels, proof_output, say)
    return claimed


def _check_not_affected(rules: _Rules, claim: dict, diff: dict[str, list[str]], repo_dir: Path) -> None:
    touched = [f"{kind}: {name}" for kind in ("changed", "deleted", "added") for name in diff[kind]]
    rules.add("no_diff_in_src", not touched, "; ".join(touched) or "src/ is identical to the fleet copy; fix.diff is empty")
    cited = claim.get("path") or []
    missing = _missing_citations(cited, repo_dir)
    rules.add("cited_path_exists", bool(cited) and not missing,
              "the verdict must cite the code path it followed" if not cited
              else "; ".join(missing) or f"{len(cited)} cited line{'s' if len(cited) != 1 else ''} exist; the reasoning is not machine-checked")
    reason = str(claim.get("reason", "")).lower()
    if "no reachable path found" not in reason or re.search(r"\bsafe\b", reason):
        rules.note('the reason should say "no reachable path found", and never "safe"')


def _check_affected(rules: _Rules, claim: dict, advisory: dict, diff: dict[str, list[str]], original: Path, repo_dir: Path,
                    wheels: Path, proof_output: dict[str, str], say: Callable[..., None]) -> None:
    claimed = claim["verdict"]
    package, fixed_version = advisory["package"], advisory["fixed_version"]
    proofs = [proof for proof in claim.get("proof") or [] if isinstance(proof, dict)]
    test_ids = [str(proof.get("test_id", "")) for proof in proofs]
    src, proof_dir = repo_dir / contract.SRC_DIR, repo_dir / contract.PROOF_DIR

    touched_tests = [name for name in diff["changed"] + diff["deleted"] if _is_test_file(name)]
    rules.add("existing_tests_byte_identical", not touched_tests,
              "; ".join(touched_tests) or "every test file from the fleet copy is unchanged")
    if claimed == contract.VERDICT_AFFECTED_PROVEN:
        app_changes = [name for name in diff["changed"] + diff["deleted"] if not _is_test_file(name)]
        if app_changes:
            rules.note("application files were changed without a fix being claimed: " + "; ".join(app_changes))

    bad_proofs = [test_id for test_id in test_ids if _proof_file(test_id) is None or not (repo_dir / _proof_file(test_id)).is_file()]
    if not rules.add("proof_in_proof_folder", bool(test_ids) and not bad_proofs,
                     "no proof test listed" if not test_ids
                     else "; ".join(f"not a test under proof/: {p}" for p in bad_proofs) or f"{len(test_ids)} proof test{'s' if len(test_ids) != 1 else ''} under proof/"):
        return

    worker_venv = repo_dir / contract.VENV_DIR
    if worker_venv.is_dir():
        rules.add("installed_library_matches_wheelhouse", *_library_matches(worker_venv, package, wheels))
    else:
        say("The worker left no venv/, so there is no installed library to compare with the wheelhouse.", "info")

    wrapper = config.sandbox_wrapper()
    sandbox = wrapper if wrapper.is_file() else None
    if sandbox is None and not config.allow_unsandboxed():
        rules.add("sandbox_available", False, f"{wrapper} not found; the gate will not run agent-written tests outside the sandbox")
        return
    if sandbox is not None:
        rules.add(record.SANDBOX_RULE, True, f"through {_short(sandbox)}")
    else:
        rules.add(record.WAIVED_RULE, True, "LE_CHONK_ALLOW_UNSANDBOXED=1: for stand-in workers only")

    gate_dir = repo_dir / contract.GATE_DIR
    if gate_dir.exists():
        shutil.rmtree(gate_dir)
    log = _Log(gate_dir / "log.txt")
    try:
        # --- vulnerable baseline: the fleet's copy, its own requirements, and the worker's proof tests
        vulnerable = gate_dir / "vulnerable"
        say("Building the vulnerable baseline: the fleet's own copy, with its own requirements, installed offline.")
        _baseline(vulnerable, original, proof_dir)
        ok, detail = _make_env(vulnerable, wheels, [], log)
        if not rules.add("vulnerable_baseline_built", ok, detail):
            return
        before = _suite(vulnerable, sandbox, log)
        say(f"Running the proof on the vulnerable baseline{'' if sandbox else ' (no sandbox: allowed for the stand-in only)'}.")
        codes = {}
        for test_id in test_ids:
            codes[test_id], output = _run_pytest(vulnerable, [test_id], sandbox, log)
            proof_output[test_id] = output.strip()[-1500:]
        claims_fail = all(proof.get("on_vulnerable") == "fail" for proof in proofs)
        rules.add("proof_fails_on_vulnerable", all(code == 1 for code in codes.values()) and claims_fail,
                  _codes(codes, "a failing test exits 1") + ("" if claims_fail else "; the verdict does not claim a failure on the vulnerable version"))

        # --- fixed baseline
        fixed = gate_dir / "fixed"
        if claimed == contract.VERDICT_AFFECTED_FIXED:
            say("Building the fixed baseline: the worker's work copy, with its requirements, installed offline.")
            _baseline(fixed, src, proof_dir)
            extra = []
        else:
            say(f"Building a fixed baseline to try the proof on: the fleet's copy with {package}=={fixed_version}.")
            _baseline(fixed, original, proof_dir)
            extra = [f"{package}=={fixed_version}"]
        ok, detail = _make_env(fixed, wheels, extra, log)
        if claimed != contract.VERDICT_AFFECTED_FIXED:
            if ok:  # there is no fix to pass on, so this is recorded and decides nothing
                codes = {test_id: _run_pytest(fixed, [test_id], sandbox, log)[0] for test_id in test_ids}
                rules.note(f"with {package}=={fixed_version}, " + _codes(codes, "a passing test exits 0"))
            else:
                rules.note("the fixed baseline could not be built: " + detail)
            return
        if not rules.add("fixed_baseline_built", ok, detail):
            return
        say("Running the proof on the fixed baseline.")
        codes = {test_id: _run_pytest(fixed, [test_id], sandbox, log)[0] for test_id in test_ids}
        claims_pass = all(proof.get("on_fixed") == "pass" for proof in proofs)
        rules.add("proof_passes_on_fixed", all(code == 0 for code in codes.values()) and claims_pass,
                  _codes(codes, "a passing test exits 0") + ("" if claims_pass else "; the verdict does not claim a pass on the fixed version"))
        say("Running the repository's own tests on both baselines.")
        rules.add("no_test_pass_to_fail_between_baselines", *_compare_suites(before, _suite(fixed, sandbox, log)))
    finally:
        for baseline in ("vulnerable", "fixed"):  # the environments are large and rebuilt every time
            shutil.rmtree(gate_dir / baseline / contract.VENV_DIR, ignore_errors=True)
            shutil.rmtree(gate_dir / baseline / ".sandbox", ignore_errors=True)  # the wrapper's own HOME, temp folder and cache
        log.close()


# ---------------------------------------------------------------- comparing folders


def _walk(root: Path) -> dict[str, Path]:
    found: dict[str, Path] = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in IGNORED_DIRS and not d.endswith(".egg-info"))
        for name in sorted(filenames):
            if name in IGNORED_FILES or name.endswith(IGNORED_SUFFIXES):
                continue
            path = Path(dirpath) / name
            if path.is_symlink() or not path.is_file():
                continue
            found[path.relative_to(root).as_posix()] = path
    return found


def _compare(original: Path, work: Path) -> dict[str, list[str]]:
    before, after = _walk(original), _walk(work)
    return {
        "changed": sorted(name for name in before.keys() & after.keys() if before[name].read_bytes() != after[name].read_bytes()),
        "deleted": sorted(before.keys() - after.keys()),
        "added": sorted(after.keys() - before.keys()),
    }


def work_copy_changes(run_id: str, repo: str, *, runs_root: str | Path | None = None) -> dict[str, list[str]] | None:
    """What the worker changed, deleted and added in src/. None if either folder is missing."""
    original = config.fleet_root() / config.check_name(repo, "repository name")
    work = config.run_dir(run_id, runs_root) / repo / contract.SRC_DIR
    return _compare(original, work) if original.is_dir() and work.is_dir() else None


def pinned_version(requirements: Path, package: str) -> str | None:
    """The version `package` is pinned to in a requirements file, or None."""
    wanted = re.sub(r"[-_.]+", "-", package).lower()
    try:
        lines = requirements.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    for line in lines:
        name, pinned, version = line.split("#", 1)[0].strip().partition("==")
        if pinned and re.sub(r"[-_.]+", "-", name.strip()).lower() == wanted and re.fullmatch(r"[0-9][0-9A-Za-z.+!-]{0,40}", version.strip()):
            return version.strip()
    return None


def _text_lines(path: Path) -> list[str] | None:
    """A file's lines, or None for a file that is not text."""
    try:
        return path.read_text(encoding="utf-8").splitlines(keepends=True)
    except (OSError, UnicodeDecodeError):
        return None


def _write_fix_diff(original: Path, src: Path, diff: dict[str, list[str]], target: Path) -> None:
    """fix.diff: src/ against the fleet copy. Empty when nothing was changed."""
    parts: list[str] = []
    for name in sorted(diff["changed"] + diff["added"] + diff["deleted"]):
        before = _text_lines(original / name) if name not in diff["added"] else []
        after = _text_lines(src / name) if name not in diff["deleted"] else []
        if before is None or after is None:
            parts.append(f"Binary files a/{name} and b/{name} differ\n")
            continue
        lines = difflib.unified_diff(before, after, "a/" + name if name not in diff["added"] else "/dev/null",
                                     "b/" + name if name not in diff["deleted"] else "/dev/null")
        parts.append("".join(line if line.endswith("\n") else line + "\n\\ No newline at end of file\n" for line in lines))
    target.write_text("".join(parts)[:MAX_DIFF_BYTES], encoding="utf-8")


def _copy_tree(source: Path, target: Path) -> None:
    """Copy a repository without environments, caches or links."""
    def ignore(directory: str, names: list[str]) -> set[str]:
        return {n for n in names if n in IGNORED_DIRS or n in IGNORED_FILES or n.endswith(IGNORED_SUFFIXES) or n.endswith(".egg-info")
                or (Path(directory) / n).is_symlink()}

    shutil.copytree(source, target, ignore=ignore, symlinks=False)


def _baseline(target: Path, source: Path, proof_dir: Path) -> None:
    """A clean copy with the layout of a repo-run root: src/, proof/ and, later, venv/."""
    _copy_tree(source, target / contract.SRC_DIR)
    if proof_dir.is_dir():
        _copy_tree(proof_dir, target / contract.PROOF_DIR)
    else:
        (target / contract.PROOF_DIR).mkdir(parents=True)
    # Without a config file of its own, pytest would climb to this repository's pyproject.toml.
    (target / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")


def _is_test_file(name: str) -> bool:
    base = PurePosixPath(name).name
    return base.endswith(".py") and (base.startswith("test_") or base.endswith("_test.py") or base == "conftest.py")


def _proof_file(test_id: str) -> PurePosixPath | None:
    """The file part of a proof test id, if it is a plain path to a Python file under proof/."""
    path = PurePosixPath(test_id.split("::", 1)[0])
    if path.is_absolute() or ".." in path.parts or path.suffix != ".py" or not re.fullmatch(r"[A-Za-z0-9._/\[\]:-]+", test_id):
        return None
    if len(path.parts) < 2 or path.parts[0] != contract.PROOF_DIR:
        return None
    return path


def _missing_citations(cited: list, repo_dir: Path) -> list[str]:
    """What is wrong with the cited path. Each file is relative to the repo-run root and must stay inside it."""
    wrong = []
    root = repo_dir.resolve()
    for step in cited:
        file, line = str(step.get("file", "")), step.get("line")
        relative = PurePosixPath(file)
        if relative.is_absolute() or ".." in relative.parts or not file:
            wrong.append(f"{file!r} is not a path inside the run folder")
            continue
        target = (repo_dir / relative).resolve()
        if not target.is_relative_to(root) or not target.is_file():
            wrong.append(f"{file} does not exist")
            continue
        with target.open("rb") as handle:
            count = sum(1 for _ in handle)
        if not isinstance(line, int) or line < 1 or line > count:
            wrong.append(f"{file} has {count} lines, so there is no line {line}")
    return wrong[:8]


# ---------------------------------------------------------------- the worker's installed library


def _squash(name: str) -> str:
    return re.sub(r"[-_.]+", "_", name).lower()


def _library_matches(venv: Path, package: str, wheels: Path) -> tuple[bool, str]:
    """Is `package` in the worker's venv/ the wheel from the wheelhouse, file for file?"""
    sites = sorted(venv.glob("lib/python*/site-packages"))
    if not sites:
        return False, "venv/ has no site-packages folder"
    site = sites[0]
    # A folder is named <package>-<version>.dist-info.
    installed = [d.name[: -len(".dist-info")] for d in site.glob("*.dist-info")]
    installed = [stem for stem in installed if _squash(stem.rpartition("-")[0]) == _squash(package)]
    if not installed:
        return False, f"{package} is not installed in the worker's venv/"
    version = installed[0].rpartition("-")[2]
    found = [w for w in wheels.glob("*.whl") if _squash(w.name.split("-", 1)[0]) == _squash(package) and w.name.split("-")[1] == version]
    if not found:
        return False, f"the wheelhouse has no wheel for {package} {version}"
    different = []
    with zipfile.ZipFile(found[0]) as wheel:
        for member in wheel.namelist():
            if member.endswith("/") or ".dist-info/" in member:
                continue
            target = site / member
            if not target.is_file() or target.is_symlink() or target.read_bytes() != wheel.read(member):
                different.append(member)
    if different:
        return False, f"{len(different)} file(s) of {package} {version} differ from the wheel: " + ", ".join(different[:4])
    return True, f"{package} {version} in venv/ matches {found[0].name}"


# ---------------------------------------------------------------- environments and pytest


class _Log:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.handle = path.open("w", encoding="utf-8")

    def write(self, title: str, text: str = "") -> None:
        self.handle.write(f"## {title}\n{text[-4000:]}\n\n")
        self.handle.flush()

    def close(self) -> None:
        self.handle.close()


def _requirements(path: Path) -> tuple[list[str], list[str]]:
    """Plain `name==version` lines only. Anything else could run code at install time."""
    wanted, refused = [], []
    for raw in path.read_text(encoding="utf-8").splitlines() if path.is_file() else []:
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        (wanted if _REQUIREMENT.match(line) else refused).append(line)
    return wanted, refused


def _make_env(baseline: Path, wheels: Path, extra: list[str], log: _Log) -> tuple[bool, str]:
    """Build <baseline>/venv offline from <baseline>/src/requirements.txt, then install `extra` over it."""
    requirements = baseline / contract.SRC_DIR / "requirements.txt"
    wanted, refused = _requirements(requirements)
    if refused:
        return False, "requirements.txt holds lines the gate will not install: " + "; ".join(refused)
    if not wanted:
        return False, f"no requirements found in {_short(requirements)}"
    venv = baseline / contract.VENV_DIR
    python = venv / "bin" / "python"
    uv = shutil.which("uv")
    offline = ["--no-index", "--find-links", str(wheels), "--only-binary", ":all:"]
    if uv:
        commands = [[uv, "venv", "--quiet", "--python", config.python_version(), str(venv)]]
        commands += [[uv, "pip", "install", "--quiet", "--offline", "--python", str(python), *offline, *batch] for batch in (wanted, extra) if batch]
    else:
        commands = [[sys.executable, "-m", "venv", str(venv)]]
        commands += [[str(python), "-m", "pip", "install", "--quiet", *offline, *batch] for batch in (wanted, extra) if batch]
    for command in commands:
        try:
            done = subprocess.run(command, capture_output=True, text=True, timeout=INSTALL_TIMEOUT, env=_plain_env(baseline, keep_home=True))
        except (OSError, subprocess.TimeoutExpired) as error:
            log.write(" ".join(command), str(error))
            return False, f"could not build the environment: {error}"
        log.write(" ".join(command), done.stdout + done.stderr)
        if done.returncode != 0:
            return False, f"install failed (exit {done.returncode}): {(done.stderr or done.stdout).strip()[-300:]}"
    return True, "installed offline from the wheelhouse: " + ", ".join(wanted + extra)


def _plain_env(baseline: Path, *, keep_home: bool = False) -> dict[str, str]:
    """No inherited secrets. Tests get a throwaway HOME; the installer keeps the real one for its cache."""
    return {
        "PATH": os.pathsep.join(["/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin", str(Path(shutil.which("uv") or "/usr/bin/uv").parent)]),
        "HOME": os.environ.get("HOME", str(baseline)) if keep_home else str(baseline),
        "LANG": "C.UTF-8",
        "TMPDIR": os.environ.get("TMPDIR", "/tmp"),
    }


def _run_pytest(baseline: Path, args: list[str], sandbox: Path | None, log: _Log) -> tuple[int | None, str]:
    """Run pytest with the baseline as the working directory, as the contract pins it.

    Returns the exit code (0 passed, 1 a test failed, anything else means it did not run cleanly) and the output.
    """
    quoted = " ".join(shlex.quote(a) for a in args)
    inner = f"cd {shlex.quote(str(baseline))} && PYTHONDONTWRITEBYTECODE=1 {contract.VENV_DIR}/bin/python -m pytest -p no:cacheprovider -q {quoted}"
    env = _plain_env(baseline)
    if sandbox is not None:
        command = [str(sandbox), inner]
        env["SANDBOX_WORKDIR"] = str(baseline)
    else:
        command = ["/bin/bash", "-c", inner]
    try:
        done = subprocess.run(command, capture_output=True, text=True, timeout=PYTEST_TIMEOUT, env=env, cwd=baseline)
    except subprocess.TimeoutExpired:
        log.write(inner, f"timed out after {PYTEST_TIMEOUT} s")
        return None, ""
    except OSError as error:
        log.write(inner, str(error))
        return None, ""
    log.write(f"{inner}\n(exit {done.returncode})", done.stdout + done.stderr)
    return done.returncode, done.stdout


def _suite(baseline: Path, sandbox: Path | None, log: _Log) -> dict[str, str] | None:
    """The outcome of every test of the repository itself, by test name. None if the suite did not run cleanly."""
    report = baseline / "suite.xml"
    code, _ = _run_pytest(baseline, [contract.SRC_DIR, f"--junitxml={report.name}"], sandbox, log)
    if code not in (0, 1, 5):  # 5: no test was collected
        return None
    outcomes: dict[str, str] = {}
    try:
        for case in ElementTree.parse(report).getroot().iter("testcase"):
            name = f"{case.get('classname', '')}::{case.get('name', '')}"
            kinds = {child.tag for child in case}
            outcomes[name] = "failed" if kinds & {"failure", "error"} else "skipped" if "skipped" in kinds else "passed"
    except (OSError, ElementTree.ParseError):
        return None if code != 5 else {}
    return outcomes


def _compare_suites(before: dict[str, str] | None, after: dict[str, str] | None) -> tuple[bool, str]:
    if before is None or after is None:
        which = "vulnerable" if before is None else "fixed"
        return False, f"the repository's own tests did not run cleanly on the {which} baseline"

    def counts(outcomes: dict[str, str]) -> str:
        return f"{sum(o == 'passed' for o in outcomes.values())} passed / {sum(o == 'failed' for o in outcomes.values())} failed"

    broken = sorted(name for name, outcome in before.items() if outcome == "passed" and after.get(name) != "passed")
    detail = f"{counts(before)} on vulnerable, {counts(after)} on fixed"
    return not broken, detail + ("; passed before and not after: " + ", ".join(broken[:5]) if broken else "")


def _codes(codes: dict[str, int | None], expectation: str) -> str:
    return "; ".join(f"{test_id} exited {code}" for test_id, code in codes.items()) + f" ({expectation})"


# ---------------------------------------------------------------- schema


def _schema_errors(claim: dict) -> list[str]:
    errors = sorted(schemas.validator("verdict").iter_errors(claim), key=lambda e: list(e.absolute_path))
    return [f"{'/'.join(map(str, e.absolute_path)) or '<root>'}: {e.message}"[:200] for e in errors][:8]
