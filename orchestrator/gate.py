"""The rules gate. There is no model in here.

An agent's verdict is a claim. Before a claim may be shown, the gate re-runs it on clean copies
that the agent never touched:

    vulnerable state = the repository as the fleet holds it, plus the files the agent added
    fixed state      = the agent's work copy (for "affected_fixed"), with its dependencies

Rules for "affected_proven" and "affected_fixed":
    proof_fails_on_vulnerable   every proof test fails on the vulnerable state
    proof_passes_on_fixed       every proof test passes on the fixed state
    suite_passes_after_fix      the whole suite passes on the fixed state ("affected_fixed")
    test_count_never_drops      the fixed state collects at least as many tests as the original
    existing_tests_untouched    no test file that was there before was changed or deleted
Rules for "not_affected":
    no_diff                     the work copy is the original, file for file
    path_cited                  the verdict cites the code path it followed

The gate can change a verdict to "needs_human" and to nothing else. It builds its own
environments from the wheelhouse, so an agent that edited its installed library gains nothing.
Agent-written tests run through track A's sandbox wrapper; without the wrapper the gate refuses
to run them unless LE_CHONK_ALLOW_UNSANDBOXED=1, which is for tests against stand-in agents.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path, PurePosixPath
from typing import Any, Callable

import jsonschema
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from orchestrator import config, events, kbscan

SCHEMA_PATH = config.REPO_ROOT / "schema" / "verdict.schema.json"
IGNORED_DIRS = {".venv", "__pycache__", ".pytest_cache", ".git", ".mypy_cache", ".ruff_cache", "node_modules"}
IGNORED_FILES = {".DS_Store"}
IGNORED_SUFFIXES = (".pyc", ".pyo")
PYTEST_TIMEOUT = 180
INSTALL_TIMEOUT = 300
# A proof for "affected_proven" has no fix to pass on. The gate still tries it on the library's
# fixed version and records the result, but does not downgrade on it. Set True to enforce.
ENFORCE_FIXED_PASS_FOR_PROVEN = False

_PACKAGE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,80}$")
_REQUIREMENT = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._-]*(\[[A-Za-z0-9._,-]+\])?"
    r"(\s*(==|>=|<=|~=|!=|<|>)\s*[A-Za-z0-9.*+!_-]+(\s*,\s*(==|>=|<=|~=|!=|<|>)\s*[A-Za-z0-9.*+!_-]+)*)?$"
)
_COLLECTED = re.compile(r"^(\d+) tests? collected", re.M)

RULE_LABELS = {
    "schema_valid": "The verdict has the agreed shape",
    "work_copy_present": "The original and the work copy are both there",
    "no_diff": "Nothing in the work copy was changed",
    "path_cited": "A code path is cited",
    "wording": 'It says "no reachable path found", never "safe"',
    "existing_tests_untouched": "No earlier test was changed or deleted",
    "no_fix_claimed_no_app_change": "No application file was changed without claiming a fix",
    "proof_listed": "The proof test is in the work copy",
    "package_named": "The advisory names the package",
    "sandbox_available": "The sandbox is there to run agent-written tests in",
    "vulnerable_state_built": "The vulnerable state was built",
    "proof_fails_on_vulnerable": "The proof fails before the fix",
    "fixed_state_built": "The fixed state was built",
    "proof_passes_on_fixed": "The proof passes after the fix",
    "test_count_never_drops": "No test disappeared",
    "suite_passes_after_fix": "The whole suite passes after the fix",
    "gate_error": "The gate ran without an error of its own",
}
VERDICTS = ("not_affected", "affected_proven", "affected_fixed", "needs_human")
MEASURED = {"vulnerable_state_built", "proof_fails_on_vulnerable", "fixed_state_built", "proof_passes_on_fixed", "test_count_never_drops", "suite_passes_after_fix"}


# ---------------------------------------------------------------- the contract


def gate(run_id: str, verdicts: list, *, runs_root: str | Path = "runs", wheelhouse: str | Path = "wheelhouse") -> list:
    """Fill each verdict's "gate" from the gate's own re-runs. May only downgrade to "needs_human".

    Each gated verdict is also written to runs/<run_id>/<repo>/verdict.json, where the grid reads
    it. The agent's own file is kept beside it as verdict.agent.json.
    """
    run_dir = config.run_dir(run_id, runs_root)
    wheels = Path(wheelhouse) if Path(wheelhouse).is_absolute() else config.REPO_ROOT / wheelhouse
    gated = []
    for verdict in verdicts:
        if not isinstance(verdict, dict):
            verdict = {"repo": "", "verdict": "needs_human", "reason": "The worker returned no verdict object."}
        try:
            result = _gate_one(run_dir, verdict, wheels)
        except Exception as error:  # a broken claim must never take the run down
            result = _fail_closed(verdict, f"{type(error).__name__}: {error}")
            events.append(run_dir, "gate", "The gate hit an error of its own. The claim goes to a person.", repo=_repo_name(verdict), kind="fail")
        _persist(run_dir, result)
        gated.append(result)
    _apply_sim_triage(run_dir, gated)
    return gated


def _apply_sim_triage(run_dir: Path, gated: list) -> None:
    """The adversarial simulator's feedback (tools/scan/patches/gate-sim-triage.patch.md).

    runs/<run_id>/sim-triage.json is untrusted input: it is read size-capped (kbscan does that)
    and a malformed file changes nothing. When the simulator flagged an advisory as a gate rule
    that a human has not reviewed, every verdict claiming that advisory is downgraded to
    "needs_human" — the only change the gate may ever make.
    """
    sim = kbscan.sim_triage_for_run(run_dir.name, run_dir.parent)
    if not sim:
        return
    defenses = sim.get("defenses") or {}
    breaches = defenses.get("breaches") or []
    if not isinstance(breaches, list):
        breaches = []
    feedback = sim.get("feedback") or {}
    entries = feedback.get("entries") if isinstance(feedback, dict) else None
    flagged = set()
    if isinstance(entries, list):
        for entry in entries:
            if (
                isinstance(entry, dict)
                and entry.get("type") == "gate-rule"
                and isinstance(entry.get("advisory_id"), str)
                and not entry.get("human_reviewed")
            ):
                flagged.add(entry["advisory_id"])
    if not flagged:
        return
    for verdict in gated:
        advisory = verdict.get("advisory") or {}
        if isinstance(advisory, dict) and advisory.get("id") in flagged and verdict.get("verdict") != "needs_human":
            verdict["gate"] = {**(verdict.get("gate") or {}),
                               "sim_triage": f"downgraded: adversarial sim breach ({len(breaches)} breach(es))"}
            verdict["verdict"] = "needs_human"
            events.append(run_dir, "gate", "The adversarial simulator flagged this advisory; the claim goes to a person.",
                          repo=_repo_name(verdict), kind="fail")


# ---------------------------------------------------------------- one verdict


class _Rules:
    def __init__(self, say: Callable[..., None] | None = None) -> None:
        self.rules: dict[str, dict[str, Any]] = {}
        self.say = say or (lambda *args, **kwargs: None)

    def add(self, name: str, passed: bool | None, detail: str = "", *, enforced: bool = True) -> bool:
        self.rules[name] = {"passed": passed, "enforced": enforced, "detail": detail[:800]}
        label = RULE_LABELS.get(name, name)
        if passed is True:
            # A passed rule's detail is repeated only where it holds a measurement.
            self.say(f"{label}: {detail[:240]}." if name in MEASURED and detail else f"{label}.", "ok", rule=name)
        else:
            self.say(f"{label}: NO{'' if enforced else ' (recorded, not enforced)'}. {detail[:240]}".strip(), "fail" if enforced else "info", rule=name)
        return bool(passed)

    def all_passed(self) -> bool:
        return all(rule["passed"] is True for rule in self.rules.values() if rule["enforced"])


def _short(path: Path) -> str:
    """A path as a person would say it: from the repository root when it is inside it."""
    try:
        return path.resolve().relative_to(config.REPO_ROOT.resolve()).as_posix()
    except ValueError:
        return "/".join(path.parts[-3:])


def _repo_name(verdict: dict) -> str | None:
    try:
        return config.check_name(verdict.get("repo"), "repository name")
    except ValueError:
        return None


def _gate_one(run_dir: Path, verdict: dict, wheels: Path) -> dict:
    repo_name = _repo_name(verdict)

    def say(text: str, kind: str = "step", **data: Any) -> None:
        events.append(run_dir, "gate", text, repo=repo_name, kind=kind, **data)

    rules = _Rules(say)
    claimed = verdict.get("verdict")
    sandboxed = None
    claim_name = claimed if claimed in VERDICTS else "an unknown verdict"
    if claimed == "needs_human":
        say("The worker asked for a person. There is no claim to re-run.", "start")
    else:
        say(f"The gate starts on a claim of {claim_name}. It trusts nothing in it and re-runs everything itself.", "start")

    schema_errors = _schema_errors(verdict)
    rules.add("schema_valid", not schema_errors, "; ".join(schema_errors))

    if not schema_errors and claimed != "needs_human":
        repo = config.check_name(verdict["repo"], "repository name")
        original = config.fleet_root() / repo
        src = run_dir / repo / "src"
        if rules.add("work_copy_present", original.is_dir() and src.is_dir(), f"original: {_short(original)}, work copy: {_short(src)}"):
            diff = _compare(original, src)
            if claimed == "not_affected":
                _check_not_affected(rules, verdict, diff)
            else:
                sandboxed = _check_affected(rules, verdict, diff, original, src, run_dir / repo / "gate", wheels, say)

    passed = rules.all_passed()
    failed = [name for name, rule in rules.rules.items() if rule["enforced"] and rule["passed"] is not True]
    if claimed == "needs_human":
        say("Gate finished: it stays with a person.", "done", passed=passed)
    elif passed:
        say(f"Gate finished: the claim of {claim_name} stands.", "done", passed=True)
    else:
        say(f"Gate finished: the claim of {claim_name} is rejected. It goes to a person. Failed: {', '.join(failed)}.", "done", passed=False)
    result = dict(verdict)
    if not passed and claimed != "needs_human":
        result["verdict"] = "needs_human"
    result["gate"] = {
        "passed": passed,
        "original_verdict": claimed,
        "checked_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "sandboxed": sandboxed,
        "rules": rules.rules,
    }
    return result


def _fail_closed(verdict: dict, detail: str) -> dict:
    result = dict(verdict)
    claimed = result.get("verdict")
    result["verdict"] = "needs_human"
    result["gate"] = {
        "passed": False,
        "original_verdict": claimed,
        "checked_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "sandboxed": None,
        "rules": {"gate_error": {"passed": False, "enforced": True, "detail": detail[:800]}},
    }
    return result


def _check_not_affected(rules: _Rules, verdict: dict, diff: dict[str, list[str]]) -> None:
    touched = [f"{kind}: {name}" for kind in ("changed", "deleted", "added") for name in diff[kind]]
    rules.add("no_diff", not touched, "; ".join(touched) or "the work copy matches the original")
    rules.add("path_cited", bool(verdict.get("path")), "the verdict must cite the code path it followed")
    reason = str(verdict.get("reason", "")).lower()
    worded = "no reachable path found" in reason and not re.search(r"\bsafe\b", reason)
    rules.add("wording", worded, 'say "no reachable path found", never "safe"', enforced=False)


def _check_affected(rules: _Rules, verdict: dict, diff: dict[str, list[str]], original: Path, src: Path, gate_dir: Path, wheels: Path,
                    say: Callable[..., None] = lambda *args, **kwargs: None) -> bool | None:
    claimed = verdict["verdict"]
    package = str(verdict["advisory"].get("package", ""))
    proofs = [str(test_id) for test_id in verdict.get("proof", [])]

    touched_tests = [name for name in diff["changed"] + diff["deleted"] if _is_test_file(name)]
    rules.add("existing_tests_untouched", not touched_tests, "; ".join(touched_tests) or "no earlier test file was changed or deleted")
    if claimed == "affected_proven":
        app_changes = [name for name in diff["changed"] + diff["deleted"] if not _is_test_file(name)]
        rules.add("no_fix_claimed_no_app_change", not app_changes, "; ".join(app_changes), enforced=False)

    bad_proofs = [test_id for test_id in proofs if _proof_file(test_id) is None or not (src / _proof_file(test_id)).is_file()]
    if not rules.add("proof_listed", bool(proofs) and not bad_proofs, "no proof test listed" if not proofs else "; ".join(f"not a test in the work copy: {p}" for p in bad_proofs)):
        return None
    if not rules.add("package_named", bool(_PACKAGE.match(package)), f"advisory package: {package!r}"):
        return None

    wrapper = config.sandbox_wrapper()
    sandbox = wrapper if wrapper.is_file() else None
    if sandbox is None and not config.allow_unsandboxed():
        rules.add("sandbox_available", False, f"{wrapper} not found; the gate will not run agent-written tests outside the sandbox")
        return None

    if gate_dir.exists():
        shutil.rmtree(gate_dir)
    log = _Log(gate_dir / "log.txt")
    try:
        # --- vulnerable state: the fleet's copy, then the files the agent added
        vulnerable = gate_dir / "vulnerable"
        say("Building the vulnerable state: the fleet's own copy, with its own requirements, installed offline.")
        _copy_tree(original, vulnerable)
        ok, detail = _make_env(vulnerable, vulnerable / "requirements.txt", wheels, [], log)
        if not rules.add("vulnerable_state_built", ok, detail):
            return sandbox is not None
        count_before = _collect_count(vulnerable, sandbox, log)
        for name in diff["added"]:
            target = vulnerable / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src / name, target)
        say(f"Running the proof on the vulnerable state{'' if sandbox else ' (no sandbox: allowed for the stand-in only)'}.")
        codes = {test_id: _pytest(vulnerable, [test_id], sandbox, log) for test_id in proofs}
        rules.add("proof_fails_on_vulnerable", all(code == 1 for code in codes.values()), _codes(codes, "a failing test exits 1"))

        # --- fixed state
        fixed = gate_dir / "fixed"
        if claimed == "affected_fixed":
            _copy_tree(src, fixed)
            fix = verdict.get("fix") or {}
            target_version = str(fix.get("target", "")) if fix.get("kind") == "upgrade" else ""
            extra = [f"{package}=={target_version}"] if _is_version(target_version) else []
        else:
            _copy_tree(vulnerable, fixed)
            newest = _newest_fixed(package, str(verdict["advisory"].get("affected_range", "")), wheels)
            extra = [f"{package}=={newest}"] if newest else []
        say("Building the fixed state: " + ("the agent's work copy" if claimed == "affected_fixed" else "the vulnerable state")
            + (f" with {extra[0]}" if extra else "") + ", installed offline.")
        ok, detail = _make_env(fixed, fixed / "requirements.txt", wheels, extra, log)
        enforce_fixed = claimed == "affected_fixed" or ENFORCE_FIXED_PASS_FOR_PROVEN
        if not rules.add("fixed_state_built", ok, detail, enforced=enforce_fixed):
            return sandbox is not None
        say("Running the proof on the fixed state.")
        codes = {test_id: _pytest(fixed, [test_id], sandbox, log) for test_id in proofs}
        rules.add("proof_passes_on_fixed", all(code == 0 for code in codes.values()), _codes(codes, "a passing test exits 0"), enforced=enforce_fixed)

        count_after = _collect_count(fixed, sandbox, log)
        claims = verdict.get("suite") or {}
        claim_before, claim_after = _total(claims.get("before")), _total(claims.get("after"))
        claims_ok = claim_before is None or claim_after is None or claim_after >= claim_before
        rules.add(
            "test_count_never_drops",
            count_before is not None and count_after is not None and count_after >= count_before and claims_ok,
            f"collected {count_before} before and {count_after} after; the verdict claims {claim_before} before and {claim_after} after",
        )
        if claimed == "affected_fixed":
            say("Running the whole test suite on the fixed state.")
            code = _pytest(fixed, [], sandbox, log)
            rules.add("suite_passes_after_fix", code == 0, f"the whole suite exited {code} on the fixed state")
    finally:
        for state in ("vulnerable", "fixed"):  # the environments are large and rebuilt every time
            shutil.rmtree(gate_dir / state / ".venv", ignore_errors=True)
        log.close()
    return sandbox is not None


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
    """What the worker changed, deleted and added in its work copy. None if either folder is missing."""
    original = config.fleet_root() / config.check_name(repo, "repository name")
    work = config.run_dir(run_id, runs_root) / repo / "src"
    return _compare(original, work) if original.is_dir() and work.is_dir() else None


def _copy_tree(source: Path, target: Path) -> None:
    """Copy a repository without environments and caches."""
    def ignore(directory: str, names: list[str]) -> set[str]:
        return {n for n in names if n in IGNORED_DIRS or n in IGNORED_FILES or n.endswith(IGNORED_SUFFIXES) or n.endswith(".egg-info")}

    shutil.copytree(source, target, ignore=ignore, symlinks=False)
    # Without a config file of its own, pytest would climb to this repository's pyproject.toml.
    if not any((target / name).is_file() for name in ("pytest.ini", "pyproject.toml", "tox.ini", "setup.cfg")):
        (target / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")


def _is_test_file(name: str) -> bool:
    base = PurePosixPath(name).name
    return base.endswith(".py") and (base.startswith("test_") or base.endswith("_test.py") or base == "conftest.py")


def _proof_file(test_id: str) -> PurePosixPath | None:
    """The file part of a pytest test id, if it is a plain relative path to a Python file."""
    path = PurePosixPath(test_id.split("::", 1)[0])
    if path.is_absolute() or ".." in path.parts or path.suffix != ".py" or not re.fullmatch(r"[A-Za-z0-9._/\[\]:-]+", test_id):
        return None
    return path


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


def _make_env(state: Path, requirements: Path, wheels: Path, extra: list[str], log: _Log) -> tuple[bool, str]:
    wanted, refused = _requirements(requirements)
    if refused:
        return False, "requirements.txt holds lines the gate will not install: " + "; ".join(refused)
    if not wanted:
        return False, f"no requirements found in {requirements}"
    venv = state / ".venv"
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
            done = subprocess.run(command, capture_output=True, text=True, timeout=INSTALL_TIMEOUT, env=_plain_env(state, keep_home=True))
        except (OSError, subprocess.TimeoutExpired) as error:
            log.write(" ".join(command), str(error))
            return False, f"could not build the environment: {error}"
        log.write(" ".join(command), done.stdout + done.stderr)
        if done.returncode != 0:
            return False, f"install failed (exit {done.returncode}): {(done.stderr or done.stdout).strip()[-300:]}"
    return True, "installed offline from the wheelhouse: " + ", ".join(wanted + extra)


def _plain_env(state: Path, *, keep_home: bool = False) -> dict[str, str]:
    """No inherited secrets. Tests get a throwaway HOME; the installer keeps the real one for its cache."""
    return {
        "PATH": os.pathsep.join(["/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin", str(Path(shutil.which("uv") or "/usr/bin/uv").parent)]),
        "HOME": os.environ.get("HOME", str(state)) if keep_home else str(state),
        "LANG": "C.UTF-8",
        "TMPDIR": os.environ.get("TMPDIR", "/tmp"),
    }


def _pytest(state: Path, args: list[str], sandbox: Path | None, log: _Log) -> int | None:
    """Exit code of pytest in `state`: 0 passed, 1 a test failed, anything else means it did not run cleanly."""
    return _run_pytest(state, args, sandbox, log)[0]


def _run_pytest(state: Path, args: list[str], sandbox: Path | None, log: _Log) -> tuple[int | None, str]:
    python = state / ".venv" / "bin" / "python"
    quoted = " ".join(shlex.quote(a) for a in args)
    inner = f"cd {shlex.quote(str(state))} && PYTHONDONTWRITEBYTECODE=1 {shlex.quote(str(python))} -m pytest -p no:cacheprovider -q {quoted}"
    env = _plain_env(state)
    if sandbox is not None:
        command = [str(sandbox), inner]
        env["SANDBOX_WORKDIR"] = str(state)
    else:
        command = ["/bin/bash", "-c", inner]
    try:
        done = subprocess.run(command, capture_output=True, text=True, timeout=PYTEST_TIMEOUT, env=env, cwd=state)
    except subprocess.TimeoutExpired:
        log.write(inner, f"timed out after {PYTEST_TIMEOUT} s")
        return None, ""
    except OSError as error:
        log.write(inner, str(error))
        return None, ""
    log.write(f"{inner}\n(exit {done.returncode})", done.stdout + done.stderr)
    return done.returncode, done.stdout


def _collect_count(state: Path, sandbox: Path | None, log: _Log) -> int | None:
    code, output = _run_pytest(state, ["--collect-only"], sandbox, log)
    if code not in (0, 5):
        return None
    match = _COLLECTED.search(output)
    return int(match.group(1)) if match else 0


def _codes(codes: dict[str, int | None], expectation: str) -> str:
    return "; ".join(f"{test_id} exited {code}" for test_id, code in codes.items()) + f" ({expectation})"


def _total(counts: Any) -> int | None:
    if isinstance(counts, dict) and isinstance(counts.get("passed"), int) and isinstance(counts.get("failed"), int):
        return counts["passed"] + counts["failed"]
    return None


def _is_version(text: str) -> bool:
    try:
        Version(text)
    except InvalidVersion:
        return False
    return True


def _newest_fixed(package: str, affected_range: str, wheels: Path) -> str | None:
    """The newest version of the package in the wheelhouse that is outside the affected range."""
    try:
        affected = SpecifierSet(affected_range.replace(" ", ""))
    except InvalidSpecifier:
        affected = None
    versions = []
    prefix = re.sub(r"[-_.]+", "_", package).lower() + "-"
    for wheel in wheels.glob("*.whl"):
        name = re.sub(r"[-_.]+", "_", wheel.name.split("-", 1)[0]).lower() + "-"
        if name != prefix:
            continue
        try:
            version = Version(wheel.name.split("-")[1])
        except (InvalidVersion, IndexError):
            continue
        if affected is None or version not in affected:
            versions.append(version)
    return str(max(versions)) if versions else None


# ---------------------------------------------------------------- schema and files


def _schema_errors(verdict: dict) -> list[str]:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    claim = {key: value for key, value in verdict.items() if key not in ("gate", "usage")}
    validator = jsonschema.Draft202012Validator(schema)
    return [f"{'/'.join(map(str, e.path)) or '<root>'}: {e.message}"[:200] for e in sorted(validator.iter_errors(claim), key=lambda e: list(e.path))][:8]


def _persist(run_dir: Path, verdict: dict) -> None:
    try:
        repo_dir = run_dir / config.check_name(verdict.get("repo"), "repository name")
    except ValueError:
        return
    repo_dir.mkdir(parents=True, exist_ok=True)
    final = repo_dir / "verdict.json"
    kept = repo_dir / "verdict.agent.json"
    if final.is_file() and not kept.exists():
        shutil.copy2(final, kept)
    temporary = repo_dir / "verdict.json.tmp"
    temporary.write_text(json.dumps(verdict, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(temporary, final)
