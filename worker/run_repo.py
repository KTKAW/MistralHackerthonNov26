"""The per-repository worker: one sandboxed, headless Vibe process on a fresh copy of one repository.

    run_repo(run_id, repo, *, fleet_root="fleet", runs_root="runs", vibe_home="vibe-home", heartbeat_fn=None)
        -> {"repo": repo, "rc": <exit code>, "verdict": <verdict.json as a dict, or None>, "export": <vibe/export.json, or {}>}

What it does, in order:

  1. checks the names and reads the run's facts from runs/<run>/advisory.json (no defaults);
  2. empties runs/<run>/<repo>/ (everything except the orchestrator's state.json) and builds the
     contract layout there: src/ (work copy), proof/, venv/ (offline, from the wheelhouse);
  3. writes proof/conftest.py, pytest.ini and vibe/prompt.md;
  4. starts Vibe headless, in its own process group, with the environment the sandbox hooks need,
     and reports progress through heartbeat_fn (what the hooks logged, never the agent's prose);
  5. stops the whole process group, whatever happened, and returns what the agent left on disk.

It never writes or repairs verdict.json: a missing or invalid file is returned as None.
It never writes state.json, fix.diff or gate/: the orchestrator and the gate own those.
The layout and the file names come from docs/contract.md (vulnerability_agent.contract).
"""
from __future__ import annotations

import json
import os
import re
import shutil
import signal
import string
import subprocess
import sys
import threading
import time
import tomllib
from pathlib import Path
from typing import Any, Callable

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

REPO_ROOT = Path(__file__).resolve().parent.parent

try:
    from vulnerability_agent import contract, runs, schemas
except ModuleNotFoundError:  # the package lives in src/ and is not always installed into the venv
    sys.path.insert(0, str(REPO_ROOT / "src"))
    from vulnerability_agent import contract, runs, schemas

from worker.setup_vibe_home import ENABLED_TOOLS, WEB_TOOLS

SANDBOX_DIR = REPO_ROOT / "sandbox"
PROMPT_TEMPLATE = Path(__file__).with_name("prompt.md")
VIBE_CHILD = Path(__file__).with_name("vibe_child.py")

# The limits from the design (PROJECT.md, "The Vibe command each activity runs").
MAX_TURNS = 80
MAX_PRICE = 3
TIME_LIMIT_SECONDS = 560
# Vibe stops itself at the time limit and writes its export. If it has not exited this many
# seconds after that, the worker stops it.
HARD_STOP_AFTER_SECONDS = 30
TERM_GRACE_SECONDS = 15  # between SIGTERM and SIGKILL
HEARTBEAT_SECONDS = 10.0
DEFAULT_MODEL = "mistral-large-4-0"
DEFAULT_PYTHON = "3.12"  # the Python the wheelhouse was built for
MAX_LINES_PER_BEAT = 8  # tool calls reported per heartbeat; the rest is summed up in one line
LINE_CHARS = 120
SETUP_HINT = "run `python -m worker.setup_vibe_home` first"

# A run id or a repository name becomes a folder name.
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,80}$")
_RESERVED = frozenset({contract.RUN_JSON, contract.ADVISORY_JSON, contract.EARLY_WARNING_MD})
# One requirement line the worker accepts: a plain pin, nothing else.
_PIN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*==[A-Za-z0-9][A-Za-z0-9.!+_-]*$")
# The advisory's facts are written into the prompt. They come from a model that read pasted text,
# so each one must look like what it claims to be before it gets there.
_FACT_PATTERNS = {
    "advisory_id": re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$"),
    "package": re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]{0,98}[A-Za-z0-9])?$"),
    "affected_version_range": re.compile(r"^[A-Za-z0-9.,<>=!~*+ -]{1,100}$"),
    "fixed_version": re.compile(r"^[A-Za-z0-9.!+_-]{1,60}$"),
    "flawed_function": re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*){0,15}$"),
}
_READ_TOOLS = frozenset({"file_system.read_file"})
_WRITE_TOOLS = frozenset({"file_system.write_file", "file_system.edit"})

CONFTEST = '''"""Written by the worker, not by the agent. Makes the application importable from proof tests."""
import sys
from pathlib import Path

_RUN_ROOT = Path(__file__).resolve().parent.parent
for _folder in (_RUN_ROOT / "src", _RUN_ROOT / "src" / "src"):
    if str(_folder) not in sys.path:
        sys.path.insert(0, str(_folder))
'''

PYTEST_INI = """# Written by the worker. With this file here, pytest takes this folder as its root and does not
# climb to the pyproject.toml of the repository that holds the runs.
[pytest]
addopts = -p no:cacheprovider
"""


# ---------------------------------------------------------------- small helpers


def check_name(value: object, what: str) -> str:
    if not isinstance(value, str) or not _NAME.match(value) or ".." in value or value in _RESERVED:
        raise ValueError(f"not a usable {what}: {value!r}")
    return value


def _resolve(path: str | os.PathLike[str]) -> Path:
    """An absolute path as given; a relative one from the repository root."""
    path = Path(path)
    return path if path.is_absolute() else REPO_ROOT / path


def _real(path: str | os.PathLike[str]) -> Path:
    return Path(os.path.realpath(path))


def _is_inside(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def wheelhouse_dir() -> Path:
    return _resolve(os.environ.get("LE_CHONK_WHEELHOUSE", str(REPO_ROOT / "wheelhouse")))


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


# ---------------------------------------------------------------- the run's facts


def read_advisory(run_root: Path) -> dict:
    """The five facts from runs/<run>/advisory.json. No file, no run: there are no defaults."""
    path = run_root / contract.ADVISORY_JSON
    if not path.is_file():
        raise FileNotFoundError(f"{path} is missing. The advisory reader writes it before any agent starts.")
    facts = _read_json(path)
    try:
        schemas.validate(facts, "advisory")
    except schemas.ValidationError as error:
        raise ValueError(f"{path} does not match the advisory schema: {error.message}") from None
    for key, pattern in _FACT_PATTERNS.items():
        if not pattern.match(facts[key]):
            raise ValueError(f"{path}: {key} does not look like a value that can go into the prompt: {facts[key]!r}")
    try:
        SpecifierSet(facts["affected_version_range"])
        Version(facts["fixed_version"])
    except (InvalidSpecifier, InvalidVersion) as error:
        raise ValueError(f"{path}: {error}") from None
    return facts


def render_prompt(facts: dict, repo_run: Path, wheelhouse: Path, python_version: str) -> str:
    template = string.Template(PROMPT_TEMPLATE.read_text(encoding="utf-8"))
    return template.substitute(
        advisory_id=facts["advisory_id"],
        package=facts["package"],
        affected_version_range=facts["affected_version_range"],
        fixed_version=facts["fixed_version"],
        flawed_function=facts["flawed_function"],
        run_root=str(repo_run),
        wheelhouse=str(wheelhouse),
        python_version=python_version,
    )


# ---------------------------------------------------------------- the repo-run root


def reset_repo_run(repo_run: Path) -> None:
    """One attempt, on a fresh copy: remove what a previous attempt left, except state.json."""
    if repo_run.is_symlink() or (repo_run.exists() and not repo_run.is_dir()):
        raise ValueError(f"{repo_run} is not a plain folder")
    if not repo_run.is_dir():
        return
    for child in repo_run.iterdir():
        if child.name == contract.STATE_JSON:
            continue  # the orchestrator wrote it before calling the worker, and owns it
        if child.is_dir() and not child.is_symlink():
            shutil.rmtree(child)
        else:
            child.unlink()


def check_links_stay_inside(src: Path) -> None:
    """A work copy with a link that leaves it would lead the file tools outside the run folder."""
    root = _real(src)
    for folder, folders, files in os.walk(src):
        for name in (*folders, *files):
            entry = Path(folder) / name
            if entry.is_symlink() and not _is_inside(_real(entry), root):
                raise ValueError(f"the repository holds a link that points outside it: {entry.relative_to(src)}")


def read_pins(requirements: Path) -> list[str]:
    """The pins in requirements.txt. Any line that is not `name==version` is refused, so no
    option, URL or path from the repository reaches the installer."""
    if not requirements.is_file():
        raise FileNotFoundError(f"the repository has no {requirements.name}")
    pins = []
    for number, raw in enumerate(requirements.read_text(encoding="utf-8").splitlines(), start=1):
        line = re.split(r"(^|\s)#", raw, maxsplit=1)[0].strip()
        if not line:
            continue
        if not _PIN.match(line):
            raise ValueError(f"{requirements.name} line {number} is not a plain `name==version` pin")
        pins.append(line)
    return pins


def build_venv(repo_run: Path, pins: list[str], wheelhouse: Path, python_version: str) -> None:
    """venv/ at the repo-run root, filled offline from the wheelhouse."""
    uv = shutil.which("uv")
    if uv is None:
        raise RuntimeError("uv is not on PATH")
    venv = repo_run / contract.VENV_DIR
    env = {key: value for key, value in os.environ.items() if key != "VIRTUAL_ENV"}
    env["UV_PYTHON_DOWNLOADS"] = "never"
    commands = [[uv, "venv", "--quiet", "--python", python_version, str(venv)]]
    if pins:
        commands.append([uv, "pip", "install", "--quiet", "--python", str(venv / "bin" / "python"), "--offline", "--no-index",
                         "--find-links", str(wheelhouse), "--only-binary", ":all:", *pins])
    for command in commands:
        done = subprocess.run(command, cwd=repo_run, env=env, capture_output=True, text=True, timeout=600)
        if done.returncode != 0:
            raise RuntimeError(f"`uv {command[1]}` failed for {repo_run.name}: {done.stderr.strip()[-800:]}")


def prepare(run_id: str, repo: str, fleet: Path, runs_root: Path, wheelhouse: Path, python_version: str) -> tuple[Path, dict]:
    """Build runs/<run>/<repo>/ as the contract describes it. Returns the repo-run root and the facts."""
    run_root = runs.run_dir(runs_root, run_id)
    facts = read_advisory(run_root)
    source = fleet / repo
    if not source.is_dir():
        raise FileNotFoundError(f"no repository named {repo} in the fleet at {fleet}")
    if not wheelhouse.is_dir():
        raise FileNotFoundError(f"the wheelhouse {wheelhouse} is missing (LE_CHONK_WHEELHOUSE)")
    repo_run = runs.repo_run_dir(run_root, repo)
    reset_repo_run(repo_run)
    runs.create_repo_run(run_root, repo)
    src = runs.make_work_copy(source, repo_run)
    check_links_stay_inside(src)
    build_venv(repo_run, read_pins(src / "requirements.txt"), wheelhouse, python_version)
    (repo_run / contract.PROOF_DIR / "conftest.py").write_text(CONFTEST, encoding="utf-8")
    (repo_run / "pytest.ini").write_text(PYTEST_INI, encoding="utf-8")
    vibe_dir = (repo_run / contract.VIBE_EXPORT_JSON).parent
    vibe_dir.mkdir()
    (vibe_dir / "prompt.md").write_text(render_prompt(facts, repo_run, wheelhouse, python_version), encoding="utf-8")
    return repo_run, facts


# ---------------------------------------------------------------- what the agent must not see or change


def deny_read_paths(repo: str, repo_run: Path, runs_root: Path, fleet: Path, wheelhouse: Path) -> list[Path]:
    """Paths the agent must not read: the fleet copy, the answer key, the other repositories' run
    folders, and with them everything else in this repository and every other run.

    The answers are in several places here (orchestrator/stub_answers.json, the test fixtures,
    docs/FLEET.md, older runs of the same repository), so the rule is the other way round: starting
    at the repository root and at the runs folder, every entry is denied unless the run folder or
    the wheelhouse lies inside it.
    """
    needed = [_real(repo_run), _real(wheelhouse)]
    denied: dict[Path, None] = {}

    def holds_something_needed(real: Path) -> bool:
        return any(_is_inside(path, real) for path in needed)

    def deny(path: Path) -> None:
        real = _real(path)
        if not holds_something_needed(real):
            denied[real] = None

    def close_off(top: Path) -> None:
        pending = [_real(top)]
        while pending:
            folder = pending.pop()
            try:
                children = sorted(folder.iterdir())
            except OSError:
                continue
            for child in children:
                real = _real(child)
                if not holds_something_needed(real):
                    denied[real] = None
                elif real.is_dir() and real not in needed:
                    pending.append(real)  # on the way down to the run folder: look at its siblings

    close_off(REPO_ROOT)
    close_off(runs_root)
    deny(fleet)
    deny(REPO_ROOT / "orchestrator" / "tests" / "fixtures" / "fleet_answers")
    deny(REPO_ROOT / "orchestrator" / "stub_answers.json")
    # The other agents of this run may not have created their folders yet. Name them anyway.
    try:
        others = [entry.name for entry in fleet.iterdir() if entry.is_dir() and entry.name != repo]
    except OSError:
        others = []
    for name in others:
        deny(repo_run.parent / name)
    for extra in os.environ.get("LE_CHONK_SANDBOX_DENY_READ", "").split(":"):
        if extra and os.path.isabs(extra):
            deny(Path(extra))
    return list(denied)


def deny_write_paths(repo_run: Path) -> list[Path]:
    """Inside the run folder, what belongs to the orchestrator, the gate and Vibe itself."""
    return [repo_run / name for name in (contract.STATE_JSON, contract.FIX_DIFF, contract.GATE_DIR, "vibe", ".vibe")]


# ---------------------------------------------------------------- Vibe


def check_vibe_home(vibe_home: Path, repo_run: Path) -> None:
    """Refuse to start an agent whose home does not register both sandbox hooks as strict, or
    whose home trusts the run folder.

    Vibe loads .vibe/hooks.toml, .vibe/config.toml and AGENTS.md from a trusted folder, and a hook
    there with the name of one of ours replaces it. The worker never passes --trust, and a headless
    run does not ask, so the run folder is untrusted unless this home's trust list says otherwise.
    """
    try:
        trust = tomllib.loads((vibe_home / "trusted_folders.toml").read_text(encoding="utf-8"))
    except FileNotFoundError:
        trust = {}
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise RuntimeError(f"cannot read {vibe_home / 'trusted_folders.toml'}: {error}") from None
    for entry in trust.get("trusted", []) if isinstance(trust.get("trusted", []), list) else []:
        if isinstance(entry, str) and _is_inside(_real(repo_run), _real(os.path.expanduser(entry))):
            raise RuntimeError(f"{vibe_home / 'trusted_folders.toml'} trusts {entry}, which holds the run folder. "
                               "Remove that entry: the agent's work folder must stay untrusted.")
    try:
        hooks = tomllib.loads((vibe_home / "hooks.toml").read_text(encoding="utf-8")).get("hooks", [])
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise RuntimeError(f"{vibe_home} has no usable hooks.toml ({error}); {SETUP_HINT}") from None
    if not (vibe_home / "config.toml").is_file():
        raise RuntimeError(f"{vibe_home} has no config.toml; {SETUP_HINT}")
    for script in ("sandbox2.py", "path_hook.py"):
        wanted = str(SANDBOX_DIR / script)
        if not any(isinstance(hook, dict) and hook.get("type") == "pre_tool" and hook.get("strict") is True
                   and hook.get("match", "*") == "*" and wanted in str(hook.get("command", "")) for hook in hooks):
            raise RuntimeError(f"{vibe_home / 'hooks.toml'} does not register {wanted} as a strict pre_tool hook; {SETUP_HINT}")


def vibe_command(repo_run: Path, model: str) -> list[str]:
    """The command line from the design, with two changes (docs/AGENT.md gives the reasons):
    no --trust, and an allow-list of tools in front of the two web tools the design turns off."""
    vibe_dir = (repo_run / contract.VIBE_EXPORT_JSON).parent
    command = [
        "vibe",
        "--workdir", str(repo_run),
        "--prompt-file", str(vibe_dir / "prompt.md"),
        "--model", model,
        "--output", "text", "--output-dir", str(vibe_dir),
        "--max-turns", str(MAX_TURNS), "--max-price", str(MAX_PRICE), "--time-limit", str(TIME_LIMIT_SECONDS),
    ]
    for tool in ENABLED_TOOLS:
        command += ["--enabled-tools", tool]
    for tool in WEB_TOOLS:
        command += ["--disabled-tools", tool]
    return [*command, "--auto-approve"]


def vibe_environment(repo: str, repo_run: Path, runs_root: Path, fleet: Path, wheelhouse: Path, vibe_home: Path) -> dict[str, str]:
    """The worker's environment, minus what could redirect Vibe, plus what the hooks and the wrapper read.

    The API key is not touched here: it reaches Vibe either because MISTRAL_API_KEY is already in
    this process's environment, or because Vibe loads <vibe home>/.env itself.
    """
    dropped = ("VIBE_", "SANDBOX_", "PYTHON")
    env = {key: value for key, value in os.environ.items() if not key.startswith(dropped) and key != "VIRTUAL_ENV"}
    env.update({
        "VIBE_HOME": str(vibe_home),
        "OTEL_ENABLED": "false",
        "SANDBOX_WORKDIR": str(repo_run),
        "SANDBOX_DENY_READ": ":".join(str(path) for path in deny_read_paths(repo, repo_run, runs_root, fleet, wheelhouse)),
        "SANDBOX_DENY_WRITE": ":".join(str(path) for path in deny_write_paths(repo_run)),
        "SANDBOX_WHEELHOUSE": str(wheelhouse),
        "SANDBOX_HOOK_LOG": str((repo_run / contract.VIBE_EXPORT_JSON).parent / "hooks.jsonl"),
        "PATH": os.pathsep.join([str(vibe_home / "tool-venv" / "bin"), os.environ.get("PATH", "/usr/bin:/bin")]),
        # Vibe looks in the macOS Keychain when it finds no key in its environment. Ten unattended
        # agents must not wait on a Keychain dialog, so that lookup is off unless someone asks for it.
        "VIBE_TEST_DISABLE_KEYRING": os.environ.get("VIBE_TEST_DISABLE_KEYRING", "1"),
    })
    return env


def _descendants(pid: int) -> list[tuple[int, str]]:
    """(pid, start time) of every process below `pid`. Vibe may start commands in their own
    process groups, which a signal to Vibe's group does not reach."""
    try:
        listing = subprocess.run(["/bin/ps", "-axo", "pid=,ppid=,lstart="], capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    children: dict[int, list[tuple[int, str]]] = {}
    for line in listing.splitlines():
        parts = line.split(None, 2)
        if len(parts) == 3 and parts[0].isdigit() and parts[1].isdigit():
            children.setdefault(int(parts[1]), []).append((int(parts[0]), parts[2].strip()))
    found, pending = [], [pid]
    while pending:
        for child in children.get(pending.pop(), []):
            found.append(child)
            pending.append(child[0])
    return found


def _started_at(pid: int) -> str | None:
    try:
        done = subprocess.run(["/bin/ps", "-o", "lstart=", "-p", str(pid)], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None
    return done.stdout.strip() or None


def stop_group(process: subprocess.Popen) -> None:
    """End Vibe's process group and everything it started. Safe to call when it has already gone."""
    below = _descendants(process.pid) if process.poll() is None else []
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGTERM)  # Vibe writes its export.json on SIGTERM
        except OSError:
            pass
        try:
            process.wait(timeout=TERM_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except OSError:
        pass
    for pid, started in below:
        if _started_at(pid) == started:  # still the same process, not a reused number
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        pass


# ---------------------------------------------------------------- progress


def _short(text: object) -> str:
    """One printable line, cut short. What a hook logged may hold text the agent chose (a command,
    a file name), so it is flattened and trimmed before it goes anywhere."""
    flat = " ".join("".join(char if char.isprintable() else " " for char in str(text)).split())
    return flat if len(flat) <= LINE_CHARS else flat[: LINE_CHARS - 3] + "..."


class HookLog:
    """Reads vibe/hooks.jsonl, the log the two hooks write: one line per decision.

    It yields counts, and one short line per tool call for the heartbeat: `shell: ...`, `read ...`,
    `wrote ...`, `refused ...`. These lines say what the hooks saw. Nothing the agent wrote as
    prose is passed on.
    """

    def __init__(self, repo_run: Path) -> None:
        self._path = (repo_run / contract.VIBE_EXPORT_JSON).parent / "hooks.jsonl"
        self._root = _real(repo_run)
        self._seen = 0
        self.counts = {"shell": 0, "sandboxed": 0, "files": 0, "refused": 0}

    def _relative(self, path: str) -> str:
        try:
            return str(Path(path).relative_to(self._root))
        except ValueError:
            return path

    def new_lines(self) -> list[str]:
        """Lines for the tool calls logged since the last call. Updates the counts."""
        try:
            entries = self._path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return []
        lines = []
        for raw in entries[self._seen:]:
            try:
                entry = json.loads(raw)
            except ValueError:
                continue
            if not isinstance(entry, dict):
                continue
            hook, decision = entry.get("hook"), entry.get("decision")
            tool, detail = str(entry.get("tool", "")), str(entry.get("detail", ""))
            if decision == "deny":
                self.counts["refused"] += 1
                lines.append(_short(f"refused {tool.rsplit('.', 1)[-1]}: {detail}"))
            elif hook == "sandbox2" and decision == "rewrite":
                self.counts["shell"] += 1
                lines.append(_short(f"shell: {detail}"))
            elif hook == "path_hook" and decision == "allow" and detail == "wrapped":
                self.counts["sandboxed"] += 1
            elif hook == "path_hook" and decision == "allow" and tool in _READ_TOOLS:
                self.counts["files"] += 1
                lines.append(_short(f"read {self._relative(detail)}"))
            elif hook == "path_hook" and decision == "allow" and tool in _WRITE_TOOLS:
                self.counts["files"] += 1
                lines.append(_short(f"wrote {self._relative(detail)}"))
        self._seen = len(entries)
        return lines

    def summary(self) -> str:
        counts = self.counts
        return (f"{counts['shell']} shell commands, {counts['sandboxed']} of them through the sandbox, "
                f"{counts['files']} file-tool calls, {counts['refused']} calls refused")


class _Heartbeat:
    """Calls heartbeat_fn about every HEARTBEAT_SECONDS from a thread, with text this code produced."""

    def __init__(self, heartbeat_fn: Callable[..., None] | None) -> None:
        self._fn = heartbeat_fn
        self._lines: Callable[[], list[str]] = lambda: ["worker starting"]
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, name="run_repo-heartbeat", daemon=True)

    def start(self) -> None:
        if self._fn is not None:
            self._thread.start()

    def say(self, lines: str | Callable[[], list[str]]) -> None:
        """Set what the next beats report, and report it once now."""
        with self._lock:
            self._lines = lines if callable(lines) else (lambda: [lines])
        self._beat()

    def _beat(self) -> None:
        if self._fn is None:
            return
        with self._lock:
            try:
                lines = self._lines()
            except Exception:
                lines = ["worker running"]
            for line in lines:
                try:
                    self._fn(line)
                except Exception:  # a failing heartbeat must not end the one attempt this repository gets
                    pass

    def _loop(self) -> None:
        while not self._stop.wait(HEARTBEAT_SECONDS):
            self._beat()

    def stop(self) -> None:
        self._stop.set()
        if self._thread.is_alive():
            self._thread.join(timeout=5)


def running_lines(log: HookLog, repo_run: Path, started: float) -> list[str]:
    """One heartbeat while Vibe runs: the new tool calls, then one line of totals."""
    calls = log.new_lines()
    if len(calls) > MAX_LINES_PER_BEAT:
        calls = [*calls[:MAX_LINES_PER_BEAT], f"and {len(calls) - MAX_LINES_PER_BEAT} more tool calls"]
    verdict = "verdict.json written" if (repo_run / contract.VERDICT_JSON).is_file() else "no verdict.json yet"
    return [*calls, f"agent running for {int(time.monotonic() - started)} s: {log.summary()}, {verdict}"]


# ---------------------------------------------------------------- the worker


def run_repo(run_id: str, repo: str, *, fleet_root: str | Path = "fleet", runs_root: str | Path = "runs",
             vibe_home: str | Path = "vibe-home", heartbeat_fn: Callable[..., None] | None = None) -> dict:
    check_name(run_id, "run id")
    check_name(repo, "repository name")
    fleet, runs_dir, home = _resolve(fleet_root), _resolve(runs_root), _resolve(vibe_home)
    wheelhouse = wheelhouse_dir()
    python_version = os.environ.get("LE_CHONK_PYTHON", DEFAULT_PYTHON)
    model = os.environ.get("LE_CHONK_MODEL", DEFAULT_MODEL)

    heartbeat = _Heartbeat(heartbeat_fn)
    heartbeat.start()
    process: subprocess.Popen | None = None
    try:
        check_vibe_home(home, runs.repo_run_dir(runs.run_dir(runs_dir, run_id), repo))
        heartbeat.say("building a fresh work copy and its virtual environment from the wheelhouse")
        repo_run, _facts = prepare(run_id, repo, fleet, runs_dir, wheelhouse, python_version)
        env = vibe_environment(repo, repo_run, runs_dir, fleet, wheelhouse, home)
        vibe = shutil.which("vibe", path=env["PATH"])
        if vibe is None:
            raise RuntimeError(f"no vibe executable on PATH or in {home / 'tool-venv' / 'bin'}; {SETUP_HINT}")
        command = [vibe, *vibe_command(repo_run, model)[1:]]
        vibe_dir = (repo_run / contract.VIBE_EXPORT_JSON).parent
        log = HookLog(repo_run)
        started = time.monotonic()
        with open(vibe_dir / "stdout.txt", "wb") as out, open(vibe_dir / "stderr.txt", "wb") as err:
            # vibe_child.py leads a new process group, runs Vibe in it, and stops Vibe if this
            # process dies. So one signal to the group reaches both.
            process = subprocess.Popen([sys.executable, str(VIBE_CHILD), str(os.getpid()), *command], cwd=repo_run, env=env,
                                       stdin=subprocess.DEVNULL, stdout=out, stderr=err, start_new_session=True)
            heartbeat.say(lambda: running_lines(log, repo_run, started))
            deadline = started + TIME_LIMIT_SECONDS + HARD_STOP_AFTER_SECONDS
            while process.poll() is None and time.monotonic() < deadline:
                try:
                    process.wait(timeout=0.5)
                except subprocess.TimeoutExpired:
                    pass
            stop_group(process)
        rc = process.returncode if process.returncode is not None else -1
        verdict = _read_json(repo_run / contract.VERDICT_JSON)
        if not isinstance(verdict, dict) or not schemas.validator("verdict").is_valid(verdict):
            verdict = None  # missing or invalid: reported as it is, never repaired
        export = _read_json(repo_run / contract.VIBE_EXPORT_JSON)

        def last_lines() -> list[str]:
            calls = log.new_lines()[:MAX_LINES_PER_BEAT]
            found = "a valid verdict.json" if verdict is not None else "no valid verdict.json"
            return [*calls, f"agent ended with exit code {rc} after {int(time.monotonic() - started)} s: {log.summary()}, {found}"]

        heartbeat.say(last_lines)
        return {"repo": repo, "rc": rc, "verdict": verdict, "export": export if isinstance(export, dict) else {}}
    finally:
        heartbeat.stop()
        if process is not None:
            stop_group(process)


def main(argv: list[str] | None = None) -> int:
    """Run one agent by hand:  python -m worker.run_repo <run id> <repository> [--fleet-root DIR] ...

    runs/<run id>/advisory.json must exist already. Progress lines go to stderr, the result to stdout.
    """
    import argparse

    parser = argparse.ArgumentParser(prog="python -m worker.run_repo", description="Run one sandboxed agent on one repository.")
    parser.add_argument("run_id")
    parser.add_argument("repo")
    parser.add_argument("--fleet-root", default="fleet")
    parser.add_argument("--runs-root", default="runs")
    parser.add_argument("--vibe-home", default="vibe-home")
    args = parser.parse_args(argv)
    result = run_repo(args.run_id, args.repo, fleet_root=args.fleet_root, runs_root=args.runs_root, vibe_home=args.vibe_home,
                      heartbeat_fn=lambda *details: print(*details, file=sys.stderr, flush=True))
    usage = {key: result["export"].get(key) for key in ("outcome", "stop_reason", "steps", "cost_usd", "usage")}
    print(json.dumps({"repo": result["repo"], "rc": result["rc"], "verdict": result["verdict"], "export": usage}, indent=2))
    return 0 if result["verdict"] is not None else 1


__all__ = ["run_repo"]

if __name__ == "__main__":
    raise SystemExit(main())
