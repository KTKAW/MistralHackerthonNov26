"""The sandbox: the wrapper (sandbox/douane) and the two Vibe pre_tool hooks.

The wrapper tests run real commands under /usr/bin/sandbox-exec, so they need macOS. The hook
tests feed each hook the JSON that Vibe 3.1.3 sends on stdin and read its answer from stdout.

    uv run --no-sync pytest tests/test_sandbox.py -q
"""
from __future__ import annotations

import json
import os
import pwd
import shlex
import shutil
import socket
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

from vulnerability_agent import contract

REPO = Path(__file__).resolve().parents[1]
SANDBOX = REPO / "sandbox"
DOUANE = SANDBOX / "douane"
WHEELHOUSE = REPO / "wheelhouse"
REAL_HOME = Path(os.path.realpath(pwd.getpwuid(os.getuid()).pw_dir))

# pytest puts src/ on the import path (pyproject.toml) but not the repository root, where the
# `worker` package lives; the hooks are plain scripts in sandbox/.
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(SANDBOX))
import hook_common  # noqa: E402
import path_hook  # noqa: E402
import sandbox2  # noqa: E402

macos = pytest.mark.skipif(
    sys.platform != "darwin" or not Path("/usr/bin/sandbox-exec").exists(),
    reason="the wrapper needs macOS sandbox-exec",
)
needs_wheels = pytest.mark.skipif(
    shutil.which("uv") is None or not any(WHEELHOUSE.glob("authlib-1.8.0-*.whl")),
    reason="needs uv and the wheelhouse at ./wheelhouse",
)


# ---------------------------------------------------------------- the wrapper


@pytest.fixture
def workdir(tmp_path: Path) -> Path:
    path = tmp_path / "run" / "repo"
    (path / "src").mkdir(parents=True)
    (path / "proof").mkdir()
    return path


def douane(command: str, workdir: Path, *, env: dict | None = None, cwd: Path | None = None) -> subprocess.CompletedProcess:
    """Call the wrapper the way Vibe and the gate do: one argument, a small environment."""
    full = {"PATH": os.environ["PATH"], "HOME": str(REAL_HOME), "LANG": "en_US.UTF-8",
            "TMPDIR": os.environ.get("TMPDIR", "/tmp"), "SANDBOX_WORKDIR": str(workdir)}
    full.update(env or {})
    return subprocess.run([str(DOUANE), command], env=full, cwd=cwd or workdir, capture_output=True, text=True, timeout=180)


@macos
def test_exit_code_is_passed_through(workdir: Path) -> None:
    assert douane("true", workdir).returncode == 0
    assert douane("exit 7", workdir).returncode == 7
    done = douane("echo out; echo err >&2; exit 3", workdir)
    assert (done.returncode, done.stdout, done.stderr) == (3, "out\n", "err\n")


@macos
def test_environment_is_scrubbed(workdir: Path) -> None:
    done = douane("env", workdir, env={"MISTRAL_API_KEY": "not-a-real-key", "SOME_TOKEN": "also-not-real",
                                       "VIBE_HOME": str(workdir.parent / "vibe-home")})
    assert done.returncode == 0
    variables = dict(line.split("=", 1) for line in done.stdout.splitlines() if "=" in line)
    assert "not-a-real-key" not in done.stdout and "also-not-real" not in done.stdout
    assert "MISTRAL_API_KEY" not in variables and "SOME_TOKEN" not in variables and "VIBE_HOME" not in variables
    real = Path(os.path.realpath(workdir))
    assert Path(variables["HOME"]) == real / ".sandbox" / "home"
    assert Path(variables["TMPDIR"]) == real / ".sandbox" / "tmp"
    assert variables["PATH"].split(":")[-4:] == ["/usr/bin", "/bin", "/usr/sbin", "/sbin"]
    assert str(REAL_HOME) not in variables["PATH"]
    assert variables["PYTHONDONTWRITEBYTECODE"] == "1" and variables["UV_OFFLINE"] == "1"


@macos
def test_network_is_denied(workdir: Path) -> None:
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    connect = f"exec 3<>/dev/tcp/127.0.0.1/{port} && echo connected"
    try:
        control = subprocess.run(["/bin/bash", "-c", connect], capture_output=True, text=True, timeout=30)
        assert "connected" in control.stdout  # the same command works outside the sandbox
        inside = douane(connect, workdir)
        assert "connected" not in inside.stdout and inside.returncode != 0
    finally:
        listener.close()
    outbound = douane("/usr/bin/curl -s -m 5 -o /dev/null https://example.com", workdir)
    assert outbound.returncode != 0


@macos
def test_writes_inside_and_in_temp_allowed_outside_denied(workdir: Path, tmp_path: Path) -> None:
    outside = tmp_path / "outside.txt"
    shared = Path("/tmp") / f"douane-test-{uuid.uuid4().hex}"
    done = douane(
        f'echo a > inside.txt && echo b > src/new.py && echo c > "$TMPDIR/t.txt" && echo d > "$HOME/h.txt" && echo inside-ok;'
        f" echo x > {shlex.quote(str(outside))} || echo outside-denied;"
        f" echo x > {shlex.quote(str(shared))} || echo shared-tmp-denied;"
        " mkdir ../sibling || echo mkdir-denied",
        workdir,
    )
    assert "inside-ok" in done.stdout and "outside-denied" in done.stdout
    assert "shared-tmp-denied" in done.stdout and "mkdir-denied" in done.stdout
    assert (workdir / "inside.txt").read_text() == "a\n" and (workdir / "src" / "new.py").is_file()
    assert (workdir / ".sandbox" / "tmp" / "t.txt").is_file() and (workdir / ".sandbox" / "home" / "h.txt").is_file()
    assert not outside.exists() and not shared.exists() and not (workdir.parent / "sibling").exists()


@macos
def test_secrets_are_unreadable(workdir: Path, tmp_path: Path) -> None:
    (workdir / ".env").write_text("TOKEN=in-workdir\n")
    (workdir / "src" / ".env.local").write_text("TOKEN=nested\n")
    (workdir / "src" / "config" / "secrets").mkdir(parents=True)
    (workdir / "src" / "config" / "secrets" / "key.pem").write_text("nested-secret\n")
    answers = tmp_path / "answers"
    answers.mkdir()
    (answers / "key.json").write_text("the-answer-key\n")
    other_run = tmp_path / "run" / "other-repo"
    other_run.mkdir()
    (other_run / "verdict.json").write_text("another-agents-verdict\n")
    vibe_home = tmp_path / "vibe-home"
    vibe_home.mkdir()
    (vibe_home / "config.toml").write_text("vibe-config\n")
    targets = [".env", "src/.env.local", "src/config/secrets/key.pem", str(answers / "key.json"),
               str(other_run / "verdict.json"), str(vibe_home / "config.toml"), str(REAL_HOME / ".vibe" / "x")]
    command = "; ".join(f"cat {shlex.quote(target)}" for target in targets)
    command += f"; ls src/config/secrets; ls {shlex.quote(str(answers))}; echo finished"
    done = douane(command, workdir, env={"SANDBOX_DENY_READ": f"{answers}:{other_run}", "VIBE_HOME": str(vibe_home)})
    assert "finished" in done.stdout
    for secret in ("in-workdir", "nested", "nested-secret", "the-answer-key", "another-agents-verdict", "vibe-config", "key.pem", "key.json"):
        assert secret not in done.stdout, secret
    assert done.stderr.count("Operation not permitted") >= 8


@macos
def test_a_secret_cannot_be_renamed_into_the_open(workdir: Path) -> None:
    (workdir / "src" / "secrets").mkdir()
    (workdir / "src" / "secrets" / "key").write_text("secret\n")
    (workdir / ".env").write_text("TOKEN=x\n")
    done = douane("mv src/secrets/key src/key; mv src/secrets src/public; mv .env env.txt; cp .env copy.txt; ln src/secrets/key hard; echo finished", workdir)
    assert "finished" in done.stdout
    assert (workdir / "src" / "secrets" / "key").is_file() and (workdir / ".env").is_file()
    for leaked in ("src/key", "src/public", "env.txt", "copy.txt", "hard"):
        assert not (workdir / leaked).exists(), leaked


@macos
def test_no_new_symlinks_in_the_workdir(workdir: Path) -> None:
    done = douane('ln -s /etc/hosts src/link || echo link-denied; ln -s /etc/hosts "$TMPDIR/link" && echo temp-link-ok', workdir)
    assert "link-denied" in done.stdout and "temp-link-ok" in done.stdout
    assert not (workdir / "src" / "link").is_symlink()


@macos
def test_other_folders_under_home_and_temp_are_unreadable(workdir: Path, tmp_path: Path) -> None:
    """Without any deny list: only the workdir is readable in the places people keep their things."""
    sibling = tmp_path / "another-project"
    sibling.mkdir()
    (sibling / "notes.txt").write_text("someone-elses-notes\n")
    (workdir / "src" / "a.txt").write_text("mine\n")
    command = (
        f"cat {shlex.quote(str(sibling / 'notes.txt'))}; ls {shlex.quote(str(sibling))}; ls {shlex.quote(str(tmp_path))};"
        f" ls {shlex.quote(str(REAL_HOME))} && echo HOME-LISTED; cat {shlex.quote(str(REPO / 'pyproject.toml'))} && echo REPO-FILE-READ;"
        " cat src/a.txt; ls src; cat /etc/hosts > /dev/null && echo system-file-ok; ls /usr/bin > /dev/null && echo system-listing-ok"
    )
    done = douane(command, workdir)
    assert "someone-elses-notes" not in done.stdout and "notes.txt" not in done.stdout
    assert "HOME-LISTED" not in done.stdout
    if hook_common.is_inside(Path(os.path.realpath(REPO)), REAL_HOME):
        assert "REPO-FILE-READ" not in done.stdout
    assert "mine" in done.stdout and "a.txt" in done.stdout
    assert "system-file-ok" in done.stdout and "system-listing-ok" in done.stdout


@macos
def test_read_allow_and_deny_write_lists(workdir: Path, tmp_path: Path) -> None:
    shared = tmp_path / "shared"
    shared.mkdir()
    (shared / "data.txt").write_text("shared-data\n")
    (workdir / "state.json").write_text('{"status": "running"}\n')
    (workdir / "vibe").mkdir()
    env = {"SANDBOX_READ_ALLOW": str(shared), "SANDBOX_DENY_WRITE": f"{workdir / 'state.json'}:{workdir / 'vibe'}:{workdir / '.vibe'}"}
    done = douane(
        f"cat {shlex.quote(str(shared / 'data.txt'))}; cat state.json; echo x > state.json || echo state-denied;"
        " rm state.json || echo rm-denied; echo x > vibe/export.json || echo vibe-denied; mkdir .vibe || echo dotvibe-denied;"
        f" echo x > {shlex.quote(str(shared / 'new.txt'))} || echo shared-write-denied",
        workdir, env=env,
    )
    assert "shared-data" in done.stdout and '"running"' in done.stdout
    for refusal in ("state-denied", "rm-denied", "vibe-denied", "dotvibe-denied", "shared-write-denied"):
        assert refusal in done.stdout, refusal
    assert (workdir / "state.json").read_text() == '{"status": "running"}\n'
    assert not (workdir / ".vibe").exists() and not (shared / "new.txt").exists()


@macos
def test_misuse_fails_closed(workdir: Path, tmp_path: Path) -> None:
    base = {"PATH": os.environ["PATH"], "HOME": str(REAL_HOME), "LANG": "C"}
    marker = workdir / "ran.txt"
    command = f"echo x > {shlex.quote(str(marker))}"
    cases = [
        {},  # no SANDBOX_WORKDIR at all
        {"SANDBOX_WORKDIR": "relative/dir"},
        {"SANDBOX_WORKDIR": str(tmp_path / "missing")},
        {"SANDBOX_WORKDIR": str(workdir), "SANDBOX_DENY_READ": str(workdir.parent)},  # would hide the workdir itself
        {"SANDBOX_WORKDIR": str(workdir), "SANDBOX_DENY_READ": "relative/path"},
        {"SANDBOX_WORKDIR": str(workdir), "SANDBOX_DENY_READ": str(tmp_path / 'has"quote')},
    ]
    for extra in cases:
        done = subprocess.run([str(DOUANE), command], env={**base, **extra}, cwd=tmp_path, capture_output=True, text=True, timeout=60)
        assert done.returncode == 125, (extra, done.stderr)
        assert "douane:" in done.stderr
    assert not marker.exists()
    usage = subprocess.run([str(DOUANE)], env={**base, "SANDBOX_WORKDIR": str(workdir)}, capture_output=True, text=True, timeout=60)
    assert usage.returncode == 125


@pytest.fixture(scope="module")
def venv_workdir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A workdir with an empty venv, made the way the worker and the gate make it."""
    path = tmp_path_factory.mktemp("venv-run") / "repo"
    (path / "proof").mkdir(parents=True)
    subprocess.run(["uv", "venv", "--quiet", "--python", "3.12", str(path / "venv")], check=True, timeout=300)
    (path / "pytest.ini").write_text("[pytest]\naddopts = -p no:cacheprovider\n")
    (path / "proof" / "test_proof.py").write_text(
        "import authlib\n\n\ndef test_installed_version(tmp_path):\n"
        "    (tmp_path / 'scratch').write_text('x')\n    assert authlib.__version__ == '1.8.0'\n"
    )
    return path


@macos
@needs_wheels
def test_offline_install_and_pinned_proof_command(venv_workdir: Path) -> None:
    env = {"SANDBOX_WHEELHOUSE": str(WHEELHOUSE)}
    install = douane(
        'uv pip install --python venv/bin/python --offline --no-index --find-links "$SANDBOX_WHEELHOUSE" --only-binary :all:'
        " authlib==1.8.0 pytest==9.2.0",
        venv_workdir, env=env,
    )
    assert install.returncode == 0, install.stderr
    # The contract's pinned command, from the repo-run root.
    proof = douane(" ".join(contract.PROOF_TEST_COMMAND), venv_workdir, env=env)
    assert proof.returncode == 0, proof.stdout + proof.stderr
    assert "1 passed" in proof.stdout
    # `python` is the venv's, the library source is readable, and nothing was compiled into the tree.
    look = douane('which python; python -c "import authlib, os; print(os.path.dirname(authlib.__file__))";'
                  ' grep -c "def " venv/lib/python3.12/site-packages/authlib/jose/rfc7515/jws.py;'
                  ' python -c "import json, inspect; print(len(open(inspect.getsourcefile(json)).read()) > 0)"', venv_workdir, env=env)
    assert look.returncode == 0, look.stderr
    assert str(Path(os.path.realpath(venv_workdir)) / "venv" / "bin" / "python") in look.stdout and "True" in look.stdout
    assert not list((venv_workdir / "proof").rglob("__pycache__"))
    # A package that is not in the wheelhouse cannot come from anywhere else.
    missing = douane("uv pip install --python venv/bin/python definitely-not-in-the-wheelhouse==1.0", venv_workdir, env=env)
    assert missing.returncode != 0
    # The gate's way of calling: nothing but PATH, HOME (the folder itself), LANG and TMPDIR.
    gate = subprocess.run(
        [str(DOUANE), f"cd {shlex.quote(str(venv_workdir))} && venv/bin/python -m pytest proof/ -q"],
        env={"PATH": "/usr/bin:/bin", "HOME": str(venv_workdir), "LANG": "en_US.UTF-8",
             "TMPDIR": os.environ.get("TMPDIR", "/tmp"), "SANDBOX_WORKDIR": str(venv_workdir)},
        cwd="/", capture_output=True, text=True, timeout=180,
    )
    assert gate.returncode == 0 and "1 passed" in gate.stdout, gate.stdout + gate.stderr
    # The upgrade the prompt asks for: the fixed version, offline. The proof test now fails.
    upgrade = douane('uv pip install --python venv/bin/python --offline --no-index --find-links "$SANDBOX_WHEELHOUSE"'
                     ' --only-binary :all: "authlib==1.9.0"', venv_workdir, env=env)
    assert upgrade.returncode == 0, upgrade.stderr
    after = douane("venv/bin/python -m pytest proof/ -q", venv_workdir, env=env)
    assert after.returncode == 1 and "1 failed" in after.stdout


# ---------------------------------------------------------------- the hooks


def payload(tool_name: str, tool_input: dict, cwd: Path) -> dict:
    """What Vibe 3.1.3 writes to a pre_tool hook's stdin."""
    return {"hook_event_name": "pre_tool", "session_id": "session-1", "parent_session_id": None,
            "transcript_path": "", "cwd": str(cwd), "tool_name": tool_name, "tool_call_id": "call_1",
            "tool_input": tool_input}


def run_hook(script: str, stdin: str, workdir: Path | None, **env: str) -> tuple[int, dict | None]:
    """Run a hook the way hooks.toml does. Returns (exit code, parsed stdout or None when empty)."""
    full = {"PATH": "/usr/bin:/bin", "HOME": str(REAL_HOME), **env}
    if workdir is not None:
        full["SANDBOX_WORKDIR"] = str(workdir)
    done = subprocess.run([sys.executable, "-I", str(SANDBOX / script)], input=stdin, env=full,
                          cwd=workdir or "/", capture_output=True, text=True, timeout=60)
    return done.returncode, (json.loads(done.stdout) if done.stdout.strip() else None)


def decision(script: str, tool_name: str, tool_input: dict, workdir: Path, **env: str) -> str:
    """"allow", "deny" or "rewrite" for one tool call. A hook that fails counts as a denial, as
    Vibe treats it: both hooks are registered with strict = true."""
    code, answer = run_hook(script, json.dumps(payload(tool_name, tool_input, workdir)), workdir, **env)
    if code != 0:
        return "deny"
    if answer is None:
        return "allow"
    if answer.get("decision") == "deny":
        assert answer.get("reason")
        return "deny"
    assert isinstance(answer["hook_specific_output"]["tool_input"], dict)
    return "rewrite"


def test_sandbox2_rewrites_shell_calls(workdir: Path) -> None:
    for tool in ("file_system.bash", "process.start"):
        code, answer = run_hook("sandbox2.py", json.dumps(payload(tool, {"command": "ls -la src", "timeout": 120}, workdir)), workdir)
        assert code == 0
        rewritten = answer["hook_specific_output"]["tool_input"]
        assert rewritten == {"command": f"{shlex.quote(str(DOUANE))} 'ls -la src'", "timeout": 120}
        assert shlex.split(rewritten["command"]) == [str(DOUANE), "ls -la src"]


def test_sandbox2_wraps_an_already_wrapped_command_once(workdir: Path) -> None:
    once = sandbox2.wrap("echo 'it''s' \"$HOME\"")
    assert sandbox2.wrap(once) == once and sandbox2.wrap(sandbox2.wrap(once)) == once
    code, answer = run_hook("sandbox2.py", json.dumps(payload("file_system.bash", {"command": once}, workdir)), workdir)
    assert code == 0 and answer["hook_specific_output"]["tool_input"]["command"] == once


def test_sandbox2_leaves_other_tools_alone(workdir: Path) -> None:
    for tool, tool_input in (("file_system.read_file", {"file_path": "src/a.py"}), ("vibe.todo", {"action": "read"})):
        assert run_hook("sandbox2.py", json.dumps(payload(tool, tool_input, workdir)), workdir) == (0, None)


@pytest.mark.parametrize("script", ["sandbox2.py", "path_hook.py"])
def test_hooks_deny_malformed_input(script: str, workdir: Path) -> None:
    good = payload("file_system.bash", {"command": "ls"}, workdir)
    broken = [
        "",
        "not json",
        "[1, 2]",
        json.dumps({**good, "hook_event_name": "post_tool"}),
        json.dumps({key: value for key, value in good.items() if key != "tool_input"}),
        json.dumps({**good, "tool_input": "ls"}),
        json.dumps({**good, "tool_name": ""}),
        json.dumps({**good, "tool_input": {}}),
        json.dumps({**good, "tool_input": {"command": ""}}),
        json.dumps({**good, "tool_input": {"command": ["ls"]}}),
    ]
    for stdin in broken:
        code, answer = run_hook(script, stdin, workdir)
        assert code != 0 or (answer or {}).get("decision") == "deny", (script, stdin)
    # Without a workdir nothing can be decided, so a well-formed call is refused too.
    code, answer = run_hook(script, json.dumps(good), None)
    assert code != 0 or (answer or {}).get("decision") == "deny"


@macos
def test_the_rewritten_command_runs_in_the_sandbox(workdir: Path, tmp_path: Path) -> None:
    """The chain as Vibe runs it: sandbox2 rewrites, path_hook accepts, a shell executes the result."""
    outside = tmp_path / "escape.txt"
    original = f"echo \"it's inside\" > src/out.txt; echo x > {shlex.quote(str(outside))}; echo \"leak=[$SOME_TOKEN]\""
    code, answer = run_hook("sandbox2.py", json.dumps(payload("file_system.bash", {"command": original}, workdir)), workdir)
    rewritten = answer["hook_specific_output"]["tool_input"]
    assert decision("path_hook.py", "file_system.bash", rewritten, workdir) == "allow"
    done = subprocess.run(["/bin/sh", "-c", rewritten["command"]], cwd=workdir, capture_output=True, text=True, timeout=60,
                          env={"PATH": os.environ["PATH"], "HOME": str(REAL_HOME), "SANDBOX_WORKDIR": str(workdir), "SOME_TOKEN": "not-real"})
    assert (workdir / "src" / "out.txt").read_text() == "it's inside\n"
    assert not outside.exists() and "leak=[]" in done.stdout


def test_path_hook_refuses_a_shell_call_that_is_not_wrapped(workdir: Path) -> None:
    assert decision("path_hook.py", "file_system.bash", {"command": "ls"}, workdir) == "deny"
    assert decision("path_hook.py", "process.start", {"command": "sleep 100"}, workdir) == "deny"
    assert decision("path_hook.py", "file_system.bash", {"command": f"{DOUANE} 'ls' ; rm -rf /"}, workdir) == "deny"
    assert decision("path_hook.py", "file_system.bash", {"command": sandbox2.wrap("ls")}, workdir) == "allow"


def test_path_hook_write_locations(workdir: Path, tmp_path: Path) -> None:
    (workdir / "venv" / "lib").mkdir(parents=True)
    (workdir / "src" / "pkg").mkdir()
    allowed = ["src/pkg/app.py", "src/requirements.txt", "proof/test_proof.py", "proof/sub/test_more.py", "verdict.json",
               str(workdir / "src" / "new.py"), str(workdir / "verdict.json"), "./src/../proof/test_x.py"]
    denied = ["outside.txt", "state.json", "fix.diff", "pytest.ini", "gate/x.py", "vibe/prompt.md", "vibe/export.json",
              "venv/lib/authlib.py", ".vibe/hooks.toml", ".sandbox/tmp/x", "src", "proof", "../other-repo/verdict.json",
              "src/../state.json", str(tmp_path / "elsewhere.txt"), "/tmp/elsewhere.txt", "src/.env", "src/.env.local",
              "src/secrets/key.pem", "proof/secrets/x", "~/notes.txt", ""]
    for tool, key in (("file_system.write_file", "file_path"), ("file_system.edit", "file_path"), ("file_system.write_file", "path")):
        for path in allowed:
            assert decision("path_hook.py", tool, {key: path, "content": "x"}, workdir) == "allow", (tool, path)
        for path in denied:
            assert decision("path_hook.py", tool, {key: path, "content": "x"}, workdir) == "deny", (tool, path)
    # Two path arguments, or none, cannot be judged.
    assert decision("path_hook.py", "file_system.write_file", {"file_path": "src/a.py", "path": "state.json"}, workdir) == "deny"
    assert decision("path_hook.py", "file_system.write_file", {"content": "x"}, workdir) == "deny"


def test_path_hook_write_locations_are_the_contracts() -> None:
    assert (*path_hook.WRITABLE_DIRS, *path_hook.WRITABLE_FILES) == contract.AGENT_WRITABLE


def test_path_hook_read_allowlist(workdir: Path, tmp_path: Path) -> None:
    (workdir / "src" / "app.py").write_text("x = 1\n")
    (workdir / "venv" / "bin").mkdir(parents=True)
    (workdir / "venv" / "lib").mkdir()
    (workdir / "venv" / "lib" / "library.py").write_text("y = 2\n")
    (workdir / "venv" / "bin" / "python").symlink_to(os.path.realpath(sys.executable))
    install = Path(os.path.realpath(sys.executable)).parent.parent
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    (wheelhouse / "pkg-1.0-py3-none-any.whl").write_text("wheel")
    extra = tmp_path / "extra"
    extra.mkdir()
    answers = tmp_path / "answers"
    answers.mkdir()
    vibe_home = tmp_path / "vibe-home"
    vibe_home.mkdir()
    env = {"SANDBOX_WHEELHOUSE": str(wheelhouse), "SANDBOX_READ_ALLOW": str(extra),
           "SANDBOX_DENY_READ": f"{answers}:{workdir.parent / 'other-repo'}", "VIBE_HOME": str(vibe_home)}
    allowed = ["src/app.py", "venv/lib/library.py", "proof/conftest.py", "verdict.json", "state.json",
               str(wheelhouse / "pkg-1.0-py3-none-any.whl"), str(extra / "notes.txt"), str(install / "lib" / "os.py")]
    denied = ["/etc/hosts", str(REAL_HOME / ".ssh" / "id_ed25519"), str(REAL_HOME / ".vibe" / "config.toml"),
              str(vibe_home / "config.toml"), str(answers / "key.json"), "../other-repo/verdict.json", str(tmp_path / "unlisted.txt"),
              ".env", "src/.env.production", "src/secrets/key.pem", ".sandbox/home/x", str(REPO / "docs" / "FLEET.md"), "~/x"]
    for path in allowed:
        assert decision("path_hook.py", "file_system.read_file", {"file_path": path}, workdir, **env) == "allow", path
    for path in denied:
        assert decision("path_hook.py", "file_system.read_file", {"file_path": path}, workdir, **env) == "deny", path
    # The runtime's own argument name works too, and a relative path is taken from the payload's cwd.
    assert decision("path_hook.py", "file_system.read_file", {"path": "src/app.py", "offset": 0, "limit": 10}, workdir, **env) == "allow"


def test_path_hook_resolves_symlinks(workdir: Path, tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "data.txt").write_text("outside\n")
    (workdir / ".env").write_text("TOKEN=x\n")
    (workdir / "venv").mkdir()
    (workdir / "src" / "link").symlink_to(outside)                  # a folder link that leaves the workdir
    (workdir / "src" / "innocent.txt").symlink_to(workdir / ".env")  # a link to a secret inside it
    (workdir / "proof" / "lib").symlink_to(workdir / "venv")         # a link from a writable folder to a protected one
    (workdir / "src" / "real").mkdir()
    (workdir / "src" / "alias").symlink_to(workdir / "src" / "real")  # a link that stays inside: fine
    for path in ("src/link/data.txt", "src/innocent.txt"):
        assert decision("path_hook.py", "file_system.read_file", {"file_path": path}, workdir) == "deny", path
    for path in ("src/link/new.py", "src/innocent.txt", "proof/lib/authlib.py"):
        assert decision("path_hook.py", "file_system.write_file", {"file_path": path, "content": "x"}, workdir) == "deny", path
    assert decision("path_hook.py", "file_system.write_file", {"file_path": "src/alias/new.py", "content": "x"}, workdir) == "allow"
    assert decision("path_hook.py", "file_system.read_file", {"file_path": "proof/lib/x.py"}, workdir) == "allow"  # venv is readable


def test_path_hook_refuses_every_tool_it_does_not_know(workdir: Path) -> None:
    unknown = {
        "skill.read": {"name": "vibe:vibe"},
        "vibe.unified_harness_scratchpad": {"action": "write", "path": "note.md", "content": "x"},
        "vibe.todo": {"action": "read"},
        "agents.spawn": {"name": "helper", "message": "do it"},
        "process.output": {"process_id": "p1"},
        "self.wait": {"timeout_ms": 1000},
        "mcp_files.read": {"path": "/etc/hosts"},
        "connector_web_search_open_url": {"url": "https://example.com"},
        "file_system.search_replace": {"file_path": "src/a.py"},
        "something.new": {},
    }
    for tool, tool_input in unknown.items():
        assert decision("path_hook.py", tool, tool_input, workdir) == "deny", tool


def test_every_enabled_tool_is_decided_by_a_hook(tmp_path: Path) -> None:
    """The worker enables four tools. Each must have a rule of its own in a hook, and both hooks
    must be registered so that Vibe runs them, strictly, for every tool."""
    import tomllib

    from worker import setup_vibe_home

    assert setup_vibe_home.ENABLED_TOOLS == ("bash", "read_file", "write_file", "edit")
    known = hook_common.SHELL_TOOLS | path_hook.READ_TOOLS | path_hook.WRITE_TOOLS
    for tool in setup_vibe_home.ENABLED_TOOLS:
        assert f"file_system.{tool}" in known, tool
    assert "file_system.bash" in hook_common.SHELL_TOOLS and hook_common.is_shell_tool("file_system.bash")

    config = tomllib.loads(setup_vibe_home.render_config())
    assert config["enabled_tools"] == list(setup_vibe_home.ENABLED_TOOLS)
    hooks = tomllib.loads(setup_vibe_home.render_hooks(tmp_path / "tool-venv" / "bin" / "python"))["hooks"]
    assert [Path(shlex.split(hook["command"])[-1]).name for hook in hooks] == ["sandbox2.py", "path_hook.py"]
    for hook in hooks:
        assert hook["type"] == "pre_tool" and hook["strict"] is True and hook["match"] == "*"
        assert Path(shlex.split(hook["command"])[-1]).is_file()


def test_hooks_log_their_decisions(workdir: Path, tmp_path: Path) -> None:
    log = tmp_path / "hooks.jsonl"
    decision("sandbox2.py", "file_system.bash", {"command": "ls"}, workdir, SANDBOX_HOOK_LOG=str(log))
    decision("path_hook.py", "file_system.bash", {"command": sandbox2.wrap("ls")}, workdir, SANDBOX_HOOK_LOG=str(log))
    decision("path_hook.py", "file_system.write_file", {"file_path": "state.json", "content": "x"}, workdir, SANDBOX_HOOK_LOG=str(log))
    entries = [json.loads(line) for line in log.read_text().splitlines()]
    assert [(entry["hook"], entry["tool"], entry["decision"]) for entry in entries] == [
        ("sandbox2", "file_system.bash", "rewrite"),
        ("path_hook", "file_system.bash", "allow"),
        ("path_hook", "file_system.write_file", "deny"),
    ]
    assert entries[0]["detail"] == "ls" and entries[1]["detail"] == "wrapped"
