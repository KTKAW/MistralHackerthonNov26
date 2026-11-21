"""Create the isolated Vibe home the per-repository agents run with. Safe to run again.

    uv run --no-sync python -m worker.setup_vibe_home            # creates ./vibe-home
    uv run --no-sync python -m worker.setup_vibe_home /abs/home  # or another folder

What it leaves in the folder (which is git-ignored):

    tool-venv/     a Python 3.12 venv holding exactly mistral-vibe==3.1.3
    config.toml    model, an allow-list of four tools, telemetry and update checks off,
                   connectors/MCP/web tools off, subagents and background processes off, the
                   sandbox wrapper on the bash allowlist
    hooks.toml     the two strict pre_tool hooks: sandbox/sandbox2.py and sandbox/path_hook.py

This script never reads, writes, prints or asks for an API key. A person supplies it: either
MISTRAL_API_KEY in the environment of the process that runs the worker, or a line
`MISTRAL_API_KEY=...` in <vibe home>/.env, written by hand. Vibe loads that file itself.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SANDBOX_DIR = REPO_ROOT / "sandbox"
VIBE_VERSION = "3.1.3"
PYTHON_VERSION = "3.12"
WORKER_MODEL = "mistral-large-4-0"  # a built-in model alias of Vibe 3.1.3

# The only tools the agent gets. Each one is decided by a hook: bash by sandbox2.py (and checked
# again by path_hook.py), the three file tools by path_hook.py. A test keeps this list and the
# hooks' own lists in step.
ENABLED_TOOLS = ("bash", "read_file", "write_file", "edit")
# Web search and fetch come from the web_search connector; these are its two tool names.
WEB_TOOLS = ("connector_web_search_web_search", "connector_web_search_open_url")


def toml_string(value: str) -> str:
    """A TOML basic string. JSON string escapes are valid TOML escapes."""
    return json.dumps(value)


def render_config(douane: Path = SANDBOX_DIR / "douane", model: str = WORKER_MODEL) -> str:
    """config.toml for the isolated home. Every key here was checked against Vibe 3.1.3's schema."""
    enabled = ", ".join(toml_string(name) for name in ENABLED_TOOLS)
    disabled = ", ".join(toml_string(name) for name in WEB_TOOLS)
    return f"""# Written by worker/setup_vibe_home.py. Change that script, not this file.

active_model = {toml_string(model)}

# Nothing leaves the machine except the model calls.
enable_telemetry = false
enable_otel = false
enable_update_checks = false
enable_auto_update = false
enable_notifications = false

# An allow-list of tools, not a list of tools to turn off. Vibe 3.1.3 offers `run_typescript`,
# `search_tool_functions` and `skill` whatever this list says; the hooks deal with those
# (see docs/AGENT.md).
enabled_tools = [{enabled}]

# No web tools, no connectors, no MCP servers, no skills.
enable_connectors = false
enable_mcp = false
disabled_tools = [{disabled}]
disabled_skills = ["*"]

# One agent per repository, and every command runs to completion in the sandbox.
enable_subagents = false
enable_background_processes = false

# The run folder lies inside the repository that holds this tool. With project context on, Vibe
# puts that repository's branch name and latest commit subjects into the agent's system prompt
# (seen in a run). Pull-request monitoring, per Vibe's settings reference, uses `gh` for the
# session's branch; the agent has no use for it.
include_project_context = false
enable_pr_monitoring = false

# sandbox2.py rewrites every command to start with the wrapper, and the allowlist is matched
# against the rewritten command. Without this entry a run without --auto-approve would stop at
# every command.
[tools.bash]
allowlist = [{toml_string(str(douane))}]
"""


def render_hooks(python: Path, sandbox_dir: Path = SANDBOX_DIR) -> str:
    """hooks.toml: both hooks see every tool call, in this order, and deny on any failure."""

    def command(script: str) -> str:
        # A hook command is a shell line. -I keeps the environment and the current folder (the
        # agent's work area) out of the interpreter's import path.
        return toml_string(f"{_shell_quote(str(python))} -I {_shell_quote(str(sandbox_dir / script))}")

    return f"""# Written by worker/setup_vibe_home.py. Change that script, not this file.

[[hooks]]
name = "sandbox-shell"
type = "pre_tool"
match = "*"
strict = true
timeout = 30.0
description = "Rewrite every shell command to run through sandbox/douane"
command = {command("sandbox2.py")}

[[hooks]]
name = "sandbox-paths"
type = "pre_tool"
match = "*"
strict = true
timeout = 30.0
description = "Limit the file tools to the run folder; refuse every tool that is not known"
command = {command("path_hook.py")}
"""


def _shell_quote(text: str) -> str:
    import shlex

    return shlex.quote(text)


def installed_version(home: Path) -> str | None:
    """The version the tool venv's vibe reports, or None when it is not there."""
    vibe = home / "tool-venv" / "bin" / "vibe"
    if not vibe.is_file():
        return None
    try:
        output = subprocess.run([str(vibe), "--version"], capture_output=True, text=True, timeout=60,
                                env={"PATH": "/usr/bin:/bin", "VIBE_HOME": str(home), "VIBE_TEST_DISABLE_KEYRING": "1"})
    except (OSError, subprocess.SubprocessError):
        return None
    words = output.stdout.split()
    return words[-1] if output.returncode == 0 and words else None


def install_vibe(home: Path) -> None:
    """The pinned Vibe in its own venv. Needs the network (PyPI) the first time."""
    if installed_version(home) == VIBE_VERSION:
        print(f"tool-venv: mistral-vibe {VIBE_VERSION} is already installed")
        return
    uv = shutil.which("uv")
    if uv is None:
        raise SystemExit("uv is not on PATH; install it first (https://docs.astral.sh/uv/)")
    venv = home / "tool-venv"
    subprocess.run([uv, "venv", "--python", PYTHON_VERSION, "--clear", str(venv)], check=True)
    subprocess.run([uv, "pip", "install", "--python", str(venv / "bin" / "python"), f"mistral-vibe=={VIBE_VERSION}"], check=True)
    found = installed_version(home)
    if found != VIBE_VERSION:
        raise SystemExit(f"expected mistral-vibe {VIBE_VERSION} in {venv}, found {found!r}")
    print(f"tool-venv: installed mistral-vibe {VIBE_VERSION}")


def write_if_changed(path: Path, text: str) -> None:
    if path.is_file() and path.read_text(encoding="utf-8") == text:
        print(f"{path.name}: unchanged")
        return
    path.write_text(text, encoding="utf-8")
    print(f"{path.name}: written")


def setup(home: Path, *, install: bool = True) -> Path:
    home = home if home.is_absolute() else REPO_ROOT / home
    home.mkdir(parents=True, exist_ok=True)
    home.chmod(0o700)
    if install:
        install_vibe(home)
    for script in ("douane", "sandbox2.py", "path_hook.py", "hook_common.py", "profile.sb.template"):
        if not (SANDBOX_DIR / script).is_file():
            raise SystemExit(f"missing sandbox file: {SANDBOX_DIR / script}")
    write_if_changed(home / "config.toml", render_config())
    write_if_changed(home / "hooks.toml", render_hooks(home / "tool-venv" / "bin" / "python"))
    return home


def main(argv: list[str]) -> int:
    home = setup(Path(argv[1]) if len(argv) > 1 else Path("vibe-home"))
    print(f"""
Vibe home ready: {home}
The API key is not handled by this script. Before a run, a person does one of:
  - export MISTRAL_API_KEY in the shell that starts the worker, or
  - put one line `MISTRAL_API_KEY=...` into {home / '.env'} (git-ignored; never commit it).
""")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
