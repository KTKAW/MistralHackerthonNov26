"""Vibe `pre_tool` hook: the file tools get the same limits as the sandboxed shell.

The file tools (`read_file`, `write_file`, `edit`) run inside the Vibe process, outside the
sandbox, so sandbox-exec does not see them. This hook is registered with strict = true and
match "*", after sandbox2.py, and decides about every tool call:

  write_file, edit   only <workdir>/src/**, <workdir>/proof/** and <workdir>/verdict.json
                     (the contract's AGENT_WRITABLE).
  read_file          only below the read roots: the workdir, the wheelhouse (SANDBOX_WHEELHOUSE),
                     the Python install behind <workdir>/venv, and SANDBOX_READ_ALLOW.
  both               never a file named .env or .env.*, never anything in a folder named secrets,
                     never the wrapper's own folder <workdir>/.sandbox, never the Vibe home or
                     ~/.vibe, never a path in SANDBOX_DENY_READ.
  bash, process.start  only when sandbox2.py has already put the wrapper in front of the command.
  anything else      refused. The worker enables four tools only (bash, read_file, write_file,
                     edit). Vibe 3.1.3 still offers `skill` and lets a `run_typescript` program
                     call tools; such calls come through here like any other, so `skill`, the
                     scratchpad, the agent and process tools, and any MCP or connector tool end here.

Every check is made twice: on the path as written and on the path with symlinks resolved, so a
link inside the workdir that points outside does not get through.
"""
from __future__ import annotations

import os
import shlex
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import hook_common as common  # noqa: E402

HOOK = "path_hook"

# The contract's AGENT_WRITABLE (src/vulnerability_agent/contract.py). A test keeps the two equal.
WRITABLE_DIRS = ("src", "proof")
WRITABLE_FILES = ("verdict.json",)

READ_TOOLS = frozenset({"file_system.read_file"})
WRITE_TOOLS = frozenset({"file_system.write_file", "file_system.edit"})
SANDBOX_OWN_DIR = ".sandbox"  # the wrapper's HOME, temp folder and uv cache; links are allowed in there
PATH_KEYS = ("file_path", "path")  # Vibe hands hooks `file_path`; the runtime's own name is `path`


def tool_path(tool_input: dict) -> str:
    """The one path argument of a file tool call."""
    found = [tool_input[key] for key in PATH_KEYS if key in tool_input]
    if len(found) != 1 or not isinstance(found[0], str) or not found[0].strip():
        raise common.Refused("the call must name exactly one file path")
    path = found[0]
    if "\x00" in path:
        raise common.Refused("the path holds a NUL character")
    if path.startswith("~"):
        raise common.Refused("paths starting with ~ are not allowed; use a path inside the run folder")
    return path


def both_forms(path: str, base: Path) -> tuple[Path, Path]:
    """The path as written (made absolute, `..` removed) and the path with symlinks resolved."""
    joined = path if os.path.isabs(path) else os.path.join(str(base), path)
    return Path(os.path.normpath(joined)), Path(os.path.realpath(joined))


def is_secret_name(path: Path) -> bool:
    return any(part == ".env" or part.startswith(".env.") or part == "secrets" for part in path.parts)


def denied_roots() -> list[Path]:
    roots = [common.real_home() / ".vibe"]
    vibe_home = os.environ.get("VIBE_HOME", "")
    if vibe_home:
        roots.append(Path(os.path.realpath(vibe_home)))
    roots.extend(common.path_list("SANDBOX_DENY_READ"))
    return roots


def check_not_denied(written: Path, resolved: Path, workdir: Path) -> None:
    for form in (written, resolved):
        if is_secret_name(form):
            raise common.Refused(".env files and secrets folders are off limits")
        if common.is_inside(form, workdir / SANDBOX_OWN_DIR):
            raise common.Refused("the sandbox's own folder is off limits for the file tools")
        for root in denied_roots():
            if common.is_inside(form, root):
                raise common.Refused("that path is off limits for this run")


def read_roots(workdir: Path) -> list[Path]:
    roots = [workdir]
    wheelhouse = os.environ.get("SANDBOX_WHEELHOUSE", "")
    if wheelhouse and os.path.isabs(wheelhouse):
        roots.append(Path(os.path.realpath(wheelhouse)))
    # The interpreter behind the venv: its install folder holds the standard library's source.
    interpreter = Path(os.path.realpath(workdir / "venv" / "bin" / "python"))
    if interpreter.is_file() and interpreter.parent.name == "bin":
        roots.append(interpreter.parent.parent)
    roots.extend(common.path_list("SANDBOX_READ_ALLOW"))
    return roots


def check_read(tool_input: dict, workdir: Path, base: Path) -> str:
    written, resolved = both_forms(tool_path(tool_input), base)
    check_not_denied(written, resolved, workdir)
    if not any(common.is_inside(resolved, root) for root in read_roots(workdir)):
        raise common.Refused(
            "read_file is limited to the run folder (src/, proof/, venv/), the wheelhouse and the Python install"
        )
    return str(resolved)


def check_write(tool_input: dict, workdir: Path, base: Path) -> str:
    written, resolved = both_forms(tool_path(tool_input), base)
    check_not_denied(written, resolved, workdir)
    inside_dir = any(workdir / name in resolved.parents for name in WRITABLE_DIRS)
    is_file = any(resolved == workdir / name for name in WRITABLE_FILES)
    if not (inside_dir or is_file):
        raise common.Refused(
            "writes are limited to src/, proof/ and verdict.json in the run folder; "
            "the installed library under venv/ must not be edited"
        )
    if resolved.is_dir():
        raise common.Refused("that path is a folder")
    return str(resolved)


def check_shell(tool_input: dict) -> str:
    """sandbox2.py runs first. If the command does not arrive wrapped, something is wrong."""
    command = tool_input.get("command")
    try:
        parts = shlex.split(command) if isinstance(command, str) else []
    except ValueError:
        parts = []
    if len(parts) != 2 or parts[0] != str(common.DOUANE):
        raise common.Refused("the shell command did not go through the sandbox wrapper, so it was refused")
    return "wrapped"


def decide(payload: dict) -> None:
    tool = payload["tool_name"]
    tool_input = payload["tool_input"]
    workdir = common.workdir()
    cwd = payload.get("cwd")
    base = Path(os.path.realpath(cwd)) if isinstance(cwd, str) and os.path.isabs(cwd) else workdir
    if tool in READ_TOOLS:
        detail = check_read(tool_input, workdir, base)
    elif tool in WRITE_TOOLS:
        detail = check_write(tool_input, workdir, base)
    elif common.is_shell_tool(tool):
        detail = check_shell(tool_input)
    else:
        raise common.Refused(f"the tool {tool} is not available in this run")
    common.log(HOOK, tool, "allow", detail)


if __name__ == "__main__":
    common.run(HOOK, decide)
