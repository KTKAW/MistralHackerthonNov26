"""Shared by the two Vibe `pre_tool` hooks, sandbox2.py and path_hook.py. Standard library only.

The protocol, as Vibe 3.1.3 implements it (see docs/AGENT.md for the source files):

  stdin   one JSON object: hook_event_name ("pre_tool"), tool_name (qualified, such as
          "file_system.bash"), tool_input (the arguments), tool_call_id, session_id, cwd,
          transcript_path, parent_session_id.
  stdout  nothing: the call goes ahead unchanged.
          {"decision": "deny", "reason": "..."}: the call is refused and the model gets the reason.
          {"hook_specific_output": {"tool_input": {...}}}: the call goes ahead with these arguments.
  exit    anything but 0, or stdout that is not such an object, is a failure. Both hooks are
          registered with strict = true, so Vibe turns a failure into a denial.

Both hooks answer every question they cannot settle with a denial.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import pwd
import sys
from pathlib import Path

SANDBOX_DIR = Path(__file__).resolve().parent
DOUANE = SANDBOX_DIR / "douane"

# Tool names as they appear in the payload of Vibe 3.1.3. The short names are what the model calls.
SHELL_TOOLS = frozenset({"file_system.bash", "process.start"})
SHELL_TOOL_ALIASES = frozenset({"bash", "process_start", "git_bash", "powershell"})


class Refused(Exception):
    """The call must not go ahead. The text is shown to the model."""


def read_payload() -> dict:
    """The hook's input. Anything that is not a well-formed pre_tool payload is refused."""
    raw = sys.stdin.read()
    try:
        payload = json.loads(raw)
    except ValueError:
        raise Refused("the hook input is not JSON") from None
    if not isinstance(payload, dict):
        raise Refused("the hook input is not a JSON object")
    if payload.get("hook_event_name") != "pre_tool":
        raise Refused("the hook input is not a pre_tool event")
    if not isinstance(payload.get("tool_name"), str) or not payload["tool_name"]:
        raise Refused("the hook input names no tool")
    if not isinstance(payload.get("tool_input"), dict):
        raise Refused("the hook input has no tool arguments")
    return payload


def is_shell_tool(name: str) -> bool:
    return name in SHELL_TOOLS or name in SHELL_TOOL_ALIASES


def workdir() -> Path:
    """SANDBOX_WORKDIR as a real path. Without it nothing can be decided."""
    value = os.environ.get("SANDBOX_WORKDIR", "")
    if not value or not os.path.isabs(value) or not os.path.isdir(value):
        raise Refused("SANDBOX_WORKDIR is not set to an existing absolute folder")
    return Path(os.path.realpath(value))


def real_home() -> Path:
    """The user's home from the password database, not from $HOME."""
    return Path(os.path.realpath(pwd.getpwuid(os.getuid()).pw_dir))


def path_list(variable: str) -> list[Path]:
    """A colon-separated list of absolute paths from the environment, as real paths."""
    paths = []
    for entry in os.environ.get(variable, "").split(":"):
        if not entry:
            continue
        if not os.path.isabs(entry):
            raise Refused(f"{variable} holds a path that is not absolute")
        paths.append(Path(os.path.realpath(entry)))
    return paths


def is_inside(path: Path, root: Path) -> bool:
    """True when `path` is `root` or lies below it. Both are expected to be real paths."""
    return path == root or root in path.parents


def log(hook: str, tool: str, decision: str, detail: str = "") -> None:
    """One line per decision in SANDBOX_HOOK_LOG. The worker counts these lines; a log that cannot
    be written never changes the decision."""
    target = os.environ.get("SANDBOX_HOOK_LOG", "")
    if not target:
        return
    line = {
        "at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "hook": hook,
        "tool": tool,
        "decision": decision,
        "detail": detail[:300],
    }
    try:
        with open(target, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(line) + "\n")
    except OSError:
        pass


def allow() -> None:
    """Let the call through unchanged: exit 0 with nothing on stdout."""
    sys.exit(0)


def rewrite(tool_input: dict) -> None:
    sys.stdout.write(json.dumps({"hook_specific_output": {"tool_input": tool_input}}))
    sys.exit(0)


def deny(reason: str) -> None:
    sys.stdout.write(json.dumps({"decision": "deny", "reason": reason}))
    sys.exit(0)


def run(hook: str, decide) -> None:
    """Run `decide(payload)`. A refusal, or any error at all, ends in a denial."""
    tool = "?"
    try:
        payload = read_payload()
        tool = payload["tool_name"]
        decide(payload)
        allow()
    except Refused as refusal:
        log(hook, tool, "deny", str(refusal))
        deny(str(refusal))
    except SystemExit:
        raise
    except BaseException as error:  # a broken hook must never let a call through
        log(hook, tool, "deny", f"hook error: {type(error).__name__}")
        deny(f"the {hook} hook failed ({type(error).__name__}), so the call was refused")
