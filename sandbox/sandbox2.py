"""Vibe `pre_tool` hook: every shell command runs through the sandbox wrapper.

Registered with strict = true and match "*". For a shell tool (`bash`, and `process.start` for
background commands) it replaces the command with

    /abs/path/sandbox/douane '<the original command>'

so the command runs under sandbox-exec with a clean environment. Every other tool passes through
untouched; path_hook.py, which runs next, decides about those and also checks that a shell command
really arrives wrapped.

Vibe shows the model the rewritten command in the conversation, so the model sometimes sends a
command that already starts with the wrapper. Such a command is unwrapped first and wrapped once.
"""
from __future__ import annotations

import shlex
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import hook_common as common  # noqa: E402

HOOK = "sandbox2"


def unwrap(command: str) -> str:
    """Strip our own wrapper from a command the model copied from an earlier, rewritten call."""
    for _ in range(5):
        try:
            parts = shlex.split(command)
        except ValueError:
            return command
        if len(parts) == 2 and parts[0] == str(common.DOUANE):
            command = parts[1]
        else:
            return command
    return command


def wrap(command: str) -> str:
    return f"{shlex.quote(str(common.DOUANE))} {shlex.quote(unwrap(command))}"


def decide(payload: dict) -> None:
    tool = payload["tool_name"]
    if not common.is_shell_tool(tool):
        common.log(HOOK, tool, "pass")
        return
    common.workdir()  # refuses when SANDBOX_WORKDIR is missing: the wrapper could not run
    if not common.DOUANE.is_file():
        raise common.Refused("the sandbox wrapper is missing, so no command may run")
    tool_input = dict(payload["tool_input"])
    command = tool_input.get("command")
    if not isinstance(command, str) or not command.strip():
        raise common.Refused("the shell call has no command text")
    if "\x00" in command:
        raise common.Refused("the command holds a NUL character")
    tool_input["command"] = wrap(command)
    common.log(HOOK, tool, "rewrite", unwrap(command))
    common.rewrite(tool_input)


if __name__ == "__main__":
    common.run(HOOK, decide)
