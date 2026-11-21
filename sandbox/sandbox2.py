#!/usr/bin/env python3
"""sandbox2.py — Vibe pre_tool hook. Rewrites every shell command to run through douane.

Wire protocol (Vibe 3.1.3): JSON payload on stdin, discriminated by hook_event_name.
pre_tool payload carries the QUALIFIED tool name (file_system.bash, process.start, ...)
and tool_input. We answer on stdout with a structured response:
  {"decision": "allow", "hook_specific_output": {"tool_input": {...}}}  -> rewrite args
  {"decision": "deny", "reason": "..."}                                  -> block the call
Exit 0 + empty stdout = pass through. The hook is registered with strict = true, so any
crash/timeout also denies the call (never runs unsandboxed).

Every decision is appended as a JSON line to $HOOK_LOG (default: $SANDBOX_WORKDIR/hook.log)
so run audits can count sandboxed vs total shell commands.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DOUANE = os.path.join(HERE, "douane")
SHELL_TOOLS = {"bash", "process_start"}


def _log(event):
    event["hook"] = "sandbox2"
    log = os.environ.get("HOOK_LOG") or os.path.join(
        os.environ.get("SANDBOX_WORKDIR") or os.getcwd(), "hook.log"
    )
    try:
        with open(log, "a") as f:
            f.write(json.dumps(event) + "\n")
    except Exception:
        pass  # logging must never break the hook


def _shquote(s):
    return "'" + s.replace("'", "'\\''") + "'"


def _short_name(tool_name):
    # payload tool_name is qualified (file_system.bash); short name is after the dot,
    # except process.start whose short name is process_start.
    short = (tool_name or "").split(".")[-1]
    if short == "start":
        return "process_start"
    return short


def main():
    try:
        payload = json.load(sys.stdin)
    except Exception as e:
        _log({"event": "error", "detail": "unparseable stdin: %s" % e})
        print(json.dumps({"decision": "deny", "reason": "sandbox2: unreadable hook payload"}))
        return 0

    tool = _short_name(payload.get("tool_name", ""))
    if tool not in SHELL_TOOLS:
        return 0  # not a shell tool — pass through untouched

    tool_input = payload.get("tool_input") or {}
    cmd = tool_input.get("command") or ""
    if not cmd.strip():
        _log({"event": "deny", "tool": tool, "reason": "empty command"})
        print(json.dumps({"decision": "deny", "reason": "sandbox2: empty command"}))
        return 0

    rewritten = DOUANE + " " + _shquote(cmd)
    new_input = dict(tool_input)
    new_input["command"] = rewritten
    _log({"event": "rewrite", "tool": tool, "original": cmd, "rewritten": rewritten})
    print(json.dumps({"decision": "allow", "hook_specific_output": {"tool_input": new_input}}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
