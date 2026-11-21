#!/usr/bin/env python3
"""path_hook.py — Vibe pre_tool hook restricting the file tools.

File tools (read_file / write_file / edit) bypass the shell sandbox, so this hook
confines them by path. SANDBOX_WORKDIR is the work-copy root (runs/<run>/<repo>),
which contains src/ (the repo copy), .venv/, wheelhouse/, advisory.json, schema/.

Rules:
  write_file / edit : allow only inside $SANDBOX_WORKDIR/src/, plus the single
                      output file $SANDBOX_WORKDIR/verdict.json.
  read_file         : never .env (anywhere) or any secrets/ directory; allow inside
                      the work copy and read-only system paths only.

Vibe 3.1.3 wire protocol: JSON payload on stdin (tool_name is qualified, e.g.
file_system.write_file; tool_input uses "path" for read_file/write_file and
"file_path" for edit). Answer on stdout: {"decision": "deny", "reason": ...} blocks
the call; exit 0 with empty stdout passes through. Registered with strict = true.
Every decision is appended as a JSON line to $HOOK_LOG.
"""
import json
import os
import sys

WORK = os.path.realpath(os.environ.get("SANDBOX_WORKDIR") or os.getcwd())
SRC = os.path.join(WORK, "src")
VERDICT = os.path.join(WORK, "verdict.json")
# Read-only system paths the sandbox profile allows. Deliberately narrow: /private
# also holds /private/var/folders (pytest tmp dirs) and /private/tmp, which are NOT
# system files — outside-workdir reads of those must be denied.
SYSTEM_READ_PREFIXES = (
    "/usr/", "/bin/", "/sbin/", "/System/", "/Library/",
    "/etc/", "/dev/", "/private/etc/", "/private/dev/",
)
WRITE_TOOLS = {"write_file", "edit"}


def _log(event):
    event["hook"] = "path_hook"
    log = os.environ.get("HOOK_LOG") or os.path.join(WORK, "hook.log")
    try:
        with open(log, "a") as f:
            f.write(json.dumps(event) + "\n")
    except Exception:
        pass


def _deny(reason):
    _log({"event": "deny", "reason": reason})
    print(json.dumps({"decision": "deny", "reason": reason}))
    return 0


def _short_name(tool_name):
    return (tool_name or "").split(".")[-1]


def main():
    try:
        payload = json.load(sys.stdin)
    except Exception as e:
        _log({"event": "error", "detail": "unparseable stdin: %s" % e})
        print(json.dumps({"decision": "deny", "reason": "path_hook: unreadable hook payload"}))
        return 0

    tool = _short_name(payload.get("tool_name", ""))
    if tool not in WRITE_TOOLS and tool != "read_file":
        return 0  # not a file-path tool — pass through

    tool_input = payload.get("tool_input") or {}
    raw_path = tool_input.get("path") or tool_input.get("file_path") or ""
    if not raw_path:
        return 0  # nothing to confine; let tool schema validation handle it

    cwd = payload.get("cwd") or os.getcwd()
    if not os.path.isabs(raw_path):
        raw_path = os.path.join(cwd, raw_path)
    rp = os.path.realpath(raw_path)

    if tool in WRITE_TOOLS:
        if rp == VERDICT or rp.startswith(SRC + os.sep):
            _log({"event": "allow", "tool": tool, "path": rp})
            return 0
        return _deny(
            "path_hook: %s confined to %s/src (plus verdict.json at the work-copy root); "
            "refused %s" % (tool, WORK, rp)
        )

    # read_file
    parts = rp.split(os.sep)
    if ".env" in parts or "secrets" in parts or rp == "/dev/urandom":
        return _deny("path_hook: reading secrets (.env / secrets/) is never allowed; refused %s" % rp)
    if rp.startswith(WORK + os.sep) or rp == WORK:
        _log({"event": "allow", "tool": tool, "path": rp})
        return 0
    if rp.startswith(SYSTEM_READ_PREFIXES):
        _log({"event": "allow", "tool": tool, "path": rp, "system": True})
        return 0
    return _deny(
        "path_hook: read outside the work copy (%s) refused; read %s" % (WORK, rp)
    )


if __name__ == "__main__":
    sys.exit(main())
