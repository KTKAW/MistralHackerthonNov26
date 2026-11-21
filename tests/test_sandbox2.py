"""Unit tests for sandbox/sandbox2.py — the pre_tool hook that rewrites every
shell command (bash / process_start) to run through douane.

Contract under test (track-A prompt, A2):
  - non-shell tools pass through untouched (exit 0, empty stdout)
  - shell commands are rewritten to `<abs path to douane> '<shquoted command>'`
  - empty command -> deny; unparseable stdin -> deny (strict hook: never run unsandboxed)
  - every decision is appended as a JSON line to $HOOK_LOG
"""
import json
import subprocess

from conftest import DOUANE, SANDBOX2, run_hook, shquote


def bash_payload(command, **extra_input):
    tool_input = {"command": command}
    tool_input.update(extra_input)
    return {"hook_event_name": "pre_tool", "tool_name": "file_system.bash", "tool_input": tool_input}


class TestPassThrough:
    def test_non_shell_tool_passes_through_untouched(self):
        rc, out, parsed, _ = run_hook(SANDBOX2, {"tool_name": "file_system.read_file",
                                                 "tool_input": {"path": "/x"}})
        assert rc == 0
        assert out == "" and parsed is None

    def test_missing_tool_name_passes_through(self):
        rc, out, parsed, _ = run_hook(SANDBOX2, {"tool_input": {"command": "ls"}})
        assert rc == 0
        assert out == ""


class TestRewrite:
    def test_bash_command_is_rewritten_through_douane(self):
        cmd = "pytest -q"
        rc, out, parsed, _ = run_hook(SANDBOX2, bash_payload(cmd))
        assert rc == 0
        assert parsed["decision"] == "allow"
        rewritten = parsed["hook_specific_output"]["tool_input"]["command"]
        assert rewritten == f"{DOUANE} {shquote(cmd)}"

    def test_other_tool_input_keys_are_preserved(self):
        rc, _, parsed, _ = run_hook(SANDBOX2, bash_payload("ls", timeout_seconds=120))
        assert rc == 0
        new_input = parsed["hook_specific_output"]["tool_input"]
        assert new_input["timeout_seconds"] == 120
        assert new_input["command"].startswith(str(DOUANE))

    def test_process_start_is_also_sandboxed(self):
        # qualified name "process.start" must map to short name "process_start"
        payload = {"tool_name": "process.start", "tool_input": {"command": "make build"}}
        rc, _, parsed, _ = run_hook(SANDBOX2, payload)
        assert rc == 0
        assert parsed["decision"] == "allow"
        assert parsed["hook_specific_output"]["tool_input"]["command"] == \
            f"{DOUANE} {shquote('make build')}"

    def test_process_start_underscore_variant(self):
        payload = {"tool_name": "process_start", "tool_input": {"command": "make build"}}
        rc, _, parsed, _ = run_hook(SANDBOX2, payload)
        assert rc == 0 and parsed["decision"] == "allow"

    def test_unqualified_bash_name(self):
        payload = {"tool_name": "bash", "tool_input": {"command": "ls"}}
        rc, _, parsed, _ = run_hook(SANDBOX2, payload)
        assert rc == 0 and parsed["decision"] == "allow"

    def test_rewritten_command_round_trips_through_sh(self):
        # The quoted command must survive shell word-splitting unchanged:
        # strip the douane prefix, let /bin/sh split the rest, compare arg 1.
        cmd = "echo 'it'\\''s a $test`with` \"quotes\" && rm -rf /"
        rc, _, parsed, _ = run_hook(SANDBOX2, bash_payload(cmd))
        assert rc == 0
        rewritten = parsed["hook_specific_output"]["tool_input"]["command"]
        assert rewritten.startswith(str(DOUANE) + " ")
        quoted = rewritten[len(str(DOUANE)) + 1:]
        probe = subprocess.run(
            ["/bin/sh", "-c", 'set -- %s; printf %%s "$1"' % quoted],
            capture_output=True, text=True,
        )
        assert probe.stdout == cmd


class TestDeny:
    def test_empty_command_denied(self):
        rc, _, parsed, _ = run_hook(SANDBOX2, bash_payload(""))
        assert rc == 0
        assert parsed["decision"] == "deny"
        assert "empty" in parsed["reason"]

    def test_whitespace_only_command_denied(self):
        rc, _, parsed, _ = run_hook(SANDBOX2, bash_payload("   \n\t "))
        assert rc == 0 and parsed["decision"] == "deny"

    def test_missing_command_key_denied(self):
        payload = {"tool_name": "file_system.bash", "tool_input": {}}
        rc, _, parsed, _ = run_hook(SANDBOX2, payload)
        assert rc == 0 and parsed["decision"] == "deny"

    def test_unparseable_stdin_denied(self):
        rc, _, parsed, _ = run_hook(SANDBOX2, None, stdin_text="this is not json{{{")
        assert rc == 0
        assert parsed["decision"] == "deny"
        assert "unreadable" in parsed["reason"]


class TestHookLog:
    def test_rewrite_is_logged_as_json_line(self, tmp_path):
        log = tmp_path / "hook.log"
        cmd = "echo hi"
        run_hook(SANDBOX2, bash_payload(cmd), env={"HOOK_LOG": str(log)})
        events = [json.loads(line) for line in log.read_text().splitlines()]
        assert len(events) == 1
        ev = events[0]
        assert ev["hook"] == "sandbox2"
        assert ev["event"] == "rewrite"
        assert ev["tool"] == "bash"
        assert ev["original"] == cmd
        assert ev["rewritten"] == f"{DOUANE} {shquote(cmd)}"

    def test_deny_is_logged(self, tmp_path):
        log = tmp_path / "hook.log"
        run_hook(SANDBOX2, bash_payload(""), env={"HOOK_LOG": str(log)})
        events = [json.loads(line) for line in log.read_text().splitlines()]
        assert events[-1]["event"] == "deny"
        assert events[-1]["hook"] == "sandbox2"

    def test_error_is_logged(self, tmp_path):
        log = tmp_path / "hook.log"
        run_hook(SANDBOX2, None, stdin_text="nope", env={"HOOK_LOG": str(log)})
        events = [json.loads(line) for line in log.read_text().splitlines()]
        assert events[-1]["event"] == "error"

    def test_default_log_location_is_workdir_hook_log(self, workdir):
        run_hook(SANDBOX2, bash_payload("ls"), env={"SANDBOX_WORKDIR": str(workdir)})
        log = workdir / "hook.log"
        assert log.exists()
        assert json.loads(log.read_text().splitlines()[-1])["event"] == "rewrite"
