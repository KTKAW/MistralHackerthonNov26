"""Unit tests for sandbox/path_hook.py — the pre_tool hook confining the file
tools to the work copy.

Contract under test (track-A prompt, A2):
  write_file / edit : only inside $SANDBOX_WORKDIR/src/ (+ verdict.json at root)
  read_file         : never .env / secrets/ / /dev/urandom; only inside the
                      work copy or read-only system prefixes
  anything else     : pass through; unparseable stdin -> deny (strict hook)
"""
import json
import os

from conftest import PATH_HOOK, run_hook


def payload(tool, path=None, cwd=None, use_file_path=False):
    key = "file_path" if use_file_path else "path"
    tool_input = {key: path} if path is not None else {}
    p = {"hook_event_name": "pre_tool", "tool_name": f"file_system.{tool}",
         "tool_input": tool_input}
    if cwd:
        p["cwd"] = cwd
    return p


def run(tool, path=None, workdir=None, cwd=None, use_file_path=False, env=None):
    e = {"SANDBOX_WORKDIR": str(workdir)} if workdir else {}
    if env:
        e.update(env)
    return run_hook(PATH_HOOK, payload(tool, path, cwd, use_file_path), env=e)


def assert_allow(res):
    rc, out, parsed, _ = res
    assert rc == 0, out
    assert out == "" and parsed is None  # pass-through


def assert_deny(res, fragment=None):
    rc, _, parsed, _ = res
    assert rc == 0
    assert parsed["decision"] == "deny"
    if fragment:
        assert fragment in parsed["reason"]


class TestWriteConfinement:
    def test_write_inside_src_allowed(self, workdir):
        assert_allow(run("write_file", str(workdir / "src" / "app.py"), workdir))

    def test_write_nested_inside_src_allowed(self, workdir):
        assert_allow(run("write_file", str(workdir / "src" / "pkg" / "mod.py"), workdir))

    def test_write_verdict_json_at_root_allowed(self, workdir):
        assert_allow(run("write_file", str(workdir / "verdict.json"), workdir))

    def test_write_outside_src_denied(self, workdir):
        assert_deny(run("write_file", str(workdir / "export.json"), workdir), "confined")

    def test_write_outside_workdir_denied(self, workdir, tmp_path):
        assert_deny(run("write_file", str(tmp_path / "evil.txt"), workdir))

    def test_write_to_workdir_root_denied(self, workdir):
        # only verdict.json is writable at the root, not arbitrary files
        assert_deny(run("write_file", str(workdir / "notes.txt"), workdir))

    def test_edit_uses_file_path_key(self, workdir):
        assert_allow(run("edit", str(workdir / "src" / "app.py"), workdir, use_file_path=True))
        assert_deny(run("edit", str(workdir / "run.py"), workdir, use_file_path=True))

    def test_relative_path_resolved_against_cwd(self, workdir):
        assert_allow(run("write_file", "new.py", workdir, cwd=str(workdir / "src")))
        assert_deny(run("write_file", "../escape.py", workdir, cwd=str(workdir / "src")))

    def test_symlink_escape_denied(self, workdir, tmp_path):
        outside = tmp_path / "outside.txt"
        outside.write_text("x")
        link = workdir / "src" / "link.txt"
        os.symlink(outside, link)
        assert_deny(run("write_file", str(link), workdir))


class TestReadRules:
    def test_read_env_at_root_denied(self, workdir):
        assert_deny(run("read_file", str(workdir / ".env"), workdir), "secrets")

    def test_read_env_nested_in_src_denied(self, workdir):
        assert_deny(run("read_file", str(workdir / "src" / ".env"), workdir), ".env")

    def test_read_secrets_dir_denied(self, workdir):
        assert_deny(run("read_file", str(workdir / "secrets" / "key.pem"), workdir), "secrets")

    def test_read_dev_urandom_denied(self, workdir):
        assert_deny(run("read_file", "/dev/urandom", workdir))

    def test_read_inside_workdir_allowed(self, workdir):
        assert_allow(run("read_file", str(workdir / "advisory.json"), workdir))
        assert_allow(run("read_file", str(workdir / "src" / "README.md"), workdir))

    def test_read_system_paths_allowed(self, workdir):
        assert_allow(run("read_file", "/usr/bin/python3", workdir))
        assert_allow(run("read_file", "/etc/hosts", workdir))

    def test_read_outside_workdir_denied(self, workdir, tmp_path):
        outside = tmp_path / "elsewhere.txt"
        outside.write_text("x")
        assert_deny(run("read_file", str(outside), workdir), "outside the work copy")

    def test_relative_read_resolved_against_cwd(self, workdir):
        assert_allow(run("read_file", "README.md", workdir, cwd=str(workdir / "src")))
        assert_deny(run("read_file", "../.env", workdir, cwd=str(workdir / "src")))

    def test_symlink_read_escape_denied(self, workdir, tmp_path):
        outside = tmp_path / "secret-outside.txt"
        outside.write_text("x")
        os.symlink(outside, workdir / "src" / "leak.txt")
        assert_deny(run("read_file", str(workdir / "src" / "leak.txt"), workdir))


class TestPassThroughAndRobustness:
    def test_non_file_tool_passes_through(self, workdir):
        assert_allow(run("bash", "/anywhere", workdir))

    def test_missing_path_passes_through(self, workdir):
        # schema validation of the tool args is the tool's own job, not ours
        rc, out, parsed, _ = run_hook(PATH_HOOK, payload("read_file", None),
                                      env={"SANDBOX_WORKDIR": str(workdir)})
        assert rc == 0 and out == ""

    def test_unparseable_stdin_denied(self, workdir):
        rc, _, parsed, _ = run_hook(PATH_HOOK, None, stdin_text="{oops",
                                   env={"SANDBOX_WORKDIR": str(workdir)})
        assert rc == 0
        assert parsed["decision"] == "deny"
        assert "unreadable" in parsed["reason"]


class TestHookLog:
    def test_allow_and_deny_are_logged(self, workdir, hook_log):
        env = {"SANDBOX_WORKDIR": str(workdir), "HOOK_LOG": str(hook_log)}
        run("write_file", str(workdir / "src" / "a.py"), workdir, env={"HOOK_LOG": str(hook_log)})
        run("write_file", str(workdir / "b.txt"), workdir, env={"HOOK_LOG": str(hook_log)})
        events = [json.loads(l) for l in hook_log.read_text().splitlines()]
        assert all(e["hook"] == "path_hook" for e in events)
        assert events[0]["event"] == "allow" and events[0]["tool"] == "write_file"
        assert events[1]["event"] == "deny"
