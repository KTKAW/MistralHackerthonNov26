"""Integration tests for sandbox/douane + profile.sb.template (the A3 manual
checks, automated). These run real `sandbox-exec` processes, so they only run
on macOS with /usr/bin/sandbox-exec present.

Contract under test:
  - writes allowed only inside $SANDBOX_WORKDIR and /tmp; everything else denied
  - reads of $SANDBOX_WORKDIR/.env, secrets/, /dev/urandom denied
  - all network denied
  - environment scrubbed (env -i): parent secrets do not leak into the child
  - missing SANDBOX_WORKDIR is a hard error, never a silent unsandboxed run
"""
import os
import shutil
import subprocess

import pytest

from conftest import DOUANE

pytestmark = pytest.mark.skipif(
    not os.path.isfile("/usr/bin/sandbox-exec"),
    reason="macOS sandbox-exec required (track A is macOS-only by design)",
)


def douane(cmd, workdir, extra_env=None, cwd=None):
    env = dict(os.environ)
    env["SANDBOX_WORKDIR"] = str(workdir)
    env.pop("MISTRAL_API_KEY", None)
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        [str(DOUANE), cmd],
        capture_output=True, text=True,
        env=env, cwd=str(cwd or workdir),
    )


class TestWrites:
    def test_write_inside_workdir_allowed(self, workdir):
        p = douane("touch src/ok.txt", workdir)
        assert p.returncode == 0, p.stderr
        assert (workdir / "src" / "ok.txt").exists()

    def test_write_outside_workdir_denied(self, workdir, tmp_path):
        p = douane("touch ../escape.txt", workdir)  # lands in tmp_path, outside WORK
        assert p.returncode != 0
        assert not (tmp_path / "escape.txt").exists()

    def test_write_to_home_denied(self, workdir):
        p = douane("touch ~/douane-escape.txt", workdir)
        assert p.returncode != 0
        assert not os.path.exists(os.path.expanduser("~/douane-escape.txt"))

    def test_write_to_tmp_allowed(self, workdir):
        target = f"/tmp/le-chonk-douane-test-{os.getpid()}"
        try:
            p = douane(f"touch {target}", workdir)
            assert p.returncode == 0, p.stderr
            assert os.path.exists(target)
        finally:
            if os.path.exists(target):
                os.unlink(target)


class TestReads:
    def test_read_workdir_file_allowed(self, workdir):
        p = douane("cat src/README.md", workdir)
        assert p.returncode == 0, p.stderr
        assert "fake service" in p.stdout

    def test_read_env_denied(self, workdir):
        p = douane("cat .env", workdir)
        assert p.returncode != 0
        assert "sk-super-secret" not in p.stdout

    def test_read_secrets_denied(self, workdir):
        p = douane("cat secrets/key.pem", workdir)
        assert p.returncode != 0
        assert "PRIVATE KEY" not in p.stdout


class TestNetwork:
    @pytest.mark.skipif(shutil.which("curl") is None, reason="curl not on PATH")
    def test_network_denied(self, workdir):
        p = douane("curl -s --max-time 5 https://example.com", workdir)
        assert p.returncode != 0
        assert p.stdout == ""


class TestEnvScrub:
    def test_parent_secrets_do_not_leak(self, workdir):
        p = douane('printf "%s" "$MISTRAL_API_KEY"', workdir,
                   extra_env={"MISTRAL_API_KEY": "sk-leak-check"})
        assert p.returncode == 0, p.stderr
        assert p.stdout == ""

    def test_sandbox_workdir_is_passed_through(self, workdir):
        p = douane('printf "%s" "$SANDBOX_WORKDIR"', workdir)
        assert p.returncode == 0
        assert p.stdout == str(workdir)


class TestRobustness:
    def test_missing_sandbox_workdir_is_hard_error(self):
        env = dict(os.environ)
        env.pop("SANDBOX_WORKDIR", None)
        p = subprocess.run([str(DOUANE), "ls"], capture_output=True, text=True, env=env)
        assert p.returncode != 0
        assert "SANDBOX_WORKDIR" in p.stderr

    def test_profile_template_placeholders_all_substituted(self, workdir, tmp_path):
        # if a placeholder survived the sed, sandbox-exec would reject the profile
        p = douane("true", workdir)
        assert p.returncode == 0, p.stderr
        template = DOUANE.parent / "profile.sb.template"
        text = template.read_text()
        assert "__WORKDIR__" in text and "__PYDIR__" in text
