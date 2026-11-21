"""Contract tests for vibe-home/: the hooks must be registered as strict
pre_tool hooks pointing at the real scripts, and douane must be allowlisted —
otherwise every rewritten shell command would stop for a manual approval
(or, worse, the hooks would silently not run).
"""
import tomllib
from pathlib import Path

from conftest import DOUANE, PATH_HOOK, REPO_ROOT, SANDBOX2, VIBE_HOME


def load(name):
    return tomllib.loads((VIBE_HOME / name).read_text())


def test_both_hooks_registered_strict_pre_tool():
    hooks = {h["name"]: h for h in load("hooks.toml")["hooks"]}
    assert "sandbox-shell" in hooks and "sandbox-paths" in hooks
    for name in ("sandbox-shell", "sandbox-paths"):
        h = hooks[name]
        assert h["type"] == "pre_tool"
        assert h["strict"] is True, f"{name} must be strict (crash => deny, never unsandboxed)"


def test_hook_commands_point_at_existing_scripts():
    hooks = {h["name"]: h for h in load("hooks.toml")["hooks"]}
    shell_cmd = hooks["sandbox-shell"]["command"]
    path_cmd = hooks["sandbox-paths"]["command"]
    assert str(SANDBOX2) in shell_cmd and Path(SANDBOX2).exists()
    assert str(PATH_HOOK) in path_cmd and Path(PATH_HOOK).exists()


def test_shell_hook_matches_bash_and_process_start():
    hooks = {h["name"]: h for h in load("hooks.toml")["hooks"]}
    match = hooks["sandbox-shell"]["match"]
    assert "bash" in match and "process" in match


def test_douane_is_allowlisted_and_executable():
    cfg = load("config.toml")
    allowlist = cfg["tools"]["bash"]["allowlist"]
    assert str(DOUANE) in allowlist
    assert DOUANE.exists() and DOUANE.stat().st_mode & 0o111


def test_telemetry_disabled():
    cfg = load("config.toml")
    assert cfg.get("enable_telemetry") is False
    assert cfg.get("enable_otel") is False


def test_gitignore_never_commits_secrets_or_runs():
    ignore = (REPO_ROOT / ".gitignore").read_text().splitlines()
    for entry in (".env", "vibe-home/", "runs/", "wheelhouse/"):
        assert entry in ignore
