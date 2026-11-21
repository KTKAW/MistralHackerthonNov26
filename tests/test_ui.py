"""Tests for worker/ui.py — the sandbox audit console.

Seeds a fake runs/ tree in tmp_path and drives the FastAPI app through
starlette's TestClient (httpx is in the wheelhouse). The playground tests
need macOS sandbox-exec and are skipped elsewhere.
"""
import json
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "worker"))

import ui  # noqa: E402

VERDICT = {
    "repo": "demo", "advisory": {"id": "CVE-2026-96760", "package": "authlib",
                                 "affected_range": "<1.9.0",
                                 "flawed_function": "authlib.jose.JsonWebSignature.deserialize_json"},
    "verdict": "affected_proven",
    "reason": "reachable via POST /token",
    "path": [{"file": "src/app.py", "line": 10, "note": "entry"}],
    "proof": ["tests/test_proof.py::test_x"],
    "suite": {"before": {"passed": 1, "failed": 1}, "after": {"passed": 2, "failed": 0}},
    "follow_ups": [],
}

HOOK_LOG = "\n".join([
    json.dumps({"event": "rewrite", "tool": "bash", "original": "pytest -q",
                "rewritten": "/x/douane 'pytest -q'", "hook": "sandbox2"}),
    json.dumps({"event": "rewrite", "tool": "process_start", "original": "make",
                "rewritten": "/x/douane 'make'", "hook": "sandbox2"}),
    json.dumps({"event": "deny", "tool": "bash", "reason": "empty command", "hook": "sandbox2"}),
    json.dumps({"event": "deny", "tool": "read_file", "reason": "secrets", "path": "/w/.env",
                "hook": "path_hook"}),
    json.dumps({"event": "allow", "tool": "read_file", "path": "/w/src/a.py", "hook": "path_hook"}),
]) + "\n"


@pytest.fixture
def runs_root(tmp_path):
    """runs/<run>/<repo>/ prepared work copy + a raw template dir to exclude."""
    work = tmp_path / "runs" / "r1" / "demo"
    (work / "src" / "src").mkdir(parents=True)
    (work / "src" / "src" / "app.py").write_text("print('hi')\n")
    (work / ".env").write_text("MISTRAL_API_KEY=sk-test\n")
    (work / "advisory.json").write_text(json.dumps(VERDICT["advisory"]))
    (work / "verdict.json").write_text(json.dumps(VERDICT))
    (work / "vibe").mkdir()
    (work / "vibe" / "export.json").write_text(json.dumps(
        {"outcome": "finished", "cost_usd": 0.01,
         "usage": {"total_tokens": 1234, "input_tokens": 1000, "output_tokens": 234}}))
    (work / "hook.log").write_text(HOOK_LOG)
    # raw pre-seeded template: has src/ but no advisory.json → must NOT be a card
    tmpl = tmp_path / "runs" / "r1" / "src"
    (tmpl / "src").mkdir(parents=True)
    return tmp_path / "runs"


@pytest.fixture
def client(runs_root):
    return TestClient(ui.create_app(runs_root=runs_root))


def test_health(client, runs_root):
    r = client.get("/api/health")
    assert r.status_code == 200 and r.json()["ok"] is True
    assert r.json()["runs_root"] == str(runs_root)


def test_runs_list_excludes_template_dirs(client):
    runs = client.get("/api/runs").json()["runs"]
    assert [r["repo"] for r in runs] == ["demo"]
    card = runs[0]
    assert card["run_id"] == "r1" and card["verdict"] == "affected_proven"
    assert card["douane_pct"] == 67  # 2 rewrites / 3 sandbox2 shell calls
    assert card["deny_count"] == 2   # one sandbox2 deny + one path_hook deny
    assert card["tokens"] == 1234 and card["cost_usd"] == 0.01


def test_run_detail(client):
    d = client.get("/api/runs/r1/demo").json()
    assert d["stages"]["verdict"] is True and d["stages"]["venv"] is False
    assert d["verdict"]["verdict"] == "affected_proven"
    assert d["hook_stats"]["rewrite"] == 2
    assert d["export"]["outcome"] == "finished"


def test_run_detail_404_and_bad_names(client):
    assert client.get("/api/runs/r1/nope").status_code == 404
    assert client.get("/api/runs/r1/a%2Fb").status_code == 404
    assert client.get("/api/runs/..%2F..%2Fetc/x").status_code == 404


def test_file_endpoint_serves_work_copy(client):
    r = client.get("/api/runs/r1/demo/file", params={"path": "src/src/app.py"})
    assert r.status_code == 200
    assert "print('hi')" in r.json()["content"]
    assert r.json()["rel"] == "src/src/app.py"


def test_file_endpoint_refuses_secrets_and_outside(client):
    assert client.get("/api/runs/r1/demo/file", params={"path": ".env"}).status_code == 403
    assert client.get("/api/runs/r1/demo/file", params={"path": "../demo/.env"}).status_code == 403
    assert client.get("/api/runs/r1/demo/file", params={"path": "/etc/passwd"}).status_code == 403
    assert client.get("/api/runs/r1/demo/file",
                      params={"path": "../../vibe-home/.env"}).status_code in (403, 404)
    assert client.get("/api/runs/r1/demo/file", params={"path": "nope.txt"}).status_code == 404


def test_validate_endpoint(client):
    r = client.post("/api/runs/r1/demo/validate")
    assert r.status_code == 200 and r.json()["ok"] is True


def test_validate_endpoint_rejects_bad_verdict(client, runs_root):
    bad = dict(VERDICT)
    del bad["proof"]  # required by the schema
    (runs_root / "r1" / "demo" / "verdict.json").write_text(json.dumps(bad))
    r = client.post("/api/runs/r1/demo/validate")
    assert r.json()["ok"] is False and "INVALID" in r.json()["output"]


def test_hooklog_sse_streams_existing_lines(client):
    with client.stream("GET", "/api/runs/r1/demo/hooklog", params={"since": 0}) as r:
        assert r.status_code == 200
        lines = []
        for line in r.iter_lines():
            if line.startswith("data: "):
                lines.append(json.loads(line[6:]))
            if len(lines) >= 5:
                break
    assert lines[0]["event"] == "rewrite"
    assert any(e["event"] == "deny" for e in lines)


def test_start_run_rejects_unknown_repo(client):
    r = client.post("/api/runs", json={"repo": "no-such-repo"})
    assert r.status_code == 404


def test_stop_unknown_run_404(client):
    assert client.post("/api/runs/nope/stop").status_code == 404


def test_policy_endpoint(client):
    j = client.get("/api/policy").json()
    assert "(deny network*)" in j["profile"]
    assert "__WORKDIR__" not in j["profile"]  # placeholders substituted
    assert "sandbox-exec" in j["douane"]


@pytest.mark.skipif(sys.platform != "darwin", reason="playground needs macOS sandbox-exec")
def test_playground_denies_network_and_escape_allows_tmp(client):
    import os
    r = client.post("/api/playground", json={"cmd": "curl -s --max-time 5 https://example.com"})
    assert r.status_code == 200 and r.json()["rc"] != 0  # network* denied
    r = client.post("/api/playground", json={"cmd": "touch ../escape-ui-test"})
    assert r.json()["rc"] != 0  # write outside workdir denied
    assert not (client.app.state.runs_root / "escape-ui-test").exists()
    # /tmp (realpath /private/tmp) is allowed by the profile
    marker = f"/tmp/le-chonk-ui-test-{os.getpid()}"
    r = client.post("/api/playground", json={"cmd": f"touch {marker}"})
    assert r.json()["rc"] == 0 and Path(marker).exists()
    Path(marker).unlink()
    r = client.post("/api/playground", json={"cmd": "cat .env"})
    assert r.json()["rc"] != 0  # .env unreadable (absent here, or denied)


@pytest.mark.skipif(sys.platform != "darwin", reason="playground needs macOS sandbox-exec")
def test_playground_empty_cmd_400(client):
    assert client.post("/api/playground", json={"cmd": "  "}).status_code == 400
