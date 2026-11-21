"""The cross-run history index: untrusted run folders in, one sanitised capped history.json out.
None of these need the fleet or the wheelhouse."""
import json

from orchestrator import history


def _write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data) if not isinstance(data, str) else data, encoding="utf-8")


def _run(runs, run_id, *, stage="approved", advisory_id="CVE-2026-1111", started_at="2026-11-21T10:00:00+00:00"):
    run_dir = runs / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    _write(run_dir / "run.json", {
        "run_id": run_id, "started_at": started_at, "deadline": "2026-11-22T10:00:00+00:00",
        "stage": stage, "repos": ["billing-api", "auth-gateway"],
        "advisory": {"id": advisory_id, "package": "authlib", "affected_range": "<1.9.1", "flawed_function": "parse"},
        "approved_by": "ada",
    })
    return run_dir


def _verdict(run_dir, repo, advisory_id, verdict, original=None, sim=False):
    _write(run_dir / repo / "verdict.json", {
        "repo": repo, "verdict": verdict,
        "advisory": {"id": advisory_id, "package": "authlib", "affected_range": "<1.9.1", "flawed_function": "parse"},
        "reason": "worker claim", "path": ["auth.py"], "proof": [], "fix": None, "suite": {}, "follow_ups": [],
        "gate": {"passed": verdict == original, "original_verdict": original or verdict,
                 "sim_triage": "downgraded: adversarial sim breach (2 breach(es))" if sim else None,
                 "rules": {}},
    })


def _sim(run_dir, breaches=2, flagged=("CVE-2026-1111",)):
    _write(run_dir / "sim-triage.json", {
        "schema": "sim-triage/1",
        "defenses": {"breaches": [{"kind": "gate-bypass", "detail": f"b{i}"} for i in range(breaches)]},
        "feedback": {"entries": [{"type": "gate-rule", "advisory_id": a, "human_reviewed": False} for a in flagged]},
    })


def test_empty_runs_dir_writes_an_empty_index(tmp_path):
    index = history.rebuild(tmp_path)
    assert index["schema"] == history.SCHEMA
    assert index["runs"] == {} and index["advisories"] == {} and index["repos"] == {} and index["timeline"] == []
    written = json.loads((tmp_path / "_index" / "history.json").read_text(encoding="utf-8"))
    assert written["schema"] == history.SCHEMA and written["truncated"] is False


def test_one_run_aggregates_verdicts_sim_triage_and_timeline(tmp_path):
    run_dir = _run(tmp_path, "run-a")
    _verdict(run_dir, "billing-api", "CVE-2026-1111", "needs_human", original="affected_proven", sim=True)
    _verdict(run_dir, "auth-gateway", "CVE-2026-1111", "not_affected")
    _sim(run_dir, breaches=2)
    (run_dir / "events.jsonl").write_text(
        '{"t": "2026-11-21T10:01:00+00:00", "source": "worker", "kind": "step", "repo": "billing-api", "text": "working on it"}\n'
        '{"t": "2026-11-21T10:02:00+00:00", "source": "gate", "kind": "done", "repo": "billing-api", "text": "claim rejected"}\n',
        encoding="utf-8",
    )
    index = history.rebuild(tmp_path)

    advisory = index["advisories"]["CVE-2026-1111"]
    assert advisory["runs"] == ["run-a"]
    assert advisory["verdicts"] == {"needs_human": 1, "not_affected": 1}
    assert advisory["gate_downgrades"] == 1 and advisory["sim_downgrades"] == 1
    assert advisory["breaches_over_time"] == [{"run": "run-a", "t": "2026-11-21T10:00:00+00:00", "breaches": 2}]

    assert index["repos"]["billing-api"][0]["verdict"] == "needs_human"
    assert index["repos"]["auth-gateway"][0]["verdict"] == "not_affected"

    run = index["runs"]["run-a"]
    assert run["stage"] == "approved" and run["events"] == 2 and run["sim_breaches"] == 2
    assert run["verdicts"]["billing-api"]["sim_triage_downgrade"] is True
    assert [e["text"] for e in index["timeline"]] == ["working on it", "claim rejected"]


def test_underscore_folders_are_skipped(tmp_path):
    _run(tmp_path, "run-a")
    (tmp_path / "_fleet").mkdir()
    (tmp_path / "_index").mkdir()
    index = history.rebuild(tmp_path)
    assert list(index["runs"]) == ["run-a"]


def test_malformed_files_are_ignored(tmp_path):
    run_dir = _run(tmp_path, "run-b", advisory_id="")
    _write(run_dir / "run.json", "{not json")
    _write(run_dir / "billing-api" / "verdict.json", "{broken")
    _write(run_dir / "sim-triage.json", "[1, 2, 3]")  # not a dict of the expected shape
    (run_dir / "events.jsonl").write_text(
        '{"t": "2026-11-21T11:00:00+00:00", "source": "orchestrator", "kind": "start", "text": "started"}\n'
        "{a line still being written\n",
        encoding="utf-8",
    )
    index = history.rebuild(tmp_path)
    run = index["runs"]["run-b"]
    assert run["verdicts"] == {} and run["sim_breaches"] == 0 and run["stage"] == ""
    assert [e["text"] for e in index["timeline"]] == ["started"]


def test_size_cap_is_enforced_and_marked(tmp_path, monkeypatch):
    monkeypatch.setattr(history, "MAX_INDEX_BYTES", 2_000)
    monkeypatch.setattr(history, "MAX_TIMELINE", 50)
    for i in range(5):
        run_dir = _run(tmp_path, f"run-{i}", started_at=f"2026-11-21T1{i}:00:00+00:00")
        _verdict(run_dir, "billing-api", "CVE-2026-1111", "affected_proven")
        (run_dir / "events.jsonl").write_text("\n".join(
            json.dumps({"t": f"2026-11-21T1{i}:00:{s:02d}+00:00", "source": "worker", "kind": "step",
                        "text": "x" * 180}) for s in range(20)
        ) + "\n", encoding="utf-8")
    index = history.rebuild(tmp_path)
    written = (tmp_path / "_index" / "history.json").read_bytes()
    assert len(written) <= history.MAX_INDEX_BYTES
    assert index["truncated"] is True
    assert len(index["timeline"]) < 100  # the cap shrank the timeline


def test_worker_text_is_sanitised_one_line_no_markup(tmp_path):
    run_dir = _run(tmp_path, "run-c")
    nasty = '<script>alert("x")</script>\nsecond line `code` | pipe -----BEGIN PRIVATE KEY-----\nABCDEF123456'
    (run_dir / "events.jsonl").write_text(
        json.dumps({"t": "2026-11-21T12:00:00+00:00", "source": "worker", "kind": "info", "text": nasty}) + "\n",
        encoding="utf-8",
    )
    index = history.rebuild(tmp_path)
    text = index["timeline"][0]["text"]
    assert "\n" not in text and "<" not in text and ">" not in text and "`" not in text
    assert "script" in text  # the word survives; only the markup is escaped
    blob = json.dumps(index)
    assert "<script>" not in blob and "-----BEGIN PRIVATE KEY-----\n" not in blob
    # no run folder is ever written by the indexer
    assert sorted(p.name for p in run_dir.iterdir()) == ["events.jsonl", "run.json"]
