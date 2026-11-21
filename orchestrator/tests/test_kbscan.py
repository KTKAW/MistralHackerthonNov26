"""The kb-scan bridge: untrusted scan documents in, sanitised summaries out, and the gate's
sim-triage downgrade rule. None of these need the fleet or the wheelhouse."""
import json

from orchestrator import gate, kbscan, report


def _write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


LATEST = {
    "schema": "kb-scan-report/1",
    "generated_at": "2026-11-21T16:00:00Z",
    "findings": [
        {"tier": 1, "cve": "CVE-2026-1111", "package": "authlib", "title": "RCE in <b>parse</b>", "source": "kev"},
        {"tier": 3, "cve": "CVE-2026-2222", "package": "requests", "title": "proxy leak", "source": "osv"},
    ],
}


def test_latest_summary_is_sanitised_and_capped(tmp_path, monkeypatch):
    monkeypatch.setenv("KB_SCAN_OUT_DIR", str(tmp_path))
    _write(tmp_path / "latest.json", LATEST)
    summary = kbscan.summary(kbscan.latest())
    assert summary["total"] == 2 and summary["tiers"] == {"1": 1, "3": 1}
    # markup in feed text is escaped, never passed through
    assert summary["items"][0]["title"] == "RCE in &lt;b&gt;parse&lt;/b&gt;"


def test_malformed_or_oversized_scan_documents_are_ignored(tmp_path, monkeypatch):
    monkeypatch.setenv("KB_SCAN_OUT_DIR", str(tmp_path))
    (tmp_path / "latest.json").write_text("{not json", encoding="utf-8")
    assert kbscan.latest() == {} and kbscan.summary(kbscan.latest())["total"] == 0
    big = tmp_path / "big.json"
    big.write_text(" " * (kbscan.MAX_BYTES + 1), encoding="utf-8")
    assert kbscan._read_capped(big) is None


def test_relevant_to_advisory_matches_cve_and_package(tmp_path, monkeypatch):
    monkeypatch.setenv("KB_SCAN_OUT_DIR", str(tmp_path))
    _write(tmp_path / "latest.json", LATEST)
    hits = kbscan.relevant_to_advisory(kbscan.latest(), "CVE-2026-1111", "")
    assert [h["cve"] for h in hits] == ["CVE-2026-1111"]
    hits = kbscan.relevant_to_advisory(kbscan.latest(), "", "requests")
    assert [h["cve"] for h in hits] == ["CVE-2026-2222"]
    assert kbscan.relevant_to_advisory(kbscan.latest(), "CVE-0000-0000", "nothing") == []


def _verdict(advisory_id: str, verdict: str = "affected_proven") -> dict:
    return {"repo": "billing-api", "verdict": verdict,
            "advisory": {"id": advisory_id, "package": "authlib", "affected_range": "<1.9.1", "flawed_function": "parse"},
            "gate": {"passed": True, "rules": {}}}


def test_gate_downgrades_only_flagged_unreviewed_advisories(tmp_path, monkeypatch):
    monkeypatch.setenv("LE_CHONK_RUNS_ROOT", str(tmp_path))
    run_dir = tmp_path / "run-1"
    sim = {"schema": "sim-triage/1", "defenses": {"breaches": [{"kind": "gate-bypass", "detail": "x"}]},
           "feedback": {"entries": [
               {"type": "gate-rule", "advisory_id": "CVE-2026-1111", "human_reviewed": False},
               {"type": "gate-rule", "advisory_id": "CVE-2026-9999", "human_reviewed": True},  # reviewed: not applied
               {"type": "watchlist", "advisory_id": "CVE-2026-8888"},
           ]}}
    _write(run_dir / "sim-triage.json", sim)
    gated = [_verdict("CVE-2026-1111"), _verdict("CVE-2026-9999"), _verdict("CVE-2026-2222")]
    gate._apply_sim_triage(run_dir, gated)
    assert gated[0]["verdict"] == "needs_human" and "sim_triage" in gated[0]["gate"]
    assert gated[1]["verdict"] == "affected_proven"  # human-reviewed: untouched
    assert gated[2]["verdict"] == "affected_proven"  # not flagged: untouched


def test_gate_ignores_malformed_sim_triage(tmp_path, monkeypatch):
    monkeypatch.setenv("LE_CHONK_RUNS_ROOT", str(tmp_path))
    run_dir = tmp_path / "run-2"
    run_dir.mkdir()
    (run_dir / "sim-triage.json").write_text("{broken", encoding="utf-8")
    gated = [_verdict("CVE-2026-1111")]
    gate._apply_sim_triage(run_dir, gated)
    assert gated[0]["verdict"] == "affected_proven"


def test_report_feed_watch_section_lists_matches_as_unverified(tmp_path, monkeypatch):
    monkeypatch.setenv("KB_SCAN_OUT_DIR", str(tmp_path / "scan-out"))
    monkeypatch.setenv("LE_CHONK_RUNS_ROOT", str(tmp_path / "runs"))
    _write(tmp_path / "scan-out" / "latest.json", LATEST)
    lines = report._feed_watch_section("run-1", {"id": "CVE-2026-1111", "package": "authlib"}, tmp_path / "runs")
    joined = "\n".join(lines)
    assert "Feed watch" in joined and "CVE-2026-1111" in joined and "Unverified feed data" in joined
    assert "<b>" not in joined  # sanitised
    assert report._feed_watch_section("run-1", {"id": "CVE-0000-0000", "package": "nope"}, tmp_path / "runs") == []
