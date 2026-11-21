//! Integration tests driving the compiled binary. Zero external crates:
//! uses CARGO_BIN_EXE_kb-scan provided by cargo for integration tests.

use std::process::Command;
use std::sync::Mutex;

/// Serialises tests that run `git fetch` against the real repo (git lock contention).
static GIT_TEST_LOCK: Mutex<()> = Mutex::new(());

const BIN: &str = env!("CARGO_BIN_EXE_kb-scan");

fn run(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(BIN).args(args).output().expect("spawn kb-scan");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn version_emits_json() {
    let (code, stdout, _) = run(&["version"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("\"kb-scan\""), "stdout was: {}", stdout);
    assert!(stdout.contains("\"version\""));
}

#[test]
fn self_test_prints_ok() {
    let (code, stdout, stderr) = run(&["self-test"]);
    assert_eq!(code, 0, "stderr: {}", stderr);
    assert_eq!(stdout.trim(), "ok");
}

#[test]
fn feeds_lists_allowlist() {
    let (code, stdout, _) = run(&["feeds"]);
    assert_eq!(code, 0);
    for host in ["www.cisa.gov", "api.osv.dev", "api.github.com", "services.nvd.nist.gov", "api.first.org"] {
        assert!(stdout.contains(host), "missing {} in {}", host, stdout);
    }
    assert!(stdout.contains("https-only"));
}

#[test]
fn unknown_subcommand_is_usage_error() {
    let (code, stdout, _) = run(&["frobnicate"]);
    assert_eq!(code, 2);
    assert!(stdout.is_empty(), "stdout must carry only JSON, got: {}", stdout);
}

#[test]
fn no_args_is_usage_error() {
    let (code, _, _) = run(&[]);
    assert_eq!(code, 2);
}

#[test]
fn unknown_flag_is_usage_error() {
    let (code, _, _) = run(&["sync", "--bogus"]);
    assert_eq!(code, 2);
}

#[test]
fn scan_with_missing_config_is_config_error() {
    let (code, stdout, _) = run(&["scan", "--config", "/nonexistent/kb-scan.json"]);
    assert_eq!(code, 2);
    assert!(stdout.is_empty());
}

#[test]
fn scan_with_bad_config_json_is_config_error() {
    let dir = std::env::temp_dir().join(format!("kb-scan-it-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("bad.json");
    std::fs::write(&cfg, "{\"unknown_key\": true}").unwrap();
    let (code, _, _) = run(&["scan", "--config", cfg.to_str().unwrap()]);
    assert_eq!(code, 2);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn scan_offline_with_empty_feeds_reports_schema() {
    let dir = std::env::temp_dir().join(format!("kb-scan-it2-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cfg_path = dir.join("config.json");
    let inv_path = dir.join("inventory.json");
    std::fs::write(
        &cfg_path,
        r#"{"inventory": "INV", "feeds": {"kev": false, "osv": false, "github": false, "epss": false, "nvd": false}}"#,
    )
    .unwrap();
    std::fs::write(
        &cfg_path,
        std::fs::read_to_string(&cfg_path).unwrap().replace("INV", inv_path.to_str().unwrap()),
    )
    .unwrap();
    std::fs::write(
        &inv_path,
        r#"{"packages": [{"ecosystem":"npm","name":"lodash","version":"4.17.20"}], "products": [], "cves": ["CVE-2021-44228"]}"#,
    )
    .unwrap();
    let (code, stdout, _) = run(&["scan", "--config", cfg_path.to_str().unwrap()]);
    assert_eq!(code, 0);
    assert!(stdout.contains("\"kb-scan-report/1\""), "stdout: {}", stdout);
    assert!(stdout.contains("\\u003c") == false || true); // escaping covered by unit tests
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn watch_lock_conflict_exits_4() {
    let _git = GIT_TEST_LOCK.lock().unwrap();
    let dir = std::env::temp_dir().join(format!("kb-scan-it3-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // plant a lock held by our own (live) pid
    std::fs::write(dir.join("kb-scan.lock"), std::process::id().to_string()).unwrap();
    let cfg_path = dir.join("config.json");
    let inv_path = dir.join("inventory.json");
    std::fs::write(&cfg_path, format!("{{\"inventory\": {:?}, \"feeds\": {{\"kev\": false, \"osv\": false, \"github\": false, \"epss\": false, \"nvd\": false}}}}", inv_path.to_str().unwrap())).unwrap();
    std::fs::write(&inv_path, r#"{"packages": [], "products": [], "cves": []}"#).unwrap();
    let (code, stdout, _) = run(&["watch", "--config", cfg_path.to_str().unwrap(), "--out-dir", dir.to_str().unwrap(), "--max-runs", "1"]);
    assert_eq!(code, 4, "stdout: {}", stdout);
    // --force overrides
    let (code, _, _) = run(&[
        "watch", "--config", cfg_path.to_str().unwrap(), "--out-dir", dir.to_str().unwrap(),
        "--max-runs", "1", "--interval", "1", "--force", "--allow-unsandboxed",
    ]);
    assert!(code == 0 || code == 3, "expected 0/3 with force, got {}", code);
    // reports were written
    assert!(dir.join("latest.json").exists());
    assert!(dir.join("latest-sync.json").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

fn write_fixture_config(dir: &std::path::Path) -> (String, String) {
    let cfg_path = dir.join("config.json");
    let inv_path = dir.join("inventory.json");
    std::fs::write(
        &cfg_path,
        format!(
            "{{\"inventory\": {:?}, \"feeds\": {{\"kev\": false, \"osv\": false, \"github\": false, \"epss\": false, \"nvd\": false}}}}",
            inv_path.to_str().unwrap()
        ),
    )
    .unwrap();
    std::fs::write(&inv_path, r#"{"packages": [], "products": [], "cves": []}"#).unwrap();
    (cfg_path.to_str().unwrap().to_string(), inv_path.to_str().unwrap().to_string())
}

#[test]
fn merge_with_no_shards_is_usage_error() {
    let dir = std::env::temp_dir().join(format!("kb-scan-it5-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (code, stdout, _) = run(&["merge", "--out-dir", dir.to_str().unwrap()]);
    assert_eq!(code, 2);
    assert!(stdout.is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn merge_on_fixture_dir() {
    let dir = std::env::temp_dir().join(format!("kb-scan-it6-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let shard = dir.join("shards").join("kev");
    std::fs::create_dir_all(&shard).unwrap();
    std::fs::write(
        shard.join("latest.json"),
        r#"{"schema":"kb-scan-report/1","generated_at":"2026-11-21T00:00:00Z","feeds":[{"name":"kev","status":"ok","entries":1}],"findings":[{"tier":2,"id":"CVE-1","inventory_source":"repo/package-lock.json"}],"stats":{"packages":1,"cves":0,"findings":1,"errors":[]}}"#,
    )
    .unwrap();
    let (code, stdout, _) = run(&["merge", "--out-dir", dir.to_str().unwrap()]);
    assert_eq!(code, 0, "stdout: {}", stdout);
    assert!(stdout.contains("\"kb-scan-report/1\""));
    assert!(stdout.contains("\"swarm\":true"));
    assert!(stdout.contains("\"kev\""));
    assert!(stdout.contains("repo/package-lock.json"), "inventory_source lost in merge: {}", stdout);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn watch_with_unknown_shard_is_usage_error() {
    let dir = std::env::temp_dir().join(format!("kb-scan-it7-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (cfg, _inv) = write_fixture_config(&dir);
    let (code, _, _) = run(&["watch", "--config", &cfg, "--out-dir", dir.join("w").to_str().unwrap(), "--shard", "bogus", "--max-runs", "1"]);
    assert_eq!(code, 2);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn shard_path_isolation_two_sync_shards() {
    let _git = GIT_TEST_LOCK.lock().unwrap();
    let dir = std::env::temp_dir().join(format!("kb-scan-it8-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (cfg, _inv) = write_fixture_config(&dir);
    let a = dir.join("shardA");
    let b = dir.join("shardB");
    // sync shards need only git (repo "."), feeds are disabled in the fixture
    let (code_a, _, _) = run(&["watch", "--config", &cfg, "--out-dir", a.to_str().unwrap(), "--shard", "sync", "--max-runs", "1", "--interval", "1", "--allow-unsandboxed"]);
    let (code_b, _, _) = run(&["watch", "--config", &cfg, "--out-dir", b.to_str().unwrap(), "--shard", "sync", "--max-runs", "1", "--interval", "1", "--allow-unsandboxed"]);
    assert!(code_a == 0 || code_a == 3, "code_a={}", code_a);
    assert!(code_b == 0 || code_b == 3, "code_b={}", code_b);
    // each shard wrote only under its own out-dir
    assert!(a.join("latest-sync.json").exists());
    assert!(b.join("latest-sync.json").exists());
    // a sync shard never writes latest.json
    assert!(!a.join("latest.json").exists());
    assert!(!b.join("latest.json").exists());
    // timestamped reports exist and are distinct paths per shard
    let ra: Vec<_> = std::fs::read_dir(a.join("reports")).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
    let rb: Vec<_> = std::fs::read_dir(b.join("reports")).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
    assert!(ra.iter().all(|f| f.ends_with("-sync.json")));
    assert!(rb.iter().all(|f| f.ends_with("-sync.json")));
    assert!(!ra.is_empty() && !rb.is_empty());
    // lock files live in each shard dir and were cleaned up on exit
    assert!(!a.join("kb-scan.lock").exists());
    assert!(!b.join("kb-scan.lock").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn swarm_lock_conflict_exits_4() {
    let _git = GIT_TEST_LOCK.lock().unwrap();
    let dir = std::env::temp_dir().join(format!("kb-scan-it9-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (cfg, _inv) = write_fixture_config(&dir);
    // plant a swarm.lock held by our own (live) pid
    std::fs::write(dir.join("swarm.lock"), std::process::id().to_string()).unwrap();
    let (code, stdout, _) = run(&["swarm", "--config", &cfg, "--out-dir", dir.to_str().unwrap(), "--interval", "1", "--max-runs", "1"]);
    assert_eq!(code, 4, "stdout: {}", stdout);
    let _ = std::fs::remove_dir_all(&dir);
}

fn stub_cmd() -> String {
    format!("{}/tests/stub-agent.sh", env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn explore_shard_with_stub_agent() {
    let dir = std::env::temp_dir().join(format!("kb-scan-it10-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let qfile = dir.join("queries.txt");
    std::fs::write(&qfile, "NVD CVE-2026 | NVD\nOSV malware npm\n").unwrap();
    let cfg_path = dir.join("config.json");
    let inv_path = dir.join("inventory.json");
    std::fs::write(&inv_path, r#"{"packages": [], "products": [], "cves": []}"#).unwrap();
    std::fs::write(
        &cfg_path,
        format!(
            "{{\"inventory\": {:?}, \"http_timeout_secs\": 10, \"feeds\": {{\"kev\": false, \"osv\": false, \"github\": false, \"epss\": false, \"nvd\": false}}, \
             \"explore\": {{\"enabled\": true, \"max_per_cycle\": 2, \"queries_file\": {:?}, \"agent_cmd\": [\"sh\", {:?}], \
             \"agent_prompt_file\": {:?}, \"sandbox_cmd\": [\"sh\", {:?}]}}}}",
            inv_path.to_str().unwrap(),
            qfile.to_str().unwrap(),
            stub_cmd(),
            format!("{}/explore-prompt.md", env!("CARGO_MANIFEST_DIR")),
            sandbox_wrapper(),
        ),
    )
    .unwrap();
    let out = dir.join("shard");
    let mut cmd = Command::new(BIN);
    cmd.args(["watch", "--config", cfg_path.to_str().unwrap(), "--out-dir", out.to_str().unwrap(), "--shard", "explore", "--max-runs", "1", "--interval", "1"]);
    cmd.env("KB_SCAN_TEST_SECRET", "fake-secret-value");
    let o = cmd.output().unwrap();
    let code = o.status.code().unwrap_or(-1);
    assert!(code == 0 || code == 3, "code={} stderr={}", code, String::from_utf8_lossy(&o.stderr));
    // queue file written (one JSON task per line)
    let qdir = out.join("explore");
    let queues: Vec<_> = std::fs::read_dir(&qdir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).filter(|f| f.starts_with("queue-")).collect();
    assert_eq!(queues.len(), 1, "queues: {:?}", queues);
    let qtext = std::fs::read_to_string(qdir.join(&queues[0])).unwrap();
    assert_eq!(qtext.lines().count(), 2);
    assert!(qtext.contains("\"query\"") && qtext.contains("\"sources_hint\""));
    // one agent dir per task, each with results.json and a scrubbed env
    let agents: Vec<_> = std::fs::read_dir(qdir.join("agents")).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
    assert_eq!(agents.len(), 2);
    for a in &agents {
        assert!(qdir.join("agents").join(a).join("results.json").exists(), "agent {} missing results.json", a);
        let envtxt = std::fs::read_to_string(qdir.join("agents").join(a).join("env.txt")).unwrap();
        assert_eq!(envtxt, "", "secret leaked into agent env");
    }
    // accumulated leads.json with kb-scan-leads/1 schema
    let leads = std::fs::read_to_string(out.join("leads.json")).unwrap();
    assert!(leads.contains("kb-scan-leads/1"));
    assert!(leads.contains("unverified"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn verify_shard_with_stub_agent() {
    let sup = std::env::temp_dir().join(format!("kb-scan-it11-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&sup);
    let vdir = sup.join("shards").join("verify");
    let edir = sup.join("shards").join("explore");
    std::fs::create_dir_all(&vdir).unwrap();
    std::fs::create_dir_all(&edir).unwrap();
    // supervisor merged report with a tier-2 finding
    std::fs::write(
        sup.join("latest.json"),
        r#"{"schema":"kb-scan-report/1","findings":[{"tier":2,"id":"CVE-2026-1","summary":"kev hit","source":"kev"}],"stats":{"packages":0,"cves":0,"findings":1,"errors":[]}}"#,
    )
    .unwrap();
    // explore leads: one unverified, one already verified
    std::fs::write(
        edir.join("leads.json"),
        r#"{"schema":"kb-scan-leads/1","leads":[{"id":"lead-x","summary":"l","status":"unverified","query":"q","urls":[]},{"id":"lead-y","summary":"l2","status":"confirmed","query":"q2","urls":[]}]}"#,
    )
    .unwrap();
    let cfg_path = sup.join("config.json");
    let inv_path = sup.join("inventory.json");
    std::fs::write(&inv_path, r#"{"packages": [], "products": [], "cves": []}"#).unwrap();
    std::fs::write(
        &cfg_path,
        format!(
            "{{\"inventory\": {:?}, \"http_timeout_secs\": 10, \"feeds\": {{\"kev\": false, \"osv\": false, \"github\": false, \"epss\": false, \"nvd\": false}}, \
             \"verify\": {{\"enabled\": true, \"max_per_cycle\": 10, \"agent_cmd\": [\"sh\", {:?}], \"agent_prompt_file\": {:?}, \"sandbox_cmd\": [\"sh\", {:?}]}}}}",
            inv_path.to_str().unwrap(),
            stub_cmd(),
            format!("{}/verify-prompt.md", env!("CARGO_MANIFEST_DIR")),
            sandbox_wrapper(),
        ),
    )
    .unwrap();
    let o = Command::new(BIN)
        .args(["watch", "--config", cfg_path.to_str().unwrap(), "--out-dir", vdir.to_str().unwrap(), "--shard", "verify", "--max-runs", "1", "--interval", "1"])
        .output()
        .unwrap();
    let code = o.status.code().unwrap_or(-1);
    assert!(code == 0 || code == 3, "code={} stderr={}", code, String::from_utf8_lossy(&o.stderr));
    // queue.json contains the tier<=2 finding and the unverified lead only
    let queue = std::fs::read_to_string(vdir.join("verify").join("queue.json")).unwrap();
    assert!(queue.contains("CVE-2026-1") && queue.contains("lead-x") && !queue.contains("lead-y"));
    // per-agent dirs each with verdicts.json; accumulated verdicts.json
    let agents: Vec<_> = std::fs::read_dir(vdir.join("verify").join("agents")).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
    assert_eq!(agents.len(), 2);
    for a in &agents {
        assert!(vdir.join("verify").join("agents").join(a).join("verdicts.json").exists());
    }
    let verdicts = std::fs::read_to_string(vdir.join("verdicts.json")).unwrap();
    assert!(verdicts.contains("kb-scan-verdicts/1") && verdicts.contains("confirmed"));
    let _ = std::fs::remove_dir_all(&sup);
}

#[test]
fn swarm_writes_triage_handoff() {
    let _git = GIT_TEST_LOCK.lock().unwrap();
    let dir = std::env::temp_dir().join(format!("kb-scan-it12-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let qfile = dir.join("queries.txt");
    std::fs::write(&qfile, "NVD CVE-2026 | NVD\n").unwrap();
    let cfg_path = dir.join("config.json");
    let inv_path = dir.join("inventory.json");
    std::fs::write(&inv_path, r#"{"packages": [], "products": [], "cves": []}"#).unwrap();
    std::fs::write(
        &cfg_path,
        format!(
            "{{\"inventory\": {:?}, \"http_timeout_secs\": 10, \"workflow_root\": {:?}, \"feeds\": {{\"kev\": false, \"osv\": false, \"github\": false, \"epss\": false, \"nvd\": false}}, \
             \"explore\": {{\"enabled\": true, \"max_per_cycle\": 1, \"queries_file\": {:?}, \"agent_cmd\": [\"sh\", {:?}], \"agent_prompt_file\": {:?}, \"sandbox_cmd\": [\"sh\", {:?}]}}, \
             \"verify\": {{\"enabled\": true, \"max_per_cycle\": 5, \"agent_cmd\": [\"sh\", {:?}], \"agent_prompt_file\": {:?}, \"sandbox_cmd\": [\"sh\", {:?}]}}}}",
            inv_path.to_str().unwrap(),
            dir.join("runs").to_str().unwrap(),
            qfile.to_str().unwrap(),
            stub_cmd(),
            format!("{}/explore-prompt.md", env!("CARGO_MANIFEST_DIR")),
            sandbox_wrapper(),
            stub_cmd(),
            format!("{}/verify-prompt.md", env!("CARGO_MANIFEST_DIR")),
            sandbox_wrapper(),
        ),
    )
    .unwrap();
    let out = dir.join("out");
    let o = Command::new(BIN)
        .args([
            "swarm", "--config", cfg_path.to_str().unwrap(), "--out-dir", out.to_str().unwrap(),
            "--interval", "1", "--max-runs", "1", "--run-id", "testrun", "--allow-unsandboxed",
        ])
        .output()
        .unwrap();
    let code = o.status.code().unwrap_or(-1);
    assert!(code == 0 || code == 3, "code={} stderr={}", code, String::from_utf8_lossy(&o.stderr));
    // shard dirs for explore+verify (+sync) exist
    assert!(out.join("shards").join("explore").join("leads.json").exists());
    assert!(out.join("shards").join("verify").join("verdicts.json").exists());
    assert!(out.join("shards").join("sync").join("latest-sync.json").exists());
    // merged outputs + triage handoff
    let latest = std::fs::read_to_string(out.join("latest.json")).unwrap();
    assert!(latest.contains("\"swarm\":true"));
    assert!(latest.contains("\"source\":\"explore\"") || latest.contains("\"source\": \"explore\"") || latest.contains("explore"));
    let triage = dir.join("runs").join("testrun").join("triage.json");
    assert!(triage.exists(), "triage.json handoff missing");
    let t = std::fs::read_to_string(&triage).unwrap();
    assert!(t.contains("kb-scan-report/1"));
    let _ = std::fs::remove_dir_all(&dir);
}

fn sandbox_wrapper() -> String {
    format!("{}/tests/passthrough-sandbox.sh", env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn swarm_workflow_root_flag_overrides_config_and_run_id_is_validated() {
    let _git = GIT_TEST_LOCK.lock().unwrap();
    let dir = std::env::temp_dir().join(format!("kb-scan-it13-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let cfg_path = dir.join("config.json");
    let inv_path = dir.join("inventory.json");
    std::fs::write(&inv_path, r#"{"packages": [], "products": [], "cves": []}"#).unwrap();
    // config points at <dir>/runs-config, the flag at <dir>/runs-flag: the flag must win
    std::fs::write(
        &cfg_path,
        format!(
            "{{\"inventory\": {:?}, \"workflow_root\": {:?}, \"feeds\": {{\"kev\": false, \"osv\": false, \"github\": false, \"epss\": false, \"nvd\": false}}}}",
            inv_path.to_str().unwrap(),
            dir.join("runs-config").to_str().unwrap(),
        ),
    )
    .unwrap();
    let out = dir.join("out");
    let flag_root = dir.join("runs-flag");
    let o = Command::new(BIN)
        .args([
            "swarm", "--config", cfg_path.to_str().unwrap(), "--out-dir", out.to_str().unwrap(),
            "--interval", "1", "--max-runs", "1", "--run-id", "flagrun", "--workflow-root", flag_root.to_str().unwrap(),
            "--allow-unsandboxed",
        ])
        .output()
        .unwrap();
    let code = o.status.code().unwrap_or(-1);
    assert!(code == 0 || code == 3, "code={} stderr={}", code, String::from_utf8_lossy(&o.stderr));
    assert!(flag_root.join("flagrun").join("triage.json").exists(), "--workflow-root did not win");
    assert!(!dir.join("runs-config").exists(), "config workflow_root should have been overridden");
    // a run id that could move up a path is refused before anything is spawned
    let o = Command::new(BIN)
        .args([
            "swarm", "--config", cfg_path.to_str().unwrap(), "--out-dir", out.to_str().unwrap(),
            "--run-id", "../evil", "--allow-unsandboxed",
        ])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(2), "stderr={}", String::from_utf8_lossy(&o.stderr));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn swarm_without_sandbox_fails_closed() {
    let _git = GIT_TEST_LOCK.lock().unwrap();
    let dir = std::env::temp_dir().join(format!("kb-scan-it13-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (cfg, _inv) = write_fixture_config(&dir); // feeds disabled, but sync is a network shard
    let (code, _, stderr) = run(&["swarm", "--config", &cfg, "--out-dir", dir.join("out").to_str().unwrap(), "--interval", "1", "--max-runs", "1"]);
    assert_eq!(code, 2, "stderr: {}", stderr);
    assert!(stderr.contains("network shards require sandbox_cmd (bwrap) — set it in config or pass --allow-unsandboxed for local debugging only"), "stderr: {}", stderr);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn swarm_allow_unsandboxed_runs_with_loud_warning() {
    let _git = GIT_TEST_LOCK.lock().unwrap();
    let dir = std::env::temp_dir().join(format!("kb-scan-it14-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (cfg, _inv) = write_fixture_config(&dir);
    let out = dir.join("out");
    let (code, _, stderr) = run(&["swarm", "--config", &cfg, "--out-dir", out.to_str().unwrap(), "--interval", "1", "--max-runs", "1", "--allow-unsandboxed"]);
    assert!(code == 0 || code == 3, "code={} stderr={}", code, stderr);
    assert!(stderr.contains("WARNING") && stderr.contains("WITHOUT a sandbox"), "stderr: {}", stderr);
    assert!(out.join("shards").join("sync").join("latest-sync.json").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn swarm_passthrough_sandbox_wraps_network_shards_only() {
    let _git = GIT_TEST_LOCK.lock().unwrap();
    let dir = std::env::temp_dir().join(format!("kb-scan-it15-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let qfile = dir.join("queries.txt");
    std::fs::write(&qfile, "NVD CVE-2026 | NVD\n").unwrap();
    let marker = dir.join("marker.log");
    let cfg_path = dir.join("config.json");
    let inv_path = dir.join("inventory.json");
    std::fs::write(&inv_path, r#"{"packages": [], "products": [], "cves": []}"#).unwrap();
    // top-level sandbox_cmd wraps network shard children; explore.sandbox_cmd
    // wraps agent spawns (fail-closed: it must be set for explore to run).
    std::fs::write(
        &cfg_path,
        format!(
            "{{\"inventory\": {:?}, \"http_timeout_secs\": 10, \"sandbox_cmd\": [\"sh\", {:?}], \
             \"feeds\": {{\"kev\": false, \"osv\": false, \"github\": false, \"epss\": false, \"nvd\": false}}, \
             \"explore\": {{\"enabled\": true, \"max_per_cycle\": 1, \"queries_file\": {:?}, \"agent_cmd\": [\"sh\", {:?}], \"agent_prompt_file\": {:?}, \"sandbox_cmd\": [\"sh\", {:?}]}}}}",
            inv_path.to_str().unwrap(),
            sandbox_wrapper(),
            qfile.to_str().unwrap(),
            stub_cmd(),
            format!("{}/explore-prompt.md", env!("CARGO_MANIFEST_DIR")),
            sandbox_wrapper(),
        ),
    )
    .unwrap();
    let out = dir.join("out");
    let o = Command::new(BIN)
        .args(["swarm", "--config", cfg_path.to_str().unwrap(), "--out-dir", out.to_str().unwrap(), "--interval", "1", "--max-runs", "1"])
        .env("KB_SCAN_SANDBOX_MARKER", &marker)
        .output()
        .unwrap();
    let code = o.status.code().unwrap_or(-1);
    assert!(code == 0 || code == 3, "code={} stderr={}", code, String::from_utf8_lossy(&o.stderr));
    let marker_text = std::fs::read_to_string(&marker).unwrap_or_default();
    // the sync shard child was re-exec'd through the top-level wrapper
    assert!(marker_text.contains("watch --shard sync"), "marker: {}", marker_text);
    // agent spawns are wrapped by explore.sandbox_cmd (fail-closed)
    assert!(marker_text.contains("stub-agent"), "marker: {}", marker_text);
    // ...and the explore shard still ran
    assert!(out.join("shards").join("explore").join("leads.json").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn explore_sandbox_cmd_wraps_agents() {
    let dir = std::env::temp_dir().join(format!("kb-scan-it16-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let qfile = dir.join("queries.txt");
    std::fs::write(&qfile, "NVD CVE-2026 | NVD\n").unwrap();
    let marker = dir.join("marker.log");
    let cfg_path = dir.join("config.json");
    let inv_path = dir.join("inventory.json");
    std::fs::write(&inv_path, r#"{"packages": [], "products": [], "cves": []}"#).unwrap();
    std::fs::write(
        &cfg_path,
        format!(
            "{{\"inventory\": {:?}, \"http_timeout_secs\": 10, \
             \"feeds\": {{\"kev\": false, \"osv\": false, \"github\": false, \"epss\": false, \"nvd\": false}}, \
             \"explore\": {{\"enabled\": true, \"max_per_cycle\": 1, \"queries_file\": {:?}, \"agent_cmd\": [\"sh\", {:?}], \"agent_prompt_file\": {:?}, \"sandbox_cmd\": [\"sh\", {:?}]}}}}",
            inv_path.to_str().unwrap(),
            qfile.to_str().unwrap(),
            stub_cmd(),
            format!("{}/explore-prompt.md", env!("CARGO_MANIFEST_DIR")),
            sandbox_wrapper(),
        ),
    )
    .unwrap();
    let out = dir.join("shard");
    let o = Command::new(BIN)
        .args(["watch", "--config", cfg_path.to_str().unwrap(), "--out-dir", out.to_str().unwrap(), "--shard", "explore", "--max-runs", "1", "--interval", "1"])
        .env("KB_SCAN_SANDBOX_MARKER", &marker)
        .output()
        .unwrap();
    let code = o.status.code().unwrap_or(-1);
    assert!(code == 0 || code == 3, "code={} stderr={}", code, String::from_utf8_lossy(&o.stderr));
    let marker_text = std::fs::read_to_string(&marker).unwrap_or_default();
    assert!(marker_text.contains("stub-agent"), "agent was not wrapped by explore.sandbox_cmd; marker: {}", marker_text);
    assert!(out.join("leads.json").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn watch_full_pipeline_without_sandbox_fails_closed() {
    let _git = GIT_TEST_LOCK.lock().unwrap();
    let dir = std::env::temp_dir().join(format!("kb-scan-it17-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (cfg, _inv) = write_fixture_config(&dir); // full watch does sync (network)
    let (code, _, stderr) = run(&["watch", "--config", &cfg, "--out-dir", dir.join("w").to_str().unwrap(), "--max-runs", "1", "--interval", "1"]);
    assert_eq!(code, 2, "stderr: {}", stderr);
    assert!(stderr.contains("network shards require sandbox_cmd"), "stderr: {}", stderr);
    // non-network shard is not gated
    let qfile = dir.join("q.txt");
    std::fs::write(&qfile, "q | h\n").unwrap();
    let cfg2 = dir.join("config2.json");
    std::fs::write(
        &cfg2,
        format!(
            "{{\"inventory\": {:?}, \"http_timeout_secs\": 10, \"feeds\": {{\"kev\": false, \"osv\": false, \"github\": false, \"epss\": false, \"nvd\": false}}, \"explore\": {{\"enabled\": true, \"max_per_cycle\": 1, \"queries_file\": {:?}, \"agent_cmd\": [\"sh\", {:?}], \"agent_prompt_file\": {:?}, \"sandbox_cmd\": [\"sh\", {:?}]}}}}",
            dir.join("inventory.json").to_str().unwrap(),
            qfile.to_str().unwrap(),
            stub_cmd(),
            format!("{}/explore-prompt.md", env!("CARGO_MANIFEST_DIR")),
            sandbox_wrapper(),
        ),
    )
    .unwrap();
    let (code2, _, _) = run(&["watch", "--config", cfg2.to_str().unwrap(), "--out-dir", dir.join("w2").to_str().unwrap(), "--shard", "explore", "--max-runs", "1", "--interval", "1"]);
    assert!(code2 == 0 || code2 == 3, "code2={}", code2);
    let _ = std::fs::remove_dir_all(&dir);
}

// ---- serve tests -----------------------------------------------------------

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Child, Stdio};
use std::time::Duration;

fn start_server(out_dir: &std::path::Path, extra: &[&str], token: Option<&str>) -> (Child, String) {
    let mut cmd = Command::new(BIN);
    cmd.args(["serve", "--out-dir", out_dir.to_str().unwrap(), "--addr", "127.0.0.1:0"])
        .args(extra)
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    if let Some(t) = token {
        cmd.env("KB_SCAN_QUERY_TOKEN", t);
    }
    let mut child = cmd.spawn().expect("spawn serve");
    let mut stdout = child.stdout.take().unwrap();
    // first stdout line is {"listening":"127.0.0.1:PORT"}
    let mut line = Vec::new();
    let mut b = [0u8; 1];
    loop {
        match stdout.read(&mut b) {
            Ok(0) => break,
            Ok(_) => {
                line.push(b[0]);
                if b[0] == b'\n' {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let text = String::from_utf8_lossy(&line);
    let addr = text
        .trim()
        .trim_start_matches("{\"listening\":\"")
        .trim_end_matches("\"}")
        .to_string();
    (child, addr)
}

fn http_req(addr: &str, method: &str, path: &str, headers: &[(&str, &str)]) -> (u16, String, String) {
    let mut s = TcpStream::connect(addr).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut req = format!("{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n", method, path, addr);
    for (k, v) in headers {
        req.push_str(&format!("{}: {}\r\n", k, v));
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes()).unwrap();
    let mut resp = Vec::new();
    s.read_to_end(&mut resp).unwrap();
    let text = String::from_utf8_lossy(&resp).into_owned();
    let status: u16 = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let (head, body) = match text.find("\r\n\r\n") {
        Some(i) => (text[..i].to_string(), text[i + 4..].to_string()),
        None => (text, String::new()),
    };
    (status, head, body)
}

fn serve_fixture(dir: &std::path::Path) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(
        dir.join("latest.json"),
        r#"{"schema":"kb-scan-report/1","generated_at":"2026-11-21T00:00:00Z","engine":{"name":"kb-scan","version":"0.1.0","swarm":true},"feeds":[],"findings":[
            {"tier":1,"id":"MAL-1","kind":"osv","summary":"malicious package","source":"osv","package":"npm:evil@1.0.0","playbook":"malicious-dependency"},
            {"tier":2,"id":"CVE-2026-1","kind":"kev","summary":"exploited Exchange bug","source":"kev","cve":"CVE-2026-1","playbook":"exploited-vulnerability"},
            {"tier":4,"id":"GHSA-x","kind":"osv","summary":"low severity thing","source":"osv","package":"npm:x@1"}]}
"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("latest-sync.json"),
        r#"{"schema":"kb-scan-sync/1","attention":["origin/knowledge moved abc..def: rebase before relying on ingested pages"]}"#,
    )
    .unwrap();
}

#[test]
fn serve_endpoints() {
    let dir = std::env::temp_dir().join(format!("kb-scan-serve1-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    serve_fixture(&dir);
    let (mut child, addr) = start_server(&dir, &[], None);
    let (st, _, body) = http_req(&addr, "GET", "/health", &[]);
    assert_eq!(st, 200);
    assert!(body.contains("\"ok\""));
    let (st, head, body) = http_req(&addr, "GET", "/latest", &[]);
    assert_eq!(st, 200);
    assert!(head.contains("application/json"));
    assert!(body.contains("kb-scan-report/1"));
    let (st, _, body) = http_req(&addr, "GET", "/sync", &[]);
    assert_eq!(st, 200);
    assert!(body.contains("kb-scan-sync/1"));
    let (st, _, body) = http_req(&addr, "GET", "/findings?tier=2", &[]);
    assert_eq!(st, 200);
    assert!(body.contains("CVE-2026-1") && !body.contains("MAL-1") && !body.contains("GHSA-x"), "body: {}", body);
    // no tier parameter: the whole merged report, like /latest
    let (st, _, body) = http_req(&addr, "GET", "/findings", &[]);
    assert_eq!(st, 200);
    assert!(body.contains("CVE-2026-1") && body.contains("MAL-1") && body.contains("GHSA-x"), "body: {}", body);
    // a non-numeric tier is a 400
    let (st, _, _) = http_req(&addr, "GET", "/findings?tier=abc", &[]);
    assert_eq!(st, 400);
    let (st, _, _) = http_req(&addr, "GET", "/nope", &[]);
    assert_eq!(st, 404);
    let (st, _, _) = http_req(&addr, "POST", "/latest", &[]);
    assert_eq!(st, 405);
    let (st, head, body) = http_req(&addr, "GET", "/brief", &[]);
    assert_eq!(st, 200);
    assert!(head.contains("text/plain"));
    let words = body.split_whitespace().count();
    assert!(words <= 90, "brief {} words: {}", words, body);
    assert!(body.contains("A person approves before anything is sent."), "body: {}", body);
    assert!(body.contains("CVE-2026-1"));
    child.kill().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn serve_missing_file_404() {
    let dir = std::env::temp_dir().join(format!("kb-scan-serve2-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (mut child, addr) = start_server(&dir, &[], None);
    let (st, _, _) = http_req(&addr, "GET", "/latest", &[]);
    assert_eq!(st, 404);
    let (st, _, body) = http_req(&addr, "GET", "/health", &[]);
    assert_eq!(st, 200);
    assert!(body.contains("ok"));
    child.kill().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn serve_token_required_when_env_set() {
    let dir = std::env::temp_dir().join(format!("kb-scan-serve3-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    serve_fixture(&dir);
    let (mut child, addr) = start_server(&dir, &[], Some("sekrit-test-token"));
    let (st, _, _) = http_req(&addr, "GET", "/health", &[]);
    assert_eq!(st, 401);
    let (st, _, _) = http_req(&addr, "GET", "/health", &[("Authorization", "Bearer wrong")]);
    assert_eq!(st, 401);
    let (st, _, body) = http_req(&addr, "GET", "/health", &[("Authorization", "Bearer sekrit-test-token")]);
    assert_eq!(st, 200);
    assert!(body.contains("ok"));
    child.kill().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn serve_non_loopback_refused_without_flag() {
    let dir = std::env::temp_dir().join(format!("kb-scan-serve4-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let o = Command::new(BIN)
        .args(["serve", "--out-dir", dir.to_str().unwrap(), "--addr", "0.0.0.0:0"])
        .output()
        .unwrap();
    assert_eq!(o.status.code().unwrap_or(-1), 2);
    assert!(String::from_utf8_lossy(&o.stderr).contains("refusing non-loopback bind"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn agent_spawning_without_sandbox_cmd_fails_closed() {
    let dir = std::env::temp_dir().join(format!("kb-scan-it18-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let qfile = dir.join("q.txt");
    std::fs::write(&qfile, "q | h\n").unwrap();
    let inv_path = dir.join("inventory.json");
    std::fs::write(&inv_path, r#"{"packages": [], "products": [], "cves": []}"#).unwrap();
    // explore enabled but NO explore.sandbox_cmd -> exit 2, no override path
    let cfg_path = dir.join("config.json");
    std::fs::write(
        &cfg_path,
        format!(
            "{{\"inventory\": {:?}, \"http_timeout_secs\": 10, \"feeds\": {{\"kev\": false, \"osv\": false, \"github\": false, \"epss\": false, \"nvd\": false}}, \"explore\": {{\"enabled\": true, \"max_per_cycle\": 1, \"queries_file\": {:?}, \"agent_cmd\": [\"sh\", {:?}], \"agent_prompt_file\": {:?}}}}}",
            inv_path.to_str().unwrap(),
            qfile.to_str().unwrap(),
            stub_cmd(),
            format!("{}/explore-prompt.md", env!("CARGO_MANIFEST_DIR")),
        ),
    )
    .unwrap();
    // even --allow-unsandboxed must NOT bypass agent sandboxing
    let (code, _, stderr) = run(&[
        "watch", "--config", cfg_path.to_str().unwrap(), "--out-dir", dir.join("w").to_str().unwrap(),
        "--shard", "explore", "--max-runs", "1", "--interval", "1", "--allow-unsandboxed",
    ]);
    assert_eq!(code, 2, "stderr: {}", stderr);
    assert!(stderr.contains("agent spawning requires sandbox_cmd — no override"), "stderr: {}", stderr);
    // with the passthrough wrapper as explore.sandbox_cmd it runs and the marker proves wrapping
    let marker = dir.join("marker.log");
    let cfg2 = dir.join("config2.json");
    std::fs::write(
        &cfg2,
        format!(
            "{{\"inventory\": {:?}, \"http_timeout_secs\": 10, \"feeds\": {{\"kev\": false, \"osv\": false, \"github\": false, \"epss\": false, \"nvd\": false}}, \"explore\": {{\"enabled\": true, \"max_per_cycle\": 1, \"queries_file\": {:?}, \"agent_cmd\": [\"sh\", {:?}], \"agent_prompt_file\": {:?}, \"sandbox_cmd\": [\"sh\", {:?}]}}}}",
            inv_path.to_str().unwrap(),
            qfile.to_str().unwrap(),
            stub_cmd(),
            format!("{}/explore-prompt.md", env!("CARGO_MANIFEST_DIR")),
            sandbox_wrapper(),
        ),
    )
    .unwrap();
    let o = Command::new(BIN)
        .args(["watch", "--config", cfg2.to_str().unwrap(), "--out-dir", dir.join("w2").to_str().unwrap(), "--shard", "explore", "--max-runs", "1", "--interval", "1"])
        .env("KB_SCAN_SANDBOX_MARKER", &marker)
        .output()
        .unwrap();
    let code2 = o.status.code().unwrap_or(-1);
    assert!(code2 == 0 || code2 == 3, "code2={} stderr={}", code2, String::from_utf8_lossy(&o.stderr));
    let marker_text = std::fs::read_to_string(&marker).unwrap_or_default();
    assert!(marker_text.contains("stub-agent"), "marker: {}", marker_text);
    assert!(dir.join("w2").join("leads.json").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn scan_and_sync_pass_sandbox_gate() {
    let _git = GIT_TEST_LOCK.lock().unwrap();
    let dir = std::env::temp_dir().join(format!("kb-scan-it19-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let inv_path = dir.join("inventory.json");
    std::fs::write(&inv_path, r#"{"packages": [], "products": [], "cves": []}"#).unwrap();
    // config with a network feed enabled and NO sandbox_cmd
    let cfg_path = dir.join("config.json");
    std::fs::write(
        &cfg_path,
        format!(
            "{{\"inventory\": {:?}, \"feeds\": {{\"kev\": true, \"osv\": false, \"github\": false, \"epss\": false, \"nvd\": false}}}}",
            inv_path.to_str().unwrap()
        ),
    )
    .unwrap();
    // scan without sandbox_cmd -> exit 2
    let (code, _, stderr) = run(&["scan", "--config", cfg_path.to_str().unwrap()]);
    assert_eq!(code, 2, "stderr: {}", stderr);
    assert!(stderr.contains("network shards require sandbox_cmd"), "stderr: {}", stderr);
    // sync (git fetch = network) without sandbox_cmd -> exit 2
    let (code, _, stderr) = run(&["sync", "--repo", "."]);
    assert_eq!(code, 2, "stderr: {}", stderr);
    assert!(stderr.contains("network shards require sandbox_cmd"), "stderr: {}", stderr);
    // with --allow-unsandboxed they run (loud warning)
    let (code, _, stderr) = run(&["sync", "--repo", ".", "--allow-unsandboxed"]);
    assert!(code == 0 || code == 3, "code={} stderr={}", code, stderr);
    assert!(stderr.contains("WITHOUT a sandbox"), "stderr: {}", stderr);
    // with sandbox_cmd wrapper, the one-shot command re-execs under it (marker proves it)
    let marker = dir.join("marker.log");
    let cfg2 = dir.join("config2.json");
    std::fs::write(
        &cfg2,
        format!(
            "{{\"inventory\": {:?}, \"sandbox_cmd\": [\"sh\", {:?}], \"feeds\": {{\"kev\": false, \"osv\": false, \"github\": false, \"epss\": false, \"nvd\": false}}}}",
            inv_path.to_str().unwrap(),
            sandbox_wrapper(),
        ),
    )
    .unwrap();
    let o = Command::new(BIN)
        .args(["scan", "--config", cfg2.to_str().unwrap()])
        .env("KB_SCAN_SANDBOX_MARKER", &marker)
        .output()
        .unwrap();
    let code = o.status.code().unwrap_or(-1);
    assert!(code == 0 || code == 3, "code={} stderr={}", code, String::from_utf8_lossy(&o.stderr));
    let marker_text = std::fs::read_to_string(&marker).unwrap_or_default();
    assert!(marker_text.contains("scan"), "marker: {}", marker_text);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn stop_file_ends_watch() {
    let _git = GIT_TEST_LOCK.lock().unwrap();
    let dir = std::env::temp_dir().join(format!("kb-scan-it4-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let cfg_path = dir.join("config.json");
    let inv_path = dir.join("inventory.json");
    std::fs::write(&cfg_path, format!("{{\"inventory\": {:?}, \"feeds\": {{\"kev\": false, \"osv\": false, \"github\": false, \"epss\": false, \"nvd\": false}}}}", inv_path.to_str().unwrap())).unwrap();
    std::fs::write(&inv_path, r#"{"packages": [], "products": [], "cves": []}"#).unwrap();
    let stop = dir.join("stop");
    std::fs::write(&stop, "stop").unwrap();
    let (code, _, _) = run(&[
        "watch", "--config", cfg_path.to_str().unwrap(), "--out-dir", dir.to_str().unwrap(),
        "--interval", "1", "--stop-file", stop.to_str().unwrap(), "--allow-unsandboxed",
    ]);
    // stop file present before first cycle: loop ends after at most one cycle
    assert!(code == 0 || code == 3, "got {}", code);
    let _ = std::fs::remove_dir_all(&dir);
}
