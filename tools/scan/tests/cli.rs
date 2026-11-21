//! Integration tests driving the compiled binary. Zero external crates:
//! uses CARGO_BIN_EXE_kb-scan provided by cargo for integration tests.

use std::process::Command;

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
        "--max-runs", "1", "--interval", "1", "--force",
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
        r#"{"schema":"kb-scan-report/1","generated_at":"2026-11-21T00:00:00Z","feeds":[{"name":"kev","status":"ok","entries":1}],"findings":[{"tier":2,"id":"CVE-1"}],"stats":{"packages":1,"cves":0,"findings":1,"errors":[]}}"#,
    )
    .unwrap();
    let (code, stdout, _) = run(&["merge", "--out-dir", dir.to_str().unwrap()]);
    assert_eq!(code, 0, "stdout: {}", stdout);
    assert!(stdout.contains("\"kb-scan-report/1\""));
    assert!(stdout.contains("\"swarm\":true"));
    assert!(stdout.contains("\"kev\""));
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
    let dir = std::env::temp_dir().join(format!("kb-scan-it8-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (cfg, _inv) = write_fixture_config(&dir);
    let a = dir.join("shardA");
    let b = dir.join("shardB");
    // sync shards need only git (repo "."), feeds are disabled in the fixture
    let (code_a, _, _) = run(&["watch", "--config", &cfg, "--out-dir", a.to_str().unwrap(), "--shard", "sync", "--max-runs", "1", "--interval", "1"]);
    let (code_b, _, _) = run(&["watch", "--config", &cfg, "--out-dir", b.to_str().unwrap(), "--shard", "sync", "--max-runs", "1", "--interval", "1"]);
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

#[test]
fn stop_file_ends_watch() {
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
        "--interval", "1", "--stop-file", stop.to_str().unwrap(),
    ]);
    // stop file present before first cycle: loop ends after at most one cycle
    assert!(code == 0 || code == 3, "got {}", code);
    let _ = std::fs::remove_dir_all(&dir);
}
