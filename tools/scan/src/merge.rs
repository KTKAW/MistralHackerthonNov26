//! Merge shard reports into one kb-scan-report/1 document.
//!
//! The swarm supervisor runs one `watch --shard <name>` child per shard, each
//! writing under `<out-dir>/shards/<name>/`. Feed shards write `latest.json`
//! (a kb-scan-report/1 with only their feed enabled); the sync shard writes
//! `latest-sync.json` (kb-scan-sync/1), which is surfaced separately.
//! Missing shards are tolerated: merge whatever exists.

use crate::config::Config;
use crate::date;
use crate::json::{self, Value};
use std::path::{Path, PathBuf};

/// All known shard names; "sync" first, then feeds, then explore/verify.
pub const SHARD_NAMES: &[&str] = &["sync", "kev", "osv", "github", "epss", "nvd", "explore", "verify"];

/// The shard list for a config: ["sync"] + each enabled feed + explore/verify
/// when enabled.
pub fn shard_list(cfg: &Config) -> Vec<String> {
    let mut v = vec!["sync".to_string()];
    if cfg.feeds.kev {
        v.push("kev".to_string());
    }
    if cfg.feeds.osv {
        v.push("osv".to_string());
    }
    if cfg.feeds.github {
        v.push("github".to_string());
    }
    if cfg.feeds.epss {
        v.push("epss".to_string());
    }
    if cfg.feeds.nvd {
        v.push("nvd".to_string());
    }
    if cfg.explore.enabled {
        v.push("explore".to_string());
    }
    if cfg.verify.enabled {
        v.push("verify".to_string());
    }
    v
}

pub fn is_valid_shard(name: &str) -> bool {
    SHARD_NAMES.contains(&name)
}

/// Network-touching shards: the sync shard (git fetch) and all feed shards.
/// These MUST run under sandbox_cmd (fail-closed). explore/verify shards do
/// their network I/O inside their own always-sandboxed agent processes.
pub fn is_network_shard(name: &str) -> bool {
    name == "sync" || matches!(name, "kev" | "osv" | "github" | "epss" | "nvd")
}

/// Fail-closed sandbox gate for network shards. Returns Err(2) when any
/// network shard is enabled, no sandbox_cmd is configured, and
/// --allow-unsandboxed was not passed. With --allow-unsandboxed it logs a
/// loud warning instead.
pub fn require_sandbox(sandbox_cmd: &[String], network_shards: &[String], allow_unsandboxed: bool) -> Result<(), i32> {
    if network_shards.is_empty() || !sandbox_cmd.is_empty() {
        return Ok(());
    }
    if allow_unsandboxed {
        eprintln!("kb-scan: WARNING: --allow-unsandboxed is set — network shards {:?} are running WITHOUT a sandbox (local debugging only, never in production)", network_shards);
        return Ok(());
    }
    eprintln!("kb-scan: network shards require sandbox_cmd (bwrap) — set it in config or pass --allow-unsandboxed for local debugging only");
    eprintln!("kb-scan: refusing to start unsandboxed network shards: {:?}", network_shards);
    Err(2)
}

pub struct Merged {
    /// The merged kb-scan-report/1.
    pub report: Value,
    /// The sync shard's kb-scan-sync/1, if present.
    pub sync: Option<Value>,
}

/// Sort key: (effective tier, id). Unverified leads never outrank tier 1/2
/// feed-confirmed findings — they sort below everything else.
fn finding_sort_key(f: &Value) -> (u64, String) {
    let tier = f.get("tier").and_then(|t| t.as_u64()).unwrap_or(u64::MAX);
    let status = f.get("status").and_then(|s| s.as_str()).unwrap_or("");
    let effective = if status == "unverified" { 5 } else { tier };
    let id = f.get("id").and_then(|i| i.as_str()).unwrap_or("").to_string();
    (effective, id)
}

/// A lead becomes a finding with source "explore" and a verdict status.
fn lead_to_finding(lead: &Value, verdict_status: Option<&str>) -> Value {
    let status = verdict_status.unwrap_or("unverified");
    let mut m = vec![
        ("tier".to_string(), Value::num("4")),
        ("kind".to_string(), Value::str("lead")),
        ("id".to_string(), Value::str(lead.get("id").and_then(|x| x.as_str()).unwrap_or(""))),
        ("summary".to_string(), Value::str(lead.get("summary").and_then(|x| x.as_str()).unwrap_or(""))),
        ("source".to_string(), Value::str("explore")),
        ("status".to_string(), Value::str(status)),
        ("playbook".to_string(), Value::str("advisory-fleet-triage")),
    ];
    if let Some(q) = lead.get("query").and_then(|x| x.as_str()) {
        m.push(("query".to_string(), Value::str(q)));
    }
    if let Some(urls) = lead.get("urls") {
        m.push(("urls".to_string(), urls.clone()));
    }
    Value::obj(m)
}

/// Merge every `<out_dir>/shards/*/latest.json` into one report.
pub fn merge_out_dir(out_dir: &Path) -> Result<Merged, String> {
    let shards_dir = out_dir.join("shards");
    let mut findings: Vec<Value> = Vec::new();
    let mut feeds: Vec<Value> = Vec::new();
    let mut shard_infos: Vec<Value> = Vec::new();
    let mut errors: Vec<Value> = Vec::new();
    let mut sum_packages: u64 = 0;
    let mut sum_cves: u64 = 0;
    let mut sum_findings: u64 = 0;
    let mut saw_any = false;

    let mut dirs: Vec<PathBuf> = Vec::new();
    if shards_dir.is_dir() {
        for entry in std::fs::read_dir(&shards_dir).map_err(|e| format!("cannot read {:?}: {}", shards_dir, e))? {
            let entry = entry.map_err(|e| format!("cannot read shard dir entry: {}", e))?;
            if entry.path().is_dir() {
                dirs.push(entry.path());
            }
        }
    }
    dirs.sort();

    for d in &dirs {
        let name = d.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let latest = d.join("latest.json");
        let text = match std::fs::read_to_string(&latest) {
            Ok(t) => t,
            Err(_) => continue, // missing-shard tolerance (e.g. sync shard writes latest-sync.json)
        };
        saw_any = true;
        let v = json::parse(&text).map_err(|e| format!("shard {:?} latest.json: {}", name, e))?;
        let generated_at = v.get("generated_at").and_then(|x| x.as_str()).unwrap_or("").to_string();
        // per-shard status: the feed entry matching the shard name, else "unknown"
        let status = v
            .get("feeds")
            .and_then(|f| f.as_array())
            .and_then(|arr| {
                arr.iter()
                    .find(|f| f.get("name").and_then(|n| n.as_str()) == Some(name.as_str()))
                    .or_else(|| arr.first())
                    .and_then(|f| f.get("status").and_then(|s| s.as_str()))
            })
            .unwrap_or("unknown")
            .to_string();
        shard_infos.push(Value::obj(vec![
            ("name".to_string(), Value::str(&name)),
            ("status".to_string(), Value::str(&status)),
            ("generated_at".to_string(), Value::str(&generated_at)),
        ]));
        if let Some(f) = v.get("feeds").and_then(|x| x.as_array()) {
            feeds.extend(f.iter().cloned());
        }
        if let Some(f) = v.get("findings").and_then(|x| x.as_array()) {
            findings.extend(f.iter().cloned());
        }
        if let Some(s) = v.get("stats") {
            sum_packages += s.get("packages").and_then(|x| x.as_u64()).unwrap_or(0);
            sum_cves += s.get("cves").and_then(|x| x.as_u64()).unwrap_or(0);
            sum_findings += s.get("findings").and_then(|x| x.as_u64()).unwrap_or(0);
            if let Some(errs) = s.get("errors").and_then(|x| x.as_array()) {
                errors.extend(errs.iter().cloned());
            }
        }
    }

    // surface the sync shard's latest-sync.json separately
    let mut sync: Option<Value> = None;
    let sync_latest = shards_dir.join("sync").join("latest-sync.json");
    if let Ok(text) = std::fs::read_to_string(&sync_latest) {
        if let Ok(v) = json::parse(&text) {
            let generated_at = v.get("generated_at").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let status = if v.get("errors").and_then(|e| e.as_array()).map(|a| !a.is_empty()).unwrap_or(false) {
                "error"
            } else {
                "ok"
            };
            shard_infos.push(Value::obj(vec![
                ("name".to_string(), Value::str("sync")),
                ("status".to_string(), Value::str(status)),
                ("generated_at".to_string(), Value::str(generated_at)),
            ]));
            sync = Some(v);
            saw_any = true;
        }
    }

    // explore shard: fold leads as findings with source "explore"
    let mut verdicts: Vec<(String, String)> = Vec::new();
    let verdicts_path = shards_dir.join("verify").join("verdicts.json");
    if let Ok(text) = std::fs::read_to_string(&verdicts_path) {
        if let Ok(v) = json::parse(&text) {
            if let Some(arr) = v.get("verdicts").and_then(|x| x.as_array()) {
                for vd in arr {
                    let id = vd.get("id").and_then(|x| x.as_str()).unwrap_or("").to_string();
                    let st = vd.get("status").and_then(|x| x.as_str()).unwrap_or("unconfirmed").to_string();
                    if !id.is_empty() {
                        verdicts.push((id, st));
                    }
                }
            }
            let generated_at = v.get("generated_at").and_then(|x| x.as_str()).unwrap_or("").to_string();
            shard_infos.push(Value::obj(vec![
                ("name".to_string(), Value::str("verify")),
                ("status".to_string(), Value::str("ok")),
                ("generated_at".to_string(), Value::str(generated_at)),
            ]));
            saw_any = true;
        }
    }
    let leads_path = shards_dir.join("explore").join("leads.json");
    let mut lead_count = 0usize;
    if let Ok(text) = std::fs::read_to_string(&leads_path) {
        if let Ok(v) = json::parse(&text) {
            if let Some(arr) = v.get("leads").and_then(|x| x.as_array()) {
                for lead in arr {
                    let id = lead.get("id").and_then(|x| x.as_str()).unwrap_or("");
                    let verdict = verdicts.iter().find(|(vid, _)| vid == id).map(|(_, s)| s.as_str());
                    findings.push(lead_to_finding(lead, verdict));
                    lead_count += 1;
                }
            }
            let generated_at = v.get("generated_at").and_then(|x| x.as_str()).unwrap_or("").to_string();
            shard_infos.push(Value::obj(vec![
                ("name".to_string(), Value::str("explore")),
                ("status".to_string(), Value::str("ok")),
                ("generated_at".to_string(), Value::str(generated_at)),
            ]));
            saw_any = true;
        }
    }
    sum_findings += lead_count as u64;

    // apply verifier verdicts to feed findings too (verify queue includes tier<=2)
    for f in findings.iter_mut() {
        if f.get("source").and_then(|s| s.as_str()) != Some("explore") {
            let id = f.get("id").and_then(|x| x.as_str()).unwrap_or("");
            if let Some((_, st)) = verdicts.iter().find(|(vid, _)| vid == id) {
                // insert/replace status member
                if let Value::Obj(members) = f {
                    members.retain(|(k, _)| k != "status");
                    members.push(("status".to_string(), Value::str(st)));
                }
            }
        }
    }

    if !saw_any {
        return Err(format!("no shard reports found under {:?}", shards_dir));
    }

    // findings concatenated and sorted by (tier, id)
    findings.sort_by(|a, b| finding_sort_key(a).cmp(&finding_sort_key(b)));

    let report = Value::obj(vec![
        ("schema".to_string(), Value::str("kb-scan-report/1")),
        ("generated_at".to_string(), Value::str(date::rfc3339_utc(date::now_secs()))),
        (
            "engine".to_string(),
            Value::obj(vec![
                ("name".to_string(), Value::str("kb-scan")),
                ("version".to_string(), Value::str(env!("CARGO_PKG_VERSION"))),
                ("static_musl".to_string(), Value::bool(cfg!(target_env = "musl"))),
                ("swarm".to_string(), Value::bool(true)),
            ]),
        ),
        ("feeds".to_string(), Value::arr(feeds)),
        ("findings".to_string(), Value::arr(findings)),
        (
            "stats".to_string(),
            Value::obj(vec![
                ("packages".to_string(), Value::num(sum_packages.to_string())),
                ("cves".to_string(), Value::num(sum_cves.to_string())),
                ("findings".to_string(), Value::num(sum_findings.to_string())),
                ("errors".to_string(), Value::arr(errors)),
            ]),
        ),
        ("shards".to_string(), Value::arr(shard_infos)),
    ]);
    Ok(Merged { report, sync })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn write_shard(base: &Path, name: &str, report: &str) {
        let d = base.join("shards").join(name);
        fs::create_dir_all(&d).unwrap();
        fs::write(d.join("latest.json"), report).unwrap();
    }

    fn fixture_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("kb-scan-merge-test-{}-{}", tag, std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn shard_list_order_and_toggles() {
        use crate::config::{ExploreCfg, VerifyCfg};
        let mut cfg = Config::default();
        cfg.feeds = crate::config::FeedToggles { kev: true, osv: true, github: true, epss: true, nvd: true };
        assert_eq!(shard_list(&cfg), vec!["sync", "kev", "osv", "github", "epss", "nvd"]);
        cfg.explore = ExploreCfg { enabled: true, ..Default::default() };
        cfg.verify = VerifyCfg { enabled: true, ..Default::default() };
        assert_eq!(shard_list(&cfg), vec!["sync", "kev", "osv", "github", "epss", "nvd", "explore", "verify"]);
        let none = Config::default();
        assert_eq!(shard_list(&none), vec!["sync", "kev", "osv", "github", "epss"]); // feeds default on, explore/verify off
        assert!(is_valid_shard("sync"));
        assert!(is_valid_shard("explore"));
        assert!(is_valid_shard("verify"));
        assert!(!is_valid_shard("bogus"));
    }

    #[test]
    fn merge_sorts_sums_and_tolerates_missing_shards() {
        let dir = fixture_dir("a");
        // shard "kev": two findings out of tier order
        write_shard(
            &dir,
            "kev",
            r#"{"schema":"kb-scan-report/1","generated_at":"2026-11-21T00:00:00Z",
                "feeds":[{"name":"kev","status":"ok","entries":2}],
                "findings":[{"tier":2,"id":"CVE-2021-44228"},{"tier":1,"id":"MAL-1"}],
                "stats":{"packages":2,"cves":1,"findings":2,"errors":["e1"]}}"#,
        );
        // shard "osv": one finding, one feed status
        write_shard(
            &dir,
            "osv",
            r#"{"schema":"kb-scan-report/1","generated_at":"2026-11-21T00:00:01Z",
                "feeds":[{"name":"osv","status":"ok","entries":1}],
                "findings":[{"tier":4,"id":"GHSA-x"}],
                "stats":{"packages":2,"cves":1,"findings":1,"errors":[]}}"#,
        );
        // sync shard: latest-sync.json only (no latest.json) — must be tolerated
        let syncd = dir.join("shards").join("sync");
        fs::create_dir_all(&syncd).unwrap();
        fs::write(syncd.join("latest-sync.json"), r#"{"schema":"kb-scan-sync/1","generated_at":"2026-11-21T00:00:02Z","errors":[]}"#).unwrap();
        // a shard dir with no latest.json at all — tolerated
        fs::create_dir_all(dir.join("shards").join("github")).unwrap();

        let m = merge_out_dir(&dir).unwrap();
        assert_eq!(m.report.get("schema").and_then(|v| v.as_str()), Some("kb-scan-report/1"));
        assert_eq!(m.report.get("engine").and_then(|e| e.get("swarm")).and_then(|v| v.as_bool()), Some(true));
        let findings = m.report.get("findings").and_then(|v| v.as_array()).unwrap();
        let order: Vec<(u64, &str)> = findings.iter().map(|f| (f.get("tier").and_then(|t| t.as_u64()).unwrap(), f.get("id").and_then(|i| i.as_str()).unwrap())).collect();
        assert_eq!(order, vec![(1, "MAL-1"), (2, "CVE-2021-44228"), (4, "GHSA-x")]);
        let stats = m.report.get("stats").unwrap();
        assert_eq!(stats.get("packages").and_then(|v| v.as_u64()), Some(4)); // summed across feed shards
        assert_eq!(stats.get("findings").and_then(|v| v.as_u64()), Some(3));
        assert_eq!(stats.get("errors").and_then(|v| v.as_array()).unwrap().len(), 1);
        let feeds = m.report.get("feeds").and_then(|v| v.as_array()).unwrap();
        assert_eq!(feeds.len(), 2); // per-shard feed status preserved
        let shards = m.report.get("shards").and_then(|v| v.as_array()).unwrap();
        let names: Vec<&str> = shards.iter().map(|s| s.get("name").and_then(|n| n.as_str()).unwrap()).collect();
        assert!(names.contains(&"kev") && names.contains(&"osv") && names.contains(&"sync"));
        let sync = shards.iter().find(|s| s.get("name").and_then(|n| n.as_str()) == Some("sync")).unwrap();
        assert_eq!(sync.get("status").and_then(|s| s.as_str()), Some("ok"));
        // sync report surfaced separately
        let s = m.sync.expect("sync report");
        assert_eq!(s.get("schema").and_then(|v| v.as_str()), Some("kb-scan-sync/1"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn merge_folds_leads_and_applies_verdicts() {
        let dir = fixture_dir("c");
        write_shard(
            &dir,
            "kev",
            r#"{"schema":"kb-scan-report/1","generated_at":"2026-11-21T00:00:00Z",
                "feeds":[{"name":"kev","status":"ok"}],
                "findings":[{"tier":2,"id":"CVE-2","summary":"kev hit"}],
                "stats":{"packages":1,"cves":1,"findings":1,"errors":[]}}"#,
        );
        let edir = dir.join("shards").join("explore");
        std::fs::create_dir_all(&edir).unwrap();
        std::fs::write(
            edir.join("leads.json"),
            r#"{"schema":"kb-scan-leads/1","generated_at":"t","leads":[
                {"id":"lead-u","summary":"unverified lead","status":"unverified","query":"q1","urls":[]},
                {"id":"lead-c","summary":"confirmed lead","status":"unverified","query":"q2","urls":[]}]}"#,
        )
        .unwrap();
        let vdir = dir.join("shards").join("verify");
        std::fs::create_dir_all(&vdir).unwrap();
        std::fs::write(
            vdir.join("verdicts.json"),
            r#"{"schema":"kb-scan-verdicts/1","generated_at":"t","verdicts":[
                {"id":"lead-c","status":"confirmed","sources":[]},
                {"id":"CVE-2","status":"confirmed","sources":[]}]}"#,
        )
        .unwrap();
        let m = merge_out_dir(&dir).unwrap();
        let findings = m.report.get("findings").and_then(|v| v.as_array()).unwrap();
        let order: Vec<(&str, &str)> = findings
            .iter()
            .map(|f| (f.get("id").and_then(|i| i.as_str()).unwrap(), f.get("status").and_then(|s| s.as_str()).unwrap_or("-")))
            .collect();
        // tier-2 feed finding first (verdict applied), confirmed lead next, unverified lead last
        assert_eq!(order, vec![("CVE-2", "confirmed"), ("lead-c", "confirmed"), ("lead-u", "unverified")]);
        let lead_u = findings.iter().find(|f| f.get("id").and_then(|i| i.as_str()) == Some("lead-u")).unwrap();
        assert_eq!(lead_u.get("source").and_then(|s| s.as_str()), Some("explore"));
        let stats = m.report.get("stats").unwrap();
        assert_eq!(stats.get("findings").and_then(|v| v.as_u64()), Some(3));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn merge_preserves_inventory_source() {
        let dir = fixture_dir("d");
        write_shard(
            &dir,
            "osv",
            r#"{"schema":"kb-scan-report/1","generated_at":"t",
                "feeds":[{"name":"osv","status":"ok"}],
                "findings":[{"tier":3,"id":"GHSA-y","package":"npm:lodash@4.17.20","inventory_source":"frontend/package-lock.json","summary":"s","source":"osv"}],
                "stats":{"packages":1,"cves":0,"findings":1,"errors":[]}}"#,
        );
        let m = merge_out_dir(&dir).unwrap();
        let f = m.report.get("findings").and_then(|v| v.as_array()).unwrap()[0].clone();
        assert_eq!(f.get("inventory_source").and_then(|v| v.as_str()), Some("frontend/package-lock.json"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn merge_errors_when_no_shards() {
        let dir = fixture_dir("b");
        assert!(merge_out_dir(&dir).is_err());
        let _ = fs::remove_dir_all(&dir);
    }
}
