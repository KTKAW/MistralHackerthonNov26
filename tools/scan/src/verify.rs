//! Verify shard: per cycle, build `<out>/verify/queue.json` from findings
//! with tier <= 2 (read from the supervisor's merged latest.json) plus all
//! unverified leads (from the explore shard's leads.json), then spawn up to
//! `max_per_cycle` sandboxed verifier agents. Each writes `verdicts.json` in
//! its own dir: `{verdicts: [{id, status: confirmed|partial|unconfirmed,
//! sources: [{url, read}]}]}`. Verdicts accumulate in `<out>/verdicts.json`.

use crate::agent::{self, AgentTask};
use crate::config::Config;
use crate::date;
use crate::json::{self, Value};
use crate::sanitize::sanitize;
use crate::watch::atomic_write;
use std::path::Path;

pub const VERDICTS_SCHEMA: &str = "kb-scan-verdicts/1";
pub const VALID_STATUSES: &[&str] = &["confirmed", "partial", "unconfirmed"];

pub struct VerifyTask {
    pub id: String,
    pub subject: String,
}

/// Build the verify queue: tier<=2 findings from the supervisor's merged
/// latest.json (path relative to this shard's out dir: ../latest.json), plus
/// all unverified leads from ../explore/leads.json.
pub fn build_tasks(shard_out: &Path) -> Vec<VerifyTask> {
    let mut tasks: Vec<VerifyTask> = Vec::new();
    // shard_out = <supervisor-out>/shards/verify, so the merged report is ../../latest.json
    let sup_latest = shard_out.join("..").join("..").join("latest.json");
    if let Ok(text) = std::fs::read_to_string(&sup_latest) {
        if let Ok(v) = json::parse(&text) {
            if let Some(findings) = v.get("findings").and_then(|f| f.as_array()) {
                for f in findings {
                    let tier = f.get("tier").and_then(|t| t.as_u64()).unwrap_or(u64::MAX);
                    if tier <= 2 {
                        let id = f.get("id").and_then(|x| x.as_str()).unwrap_or("").to_string();
                        let summary = f.get("summary").and_then(|x| x.as_str()).unwrap_or("").to_string();
                        if !id.is_empty() && !tasks.iter().any(|t| t.id == id) {
                            tasks.push(VerifyTask { id, subject: summary });
                        }
                    }
                }
            }
        }
    }
    let leads_path = shard_out.join("..").join("explore").join("leads.json");
    if let Ok(text) = std::fs::read_to_string(&leads_path) {
        if let Ok(v) = json::parse(&text) {
            if let Some(leads) = v.get("leads").and_then(|l| l.as_array()) {
                for l in leads {
                    let status = l.get("status").and_then(|s| s.as_str()).unwrap_or("unverified");
                    if status == "unverified" {
                        let id = l.get("id").and_then(|x| x.as_str()).unwrap_or("").to_string();
                        let summary = l.get("summary").and_then(|x| x.as_str()).unwrap_or("").to_string();
                        if !id.is_empty() && !tasks.iter().any(|t| t.id == id) {
                            tasks.push(VerifyTask { id, subject: summary });
                        }
                    }
                }
            }
        }
    }
    tasks
}

pub struct CycleSummary {
    pub tasks: usize,
    pub agents_spawned: usize,
    pub verdicts: usize,
}

/// One verify cycle. `shard_out` is this shard's own out dir
/// (<supervisor-out>/shards/verify).
pub fn run_cycle(cfg: &Config, shard_out: &Path) -> Result<CycleSummary, String> {
    let vc = &cfg.verify;
    let verify_dir = shard_out.join("verify");
    let agents_dir = verify_dir.join("agents");
    std::fs::create_dir_all(&agents_dir).map_err(|e| format!("cannot create {:?}: {}", agents_dir, e))?;

    let tasks = build_tasks(shard_out);
    let queue = Value::obj(vec![
        ("schema".to_string(), Value::str("kb-scan-verify-queue/1")),
        ("generated_at".to_string(), Value::str(date::rfc3339_utc(date::now_secs()))),
        (
            "tasks".to_string(),
            Value::arr(
                tasks
                    .iter()
                    .map(|t| Value::obj(vec![("id".to_string(), Value::str(&t.id)), ("subject".to_string(), Value::str(&t.subject))]))
                    .collect(),
            ),
        ),
    ]);
    atomic_write(&verify_dir.join("queue.json"), &json::to_compact(&queue))?;

    if vc.agent_cmd.is_empty() {
        return Err("verify enabled but agent_cmd is empty".to_string());
    }
    let prompt_template = std::fs::read_to_string(&vc.agent_prompt_file)
        .map_err(|e| format!("cannot read agent prompt file {:?}: {}", vc.agent_prompt_file, e))?;
    let timeout = cfg.http_timeout_secs.saturating_mul(4);

    let mut new_verdicts: Vec<Value> = Vec::new();
    let mut spawned = 0usize;
    for t in tasks.iter().take(vc.max_per_cycle as usize) {
        let prompt = agent::render_prompt(
            &prompt_template,
            &AgentTask { id: t.id.clone(), prompt: String::new() },
            &t.subject,
            "NVD, OSV, EPSS, vendor security blogs, watchlist publishers",
        );
        let task = AgentTask { id: t.id.clone(), prompt };
        let agent_dir = agents_dir.join(&t.id);
        match agent::run_agent(&vc.agent_cmd, &vc.sandbox_cmd, &task, &agent_dir, timeout) {
            Ok(outcome) => {
                spawned += 1;
                if outcome.timed_out {
                    eprintln!("kb-scan verify: agent {} timed out and was killed", t.id);
                }
                match agent::read_agent_json(&outcome.agent_dir.join("verdicts.json")) {
                    Ok(v) => {
                        if let Some(arr) = v.get("verdicts").and_then(|x| x.as_array()) {
                            for vd in arr {
                                if let Some(v2) = sanitise_verdict(vd) {
                                    new_verdicts.push(v2);
                                }
                            }
                        }
                    }
                    Err(e) => eprintln!("kb-scan verify: agent {} produced no usable verdicts.json: {}", t.id, e),
                }
            }
            Err(e) => {
                eprintln!("kb-scan verify: {}", e);
                return Err(e);
            }
        }
    }

    // accumulate verdicts.json, latest verdict per id wins
    let verdicts_path = shard_out.join("verdicts.json");
    let mut all: Vec<Value> = Vec::new();
    if let Ok(text) = std::fs::read_to_string(&verdicts_path) {
        if let Ok(v) = json::parse(&text) {
            if let Some(arr) = v.get("verdicts").and_then(|x| x.as_array()) {
                all.extend(arr.iter().cloned());
            }
        }
    }
    for vd in &new_verdicts {
        let id = vd.get("id").and_then(|x| x.as_str()).unwrap_or("");
        if let Some(pos) = all.iter().position(|x| x.get("id").and_then(|i| i.as_str()) == Some(id)) {
            all[pos] = vd.clone();
        } else {
            all.push(vd.clone());
        }
    }
    let doc = Value::obj(vec![
        ("schema".to_string(), Value::str(VERDICTS_SCHEMA)),
        ("generated_at".to_string(), Value::str(date::rfc3339_utc(date::now_secs()))),
        ("verdicts".to_string(), Value::arr(all.clone())),
    ]);
    atomic_write(&verdicts_path, &json::to_compact(&doc))?;

    Ok(CycleSummary { tasks: tasks.len(), agents_spawned: spawned, verdicts: all.len() })
}

/// Sanitise one verdict; status restricted to confirmed|partial|unconfirmed.
fn sanitise_verdict(v: &Value) -> Option<Value> {
    let id = v.get("id").and_then(|x| x.as_str())?;
    let status = v.get("status").and_then(|x| x.as_str()).unwrap_or("unconfirmed");
    let status = if VALID_STATUSES.contains(&status) { status } else { "unconfirmed" };
    let sources: Vec<Value> = v
        .get("sources")
        .and_then(|s| s.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|s| {
                    let url = sanitize(s.get("url").and_then(|x| x.as_str())?);
                    let read = sanitize(s.get("read").and_then(|x| x.as_str()).unwrap_or("via-snippet"));
                    Some(Value::obj(vec![("url".to_string(), Value::str(url)), ("read".to_string(), Value::str(read))]))
                })
                .collect()
        })
        .unwrap_or_default();
    Some(Value::obj(vec![
        ("id".to_string(), Value::str(sanitize(id))),
        ("status".to_string(), Value::str(status)),
        ("sources".to_string(), Value::arr(sources)),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_from_findings_and_leads() {
        let sup = std::env::temp_dir().join(format!("kb-scan-vq-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&sup);
        let vdir = sup.join("shards").join("verify");
        let edir = sup.join("shards").join("explore");
        std::fs::create_dir_all(&vdir).unwrap();
        std::fs::create_dir_all(&edir).unwrap();
        std::fs::write(
            sup.join("latest.json"),
            r#"{"findings":[{"tier":1,"id":"MAL-1","summary":"m"},{"tier":2,"id":"CVE-1","summary":"c"},{"tier":4,"id":"GHSA-x","summary":"g"}]}"#,
        )
        .unwrap();
        std::fs::write(
            edir.join("leads.json"),
            r#"{"schema":"kb-scan-leads/1","leads":[{"id":"lead-a","status":"unverified","summary":"l1"},{"id":"lead-b","status":"confirmed","summary":"l2"}]}"#,
        )
        .unwrap();
        let tasks = build_tasks(&vdir);
        let ids: Vec<&str> = tasks.iter().map(|t| t.id.as_str()).collect();
        assert_eq!(ids, vec!["MAL-1", "CVE-1", "lead-a"]); // tier<=2 findings + unverified leads only
        let _ = std::fs::remove_dir_all(&sup);
    }

    #[test]
    fn verdict_status_whitelist() {
        let v = json::parse(r#"{"id":"CVE-1","status":"confirmed","sources":[{"url":"https://x","read":"full"}]}"#).unwrap();
        let s = sanitise_verdict(&v).unwrap();
        assert_eq!(s.get("status").and_then(|x| x.as_str()), Some("confirmed"));
        let bad = json::parse(r#"{"id":"CVE-1","status":"hacked"}"#).unwrap();
        let s = sanitise_verdict(&bad).unwrap();
        assert_eq!(s.get("status").and_then(|x| x.as_str()), Some("unconfirmed"));
    }
}
