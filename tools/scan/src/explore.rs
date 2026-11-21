//! Explore shard: per cycle, rotate the query list (round-robin + one jittered
//! extra term per cycle from a small built-in list), write
//! `<out>/explore/queue-<ts>.json` (one JSON task per line), then spawn up to
//! `max_per_cycle` sandboxed agent processes and collect their
//! `results.json` (schema kb-scan-leads/1, leads status "unverified").
//! Accumulated leads are written to `<out>/leads.json`.

use crate::agent::{self, AgentTask};
use crate::config::Config;
use crate::date;
use crate::json::{self, Value};
use crate::sanitize::sanitize;
use crate::watch::atomic_write;
use std::path::Path;

pub const LEADS_SCHEMA: &str = "kb-scan-leads/1";
pub const DEFAULT_SOURCES_HINT: &str = "NVD, OSV, vendor security blogs, watchlist publishers (watchlist.md)";

/// Small built-in list of rotating extra terms (one jittered pick per cycle).
pub const EXTRA_TERMS: &[&str] = &[
    "new zero-day exploited in the wild",
    "CVE-2026 POC released",
    "ransomware group claims victim",
    "actively exploited in the wild this week",
    "patch bypass published",
];

/// xorshift64* — std-only PRNG for the jitter pick.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Rng {
        Rng(seed.max(1))
    }
    pub fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }
    pub fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }
}

pub struct Task {
    pub id: String,
    pub query: String,
    pub sources_hint: String,
}

/// Read the queries file: one query per line, `#` comments and blank lines
/// skipped, optional `query | sources_hint` split. Capped.
pub fn load_queries(path: &Path) -> Result<Vec<(String, String)>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read queries file {:?}: {}", path, e))?;
    if text.len() > 1024 * 1024 {
        return Err(format!("queries file {:?} exceeds 1 MiB cap", path));
    }
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if out.len() >= 10_000 {
            return Err("queries file exceeds 10k line cap".to_string());
        }
        match line.split_once('|') {
            Some((q, hint)) => out.push((sanitize(q), sanitize(hint))),
            None => out.push((sanitize(line), DEFAULT_SOURCES_HINT.to_string())),
        }
    }
    if out.is_empty() {
        return Err(format!("queries file {:?} has no queries", path));
    }
    Ok(out)
}

/// Pick up to `max_per_cycle` tasks round-robin starting at `offset`, and
/// append one jittered extra term to one of them.
pub fn pick_tasks(queries: &[(String, String)], offset: usize, max_per_cycle: u64, rng: &mut Rng) -> Vec<Task> {
    let n = (max_per_cycle as usize).min(queries.len()).max(1);
    let mut tasks: Vec<Task> = Vec::new();
    for i in 0..n {
        let (q, hint) = &queries[(offset + i) % queries.len()];
        tasks.push(Task { id: String::new(), query: q.clone(), sources_hint: hint.clone() });
    }
    if !tasks.is_empty() {
        let idx = rng.below(tasks.len());
        let term = EXTRA_TERMS[rng.below(EXTRA_TERMS.len())];
        tasks[idx].query = format!("{} {}", tasks[idx].query, term);
    }
    tasks
}

pub struct CycleSummary {
    pub tasks: usize,
    pub agents_spawned: usize,
    #[allow(dead_code)]
    pub agents_timed_out: usize,
    pub leads: usize,
    pub queue_file: String,
}

/// One explore cycle. `out_dir` is the shard's own out dir.
pub fn run_cycle(cfg: &Config, out_dir: &Path, rotation: &mut usize, rng: &mut Rng) -> Result<CycleSummary, String> {
    let ec = &cfg.explore;
    let explore_dir = out_dir.join("explore");
    let agents_dir = explore_dir.join("agents");
    std::fs::create_dir_all(&agents_dir).map_err(|e| format!("cannot create {:?}: {}", agents_dir, e))?;

    let queries = load_queries(Path::new(&ec.queries_file))?;
    let mut tasks = pick_tasks(&queries, *rotation, ec.max_per_cycle, rng);
    *rotation = (*rotation + tasks.len()) % queries.len();
    let stamp = date::file_stamp(date::now_secs());
    for (i, t) in tasks.iter_mut().enumerate() {
        t.id = format!("exp-{}-{}", stamp, i);
    }

    // queue file: one JSON task per line (JSONL), written atomically
    let mut queue_text = String::new();
    for t in &tasks {
        let line = json::to_compact(&Value::obj(vec![
            ("id".to_string(), Value::str(&t.id)),
            ("query".to_string(), Value::str(&t.query)),
            ("sources_hint".to_string(), Value::str(&t.sources_hint)),
        ]));
        queue_text.push_str(&line);
        queue_text.push('\n');
    }
    let queue_name = format!("queue-{}.json", stamp);
    atomic_write(&explore_dir.join(&queue_name), &queue_text)?;

    // spawn agents (up to max_per_cycle), prompt loaded from file, task substituted
    let prompt_template = std::fs::read_to_string(&ec.agent_prompt_file)
        .map_err(|e| format!("cannot read agent prompt file {:?}: {}", ec.agent_prompt_file, e))?;
    let timeout = cfg.http_timeout_secs.saturating_mul(4);
    let mut leads: Vec<Value> = Vec::new();
    let mut spawned = 0usize;
    let mut timed_out = 0usize;
    for t in &tasks {
        if spawned >= ec.max_per_cycle as usize {
            break;
        }
        if ec.agent_cmd.is_empty() {
            return Err("explore enabled but agent_cmd is empty".to_string());
        }
        let prompt = agent::render_prompt(&prompt_template, &AgentTask { id: t.id.clone(), prompt: String::new() }, &t.query, &t.sources_hint);
        let task = AgentTask { id: t.id.clone(), prompt };
        let agent_dir = agents_dir.join(&t.id);
        match agent::run_agent(&ec.agent_cmd, &ec.sandbox_cmd, &task, &agent_dir, timeout) {
            Ok(outcome) => {
                spawned += 1;
                if outcome.timed_out {
                    timed_out += 1;
                    eprintln!("kb-scan explore: agent {} timed out and was killed", t.id);
                }
                // collect results.json (schema kb-scan-leads/1)
                match agent::read_agent_json(&outcome.agent_dir.join("results.json")) {
                    Ok(v) => {
                        if let Some(arr) = v.get("leads").and_then(|x| x.as_array()) {
                            for (i, lead) in arr.iter().enumerate() {
                                leads.push(lead_to_finding(&t.id, i, lead));
                            }
                        }
                    }
                    Err(e) => eprintln!("kb-scan explore: agent {} produced no usable results.json: {}", t.id, e),
                }
            }
            Err(e) => {
                eprintln!("kb-scan explore: {}", e);
                return Err(e);
            }
        }
    }

    // accumulate into leads.json (atomic), dedup by id
    let leads_path = out_dir.join("leads.json");
    let mut all: Vec<Value> = Vec::new();
    if let Ok(text) = std::fs::read_to_string(&leads_path) {
        if let Ok(v) = json::parse(&text) {
            if let Some(arr) = v.get("leads").and_then(|x| x.as_array()) {
                all.extend(arr.iter().cloned());
            }
        }
    }
    for l in &leads {
        let id = l.get("id").and_then(|x| x.as_str()).unwrap_or("");
        if !all.iter().any(|x| x.get("id").and_then(|i| i.as_str()) == Some(id)) {
            all.push(l.clone());
        }
    }
    let doc = Value::obj(vec![
        ("schema".to_string(), Value::str(LEADS_SCHEMA)),
        ("generated_at".to_string(), Value::str(date::rfc3339_utc(date::now_secs()))),
        ("leads".to_string(), Value::arr(all.clone())),
    ]);
    atomic_write(&leads_path, &json::to_compact(&doc))?;

    Ok(CycleSummary { tasks: tasks.len(), agents_spawned: spawned, agents_timed_out: timed_out, leads: all.len(), queue_file: queue_name })
}

/// Convert one agent lead into a stored lead object. Agent output is
/// untrusted: every string sanitised, status forced to "unverified".
fn lead_to_finding(task_id: &str, idx: usize, lead: &Value) -> Value {
    let summary = sanitize(lead.get("summary").and_then(|x| x.as_str()).unwrap_or(""));
    let query = sanitize(lead.get("query").and_then(|x| x.as_str()).unwrap_or(""));
    let urls: Vec<Value> = lead
        .get("urls")
        .and_then(|u| u.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|u| {
                    let url = sanitize(u.get("url").and_then(|x| x.as_str())?);
                    let read = sanitize(u.get("read").and_then(|x| x.as_str()).unwrap_or("via-snippet"));
                    Some(Value::obj(vec![("url".to_string(), Value::str(url)), ("read".to_string(), Value::str(read))]))
                })
                .collect()
        })
        .unwrap_or_default();
    Value::obj(vec![
        ("id".to_string(), Value::str(format!("lead-{}-{}", task_id, idx))),
        ("task_id".to_string(), Value::str(task_id)),
        ("query".to_string(), Value::str(query)),
        ("summary".to_string(), Value::str(summary)),
        ("urls".to_string(), Value::arr(urls)),
        ("status".to_string(), Value::str("unverified")),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_rotation_and_jitter() {
        let queries: Vec<(String, String)> = (0..6).map(|i| (format!("q{}", i), "hint".to_string())).collect();
        let mut rng = Rng::new(42);
        let mut offset = 0usize;
        let t1 = pick_tasks(&queries, offset, 3, &mut rng);
        offset = (offset + t1.len()) % queries.len();
        let ids: Vec<&str> = t1.iter().map(|t| t.query.as_str()).collect();
        // round-robin: first three queries, exactly one with a jittered extra term
        let extras = t1.iter().filter(|t| EXTRA_TERMS.iter().any(|e| t.query.ends_with(e))).count();
        assert_eq!(extras, 1);
        assert_eq!(ids.len(), 3);
        let t2 = pick_tasks(&queries, offset, 3, &mut rng);
        // rotation advanced by 3 (mod 6)
        assert!(t2[0].query.starts_with("q3") || EXTRA_TERMS.iter().any(|e| t2[0].query.starts_with(&format!("q3 {}", e))) || t2[0].query == "q3  ".trim_end() || t2[0].query.starts_with("q3"));
    }

    #[test]
    fn load_queries_parsing() {
        let dir = std::env::temp_dir().join(format!("kb-scan-q-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("q.txt");
        std::fs::write(&f, "# comment\n\nNVD CVE-2026 | NVD\nOSV malware npm\n").unwrap();
        let q = load_queries(&f).unwrap();
        assert_eq!(q.len(), 2);
        assert_eq!(q[0], ("NVD CVE-2026".to_string(), "NVD".to_string()));
        assert_eq!(q[1].1, DEFAULT_SOURCES_HINT);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn lead_sanitisation_forces_unverified() {
        let lead = json::parse(r#"{"query":"q","summary":"bad <script>  text","urls":[{"url":"https://x","read":"full"}],"status":"confirmed"}"#).unwrap();
        let f = lead_to_finding("exp-1", 0, &lead);
        assert_eq!(f.get("status").and_then(|v| v.as_str()), Some("unverified"));
        assert_eq!(f.get("id").and_then(|v| v.as_str()), Some("lead-exp-1-0"));
        assert_eq!(f.get("summary").and_then(|v| v.as_str()), Some("bad <script> text"));
    }
}
