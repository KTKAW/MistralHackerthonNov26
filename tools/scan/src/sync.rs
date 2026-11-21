//! Sync pass: poll git and emit a kb-scan-sync/1 report. Report only —
//! the engine never merges, rebases or pushes.

use crate::date;
use crate::git;
use crate::json::{self, Value};
use crate::sanitize::sanitize;

pub struct SyncOutcome {
    pub report: Value,
    pub had_error: bool,
}

pub fn run_sync(repo: &str, remote: &str) -> SyncOutcome {
    let generated_at = date::rfc3339_utc(date::now_secs());
    let mut errors: Vec<String> = Vec::new();

    if let Err(e) = git::fetch(repo, remote) {
        errors.push(e);
    }

    let mut branches_v: Vec<Value> = Vec::new();
    let mut new_branches: Vec<Value> = Vec::new();
    let mut attention: Vec<Value> = Vec::new();

    match git::remote_branches(repo, remote) {
        Ok(branches) => {
            for (short, full_ref, remote_sha) in &branches {
                let local = short.clone();
                let local_exists = git::local_exists(repo, &local);
                let (ahead, behind, new_commits_v, moved) = if local_exists {
                    let (a, b) = git::ahead_behind(repo, &local, full_ref).unwrap_or((0, 0));
                    let commits = git::new_commits(repo, Some(&local), full_ref);
                    (a, b, commits, a > 0 || b > 0)
                } else {
                    let count = git::remote_only_count(repo, full_ref);
                    let commits = git::new_commits(repo, None, full_ref);
                    new_branches.push(Value::str(format!("{}/{}", remote, short)));
                    attention.push(Value::str(format!("new branch {}/{} appeared", remote, short)));
                    (0, count, commits, count > 0)
                };
                if local_exists && behind > 0 {
                    let local_sha = git::git(repo, &["rev-parse", "--short", &local])
                        .map(|o| o.stdout.trim().to_string())
                        .unwrap_or_else(|_| "?".to_string());
                    let remote_short = &remote_sha[..remote_sha.len().min(7)];
                    attention.push(Value::str(format!(
                        "{}/{} moved {}..{}: rebase before relying on ingested pages",
                        remote, short, local_sha, remote_short
                    )));
                }
                if local_exists && ahead > 0 {
                    attention.push(Value::str(format!(
                        "local {} is {} commit(s) ahead of {}/{} (not pushed)",
                        short, ahead, remote, short
                    )));
                }
                let commits_v: Vec<Value> = new_commits_v
                    .iter()
                    .map(|(sha, subject)| {
                        json::Value::obj(vec![
                            ("sha".to_string(), Value::str(sha)),
                            ("subject".to_string(), Value::str(sanitize(subject))),
                        ])
                    })
                    .collect();
                branches_v.push(Value::obj(vec![
                    ("name".to_string(), Value::str(format!("{}/{}", remote, short))),
                    ("ahead".to_string(), Value::num(ahead.to_string())),
                    ("behind".to_string(), Value::num(behind.to_string())),
                    ("new_commits".to_string(), Value::arr(commits_v)),
                    ("moved".to_string(), Value::bool(moved)),
                ]));
            }
        }
        Err(e) => errors.push(e),
    }

    let report = Value::obj(vec![
        ("schema".to_string(), Value::str("kb-scan-sync/1")),
        ("generated_at".to_string(), Value::str(generated_at)),
        ("repo".to_string(), Value::str(repo)),
        ("remote".to_string(), Value::str(remote)),
        ("branches".to_string(), Value::arr(branches_v)),
        ("new_branches".to_string(), Value::arr(new_branches)),
        ("attention".to_string(), Value::arr(attention)),
        ("errors".to_string(), Value::arr(errors.iter().map(|e| Value::str(sanitize(e))).collect())),
    ]);
    SyncOutcome { report, had_error: !errors.is_empty() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sync_report_schema_on_local_repo() {
        let dir = std::env::temp_dir().join(format!("kb-scan-sync-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let repo = dir.to_str().unwrap().to_string();
        assert!(git::git(&repo, &["init", "-q", "-b", "main"]).map(|o| o.ok()).unwrap_or(false));
        let out = run_sync(&repo, "origin");
        assert_eq!(out.report.get("schema").and_then(|v| v.as_str()), Some("kb-scan-sync/1"));
        assert!(out.report.get("generated_at").and_then(|v| v.as_str()).is_some());
        // no origin remote: fetch fails, reported as error, exit-worthy
        assert!(out.had_error);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
