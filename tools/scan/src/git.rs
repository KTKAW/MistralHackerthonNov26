//! Git operations, all as argv arrays (no shell), read-only with respect to
//! the repository: fetch --prune, for-each-ref, rev-list, log. The engine
//! never merges, rebases, resets or pushes — it only reports.

use crate::proc::run_capped;

/// Cap on any single git command's stdout.
pub const MAX_GIT_OUTPUT: usize = 4 * 1024 * 1024;

pub struct GitOutput {
    pub stdout: String,
    pub truncated: bool,
    pub stderr: String,
    pub code: Option<i32>,
}

pub fn git(repo: &str, args: &[&str]) -> Result<GitOutput, String> {
    let mut full: Vec<String> = vec!["-C".to_string(), repo.to_string()];
    full.extend(args.iter().map(|s| s.to_string()));
    let out = run_capped("git", &full, None, MAX_GIT_OUTPUT)
        .map_err(|e| format!("failed to spawn git: {}", e))?;
    Ok(GitOutput {
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        truncated: out.stdout_truncated,
        stderr: out.stderr,
        code: out.code,
    })
}

impl GitOutput {
    pub fn ok(&self) -> bool {
        self.code == Some(0) && !self.truncated
    }
}

/// `git -C repo fetch <remote> --prune`
pub fn fetch(repo: &str, remote: &str) -> Result<(), String> {
    let out = git(repo, &["fetch", "--prune", remote])?;
    if !out.ok() {
        return Err(format!("git fetch {} --prune failed: {}", remote, out.stderr.trim()));
    }
    Ok(())
}

/// List remote-tracking branches: Vec<(short_name, full_ref, sha)>.
pub fn remote_branches(repo: &str, remote: &str) -> Result<Vec<(String, String, String)>, String> {
    let prefix = format!("refs/remotes/{}/", remote);
    let out = git(repo, &["for-each-ref", &prefix, "--format=%(refname) %(objectname)"])?;
    if !out.ok() {
        return Err(format!("git for-each-ref failed: {}", out.stderr.trim()));
    }
    let mut branches = Vec::new();
    for line in out.stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.splitn(2, ' ');
        let full = parts.next().unwrap_or("").to_string();
        let sha = parts.next().unwrap_or("").trim().to_string();
        if let Some(short) = full.strip_prefix(&prefix) {
            branches.push((short.to_string(), full, sha));
        }
    }
    Ok(branches)
}

/// `git rev-list --left-right --count <local>...<remote_ref>` -> (ahead, behind).
/// Returns None if the local branch does not exist.
pub fn ahead_behind(repo: &str, local: &str, remote_ref: &str) -> Option<(u64, u64)> {
    let range = format!("{}...{}", local, remote_ref);
    let out = git(repo, &["rev-list", "--left-right", "--count", &range]).ok()?;
    if !out.ok() {
        return None;
    }
    let mut it = out.stdout.split_whitespace();
    let ahead = it.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let behind = it.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    Some((ahead, behind))
}

/// Count commits on the remote branch when no local branch exists.
pub fn remote_only_count(repo: &str, remote_ref: &str) -> u64 {
    let out = match git(repo, &["rev-list", "--count", remote_ref]) {
        Ok(o) if o.ok() => o,
        _ => return 0,
    };
    out.stdout.trim().parse().unwrap_or(0)
}

/// New commits on the remote side: `git log --format=%H%x00%s <local>..<remote_ref>`
/// (or the whole branch when no local exists). Capped by MAX_GIT_OUTPUT.
pub fn new_commits(repo: &str, local: Option<&str>, remote_ref: &str) -> Vec<(String, String)> {
    let range = match local {
        Some(l) => format!("{}..{}", l, remote_ref),
        None => remote_ref.to_string(),
    };
    let out = match git(repo, &["log", "--format=%H%x00%s", &range]) {
        Ok(o) if o.ok() => o,
        _ => return Vec::new(),
    };
    let mut commits = Vec::new();
    for line in out.stdout.lines() {
        if let Some((sha, subject)) = line.split_once('\0') {
            if !sha.is_empty() {
                commits.push((sha.to_string(), subject.to_string()));
            }
        }
    }
    commits
}

/// Does a local branch exist?
pub fn local_exists(repo: &str, branch: &str) -> bool {
    let out = git(repo, &["rev-parse", "--verify", "--quiet", branch]);
    matches!(out, Ok(o) if o.code == Some(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ahead_behind_output() {
        // exercise the parsing logic through a tiny local repo built in /tmp
        let dir = std::env::temp_dir().join(format!("kb-scan-git-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let repo = dir.to_str().unwrap().to_string();
        assert!(git(&repo, &["init", "-q", "-b", "main"]).map(|o| o.ok()).unwrap_or(false));
        assert!(git(&repo, &["config", "user.email", "t@t"]).map(|o| o.ok()).unwrap_or(false));
        assert!(git(&repo, &["config", "user.name", "t"]).map(|o| o.ok()).unwrap_or(false));
        std::fs::write(dir.join("f"), "x").unwrap();
        assert!(git(&repo, &["add", "f"]).map(|o| o.ok()).unwrap_or(false));
        assert!(git(&repo, &["commit", "-q", "-m", "first"]).map(|o| o.ok()).unwrap_or(false));
        assert!(local_exists(&repo, "main"));
        assert!(!local_exists(&repo, "nope"));
        let ab = ahead_behind(&repo, "main", "main");
        assert_eq!(ab, Some((0, 0)));
        // whole-branch listing works even with a single commit
        let all = new_commits(&repo, None, "main");
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].1, "first");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
