//! Spawning one sandboxed LLM-agent process per task. The engine only
//! schedules, queues, spawns and merges — it never reads web content itself.
//! Every agent runs as an argv array (never a shell), under sandbox_cmd if
//! configured, in a fresh per-agent cwd, with a scrubbed environment (no
//! inherited secrets), and a hard timeout after which it is killed.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Scrubbed environment: only PATH and HOME are provided; nothing (in
/// particular no tokens or secrets) is inherited from the parent.
fn scrubbed_env(cmd: &mut Command) {
    cmd.env_clear();
    let path = std::env::var("PATH").unwrap_or_else(|_| "/usr/local/bin:/usr/bin:/bin".to_string());
    cmd.env("PATH", path);
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    cmd.env("HOME", home);
    // test hook only: lets tests/passthrough-sandbox.sh prove agent wrapping;
    // it is not a secret and carries no credentials
    if let Ok(m) = std::env::var("KB_SCAN_SANDBOX_MARKER") {
        cmd.env("KB_SCAN_SANDBOX_MARKER", m);
    }
}

pub struct AgentTask {
    pub id: String,
    /// fully substituted prompt text (the last argv element)
    pub prompt: String,
}

pub struct AgentOutcome {
    pub timed_out: bool,
    #[allow(dead_code)]
    pub exit_code: Option<i32>,
    pub agent_dir: PathBuf,
}

/// Substitute the task fields into the prompt template. Supported
/// placeholders: {{id}}, {{query}}, {{subject}}, {{sources_hint}}.
pub fn render_prompt(template: &str, task: &AgentTask, query: &str, sources_hint: &str) -> String {
    template
        .replace("{{id}}", &task.id)
        .replace("{{query}}", query)
        .replace("{{subject}}", query)
        .replace("{{sources_hint}}", sources_hint)
}

/// Spawn one agent for a task and wait for it, killing it at the hard
/// timeout. `agent_cmd` is the argv prefix (e.g. ["vibe","-p"]); the
/// substituted prompt is appended as the final argv element. `sandbox_cmd`,
/// if non-empty, wraps the whole thing (e.g. bwrap). Never a shell.
pub fn run_agent(
    agent_cmd: &[String],
    sandbox_cmd: &[String],
    task: &AgentTask,
    agent_dir: &Path,
    timeout_secs: u64,
) -> Result<AgentOutcome, String> {
    if agent_cmd.is_empty() {
        return Err("agent_cmd is empty; refusing to spawn".to_string());
    }
    // fresh per-agent dir
    let _ = std::fs::remove_dir_all(agent_dir);
    std::fs::create_dir_all(agent_dir).map_err(|e| format!("cannot create agent dir {:?}: {}", agent_dir, e))?;

    // Resolve path-like argv elements (e.g. a relative script path in
    // agent_cmd) against the ENGINE's cwd, not the agent's per-agent cwd —
    // otherwise a config like ["sh", "tools/scan/tests/stub-agent.sh"] would
    // break the moment the child chdirs into its sandbox dir.
    let resolve = |a: &String| -> String {
        if a.contains('/') && !a.starts_with('/') {
            let p = Path::new(a);
            if p.exists() {
                if let Ok(abs) = std::fs::canonicalize(p) {
                    return abs.to_string_lossy().into_owned();
                }
            }
        }
        a.clone()
    };
    let mut argv: Vec<String> = Vec::new();
    argv.extend(sandbox_cmd.iter().map(resolve));
    argv.extend(agent_cmd.iter().map(resolve));
    argv.push(task.prompt.clone());

    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..])
        .current_dir(agent_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    scrubbed_env(&mut cmd);
    cmd.env("KB_SCAN_AGENT_ID", &task.id);
    let mut child = cmd.spawn().map_err(|e| format!("failed to spawn agent ({}): {}", argv[0], e))?;

    let deadline = Instant::now() + Duration::from_secs(timeout_secs.max(1));
    let code = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status.code(),
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Ok(AgentOutcome { timed_out: true, exit_code: None, agent_dir: agent_dir.to_path_buf() });
                }
                std::thread::sleep(Duration::from_millis(200));
            }
            Err(e) => return Err(format!("wait failed: {}", e)),
        }
    };
    Ok(AgentOutcome { timed_out: false, exit_code: code, agent_dir: agent_dir.to_path_buf() })
}

/// Read a capped, strictly-parsed JSON file (agent output). Agent output is
/// untrusted: parsed with the strict parser and every string sanitised by
/// the caller.
pub fn read_agent_json(path: &Path) -> Result<crate::json::Value, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read {:?}: {}", path, e))?;
    if text.len() > 4 * 1024 * 1024 {
        return Err(format!("{:?} exceeds 4 MiB byte cap", path));
    }
    crate::json::parse(&text).map_err(|e| format!("{:?}: {}", path, e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prompt_substitution() {
        let t = AgentTask { id: "exp-1".into(), prompt: "x".into() };
        let out = render_prompt("id={{id}} q={{query}} s={{subject}} h={{sources_hint}}", &t, "QUERY", "HINT");
        assert_eq!(out, "id=exp-1 q=QUERY s=QUERY h=HINT");
    }

    #[test]
    fn timeout_kills_agent() {
        let dir = std::env::temp_dir().join(format!("kb-scan-agent-to-{}", std::process::id()));
        let task = AgentTask { id: "t1".into(), prompt: "ignored".into() };
        let argv = vec!["sh".to_string(), "-c".to_string(), "sleep 30".to_string()];
        let start = Instant::now();
        let out = run_agent(&argv, &[], &task, &dir, 1).unwrap();
        assert!(out.timed_out);
        assert!(start.elapsed() < Duration::from_secs(10));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn empty_agent_cmd_refused() {
        let dir = std::env::temp_dir().join(format!("kb-scan-agent-empty-{}", std::process::id()));
        let task = AgentTask { id: "t".into(), prompt: "p".into() };
        assert!(run_agent(&[], &[], &task, &dir, 1).is_err());
    }
}
