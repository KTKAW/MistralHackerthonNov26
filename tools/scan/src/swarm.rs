//! SWARM runtime mode: the polling agent itself is a swarm of isolated
//! pollers. The supervisor spawns one child process of the current exe per
//! shard — `<exe> watch --shard <name> --config <same> --interval <same>
//! --max-runs <same> --out-dir <out-dir>/shards/<name>` with env
//! KB_SCAN_SHARD=<name> — monitors them, respawns abnormal exits with
//! exponential backoff (cap 60s), and after each cycle merges the shard
//! reports into <out-dir>/latest.json (+ latest-sync.json) and timestamped
//! copies under <out-dir>/reports/. All writes are atomic (temp + rename).
//! The supervisor holds <out-dir>/swarm.lock (create_new + /proc stale check;
//! exit 4 if held, --force overrides).

use crate::config;
use crate::date;
use crate::json;
use crate::merge::{self, Merged};
use crate::watch::{acquire_lock_file, atomic_write};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Backoff cap for respawning a shard child, in seconds.
pub const BACKOFF_CAP_SECS: u64 = 60;

pub struct SwarmArgs {
    pub config_path: String,
    pub interval_secs: Option<u64>,
    pub max_runs: Option<u64>,
    pub out_dir: Option<String>,
    pub pretty: bool,
    pub force: bool,
    pub stop_file: Option<String>,
    /// Workflow run id for the triage.json handoff; "latest" if not given.
    pub run_id: Option<String>,
}

struct ChildProc {
    child: Option<Child>,
    /// exited cleanly (0) or with reported partial errors (3) — do not respawn
    finished: bool,
    fail_count: u32,
    next_spawn: Instant,
    started: Instant,
}

fn spawn_shard(
    exe: &Path,
    shard: &str,
    config_path: &str,
    interval: u64,
    max_runs: u64,
    shard_out: &Path,
) -> Result<Child, String> {
    let mut cmd = Command::new(exe);
    cmd.arg("watch")
        .arg("--shard").arg(shard)
        .arg("--interval").arg(interval.to_string())
        .arg("--max-runs").arg(max_runs.to_string())
        .arg("--out-dir").arg(shard_out)
        .env("KB_SCAN_SHARD", shard)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit()); // shard progress lines stay visible on stderr
    if !config_path.is_empty() {
        cmd.arg("--config").arg(config_path);
    }
    cmd.spawn().map_err(|e| format!("failed to spawn shard {}: {}", shard, e))
}

fn backoff_secs(fail_count: u32) -> u64 {
    let shift = fail_count.saturating_sub(1).min(10);
    (1u64 << shift).min(BACKOFF_CAP_SECS)
}

/// Write the merged outputs atomically: latest.json, latest-sync.json,
/// timestamped copies under reports/, and the triage handoff at
/// <workflow_root>/<run>/triage.json (the file the main workflow's step 0
/// reads).
fn write_merged(
    out_dir: &Path,
    reports_dir: &Path,
    merged: &Merged,
    pretty: bool,
    workflow_root: &str,
    run_id: &str,
) -> Result<(), String> {
    let stamp = date::file_stamp(date::now_secs());
    let report_json = json::serialize(&merged.report, pretty);
    atomic_write(&out_dir.join("latest.json"), &report_json)?;
    atomic_write(&reports_dir.join(format!("{}-scan.json", stamp)), &report_json)?;
    if let Some(sync) = &merged.sync {
        let sync_json = json::serialize(sync, pretty);
        atomic_write(&out_dir.join("latest-sync.json"), &sync_json)?;
        atomic_write(&reports_dir.join(format!("{}-sync.json", stamp)), &sync_json)?;
    }
    let run_dir = Path::new(workflow_root).join(run_id);
    std::fs::create_dir_all(&run_dir).map_err(|e| format!("cannot create {:?}: {}", run_dir, e))?;
    atomic_write(&run_dir.join("triage.json"), &report_json)?;
    Ok(())
}

/// Run the swarm supervisor. Returns the process exit code.
pub fn run_swarm(args: &SwarmArgs) -> i32 {
    let mut cfg = match config::load_config(&args.config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("kb-scan: {}", e);
            return 2;
        }
    };
    if let Some(i) = args.interval_secs {
        cfg.interval_secs = i;
    }
    if let Some(m) = args.max_runs {
        cfg.max_runs = m;
    }
    if let Some(o) = &args.out_dir {
        cfg.out_dir = o.clone();
    }
    let out_dir = PathBuf::from(&cfg.out_dir);
    let reports_dir = out_dir.join("reports");
    let shards_dir = out_dir.join("shards");
    for d in [&out_dir, &reports_dir, &shards_dir] {
        if let Err(e) = std::fs::create_dir_all(d) {
            eprintln!("kb-scan: cannot create {:?}: {}", d, e);
            return 2;
        }
    }
    let stop_file = match &args.stop_file {
        Some(s) => PathBuf::from(s),
        None => out_dir.join("stop"),
    };

    // supervisor lock
    let _lock = match acquire_lock_file(&out_dir.join("swarm.lock"), args.force) {
        Ok(l) => l,
        Err(code) => return code,
    };

    let shards = merge::shard_list(&cfg);
    let run_id = args.run_id.clone().unwrap_or_else(|| "latest".to_string());
    eprintln!("kb-scan: swarm starting with shards {:?} (interval {}s, max-runs {})", shards, cfg.interval_secs, cfg.max_runs);

    let exe = match std::env::current_exe() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("kb-scan: cannot locate current exe: {}", e);
            return 2;
        }
    };

    let mut children: HashMap<String, ChildProc> = HashMap::new();
    for shard in &shards {
        let shard_out = shards_dir.join(shard);
        match spawn_shard(&exe, shard, &args.config_path, cfg.interval_secs, cfg.max_runs, &shard_out) {
            Ok(child) => {
                eprintln!("kb-scan: spawned shard {} (pid {}) -> {:?}", shard, child.id(), shard_out);
                children.insert(
                    shard.clone(),
                    ChildProc { child: Some(child), finished: false, fail_count: 0, next_spawn: Instant::now(), started: Instant::now() },
                );
            }
            Err(e) => {
                eprintln!("kb-scan: {}", e);
                children.insert(
                    shard.clone(),
                    ChildProc { child: None, finished: false, fail_count: 1, next_spawn: Instant::now() + Duration::from_secs(1), started: Instant::now() },
                );
            }
        }
    }

    let max_runs = cfg.max_runs;
    let interval = cfg.interval_secs.max(1);
    let mut cycle = 0u64;
    let mut any_errors = false;
    let mut stopped = false;

    loop {
        cycle += 1;
        // wait one interval in 1s ticks, reaping children as they exit
        for _ in 0..interval {
            std::thread::sleep(Duration::from_secs(1));
            if stop_file.exists() {
                stopped = true;
                break;
            }
            reap_children(&mut children, cfg.interval_secs, &mut any_errors);
        }
        reap_children(&mut children, cfg.interval_secs, &mut any_errors);

        // merge after each cycle
        match merge::merge_out_dir(&out_dir) {
            Ok(merged) => {
                if let Err(e) = write_merged(&out_dir, &reports_dir, &merged, args.pretty, &cfg.workflow_root, &run_id) {
                    eprintln!("kb-scan: merge write failed: {}", e);
                    any_errors = true;
                } else {
                    eprintln!("kb-scan: cycle {} merged {} shard report(s) -> latest.json + {}/{}/triage.json", cycle, merged.report.get("shards").and_then(|s| s.as_array()).map(|a| a.len()).unwrap_or(0), cfg.workflow_root, run_id);
                }
            }
            Err(e) => {
                // shards may not have written yet on the first cycle; only an error later
                eprintln!("kb-scan: cycle {} merge: {}", cycle, e);
                if cycle > 1 {
                    any_errors = true;
                }
            }
        }

        let supervisor_done = max_runs > 0 && cycle >= max_runs;
        if stopped || supervisor_done {
            break;
        }
        // respawn shards that died abnormally, with exponential backoff
        for shard in &shards {
            let cp = children.get_mut(shard).expect("shard present");
            if cp.child.is_none() && !cp.finished && Instant::now() >= cp.next_spawn {
                let shard_out = shards_dir.join(shard);
                match spawn_shard(&exe, shard, &args.config_path, cfg.interval_secs, cfg.max_runs, &shard_out) {
                    Ok(child) => {
                        eprintln!("kb-scan: respawned shard {} (pid {})", shard, child.id());
                        cp.child = Some(child);
                        cp.started = Instant::now();
                    }
                    Err(e) => {
                        cp.fail_count += 1;
                        cp.next_spawn = Instant::now() + Duration::from_secs(backoff_secs(cp.fail_count));
                        eprintln!("kb-scan: {} (retry in {}s)", e, backoff_secs(cp.fail_count));
                    }
                }
            }
        }
    }

    if stopped {
        eprintln!("kb-scan: stop file {:?} present, stopping swarm", stop_file);
    }
    // shutdown: terminate remaining children and reap them
    for (shard, cp) in children.iter_mut() {
        if let Some(child) = cp.child.as_mut() {
            eprintln!("kb-scan: stopping shard {} (pid {})", shard, child.id());
            let _ = child.kill();
        }
    }
    for cp in children.values_mut() {
        if let Some(child) = cp.child.as_mut() {
            let _ = child.wait();
        }
    }

    // final merge so latest.json reflects the last state of every shard
    match merge::merge_out_dir(&out_dir) {
        Ok(merged) => {
            if let Err(e) = write_merged(&out_dir, &reports_dir, &merged, args.pretty, &cfg.workflow_root, &run_id) {
                eprintln!("kb-scan: final merge write failed: {}", e);
                any_errors = true;
            }
        }
        Err(e) => {
            eprintln!("kb-scan: final merge: {}", e);
            any_errors = true;
        }
    }
    eprintln!("kb-scan: swarm finished after {} cycle(s)", cycle);
    if any_errors { 3 } else { 0 }
}

/// Poll every child; record exits. Clean exits (0) and partial-error exits (3,
/// e.g. a rate-limited feed) mark the shard finished — children exit on their
/// own once their --max-runs is reached, so they must not be respawned.
fn reap_children(children: &mut HashMap<String, ChildProc>, interval: u64, any_errors: &mut bool) {
    for cp in children.values_mut() {
        let Some(child) = cp.child.as_mut() else { continue };
        match child.try_wait() {
            Ok(Some(status)) => {
                let code = status.code().unwrap_or(-1);
                cp.child = None;
                if code == 0 || code == 3 {
                    cp.finished = true;
                } else {
                    cp.fail_count += 1;
                    cp.next_spawn = Instant::now() + Duration::from_secs(backoff_secs(cp.fail_count));
                    *any_errors = true;
                    eprintln!("kb-scan: shard child exited with code {} (respawn in {}s)", code, backoff_secs(cp.fail_count));
                }
            }
            Ok(None) => {
                // still alive; if it has survived a full interval, reset backoff
                if cp.started.elapsed() >= Duration::from_secs(interval) {
                    cp.fail_count = 0;
                }
            }
            Err(_) => {
                cp.child = None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_is_capped_at_60s() {
        assert_eq!(backoff_secs(1), 1);
        assert_eq!(backoff_secs(2), 2);
        assert_eq!(backoff_secs(3), 4);
        assert_eq!(backoff_secs(7), 60);
        assert_eq!(backoff_secs(20), 60);
        assert_eq!(backoff_secs(100), 60);
    }
}
