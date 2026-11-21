//! Watch loop: one instance at a time (create_new lock file + /proc stale
//! detection + --force), each cycle runs sync then scan and writes reports
//! atomically (temp file + rename). A stop file or --max-runs ends the loop.
//! The loop never acts on findings — it writes reports and proposes.

use crate::config::{self, FeedToggles};
use crate::date;
use crate::json;
use crate::merge;
use crate::scan;
use crate::sync;
use std::io::Write;
use std::path::{Path, PathBuf};

pub struct WatchArgs {
    pub config_path: String,
    pub interval_secs: Option<u64>,
    pub max_runs: Option<u64>,
    pub out_dir: Option<String>,
    pub pretty: bool,
    pub force: bool,
    pub stop_file: Option<String>,
    pub max_filesize: Option<usize>,
    /// Swarm shard mode: run only this shard's work ("sync" or one feed name).
    pub shard: Option<String>,
}

/// Atomically write a file: write to `<path>.tmp-<pid>` then rename.
pub fn atomic_write(path: &Path, contents: &str) -> Result<(), String> {
    let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
    {
        let mut f = std::fs::File::create(&tmp).map_err(|e| format!("cannot create {:?}: {}", tmp, e))?;
        f.write_all(contents.as_bytes()).map_err(|e| format!("cannot write {:?}: {}", tmp, e))?;
        f.sync_all().map_err(|e| format!("cannot fsync {:?}: {}", tmp, e))?;
    }
    std::fs::rename(&tmp, path).map_err(|e| format!("cannot rename {:?} -> {:?}: {}", tmp, path, e))
}

pub struct LockGuard {
    path: PathBuf,
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Acquire a single-instance lock at an explicit path (create_new + /proc
/// stale detection). Returns Err(exit_code) on failure: exit 4 when another
/// live instance holds it (unless force), 2 when the file cannot be created.
pub fn acquire_lock_file(lock_path: &Path, force: bool) -> Result<LockGuard, i32> {
    let try_create = |lock_path: &Path| -> Result<std::fs::File, std::io::Error> {
        std::fs::OpenOptions::new().write(true).create_new(true).open(lock_path)
    };
    match try_create(lock_path) {
        Ok(mut f) => {
            let _ = writeln!(f, "{}", std::process::id());
            return Ok(LockGuard { path: lock_path.to_path_buf() });
        }
        Err(e) if e.kind() != std::io::ErrorKind::AlreadyExists => {
            eprintln!("kb-scan: cannot create lock file {:?}: {}", lock_path, e);
            return Err(2);
        }
        Err(_) => {}
    }
    // Lock exists: is the holder alive?
    let existing = std::fs::read_to_string(lock_path).unwrap_or_default();
    let pid: Option<u32> = existing.trim().parse().ok();
    let alive = pid.map(|p| Path::new(&format!("/proc/{}", p)).is_dir()).unwrap_or(false);
    if alive && !force {
        eprintln!("kb-scan: lock held by live pid {} ({:?}); use --force to override", pid.unwrap_or(0), lock_path);
        return Err(4);
    }
    if alive && force {
        eprintln!("kb-scan: --force: overriding lock held by pid {}", pid.unwrap_or(0));
    } else {
        eprintln!("kb-scan: removing stale lock (pid {:?})", pid);
    }
    let _ = std::fs::remove_file(lock_path);
    match try_create(lock_path) {
        Ok(mut f) => {
            let _ = writeln!(f, "{}", std::process::id());
            Ok(LockGuard { path: lock_path.to_path_buf() })
        }
        Err(_) => {
            eprintln!("kb-scan: could not re-create lock file {:?}", lock_path);
            Err(4)
        }
    }
}

/// Acquire the per-instance lock inside an out dir.
fn acquire_lock(out_dir: &Path, force: bool) -> Result<LockGuard, i32> {
    acquire_lock_file(&out_dir.join("kb-scan.lock"), force)
}

fn sleep_interruptible(secs: u64, stop_file: &Path) {
    for _ in 0..secs {
        if stop_file.exists() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

/// Run the watch loop. Returns the process exit code.
pub fn run_watch(args: &WatchArgs) -> i32 {
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
    if let Some(m) = args.max_filesize {
        cfg.max_body_bytes = m;
    }
    let out_dir = PathBuf::from(&cfg.out_dir);
    let reports_dir = out_dir.join("reports");
    for d in [&out_dir, &reports_dir] {
        if let Err(e) = std::fs::create_dir_all(d) {
            eprintln!("kb-scan: cannot create {:?}: {}", d, e);
            return 2;
        }
    }
    let stop_file = PathBuf::from(args.stop_file.as_deref().unwrap_or("").to_string());
    let stop_file = if args.stop_file.is_some() {
        stop_file
    } else {
        out_dir.join("stop")
    };

    let _lock = match acquire_lock(&out_dir, args.force) {
        Ok(l) => l,
        Err(code) => return code,
    };

    // shard validation happens before any network/inventory work
    if let Some(s) = &args.shard {
        if !merge::is_valid_shard(s) {
            eprintln!("kb-scan: unknown shard {:?} (expected one of {:?})", s, merge::SHARD_NAMES);
            return 2;
        }
    }
    let shard = args.shard.clone();

    let inventory = match config::load_inventory(&cfg, None) {
        Ok(inv) => inv,
        Err(e) => {
            eprintln!("kb-scan: {}", e);
            return 2;
        }
    };

    // In shard mode a feed shard runs only that feed: force the toggles.
    let effective_cfg = match &shard {
        Some(name) if name != "sync" => {
            let mut c = cfg.clone();
            c.feeds = FeedToggles {
                kev: name == "kev",
                osv: name == "osv",
                github: name == "github",
                epss: name == "epss",
                nvd: name == "nvd",
            };
            c
        }
        _ => cfg.clone(),
    };

    let max_runs = effective_cfg.max_runs;
    let mut run = 0u64;
    let mut any_errors = false;
    loop {
        run += 1;
        if max_runs > 0 && run > max_runs {
            break;
        }
        if stop_file.exists() {
            eprintln!("kb-scan: stop file {:?} present, ending loop", stop_file);
            break;
        }
        eprintln!("kb-scan: cycle {} starting{}", run, shard.as_ref().map(|s| format!(" (shard {})", s)).unwrap_or_default());
        let stamp = date::file_stamp(date::now_secs());

        let do_sync = shard.as_deref().map(|s| s == "sync").unwrap_or(true);
        let do_scan = shard.is_none() || (shard.as_deref() != Some("sync"));

        // sync pass (report only)
        if do_sync {
            let sync_out = sync::run_sync(".", &effective_cfg.git_remote);
            if sync_out.had_error {
                any_errors = true;
            }
            let sync_json = json::serialize(&sync_out.report, args.pretty);
            let sync_name = format!("{}-sync.json", stamp);
            if let Err(e) = atomic_write(&reports_dir.join(&sync_name), &sync_json) {
                eprintln!("kb-scan: {}", e);
            }
            if let Err(e) = atomic_write(&out_dir.join("latest-sync.json"), &sync_json) {
                eprintln!("kb-scan: {}", e);
            }
            eprintln!("kb-scan: cycle {} wrote {}", run, sync_name);
        }

        // scan pass
        if do_scan {
            let scan_out = scan::run_scan(&effective_cfg, &inventory);
            if scan_out.had_errors {
                any_errors = true;
            }
            let scan_json = json::serialize(&scan_out.report, args.pretty);
            let scan_name = format!("{}-scan.json", stamp);
            if let Err(e) = atomic_write(&reports_dir.join(&scan_name), &scan_json) {
                eprintln!("kb-scan: {}", e);
            }
            if let Err(e) = atomic_write(&out_dir.join("latest.json"), &scan_json) {
                eprintln!("kb-scan: {}", e);
            }
            eprintln!("kb-scan: cycle {} wrote {}", run, scan_name);
        }

        if max_runs > 0 && run >= max_runs {
            break;
        }
        sleep_interruptible(effective_cfg.interval_secs, &stop_file);
    }
    eprintln!("kb-scan: watch loop finished after {} cycle(s)", run);
    if any_errors { 3 } else { 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_write_roundtrip() {
        let dir = std::env::temp_dir().join(format!("kb-scan-atomic-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("r.json");
        atomic_write(&p, "{\"a\":1}").unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "{\"a\":1}");
        // no temp files left behind
        let leftovers: Vec<_> = std::fs::read_dir(&dir).unwrap().filter_map(|e| e.ok()).filter(|e| e.file_name().to_string_lossy().contains("tmp")).collect();
        assert!(leftovers.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn stale_lock_is_reclaimed_live_lock_refused() {
        let dir = std::env::temp_dir().join(format!("kb-scan-lock-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // stale lock: pid that does not exist
        std::fs::write(dir.join("kb-scan.lock"), "99999999").unwrap();
        let guard = acquire_lock(&dir, false).expect("stale lock should be reclaimed");
        drop(guard);
        assert!(!dir.join("kb-scan.lock").exists());
        // live lock: our own pid
        std::fs::write(dir.join("kb-scan.lock"), std::process::id().to_string()).unwrap();
        assert!(acquire_lock(&dir, false).err() == Some(4));
        // --force overrides
        let guard = acquire_lock(&dir, true).expect("force should override");
        drop(guard);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
