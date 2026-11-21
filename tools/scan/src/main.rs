//! kb-scan — continuous host-side sync/scan engine for the knowledge base.
//!
//! Subcommands (pinned): version, self-test, feeds, sync, scan, watch.
//! Exit codes: 0 ok · 2 usage/config error · 3 feed/git error (partial
//! results still reported) · 4 lock held by another instance.
//! stdout carries only JSON; human-readable progress goes to stderr.

#![forbid(unsafe_code)]

mod agent;
mod config;
mod date;
mod explore;
mod feeds;
mod git;
mod http;
mod json;
mod merge;
mod proc;
mod sanitize;
mod scan;
mod serve;
mod swarm;
mod sync;
mod triage;
mod url;
mod verify;
mod watch;

use json::Value;
use std::process::exit;

const USAGE: &str = "kb-scan — knowledge-base sync/scan engine

USAGE:
  kb-scan version
  kb-scan self-test
  kb-scan feeds
  kb-scan sync   [--repo DIR] [--out FILE] [--pretty] [--allow-unsandboxed]
  kb-scan scan   [--config FILE] [--inventory FILE] [--out FILE] [--pretty] [--max-filesize BYTES]
                 [--allow-unsandboxed]
  kb-scan watch  [--config FILE] [--interval SECS] [--max-runs N] [--out-dir DIR] [--pretty]
                 [--force] [--stop-file FILE] [--max-filesize BYTES] [--shard NAME]
                 [--allow-unsandboxed]
  kb-scan swarm  [--config FILE] [--interval SECS] [--max-runs N] [--out-dir DIR] [--pretty]
                 [--force] [--stop-file FILE] [--run-id ID] [--workflow-root DIR]
                 [--allow-unsandboxed]
  kb-scan merge  [--out-dir DIR] [--out FILE] [--pretty]
  kb-scan serve  --out-dir DIR [--addr 127.0.0.1:8787] [--allow-non-localhost]

Exit codes: 0 ok · 2 usage/config error · 3 feed/git error (partial results reported) · 4 lock held.
stdout carries only JSON; progress goes to stderr.";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    exit(real_main(&args));
}

/// Parse `--key value` / `--key=value` / boolean `--flag` arguments.
struct Flags {
    values: std::collections::HashMap<String, String>,
    bools: std::collections::HashSet<String>,
}

fn parse_flags(args: &[String], allowed: &[&str]) -> Result<Flags, String> {
    let mut values = std::collections::HashMap::new();
    let mut bools = std::collections::HashSet::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if let Some(rest) = a.strip_prefix("--") {
            let (key, inline) = match rest.split_once('=') {
                Some((k, v)) => (k.to_string(), Some(v.to_string())),
                None => (rest.to_string(), None),
            };
            if !allowed.contains(&key.as_str()) {
                return Err(format!("unknown flag --{}", key));
            }
            match inline {
                Some(v) => {
                    values.insert(key, v);
                }
                None => {
                    // boolean flags take no value
                    if matches!(key.as_str(), "pretty" | "force" | "allow-unsandboxed") {
                        bools.insert(key);
                    } else {
                        if i + 1 >= args.len() {
                            return Err(format!("flag --{} requires a value", key));
                        }
                        values.insert(key, args[i + 1].clone());
                        i += 1;
                    }
                }
            }
        } else {
            return Err(format!("unexpected argument {:?}", a));
        }
        i += 1;
    }
    Ok(Flags { values, bools })
}

impl Flags {
    fn get(&self, k: &str) -> Option<&str> {
        self.values.get(k).map(|s| s.as_str())
    }
    fn bool(&self, k: &str) -> bool {
        self.bools.contains(k)
    }
    fn u64(&self, k: &str) -> Result<Option<u64>, String> {
        match self.get(k) {
            None => Ok(None),
            Some(s) => s.parse::<u64>().map(Some).map_err(|_| format!("--{} must be a non-negative integer", k)),
        }
    }
}

fn print_json(v: &Value, pretty: bool) {
    println!("{}", json::serialize(v, pretty));
}

fn write_out_or_stdout(out: Option<&str>, text: &str, pretty: bool, v: &Value) -> i32 {
    match out {
        Some(path) => {
            if let Err(e) = watch::atomic_write(std::path::Path::new(path), text) {
                eprintln!("kb-scan: {}", e);
                return 2;
            }
            eprintln!("kb-scan: wrote {}", path);
            let _ = (pretty, v);
            0
        }
        None => {
            print_json(v, pretty);
            0
        }
    }
}

fn cmd_version() -> i32 {
    print_json(
        &Value::obj(vec![
            ("name".to_string(), Value::str("kb-scan")),
            ("version".to_string(), Value::str(env!("CARGO_PKG_VERSION"))),
            ("static_musl".to_string(), Value::bool(cfg!(target_env = "musl"))),
        ]),
        false,
    );
    0
}

fn cmd_feeds() -> i32 {
    let feed_list = Value::arr(vec![
        Value::obj(vec![
            ("name".to_string(), Value::str("kev")),
            ("method".to_string(), Value::str("GET")),
            ("url".to_string(), Value::str(feeds::KEV_URL)),
            ("host".to_string(), Value::str("www.cisa.gov")),
        ]),
        Value::obj(vec![
            ("name".to_string(), Value::str("osv")),
            ("method".to_string(), Value::str("POST")),
            ("url".to_string(), Value::str(feeds::OSV_QUERY_URL)),
            ("url".to_string(), Value::str(feeds::OSV_BATCH_URL)),
            ("host".to_string(), Value::str("api.osv.dev")),
        ]),
        Value::obj(vec![
            ("name".to_string(), Value::str("github")),
            ("method".to_string(), Value::str("GET")),
            ("url".to_string(), Value::str(feeds::GITHUB_ADVISORIES_URL)),
            ("host".to_string(), Value::str("api.github.com")),
        ]),
        Value::obj(vec![
            ("name".to_string(), Value::str("epss")),
            ("method".to_string(), Value::str("GET")),
            ("url".to_string(), Value::str(feeds::EPSS_URL)),
            ("host".to_string(), Value::str("api.first.org")),
        ]),
        Value::obj(vec![
            ("name".to_string(), Value::str("nvd")),
            ("method".to_string(), Value::str("GET")),
            ("url".to_string(), Value::str(feeds::NVD_URL)),
            ("host".to_string(), Value::str("services.nvd.nist.gov")),
            ("default".to_string(), Value::bool(false)),
        ]),
    ]);
    print_json(
        &Value::obj(vec![
            ("allowlist".to_string(), Value::arr(url::ALLOWED_HOSTS.iter().map(|h| Value::str(*h)).collect())),
            ("scheme".to_string(), Value::str("https-only")),
            ("transport".to_string(), Value::str("curl argv array, no shell, no redirects")),
            ("feeds".to_string(), feed_list),
        ]),
        false,
    );
    0
}

fn cmd_self_test() -> i32 {
    let mut failures: Vec<String> = Vec::new();
    let mut check = |name: &str, ok: bool| {
        if ok {
            eprintln!("kb-scan self-test: {} ok", name);
        } else {
            failures.push(name.to_string());
            eprintln!("kb-scan self-test: {} FAILED", name);
        }
    };

    // JSON roundtrip + escaping
    let src = r#"{"a":[1,2.5,-3e2,true,false,null,"x<y&z"],"b":{"c":"d"}}"#;
    let v = json::parse(src).ok();
    check("json-parse", v.is_some());
    // roundtrip: parse(serialize(parse(src))) == parse(src) (output escapes
    // < > & so the serialized text need not equal the input text)
    let roundtrip = v
        .as_ref()
        .map(|val| json::parse(&json::to_compact(val)).map(|v2| v2 == *val).unwrap_or(false))
        .unwrap_or(false);
    check("json-roundtrip", roundtrip);
    let esc = json::to_compact(&Value::str("<a>&</a>"));
    check("json-html-escape", esc == "\"\\u003ca\\u003e\\u0026\\u003c/a\\u003e\"");
    check("json-depth-cap", json::parse(&format!("{}1{}", "[".repeat(json::MAX_DEPTH + 2), "]".repeat(json::MAX_DEPTH + 2))).is_err());
    check("json-dup-key", json::parse(r#"{"a":1,"a":2}"#).is_err());

    // sanitiser
    check("sanitize", sanitize::sanitize(" a\u{00} b\n c ") == "a b c");

    // url encoder + allowlist
    check("url-encode", url::encode_component("a b&c@") == "a%20b%26c%40");
    check("allowlist", url::host_allowed("api.osv.dev") && !url::host_allowed("api.osv.dev.evil.com"));
    check("url-check", url::check_url("https://api.first.org/data/v1/epss?cve=CVE-2021-44228").is_ok()
        && url::check_url("http://api.osv.dev/").is_err());

    // triage
    check(
        "triage",
        triage::tier_for(true, true, true, Some(0.9), 0.5) == 1
            && triage::tier_for(false, true, false, None, 0.5) == 2
            && triage::tier_for(false, false, false, Some(0.5), 0.5) == 3
            && triage::tier_for(false, false, false, None, 0.5) == 4,
    );

    // date math
    check(
        "date-math",
        date::unix_to_ymd(0) == (1970, 1, 1)
            && date::unix_to_ymd(1_700_000_000) == (2023, 11, 14)
            && date::parse_ymd("2000-02-29") == Some(11_016)
            && date::rfc3339_utc(1_700_000_000) == "2023-11-14T22:13:20Z",
    );

    // merge smoke check: two feed shards + a sync shard merge into one report
    let mdir = std::env::temp_dir().join(format!("kb-scan-selftest-merge-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&mdir);
    let mk = |name: &str, body: &str| {
        let d = mdir.join("shards").join(name);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("latest.json"), body).unwrap();
    };
    mk("kev", r#"{"schema":"kb-scan-report/1","generated_at":"2026-11-21T00:00:00Z","feeds":[{"name":"kev","status":"ok"}],"findings":[{"tier":2,"id":"CVE-1"}],"stats":{"packages":1,"cves":1,"findings":1,"errors":[]}}"#);
    mk("osv", r#"{"schema":"kb-scan-report/1","generated_at":"2026-11-21T00:00:00Z","feeds":[{"name":"osv","status":"ok"}],"findings":[{"tier":1,"id":"MAL-1"}],"stats":{"packages":1,"cves":1,"findings":1,"errors":[]}}"#);
    let syncd = mdir.join("shards").join("sync");
    std::fs::create_dir_all(&syncd).unwrap();
    std::fs::write(syncd.join("latest-sync.json"), r#"{"schema":"kb-scan-sync/1","generated_at":"2026-11-21T00:00:00Z","errors":[]}"#).unwrap();
    let merge_ok = (|| {
        let m = merge::merge_out_dir(&mdir).ok()?;
        if m.report.get("schema").and_then(|v| v.as_str()) != Some("kb-scan-report/1") {
            return None;
        }
        if m.report.get("engine").and_then(|e| e.get("swarm")).and_then(|v| v.as_bool()) != Some(true) {
            return None;
        }
        let f = m.report.get("findings").and_then(|v| v.as_array())?;
        let first_tier = f.first().and_then(|x| x.get("tier")).and_then(|t| t.as_u64())?;
        let stats = m.report.get("stats")?;
        if first_tier != 1 || stats.get("findings").and_then(|v| v.as_u64()) != Some(2) {
            return None;
        }
        if m.sync.is_none() {
            return None;
        }
        Some(())
    })();
    let _ = std::fs::remove_dir_all(&mdir);
    check("merge-smoke", merge_ok.is_some());

    // explore smoke: one stub-agent cycle (stub script, never a real model call)
    let stub = format!("{}/tests/stub-agent.sh", env!("CARGO_MANIFEST_DIR"));
    let edir = std::env::temp_dir().join(format!("kb-scan-selftest-explore-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&edir);
    std::fs::create_dir_all(&edir).unwrap();
    let qfile = edir.join("queries.txt");
    std::fs::write(&qfile, "NVD CVE-2026 | NVD\nOSV malware npm\n").unwrap();
    let mut ecfg = config::Config::default();
    ecfg.http_timeout_secs = 5;
    ecfg.explore.enabled = true;
    ecfg.explore.max_per_cycle = 2;
    ecfg.explore.queries_file = qfile.to_str().unwrap().to_string();
    ecfg.explore.agent_cmd = vec!["sh".to_string(), stub.clone()];
    ecfg.explore.agent_prompt_file = format!("{}/explore-prompt.md", env!("CARGO_MANIFEST_DIR"));
    ecfg.explore.sandbox_cmd = vec!["sh".to_string(), format!("{}/tests/passthrough-sandbox.sh", env!("CARGO_MANIFEST_DIR"))];
    let mut rotation = 0usize;
    let mut rng = explore::Rng::new(7);
    let explore_ok = explore::run_cycle(&ecfg, &edir, &mut rotation, &mut rng)
        .map(|sum| {
            sum.agents_spawned == 2
                && edir.join("explore").join(&sum.queue_file).exists()
                && edir.join("leads.json").exists()
                && std::fs::read_to_string(edir.join("leads.json")).map(|t| t.contains("kb-scan-leads/1")).unwrap_or(false)
        })
        .unwrap_or(false);
    let _ = std::fs::remove_dir_all(&edir);
    check("explore-stub-agent", explore_ok);

    if failures.is_empty() {
        println!("ok");
        0
    } else {
        eprintln!("kb-scan self-test: {} check(s) failed: {}", failures.len(), failures.join(", "));
        3
    }
}

/// Sandbox gate for one-shot network commands (scan/sync): fail closed unless
/// sandbox_cmd is set or --allow-unsandboxed is passed; when sandbox_cmd is
/// set, re-exec this very command under the wrapper (argv array, no shell,
/// guarded by KB_SCAN_IN_SANDBOX so it happens exactly once).
fn sandbox_gate_reexec(cfg: &config::Config, network: &[String], allow_unsandboxed: bool, args: &[String]) -> Option<i32> {
    if let Err(code) = merge::require_sandbox(&cfg.sandbox_cmd, network, allow_unsandboxed) {
        return Some(code);
    }
    if cfg.sandbox_cmd.is_empty() || std::env::var("KB_SCAN_IN_SANDBOX").is_ok() {
        return None; // gate passed; nothing to wrap (or already inside)
    }
    let exe = match std::env::current_exe() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("kb-scan: cannot locate current exe for sandbox re-exec: {}", e);
            return Some(2);
        }
    };
    let mut argv: Vec<String> = cfg.sandbox_cmd.clone();
    argv.push(exe.to_string_lossy().into_owned());
    argv.extend(args.iter().cloned());
    eprintln!("kb-scan: re-exec under sandbox_cmd for network command {:?}", args[0]);
    let status = std::process::Command::new(&argv[0])
        .args(&argv[1..])
        .env("KB_SCAN_IN_SANDBOX", "1")
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status();
    match status {
        Ok(s) => Some(s.code().unwrap_or(3)),
        Err(e) => {
            eprintln!("kb-scan: sandbox re-exec failed: {}", e);
            Some(2)
        }
    }
}

fn cmd_sync(args: &[String]) -> i32 {
    let flags = match parse_flags(args, &["repo", "out", "pretty", "allow-unsandboxed"]) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("kb-scan sync: {}", e);
            eprintln!("{}", USAGE);
            return 2;
        }
    };
    // sync performs network I/O (git fetch) — same fail-closed sandbox rule
    let sync_cfg = config::load_config("").unwrap_or_default();
    let mut full_args = vec!["sync".to_string()];
    full_args.extend(args.iter().cloned());
    if let Some(code) = sandbox_gate_reexec(&sync_cfg, &["sync".to_string()], flags.bool("allow-unsandboxed"), &full_args) {
        return code;
    }
    let repo = flags.get("repo").unwrap_or(".");
    let pretty = flags.bool("pretty");
    let remote = config::load_config("")
        .map(|c| c.git_remote)
        .unwrap_or_else(|_| "origin".to_string());
    eprintln!("kb-scan: polling git remote '{}' in {}", remote, repo);
    let out = sync::run_sync(repo, &remote);
    if out.had_error {
        eprintln!("kb-scan: sync completed with errors (partial results reported)");
    }
    let text = json::serialize(&out.report, pretty);
    let code = write_out_or_stdout(flags.get("out"), &text, pretty, &out.report);
    if code != 0 {
        return code;
    }
    if out.had_error {
        3
    } else {
        0
    }
}

fn cmd_scan(args: &[String]) -> i32 {
    let flags = match parse_flags(args, &["config", "inventory", "out", "pretty", "max-filesize", "allow-unsandboxed"]) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("kb-scan scan: {}", e);
            eprintln!("{}", USAGE);
            return 2;
        }
    };
    let pretty = flags.bool("pretty");
    let cfg = match config::load_config(flags.get("config").unwrap_or("")) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("kb-scan: {}", e);
            return 2;
        }
    };
    // scan performs network I/O (feeds) — same fail-closed sandbox rule
    let network: Vec<String> = {
        let mut v = Vec::new();
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
        v
    };
    let mut full_args = vec!["scan".to_string()];
    full_args.extend(args.iter().cloned());
    if let Some(code) = sandbox_gate_reexec(&cfg, &network, flags.bool("allow-unsandboxed"), &full_args) {
        return code;
    }
    let mut cfg = cfg;
    if let Ok(Some(m)) = flags.u64("max-filesize") {
        cfg.max_body_bytes = m as usize;
    } else if flags.get("max-filesize").is_some() {
        eprintln!("kb-scan: --max-filesize must be a non-negative integer");
        return 2;
    }
    let inv = match config::load_inventory(&cfg, flags.get("inventory")) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("kb-scan: {}", e);
            return 2;
        }
    };
    eprintln!(
        "kb-scan: scanning {} package(s), {} cve(s), {} product(s)",
        inv.packages.len(),
        inv.cves.len(),
        inv.products.len()
    );
    let out = scan::run_scan(&cfg, &inv);
    if out.had_errors {
        eprintln!("kb-scan: scan completed with feed errors (partial results reported)");
    }
    let text = json::serialize(&out.report, pretty);
    let code = write_out_or_stdout(flags.get("out"), &text, pretty, &out.report);
    if code != 0 {
        return code;
    }
    if out.had_errors {
        3
    } else {
        0
    }
}

fn cmd_watch(args: &[String]) -> i32 {
    let flags = match parse_flags(
        args,
        &["config", "interval", "max-runs", "out-dir", "pretty", "force", "stop-file", "max-filesize", "shard", "allow-unsandboxed"],
    ) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("kb-scan watch: {}", e);
            eprintln!("{}", USAGE);
            return 2;
        }
    };
    let interval = match flags.u64("interval") {
        Ok(v) => v,
        Err(e) => {
            eprintln!("kb-scan watch: {}", e);
            return 2;
        }
    };
    let max_runs = match flags.u64("max-runs") {
        Ok(v) => v,
        Err(e) => {
            eprintln!("kb-scan watch: {}", e);
            return 2;
        }
    };
    let max_filesize = match flags.u64("max-filesize") {
        Ok(v) => v.map(|m| m as usize),
        Err(e) => {
            eprintln!("kb-scan watch: {}", e);
            return 2;
        }
    };
    watch::run_watch(&watch::WatchArgs {
        config_path: flags.get("config").unwrap_or("").to_string(),
        interval_secs: interval,
        max_runs,
        out_dir: flags.get("out-dir").map(|s| s.to_string()),
        pretty: flags.bool("pretty"),
        force: flags.bool("force"),
        stop_file: flags.get("stop-file").map(|s| s.to_string()),
        max_filesize,
        shard: flags.get("shard").map(|s| s.to_string()),
        allow_unsandboxed: flags.bool("allow-unsandboxed"),
    })
}

fn cmd_swarm(args: &[String]) -> i32 {
    let flags = match parse_flags(
        args,
        &["config", "interval", "max-runs", "out-dir", "pretty", "force", "stop-file", "run-id", "workflow-root", "allow-unsandboxed"],
    ) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("kb-scan swarm: {}", e);
            eprintln!("{}", USAGE);
            return 2;
        }
    };
    let interval = match flags.u64("interval") {
        Ok(v) => v,
        Err(e) => {
            eprintln!("kb-scan swarm: {}", e);
            return 2;
        }
    };
    let max_runs = match flags.u64("max-runs") {
        Ok(v) => v,
        Err(e) => {
            eprintln!("kb-scan swarm: {}", e);
            return 2;
        }
    };
    swarm::run_swarm(&swarm::SwarmArgs {
        config_path: flags.get("config").unwrap_or("").to_string(),
        interval_secs: interval,
        max_runs,
        out_dir: flags.get("out-dir").map(|s| s.to_string()),
        pretty: flags.bool("pretty"),
        force: flags.bool("force"),
        stop_file: flags.get("stop-file").map(|s| s.to_string()),
        run_id: flags.get("run-id").map(|s| s.to_string()),
        workflow_root: flags.get("workflow-root").map(|s| s.to_string()),
        allow_unsandboxed: flags.bool("allow-unsandboxed"),
    })
}

fn cmd_merge(args: &[String]) -> i32 {
    let flags = match parse_flags(args, &["out-dir", "out", "pretty"]) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("kb-scan merge: {}", e);
            eprintln!("{}", USAGE);
            return 2;
        }
    };
    let out_dir = flags.get("out-dir").unwrap_or("tools/scan/out");
    match merge::merge_out_dir(std::path::Path::new(out_dir)) {
        Err(e) => {
            eprintln!("kb-scan merge: {}", e);
            2
        }
        Ok(merged) => write_out_or_stdout(flags.get("out"), &json::serialize(&merged.report, flags.bool("pretty")), flags.bool("pretty"), &merged.report),
    }
}

fn cmd_serve(args: &[String]) -> i32 {
    let flags = match parse_flags(args, &["out-dir", "addr", "allow-non-localhost"]) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("kb-scan serve: {}", e);
            eprintln!("{}", USAGE);
            return 2;
        }
    };
    let out_dir = match flags.get("out-dir") {
        Some(d) => d.to_string(),
        None => {
            eprintln!("kb-scan serve: --out-dir is required");
            eprintln!("{}", USAGE);
            return 2;
        }
    };
    serve::run_serve(&serve::ServeArgs {
        out_dir,
        addr: flags.get("addr").unwrap_or(serve::DEFAULT_ADDR).to_string(),
        allow_non_localhost: flags.bool("allow-non-localhost"),
    })
}

fn real_main(args: &[String]) -> i32 {
    match args.first().map(|s| s.as_str()) {
        None => {
            eprintln!("{}", USAGE);
            2
        }
        Some("-h") | Some("--help") | Some("help") => {
            eprintln!("{}", USAGE);
            0
        }
        Some("version") => cmd_version(),
        Some("self-test") => cmd_self_test(),
        Some("feeds") => cmd_feeds(),
        Some("sync") => cmd_sync(&args[1..]),
        Some("scan") => cmd_scan(&args[1..]),
        Some("watch") => cmd_watch(&args[1..]),
        Some("swarm") => cmd_swarm(&args[1..]),
        Some("merge") => cmd_merge(&args[1..]),
        Some("serve") => cmd_serve(&args[1..]),
        Some(other) => {
            eprintln!("kb-scan: unknown subcommand {:?}", other);
            eprintln!("{}", USAGE);
            2
        }
    }
}
