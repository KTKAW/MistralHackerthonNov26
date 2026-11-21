//! `kb-scan serve` — localhost-only read-only query loop over the report
//! files. std::net::TcpListener only, zero deps. Endpoints (GET only):
//!   /health            -> {"status":"ok"}
//!   /latest            -> <out-dir>/latest.json bytes (kb-scan-report/1)
//!   /sync              -> <out-dir>/latest-sync.json bytes (kb-scan-sync/1)
//!   /findings          -> latest.json as-is (all tiers); /findings?tier=N filters to tier N
//!                         (a non-numeric tier is a 400)
//!   /brief             -> ≤90-word text/plain brief from latest.json + sync
//! Unknown path or missing file -> 404; non-GET -> 405. If KB_SCAN_QUERY_TOKEN
//! is set, requests need `Authorization: Bearer <token>` (never logged).

use crate::json::{self, Value};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::time::Duration;

pub const DEFAULT_ADDR: &str = "127.0.0.1:8787";
/// Cap on the request head (request line + headers) we are willing to read.
pub const MAX_REQUEST_BYTES: usize = 8 * 1024;
/// Cap on a served file body.
pub const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
pub const READ_TIMEOUT: Duration = Duration::from_secs(10);
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
/// Word budget for the brief.
pub const BRIEF_MAX_WORDS: usize = 90;
pub const BRIEF_CLOSER: &str = "A person approves before anything is sent.";

pub struct ServeArgs {
    pub out_dir: String,
    pub addr: String,
    pub allow_non_localhost: bool,
}

/// Constant-time-ish equality (XOR-accumulate; fine at this scale).
fn token_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc = 0u8;
    for i in 0..a.len() {
        acc |= a[i] ^ b[i];
    }
    acc == 0
}

fn is_authorized(headers: &str, token: &str) -> bool {
    for line in headers.lines() {
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("authorization") {
                let v = value.trim();
                // scheme is case-insensitive; the token itself is compared exactly
                if v.len() >= 6 && v[..6].eq_ignore_ascii_case("bearer") {
                    return token_eq(v[6..].trim().as_bytes(), token.as_bytes());
                }
                return false;
            }
        }
    }
    false
}

fn read_file_capped(path: &Path) -> Option<Vec<u8>> {
    let meta = std::fs::metadata(path).ok()?;
    if meta.len() as usize > MAX_RESPONSE_BYTES {
        return None;
    }
    std::fs::read(path).ok()
}

fn respond(stream: &mut TcpStream, status: &str, content_type: &str, body: &[u8]) -> std::io::Result<()> {
    let head = format!(
        "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        status,
        content_type,
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

fn json_response(stream: &mut TcpStream, status: &str, body: &str) -> std::io::Result<()> {
    respond(stream, status, "application/json", body.as_bytes())
}

/// Filter latest.json's findings to one tier and re-serialise.
pub fn filter_tier(latest_text: &str, tier: u64) -> Result<String, String> {
    let v = json::parse(latest_text).map_err(|e| e.to_string())?;
    let mut out = v.clone();
    if let Value::Obj(members) = &mut out {
        let mut kept = 0usize;
        for (k, val) in members.iter_mut() {
            if k == "findings" {
                if let Value::Arr(arr) = val {
                    arr.retain(|f| f.get("tier").and_then(|t| t.as_u64()) == Some(tier));
                    kept = arr.len();
                }
            }
        }
        for (k, val) in members.iter_mut() {
            if k == "stats" {
                if let Value::Obj(stats) = val {
                    for (sk, sv) in stats.iter_mut() {
                        if sk == "findings" {
                            *sv = Value::num(kept.to_string());
                        }
                    }
                }
            }
        }
    }
    Ok(json::to_compact(&out))
}

fn word_count(s: &str) -> usize {
    s.split_whitespace().count()
}

fn take_words(s: &str, n: usize) -> String {
    s.split_whitespace().take(n).collect::<Vec<_>>().join(" ")
}

/// Render the ≤90-word decision-ready brief from the merged report (+ sync
/// attention lines). Engine-side, deterministic; schemas identical to the
/// Python renderer.
pub fn render_brief(latest: &Value, sync: Option<&Value>) -> String {
    let findings = latest.get("findings").and_then(|f| f.as_array()).map(|a| a.to_vec()).unwrap_or_default();
    // top verified tier 1/2 findings (unverified/unconfirmed leads excluded)
    let top: Vec<&Value> = findings
        .iter()
        .filter(|f| {
            let tier = f.get("tier").and_then(|t| t.as_u64()).unwrap_or(u64::MAX);
            let status = f.get("status").and_then(|s| s.as_str()).unwrap_or("confirmed");
            tier <= 2 && status != "unverified" && status != "unconfirmed"
        })
        .take(4)
        .collect();
    let attention: Vec<String> = sync
        .and_then(|s| s.get("attention").and_then(|a| a.as_array()))
        .map(|arr| arr.iter().filter_map(|a| a.as_str().map(|s| s.to_string())).take(3).collect())
        .unwrap_or_default();

    // shrink until within budget: summary words 12 -> 0, then attention 3 -> 0
    for summary_words in (0..=12).rev() {
        for attn in (0..=attention.len()).rev() {
            let mut lines: Vec<String> = Vec::new();
            lines.push(format!("kb-scan brief: {} verified tier 1 or 2 finding(s).", top.len()));
            for f in &top {
                let id = f.get("id").and_then(|i| i.as_str()).unwrap_or("?");
                let tier = f.get("tier").and_then(|t| t.as_u64()).unwrap_or(0);
                let what = take_words(f.get("summary").and_then(|s| s.as_str()).unwrap_or(""), summary_words);
                let runs = f
                    .get("package")
                    .or_else(|| f.get("product"))
                    .and_then(|p| p.as_str())
                    .unwrap_or("our stack");
                let mut line = format!("Tier {} {}:", tier, id);
                if !what.is_empty() {
                    line.push_str(&format!(" {}", what));
                }
                line.push_str(&format!(" in {}.", take_words(runs, 8)));
                lines.push(line);
            }
            for a in attention.iter().take(attn) {
                lines.push(format!("Sync: {}", take_words(a, 12)));
            }
            lines.push(BRIEF_CLOSER.to_string());
            let text = lines.join(" ");
            if word_count(&text) <= BRIEF_MAX_WORDS {
                return text;
            }
        }
    }
    BRIEF_CLOSER.to_string()
}

fn handle_conn(mut stream: TcpStream, out_dir: &Path, token: Option<&str>) {
    let _ = stream.set_read_timeout(Some(READ_TIMEOUT));
    let _ = stream.set_write_timeout(Some(WRITE_TIMEOUT));
    // read the request head, capped
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if buf.len() >= MAX_REQUEST_BYTES || buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(_) => break, // timeout or reset: stop reading
        }
    }
    let head = String::from_utf8_lossy(&buf);
    let request_line = head.lines().next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let raw_path = parts.next().unwrap_or("").to_string();
    let (path, query) = match raw_path.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (raw_path.clone(), String::new()),
    };
    let headers = &head[request_line.len()..];

    // auth (token never logged)
    if let Some(tok) = token {
        if !is_authorized(headers, tok) {
            let _ = json_response(&mut stream, "401 Unauthorized", r#"{"error":"unauthorized"}"#);
            return;
        }
    }

    if method != "GET" {
        let _ = json_response(&mut stream, "405 Method Not Allowed", r#"{"error":"method not allowed"}"#);
        return;
    }

    match path.as_str() {
        "/health" => {
            let _ = json_response(&mut stream, "200 OK", r#"{"status":"ok"}"#);
        }
        "/latest" => match read_file_capped(&out_dir.join("latest.json")) {
            Some(bytes) => {
                let _ = respond(&mut stream, "200 OK", "application/json", &bytes);
            }
            None => {
                let _ = json_response(&mut stream, "404 Not Found", r#"{"error":"latest.json not found"}"#);
            }
        },
        "/sync" => match read_file_capped(&out_dir.join("latest-sync.json")) {
            Some(bytes) => {
                let _ = respond(&mut stream, "200 OK", "application/json", &bytes);
            }
            None => {
                let _ = json_response(&mut stream, "404 Not Found", r#"{"error":"latest-sync.json not found"}"#);
            }
        },
        "/findings" => {
            // ?tier=N filters; no tier parameter serves the whole merged report,
            // so `tools/scan.py query findings` (no --tier) matches /latest.
            let tier_param = query
                .split('&')
                .find_map(|kv| kv.split_once('=').filter(|(k, _)| *k == "tier").map(|(_, v)| v.to_string()));
            let parsed = match &tier_param {
                None => None,
                Some(t) => match t.parse::<u64>() {
                    Ok(n) => Some(n),
                    Err(_) => {
                        let _ = json_response(&mut stream, "400 Bad Request", r#"{"error":"tier must be a non-negative integer"}"#);
                        return;
                    }
                },
            };
            match read_file_capped(&out_dir.join("latest.json")) {
                Some(bytes) => match parsed {
                    Some(t) => {
                        let text = String::from_utf8_lossy(&bytes).into_owned();
                        match filter_tier(&text, t) {
                            Ok(filtered) => {
                                let _ = json_response(&mut stream, "200 OK", &filtered);
                            }
                            Err(e) => {
                                let _ = json_response(&mut stream, "500 Internal Server Error", &format!("{{\"error\":\"{}\"}}", e));
                            }
                        }
                    }
                    None => {
                        let _ = respond(&mut stream, "200 OK", "application/json", &bytes);
                    }
                },
                None => {
                    let _ = json_response(&mut stream, "404 Not Found", r#"{"error":"latest.json not found"}"#);
                }
            }
        }
        "/brief" => {
            let latest = read_file_capped(&out_dir.join("latest.json")).map(|b| String::from_utf8_lossy(&b).into_owned());
            let sync = read_file_capped(&out_dir.join("latest-sync.json")).map(|b| String::from_utf8_lossy(&b).into_owned());
            match latest {
                Some(text) => match json::parse(&text) {
                    Ok(v) => {
                        let sync_v = sync.and_then(|s| json::parse(&s).ok());
                        let brief = render_brief(&v, sync_v.as_ref());
                        let _ = respond(&mut stream, "200 OK", "text/plain; charset=utf-8", brief.as_bytes());
                    }
                    Err(e) => {
                        let _ = json_response(&mut stream, "500 Internal Server Error", &format!("{{\"error\":\"{}\"}}", e));
                    }
                },
                None => {
                    let _ = json_response(&mut stream, "404 Not Found", r#"{"error":"latest.json not found"}"#);
                }
            }
        }
        _ => {
            let _ = json_response(&mut stream, "404 Not Found", r#"{"error":"unknown path"}"#);
        }
    }
}

/// Run the query server. Returns the process exit code.
pub fn run_serve(args: &ServeArgs) -> i32 {
    let addr: std::net::SocketAddr = match args.addr.parse() {
        Ok(a) => a,
        Err(_) => {
            eprintln!("kb-scan serve: invalid --addr {:?}", args.addr);
            return 2;
        }
    };
    if !addr.ip().is_loopback() && !args.allow_non_localhost {
        eprintln!("kb-scan serve: refusing non-loopback bind {} (pass --allow-non-localhost for local debugging only)", args.addr);
        return 2;
    }
    let listener = match TcpListener::bind(addr) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("kb-scan serve: cannot bind {}: {}", args.addr, e);
            return 2;
        }
    };
    let bound = listener.local_addr().map(|a| a.to_string()).unwrap_or_else(|_| args.addr.clone());
    // stdout carries only JSON: announce the bound address as JSON
    println!("{{\"listening\":\"{}\"}}", bound);
    eprintln!("kb-scan: serve listening on http://{} (out-dir {:?})", bound, args.out_dir);
    let out_dir = std::path::PathBuf::from(&args.out_dir);
    // token read once; never logged or written
    let token = std::env::var("KB_SCAN_QUERY_TOKEN").ok().filter(|t| !t.is_empty());
    if token.is_some() {
        eprintln!("kb-scan: serve requires Authorization: Bearer <KB_SCAN_QUERY_TOKEN>");
    }
    loop {
        match listener.accept() {
            Ok((stream, _peer)) => {
                let out = out_dir.clone();
                let tok = token.clone();
                // one thread per connection; handle dropped at scope end bounds lifetime
                std::thread::spawn(move || handle_conn(stream, &out, tok.as_deref()));
            }
            Err(e) => {
                eprintln!("kb-scan serve: accept error: {}", e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_report() -> Value {
        json::parse(
            r#"{"schema":"kb-scan-report/1","findings":[
                {"tier":1,"id":"MAL-1","summary":"malicious package installed","package":"npm:evil@1.0.0"},
                {"tier":2,"id":"CVE-2026-1","summary":"exploited bug in Exchange","product":"Microsoft Exchange Server"},
                {"tier":4,"id":"GHSA-x","summary":"low sev","package":"npm:x@1"},
                {"tier":4,"id":"lead-1","summary":"unverified lead","source":"explore","status":"unverified"}],
                "stats":{"packages":2,"cves":1,"findings":4,"errors":[]}}"#,
        )
        .unwrap()
    }

    #[test]
    fn filter_tier_keeps_schema_and_tier() {
        let text = json::to_compact(&sample_report());
        let out = filter_tier(&text, 2).unwrap();
        let v = json::parse(&out).unwrap();
        assert_eq!(v.get("schema").and_then(|s| s.as_str()), Some("kb-scan-report/1"));
        let f = v.get("findings").and_then(|x| x.as_array()).unwrap();
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].get("id").and_then(|i| i.as_str()), Some("CVE-2026-1"));
        assert_eq!(v.get("stats").and_then(|s| s.get("findings")).and_then(|x| x.as_u64()), Some(1));
    }

    #[test]
    fn brief_within_budget_and_has_closer() {
        let sync = json::parse(r#"{"attention":["origin/knowledge moved abc..def: rebase before relying on ingested pages"]}"#).unwrap();
        let brief = render_brief(&sample_report(), Some(&sync));
        assert!(word_count(&brief) <= BRIEF_MAX_WORDS, "brief has {} words: {}", word_count(&brief), brief);
        assert!(brief.contains(BRIEF_CLOSER));
        assert!(brief.contains("CVE-2026-1"));
        assert!(!brief.contains("GHSA-x")); // tier 4 excluded
        assert!(!brief.contains("lead-1")); // unverified excluded
    }

    #[test]
    fn token_compare() {
        assert!(token_eq(b"abc", b"abc"));
        assert!(!token_eq(b"abc", b"abd"));
        assert!(!token_eq(b"abc", b"abcd"));
        assert!(is_authorized("Host: x\r\nAuthorization: Bearer sekrit\r\n", "sekrit"));
        assert!(!is_authorized("Host: x\r\nAuthorization: Bearer wrong\r\n", "sekrit"));
        assert!(!is_authorized("Host: x\r\n", "sekrit"));
    }
}
