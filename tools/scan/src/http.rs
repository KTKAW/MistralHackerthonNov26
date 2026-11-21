//! HTTP egress, exclusively through the `curl` binary invoked as an argv
//! array (never a shell). https only (enforced both by curl `--proto` and by
//! the compiled-in host allowlist in url.rs), no redirect following, timeouts,
//! --max-filesize, capped stdout/stderr. An optional GITHUB_TOKEN is forwarded
//! as a single `-H` argv element and is never logged, stored or printed.

use crate::proc::{run_capped, CappedOutput};
use crate::url;

pub const CONNECT_TIMEOUT_SECS: u64 = 10;
/// Read cap for a response body (slightly above --max-filesize allowance).
pub const MAX_READ_BYTES: usize = 16 * 1024 * 1024;

pub struct Response {
    /// HTTP status code (0 if curl failed before any response).
    pub status: u16,
    pub body: Vec<u8>,
    /// true when the body hit the read cap and was truncated (and curl killed)
    pub truncated: bool,
    pub curl_code: Option<i32>,
    pub curl_stderr: String,
}

impl Response {
    pub fn body_str(&self) -> &str {
        std::str::from_utf8(&self.body).unwrap_or("")
    }
    #[allow(dead_code)]
    pub fn ok(&self) -> bool {
        (200..300).contains(&self.status) && !self.truncated
    }
}

/// Read GITHUB_TOKEN from the environment. The value is only ever passed to
/// curl as one argv element; it is never logged or written anywhere.
fn github_token() -> Option<String> {
    std::env::var("GITHUB_TOKEN").ok().filter(|t| !t.is_empty())
}

fn base_args(timeout_secs: u64, max_filesize: usize) -> Vec<String> {
    let mut a = vec![
        // -q must be first: ignore any ~/.curlrc
        "-q".to_string(),
        "--silent".to_string(),
        "--show-error".to_string(),
        // https only, enforced by curl itself
        "--proto".to_string(),
        "-all,https".to_string(),
        "--max-time".to_string(),
        timeout_secs.to_string(),
        "--connect-timeout".to_string(),
        CONNECT_TIMEOUT_SECS.to_string(),
        "--max-filesize".to_string(),
        max_filesize.to_string(),
        // no redirects: -L/--location is deliberately never passed
        "--user-agent".to_string(),
        "kb-scan/0.1.0".to_string(),
        // append "\n<http_code>" to stdout so the caller can split it off
        "-w".to_string(),
        "\n%{http_code}".to_string(),
    ];
    if let Some(token) = github_token() {
        // one single argv element; never logged
        a.push("-H".to_string());
        a.push(format!("Authorization: Bearer {}", token));
    }
    a
}

fn run(url: &str, extra: &[String], body: Option<&[u8]>, timeout_secs: u64, max_filesize: usize, max_read: usize) -> Result<Response, String> {
    url::check_url(url)?;
    let mut args = base_args(timeout_secs, max_filesize);
    args.extend_from_slice(extra);
    args.push(url.to_string());
    // NOTE: argv (including any -H header) is never printed or logged.
    let out: CappedOutput = run_capped("curl", &args, body, max_read)
        .map_err(|e| format!("failed to spawn curl: {}", e))?;
    Ok(split_response(out))
}

fn split_response(out: CappedOutput) -> Response {
    // stdout = body + "\n" + 3-digit code appended by -w
    let mut split_at = out.stdout.len();
    let mut status: u16 = 0;
    if let Some(idx) = out.stdout.iter().rposition(|&b| b == b'\n') {
        let tail = &out.stdout[idx + 1..];
        if tail.len() == 3 && tail.iter().all(|b| b.is_ascii_digit()) {
            if let Ok(code) = std::str::from_utf8(tail).unwrap_or("0").parse::<u16>() {
                status = code;
                split_at = idx;
            }
        }
    }
    let body = out.stdout[..split_at].to_vec();
    Response {
        status,
        body,
        truncated: out.stdout_truncated,
        curl_code: out.code,
        curl_stderr: out.stderr,
    }
}

/// HTTPS GET. `url` must pass the allowlist check.
pub fn get(url: &str, timeout_secs: u64, max_filesize: usize) -> Result<Response, String> {
    run(url, &[], None, timeout_secs, max_filesize, MAX_READ_BYTES)
}

/// HTTPS POST with a JSON body piped over stdin (`--data-binary @-`).
pub fn post_json(url: &str, body: &[u8], timeout_secs: u64, max_filesize: usize) -> Result<Response, String> {
    let extra = [
        "--request".to_string(),
        "POST".to_string(),
        "--header".to_string(),
        "Content-Type: application/json".to_string(),
        "--header".to_string(),
        "Accept: application/json".to_string(),
        "--data-binary".to_string(),
        "@-".to_string(),
    ];
    run(url, &extra, Some(body), timeout_secs, max_filesize, MAX_READ_BYTES)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake(body: &[u8], code: &str) -> CappedOutput {
        let mut stdout = body.to_vec();
        stdout.push(b'\n');
        stdout.extend_from_slice(code.as_bytes());
        CappedOutput {
            stdout,
            stdout_truncated: false,
            stderr: String::new(),
            code: Some(0),
        }
    }

    #[test]
    fn splits_status_code_from_body() {
        let r = split_response(fake(b"{\"ok\":true}", "200"));
        assert_eq!(r.status, 200);
        assert_eq!(r.body_str(), "{\"ok\":true}");
        assert!(r.ok());
    }

    #[test]
    fn handles_error_status_and_missing_code() {
        let r = split_response(fake(b"Forbidden", "403"));
        assert_eq!(r.status, 403);
        assert!(!r.ok());
        let r2 = split_response(fake(b"no code", "000"));
        assert_eq!(r2.status, 0);
    }

    #[test]
    fn rejects_non_allowlisted_url() {
        assert!(get("https://evil.com/", 10, 1024).is_err());
        assert!(get("http://api.osv.dev/v1/query", 10, 1024).is_err());
    }
}
