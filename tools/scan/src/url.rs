//! URL handling: percent-encoding of query components and a compiled-in
//! https-only host allowlist taken from feeds.md. No URL is ever built by
//! string concatenation of feed-derived text; only these allowlisted hosts
//! are contacted, and only over https.

/// Hosts the engine is allowed to contact (from feeds.md), exact match only.
pub const ALLOWED_HOSTS: &[&str] = &[
    "www.cisa.gov",
    "api.osv.dev",
    "api.github.com",
    "services.nvd.nist.gov",
    "api.first.org",
];

/// Exact host allowlist check.
pub fn host_allowed(host: &str) -> bool {
    ALLOWED_HOSTS.contains(&host)
}

/// Extract the host from an `https://` URL. Returns None for anything that
/// is not a plain https URL with no userinfo and no explicit port.
pub fn https_host(url: &str) -> Option<&str> {
    let rest = url.strip_prefix("https://")?;
    if rest.is_empty() || rest.starts_with('/') {
        return None;
    }
    let host_end = rest.find(|c| c == '/' || c == '?' || c == '#').unwrap_or(rest.len());
    let authority = &rest[..host_end];
    if authority.is_empty() || authority.contains('@') || authority.contains(':') {
        return None; // no userinfo, no port
    }
    Some(authority)
}

/// Validate a URL against the allowlist: must be https, host must exactly
/// match an allowlisted entry.
pub fn check_url(url: &str) -> Result<(), String> {
    match https_host(url) {
        None => Err(format!("not an https URL without userinfo/port: {:?}", url)),
        Some(host) if host_allowed(host) => Ok(()),
        Some(host) => Err(format!("host {:?} is not in the allowlist", host)),
    }
}

/// Percent-encode a query component. Only unreserved characters
/// (RFC 3986: A-Z a-z 0-9 - _ . ~) pass through; everything else, including
/// all UTF-8 bytes, becomes %XX with uppercase hex.
pub fn encode_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

/// Build a URL from an allowlisted base and percent-encoded query pairs.
/// Fails if the base is not allowlisted https.
pub fn build_url(base: &str, query: &[(String, String)]) -> Result<String, String> {
    check_url(base)?;
    if query.is_empty() {
        return Ok(base.to_string());
    }
    let mut url = String::from(base);
    url.push('?');
    for (i, (k, v)) in query.iter().enumerate() {
        if i > 0 {
            url.push('&');
        }
        url.push_str(&encode_component(k));
        url.push('=');
        url.push_str(&encode_component(v));
    }
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoder_passes_unreserved_only() {
        assert_eq!(encode_component("abcXYZ019-_.~"), "abcXYZ019-_.~");
        assert_eq!(encode_component("a b&c=d?e/f"), "a%20b%26c%3Dd%3Fe%2Ff");
        assert_eq!(encode_component("CVE-2021-44228"), "CVE-2021-44228");
        assert_eq!(encode_component("lodash@4.17.20"), "lodash%404.17.20");
        assert_eq!(encode_component("héllo"), "h%C3%A9llo");
    }

    #[test]
    fn allowlist_exact_match() {
        for h in ALLOWED_HOSTS {
            assert!(host_allowed(h));
        }
        assert!(!host_allowed("evil.com"));
        assert!(!host_allowed("api.osv.dev.evil.com"));
        assert!(!host_allowed("www.cisa.gov.evil.com"));
        assert!(!host_allowed("api.github.com."));
        assert!(!host_allowed(""));
        assert!(!host_allowed("API.OSV.DEV")); // case-sensitive exact match
    }

    #[test]
    fn check_url_rules() {
        assert!(check_url("https://api.osv.dev/v1/query").is_ok());
        assert!(check_url("https://api.osv.dev/v1/querybatch").is_ok());
        assert!(check_url("https://api.first.org/data/v1/epss?cve=CVE-2021-44228").is_ok());
        assert!(check_url("http://api.osv.dev/v1/query").is_err()); // http not allowed
        assert!(check_url("https://evil.com/").is_err());
        assert!(check_url("https://user@api.osv.dev/").is_err()); // userinfo
        assert!(check_url("https://api.osv.dev:8443/").is_err()); // port
        assert!(check_url("ftp://api.osv.dev/").is_err());
        assert!(check_url("https://api.osv.dev@evil.com/").is_err());
    }

    #[test]
    fn build_url_encodes_query() {
        let u = build_url(
            "https://api.github.com/advisories",
            &[("affects".into(), "lodash@4.17.20".into()), ("type".into(), "malware".into())],
        )
        .unwrap();
        assert_eq!(u, "https://api.github.com/advisories?affects=lodash%404.17.20&type=malware");
        assert!(build_url("https://evil.com/", &[]).is_err());
    }
}
