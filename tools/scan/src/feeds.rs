//! Live feed queries. Every request goes through http.rs (curl argv, https
//! allowlist, timeouts, caps). Feed payloads are parsed with the strict JSON
//! parser and all text is sanitised before it enters a report.

use crate::config::{Config, Inventory, Package};
use crate::http::{self, Response};
use crate::json::{self, Value};
use crate::sanitize::sanitize;
use crate::triage;
use crate::url;
use std::collections::{HashMap, HashSet};

pub const KEV_URL: &str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
pub const OSV_QUERY_URL: &str = "https://api.osv.dev/v1/query";
pub const OSV_BATCH_URL: &str = "https://api.osv.dev/v1/querybatch";
pub const GITHUB_ADVISORIES_URL: &str = "https://api.github.com/advisories";
pub const EPSS_URL: &str = "https://api.first.org/data/v1/epss";
pub const NVD_URL: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";

/// OSV querybatch chunk cap (pinned: <= 1000 queries per request).
pub const OSV_BATCH_CHUNK: usize = 1000;
/// Cap on how many CVEs we ask EPSS about per scan, to bound request count.
pub const MAX_EPSS_LOOKUPS: usize = 100;
/// Cap on GitHub advisory lookups per scan.
pub const MAX_GITHUB_LOOKUPS: usize = 200;

#[derive(Clone, Debug)]
pub struct FeedStatus {
    pub name: &'static str,
    pub status: String,
    pub detail: Option<String>,
    pub entries: usize,
}

impl FeedStatus {
    pub fn to_json(&self) -> Value {
        let mut m = vec![
            ("name".to_string(), Value::str(self.name)),
            ("status".to_string(), Value::str(&self.status)),
        ];
        if let Some(d) = &self.detail {
            m.push(("detail".to_string(), Value::str(sanitize(d))));
        }
        m.push(("entries".to_string(), Value::num(self.entries.to_string())));
        Value::obj(m)
    }
}

#[derive(Clone, Debug)]
pub struct Finding {
    pub kind: &'static str, // kev | osv | github | epss | nvd
    pub id: String,
    pub package: Option<String>,
    /// lockfile/repo path from the inventory entry, when present
    pub inventory_source: Option<String>,
    pub product: Option<String>,
    pub cve: Option<String>,
    pub summary: String,
    pub source: String,
    pub is_malware: bool,
    pub high_severity: bool,
    pub epss: Option<f64>,
    pub kev_date_added: Option<String>,
}

impl Finding {
    /// Compute tier + playbook now that KEV/EPSS context is known.
    pub fn finalize(&self, kev_cves: &HashSet<String>, epss_threshold: f64) -> (u8, &'static str) {
        let in_kev = self.cve.as_ref().map(|c| kev_cves.contains(c)).unwrap_or(false);
        let tier = triage::tier_for(self.is_malware, in_kev, self.high_severity, self.epss, epss_threshold);
        let is_package = self.package.is_some();
        (tier, triage::playbook_for(tier, is_package))
    }

    pub fn to_json(&self, kev_cves: &HashSet<String>, epss_threshold: f64) -> Value {
        let (tier, playbook) = self.finalize(kev_cves, epss_threshold);
        let mut m = vec![
            ("tier".to_string(), Value::num(tier.to_string())),
            ("kind".to_string(), Value::str(self.kind)),
            ("id".to_string(), Value::str(&self.id)),
        ];
        if let Some(p) = &self.package {
            m.push(("package".to_string(), Value::str(p)));
        }
        if let Some(s) = &self.inventory_source {
            m.push(("inventory_source".to_string(), Value::str(s)));
        }
        if let Some(p) = &self.product {
            m.push(("product".to_string(), Value::str(p)));
        }
        if let Some(c) = &self.cve {
            m.push(("cve".to_string(), Value::str(c)));
        }
        m.push(("summary".to_string(), Value::str(&self.summary)));
        m.push(("source".to_string(), Value::str(&self.source)));
        if let Some(e) = self.epss {
            m.push(("epss".to_string(), Value::num(format!("{:.6}", e))));
        }
        if let Some(d) = &self.kev_date_added {
            m.push(("kev_date_added".to_string(), Value::str(d)));
        }
        m.push(("playbook".to_string(), Value::str(playbook)));
        Value::obj(m)
    }
}

pub struct KevEntry {
    pub cve: String,
    pub vendor: String,
    pub product: String,
    pub name: String,
    pub description: String,
    pub date_added: String,
}

fn parse_json_body(resp: &Response, feed: &str) -> Result<Value, String> {
    if resp.truncated {
        return Err(format!("{}: response exceeded read cap and was truncated", feed));
    }
    if resp.status == 0 {
        return Err(format!("{}: curl failed (exit {:?}): {}", feed, resp.curl_code, resp.curl_stderr.trim()));
    }
    if !(200..300).contains(&resp.status) {
        return Err(format!("{}: HTTP {}", feed, resp.status));
    }
    json::parse(resp.body_str()).map_err(|e| format!("{}: invalid JSON: {}", feed, e))
}

/// CISA KEV: one GET, full catalog.
pub fn fetch_kev(cfg: &Config) -> (Vec<KevEntry>, FeedStatus, Option<String>) {
    let name = "kev";
    match http::get(KEV_URL, cfg.http_timeout_secs, cfg.max_body_bytes) {
        Err(e) => (
            Vec::new(),
            FeedStatus { name, status: "error".into(), detail: Some(e.clone()), entries: 0 },
            Some(e),
        ),
        Ok(resp) => match parse_json_body(&resp, name) {
            Err(e) => (
                Vec::new(),
                FeedStatus { name, status: "error".into(), detail: Some(e.clone()), entries: 0 },
                Some(e),
            ),
            Ok(v) => {
                let mut entries = Vec::new();
                if let Some(catalog) = v.get("vulnerabilities").and_then(|x| x.as_array()) {
                    for e in catalog {
                        entries.push(KevEntry {
                            cve: e.get("cveID").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                            vendor: sanitize(e.get("vendorProject").and_then(|x| x.as_str()).unwrap_or("")),
                            product: sanitize(e.get("product").and_then(|x| x.as_str()).unwrap_or("")),
                            name: sanitize(e.get("vulnerabilityName").and_then(|x| x.as_str()).unwrap_or("")),
                            description: sanitize(e.get("shortDescription").and_then(|x| x.as_str()).unwrap_or("")),
                            date_added: e.get("dateAdded").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                        });
                    }
                }
                let n = entries.len();
                (entries, FeedStatus { name, status: "ok".into(), detail: None, entries: n }, None)
            }
        },
    }
}

fn osv_query_body(packages: &[Package]) -> String {
    let queries: Vec<Value> = packages
        .iter()
        .map(|p| {
            Value::obj(vec![
                (
                    "package".to_string(),
                    Value::obj(vec![
                        ("name".to_string(), Value::str(&p.name)),
                        ("ecosystem".to_string(), Value::str(&p.ecosystem)),
                    ]),
                ),
                ("version".to_string(), Value::str(&p.version)),
            ])
        })
        .collect();
    json::to_compact(&Value::obj(vec![("queries".to_string(), Value::arr(queries))]))
}

fn osv_single_body(p: &Package) -> String {
    json::to_compact(&Value::obj(vec![
        (
            "package".to_string(),
            Value::obj(vec![
                ("name".to_string(), Value::str(&p.name)),
                ("ecosystem".to_string(), Value::str(&p.ecosystem)),
            ]),
        ),
        ("version".to_string(), Value::str(&p.version)),
    ]))
}

fn osv_findings_from_vuln(v: &Value, pkg: &Package, out: &mut Vec<Finding>) {
    let id = v.get("id").and_then(|x| x.as_str()).unwrap_or("").to_string();
    if id.is_empty() {
        return;
    }
    let summary = sanitize(
        v.get("summary")
            .and_then(|x| x.as_str())
            .unwrap_or_else(|| v.get("details").and_then(|x| x.as_str()).unwrap_or("")),
    );
    let is_mal = triage::is_mal_id(&id);
    let sev = v
        .get("database_specific")
        .and_then(|d| d.get("severity"))
        .and_then(|x| x.as_str())
        .unwrap_or("");
    let high = triage::is_high_severity(sev);
    let cve = v
        .get("aliases")
        .and_then(|a| a.as_array())
        .and_then(|arr| arr.iter().find_map(|a| a.as_str().filter(|s| s.starts_with("CVE-"))))
        .map(|s| s.to_string());
    out.push(Finding {
        kind: "osv",
        id,
        package: Some(format!("{}:{}@{}", pkg.ecosystem, pkg.name, pkg.version)),
        inventory_source: pkg.source.clone(),
        product: None,
        cve,
        summary,
        source: OSV_QUERY_URL.to_string(),
        is_malware: is_mal,
        high_severity: high,
        epss: None,
        kev_date_added: None,
    });
}

/// OSV: querybatch POST (chunks <= 1000, body piped via stdin); a single
/// package uses the single-query endpoint.
pub fn query_osv(cfg: &Config, packages: &[Package]) -> (Vec<Finding>, FeedStatus, Option<String>) {
    let name = "osv";
    if packages.is_empty() {
        return (Vec::new(), FeedStatus { name, status: "skipped".into(), detail: Some("no packages in inventory".into()), entries: 0 }, None);
    }
    let mut findings = Vec::new();
    let mut entries = 0usize;
    let mut error: Option<String> = None;
    if packages.len() == 1 {
        let body = osv_single_body(&packages[0]);
        match http::post_json(OSV_QUERY_URL, body.as_bytes(), cfg.http_timeout_secs, cfg.max_body_bytes) {
            Err(e) => error = Some(e),
            Ok(resp) => match parse_json_body(&resp, name) {
                Err(e) => error = Some(e),
                Ok(v) => {
                    if let Some(vulns) = v.get("vulns").and_then(|x| x.as_array()) {
                        entries = vulns.len();
                        for vuln in vulns {
                            osv_findings_from_vuln(vuln, &packages[0], &mut findings);
                        }
                    }
                }
            },
        }
    } else {
        for chunk in packages.chunks(OSV_BATCH_CHUNK) {
            let body = osv_query_body(chunk);
            match http::post_json(OSV_BATCH_URL, body.as_bytes(), cfg.http_timeout_secs, cfg.max_body_bytes) {
                Err(e) => {
                    error = Some(e);
                    break;
                }
                Ok(resp) => match parse_json_body(&resp, name) {
                    Err(e) => {
                        error = Some(e);
                        break;
                    }
                    Ok(v) => {
                        if let Some(results) = v.get("results").and_then(|x| x.as_array()) {
                            for (i, r) in results.iter().enumerate() {
                                let pkg = &chunk[i.min(chunk.len() - 1)];
                                if let Some(vulns) = r.get("vulns").and_then(|x| x.as_array()) {
                                    entries += vulns.len();
                                    for vuln in vulns {
                                        osv_findings_from_vuln(vuln, pkg, &mut findings);
                                    }
                                }
                            }
                        }
                    }
                },
            }
        }
    }
    let status = if error.is_some() { "error" } else { "ok" };
    (
        findings,
        FeedStatus { name, status: status.into(), detail: error.clone(), entries },
        error,
    )
}

/// Map an OSV ecosystem name to the GitHub Advisory Database ecosystem param.
pub fn github_ecosystem(osv_ecosystem: &str) -> String {
    match osv_ecosystem {
        "npm" => "npm",
        "PyPI" => "pip",
        "crates.io" => "cargo",
        "Go" => "go",
        "Maven" => "maven",
        "RubyGems" => "rubygems",
        "NuGet" => "nuget",
        "Packagist" => "composer",
        "Pub" => "pub",
        "Hex" => "hex",
        other => other,
    }
    .to_string()
}

/// GitHub Advisory Database: one GET per package. 403 / 429 / rate-limit
/// bodies are handled gracefully: the feed is marked rate-limited and the
/// remaining lookups are skipped (partial results are still reported).
pub fn query_github(cfg: &Config, packages: &[Package]) -> (Vec<Finding>, FeedStatus, Option<String>) {
    let name = "github";
    let mut findings = Vec::new();
    let mut entries = 0usize;
    let mut rate_limited = false;
    let mut error: Option<String> = None;
    for pkg in packages.iter().take(MAX_GITHUB_LOOKUPS) {
        if rate_limited {
            break;
        }
        let eco = github_ecosystem(&pkg.ecosystem);
        let url = match url::build_url(
            GITHUB_ADVISORIES_URL,
            &[
                ("ecosystem".to_string(), eco),
                ("affects".to_string(), format!("{}@{}", pkg.name, pkg.version)),
            ],
        ) {
            Ok(u) => u,
            Err(e) => {
                error = Some(e);
                break;
            }
        };
        match http::get(&url, cfg.http_timeout_secs, cfg.max_body_bytes) {
            Err(e) => {
                error = Some(e);
                break;
            }
            Ok(resp) => {
                if resp.status == 403 || resp.status == 429 {
                    rate_limited = true;
                    error = Some(format!("HTTP {} (rate limit or forbidden) for package {}", resp.status, pkg.name));
                    break;
                }
                match parse_json_body(&resp, name) {
                    Err(e) => {
                        if resp.body_str().contains("rate limit") {
                            rate_limited = true;
                            error = Some("GitHub API rate limit exceeded".to_string());
                        } else {
                            error = Some(e);
                        }
                        break;
                    }
                    Ok(v) => {
                        if let Some(arr) = v.as_array() {
                            entries += arr.len();
                            for a in arr {
                                let ghsa = a.get("ghsa_id").and_then(|x| x.as_str()).unwrap_or("").to_string();
                                if ghsa.is_empty() {
                                    continue;
                                }
                                let atype = a.get("type").and_then(|x| x.as_str()).unwrap_or("reviewed");
                                let is_mal = atype == "malware";
                                let severity = a.get("severity").and_then(|x| x.as_str()).unwrap_or("");
                                let cve = a
                                    .get("cve_id")
                                    .and_then(|x| x.as_str())
                                    .filter(|s| !s.is_empty())
                                    .map(|s| s.to_string());
                                findings.push(Finding {
                                    kind: "github",
                                    id: ghsa,
                                    package: Some(format!("{}:{}@{}", pkg.ecosystem, pkg.name, pkg.version)),
                                    inventory_source: pkg.source.clone(),
                                    product: None,
                                    cve,
                                    summary: sanitize(a.get("summary").and_then(|x| x.as_str()).unwrap_or("")),
                                    source: url.clone(),
                                    is_malware: is_mal,
                                    high_severity: triage::is_high_severity(severity),
                                    epss: None,
                                    kev_date_added: None,
                                });
                            }
                        }
                    }
                }
            }
        }
    }
    let status = if rate_limited {
        "rate-limited"
    } else if error.is_some() {
        "error"
    } else {
        "ok"
    };
    (
        findings,
        FeedStatus { name, status: status.into(), detail: error.clone(), entries },
        error,
    )
}

/// EPSS: one GET per CVE, bounded by MAX_EPSS_LOOKUPS.
pub fn query_epss(cfg: &Config, cves: &[String]) -> (HashMap<String, f64>, FeedStatus, Option<String>) {
    let name = "epss";
    let mut map = HashMap::new();
    let mut error: Option<String> = None;
    let mut entries = 0usize;
    for cve in cves.iter().take(MAX_EPSS_LOOKUPS) {
        let url = match url::build_url(EPSS_URL, &[("cve".to_string(), cve.clone())]) {
            Ok(u) => u,
            Err(e) => {
                error = Some(e);
                break;
            }
        };
        match http::get(&url, cfg.http_timeout_secs, cfg.max_body_bytes) {
            Err(e) => {
                error = Some(e);
                break;
            }
            Ok(resp) => match parse_json_body(&resp, name) {
                Err(e) => {
                    error = Some(e);
                    break;
                }
                Ok(v) => {
                    if let Some(data) = v.get("data").and_then(|x| x.as_array()) {
                        for d in data {
                            if let Some(c) = d.get("cve").and_then(|x| x.as_str()) {
                                if let Some(e) = d.get("epss").and_then(|x| x.as_str()).and_then(|s| s.parse::<f64>().ok()) {
                                    map.insert(c.to_string(), e);
                                    entries += 1;
                                }
                            }
                        }
                    }
                }
            },
        }
    }
    let status = if error.is_some() { "error" } else { "ok" };
    (map, FeedStatus { name, status: status.into(), detail: error.clone(), entries }, error)
}

/// NVD (optional, default off): one GET per inventory CVE.
pub fn query_nvd(cfg: &Config, cves: &[String]) -> (Vec<Finding>, FeedStatus, Option<String>) {
    let name = "nvd";
    let mut findings = Vec::new();
    let mut error: Option<String> = None;
    let mut entries = 0usize;
    for cve in cves.iter().take(MAX_EPSS_LOOKUPS) {
        let url = match url::build_url(NVD_URL, &[("cveId".to_string(), cve.clone())]) {
            Ok(u) => u,
            Err(e) => {
                error = Some(e);
                break;
            }
        };
        match http::get(&url, cfg.http_timeout_secs, cfg.max_body_bytes) {
            Err(e) => {
                error = Some(e);
                break;
            }
            Ok(resp) => {
                if resp.status == 403 || resp.status == 404 {
                    continue; // NVD throttles/404s individual CVEs; keep going
                }
                match parse_json_body(&resp, name) {
                    Err(e) => {
                        error = Some(e);
                        break;
                    }
                    Ok(v) => {
                        if let Some(vulns) = v.get("vulnerabilities").and_then(|x| x.as_array()) {
                            for item in vulns {
                                if let Some(c) = item.get("cve") {
                                    entries += 1;
                                    let id = c.get("id").and_then(|x| x.as_str()).unwrap_or(cve).to_string();
                                    let desc = c
                                        .get("descriptions")
                                        .and_then(|d| d.as_array())
                                        .and_then(|arr| arr.iter().find_map(|d| d.get("value").and_then(|x| x.as_str())))
                                        .unwrap_or("");
                                    let high = c
                                        .get("metrics")
                                        .map(|m| {
                                            json::to_compact(m).to_ascii_lowercase().contains("\"high\"")
                                                || json::to_compact(m).to_ascii_lowercase().contains("\"critical\"")
                                        })
                                        .unwrap_or(false);
                                    findings.push(Finding {
                                        kind: "nvd",
                                        id,
                                        package: None,
                                        inventory_source: None,
                                        product: None,
                                        cve: Some(cve.clone()),
                                        summary: sanitize(desc),
                                        source: url.clone(),
                                        is_malware: false,
                                        high_severity: high,
                                        epss: None,
                                        kev_date_added: None,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    let status = if error.is_some() { "error" } else { "ok" };
    (
        findings,
        FeedStatus { name, status: status.into(), detail: error.clone(), entries },
        error,
    )
}

/// Inventory matching helpers.
pub fn product_matches_kev(inv: &Inventory, kev: &KevEntry) -> bool {
    inv.products.iter().any(|p| {
        p.vendor.eq_ignore_ascii_case(&kev.vendor) && p.product.eq_ignore_ascii_case(&kev.product)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn osv_batch_body_shape_and_chunk_cap() {
        let pkgs: Vec<Package> = (0..5)
            .map(|i| Package { ecosystem: "npm".into(), name: format!("p{}", i), version: "1.0.0".into(), source: None })
            .collect();
        let body = osv_query_body(&pkgs);
        let v = json::parse(&body).unwrap();
        let q = v.get("queries").and_then(|x| x.as_array()).unwrap();
        assert_eq!(q.len(), 5);
        assert!(OSV_BATCH_CHUNK <= 1000);
        let single = osv_single_body(&pkgs[0]);
        let sv = json::parse(&single).unwrap();
        assert!(sv.get("queries").is_none());
        assert_eq!(sv.get("version").and_then(|x| x.as_str()), Some("1.0.0"));
    }

    #[test]
    fn github_ecosystem_mapping() {
        assert_eq!(github_ecosystem("npm"), "npm");
        assert_eq!(github_ecosystem("PyPI"), "pip");
        assert_eq!(github_ecosystem("crates.io"), "cargo");
        assert_eq!(github_ecosystem("Go"), "go");
    }

    #[test]
    fn osv_vuln_to_finding_mal_and_cve() {
        let pkg = Package { ecosystem: "npm".into(), name: "evil".into(), version: "1.0.0".into(), source: None };
        let vuln = json::parse(r#"{"id":"MAL-2026-1","summary":"bad  pkg","aliases":["CVE-2026-1"],"database_specific":{"severity":"CRITICAL"}}"#).unwrap();
        let mut out = Vec::new();
        osv_findings_from_vuln(&vuln, &pkg, &mut out);
        assert_eq!(out.len(), 1);
        assert!(out[0].is_malware);
        assert!(out[0].high_severity);
        assert_eq!(out[0].cve.as_deref(), Some("CVE-2026-1"));
        assert_eq!(out[0].summary, "bad pkg");
    }

    #[test]
    fn finding_carries_inventory_source_when_present() {
        use std::collections::HashSet;
        let kev: HashSet<String> = HashSet::new();
        // with source: emitted in JSON
        let pkg = Package { ecosystem: "npm".into(), name: "lodash".into(), version: "4.17.20".into(), source: Some("frontend/package-lock.json".into()) };
        let vuln = json::parse(r#"{"id":"GHSA-x","summary":"s","database_specific":{"severity":"HIGH"}}"#).unwrap();
        let mut out = Vec::new();
        osv_findings_from_vuln(&vuln, &pkg, &mut out);
        assert_eq!(out[0].inventory_source.as_deref(), Some("frontend/package-lock.json"));
        let j = out[0].to_json(&kev, 0.5);
        assert_eq!(j.get("inventory_source").and_then(|v| v.as_str()), Some("frontend/package-lock.json"));
        // without source: field absent
        let pkg2 = Package { source: None, ..pkg.clone() };
        let mut out2 = Vec::new();
        osv_findings_from_vuln(&vuln, &pkg2, &mut out2);
        let j2 = out2[0].to_json(&kev, 0.5);
        assert!(j2.get("inventory_source").is_none());
    }
}
