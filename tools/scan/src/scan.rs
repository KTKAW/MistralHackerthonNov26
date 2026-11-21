//! One scan pass: query the enabled feeds against the inventory, rank
//! findings by the triage order, and build the kb-scan-report/1 document.

use crate::config::{Config, Inventory};
use crate::date;
use crate::feeds::{self, FeedStatus, Finding};
use crate::json::Value;
use crate::sanitize::sanitize;
use std::collections::{HashMap, HashSet};

pub struct ScanOutcome {
    pub report: Value,
    pub had_errors: bool,
}

pub fn run_scan(cfg: &Config, inv: &Inventory) -> ScanOutcome {
    let generated_at = date::rfc3339_utc(date::now_secs());
    let mut statuses: Vec<FeedStatus> = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    let mut findings: Vec<Finding> = Vec::new();

    // --- CISA KEV -----------------------------------------------------------
    let mut kev_cves: HashSet<String> = HashSet::new();
    let mut kev_dates: HashMap<String, String> = HashMap::new();
    if cfg.feeds.kev {
        let (entries, status, err) = feeds::fetch_kev(cfg);
        if let Some(e) = err {
            errors.push(e);
        }
        let today = date::now_secs().div_euclid(86_400);
        let mut recent = 0usize;
        for e in &entries {
            if !e.cve.is_empty() {
                kev_cves.insert(e.cve.clone());
                kev_dates.insert(e.cve.clone(), e.date_added.clone());
            }
            if let Some(d) = date::parse_ymd(&e.date_added) {
                if today - d <= cfg.kev_recent_days as i64 && today >= d {
                    recent += 1;
                }
            }
            // inventory match: CVE listed, or vendor/product pair
            let cve_hit = !e.cve.is_empty() && inv.cves.iter().any(|c| c == &e.cve);
            let prod_hit = feeds::product_matches_kev(inv, e);
            if cve_hit || prod_hit {
                let summary = if !e.name.is_empty() {
                    format!("{} — {}", e.name, e.description)
                } else {
                    e.description.clone()
                };
                findings.push(Finding {
                    kind: "kev",
                    id: e.cve.clone(),
                    package: None,
                    inventory_source: None,
                    product: if prod_hit && !cve_hit {
                        Some(format!("{} {}", e.vendor, e.product))
                    } else {
                        None
                    },
                    cve: if e.cve.is_empty() { None } else { Some(e.cve.clone()) },
                    summary: sanitize(&summary),
                    source: feeds::KEV_URL.to_string(),
                    is_malware: false,
                    high_severity: true, // KEV = actively exploited
                    epss: None,
                    kev_date_added: if e.date_added.is_empty() { None } else { Some(e.date_added.clone()) },
                });
            }
        }
        let mut status = status;
        if recent > 0 && status.detail.is_none() {
            status.detail = Some(format!("{} entries added in the last {} days", recent, cfg.kev_recent_days));
        }
        statuses.push(status);
    }

    // --- OSV -----------------------------------------------------------------
    if cfg.feeds.osv {
        let (f, status, err) = feeds::query_osv(cfg, &inv.packages);
        if let Some(e) = err {
            errors.push(e);
        }
        findings.extend(f);
        statuses.push(status);
    }

    // --- GitHub Advisory Database --------------------------------------------
    if cfg.feeds.github {
        let (f, status, err) = feeds::query_github(cfg, &inv.packages);
        if let Some(e) = err {
            errors.push(e);
        }
        findings.extend(f);
        statuses.push(status);
    }

    // --- EPSS (for inventory CVEs + CVEs seen in findings) --------------------
    let mut epss_map: HashMap<String, f64> = HashMap::new();
    if cfg.feeds.epss {
        let mut cves: Vec<String> = inv.cves.clone();
        for f in &findings {
            if let Some(c) = &f.cve {
                if !cves.contains(c) {
                    cves.push(c.clone());
                }
            }
        }
        cves.sort();
        cves.dedup();
        let (map, status, err) = feeds::query_epss(cfg, &cves);
        if let Some(e) = err {
            errors.push(e);
        }
        epss_map = map;
        statuses.push(status);
    }

    // attach EPSS scores + KEV dates to findings
    for f in findings.iter_mut() {
        if let Some(c) = &f.cve {
            if let Some(e) = epss_map.get(c) {
                f.epss = Some(*e);
            }
            if f.kev_date_added.is_none() {
                if let Some(d) = kev_dates.get(c) {
                    f.kev_date_added = Some(d.clone());
                }
            }
        }
    }

    // --- NVD (optional, default off) ------------------------------------------
    if cfg.feeds.nvd {
        let (f, status, err) = feeds::query_nvd(cfg, &inv.cves);
        if let Some(e) = err {
            errors.push(e);
        }
        findings.extend(f);
        statuses.push(status);
    }

    // --- dedup + rank ----------------------------------------------------------
    let mut seen: HashSet<String> = HashSet::new();
    findings.retain(|f| {
        let key = format!("{}|{}|{}|{}", f.kind, f.id, f.package.as_deref().unwrap_or(""), f.cve.as_deref().unwrap_or(""));
        seen.insert(key)
    });
    let mut ranked: Vec<(u8, &Finding)> = findings
        .iter()
        .map(|f| {
            let (tier, _) = f.finalize(&kev_cves, cfg.epss_threshold);
            (tier, f)
        })
        .collect();
    ranked.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.id.cmp(&b.1.id)));

    let findings_v: Vec<Value> = ranked
        .iter()
        .map(|(_, f)| f.to_json(&kev_cves, cfg.epss_threshold))
        .collect();

    let report = Value::obj(vec![
        ("schema".to_string(), Value::str("kb-scan-report/1")),
        ("generated_at".to_string(), Value::str(generated_at)),
        (
            "engine".to_string(),
            Value::obj(vec![
                ("name".to_string(), Value::str("kb-scan")),
                ("version".to_string(), Value::str(env!("CARGO_PKG_VERSION"))),
                ("static_musl".to_string(), Value::bool(cfg!(target_env = "musl"))),
            ]),
        ),
        (
            "feeds".to_string(),
            Value::arr(statuses.iter().map(|s| s.to_json()).collect()),
        ),
        ("findings".to_string(), Value::arr(findings_v)),
        (
            "stats".to_string(),
            Value::obj(vec![
                ("packages".to_string(), Value::num(inv.packages.len().to_string())),
                ("cves".to_string(), Value::num(inv.cves.len().to_string())),
                ("findings".to_string(), Value::num(findings.len().to_string())),
                (
                    "errors".to_string(),
                    Value::arr(errors.iter().map(|e| Value::str(sanitize(e))).collect()),
                ),
            ]),
        ),
    ]);
    ScanOutcome { report, had_errors: !errors.is_empty() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Package;

    fn sample_inventory() -> Inventory {
        Inventory {
            packages: vec![Package { ecosystem: "npm".into(), name: "lodash".into(), version: "4.17.20".into(), source: None }],
            products: vec![],
            cves: vec!["CVE-2021-44228".to_string()],
        }
    }

    #[test]
    fn report_schema_shape_offline() {
        // all feeds disabled -> no network, deterministic report
        let mut cfg = Config::default();
        cfg.feeds = crate::config::FeedToggles { kev: false, osv: false, github: false, epss: false, nvd: false };
        let out = run_scan(&cfg, &sample_inventory());
        assert_eq!(out.report.get("schema").and_then(|v| v.as_str()), Some("kb-scan-report/1"));
        assert_eq!(
            out.report.get("engine").and_then(|e| e.get("name")).and_then(|v| v.as_str()),
            Some("kb-scan")
        );
        let stats = out.report.get("stats").unwrap();
        assert_eq!(stats.get("packages").and_then(|v| v.as_u64()), Some(1));
        assert_eq!(stats.get("cves").and_then(|v| v.as_u64()), Some(1));
        assert!(!out.had_errors);
    }

    #[test]
    fn findings_sorted_by_tier() {
        let mut cfg = Config::default();
        cfg.feeds = crate::config::FeedToggles { kev: false, osv: false, github: false, epss: false, nvd: false };
        let out = run_scan(&cfg, &sample_inventory());
        let arr = out.report.get("findings").and_then(|v| v.as_array()).unwrap();
        let tiers: Vec<u64> = arr.iter().filter_map(|f| f.get("tier").and_then(|t| t.as_u64())).collect();
        let mut sorted = tiers.clone();
        sorted.sort();
        assert_eq!(tiers, sorted);
    }
}
