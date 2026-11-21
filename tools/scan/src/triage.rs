//! Triage tiers, following feeds.md "Order of triage":
//!   1 malware (MAL- ids / GitHub type=malware)   -> playbook malicious-dependency
//!   2 CVE in KEV touching the inventory         -> playbook exploited-vulnerability
//!   3 high/critical severity or EPSS >= threshold
//!   4 the rest
//! When the match is a library/package rather than a product, the playbook
//! is advisory-fleet-triage (the Le Chonk run).

/// Decide the tier for a finding.
pub fn tier_for(is_malware: bool, in_kev: bool, high_severity: bool, epss: Option<f64>, epss_threshold: f64) -> u8 {
    if is_malware {
        1
    } else if in_kev {
        2
    } else if high_severity || epss.map(|e| e >= epss_threshold).unwrap_or(false) {
        3
    } else {
        4
    }
}

/// Playbook for a finding. Tier-1 malware always routes to
/// malicious-dependency (precedence). Any package/library match routes to
/// advisory-fleet-triage (the Le Chonk run) at any tier. Product matches
/// follow the triage order: tier 2 (KEV) -> exploited-vulnerability.
pub fn playbook_for(tier: u8, is_package_match: bool) -> &'static str {
    if tier == 1 {
        return "malicious-dependency";
    }
    if is_package_match {
        return "advisory-fleet-triage";
    }
    match tier {
        2 => "exploited-vulnerability",
        _ => "advisory-fleet-triage",
    }
}

/// Is this advisory id a malware id? (OSV MAL-… or GitHub type=malware is
/// passed in separately as is_malware.)
pub fn is_mal_id(id: &str) -> bool {
    id.starts_with("MAL-")
}

/// Case-insensitive severity check for "high"/"critical".
pub fn is_high_severity(severity: &str) -> bool {
    let s = severity.to_ascii_lowercase();
    s.contains("critical") || s.contains("high")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tier_order() {
        assert_eq!(tier_for(true, true, true, Some(0.99), 0.5), 1); // malware wins
        assert_eq!(tier_for(false, true, false, None, 0.5), 2); // KEV next
        assert_eq!(tier_for(false, false, true, None, 0.5), 3); // high severity
        assert_eq!(tier_for(false, false, false, Some(0.5), 0.5), 3); // epss >= threshold
        assert_eq!(tier_for(false, false, false, Some(0.4999), 0.5), 4);
        assert_eq!(tier_for(false, false, false, None, 0.5), 4);
    }

    #[test]
    fn playbooks() {
        // tier-1 malware keeps malicious-dependency precedence, even for packages
        assert_eq!(playbook_for(1, true), "malicious-dependency");
        assert_eq!(playbook_for(1, false), "malicious-dependency");
        // package/library match -> advisory-fleet-triage at ANY tier
        assert_eq!(playbook_for(2, true), "advisory-fleet-triage");
        assert_eq!(playbook_for(3, true), "advisory-fleet-triage");
        assert_eq!(playbook_for(4, true), "advisory-fleet-triage");
        // product matches follow the triage order
        assert_eq!(playbook_for(2, false), "exploited-vulnerability");
        assert_eq!(playbook_for(3, false), "advisory-fleet-triage");
        assert_eq!(playbook_for(4, false), "advisory-fleet-triage");
    }

    #[test]
    fn mal_and_severity_helpers() {
        assert!(is_mal_id("MAL-2024-1234"));
        assert!(!is_mal_id("GHSA-xxxx-yyyy-zzzz"));
        assert!(!is_mal_id("CVE-2021-44228"));
        assert!(is_high_severity("CRITICAL"));
        assert!(is_high_severity("High"));
        assert!(!is_high_severity("medium"));
        assert!(!is_high_severity("low"));
    }
}
