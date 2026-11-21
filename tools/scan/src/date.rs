//! Date math in UTC, hand-rolled (no chrono): unix timestamp <-> civil date,
//! and YYYY-MM-DD parsing. Needed for `kev_recent_days` and report stamps.

pub const SECS_PER_DAY: i64 = 86_400;

/// Days from 1970-01-01 to y-m-d (proleptic Gregorian, Howard Hinnant's
/// civil-from-days inverse).
pub fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let mp = ((m + 9) % 12) as i64; // [0, 11]
    let doy = (153 * mp + 2) / 5 + (d - 1) as i64;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Civil date from days since 1970-01-01.
pub fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Unix seconds -> (year, month, day) in UTC.
pub fn unix_to_ymd(secs: i64) -> (i64, u32, u32) {
    civil_from_days(secs.div_euclid(SECS_PER_DAY))
}

/// Parse "YYYY-MM-DD" (exactly 10 chars, digits where required) into days
/// since epoch. Returns None on any deviation.
pub fn parse_ymd(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
        return None;
    }
    let dig = |from: usize, to: usize| -> Option<i64> {
        let mut v: i64 = 0;
        for &c in &b[from..to] {
            if !c.is_ascii_digit() {
                return None;
            }
            v = v * 10 + (c - b'0') as i64;
        }
        Some(v)
    };
    let y = dig(0, 4)?;
    let m = dig(5, 7)? as u32;
    let d = dig(8, 10)? as u32;
    if !(1..=12).contains(&m) || d < 1 || d > 31 {
        return None;
    }
    Some(days_from_civil(y, m, d))
}

/// Format days-since-epoch as "YYYY-MM-DD".
#[allow(dead_code)] // used by tests and available for report rendering
pub fn format_ymd(days: i64) -> String {
    let (y, m, d) = civil_from_days(days);
    format!("{:04}-{:02}-{:02}", y, m, d)
}

/// Current UTC date from the system clock.
#[allow(dead_code)]
pub fn today_ymd() -> (i64, u32, u32) {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    unix_to_ymd(secs)
}

/// Current unix seconds.
pub fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// RFC 3339 UTC timestamp, e.g. 2026-11-21T12:34:56Z.
pub fn rfc3339_utc(secs: i64) -> String {
    let (y, m, d) = civil_from_days(secs.div_euclid(SECS_PER_DAY));
    let rem = secs.rem_euclid(SECS_PER_DAY);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y,
        m,
        d,
        rem / 3600,
        (rem / 60) % 60,
        rem % 60
    )
}

/// Compact stamp for file names, e.g. 20261121T123456Z.
pub fn file_stamp(secs: i64) -> String {
    rfc3339_utc(secs).replace(['-', ':'], "")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_is_1970_01_01() {
        assert_eq!(unix_to_ymd(0), (1970, 1, 1));
        assert_eq!(format_ymd(0), "1970-01-01");
        assert_eq!(parse_ymd("1970-01-01"), Some(0));
    }

    #[test]
    fn known_timestamps() {
        // 1700000000 = 2023-11-14T22:13:20Z
        assert_eq!(unix_to_ymd(1_700_000_000), (2023, 11, 14));
        assert_eq!(rfc3339_utc(1_700_000_000), "2023-11-14T22:13:20Z");
        // leap day 2000-02-29 = 951782400
        assert_eq!(unix_to_ymd(951_782_400), (2000, 2, 29));
        assert_eq!(parse_ymd("2000-02-29"), Some(11_016)); // 951_782_400 secs / 86_400
        // 2026-11-21 = ?
        let d = parse_ymd("2026-11-21").unwrap();
        assert_eq!(format_ymd(d), "2026-11-21");
        assert_eq!(civil_from_days(days_from_civil(2026, 11, 21)), (2026, 11, 21));
    }

    #[test]
    fn negative_timestamps() {
        // 1960-01-01 = -3650 days approx; just check roundtrip
        let d = days_from_civil(1960, 1, 1);
        assert_eq!(civil_from_days(d), (1960, 1, 1));
        assert_eq!(unix_to_ymd(-86_400), (1969, 12, 31));
    }

    #[test]
    fn parse_rejects_garbage() {
        assert_eq!(parse_ymd("2026-13-01"), None);
        assert_eq!(parse_ymd("2026-00-10"), None);
        assert_eq!(parse_ymd("2026-11-32"), None);
        assert_eq!(parse_ymd("2026/11/21"), None);
        assert_eq!(parse_ymd("2026-11-2"), None);
        assert_eq!(parse_ymd("abcd-ef-gh"), None);
        assert_eq!(parse_ymd(""), None);
    }

    #[test]
    fn file_stamp_format() {
        assert_eq!(file_stamp(1_700_000_000), "20231114T221320Z");
    }
}
