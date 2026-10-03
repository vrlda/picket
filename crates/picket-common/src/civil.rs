//! Minimal civil-date arithmetic (no chrono). The inverse of the server's
//! format_ts (Hinnant's algorithms). Used by the TLS cert sensor to parse
//! `openssl x509 -enddate` output.

/// Days since 1970-01-01 for a proleptic-Gregorian civil date.
pub fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// Parse "Sep 16 12:00:00 2026" (openssl `-enddate` output format, GMT) into
/// unix SECONDS. Returns None for anything malformed.
pub fn parse_gm_date(s: &str) -> Option<i64> {
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() != 4 {
        return None;
    }
    let month = match parts[0] {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    };
    let day: i64 = parts[1].parse().ok()?;
    let hms: Vec<i64> = parts[2]
        .split(':')
        .map(|p| p.parse().ok())
        .collect::<Option<Vec<i64>>>()?;
    if hms.len() != 3 {
        return None;
    }
    let year: i64 = parts[3].parse().ok()?;
    if !(1..=31).contains(&day) || hms[0] > 23 || hms[1] > 59 || hms[2] > 59 {
        return None;
    }
    Some(days_from_civil(year, month, day) * 86400 + hms[0] * 3600 + hms[1] * 60 + hms[2])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_known_epochs() {
        assert_eq!(parse_gm_date("Jan 1 00:00:00 1970"), Some(0));
        assert_eq!(parse_gm_date("Sep 9 01:46:40 2001"), Some(1_000_000_000));
    }

    #[test]
    fn rejects_malformed() {
        assert_eq!(parse_gm_date("Sep 16 12:00:00"), None);
        assert_eq!(parse_gm_date("Foo 16 12:00:00 2026"), None);
        assert_eq!(parse_gm_date("Sep 32 12:00:00 2026"), None);
        assert_eq!(parse_gm_date("Sep 16 25:00:00 2026"), None);
        assert_eq!(parse_gm_date(""), None);
    }

    #[test]
    fn round_trips_civil_days() {
        // 2025-09-16 05:20:00 UTC = 1758000000 (pinned by the server's
        // format_ts test) → 2025-09-16 00:00:00 = 1758000000 - 19200.
        // Verify with `date -r 1757980800 -u` (expect Tue Sep 16 00:00:00 UTC 2025)
        // before relying on this value; if it disagrees, fix the expected
        // value — do NOT bend the algorithm.
        assert_eq!(days_from_civil(2025, 9, 16) * 86400, 1_757_980_800);
    }
}
