//! Shared copy formatting helpers: duration, counts, bytes, rates, timestamps.
//!
//! All formatting follows UX-DR18/DR19 conventions.

/// Format a duration for human display.
///
/// Examples: `0.85s`, `1.18s`, `47s`, `3m 12s`, `2h 15m`.
pub fn format_duration(d: std::time::Duration) -> String {
    let total_secs = d.as_secs();
    let millis = d.subsec_millis();

    if total_secs == 0 {
        if millis == 0 {
            return "0s".to_owned();
        }
        let frac = format!("{millis:03}");
        let frac = frac.trim_end_matches('0');
        return format!("0.{frac}s");
    }

    if total_secs < 60 {
        if millis > 0 {
            let frac = format!("{millis:03}");
            let frac = frac.trim_end_matches('0');
            return format!("{total_secs}.{frac}s");
        }
        return format!("{total_secs}s");
    }

    let hours = total_secs / 3600;
    let minutes = (total_secs % 3600) / 60;
    let secs = total_secs % 60;

    if hours > 0 {
        if minutes > 0 { format!("{hours}h {minutes}m") } else { format!("{hours}h") }
    } else if secs > 0 {
        format!("{minutes}m {secs}s")
    } else {
        format!("{minutes}m")
    }
}

/// Format a count with thousand separators.
///
/// Example: `12,847`.
pub fn format_count(n: u64) -> String {
    if n < 1000 {
        return n.to_string();
    }

    let s = n.to_string();
    let mut result = String::with_capacity(s.len() + s.len() / 3);
    let digits: Vec<char> = s.chars().collect();
    let len = digits.len();

    for (i, ch) in digits.iter().enumerate() {
        if i > 0 && (len - i).is_multiple_of(3) {
            result.push(',');
        }
        result.push(*ch);
    }
    result
}

/// Format bytes in human-readable IEC-style units (using MB, not MiB, per UX spec).
///
/// Examples: `0 B`, `512 B`, `4.2 KB`, `2.1 MB`, `80 MB`, `1.3 GB`.
pub fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * 1024;
    const GB: u64 = 1024 * 1024 * 1024;
    const TB: u64 = 1024 * 1024 * 1024 * 1024;

    if bytes < KB {
        return format!("{bytes} B");
    }
    if bytes < MB {
        let val = bytes as f64 / KB as f64;
        return format_unit(val, "KB");
    }
    if bytes < GB {
        let val = bytes as f64 / MB as f64;
        return format_unit(val, "MB");
    }
    if bytes < TB {
        let val = bytes as f64 / GB as f64;
        return format_unit(val, "GB");
    }
    let val = bytes as f64 / TB as f64;
    format_unit(val, "TB")
}

fn format_unit(val: f64, unit: &str) -> String {
    if val >= 10.0 { format!("{:.0} {unit}", val) } else { format!("{:.1} {unit}", val) }
}

/// Format a rate relative to a baseline.
///
/// Shows `45x baseline` when current/baseline > 1.5, otherwise the raw value.
pub fn format_rate(current: f64, baseline: f64) -> String {
    if baseline <= 0.0 {
        return format!("{current:.1}");
    }
    let ratio = current / baseline;
    if ratio > 1.5 { format!("{ratio:.0}x baseline") } else { format!("{current:.1}") }
}

/// Format a timestamp — relative for <24h, absolute ISO for older.
///
/// Examples: `just now`, `14m ago`, `3h ago`, `2026-04-04T14:47:12Z`.
pub fn format_timestamp(ts: chrono::DateTime<chrono::Utc>) -> String {
    let now = chrono::Utc::now();
    let delta = now.signed_duration_since(ts);

    if delta.num_seconds() < 0 {
        // Future timestamp — show absolute.
        return format_timestamp_absolute(ts);
    }

    if delta.num_seconds() < 60 {
        return "just now".to_owned();
    }
    if delta.num_minutes() < 60 {
        return format!("{}m ago", delta.num_minutes());
    }
    if delta.num_hours() < 24 {
        return format!("{}h ago", delta.num_hours());
    }

    format_timestamp_absolute(ts)
}

/// Always format as absolute ISO timestamp.
pub fn format_timestamp_absolute(ts: chrono::DateTime<chrono::Utc>) -> String {
    ts.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn duration_zero() {
        assert_eq!(format_duration(Duration::ZERO), "0s");
    }

    #[test]
    fn duration_sub_second() {
        assert_eq!(format_duration(Duration::from_millis(850)), "0.85s");
        assert_eq!(format_duration(Duration::from_millis(100)), "0.1s");
    }

    #[test]
    fn duration_seconds_with_millis() {
        assert_eq!(format_duration(Duration::from_millis(1180)), "1.18s");
    }

    #[test]
    fn duration_exact_seconds() {
        assert_eq!(format_duration(Duration::from_secs(47)), "47s");
    }

    #[test]
    fn duration_minutes_and_seconds() {
        assert_eq!(format_duration(Duration::from_secs(192)), "3m 12s");
    }

    #[test]
    fn duration_exact_minutes() {
        assert_eq!(format_duration(Duration::from_secs(300)), "5m");
    }

    #[test]
    fn duration_hours_and_minutes() {
        assert_eq!(format_duration(Duration::from_secs(8100)), "2h 15m");
    }

    #[test]
    fn duration_exact_hours() {
        assert_eq!(format_duration(Duration::from_secs(7200)), "2h");
    }

    #[test]
    fn count_small() {
        assert_eq!(format_count(0), "0");
        assert_eq!(format_count(42), "42");
        assert_eq!(format_count(999), "999");
    }

    #[test]
    fn count_thousands() {
        assert_eq!(format_count(1000), "1,000");
        assert_eq!(format_count(12847), "12,847");
        assert_eq!(format_count(1_000_000), "1,000,000");
    }

    #[test]
    fn count_u64_max() {
        assert_eq!(format_count(u64::MAX), "18,446,744,073,709,551,615");
    }

    #[test]
    fn bytes_zero() {
        assert_eq!(format_bytes(0), "0 B");
    }

    #[test]
    fn bytes_under_kb() {
        assert_eq!(format_bytes(512), "512 B");
    }

    #[test]
    fn bytes_kb_range() {
        assert_eq!(format_bytes(4300), "4.2 KB");
    }

    #[test]
    fn bytes_mb_range() {
        assert_eq!(format_bytes(2_202_009), "2.1 MB");
        assert_eq!(format_bytes(83_886_080), "80 MB");
    }

    #[test]
    fn bytes_gb_range() {
        assert_eq!(format_bytes(1_395_864_371), "1.3 GB");
    }

    #[test]
    fn rate_above_threshold() {
        assert_eq!(format_rate(900.0, 20.0), "45x baseline");
    }

    #[test]
    fn rate_below_threshold() {
        assert_eq!(format_rate(20.0, 20.0), "20.0");
    }

    #[test]
    fn rate_zero_baseline() {
        assert_eq!(format_rate(5.0, 0.0), "5.0");
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn timestamp_absolute_format() {
        let ts = chrono::DateTime::parse_from_rfc3339("2026-04-04T14:47:12Z")
            .expect("parse")
            .with_timezone(&chrono::Utc);
        assert_eq!(format_timestamp_absolute(ts), "2026-04-04T14:47:12Z");
    }

    #[test]
    fn timestamp_recent_is_relative() {
        let now = chrono::Utc::now();
        let ts = now - chrono::Duration::minutes(14);
        assert_eq!(format_timestamp(ts), "14m ago");
    }

    #[test]
    fn timestamp_hours_ago() {
        let now = chrono::Utc::now();
        let ts = now - chrono::Duration::hours(3);
        assert_eq!(format_timestamp(ts), "3h ago");
    }

    #[test]
    fn timestamp_just_now() {
        let now = chrono::Utc::now();
        let ts = now - chrono::Duration::seconds(5);
        assert_eq!(format_timestamp(ts), "just now");
    }

    #[test]
    fn timestamp_old_is_absolute() {
        let now = chrono::Utc::now();
        let ts = now - chrono::Duration::hours(25);
        let result = format_timestamp(ts);
        // Should be absolute ISO format.
        assert!(result.contains('T'));
        assert!(result.ends_with('Z'));
    }
}
