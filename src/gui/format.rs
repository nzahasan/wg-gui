//! Number and time formatting, ported from the mock.

use std::time::{SystemTime, UNIX_EPOCH};

/// A rate given in KB/s: "512 B/s", "2.5 KB/s", "820 KB/s" or "1.25 MB/s".
pub fn rate(kb_per_second: f32) -> String {
    let kb = kb_per_second.max(0.0);
    if kb >= 1024.0 {
        format!("{:.2} MB/s", kb / 1024.0)
    } else if kb >= 10.0 {
        format!("{} KB/s", kb.round() as u64)
    } else if kb >= 1.0 {
        format!("{} KB/s", trim_zero(format!("{kb:.1}")))
    } else {
        format!("{} B/s", (kb * 1024.0).round() as u64)
    }
}

/// "2.0" -> "2", "2.5" -> "2.5".
fn trim_zero(number: String) -> String {
    number.strip_suffix(".0").map(str::to_string).unwrap_or(number)
}

pub fn bytes(n: u64) -> String {
    const KB: f64 = 1024.0;
    let b = n as f64;
    if b >= KB * KB * KB {
        format!("{:.2} GB", b / (KB * KB * KB))
    } else if b >= KB * KB {
        format!("{:.1} MB", b / (KB * KB))
    } else if b >= KB {
        format!("{:.0} KB", b / KB)
    } else {
        format!("{n} B")
    }
}

/// "HH:MM:SS".
pub fn duration(seconds: u64) -> String {
    format!("{:02}:{:02}:{:02}", seconds / 3600, seconds / 60 % 60, seconds % 60)
}

/// 1234567 -> "1,234,567".
pub fn count(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// The current time as "2026-10-04T12:00:00Z".
pub fn utc_now() -> String {
    let seconds = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    utc(seconds)
}

pub fn utc(unix_seconds: u64) -> String {
    let days = (unix_seconds / 86_400) as i64;
    let rest = unix_seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z", rest / 3600, rest / 60 % 60, rest % 60)
}

/// Days since 1970-01-01 to (year, month, day); Howard Hinnant's algorithm.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_like_the_mock() {
        assert_eq!(rate(820.4), "820 KB/s");
        assert_eq!(rate(1280.0), "1.25 MB/s");
        assert_eq!(rate(2.5), "2.5 KB/s");
        assert_eq!(rate(5.0), "5 KB/s");
        assert_eq!(rate(0.5), "512 B/s");
        assert_eq!(rate(0.0), "0 B/s");
        assert_eq!(bytes(512), "512 B");
        assert_eq!(bytes(612 * 1024 * 1024), "612.0 MB");
        assert_eq!(bytes(3 * 1024 * 1024 * 1024), "3.00 GB");
        assert_eq!(duration(754), "00:12:34");
        assert_eq!(duration(90_061), "25:01:01");
        assert_eq!(count(0), "0");
        assert_eq!(count(1_234_567), "1,234,567");
    }

    #[test]
    fn utc_timestamps() {
        assert_eq!(utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(utc(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(utc(1_791_072_000 + 3661), "2026-10-04T01:01:01Z");
    }
}
