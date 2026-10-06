//! Number and time formatting, ported from the mock.

use std::ffi::{c_char, c_int};
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

/// The current time in the device's time zone, as
/// "2026-10-04T18:00:00+06:00".
pub fn local_now() -> String {
    let seconds = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    local(seconds)
}

/// A time in the device's time zone, as "2026-10-04T18:00:00+06:00".
pub fn local(unix_seconds: u64) -> String {
    with_offset(unix_seconds, utc_offset(unix_seconds))
}

/// ISO 8601 with a "+HH:MM" offset given in seconds east of UTC.
fn with_offset(unix_seconds: u64, offset_seconds: i64) -> String {
    let local = unix_seconds as i64 + offset_seconds;
    let days = local.div_euclid(86_400);
    let rest = local.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let sign = if offset_seconds < 0 { '-' } else { '+' };
    let offset_minutes = offset_seconds.abs() / 60;
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}{sign}{:02}:{:02}",
        rest / 3600,
        rest / 60 % 60,
        rest % 60,
        offset_minutes / 60,
        offset_minutes % 60
    )
}

/// `struct tm` from macOS <time.h>.
#[repr(C)]
struct Tm {
    tm_sec: c_int,
    tm_min: c_int,
    tm_hour: c_int,
    tm_mday: c_int,
    tm_mon: c_int,
    tm_year: c_int,
    tm_wday: c_int,
    tm_yday: c_int,
    tm_isdst: c_int,
    /// `long`, which is 64 bits on macOS.
    tm_gmtoff: i64,
    tm_zone: *const c_char,
}

unsafe extern "C" {
    fn localtime_r(time: *const i64, result: *mut Tm) -> *mut Tm;
}

/// Seconds east of UTC in the device's time zone at that moment (so
/// daylight saving is taken into account); 0 if it cannot be found.
fn utc_offset(unix_seconds: u64) -> i64 {
    let time = unix_seconds as i64;
    let mut tm = std::mem::MaybeUninit::<Tm>::zeroed();
    // SAFETY: both pointers are valid for the call; localtime_r is the
    // thread-safe variant and only writes into `tm`.
    let result = unsafe { localtime_r(&time, tm.as_mut_ptr()) };
    if result.is_null() { 0 } else { unsafe { tm.assume_init() }.tm_gmtoff }
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

    #[test]
    fn local_timestamps() {
        assert_eq!(with_offset(1_791_072_000, 6 * 3600), "2026-10-04T06:00:00+06:00");
        assert_eq!(with_offset(1_791_072_000, -(5 * 3600 + 1800)), "2026-10-03T18:30:00-05:30");
        assert_eq!(with_offset(0, 0), "1970-01-01T00:00:00+00:00");
        let now = local_now();
        assert_eq!(now.len(), "2026-10-04T06:00:00+06:00".len(), "{now}");
    }
}
