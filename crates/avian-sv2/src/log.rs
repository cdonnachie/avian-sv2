//! A timestamp on every log line.
//!
//! Without one a log says what happened but not when, which is exactly what
//! is needed to line the pool up against a node's debug.log and a miner's
//! output. UTC, marked with a Z, because a pool in a container runs on UTC
//! while a miner on the host prints local time: the marker is what stops the
//! two looking like they disagree.
//!
//! Formatted here rather than with a date crate. The workspace carries the
//! SRI crates and secp256k1 and nothing else, and a dependency earning its
//! place by printing one prefix would be the largest thing in the tree.

use std::time::{SystemTime, UNIX_EPOCH};

/// `2026-11-02 04:55:05Z`, from the system clock.
///
/// A clock set before the epoch formats as the epoch rather than failing. A
/// log line is not worth a panic, and a machine whose clock is that wrong has
/// worse problems than this prefix.
pub fn timestamp() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format(secs)
}

/// The same thing for a given instant, which is what the tests can check.
pub fn format(secs: u64) -> String {
    let (y, m, d, hh, mm, ss) = civil_from_unix(secs);
    format!("{y:04}-{m:02}-{d:02} {hh:02}:{mm:02}:{ss:02}Z")
}

/// Splits seconds since the epoch into a UTC date and time.
///
/// Howard Hinnant's civil_from_days, in the unsigned form that is enough
/// here: 1970 onwards, so nothing goes negative. No leap seconds, because
/// Unix time does not have any to account for.
fn civil_from_unix(secs: u64) -> (u64, u64, u64, u64, u64, u64) {
    let days = secs / 86_400;
    let rem = secs % 86_400;

    // Shifting the epoch to 0000-03-01 puts the leap day at the end of the
    // year, which is what lets the month and day below be plain arithmetic
    // with no table and no special case for February.
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + u64::from(m <= 2);

    (y, m, d, rem / 3600, (rem % 3600) / 60, rem % 60)
}

/// A log line, stamped, on stderr.
///
/// All of it on stderr so that one stream carries the whole log in order.
/// The pool used to print its startup lines on stdout and everything after
/// on stderr, which looks right through `docker compose logs`, because that
/// merges them, and interleaves unpredictably anywhere else.
#[macro_export]
macro_rules! logln {
    ($($arg:tt)*) => {
        eprintln!("[{}] {}", $crate::log::timestamp(), format_args!($($arg)*))
    };
}

#[cfg(test)]
mod tests {
    use super::format;

    #[test]
    fn known_instants() {
        // The epoch itself, then the two sides of a day boundary, because an
        // off-by-one in the day split is invisible at any other second.
        assert_eq!(format(0), "1970-01-01 00:00:00Z");
        assert_eq!(format(1), "1970-01-01 00:00:01Z");
        assert_eq!(format(86_399), "1970-01-01 23:59:59Z");
        assert_eq!(format(86_400), "1970-01-02 00:00:00Z");

        // Leap days in both directions that the century rules get wrong if
        // the era arithmetic is off: 2000 is a leap year, 2100 is not.
        assert_eq!(format(951_782_400), "2000-02-29 00:00:00Z");
        assert_eq!(format(1_709_164_800), "2024-02-29 00:00:00Z");
        assert_eq!(format(4_102_444_800), "2100-01-01 00:00:00Z");

        // An ntime from a real template, so the formatting of a time that is
        // not midnight is checked too.
        assert_eq!(format(1_793_621_386), "2026-11-02 12:09:46Z");
    }

    #[test]
    fn every_day_for_two_centuries() {
        // Walks a day at a time and checks the date only ever moves forward
        // by one, which catches a wrong year length anywhere in the range
        // without a table of expected values to maintain.
        let mut prev = (1970u64, 1u64, 1u64);
        let mut day = 1u64;
        while day < 365 * 200 {
            let text = format(day * 86_400);
            let y: u64 = text[0..4].parse().unwrap();
            let m: u64 = text[5..7].parse().unwrap();
            let d: u64 = text[8..10].parse().unwrap();
            assert!((1..=12).contains(&m), "{text}");
            assert!((1..=31).contains(&d), "{text}");
            let forward = (y, m, d) > prev;
            assert!(forward, "{text} does not follow {prev:?}");
            prev = (y, m, d);
            day += 1;
        }
    }
}
