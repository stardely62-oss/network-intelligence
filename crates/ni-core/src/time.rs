//! Time helpers. All timestamps in Network Intelligence are Unix
//! milliseconds (UTC), except raw Windows FILETIME values which are kept as
//! received and converted explicitly.

use std::time::{SystemTime, UNIX_EPOCH};

/// Unix time in milliseconds (UTC).
pub type UnixMs = i64;

/// Current wall-clock time in Unix milliseconds.
pub fn now_ms() -> UnixMs {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// 100-ns intervals between 1601-01-01 and 1970-01-01.
const FILETIME_UNIX_DIFF: u64 = 116_444_736_000_000_000;

/// Converts a Windows FILETIME (100-ns ticks since 1601) to Unix ms.
/// Returns `None` for zero and for values before 1970.
pub fn filetime_to_unix_ms(ft: u64) -> Option<UnixMs> {
    if ft == 0 || ft < FILETIME_UNIX_DIFF {
        return None;
    }
    Some(((ft - FILETIME_UNIX_DIFF) / 10_000) as i64)
}

/// Same as [`filetime_to_unix_ms`] but also rejects values that are not
/// plausible wall-clock times (before 2000 or more than a day in the future).
/// Used for fields whose exact semantics are not guaranteed by the OS
/// documentation, such as socket creation timestamps.
pub fn plausible_filetime(ft: u64, now: UnixMs) -> Option<UnixMs> {
    const Y2000: UnixMs = 946_684_800_000;
    let ms = filetime_to_unix_ms(ft)?;
    (Y2000..=now + 86_400_000).contains(&ms).then_some(ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filetime_conversion() {
        assert_eq!(filetime_to_unix_ms(0), None);
        assert_eq!(filetime_to_unix_ms(FILETIME_UNIX_DIFF), Some(0));
        // 2024-01-01T00:00:00Z
        let ft = FILETIME_UNIX_DIFF + 1_704_067_200_000 * 10_000;
        assert_eq!(filetime_to_unix_ms(ft), Some(1_704_067_200_000));
        assert_eq!(
            plausible_filetime(ft, 1_704_067_200_000),
            Some(1_704_067_200_000)
        );
        // Far future is rejected.
        assert_eq!(plausible_filetime(ft, 1_000_000_000_000), None);
        // A tick counter misread as FILETIME (small value) is rejected.
        assert_eq!(plausible_filetime(12_345_678, now_ms()), None);
    }
}
