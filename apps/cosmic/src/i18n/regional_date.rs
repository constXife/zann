//! Format native UI dates with the desktop's time zone and LC_TIME.
use std::{ffi::CStr, io, ptr};

use jiff::{civil::Date, Timestamp};
use libc::{locale_t, tm, wchar_t};

// The wide POSIX interface preserves localized names even in a non-UTF-8 locale.
unsafe extern "C" {
    fn wcsftime_l(
        output: *mut wchar_t,
        capacity: usize,
        format: *const wchar_t,
        date: *const tm,
        locale: locale_t,
    ) -> usize;
}

pub(crate) fn short_date(date: Date) -> String {
    // An empty locale name asks libc to resolve LC_ALL, LC_TIME and LANG.
    render(&civil_day(date), Style::Date, c"").unwrap_or_else(unavailable)
}

pub fn format_timestamp(value: &str) -> String {
    timestamp_label(value, None, c"").unwrap_or_else(unavailable)
}

pub(crate) fn format_sync_timestamp(value: &str) -> String {
    timestamp_label(value, Some(Timestamp::now()), c"").unwrap_or_else(unavailable)
}

fn unavailable(error: io::Error) -> String {
    format!("{} · {error}", super::t("common.dateUnavailable"))
}

fn timestamp_label(value: &str, today: Option<Timestamp>, locale: &CStr) -> io::Result<String> {
    let instant = value.parse::<Timestamp>().map_err(io::Error::other)?;
    let local = local_time(instant)?;
    let same_day = today
        .map(local_time)
        .transpose()?
        .is_some_and(|now| (now.tm_year, now.tm_yday) == (local.tm_year, local.tm_yday));
    render(
        &local,
        if same_day {
            Style::Time
        } else {
            Style::DateTime
        },
        locale,
    )
}

fn local_time(instant: Timestamp) -> io::Result<tm> {
    let seconds = libc::time_t::try_from(instant.as_second()).map_err(io::Error::other)?;
    let mut local = std::mem::MaybeUninit::<tm>::uninit();
    // SAFETY: localtime_r initializes the caller's tm on success.
    if unsafe { libc::localtime_r(&seconds, local.as_mut_ptr()) }.is_null() {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { local.assume_init() })
}

fn civil_day(date: Date) -> tm {
    // SAFETY: tm contains only C integers and a nullable timezone pointer.
    let mut local: tm = unsafe { std::mem::zeroed() };
    local.tm_year = i32::from(date.year()) - 1900;
    local.tm_mon = i32::from(date.month()) - 1;
    local.tm_mday = i32::from(date.day());
    local.tm_yday = i32::from(date.day_of_year()) - 1;
    local.tm_wday = i32::from(date.weekday().to_sunday_zero_offset());

    local
}

enum Style {
    Date,
    Time,
    DateTime,
}

fn render(local: &tm, style: Style, locale_name: &CStr) -> io::Result<String> {
    let pattern: &[wchar_t] = match style {
        Style::Date => &['%' as _, 'x' as _, 0],
        Style::Time => &['%' as _, 'X' as _, 0],
        Style::DateTime => &['%' as _, 'x' as _, ' ' as _, '%' as _, 'X' as _, 0],
    };
    let mut output = [0 as wchar_t; 256];
    // SAFETY: newlocale owns a fresh handle. The format is NUL-terminated, the
    // buffer length is in wchar_t units and the handle lives through the call.
    let length = unsafe {
        let locale = libc::newlocale(
            libc::LC_TIME_MASK | libc::LC_CTYPE_MASK,
            locale_name.as_ptr(),
            ptr::null_mut(),
        );
        if locale.is_null() {
            return Err(io::Error::last_os_error());
        }
        let written = wcsftime_l(
            output.as_mut_ptr(),
            output.len(),
            pattern.as_ptr(),
            local,
            locale,
        );
        libc::freelocale(locale);
        written
    };
    if length == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "system date or time did not fit",
        ));
    }
    output[..length]
        .iter()
        .map(|&unit| {
            char::from_u32(unit as u32).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid system date character")
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offset_and_fractional_timestamps_use_the_same_local_clock() {
        let utc = "2026-11-25T23:30:12Z";
        let with_offset = "2026-11-26T01:30:12.123456789+02:00";
        let now = utc.parse::<Timestamp>().expect("fixture timestamp");
        let full = timestamp_label(utc, None, c"C").expect("date and time");
        let time = timestamp_label(with_offset, Some(now), c"C").expect("time today");
        assert_eq!(
            full,
            timestamp_label(with_offset, None, c"C").expect("same instant")
        );
        assert!(full.ends_with(&time));
        assert!(full.len() > time.len());
        let another_day = "2026-11-20T23:30:12Z".parse().expect("earlier day");
        assert_eq!(
            timestamp_label(utc, Some(another_day), c"C").expect("earlier sync"),
            full
        );
        assert!(timestamp_label("invalid", None, c"C").is_err());
    }

    #[test]
    fn civil_date_uses_the_posix_locales_short_pattern() {
        let date = Date::new(2026, 11, 25).expect("fixture date");
        assert_eq!(
            render(&civil_day(date), Style::Date, c"C").expect("POSIX short date"),
            "11/25/26"
        );
    }
}
