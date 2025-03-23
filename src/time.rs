use ::time::OffsetDateTime;
use std::fmt::Display;
use std::ops::{Deref, Neg};
use std::str::FromStr;
use std::time::Duration;

pub fn parse_duration(s: &str) -> Result<Duration, String> {
    cyborgtime::parse_duration(s).map_err(|e| format!("Invalid duration: {e}"))
}

#[derive(Clone)]
pub struct ParsedDuration {
    inner: Duration,
}

impl From<Duration> for ParsedDuration {
    fn from(inner: Duration) -> Self {
        ParsedDuration { inner }
    }
}

impl From<u64> for ParsedDuration {
    fn from(seconds: u64) -> Self {
        Duration::from_secs(seconds).into()
    }
}

impl Deref for ParsedDuration {
    type Target = Duration;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl FromStr for ParsedDuration {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_duration(s).map(ParsedDuration::from)
    }
}

impl Display for ParsedDuration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match humanize_duration_core(**self) {
            Ok(duration) => write!(f, "{duration}"),
            Err(_) => write!(f, "Time too long to display"),
        }
    }
}

#[allow(clippy::missing_panics_doc)]
pub fn current_time_truncated() -> OffsetDateTime {
    let now = OffsetDateTime::now_utc();
    now.replace_nanosecond(0).unwrap(/* unreachable */)
}

pub fn humanize_duration_core(
    duration: core::time::Duration,
) -> Result<String, time::error::ConversionRange> {
    Ok(humanize_duration(duration.try_into()?))
}

pub fn humanize_duration(mut duration: time::Duration) -> String {
    const SECONDS_IN_MINUTE: i64 = 60;
    const SECONDS_IN_HOUR: i64 = 3600;
    const SECONDS_IN_DAY: i64 = 86400;
    const SECONDS_IN_MONTH: i64 = 2_630_016; // Approximation (30.44 days)
    const SECONDS_IN_YEAR: i64 = 31_557_600; // Approximation (365.25 days)

    if duration.is_negative() {
        duration = duration.neg();
    }

    let mut remaining_seconds = duration.whole_seconds();

    let years = remaining_seconds / SECONDS_IN_YEAR;
    remaining_seconds %= SECONDS_IN_YEAR;
    let months = remaining_seconds / SECONDS_IN_MONTH;
    remaining_seconds %= SECONDS_IN_MONTH;
    let days = remaining_seconds / SECONDS_IN_DAY;
    remaining_seconds %= SECONDS_IN_DAY;
    let hours = remaining_seconds / SECONDS_IN_HOUR;
    remaining_seconds %= SECONDS_IN_HOUR;
    let minutes = remaining_seconds / SECONDS_IN_MINUTE;
    remaining_seconds %= SECONDS_IN_MINUTE;
    let seconds = remaining_seconds;

    let mut components = Vec::new();
    if years > 0 {
        components.push(format!(
            "{} year{}",
            years,
            if years > 1 { "s" } else { "" }
        ));
    }
    if months > 0 {
        components.push(format!(
            "{} month{}",
            months,
            if months > 1 { "s" } else { "" }
        ));
    }
    if days > 0 {
        components.push(format!("{} day{}", days, if days > 1 { "s" } else { "" }));
    }
    if hours > 0 {
        components.push(format!(
            "{} hour{}",
            hours,
            if hours > 1 { "s" } else { "" }
        ));
    }
    if minutes > 0 {
        components.push(format!(
            "{} minute{}",
            minutes,
            if minutes > 1 { "s" } else { "" }
        ));
    }
    if seconds > 0 || components.is_empty() {
        components.push(format!(
            "{} second{}",
            seconds,
            if seconds == 1 { "" } else { "s" }
        ));
    }

    components.join(", ")
}

#[cfg(test)]
mod tests {
    use crate::time::humanize_duration;
    use rstest::rstest;

    #[rstest]
    #[case(time::Duration::ZERO, "0 seconds")]
    #[case(std::time::Duration::from_secs(60).try_into().unwrap(), "1 minute")]
    #[case(std::time::Duration::from_secs(61).try_into().unwrap(), "1 minute, 1 second")]
    #[case(std::time::Duration::from_secs(60 * 60).try_into().unwrap(), "1 hour")]
    #[case(std::time::Duration::from_secs(60 * 60 * 24).try_into().unwrap(), "1 day")]
    #[case(std::time::Duration::from_secs_f64(60f64 * 60f64 * 24f64 * 30.44).try_into().unwrap(), "1 month")]
    #[case(std::time::Duration::from_secs_f64(60f64 * 60f64 * 24f64 * 365.25).try_into().unwrap(), "1 year")]
    #[case(std::time::Duration::from_nanos(1).try_into().unwrap(), "0 seconds")]
    #[case(std::time::Duration::from_secs_f64(62.321).try_into().unwrap(), "1 minute, 2 seconds")]
    #[case(std::time::Duration::from_secs_f64(60f64 * 60f64 * 24f64 * 90f64 * 1.1111).try_into().unwrap(), "3 months, 8 days, 16 hours, 17 minutes, 45 seconds")]
    fn test_humanize_duration(#[case] test_value: time::Duration, #[case] expected: &str) {
        let humanized = humanize_duration(test_value);
        assert_eq!(humanized, expected);
    }
}
