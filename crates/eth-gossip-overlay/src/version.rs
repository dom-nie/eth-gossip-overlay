//! The two lines `--version` prints (D29).
//!
//! The first identifies the build well enough to find the source it came from. The second says
//! what this binary can pair with: the protocol major travels in the ALPN and the minor and the
//! feature bits in HELLO, so those three numbers are the whole compatibility story an operator
//! needs during a rolling upgrade. T-048 reads both lines off the released artefacts.

use std::sync::LazyLock;

use overlay_core::protocol::{PROTOCOL_MAJOR, PROTOCOL_MINOR, SUPPORTED_FEATURES};

/// What `--version` prints after the binary name clap puts in front of it, built once because
/// clap wants a `&'static str`.
pub static VERSION: LazyLock<String> = LazyLock::new(|| {
    format!(
        "{} {} {}\nprotocol {PROTOCOL_MAJOR}.{PROTOCOL_MINOR} features=0x{SUPPORTED_FEATURES:x}",
        env!("CARGO_PKG_VERSION"),
        env!("ETH_GOSSIP_OVERLAY_GIT_SHA"),
        build_date(env!("ETH_GOSSIP_OVERLAY_BUILD_EPOCH")),
    )
});

/// The day a Unix timestamp falls on in UTC, as `yyyy-mm-dd`. Anything that is not a timestamp
/// passes through, which is what a build with no clock and no `SOURCE_DATE_EPOCH` leaves.
///
/// This is Howard Hinnant's civil-from-days, exact for every day a release will ever carry and
/// eight lines shorter than reaching for a calendar crate.
fn build_date(epoch: &str) -> String {
    let Ok(seconds) = epoch.parse::<i64>() else {
        return epoch.to_owned();
    };
    let days = seconds.div_euclid(86_400) + 719_468;
    let era = days.div_euclid(146_097);
    let day_of_era = days.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The epoch itself, a leap day, the last day of a year and a century boundary: the four
    /// places the civil-from-days arithmetic can go wrong.
    #[test]
    fn build_date_renders_the_utc_day_of_a_timestamp() {
        assert_eq!(build_date("0"), "1970-01-01");
        assert_eq!(build_date("1709164800"), "2024-02-29");
        assert_eq!(build_date("1735603200"), "2024-12-31");
        assert_eq!(build_date("4102444800"), "2100-01-01");
    }

    /// A build with no clock and no `SOURCE_DATE_EPOCH` says so rather than claiming a date.
    #[test]
    fn build_date_passes_through_what_is_not_a_timestamp() {
        assert_eq!(build_date("unknown"), "unknown");
    }

    /// D29: the second line is what a peer's release notes are read against, so its shape is
    /// fixed rather than derived from whatever the constants happen to be.
    #[test]
    fn version_ends_with_the_protocol_line() {
        let lines: Vec<&str> = VERSION.lines().collect();

        assert_eq!(lines.len(), 2, "{}", *VERSION);
        assert!(
            lines[0].starts_with(concat!(env!("CARGO_PKG_VERSION"), " ")),
            "{}",
            lines[0]
        );
        assert_eq!(lines[1], "protocol 1.0 features=0x1");
    }
}
