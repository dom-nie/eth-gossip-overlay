//! Reading the NIC's own arrival time off the overlay socket (§11.1).
//!
//! `SO_TIMESTAMPING` with `SOF_TIMESTAMPING_RX_HARDWARE | SOF_TIMESTAMPING_RAW_HARDWARE` makes
//! the kernel attach an `SCM_TIMESTAMPING` control message to every datagram, carrying the
//! moment the card saw it rather than the moment a softirq got round to it. With chrony's
//! `hwtimestamp` or ptp4l disciplining the card's clock, that reading is the same clock on
//! every host in the fleet, which is what makes the spread metric trustworthy to microseconds
//! (§11). [`arrival`] is the parser for that message and the whole of what this module decides.
//!
//! # Which socket the control message is read from
//!
//! T-093 had two routes and this is the record of the choice. The first was to set the option
//! on the descriptor `busy_poll::epoll_fd::find` already returns, which is the socket quinn
//! owns, and read the messages there. **That route is closed, and not on taste.** quinn-udp
//! reads its own control messages out of a fixed 88-byte buffer, and on the `[::]` socket §11
//! binds, three messages already fill all 88 of it: `IPV6_TCLASS` at 24, `IPV6_PKTINFO` at 40
//! and `UDP_GRO` at 24. `SCM_TIMESTAMPING` needs 64 more, and the kernel writes it *first*, so
//! turning the option on would push quinn's own three past the end of the buffer. quinn would
//! lose the destination address it answers from, the ECN bits it reads congestion out of, and
//! the segment size that makes GRO work. A tuning that ships off must not be able to break the
//! only transport this product has, which is the same test T-092 applied.
//!
//! So the route is the second one: an `AsyncUdpSocket` of our own on `tokio::io::unix::AsyncFd`,
//! written the way quinn's `TokioRuntime` socket is written, whose `poll_recv` sizes its own
//! control buffer and hands what [`arrival`] finds to the receive path. It stays registered in
//! the I/O thread's epoll, so T-092's lookup still finds it. **That socket is not written yet.**
//! Its `poll_recv` is the one part of this feature that cannot be compiled or run anywhere but
//! on Linux, and writing a hand-rolled `recvmmsg` on the receive path of the only transport
//! this product has, on a machine that cannot build it, is how an optional tuning turns into an
//! outage. Until it exists `overlay_hw_timestamps` reads 0 and every event says `ts_source=sw`,
//! which is exactly what a host with no hardware timestamping reports anyway.

use overlay_core::events::TsSource;

/// `SOL_SOCKET` and `SCM_TIMESTAMPING` as 64-bit Linux numbers them.
///
/// Written out rather than taken from libc because this parser and its byte fixture are
/// compiled and run everywhere the suite runs, and only Linux has libc's copies. On Linux the
/// test below holds these to libc's own.
const SOL_SOCKET: i32 = 1;
const SCM_TIMESTAMPING: i32 = 37;

/// `struct cmsghdr` on 64-bit Linux: an eight-byte length, then the level and the type.
const CMSG_HEADER: usize = 16;

/// `struct timespec` on 64-bit Linux: two 64-bit words.
const TIMESPEC: usize = 16;

/// Control messages start on a multiple of this.
const CMSG_ALIGN: usize = 8;

/// Where `struct scm_timestamping` keeps the kernel's software reading.
const SOFTWARE: usize = 0;

/// Where it keeps the card's own. The slot between the two has been unused since the option was
/// added.
const RAW_HARDWARE: usize = 2;

/// When the datagram this control buffer came with arrived, and which clock said so.
///
/// The card's reading wins wherever there is one, because it is the reading that means the same
/// thing on every host in the fleet. A zero in that slot is the kernel saying the card had no
/// clock, not a datagram from 1970, so it falls back to the software reading; a buffer with no
/// timestamp in it at all answers `None` and the caller keeps its own clock reading.
pub fn arrival(control: &[u8]) -> Option<(TsSource, u64)> {
    let stamps = timestamping(control)?;
    let read = |slot: usize| {
        let at = slot * TIMESPEC;
        let word = |from: usize| -> Option<i64> {
            Some(i64::from_ne_bytes(
                stamps.get(from..from + 8)?.try_into().ok()?,
            ))
        };
        let seconds = u64::try_from(word(at)?).ok()?;
        let nanos = u64::try_from(word(at + 8)?).ok()?;
        seconds
            .checked_mul(1_000_000_000)?
            .checked_add(nanos)
            .filter(|since_epoch| *since_epoch > 0)
    };
    match read(RAW_HARDWARE) {
        Some(nanos) => Some((TsSource::Hw, nanos)),
        None => read(SOFTWARE).map(|nanos| (TsSource::Sw, nanos)),
    }
}

/// The body of the first `SCM_TIMESTAMPING` message in `control`.
///
/// A length that runs past the end of the buffer ends the walk rather than being followed: a
/// truncated control buffer is what the kernel leaves when it had more to say than there was
/// room for, and reading past it would put whatever is next in memory into an arrival time.
fn timestamping(control: &[u8]) -> Option<&[u8]> {
    let word = |at: usize| -> Option<i32> {
        Some(i32::from_ne_bytes(
            control.get(at..at + 4)?.try_into().ok()?,
        ))
    };
    let mut at = 0;
    while at + CMSG_HEADER <= control.len() {
        let len = usize::try_from(u64::from_ne_bytes(
            control.get(at..at + 8)?.try_into().ok()?,
        ))
        .ok()?;
        if len < CMSG_HEADER || at + len > control.len() {
            return None;
        }
        let body = control.get(at + CMSG_HEADER..at + len)?;
        if (word(at + 8)?, word(at + 12)?) == (SOL_SOCKET, SCM_TIMESTAMPING)
            && body.len() >= 3 * TIMESPEC
        {
            return Some(body);
        }
        at += len.next_multiple_of(CMSG_ALIGN);
    }
    None
}

#[cfg(test)]
mod tests {
    use overlay_core::events::TsSource;

    use super::*;

    /// One `SCM_TIMESTAMPING` control message as a 64-bit Linux kernel writes it: a 16-byte
    /// `cmsghdr` at `SOL_SOCKET`/`SCM_TIMESTAMPING`, then `struct scm_timestamping`'s three
    /// `timespec`s. The middle one has been unused since the option was added; the first is the
    /// kernel's software stamp and the last is the card's own.
    ///
    /// Little-endian, because the kernel writes host order and every target this workspace
    /// builds for is little-endian. A big-endian host would need its own copy of these bytes.
    const SCM_TIMESTAMPING_CMSG: [u8; 64] = [
        // cmsg_len = 64
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        // cmsg_level = SOL_SOCKET, cmsg_type = SCM_TIMESTAMPING
        0x01, 0x00, 0x00, 0x00, 0x25, 0x00, 0x00, 0x00, //
        // ts[0]: software, 1757000000.123456789
        0x40, 0xb1, 0xb9, 0x68, 0x00, 0x00, 0x00, 0x00, //
        0x15, 0xcd, 0x5b, 0x07, 0x00, 0x00, 0x00, 0x00, //
        // ts[1]: the unused legacy slot
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        // ts[2]: raw hardware, 1757000000.123450000
        0x40, 0xb1, 0xb9, 0x68, 0x00, 0x00, 0x00, 0x00, //
        0x90, 0xb2, 0x5b, 0x07, 0x00, 0x00, 0x00, 0x00, //
    ];

    /// The whole point of §11.1's hardware timestamps: the card's reading wins, because it is
    /// the one that is the same on every host in the fleet to microseconds. The software stamp
    /// is there and is later, and taking it would put softirq scheduling into the spread number.
    #[test]
    fn scm_timestamping_cmsg_is_parsed_into_nanoseconds() {
        assert_eq!(
            arrival(&SCM_TIMESTAMPING_CMSG),
            Some((TsSource::Hw, 1_757_000_000_123_450_000))
        );
    }

    /// A card with no PTP clock leaves the hardware slot at zero, and a zero there is the
    /// kernel saying "there was none" rather than a reading from 1970.
    #[test]
    fn a_cmsg_with_no_hardware_reading_falls_back_to_the_software_one() {
        let mut cmsg = SCM_TIMESTAMPING_CMSG;
        cmsg[48..64].fill(0);

        assert_eq!(
            arrival(&cmsg),
            Some((TsSource::Sw, 1_757_000_000_123_456_789))
        );
    }

    /// Every other control message the overlay's socket asks for is longer than this one and
    /// none of them is a timestamp. Walking off the end of a buffer, or reading a truncated
    /// message as a reading, would put a garbage arrival time on a fleet-spread query.
    #[test]
    fn a_buffer_with_no_timestamp_in_it_yields_nothing() {
        assert_eq!(arrival(&[]), None);
        assert_eq!(arrival(&SCM_TIMESTAMPING_CMSG[..32]), None);

        let mut other = SCM_TIMESTAMPING_CMSG;
        // IPV6_TCLASS rather than SCM_TIMESTAMPING, which is one of the messages quinn reads.
        other[8..16].copy_from_slice(&[41, 0, 0, 0, 67, 0, 0, 0]);

        assert_eq!(arrival(&other), None);
    }

    /// These numbers are a kernel ABI, and a wrong one reads whatever happened to sit at that
    /// offset as an arrival time. The bytes above are the ABI too, so this is what says the
    /// fixture and the parser are both describing the kernel the sidecar runs on.
    #[cfg(target_os = "linux")]
    #[test]
    fn scm_timestamping_constants_match_the_kernel_abi() {
        assert_eq!(SOL_SOCKET, libc::SOL_SOCKET);
        assert_eq!(SCM_TIMESTAMPING, libc::SCM_TIMESTAMPING);
        assert_eq!(CMSG_HEADER, size_of::<libc::cmsghdr>());
        assert_eq!(TIMESPEC, size_of::<libc::timespec>());
    }
}
