//! Reading the NIC's own arrival time off the overlay socket (§11.1).

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
}
