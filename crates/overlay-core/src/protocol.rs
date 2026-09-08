//! What both ends of an overlay connection have to agree on before anything else.
//!
//! The major travels in the ALPN, so a pair that disagrees on it fails to pair at the TLS layer
//! instead of exchanging frames neither side understands. The minor, the feature bits and the two
//! limits travel in HELLO and are negotiated down to what both ends support: a pair operates at
//! `min(minor)` and at the intersection of the feature bits, and a sender never emits a frame
//! type, a flag or a behaviour the peer did not advertise, nor exceeds the limits it named. That
//! is what lets a release that adds a feature still pair with one that has never heard of it, and
//! what makes a rolling upgrade a rolling upgrade rather than an outage (D29).
//!
//! There is deliberately no `PROTOCOL_VERSION` constant and no equality check on a version
//! field anywhere. A fleet is upgraded host by host, and a pair that refused to talk until
//! both ends matched exactly would turn every rolling upgrade into an outage.

/// The protocol major. It changes only when a release stops being able to talk to the one
/// before it, which is the whole point of putting it where pairing fails.
pub const PROTOCOL_MAJOR: u8 = 1;

/// The ALPN both ends offer, as the bytes rustls wants. The only place the major reaches the
/// wire, so there is one string to keep right.
pub fn protocol_alpn() -> Vec<u8> {
    format!("eth-gossip-overlay/{PROTOCOL_MAJOR}").into_bytes()
}

/// The protocol minor. It changes when a release adds something a peer can use without being told
/// about it first; anything a peer has to opt into is a feature bit instead.
pub const PROTOCOL_MINOR: u16 = 0;

/// The optional behaviours a release can advertise in HELLO. A bit is set only once both the code
/// and the ticket that ships it are in, so a v1 binary that meets a v2 one is sent v1 frames.
pub mod features {
    /// Small-class batches over QUIC datagrams instead of streams (T-062).
    pub const DATAGRAM_BATCHES: u64 = bit(0);
    /// Large messages split into chunks with parity and striped over a region (T-073).
    pub const STRIPING: u64 = bit(1);
    /// Chunk and custody-column repair (T-082).
    pub const REPAIR: u64 = bit(2);

    /// Every bit this release defines, with the name `eth-gossip-overlayctl status` prints for it.
    /// The rendering reads this rather than keeping a list of its own, so a bit added without a
    /// name here is shown as part of the hex and nothing claims to know what it is (T-042).
    pub const NAMES: [(&str, u64); 3] = [
        ("datagram_batches", DATAGRAM_BATCHES),
        ("striping", STRIPING),
        ("repair", REPAIR),
    ];

    const fn bit(position: u32) -> u64 {
        1 << position
    }
}

/// What this build puts in HELLO. `DATAGRAM_BATCHES` is the one bit it sets: it coalesces the
/// small class into `BATCH` datagrams for a peer that advertises the bit too, and falls back to
/// whole messages on streams for every other peer, which is what an older release reads (T-062).
pub const SUPPORTED_FEATURES: u64 = features::DATAGRAM_BATCHES;

/// The largest frame this build accepts on a stream, which is what it advertises in HELLO. A
/// whole message plus the chunk header and the room a `REPAIR_RESP` needs around it.
pub const MAX_FRAME_BYTES: u32 = (crate::wire::MAX_PAYLOAD_BYTES + 1024) as u32;

/// The most entries this build accepts in one `BATCH`, which is what it advertises in HELLO. Far
/// more than a datagram holds; the bound is against a peer that lies about its count, not against
/// an honest batcher.
pub const MAX_BATCH_ENTRIES: u16 = 1024;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alpn_is_the_protocol_name_and_the_major() {
        assert_eq!(PROTOCOL_MAJOR, 1);
        assert_eq!(protocol_alpn(), b"eth-gossip-overlay/1");
    }

    /// The numbers a peer reads out of HELLO and holds this host to, so they are pinned as
    /// literals rather than recomputed the way the constants build them.
    #[test]
    fn hello_advertises_the_version_and_limits_this_release_committed_to() {
        assert_eq!(PROTOCOL_MINOR, 0);
        assert_eq!(SUPPORTED_FEATURES, 3);
        assert_eq!(MAX_FRAME_BYTES, 10_486_784);
        assert_eq!(MAX_BATCH_ENTRIES, 1024);
    }

    /// A bit that moved would make one release read another's frames as a feature it never
    /// advertised, which is the one thing the negotiation exists to prevent.
    #[test]
    fn feature_bits_keep_the_positions_they_were_assigned() {
        assert_eq!(features::DATAGRAM_BATCHES, 1);
        assert_eq!(features::STRIPING, 2);
        assert_eq!(features::REPAIR, 4);
    }

    /// A bit with no name would be rendered as hex alone, which reads as an unknown feature
    /// rather than as one this release defines.
    #[test]
    fn every_feature_bit_has_a_name() {
        let named = features::NAMES.iter().fold(0, |bits, (_, bit)| bits | bit);

        assert_eq!(
            named,
            features::DATAGRAM_BATCHES | features::STRIPING | features::REPAIR
        );
    }
}
