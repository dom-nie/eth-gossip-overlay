//! What both ends of an overlay connection have to agree on before anything else.
//!
//! Only the major lives here today. It travels in the ALPN, so a pair that disagrees on it
//! fails to pair at the TLS layer instead of exchanging frames neither side understands.
//! T-024 adds the minor, the feature bits and the frame and batch limits alongside it; those
//! travel in HELLO and are negotiated down to what both ends support, so a release that adds
//! a feature still pairs with one that has never heard of it (D29).
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
    format!("fleet-overlay/{PROTOCOL_MAJOR}").into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alpn_is_the_protocol_name_and_the_major() {
        assert_eq!(PROTOCOL_MAJOR, 1);
        assert_eq!(protocol_alpn(), b"fleet-overlay/1");
    }
}
