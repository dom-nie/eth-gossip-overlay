//! What both ends of an overlay connection have to agree on before anything else.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alpn_is_the_protocol_name_and_the_major() {
        assert_eq!(PROTOCOL_MAJOR, 1);
        assert_eq!(protocol_alpn(), b"fleet-overlay/1");
    }
}
