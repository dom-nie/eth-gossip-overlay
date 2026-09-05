#[cfg(test)]
mod tests {
    use super::*;

    const TOPIC: &str = "/eth2/6a95a1a9/beacon_block/ssz_snappy";
    const HELLO_SNAPPY: &[u8] = &[0x05, 0x10, 0x68, 0x65, 0x6c, 0x6c, 0x6f];
    const HELLO_ID: &str = "d1346976629ef3d2c04a2a53ccacb9499c3db63a";

    #[test]
    fn valid_snappy_payload_matches_spec_vector() {
        let computed = compute(TOPIC, HELLO_SNAPPY, 1024);

        assert_eq!(computed.branch, Branch::Valid);
        assert_eq!(computed.id.to_string(), HELLO_ID);
    }
}
