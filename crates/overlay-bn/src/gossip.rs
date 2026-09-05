//! The gossipsub behaviour on the BN link.

#[cfg(test)]
mod tests {
    use prometheus_client::registry::Registry;

    use super::*;
    use crate::testutil;

    const TOPIC: &str = "/eth2/6a95a1a9/beacon_block/ssz_snappy";
    /// `hello`, snappy-compressed: T-006's spec vector input.
    const HELLO_SNAPPY: &[u8] = &[0x05, 0x10, 0x68, 0x65, 0x6c, 0x6c, 0x6f];

    fn cfg() -> BnLinkConfig {
        BnLinkConfig {
            idontwant_on_publish: true,
        }
    }

    #[tokio::test]
    async fn payload_is_not_decompressed_by_transform() {
        let mut registry = Registry::default();
        let (mut sidecar, mut bn) = testutil::connected_pair(
            build_behaviour(&cfg(), &mut registry),
            build_behaviour(&cfg(), &mut registry),
        )
        .await;
        let topic = testutil::subscribe_both(&mut sidecar, &mut bn, TOPIC).await;

        sidecar
            .behaviour_mut()
            .publish(topic, HELLO_SNAPPY.to_vec())
            .unwrap();
        let received = testutil::next_message(&mut sidecar, &mut bn).await;

        assert_eq!(received.data, HELLO_SNAPPY);
    }
}
