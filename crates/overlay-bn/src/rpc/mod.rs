//! The handful of eth2 req/resp protocols the beacon node's peer manager needs answered
//! (§5.2 "Minimal req/resp", CL-N1).

pub mod msg;

#[cfg(test)]
mod tests {
    use libp2p::StreamProtocol;
    use libp2p::futures::executor::block_on;
    use libp2p::request_response::Codec;

    use super::*;
    use crate::rpc::msg::Ping;

    const PING: StreamProtocol = StreamProtocol::new("/eth2/beacon_chain/req/ping/1/ssz_snappy");

    /// CRC-32C (Castagnoli), bit by bit, then snappy's checksum mask.
    fn snappy_crc(data: &[u8]) -> u32 {
        let mut crc = u32::MAX;
        for byte in data {
            crc ^= u32::from(*byte);
            for _ in 0..8 {
                crc = if crc & 1 == 1 {
                    (crc >> 1) ^ 0x82f6_3b78
                } else {
                    crc >> 1
                };
            }
        }
        let crc = !crc;
        (crc.rotate_right(15)).wrapping_add(0xa282_ead8)
    }

    /// `<result 0><varint 8><snappy stream identifier><uncompressed chunk of 8 bytes>`: a
    /// payload this short does not shrink, so the encoder writes it as chunk type 1 with the
    /// masked CRC-32C of the payload and the payload itself, 28 bytes in all.
    #[test]
    fn response_chunk_framing_matches_the_spec() {
        let payload = Ping(0x0102_0304_0506_0708).encode();
        let mut golden = vec![0x00, 0x08];
        golden.extend_from_slice(b"\xff\x06\x00\x00sNaPpY");
        golden.extend_from_slice(&[0x01, 12, 0, 0]);
        golden.extend_from_slice(&snappy_crc(&payload).to_le_bytes());
        golden.extend_from_slice(&payload);

        let mut out = Vec::new();
        block_on(Eth2Codec.write_response(&PING, &mut out, Response::Success(payload))).unwrap();

        assert_eq!(out.len(), 28);
        assert_eq!(out, golden);
    }
}
