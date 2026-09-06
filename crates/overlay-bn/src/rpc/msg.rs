//! The four request/response bodies the sidecar reads and writes, as fixed-size little-endian
//! SSZ.

#[cfg(test)]
mod tests {
    use lighthouse_network::rpc::methods::StatusMessageV1;
    use ssz::{Decode, Encode};
    use types::{Epoch, Hash256, Slot};

    use super::*;

    fn status() -> Status {
        Status {
            fork_digest: [1, 2, 3, 4],
            finalized_root: [0xaa; 32],
            finalized_epoch: 7,
            head_root: [0xbb; 32],
            head_slot: 250,
            earliest_available_slot: None,
        }
    }

    #[test]
    fn status_v1_round_trips_against_lighthouse_ssz() {
        let ours = status().encode(1);

        let theirs = StatusMessageV1::from_ssz_bytes(&ours).unwrap();
        let back = Status::decode(&theirs.as_ssz_bytes(), 1).unwrap();

        assert_eq!(ours.len(), Status::V1_LEN);
        assert_eq!(theirs.fork_digest, [1, 2, 3, 4]);
        assert_eq!(theirs.finalized_root, Hash256::repeat_byte(0xaa));
        assert_eq!(theirs.finalized_epoch, Epoch::new(7));
        assert_eq!(theirs.head_root, Hash256::repeat_byte(0xbb));
        assert_eq!(theirs.head_slot, Slot::new(250));
        assert_eq!(back, status());
    }
}
