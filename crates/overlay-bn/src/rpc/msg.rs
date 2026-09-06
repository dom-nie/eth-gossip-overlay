//! The four request/response bodies the sidecar reads and writes, as fixed-size little-endian
//! SSZ. Every field is a `u64`, a `[u8; 32]` or a byte array, so each body is a fixed byte
//! layout copied from `beacon_node/lighthouse_network/src/rpc/methods.rs`, and a body of any
//! other length is malformed.

/// A body that is not the fixed-size SSZ its protocol version calls for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Malformed;

/// `StatusMessage`: the requester's view of its own chain. Version 1 stops at `head_slot`;
/// version 2 adds `earliest_available_slot`, which is `None` after a v1 decode and written as
/// 0 when a v2 encode has none, the way Lighthouse's `status_v2()` fills it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Status {
    /// The fork digest of the requester's current fork.
    pub fork_digest: [u8; 4],
    /// The root of the requester's latest finalized block.
    pub finalized_root: [u8; 32],
    /// The epoch of that finalized block.
    pub finalized_epoch: u64,
    /// The requester's head block root.
    pub head_root: [u8; 32],
    /// The slot of the head block.
    pub head_slot: u64,
    /// The slot from which the requester has every block and blob or column; v2 only.
    pub earliest_available_slot: Option<u64>,
}

impl Status {
    /// The v1 body: four fields of 4, 32, 8, 32 and 8 bytes.
    pub const V1_LEN: usize = 84;
    /// The v2 body: v1 plus one `u64`.
    pub const V2_LEN: usize = 92;

    /// The body at protocol `version` 1 or 2.
    pub fn encode(&self, version: u8) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::V2_LEN);
        out.extend_from_slice(&self.fork_digest);
        out.extend_from_slice(&self.finalized_root);
        out.extend_from_slice(&self.finalized_epoch.to_le_bytes());
        out.extend_from_slice(&self.head_root);
        out.extend_from_slice(&self.head_slot.to_le_bytes());
        if version >= 2 {
            out.extend_from_slice(&self.earliest_available_slot.unwrap_or(0).to_le_bytes());
        }
        out
    }

    /// Reads a body sent on protocol `version` 1 or 2.
    pub fn decode(bytes: &[u8], version: u8) -> Result<Self, Malformed> {
        let expected = if version >= 2 {
            Self::V2_LEN
        } else {
            Self::V1_LEN
        };
        if bytes.len() != expected {
            return Err(Malformed);
        }
        Ok(Self {
            fork_digest: array(&bytes[0..4]),
            finalized_root: array(&bytes[4..36]),
            finalized_epoch: u64_at(bytes, 36),
            head_root: array(&bytes[44..76]),
            head_slot: u64_at(bytes, 76),
            earliest_available_slot: (version >= 2).then(|| u64_at(bytes, 84)),
        })
    }
}

/// `MetaData`: what the sidecar tells the beacon node about itself. The bitfields are SSZ
/// `Bitvector[64]` and `Bitvector[4]`: subnet `i` is bit `i % 8` of byte `i / 8`. Version 1
/// stops after `attnets`, version 2 adds `syncnets`, version 3 the custody group count, which
/// is `None` after a v1 or v2 decode and written as 0 when a v3 encode has none.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MetaData {
    /// Bumped whenever the rest changes, so the beacon node knows to ask again.
    pub seq_number: u64,
    /// The attestation subnets the sidecar is subscribed to.
    pub attnets: [u8; 8],
    /// The sync committee subnets, in the low four bits.
    pub syncnets: u8,
    /// How many custody groups the sidecar claims; v3 only.
    pub custody_group_count: Option<u64>,
}

impl MetaData {
    /// The v1 body: `seq_number` and `attnets`.
    pub const V1_LEN: usize = 16;
    /// The v2 body: v1 plus one byte of `syncnets`.
    pub const V2_LEN: usize = 17;
    /// The v3 body: v2 plus one `u64`.
    pub const V3_LEN: usize = 25;

    /// The body at protocol `version` 1, 2 or 3.
    pub fn encode(&self, version: u8) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::V3_LEN);
        out.extend_from_slice(&self.seq_number.to_le_bytes());
        out.extend_from_slice(&self.attnets);
        if version >= 2 {
            out.push(self.syncnets);
        }
        if version >= 3 {
            out.extend_from_slice(&self.custody_group_count.unwrap_or(0).to_le_bytes());
        }
        out
    }

    /// Reads a body sent on protocol `version` 1, 2 or 3.
    pub fn decode(bytes: &[u8], version: u8) -> Result<Self, Malformed> {
        let expected = match version {
            0 | 1 => Self::V1_LEN,
            2 => Self::V2_LEN,
            _ => Self::V3_LEN,
        };
        if bytes.len() != expected {
            return Err(Malformed);
        }
        Ok(Self {
            seq_number: u64_at(bytes, 0),
            attnets: array(&bytes[8..16]),
            syncnets: bytes.get(16).copied().unwrap_or(0),
            custody_group_count: (version >= 3).then(|| u64_at(bytes, 17)),
        })
    }
}

/// `Ping`: the sender's metadata sequence number, so the other side knows whether its copy of
/// the metadata is stale.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ping(pub u64);

impl Ping {
    /// The body: one `u64`.
    pub fn encode(self) -> Vec<u8> {
        self.0.to_le_bytes().to_vec()
    }

    /// Reads a body.
    pub fn decode(bytes: &[u8]) -> Result<Self, Malformed> {
        u64_exact(bytes).map(Self)
    }
}

/// `Goodbye`: the reason code the sender closes the connection with, from Lighthouse's
/// `GoodbyeReason` (1 client shutdown, 2 irrelevant network, 3 fault, 128 and up for the
/// peer-management reasons). Kept as the raw number: the sidecar only logs it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Goodbye(pub u64);

impl Goodbye {
    /// The body: one `u64`.
    pub fn encode(self) -> Vec<u8> {
        self.0.to_le_bytes().to_vec()
    }

    /// Reads a body.
    pub fn decode(bytes: &[u8]) -> Result<Self, Malformed> {
        u64_exact(bytes).map(Self)
    }
}

/// A body that is exactly one little-endian `u64`.
fn u64_exact(bytes: &[u8]) -> Result<u64, Malformed> {
    <[u8; 8]>::try_from(bytes)
        .map(u64::from_le_bytes)
        .map_err(|_| Malformed)
}

/// A little-endian `u64` at `offset`; the caller has checked the length.
fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(array(&bytes[offset..offset + 8]))
}

/// A fixed array from a slice of exactly that length; the caller has checked the length.
fn array<const N: usize>(bytes: &[u8]) -> [u8; N] {
    let mut out = [0; N];
    out.copy_from_slice(bytes);
    out
}

#[cfg(test)]
mod tests {
    use lighthouse_network::rpc::GoodbyeReason;
    use lighthouse_network::rpc::methods::{
        MetaDataV2, MetaDataV3, Ping as LighthousePing, StatusMessageV1, StatusMessageV2,
    };
    use ssz::{Decode, Encode};
    use types::{Epoch, Hash256, MainnetEthSpec, Slot};

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

    #[test]
    fn status_v2_round_trips_against_lighthouse_ssz() {
        let status = Status {
            earliest_available_slot: Some(9),
            ..status()
        };
        let ours = status.encode(2);

        let theirs = StatusMessageV2::from_ssz_bytes(&ours).unwrap();
        let back = Status::decode(&theirs.as_ssz_bytes(), 2).unwrap();

        assert_eq!(ours.len(), Status::V2_LEN);
        assert_eq!(theirs.head_slot, Slot::new(250));
        assert_eq!(theirs.earliest_available_slot, Slot::new(9));
        assert_eq!(back, status);
        assert!(StatusMessageV1::from_ssz_bytes(&ours).is_err());
        assert_eq!(Status::decode(&ours, 1), Err(Malformed));
    }

    /// Bit 3 of attnets and bit 1 of syncnets: byte i/8, bit i%8, as `Bitvector` lays them
    /// out.
    #[test]
    fn metadata_v2_and_v3_round_trip_against_lighthouse_ssz() {
        let metadata = MetaData {
            seq_number: 5,
            attnets: [0b1000, 0, 0, 0, 0, 0, 0, 0],
            syncnets: 0b10,
            custody_group_count: Some(8),
        };

        let v2 = metadata.encode(2);
        let theirs = MetaDataV2::<MainnetEthSpec>::from_ssz_bytes(&v2).unwrap();
        assert_eq!(v2.len(), MetaData::V2_LEN);
        assert_eq!(theirs.seq_number, 5);
        assert!(theirs.attnets.get(3).unwrap());
        assert!(!theirs.attnets.get(2).unwrap());
        assert!(theirs.syncnets.get(1).unwrap());
        assert_eq!(
            MetaData::decode(&theirs.as_ssz_bytes(), 2).unwrap(),
            MetaData {
                custody_group_count: None,
                ..metadata.clone()
            }
        );

        let v3 = metadata.encode(3);
        let theirs = MetaDataV3::<MainnetEthSpec>::from_ssz_bytes(&v3).unwrap();
        assert_eq!(v3.len(), MetaData::V3_LEN);
        assert_eq!(theirs.custody_group_count, 8);
        assert_eq!(MetaData::decode(&theirs.as_ssz_bytes(), 3).unwrap(), metadata);
        assert_eq!(MetaData::decode(&v3, 2), Err(Malformed));
    }

    #[test]
    fn ping_and_goodbye_round_trip_against_lighthouse_ssz() {
        let ping = LighthousePing::from_ssz_bytes(&Ping(0x0102_0304_0506_0708).encode()).unwrap();
        assert_eq!(ping.data, 0x0102_0304_0506_0708);
        assert_eq!(Ping::decode(&ping.as_ssz_bytes()), Ok(Ping(0x0102_0304_0506_0708)));

        let reason = GoodbyeReason::from_ssz_bytes(&Goodbye(129).encode()).unwrap();
        assert_eq!(reason, GoodbyeReason::TooManyPeers);
        assert_eq!(Goodbye::decode(&reason.as_ssz_bytes()), Ok(Goodbye(129)));

        assert_eq!(Ping::decode(&[1; 7]), Err(Malformed));
        assert_eq!(Goodbye::decode(&[1; 9]), Err(Malformed));
    }
}
