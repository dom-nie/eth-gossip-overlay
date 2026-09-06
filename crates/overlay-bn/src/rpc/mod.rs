//! The handful of eth2 req/resp protocols the beacon node's peer manager needs answered
//! (§5.2 "Minimal req/resp", CL-N1).
//!
//! The wire format is Lighthouse's `SSZSnappyInboundCodec`
//! (`beacon_node/lighthouse_network/src/rpc/codec.rs`): a request is the uncompressed SSZ
//! length as an unsigned LEB128 varint followed by the SSZ in snappy's framing format, and a
//! response chunk is a result byte in front of the same. The protocols answered here carry no
//! context bytes (`ProtocolId::has_context_bytes` in `rpc/protocol.rs`).

use std::collections::BTreeSet;
use std::io::{self, Write};

use libp2p::StreamProtocol;
use libp2p::futures::{AsyncWrite, AsyncWriteExt};
use libp2p::request_response::Codec;
use overlay_core::topic::{Topic, TopicKind};

use crate::rpc::msg::{Malformed, MetaData, Ping, Status};
use crate::rpc::proto::Protocol;

pub mod msg;
pub mod proto;

/// Answers requests from the sidecar's own state and nothing else: no chain, no clock, no
/// channels, so the swarm loop calls it inline.
#[derive(Clone, Debug, Default)]
pub struct Responder {
    metadata: MetaData,
}

impl Responder {
    /// A responder with empty bitfields at sequence number 0.
    pub fn new() -> Self {
        Self::default()
    }

    /// What a `MetaData` request is answered with right now.
    pub fn metadata(&self) -> &MetaData {
        &self.metadata
    }

    /// Recomputes the metadata from the beacon node's own subscriptions (the mirror's
    /// `advertised` set, D12): attestation and sync committee subnets become bits, the data
    /// column topics are counted as custody groups. The extra column topics the sidecar adds
    /// on its own are in `local`, not here, so they never inflate the count. The sequence
    /// number moves only when the result differs, because Lighthouse re-requests the metadata
    /// every time it sees the number rise.
    pub fn set_subscriptions(&mut self, advertised: &BTreeSet<Topic>) {
        let mut next = MetaData {
            custody_group_count: Some(0),
            ..MetaData::default()
        };
        for topic in advertised {
            match *topic.kind() {
                TopicKind::Attestation(i) if usize::from(i) < 8 * next.attnets.len() => {
                    next.attnets[usize::from(i / 8)] |= 1 << (i % 8);
                }
                TopicKind::SyncCommittee(i) if i < SYNCNETS_BITS => next.syncnets |= 1 << i,
                TopicKind::DataColumnSidecar(_) => {
                    next.custody_group_count = next.custody_group_count.map(|n| n + 1);
                }
                _ => {}
            }
        }
        next.seq_number = self.metadata.seq_number;
        if next != self.metadata {
            next.seq_number += 1;
            self.metadata = next;
        }
    }

    /// The response to `request`, received on `protocol`.
    ///
    /// Status is echoed. Lighthouse classifies a peer by comparing the peer's Status with its
    /// own in `remote_sync_type` (`beacon_node/network/src/sync/peer_sync_info.rs`): an equal
    /// `finalized_epoch` with a `head_slot` inside `SLOT_IMPORT_TOLERANCE` of its own head is
    /// `FullySynced`, so the beacon node's own fields are the one answer that makes the sidecar
    /// `Synced` by construction, at any slot and on any network, with no chain to consult.
    pub fn respond(&self, protocol: Protocol, request: &[u8]) -> Response {
        let body = match protocol {
            Protocol::StatusV1 => Status::decode(request, 1).map(|status| status.encode(1)),
            Protocol::StatusV2 => Status::decode(request, 2).map(|status| status.encode(2)),
            Protocol::PingV1 => {
                Ping::decode(request).map(|_| Ping(self.metadata.seq_number).encode())
            }
            Protocol::MetaDataV1 => Ok(self.metadata.encode(1)),
            Protocol::MetaDataV2 => Ok(self.metadata.encode(2)),
            Protocol::MetaDataV3 => Ok(self.metadata.encode(3)),
            _ => return Response::ResourceUnavailable,
        };
        match body {
            Ok(body) => Response::Success(body),
            Err(Malformed) => Response::InvalidRequest,
        }
    }
}

/// What the sidecar sends back for one request. `Goodbye` is the peer's own farewell; nothing
/// is written for it and the loop closes the connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Response {
    /// A success chunk carrying the SSZ body.
    Success(Vec<u8>),
    /// Result code 1: the body did not decode.
    InvalidRequest,
    /// Result code 3: a protocol the sidecar registers but does not serve.
    ResourceUnavailable,
    /// The peer sent Goodbye with this reason; there is no response to write.
    Goodbye(u64),
}

/// `syncnets` is SSZ `Bitvector[4]`; a set bit past that fails Lighthouse's decode.
const SYNCNETS_BITS: u8 = 4;

/// The result byte of a success chunk (`RpcResponse::as_u8` in `rpc/methods.rs`).
pub const SUCCESS: u8 = 0;
/// The result byte of an `InvalidRequest` error chunk (`RpcErrorResponse::as_u8`).
pub const INVALID_REQUEST: u8 = 1;
/// The result byte of a `ServerError` error chunk; listed so the codes read as a set.
pub const SERVER_ERROR: u8 = 2;
/// The result byte of a `ResourceUnavailable` error chunk.
pub const RESOURCE_UNAVAILABLE: u8 = 3;

/// One codec for every protocol id: the `Codec` trait hands it the negotiated protocol. Inbound
/// only; the outbound half refuses, which is what keeps the sidecar from ever asking the beacon
/// node for anything.
#[derive(Clone, Copy, Debug, Default)]
pub struct Eth2Codec;

impl Codec for Eth2Codec {
    type Protocol = StreamProtocol;
    type Request = Vec<u8>;
    type Response = Response;

    async fn read_request<T>(&mut self, _: &StreamProtocol, _: &mut T) -> io::Result<Vec<u8>>
    where
        T: libp2p::futures::AsyncRead + Unpin + Send,
    {
        Err(io::ErrorKind::Unsupported.into())
    }

    async fn read_response<T>(&mut self, _: &StreamProtocol, _: &mut T) -> io::Result<Response>
    where
        T: libp2p::futures::AsyncRead + Unpin + Send,
    {
        Err(io::ErrorKind::Unsupported.into())
    }

    async fn write_request<T>(
        &mut self,
        _: &StreamProtocol,
        _: &mut T,
        _: Vec<u8>,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        Err(io::ErrorKind::Unsupported.into())
    }

    /// Exactly one chunk; the behaviour closes the write side after it, which is the stream
    /// end Lighthouse expects after a single response.
    async fn write_response<T>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
        response: Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let (code, payload) = match response {
            Response::Success(payload) => (SUCCESS, payload),
            Response::InvalidRequest => (INVALID_REQUEST, b"invalid request".to_vec()),
            Response::ResourceUnavailable => {
                (RESOURCE_UNAVAILABLE, b"resource unavailable".to_vec())
            }
            Response::Goodbye(_) => return Ok(()),
        };
        io.write_all(&chunk(code, &payload)?).await
    }
}

/// `<code><varint len(payload)><snappy framed payload>`. An error chunk's payload is the
/// message as raw bytes, which is how Lighthouse reads its SSZ byte list.
fn chunk(code: u8, payload: &[u8]) -> io::Result<Vec<u8>> {
    let mut out = vec![code];
    out.extend_from_slice(&varint(payload.len()));
    let mut encoder = snap::write::FrameEncoder::new(Vec::new());
    encoder.write_all(payload)?;
    encoder.flush()?;
    out.extend_from_slice(encoder.get_ref());
    Ok(out)
}

/// Unsigned LEB128, the length prefix `unsigned_varint` writes for Lighthouse.
fn varint(mut value: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(2);
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
    out
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use libp2p::StreamProtocol;
    use libp2p::futures::executor::block_on;
    use libp2p::request_response::Codec;
    use overlay_core::topic::Topic;

    use super::*;
    use crate::rpc::msg::{Ping, Status};
    use crate::rpc::proto::Protocol;

    fn topics(names: &[&str]) -> BTreeSet<Topic> {
        names
            .iter()
            .map(|name| Topic::parse(&format!("/eth2/6a95a1a9/{name}/ssz_snappy")).unwrap())
            .collect()
    }

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
    fn status_response_echoes_the_request_fields() {
        let request = status().encode(1);

        let response = Responder::new().respond(Protocol::StatusV1, &request);

        assert_eq!(response, Response::Success(request));
    }

    #[test]
    fn status_v2_echoes_earliest_available_slot_and_v1_omits_it() {
        let status = Status {
            earliest_available_slot: Some(9),
            ..status()
        };
        let responder = Responder::new();

        let v2 = responder.respond(Protocol::StatusV2, &status.encode(2));
        let v1 = responder.respond(Protocol::StatusV1, &status.encode(1));

        assert_eq!(v2, Response::Success(status.encode(2)));
        assert_eq!(v1, Response::Success(status.encode(1)));
        assert_eq!(status.encode(1).len(), Status::V1_LEN);
        assert_eq!(
            Status::decode(&status.encode(1), 1)
                .unwrap()
                .earliest_available_slot,
            None
        );
        assert_eq!(
            responder.respond(Protocol::StatusV1, &status.encode(2)),
            Response::InvalidRequest
        );
    }

    #[test]
    fn ping_reply_carries_the_current_metadata_seq_number() {
        let responder = Responder::new();

        let reply = responder.respond(Protocol::PingV1, &Ping(41).encode());

        assert_eq!(responder.metadata().seq_number, 0);
        assert_eq!(reply, Response::Success(Ping(0).encode()));
        assert_eq!(
            responder.respond(Protocol::PingV1, &[1, 2, 3]),
            Response::InvalidRequest
        );
    }

    #[test]
    fn metadata_attnets_and_syncnets_follow_the_advertised_set() {
        let mut responder = Responder::new();

        responder.set_subscriptions(&topics(&["beacon_attestation_3", "sync_committee_1"]));

        let expected = MetaData {
            seq_number: 1,
            attnets: [0b1000, 0, 0, 0, 0, 0, 0, 0],
            syncnets: 0b10,
            custody_group_count: Some(0),
        };
        assert_eq!(responder.metadata(), &expected);
        assert_eq!(
            responder.respond(Protocol::MetaDataV2, &[]),
            Response::Success(expected.encode(2))
        );
        assert_eq!(
            responder.respond(Protocol::MetaDataV3, &[]),
            Response::Success(expected.encode(3))
        );
    }

    /// The mirror's extra column topics live in `local`, never in `advertised`, so a
    /// responder fed the advertised set alone counts only what the beacon node subscribed to.
    #[test]
    fn custody_group_count_counts_only_columns_the_bn_subscribes_to() {
        let columns: Vec<String> = (0..128)
            .map(|i| format!("data_column_sidecar_{i}"))
            .collect();
        let names: Vec<&str> = columns.iter().map(String::as_str).collect();
        let mut all = Responder::new();
        let mut none = Responder::new();

        all.set_subscriptions(&topics(&names));
        none.set_subscriptions(&topics(&["beacon_block"]));

        assert_eq!(all.metadata().custody_group_count, Some(128));
        assert_eq!(none.metadata().custody_group_count, Some(0));
        assert_eq!(all.metadata().attnets, [0; 8]);
    }

    #[test]
    fn seq_number_increments_only_when_metadata_changes() {
        let mut responder = Responder::new();
        let set = topics(&["beacon_attestation_3"]);

        responder.set_subscriptions(&set);
        responder.set_subscriptions(&set);
        let after_repeat = responder.metadata().seq_number;
        responder.set_subscriptions(&topics(&["beacon_attestation_3", "sync_committee_1"]));
        let after_change = responder.metadata().seq_number;
        responder.set_subscriptions(&BTreeSet::new());

        assert_eq!(after_repeat, 1);
        assert_eq!(after_change, 2);
        assert_eq!(responder.metadata().seq_number, 3);
        assert_eq!(
            responder.respond(Protocol::PingV1, &Ping(0).encode()),
            Response::Success(Ping(3).encode())
        );
    }

    /// A well-formed BlocksByRange v2 request (start slot, count, step) on a registered
    /// protocol the sidecar does not serve.
    #[test]
    fn unsupported_protocol_request_gets_resource_unavailable() {
        let id = StreamProtocol::new("/eth2/beacon_chain/req/beacon_blocks_by_range/2/ssz_snappy");
        let mut request = Vec::new();
        for field in [0u64, 10, 1] {
            request.extend_from_slice(&field.to_le_bytes());
        }

        let protocol = proto::classify(&id);
        let response = Responder::new().respond(protocol, &request);

        assert_eq!(protocol, Protocol::Unsupported);
        assert_eq!(response, Response::ResourceUnavailable);
        assert_eq!(proto::classify(&PING), Protocol::PingV1);
    }
}
