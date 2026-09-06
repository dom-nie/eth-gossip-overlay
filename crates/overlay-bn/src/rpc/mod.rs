//! The handful of eth2 req/resp protocols the beacon node's peer manager needs answered
//! (§5.2 "Minimal req/resp", CL-N1).
//!
//! The wire format is Lighthouse's `SSZSnappyInboundCodec`
//! (`beacon_node/lighthouse_network/src/rpc/codec.rs`): a request is the uncompressed SSZ
//! length as an unsigned LEB128 varint followed by the SSZ in snappy's framing format, and a
//! response chunk is a result byte in front of the same. The protocols answered here carry no
//! context bytes (`ProtocolId::has_context_bytes` in `rpc/protocol.rs`).
//!
//! Answering `ResourceUnavailable` is not free on every protocol. For a request the beacon
//! node made itself on `BlocksByRange` or `BlocksByRoot` it is `PeerAction::Fatal`, an
//! immediate ban (`RPCError::ErrorResponse` in
//! `beacon_node/lighthouse_network/src/peer_manager/mod.rs:553-584`), and the Status echo
//! below is what puts the sidecar in `synced_peers()`, which is where range sync picks the
//! peers it asks. So the sidecar is a candidate for exactly the requests it refuses. What
//! keeps that from ending in a ban is trust: `--trusted-peers` exempts it from the score
//! change, and it must be in place before the first sync request. That is what the
//! `overlay_bn_trusted` gauge T-018 feeds, and the `OverlayNotTrustedByBn` alert on it
//! (Architecture.md §12), are for.

use std::collections::BTreeSet;
use std::io::{self, Read, Write};

use libp2p::StreamProtocol;
use libp2p::futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::request_response::Codec;
use overlay_core::topic::{Topic, TopicKind};
use snap::read::FrameDecoder;

use crate::rpc::msg::{Goodbye, Malformed, MetaData, Ping, Status};
use crate::rpc::proto::Protocol;
use crate::spec::SpecSnapshot;

pub mod msg;
pub mod proto;

/// Answers requests from the sidecar's own state and nothing else: no chain, no clock, no
/// channels, so the swarm loop calls it inline. Its two inputs are the beacon node's
/// subscriptions and the beacon node's spec.
#[derive(Clone, Debug)]
pub struct Responder {
    metadata: MetaData,
    /// Column subnets the beacon node subscribes to, before the range below is applied. A
    /// subnet is counted once however many fork digests it is subscribed under.
    columns: BTreeSet<u8>,
    /// The range Lighthouse accepts a custody group count in.
    custody_requirement: u64,
    number_of_custody_groups: u64,
}

impl Default for Responder {
    fn default() -> Self {
        Self {
            metadata: MetaData {
                custody_group_count: Some(SpecSnapshot::MAINNET.custody_requirement),
                ..MetaData::default()
            },
            columns: BTreeSet::new(),
            custody_requirement: SpecSnapshot::MAINNET.custody_requirement,
            number_of_custody_groups: SpecSnapshot::MAINNET.number_of_custody_groups,
        }
    }
}

impl Responder {
    /// A responder with empty bitfields at sequence number 0, on mainnet's spec until the
    /// beacon node's own arrives.
    pub fn new() -> Self {
        Self::default()
    }

    /// What a `MetaData` request is answered with right now.
    pub fn metadata(&self) -> &MetaData {
        &self.metadata
    }

    /// Recomputes the metadata from the beacon node's own subscriptions (the mirror's
    /// `advertised` set, D12): attestation and sync committee subnets become bits, and the
    /// distinct column subnets, however many fork digests each is subscribed under, are the
    /// custody group count, which is then held inside the range the beacon node's spec gives
    /// (`publish` below). The extra column topics the sidecar adds on its own are in `local`, not here,
    /// so they never inflate the count.
    pub fn set_subscriptions(&mut self, advertised: &BTreeSet<Topic>) {
        let mut attnets = [0; 8];
        let mut syncnets = 0;
        self.columns.clear();
        for topic in advertised {
            match *topic.kind() {
                TopicKind::Attestation(i) if usize::from(i) < 8 * attnets.len() => {
                    attnets[usize::from(i / 8)] |= 1 << (i % 8);
                }
                TopicKind::SyncCommittee(i) if i < SYNCNETS_BITS => syncnets |= 1 << i,
                TopicKind::DataColumnSidecar(subnet) => {
                    self.columns.insert(subnet);
                }
                _ => {}
            }
        }
        self.publish(attnets, syncnets);
    }

    /// Takes the custody group range from the beacon node's spec. Until this is called the
    /// range is mainnet's, which every network the sidecar has seen shares.
    pub fn set_spec(&mut self, spec: &SpecSnapshot) {
        self.custody_requirement = spec.custody_requirement;
        self.number_of_custody_groups = spec.number_of_custody_groups;
        self.publish(self.metadata.attnets, self.metadata.syncnets);
    }

    /// Puts the current inputs into the metadata a peer reads, moving the sequence number only
    /// when what it would read changed, because Lighthouse re-requests the metadata every time
    /// it sees the number rise.
    ///
    /// The custody group count is held inside the range the beacon node's spec gives, because
    /// `compute_peer_custody_groups` refuses a count outside
    /// `custody_requirement..=number_of_custody_groups` and `meta_data_response` answers that
    /// refusal with `goodbye_peer(.., GoodbyeReason::Fault, ..)`
    /// (`beacon_node/lighthouse_network/src/peer_manager/mod.rs`). A syncing beacon node
    /// subscribes to no column topic at all, so the honest count is below the floor whenever
    /// it matters most.
    fn publish(&mut self, attnets: [u8; 8], syncnets: u8) {
        let next = MetaData {
            seq_number: self.metadata.seq_number,
            attnets,
            syncnets,
            // Not `clamp`, which panics when a beacon node reports a floor above its ceiling.
            custody_group_count: Some(
                (self.columns.len() as u64)
                    .max(self.custody_requirement)
                    .min(self.number_of_custody_groups),
            ),
        };
        if next != self.metadata {
            self.metadata = MetaData {
                seq_number: next.seq_number + 1,
                ..next
            };
        }
    }

    /// The response to what the codec read off one stream.
    ///
    /// The protocol is decided on before the body: a protocol the sidecar registers but does
    /// not serve is answered `ResourceUnavailable` whatever arrived on it, because a body
    /// longer than the 92 bytes of the largest request the sidecar serves is routine there (a
    /// by-root request of three roots is 96 bytes) and `InvalidRequest` costs the sidecar
    /// peer score, while `ResourceUnavailable` costs nothing on the two protocols upstream
    /// exempts, `BlobsByRoot` and `DataColumnsByRoot` (`RPCError::ErrorResponse` in
    /// `beacon_node/lighthouse_network/src/peer_manager/mod.rs:559`). On the rest it is the
    /// module doc's `PeerAction::Fatal`, which is why trust has to be in place.
    pub fn answer(&self, request: &Request) -> Response {
        match request {
            (Protocol::Unsupported, _) => Response::ResourceUnavailable,
            (protocol, Ok(body)) => self.respond(*protocol, body),
            (_, Err(Malformed)) => Response::InvalidRequest,
        }
    }

    /// The response to `request`, received on `protocol`.
    ///
    /// A Goodbye is reported rather than answered: there is no chunk to write for it, and the
    /// caller closes the connection.
    ///
    /// Status is echoed. Lighthouse classifies a peer by comparing the peer's Status with its
    /// own in `remote_sync_type` (`beacon_node/network/src/sync/peer_sync_info.rs`): an equal
    /// `finalized_epoch` with a `head_slot` inside `SLOT_IMPORT_TOLERANCE` of its own head is
    /// `FullySynced`, so the beacon node's own fields are the one answer that makes the sidecar
    /// `Synced` by construction, at any slot and on any network, with no chain to consult.
    fn respond(&self, protocol: Protocol, request: &[u8]) -> Response {
        let body = match protocol {
            Protocol::StatusV1 => Status::decode(request, 1).map(|status| status.encode(1)),
            Protocol::StatusV2 => Status::decode(request, 2).map(|status| status.encode(2)),
            Protocol::PingV1 => {
                Ping::decode(request).map(|_| Ping(self.metadata.seq_number).encode())
            }
            Protocol::MetaDataV1 => Ok(self.metadata.encode(1)),
            Protocol::MetaDataV2 => Ok(self.metadata.encode(2)),
            Protocol::MetaDataV3 => Ok(self.metadata.encode(3)),
            Protocol::GoodbyeV1 => {
                return match Goodbye::decode(request) {
                    Ok(Goodbye(reason)) => Response::Goodbye(reason),
                    Err(Malformed) => Response::InvalidRequest,
                };
            }
            Protocol::Unsupported => return Response::ResourceUnavailable,
        };
        match body {
            Ok(body) => Response::Success(body),
            Err(Malformed) => Response::InvalidRequest,
        }
    }
}

/// What the codec reads off an inbound stream: the negotiated protocol and the request body,
/// or the reason the body was refused. A refusal is a value rather than an `io::Error` so the
/// behaviour still hands the loop a channel to answer `InvalidRequest` on, which is what
/// Lighthouse's outbound codec expects instead of a stream that dies.
pub type Request = (Protocol, Result<Vec<u8>, Malformed>);

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

/// The largest request body the sidecar accepts, uncompressed: a Status v2. Everything else
/// it serves is smaller, and nothing it serves is variable length.
pub const MAX_REQUEST_LEN: usize = Status::V2_LEN;

/// Under 128, so a legal length prefix is a single varint byte with the high bit clear and
/// [`body`] can refuse every other prefix by comparing one byte.
const _: () = assert!(MAX_REQUEST_LEN < 0x80);

/// What is read from an inbound stream before the rest is refused: the length prefix plus
/// `snap::raw::max_compress_len(MAX_REQUEST_LEN)`, which is `32 + n + n / 6` and is the bound
/// Lighthouse's inbound codec puts on the framed bytes of a request that long.
const MAX_REQUEST_BYTES: u64 = 1 + 32 + MAX_REQUEST_LEN as u64 + MAX_REQUEST_LEN as u64 / 6;

/// The result byte of a success chunk (`RpcResponse::as_u8` in `rpc/methods.rs`).
pub const SUCCESS: u8 = 0;
/// The result byte of an `InvalidRequest` error chunk (`RpcErrorResponse::as_u8`).
pub const INVALID_REQUEST: u8 = 1;
/// The result byte of a `ResourceUnavailable` error chunk.
pub const RESOURCE_UNAVAILABLE: u8 = 3;

/// One codec for every protocol id: the `Codec` trait hands it the negotiated protocol. Inbound
/// only; the outbound half refuses, which is what keeps the sidecar from ever asking the beacon
/// node for anything.
#[derive(Clone, Copy, Debug, Default)]
pub struct Eth2Codec;

impl Codec for Eth2Codec {
    type Protocol = StreamProtocol;
    type Request = Request;
    type Response = Response;

    /// The stream is read to its end, which the requester closes after writing the request
    /// (`upgrade_outbound` in `rpc/outbound.rs` sends and then closes), bounded by snappy's
    /// worst case for a legal request, so a peer that writes forever is cut off, not followed.
    async fn read_request<T>(&mut self, id: &StreamProtocol, io: &mut T) -> io::Result<Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut raw = Vec::new();
        io.take(MAX_REQUEST_BYTES).read_to_end(&mut raw).await?;
        Ok((proto::classify(id), body(&raw)))
    }

    async fn read_response<T>(&mut self, _: &StreamProtocol, _: &mut T) -> io::Result<Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        Err(io::ErrorKind::Unsupported.into())
    }

    async fn write_request<T>(
        &mut self,
        _: &StreamProtocol,
        _: &mut T,
        _: Request,
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

/// The body of a request: `<varint uncompressed length><snappy framed ssz>`, the framing
/// `SSZSnappyInboundCodec::decode` reads. An empty stream is an empty body, which is how
/// Lighthouse sends a `MetaData` request, whose length prefix it omits entirely. A prefix
/// past the largest legal request is refused before the frame decoder sees a byte.
fn body(raw: &[u8]) -> Result<Vec<u8>, Malformed> {
    let Some((&len, framed)) = raw.split_first() else {
        return Ok(Vec::new());
    };
    if usize::from(len) > MAX_REQUEST_LEN {
        return Err(Malformed);
    }
    let mut out = vec![0; usize::from(len)];
    FrameDecoder::new(framed)
        .read_exact(&mut out)
        .map_err(|_| Malformed)?;
    Ok(out)
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
    use libp2p::futures::io::Cursor;
    use libp2p::request_response::Codec;
    use overlay_core::topic::Topic;
    use proptest::prelude::*;

    use super::*;
    use crate::rpc::msg::{Ping, Status};
    use crate::rpc::proto::Protocol;
    use crate::spec::SpecSnapshot;

    fn topics(names: &[&str]) -> BTreeSet<Topic> {
        topics_at("6a95a1a9", names)
    }

    fn topics_at(digest: &str, names: &[&str]) -> BTreeSet<Topic> {
        names
            .iter()
            .map(|name| Topic::parse(&format!("/eth2/{digest}/{name}/ssz_snappy")).unwrap())
            .collect()
    }

    const PING: StreamProtocol = StreamProtocol::new("/eth2/beacon_chain/req/ping/1/ssz_snappy");
    const STATUS_V2: StreamProtocol =
        StreamProtocol::new("/eth2/beacon_chain/req/status/2/ssz_snappy");
    const METADATA_V2: StreamProtocol =
        StreamProtocol::new("/eth2/beacon_chain/req/metadata/2/ssz_snappy");

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
            custody_group_count: Some(SpecSnapshot::MAINNET.custody_requirement),
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
    ///
    /// What is counted is the subnet, not the topic. Across a fork the beacon node holds both
    /// digests' topics at once, joining the next fork's two slots early and leaving the old
    /// one two epochs late (`beacon_node/network/src/service.rs`), and counting topics would
    /// double the number it reports for those two epochs.
    #[test]
    fn custody_group_count_counts_only_columns_the_bn_subscribes_to() {
        let columns: Vec<String> = (0..128)
            .map(|i| format!("data_column_sidecar_{i}"))
            .collect();
        let names: Vec<&str> = columns.iter().map(String::as_str).collect();
        let mut all = Responder::new();
        let mut none = Responder::new();
        let mut forking = Responder::new();
        let two_digests: BTreeSet<Topic> = topics_at("6a95a1a9", &names[..8])
            .union(&topics_at("f0e1d2c3", &names[..8]))
            .cloned()
            .collect();

        all.set_subscriptions(&topics(&names));
        none.set_subscriptions(&topics(&["beacon_block"]));
        forking.set_subscriptions(&two_digests);

        assert_eq!(all.metadata().custody_group_count, Some(128));
        assert_eq!(none.metadata().custody_group_count, Some(4));
        assert_eq!(forking.metadata().custody_group_count, Some(8));
        assert_eq!(all.metadata().attnets, [0; 8]);
    }

    /// Lighthouse's peer manager refuses a custody group count outside
    /// `custody_requirement..=number_of_custody_groups` and says goodbye to the peer for it
    /// (`compute_peer_custody_groups` and `meta_data_response` in
    /// `beacon_node/lighthouse_network/src/peer_manager/mod.rs`), so what the sidecar reports
    /// is held inside that range: a beacon node that is syncing subscribes to nothing, and one
    /// that custodies the minimum subscribes to fewer topics than the minimum count.
    #[test]
    fn custody_group_count_stays_inside_the_range_lighthouse_accepts() {
        let mut responder = Responder::new();
        let floor = SpecSnapshot::MAINNET.custody_requirement;

        let syncing = responder.metadata().custody_group_count;
        responder.set_subscriptions(&topics(&["data_column_sidecar_0"]));
        let one_column = responder.metadata().custody_group_count;
        responder.set_spec(&SpecSnapshot {
            custody_requirement: 1,
            number_of_custody_groups: 1,
            ..SpecSnapshot::MAINNET
        });

        assert_eq!(syncing, Some(floor));
        assert_eq!(one_column, Some(floor));
        assert_eq!(responder.metadata().custody_group_count, Some(1));
    }

    /// The sequence number tracks what a peer would read, whichever input moved it: a spec
    /// that changes the reported count bumps it, and one that does not leaves it alone.
    #[test]
    fn seq_number_follows_the_spec_as_well_as_the_subscriptions() {
        let mut responder = Responder::new();
        responder.set_subscriptions(&topics(&["data_column_sidecar_0"]));
        let after_subscriptions = responder.metadata().seq_number;

        responder.set_spec(&SpecSnapshot::MAINNET);
        let unchanged = responder.metadata().seq_number;
        responder.set_spec(&SpecSnapshot {
            custody_requirement: 1,
            ..SpecSnapshot::MAINNET
        });

        assert_eq!(unchanged, after_subscriptions);
        assert_eq!(responder.metadata().seq_number, after_subscriptions + 1);
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

    /// The request framing without the result byte a response carries.
    fn request(body: &[u8]) -> Vec<u8> {
        chunk(SUCCESS, body).unwrap()[1..].to_vec()
    }

    fn read(id: &StreamProtocol, bytes: &[u8]) -> (Protocol, Result<Vec<u8>, Malformed>) {
        block_on(Eth2Codec.read_request(id, &mut Cursor::new(bytes.to_vec())))
            .expect("a request is read to a result, never an io error")
    }

    /// Nothing a peer puts on the wire reaches a panic. The length prefix is checked against
    /// the largest legal request before anything is decompressed, a frame that runs out or
    /// disagrees with its prefix is refused, and a `MetaData` request, which Lighthouse sends
    /// as an empty stream, still reads.
    #[test]
    fn malformed_request_gets_invalid_request_not_a_panic() {
        let status = status().encode(2);
        let good = request(&status);
        let responder = Responder::new();
        let answer = |id: &StreamProtocol, bytes: &[u8]| responder.answer(&read(id, bytes));

        let short = request(&status[..Status::V1_LEN]);
        assert_eq!(read(&STATUS_V2, &good), (Protocol::StatusV2, Ok(status)));
        assert_eq!(
            read(&METADATA_V2, &[]),
            (Protocol::MetaDataV2, Ok(Vec::new()))
        );
        for bytes in [
            // The frame runs out before the prefix is satisfied.
            good[..good.len() - 4].to_vec(),
            // The prefix promises a v2 body and the frame carries a v1 one.
            [varint(Status::V2_LEN), short[1..].to_vec()].concat(),
            // One byte past the largest legal request, and a prefix promising megabytes.
            [varint(Status::V2_LEN + 1), good[1..].to_vec()].concat(),
            varint(1 << 20),
            Vec::new(),
        ] {
            assert_eq!(
                answer(&STATUS_V2, &bytes),
                Response::InvalidRequest,
                "{bytes:02x?}"
            );
        }

        proptest!(|(bytes in proptest::collection::vec(any::<u8>(), 0..256))| {
            for id in proto::all() {
                let response = answer(&id, &bytes);
                prop_assert!(plausible(proto::classify(&id), &response), "{id} {response:?}");
            }
        });
    }

    /// What a response to random bytes may be: an error, or a success whose body is the one
    /// its protocol calls for. A `Goodbye` only ever comes from the goodbye protocol.
    fn plausible(protocol: Protocol, response: &Response) -> bool {
        match (protocol, response) {
            (Protocol::StatusV1, Response::Success(body)) => body.len() == Status::V1_LEN,
            (Protocol::StatusV2, Response::Success(body)) => body.len() == Status::V2_LEN,
            (Protocol::PingV1, Response::Success(body)) => body.len() == 8,
            (Protocol::GoodbyeV1, Response::Goodbye(_)) => true,
            (_, Response::Goodbye(_)) => false,
            _ => true,
        }
    }

    /// Goodbye is read, not answered: the reason goes to the swarm loop, which logs it and
    /// closes the connection.
    #[test]
    fn goodbye_is_reported_with_its_reason() {
        let responder = Responder::new();

        let farewell = responder.respond(Protocol::GoodbyeV1, &Goodbye(129).encode());

        assert_eq!(farewell, Response::Goodbye(129));
        assert_eq!(
            responder.respond(Protocol::GoodbyeV1, &[1, 2, 3]),
            Response::InvalidRequest
        );
    }

    /// A body longer than anything the sidecar serves, on a protocol it does not serve: a
    /// by-root request of three roots is 96 bytes and routine. The protocol decides, not the
    /// body, because `ResourceUnavailable` on `BlobsByRoot` and `DataColumnsByRoot` carries no
    /// peer action at all while `InvalidRequest` is a `PeerAction::LowToleranceError`
    /// (`RPCError::ErrorResponse` in
    /// `beacon_node/lighthouse_network/src/peer_manager/mod.rs:559`).
    #[test]
    fn an_unserved_protocol_is_unavailable_whatever_its_body_was() {
        let id = StreamProtocol::new("/eth2/beacon_chain/req/blob_sidecars_by_root/1/ssz_snappy");
        let long = read(&id, &request(&[0xab; 96]));

        assert_eq!(long, (Protocol::Unsupported, Err(Malformed)));
        assert_eq!(
            Responder::new().answer(&long),
            Response::ResourceUnavailable
        );
        assert_eq!(
            Responder::new().answer(&(Protocol::PingV1, Err(Malformed))),
            Response::InvalidRequest
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
        let response = Responder::new().answer(&(protocol, Ok(request)));

        assert_eq!(protocol, Protocol::Unsupported);
        assert_eq!(response, Response::ResourceUnavailable);
        assert_eq!(proto::classify(&PING), Protocol::PingV1);
    }
}
