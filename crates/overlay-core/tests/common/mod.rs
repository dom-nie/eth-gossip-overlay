//! One representative value per vectors file, shared by the round-trip and truncation tests,
//! the corpus test and `examples/gen_vectors.rs`. A variant added here is covered by all four
//! at once, which is the only way the corpus stays complete.

use bytes::Bytes;
use overlay_core::msgid::MessageId;
use overlay_core::wire::{BatchEntry, BatchFlags, Chunk, ChunkFlags, Frame, Hello, RepairReq, RepairResp};

/// The name of each `tests/vectors/v1/<name>.bin` and the frame it holds. The values are frozen:
/// the corpus is what proves a later release still decodes this one byte for byte, so edit this
/// list only to add a variant.
pub fn samples() -> Vec<(&'static str, Frame)> {
    let msg_id = MessageId(*b"0123456789abcdefghij");
    let block_root: [u8; 32] = std::array::from_fn(|i| i as u8);

    vec![
        (
            "hello",
            Frame::Hello(Hello {
                minor: 3,
                features: 0b101,
                max_frame_bytes: 1_048_576,
                max_batch_entries: 512,
                instance_id: 0x0123_4567_89ab_cdef,
                hostname: "bn-eu-07".into(),
                region: "eu".into(),
                site: "fra1".into(),
                software_version: "0.1.0".into(),
                topics: vec![
                    (1, "/eth2/6a95a1a9/beacon_block/ssz_snappy".into()),
                    (2, "/eth2/6a95a1a9/data_column_sidecar_3/ssz_snappy".into()),
                ],
            }),
        ),
        (
            "subs",
            Frame::Subs {
                bitmap: Bytes::from_static(&[0b1010_1010, 0x00, 0xff, 0x01]),
            },
        ),
        (
            "topic_add",
            Frame::TopicAdd {
                id: 7,
                topic: "/eth2/6a95a1a9/beacon_attestation_11/ssz_snappy".into(),
            },
        ),
        (
            "batch",
            Frame::Batch {
                flags: BatchFlags::NONE,
                entries: vec![
                    BatchEntry {
                        topic_id: 7,
                        payload: Bytes::from_static(b"attestation on subnet 11"),
                    },
                    BatchEntry {
                        topic_id: 9,
                        payload: Bytes::from_static(b"sync committee message"),
                    },
                ],
            },
        ),
        (
            "batch_relay",
            Frame::Batch {
                flags: BatchFlags::RELAY,
                entries: vec![BatchEntry {
                    topic_id: 7,
                    payload: Bytes::from_static(b"one entry for the remote region"),
                }],
            },
        ),
        (
            "chunk",
            Frame::Chunk {
                flags: ChunkFlags::NONE,
                chunk: striped(msg_id),
            },
        ),
        (
            "chunk_forwarded",
            Frame::Chunk {
                flags: ChunkFlags::FORWARDED,
                chunk: striped(msg_id),
            },
        ),
        (
            "chunk_whole",
            Frame::whole_message(msg_id, 7, Bytes::from_static(b"a whole gossipsub message")),
        ),
        (
            "repair_req_missing",
            Frame::RepairReq(RepairReq::Missing {
                msg_id,
                missing: vec![0, 1, 5, 8],
            }),
        ),
        (
            "repair_req_column",
            Frame::RepairReq(RepairReq::Column {
                block_root,
                index: 42,
            }),
        ),
        (
            "repair_resp_not_found",
            Frame::RepairResp(RepairResp::NotFound),
        ),
        (
            "repair_resp_chunks",
            Frame::RepairResp(RepairResp::Chunks(vec![
                striped(msg_id),
                Chunk {
                    msg_id: MessageId(*b"jihgfedcba9876543210"),
                    topic_id: 7,
                    k: 1,
                    m: 0,
                    index: 0,
                    total_len: 25,
                    data: Bytes::from_static(b"a whole gossipsub message"),
                },
            ])),
        ),
    ]
}

fn striped(msg_id: MessageId) -> Chunk {
    Chunk {
        msg_id,
        topic_id: 2,
        k: 8,
        m: 1,
        index: 3,
        total_len: 16_384,
        data: Bytes::from_static(b"chunk three of a data column sidecar"),
    }
}
