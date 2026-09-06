//! The frame codec's public surface: round trips, the limits, the two carriers and the frozen
//! vectors corpus.

mod common;

use bytes::{Bytes, BytesMut};
use overlay_core::msgid::MessageId;
use overlay_core::protocol::MAX_BATCH_ENTRIES;
use overlay_core::wire::{
    BatchEntry, BatchFlags, Chunk, ChunkFlags, DecodeError, Frame, FrameType, Hello,
    MAX_MISSING_INDICES, MAX_PAYLOAD_BYTES, MAX_TOPIC_BYTES, RepairReq, RepairResp,
};
use proptest::prelude::*;

#[test]
fn round_trip_each_variant_with_representative_values() {
    for (name, frame) in common::samples() {
        let mut out = BytesMut::new();
        frame.encode(&mut out);

        let mut buf = out.freeze();
        let decoded = Frame::decode(&mut buf);

        assert_eq!(decoded, Ok(frame), "{name}");
        assert!(buf.is_empty(), "{name}: {} bytes left over", buf.len());
    }
}

fn msg_id() -> impl Strategy<Value = MessageId> {
    any::<[u8; 20]>().prop_map(MessageId)
}

fn payload(max: usize) -> impl Strategy<Value = Bytes> {
    prop::collection::vec(any::<u8>(), 0..=max).prop_map(Bytes::from)
}

fn text(max: usize) -> impl Strategy<Value = String> {
    prop::collection::vec(prop::char::range('a', 'z'), 0..=max)
        .prop_map(|chars| chars.into_iter().collect())
}

fn chunk() -> impl Strategy<Value = Chunk> {
    (
        msg_id(),
        any::<u16>(),
        1u16..=64,
        0u16..=16,
        payload(512),
        0u32..=MAX_PAYLOAD_BYTES as u32,
    )
        .prop_flat_map(|(msg_id, topic_id, k, m, data, total_len)| {
            (0u16..k + m).prop_map(move |index| Chunk {
                msg_id,
                topic_id,
                k,
                m,
                index,
                total_len: if k == 1 && m == 0 {
                    data.len() as u32
                } else {
                    total_len
                },
                data: data.clone(),
            })
        })
}

fn frame() -> impl Strategy<Value = Frame> {
    prop_oneof![
        (
            (
                any::<u16>(),
                any::<u64>(),
                any::<u32>(),
                any::<u16>(),
                any::<u64>()
            ),
            (
                text(64),
                text(64),
                text(64),
                text(64),
                prop::collection::vec((any::<u16>(), text(MAX_TOPIC_BYTES)), 0..=16),
            ),
        )
            .prop_map(|(numbers, strings)| {
                let (minor, features, max_frame_bytes, max_batch_entries, instance_id) = numbers;
                let (hostname, region, site, software_version, topics) = strings;
                Frame::Hello(Hello {
                    minor,
                    features,
                    max_frame_bytes,
                    max_batch_entries,
                    instance_id,
                    hostname,
                    region,
                    site,
                    software_version,
                    topics,
                })
            }),
        payload(1024).prop_map(|bitmap| Frame::Subs { bitmap }),
        (any::<u16>(), text(MAX_TOPIC_BYTES)).prop_map(|(id, topic)| Frame::TopicAdd { id, topic }),
        (
            prop_oneof![Just(BatchFlags::NONE), Just(BatchFlags::RELAY)],
            prop::collection::vec(
                (any::<u16>(), payload(256))
                    .prop_map(|(topic_id, payload)| BatchEntry { topic_id, payload }),
                0..=MAX_BATCH_ENTRIES as usize,
            ),
        )
            .prop_map(|(flags, entries)| Frame::Batch { flags, entries }),
        (
            prop_oneof![Just(ChunkFlags::NONE), Just(ChunkFlags::FORWARDED)],
            chunk(),
        )
            .prop_map(|(flags, chunk)| Frame::Chunk { flags, chunk }),
        (
            msg_id(),
            prop::collection::vec(any::<u16>(), 0..=MAX_MISSING_INDICES),
        )
            .prop_map(|(msg_id, missing)| Frame::RepairReq(RepairReq::Missing { msg_id, missing })),
        (any::<[u8; 32]>(), any::<u8>()).prop_map(|(block_root, index)| Frame::RepairReq(
            RepairReq::Column { block_root, index }
        )),
        Just(Frame::RepairResp(RepairResp::NotFound)),
        prop::collection::vec(chunk(), 0..=8)
            .prop_map(|chunks| Frame::RepairResp(RepairResp::Chunks(chunks))),
    ]
}

proptest! {
    #[test]
    fn round_trip_property_all_variants(frame in frame()) {
        let mut out = BytesMut::new();
        frame.encode(&mut out);

        let mut buf = out.freeze();
        let decoded = Frame::decode(&mut buf);

        prop_assert_eq!(decoded, Ok(frame));
        prop_assert!(buf.is_empty());
    }
}

#[test]
fn truncated_input_is_truncated_error_for_every_variant() {
    for (name, frame) in common::samples() {
        let mut out = BytesMut::new();
        frame.encode(&mut out);
        let full = out.freeze();

        for len in 0..full.len() {
            let mut buf = full.slice(..len);

            assert_eq!(
                Frame::decode(&mut buf),
                Err(DecodeError::Truncated),
                "{name} cut to {len} of {} bytes",
                full.len()
            );
        }
    }
}

#[test]
fn unknown_and_reserved_frame_types_are_unknown_type() {
    for type_byte in [0u8, FrameType::Have.id(), 9, 255] {
        let mut buf = Bytes::from(vec![type_byte, 0, 1, 2, 3]);

        assert_eq!(
            Frame::decode(&mut buf),
            Err(DecodeError::UnknownType(type_byte))
        );
    }
}
