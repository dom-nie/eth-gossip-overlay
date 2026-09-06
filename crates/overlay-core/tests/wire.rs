//! The frame codec's public surface: round trips, the limits, the two carriers and the frozen
//! vectors corpus.

// A helper that cannot read its own fixture reports it by panicking, which is what its expects
// are; the tests themselves are already allowed theirs.
#![allow(clippy::expect_used)]

mod common;

use std::collections::BTreeMap;
use std::future::Future;
use std::path::Path;
use std::time::Duration;

use bytes::{BufMut, Bytes, BytesMut};
use overlay_core::msgid::MessageId;
use overlay_core::protocol::{MAX_BATCH_ENTRIES, MAX_FRAME_BYTES};
use overlay_core::wire::{
    BatchEntry, BatchFlags, Chunk, ChunkFlags, DecodeError, Frame, FrameType, Hello,
    MAX_MISSING_INDICES, MAX_PAYLOAD_BYTES, MAX_TOPIC_BYTES, Read, ReadError, RepairReq,
    RepairResp, read_frame, write_frame,
};
use proptest::prelude::*;
use tokio::io::AsyncWriteExt;

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

#[test]
fn unknown_flag_bits_are_ignored_and_defined_bits_round_trip() {
    for (name, frame) in common::samples() {
        let mut out = BytesMut::new();
        frame.encode(&mut out);

        let expected = match &frame {
            Frame::Batch { flags, .. } => flags.bits(),
            Frame::Chunk { flags, .. } => flags.bits(),
            _ => 0,
        };
        assert_eq!(
            out[1], expected,
            "{name} wrote a flag byte it does not define"
        );

        out[1] |= 1 << 7;
        let mut buf = out.freeze();

        assert_eq!(Frame::decode(&mut buf), Ok(frame), "{name} with bit 7 set");
    }
}

#[test]
fn batch_exceeding_max_batch_entries_is_over_limit() {
    assert_eq!(
        Frame::decode(&mut batch_of(MAX_BATCH_ENTRIES + 1)),
        Err(DecodeError::OverLimit("entries"))
    );
    assert!(matches!(
        Frame::decode(&mut batch_of(MAX_BATCH_ENTRIES)),
        Ok(Frame::Batch { .. })
    ));
}

fn batch_of(count: u16) -> Bytes {
    let mut out = BytesMut::new();
    out.put_u8(FrameType::Batch.id());
    out.put_u8(0);
    out.put_u16_le(count);
    for _ in 0..count {
        out.put_u16_le(1);
        out.put_u16_le(0);
    }
    out.freeze()
}

#[test]
fn chunk_exceeding_max_payload_bytes_is_over_limit() {
    assert_eq!(
        Frame::decode(&mut chunk_header(1024, MAX_PAYLOAD_BYTES as u32 + 1)),
        Err(DecodeError::OverLimit("data"))
    );
    assert_eq!(
        Frame::decode(&mut chunk_header(1024, MAX_PAYLOAD_BYTES as u32)),
        Err(DecodeError::Truncated),
        "a length at the maximum is read, not refused"
    );

    assert_eq!(
        Frame::decode(&mut chunk_header(MAX_PAYLOAD_BYTES as u32 + 1, 0)),
        Err(DecodeError::OverLimit("total_len"))
    );
    assert_eq!(
        Frame::decode(&mut chunk_header(MAX_PAYLOAD_BYTES as u32, 0)),
        Ok(Frame::Chunk {
            flags: ChunkFlags::NONE,
            chunk: Chunk {
                msg_id: MessageId([0; 20]),
                topic_id: 1,
                k: 8,
                m: 1,
                index: 3,
                total_len: MAX_PAYLOAD_BYTES as u32,
                data: Bytes::new(),
            },
        })
    );
}

/// A chunk frame carrying `data_len` as its length prefix but no data behind it, so a length past
/// the limit costs the test nothing to build and the decoder nothing to refuse.
fn chunk_header(total_len: u32, data_len: u32) -> Bytes {
    let mut out = BytesMut::new();
    out.put_u8(FrameType::Chunk.id());
    out.put_u8(0);
    out.put_slice(&[0u8; 20]);
    out.put_u16_le(1);
    out.put_u16_le(8);
    out.put_u16_le(1);
    out.put_u16_le(3);
    out.put_u32_le(total_len);
    out.put_u32_le(data_len);
    out.freeze()
}

#[test]
fn chunk_index_must_be_below_k_plus_m_and_k_at_least_one() {
    assert_eq!(
        Frame::decode(&mut striped(0, 2, 0)),
        Err(DecodeError::Invalid("k"))
    );
    assert_eq!(
        Frame::decode(&mut striped(4, 2, 6)),
        Err(DecodeError::Invalid("index"))
    );
    assert!(matches!(
        Frame::decode(&mut striped(4, 2, 5)),
        Ok(Frame::Chunk { .. })
    ));
}

fn striped(k: u16, m: u16, index: u16) -> Bytes {
    let mut out = BytesMut::new();
    Frame::Chunk {
        flags: ChunkFlags::NONE,
        chunk: Chunk {
            msg_id: MessageId([0; 20]),
            topic_id: 1,
            k,
            m,
            index,
            total_len: 2048,
            data: Bytes::from_static(b"chunk"),
        },
    }
    .encode(&mut out);
    out.freeze()
}

#[test]
fn whole_message_chunk_has_k1_m0_index0_and_len_equal_to_total_len() {
    let payload = Bytes::from_static(b"a whole gossipsub message");
    let frame = Frame::whole_message(MessageId([7; 20]), 9, payload.clone());

    let Frame::Chunk { flags, chunk } = &frame else {
        panic!("whole_message built {frame:?}");
    };
    assert_eq!(*flags, ChunkFlags::NONE);
    assert_eq!((chunk.k, chunk.m, chunk.index), (1, 0, 0));
    assert_eq!(chunk.total_len as usize, payload.len());
    assert_eq!(chunk.data, payload);
    assert!(chunk.is_whole());

    let mut out = BytesMut::new();
    Frame::Chunk {
        flags: ChunkFlags::NONE,
        chunk: Chunk {
            total_len: chunk.total_len + 1,
            ..chunk.clone()
        },
    }
    .encode(&mut out);

    assert_eq!(
        Frame::decode(&mut out.freeze()),
        Err(DecodeError::Invalid("whole"))
    );
    assert!(!striped_chunk().is_whole());
}

fn striped_chunk() -> Chunk {
    Chunk {
        msg_id: MessageId([7; 20]),
        topic_id: 9,
        k: 2,
        m: 0,
        index: 1,
        total_len: 2048,
        data: Bytes::from_static(b"half of it"),
    }
}

#[test]
fn vectors_corpus_decodes_to_expected_values_and_reencodes_byte_identically() {
    let mut on_disk = corpus();

    for (name, frame) in common::samples() {
        let Some(bytes) = on_disk.remove(name) else {
            panic!("tests/vectors/v1/{name}.bin is missing");
        };

        let mut buf = Bytes::from(bytes.clone());
        assert_eq!(Frame::decode(&mut buf), Ok(frame.clone()), "{name}");
        assert!(buf.is_empty(), "{name}: {} bytes left over", buf.len());

        let mut out = BytesMut::new();
        frame.encode(&mut out);
        assert_eq!(
            out.as_ref(),
            bytes.as_slice(),
            "{name} re-encodes differently"
        );
    }

    assert!(
        on_disk.is_empty(),
        "vector files no sample accounts for: {:?}",
        on_disk.keys().collect::<Vec<_>>()
    );
}

fn corpus() -> BTreeMap<String, Vec<u8>> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/v1");
    let mut files = BTreeMap::new();

    for entry in std::fs::read_dir(&dir).expect("tests/vectors/v1 is missing") {
        let path = entry.expect("vectors directory entry").path();
        if path.extension().is_some_and(|ext| ext == "bin") {
            let name = path
                .file_stem()
                .expect("vector file name")
                .to_string_lossy();
            let bytes = std::fs::read(&path).expect("vector file");
            files.insert(name.into_owned(), bytes);
        }
    }
    files
}

/// Every await here drives I/O that a broken codec would simply never finish. A bound turns that
/// into a failure instead of a suite that hangs (DECISIONS section 7).
async fn within<F: Future>(work: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(5), work)
        .await
        .expect("timed out")
}

#[tokio::test]
async fn stream_helpers_round_trip_two_frames_back_to_back() {
    let (mut writer, mut reader) = tokio::io::duplex(64 * 1024);
    let sent: Vec<Frame> = common::samples()
        .into_iter()
        .map(|(_, frame)| frame)
        .take(2)
        .collect();

    for frame in &sent {
        within(write_frame(&mut writer, frame))
            .await
            .expect("write");
    }

    for frame in sent {
        let read = within(read_frame(&mut reader, MAX_FRAME_BYTES)).await;

        assert!(matches!(read, Ok(Read::Frame(got)) if got == frame));
    }
}

#[tokio::test]
async fn read_frame_returns_unknown_for_an_unknown_type_and_the_next_frame_after_it() {
    let (mut writer, mut reader) = tokio::io::duplex(64 * 1024);
    let (_, hello) = common::samples().swap_remove(0);

    let body = [200u8, 0, 1, 2, 3];
    within(writer.write_all(&(body.len() as u32).to_le_bytes()))
        .await
        .expect("write");
    within(writer.write_all(&body)).await.expect("write");
    within(write_frame(&mut writer, &hello))
        .await
        .expect("write");

    let first = within(read_frame(&mut reader, MAX_FRAME_BYTES)).await;
    let second = within(read_frame(&mut reader, MAX_FRAME_BYTES)).await;

    assert!(matches!(first, Ok(Read::Unknown(200))));
    assert!(matches!(second, Ok(Read::Frame(got)) if got == hello));
}

#[tokio::test]
async fn read_frame_rejects_length_prefix_above_maximum_without_allocating() {
    let (mut writer, mut reader) = tokio::io::duplex(64);

    within(writer.write_all(&u32::MAX.to_le_bytes()))
        .await
        .expect("write");
    let read = within(read_frame(&mut reader, MAX_FRAME_BYTES)).await;

    assert!(matches!(read, Err(ReadError::TooLarge(u32::MAX))));
}
