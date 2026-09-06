//! The frame codec's public surface: round trips, the limits, the two carriers and the frozen
//! vectors corpus.

mod common;

use bytes::BytesMut;
use overlay_core::wire::Frame;

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
