//! Splitting a large message into fixed-size chunks and adding Reed-Solomon parity (§5.4).
//!
//! §14 rejected RLNC: its coordination-free chunk selection and recoding pay off on a lossy
//! multi-hop mesh of strangers, and this overlay is one or two hops between hosts that trust
//! each other and know the whole membership, so all that would remain is the cost, a Gaussian
//! elimination and a rank check on every message before it can be delivered. Systematic
//! Reed-Solomon buys the same resilience to a lost chunk while the common case, every data
//! chunk present, is a concatenation that never calls the codec.

use bytes::{Bytes, BytesMut};
use reed_solomon_simd::{ReedSolomonDecoder, ReedSolomonEncoder};

use crate::wire::MAX_PAYLOAD_BYTES;

/// Every shape the codec refuses is one [`Params::for_len`] already ruled out.
const CODEC_TAKES: &str = "Params::for_len proved the codec takes this split";

/// How one message is split: `k` data chunks of `chunk_bytes` each, `m` parity chunks after
/// them, and the payload's own length so a receiver can drop the padding off the last data
/// chunk. The fields are the ones a [`crate::wire::Chunk`] header carries, in the same widths,
/// so a receiver rebuilds the parameters from any chunk that reaches it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    /// Data chunks, at least one.
    pub k: u16,
    /// Parity chunks, at least one.
    pub m: u16,
    /// The length of every chunk, padding included.
    pub chunk_bytes: usize,
    /// The payload's length before padding.
    pub total_len: u32,
}

impl Params {
    /// The split a payload of `total_len` gets: `k` covers it at `chunk_bytes` apiece and `m` is
    /// `parity_ratio` of that, rounded up, never below one so every message can survive losing a
    /// chunk.
    ///
    /// `chunk_bytes` is a positive multiple of 64, which T-002 already refuses to start without.
    /// It is checked again here because this is where a bad value would divide by zero or reach
    /// the codec.
    pub fn for_len(
        total_len: usize,
        chunk_bytes: usize,
        parity_ratio: f64,
    ) -> Result<Self, RsError> {
        if chunk_bytes == 0 || !chunk_bytes.is_multiple_of(64) {
            return Err(RsError::BadChunkBytes { chunk_bytes });
        }
        if total_len > MAX_PAYLOAD_BYTES {
            return Err(RsError::PayloadTooLarge { total_len });
        }
        let k = total_len.div_ceil(chunk_bytes).max(1);
        let m = ((parity_ratio * k as f64).ceil() as usize).max(1);
        if !ReedSolomonEncoder::supports(k, m) {
            return Err(RsError::TooManyChunks { k, m });
        }
        Ok(Self {
            k: k as u16,
            m: m as u16,
            chunk_bytes,
            total_len: total_len as u32,
        })
    }
}

/// Splits `payload` into `params.k` data chunks and the `params.m` parity chunks that follow
/// them, `k + m` in all, each `params.chunk_bytes` long. A chunk's index is its position in the
/// returned vector, which is what a [`crate::wire::Chunk`] header carries.
///
/// The last data chunk is zero-padded; `params.total_len` is what tells a receiver where the
/// payload ended. Everything is one allocation: the padded message and its parity live in a
/// single buffer and every returned `Bytes` is a refcounted view into it.
///
/// Infallible, so the caller owns the limits: `params` comes from [`Params::for_len`] for this
/// payload, and a debug build stops on a payload of a different length rather than encode a
/// message whose declared length is a lie.
pub fn encode(payload: &[u8], params: Params) -> Vec<Bytes> {
    debug_assert_eq!(
        payload.len(),
        params.total_len as usize,
        "params were built for a different payload"
    );
    let chunk_bytes = params.chunk_bytes;
    let (k, m) = (usize::from(params.k), usize::from(params.m));

    let mut buf = BytesMut::zeroed((k + m) * chunk_bytes);
    let len = payload.len().min(k * chunk_bytes);
    buf[..len].copy_from_slice(&payload[..len]);
    write_parity(&mut buf, params);

    let buf = buf.freeze();
    (0..k + m)
        .map(|index| buf.slice(index * chunk_bytes..(index + 1) * chunk_bytes))
        .collect()
}

/// Fills the `m` chunks after the data with parity computed over the data.
#[expect(
    clippy::expect_used,
    reason = "for_len proved the shard count and size, and exactly k shards are added"
)]
fn write_parity(buf: &mut BytesMut, params: Params) {
    let chunk_bytes = params.chunk_bytes;
    let (k, m) = (usize::from(params.k), usize::from(params.m));

    let mut encoder = ReedSolomonEncoder::new(k, m, chunk_bytes).expect(CODEC_TAKES);
    for index in 0..k {
        encoder
            .add_original_shard(&buf[index * chunk_bytes..(index + 1) * chunk_bytes])
            .expect(CODEC_TAKES);
    }

    let parity = encoder.encode().expect(CODEC_TAKES);
    for (index, shard) in parity.recovery_iter().enumerate() {
        let at = (k + index) * chunk_bytes;
        buf[at..at + chunk_bytes].copy_from_slice(shard);
    }
}

/// A message put back together.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decoded {
    /// The payload, padding removed.
    pub payload: Bytes,
    /// Whether parity had to be used, which means a chunk was lost on the way (§5.4 step 4).
    pub used_parity: bool,
}

/// Rebuilds the message from the chunks in `have`, each paired with the index its header
/// carried. Any `params.k` of the `k + m` are enough.
pub fn decode(params: Params, have: &[(u16, Bytes)]) -> Result<Decoded, RsError> {
    let held = place(params, have);

    if let Some(payload) = concatenate(params, &held) {
        return Ok(Decoded {
            payload,
            used_parity: false,
        });
    }

    if have.len() < usize::from(params.k) {
        return Err(RsError::NotEnoughChunks {
            have: have.len(),
            need: usize::from(params.k),
        });
    }

    Ok(Decoded {
        payload: repair(params, &held),
        used_parity: true,
    })
}

/// The chunks laid out by index, `None` where one did not arrive.
fn place(params: Params, have: &[(u16, Bytes)]) -> Vec<Option<&Bytes>> {
    let mut held = vec![None; usize::from(params.k) + usize::from(params.m)];
    for (index, chunk) in have {
        held[usize::from(*index)] = Some(chunk);
    }
    held
}

/// The payload when every data chunk is here, which is the normal case and the reason the split
/// is systematic: the message is the first `k` chunks joined and cut back to `total_len`, and
/// the codec is never called (§5.4 step 4, D33).
fn concatenate(params: Params, held: &[Option<&Bytes>]) -> Option<Bytes> {
    let k = usize::from(params.k);
    let mut payload = BytesMut::with_capacity(k * params.chunk_bytes);
    for chunk in &held[..k] {
        payload.extend_from_slice((*chunk)?);
    }
    payload.truncate(params.total_len as usize);
    Some(payload.freeze())
}

/// The payload when a data chunk is missing and parity has to stand in for it. Only reached
/// once `held` carries at least `k` chunks, which is all the codec needs.
#[expect(
    clippy::expect_used,
    reason = "for_len proved the split, and the caller proved k distinct chunks are here"
)]
fn repair(params: Params, held: &[Option<&Bytes>]) -> Bytes {
    let k = usize::from(params.k);
    let mut decoder =
        ReedSolomonDecoder::new(k, usize::from(params.m), params.chunk_bytes).expect(CODEC_TAKES);
    for (index, chunk) in held.iter().enumerate() {
        let Some(chunk) = chunk else { continue };
        if index < k {
            decoder.add_original_shard(index, chunk)
        } else {
            decoder.add_recovery_shard(index - k, chunk)
        }
        .expect(CODEC_TAKES);
    }
    let restored = decoder.decode().expect(CODEC_TAKES);

    let mut payload = BytesMut::with_capacity(k * params.chunk_bytes);
    for (index, chunk) in held[..k].iter().enumerate() {
        match *chunk {
            Some(chunk) => payload.extend_from_slice(chunk),
            None => payload.extend_from_slice(
                restored
                    .restored_original(index)
                    .expect("a data chunk that did not arrive"),
            ),
        }
    }
    payload.truncate(params.total_len as usize);
    payload.freeze()
}

/// Why a message could not be split or put back together.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RsError {
    /// The chunk size is not a positive multiple of 64.
    #[error("chunk_bytes {chunk_bytes} is not a positive multiple of 64")]
    BadChunkBytes {
        /// What was asked for.
        chunk_bytes: usize,
    },
    /// The payload is longer than any message the overlay carries.
    #[error("{total_len} bytes is past the {MAX_PAYLOAD_BYTES} byte maximum")]
    PayloadTooLarge {
        /// What was asked for.
        total_len: usize,
    },
    /// The split the arguments ask for is past what the codec encodes, which at 64-byte chunks
    /// arrives well before [`MAX_PAYLOAD_BYTES`] does. Larger chunks are the way out.
    #[error("{k} data and {m} parity chunks is more than the codec encodes")]
    TooManyChunks {
        /// The data chunks the payload would need.
        k: usize,
        /// The parity chunks that go with them.
        m: usize,
    },
    /// Fewer distinct chunks arrived than the message needs. The reassembler (T-074) waits for
    /// more or asks for them.
    #[error("{have} chunks, {need} needed")]
    NotEnoughChunks {
        /// How many arrived.
        have: usize,
        /// How many any combination of data and parity has to add up to.
        need: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pseudo-random bytes, so a chunk that came back from the wrong offset is visible.
    fn payload(len: usize) -> Vec<u8> {
        let mut state = 0x9E37_79B1u32;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                state as u8
            })
            .collect()
    }

    /// The chunks at `indices`, in the shape [`decode`] takes them.
    fn held(chunks: &[Bytes], indices: impl IntoIterator<Item = u16>) -> Vec<(u16, Bytes)> {
        indices
            .into_iter()
            .map(|index| (index, chunks[usize::from(index)].clone()))
            .collect()
    }

    #[test]
    fn params_for_200kb_and_2kb_chunks_gives_k_100_m_10() {
        let params = Params::for_len(200 * 1024, 2048, 0.10).unwrap();

        assert_eq!(params.k, 100);
        assert_eq!(params.m, 10);
        assert_eq!(params.chunk_bytes, 2048);
        assert_eq!(params.total_len, 200 * 1024);
    }

    #[test]
    fn params_m_is_ceil_of_ratio_times_k_with_minimum_one() {
        let one_chunk = Params::for_len(1024, 2048, 0.10).unwrap();
        let rounded_up = Params::for_len(51 * 2048, 2048, 0.10).unwrap();
        let no_parity_asked_for = Params::for_len(100 * 2048, 2048, 0.0).unwrap();

        assert_eq!((one_chunk.k, one_chunk.m), (1, 1));
        assert_eq!((rounded_up.k, rounded_up.m), (51, 6));
        assert_eq!((no_parity_asked_for.k, no_parity_asked_for.m), (100, 1));
    }

    #[test]
    fn params_rejects_chunk_bytes_not_multiple_of_64() {
        for chunk_bytes in [2000, 0] {
            assert_eq!(
                Params::for_len(4096, chunk_bytes, 0.10),
                Err(RsError::BadChunkBytes { chunk_bytes })
            );
        }
        assert!(Params::for_len(4096, 2048, 0.10).is_ok());
    }

    #[test]
    fn params_rejects_a_split_no_chunk_header_could_carry() {
        assert_eq!(
            Params::for_len(MAX_PAYLOAD_BYTES + 1, 2048, 0.10),
            Err(RsError::PayloadTooLarge {
                total_len: MAX_PAYLOAD_BYTES + 1
            })
        );
        assert!(Params::for_len(MAX_PAYLOAD_BYTES, 2048, 0.10).is_ok());
        assert_eq!(
            Params::for_len(MAX_PAYLOAD_BYTES, 64, 0.10),
            Err(RsError::TooManyChunks {
                k: 163_840,
                m: 16_384
            })
        );
    }

    #[test]
    fn encode_produces_k_plus_m_chunks_of_equal_length() {
        let params = Params::for_len(200 * 1024, 2048, 0.10).unwrap();

        let chunks = encode(&payload(200 * 1024), params);

        assert_eq!(chunks.len(), 110);
        assert!(chunks.iter().all(|chunk| chunk.len() == 2048));
    }

    #[test]
    fn first_k_chunks_are_the_payload_with_zero_padding() {
        let len = 5 * 2048 + 100;
        let payload = payload(len);
        let params = Params::for_len(len, 2048, 0.10).unwrap();

        let chunks = encode(&payload, params);

        assert_eq!(params.k, 6);
        let data: Vec<u8> = chunks[..6]
            .iter()
            .flat_map(|chunk| chunk.iter().copied())
            .collect();
        assert_eq!(data[..len], payload[..]);
        assert!(data[len..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn decode_with_all_data_chunks_returns_payload_and_used_parity_false() {
        let len = 5 * 2048 + 100;
        let payload = payload(len);
        let params = Params::for_len(len, 2048, 0.10).unwrap();
        let chunks = encode(&payload, params);

        let decoded = decode(params, &held(&chunks, 0..params.k)).unwrap();

        assert_eq!(decoded.payload, payload);
        assert!(!decoded.used_parity);
    }

    #[test]
    fn decode_with_one_data_chunk_missing_uses_parity_and_returns_exact_payload() {
        let len = 5 * 2048 + 100;
        let payload = payload(len);
        let params = Params::for_len(len, 2048, 0.10).unwrap();
        let chunks = encode(&payload, params);
        assert_eq!((params.k, params.m), (6, 1));

        let decoded = decode(params, &held(&chunks, [0, 1, 2, 4, 5, 6])).unwrap();

        assert_eq!(decoded.payload, payload);
        assert!(decoded.used_parity);
    }
}
