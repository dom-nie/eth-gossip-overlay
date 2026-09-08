//! Splitting a large message into fixed-size chunks and adding Reed-Solomon parity (§5.4).
//!
//! §14 rejected RLNC: its coordination-free chunk selection and recoding pay off on a lossy
//! multi-hop mesh of strangers, and this overlay is one or two hops between hosts that trust
//! each other and know the whole membership, so all that would remain is the cost, a Gaussian
//! elimination and a rank check on every message before it can be delivered. Systematic
//! Reed-Solomon buys the same resilience to a lost chunk while the common case, every data
//! chunk present, is a concatenation that never calls the codec.

use reed_solomon_simd::ReedSolomonEncoder;

use crate::wire::MAX_PAYLOAD_BYTES;

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
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
