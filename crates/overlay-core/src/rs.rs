//! Splitting a large message into fixed-size chunks and adding Reed-Solomon parity (§5.4).
//!
//! §14 rejected RLNC: its coordination-free chunk selection and recoding pay off on a lossy
//! multi-hop mesh of strangers, and this overlay is one or two hops between hosts that trust
//! each other and know the whole membership, so all that would remain is the cost, a Gaussian
//! elimination and a rank check on every message before it can be delivered. Systematic
//! Reed-Solomon buys the same resilience to a lost chunk while the common case, every data
//! chunk present, is a concatenation that never calls the codec.

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
}
