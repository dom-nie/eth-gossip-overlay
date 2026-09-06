//! What one sibling may make this host fan out (DX-N3, OPS-N2).
//!
//! A second hop is work a peer asks this host to do: a `RELAY` batch it re-fans in its own
//! region (T-063), a chunk it forwards to the rest of its region (T-073). A peer that asks for
//! far more of it than a slot's traffic can account for is either broken or hostile, and the
//! answer to both is the same: deliver what arrived locally, do not fan it out, and count it.
//! A peer that keeps it up for more than [`SUSTAINED_VIOLATION`] loses the connection and comes
//! back through the ordinary reconnect backoff.
//!
//! Nothing in v1 charges the bucket, because nothing in v1 fans out what it receives (§3
//! principle 1). It is built, tested and wired into the receiver here so that T-063 and T-073
//! have one budget to charge rather than one each.
//!
//! `now` is a parameter everywhere, so the bucket holds no clock and a test drives it with plain
//! `Instant` arithmetic.

use std::time::{Duration, Instant};

use crate::ratelimit::TokenBucket;

/// How long a peer may stay over its budget before the connection is closed with
/// `RateExceeded` (DX-N3).
pub const SUSTAINED_VIOLATION: Duration = Duration::from_secs(10);

/// What one slot of large-class traffic is taken to be: a block plus 128 data columns with
/// parity, at T-071's sizes. An estimate the budget is derived from, not a limit anything is
/// measured against.
pub const LARGE_BYTES_PER_SLOT_ESTIMATE: usize = 6 * 1024 * 1024;

/// Which second hop the bytes were for, the `kind` label of `fanout_suppressed_total`.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum FanoutKind {
    /// A `RELAY` batch to re-fan inside this host's region (T-063).
    Relay,
    /// A chunk to forward to the rest of this host's region (T-073).
    Chunk,
}

impl FanoutKind {
    /// The label value.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Relay => "relay",
            Self::Chunk => "chunk",
        }
    }
}

/// What a charge came to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Charge {
    /// The bucket had the bytes. Fan the traffic out.
    Allowed,
    /// It did not. Deliver locally, fan nothing out, and count
    /// `fanout_suppressed_total{peer, kind}`.
    Suppressed,
    /// It has not had them for more than [`SUSTAINED_VIOLATION`]. The same as `Suppressed`, and
    /// the receiver closes the connection with `RateExceeded`.
    CloseRateExceeded,
}

/// One peer's fan-out budget: a token bucket over the bytes that trigger a second hop, and how
/// long the peer has been over it.
#[derive(Clone, Debug)]
pub struct FanoutBudget {
    bucket: TokenBucket,
    violation_since: Option<Instant>,
}

impl FanoutBudget {
    /// The budget a peer gets, from the fleet it is part of.
    ///
    /// Capacity is one slot's worth of what a single sibling can honestly make this host fan
    /// out: four times the share of a slot's large-class traffic that falls to one host, rounded
    /// up to whole chunks because a chunk is the unit anything arrives in. Refill is that
    /// capacity per slot, so a peer at the expected rate never runs dry and one at four times it
    /// is over budget inside a slot.
    ///
    /// ```text
    /// capacity = ceil(4 * LARGE_BYTES_PER_SLOT_ESTIMATE / roster_size / chunk_bytes) * chunk_bytes
    /// refill   = capacity / slot_secs bytes per second, rounded down
    /// ```
    ///
    /// A roster of one, a chunk size of zero or a slot of zero seconds are not configurations
    /// this sidecar runs, but they are arithmetic this must not divide by, so each floor is 1.
    pub fn default_for(
        roster_size: usize,
        chunk_bytes: usize,
        slot_secs: u64,
        now: Instant,
    ) -> Self {
        let chunk_bytes = chunk_bytes.max(1) as u64;
        let share = (4 * LARGE_BYTES_PER_SLOT_ESTIMATE / roster_size.max(1)) as u64;
        let capacity = share.div_ceil(chunk_bytes) * chunk_bytes;
        Self {
            bucket: TokenBucket::new(capacity / slot_secs.max(1), capacity, now),
            violation_since: None,
        }
    }

    /// Takes `bytes` out of the bucket, refilled up to `now`.
    ///
    /// `kind` is the `fanout_suppressed_total{peer, kind}` label the caller counts a refusal
    /// under. One bucket covers every kind: the budget is what one peer may make this host fan
    /// out, however it asked.
    pub fn charge(&mut self, _kind: FanoutKind, bytes: usize, now: Instant) -> Charge {
        if self.bucket.try_take(bytes as u64, now) {
            self.violation_since = None;
            return Charge::Allowed;
        }
        let since = *self.violation_since.get_or_insert(now);
        if now.saturating_duration_since(since) > SUSTAINED_VIOLATION {
            Charge::CloseRateExceeded
        } else {
            Charge::Suppressed
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A slot's traffic in one burst goes through, and the byte after it does not until the
    /// bucket has refilled. The numbers are the arithmetic in [`FanoutBudget::default_for`] for
    /// a 200-host fleet at T-071's chunk size and mainnet's slot: 4 x 6 MiB over 200 hosts is
    /// 125,829 bytes, which is 62 whole 2 KiB chunks, refilled over twelve seconds.
    #[test]
    fn fanout_budget_allows_a_slot_burst_then_suppresses_and_refills() {
        let slot_start = Instant::now();
        let mut budget = FanoutBudget::default_for(200, 2048, 12, slot_start);

        assert_eq!(
            budget.charge(FanoutKind::Chunk, 62 * 2048, slot_start),
            Charge::Allowed
        );
        assert_eq!(
            budget.charge(FanoutKind::Chunk, 1, slot_start),
            Charge::Suppressed
        );

        let a_second_later = slot_start + Duration::from_secs(1);
        assert_eq!(
            budget.charge(FanoutKind::Relay, 62 * 2048 / 12, a_second_later),
            Charge::Allowed
        );
        assert_eq!(
            budget.charge(FanoutKind::Relay, 1, a_second_later),
            Charge::Suppressed
        );
    }
}
