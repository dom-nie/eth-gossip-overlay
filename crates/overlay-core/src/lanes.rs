//! The hand-off from the BN link's swarm loop to whoever consumes what the beacon node sends
//! (D07): two bounded `mpsc` lanes, one per [`Class`], filled with `try_send` so the swarm
//! loop never waits on a consumer, and drained large-first so a block is never queued behind
//! attestations. MASTER.md keeps channels out of this crate; D07 put the lanes here anyway,
//! because the capacities, the drop policy and which class wins are the decision, and the
//! channels are only its carrier.

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::topic::Class;

    #[tokio::test]
    async fn lanes_recv_prefers_large_when_both_have_items() {
        let mut lanes = ClassLanes::new(Arc::new(()));
        lanes.push(Class::Small, "attestation").unwrap();
        lanes.push(Class::Large, "block").unwrap();

        assert_eq!(lanes.recv().await, "block");
        assert_eq!(lanes.recv().await, "attestation");
    }
}
