//! Which host each chunk of a large message goes to (§5.4, D18).
//!
//! Fanning a whole block out from one host costs a copy of it per recipient off one NIC, so a
//! large message is split into chunks and each chunk goes to one host of the region, which
//! forwards it to the rest (T-073). Which chunk lands where is arithmetic over hostnames, so
//! every origin works it out from its own live view with nothing to ask and nothing to agree on
//! (§3).
//!
//! The round robin runs over the region's hosts in hostname order and starts where the message
//! id points. Two origins that took the same message off public gossip and see the same live
//! hosts therefore assign every chunk the same way, and the two copies deduplicate on arrival
//! instead of doubling the traffic (§5.4). The rotation is what keeps chunk 0 of every message
//! off the same host.
//!
//! The pool is the region's live hosts subscribed to the topic, which is the one thing striping
//! and relay selection do differently: a relay carries a batch for its region and need not want
//! anything in it (D20), while a chunk sent to a host whose beacon node discards the column
//! bought nothing (D18).

use crate::msgid::MessageId;
use crate::roster::Hostname;

/// Where each chunk of the message with `msg_id` goes: chunk `i` to the `i`th host of the
/// returned vector, which is `n_chunks` long.
///
/// `hosts_sorted` is the region's live hosts subscribed to the topic in hostname order, and it
/// is the caller's to build: this takes hostnames and no connections, so the arithmetic is a
/// function a test can ask a question of.
///
/// Five hosts, seven chunks and an id that rotates by 3:
///
/// ```text
/// hosts    bn-01  bn-02  bn-03  bn-04  bn-05
/// chunks       2      3      4   0, 5   1, 6
/// ```
///
/// A region with more chunks than hosts wraps, so the hosts the rotation starts on take a
/// second chunk before any host takes a third. A region with nobody live in it takes nothing.
pub fn assign(msg_id: &MessageId, hosts_sorted: &[Hostname], n_chunks: usize) -> Vec<Hostname> {
    if hosts_sorted.is_empty() {
        return Vec::new();
    }
    let start = (rotation(msg_id) % hosts_sorted.len() as u64) as usize;
    (0..n_chunks)
        .map(|chunk| hosts_sorted[(start + chunk) % hosts_sorted.len()].clone())
        .collect()
}

/// The offset the round robin starts at, before the region's size is divided out: the message
/// id's first eight bytes, little-endian (D18). The id is a hash already, so nothing here
/// hashes it again.
fn rotation(msg_id: &MessageId) -> u64 {
    let mut head = [0u8; 8];
    head.copy_from_slice(&msg_id.0[..8]);
    u64::from_le_bytes(head)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msgid::MessageId;
    use crate::roster::Hostname;

    fn host(name: &str) -> Hostname {
        Hostname(name.to_owned())
    }

    /// A region's live subscribed hosts, in the hostname order the caller sorts them into.
    fn hosts(count: usize) -> Vec<Hostname> {
        (1..=count).map(|n| host(&format!("bn-{n:02}"))).collect()
    }

    /// An id whose first eight bytes little-endian are `rotation`, which is the number the
    /// assignment takes the remainder of (D18).
    fn msg_id(rotation: u64) -> MessageId {
        let mut id = [0u8; 20];
        id[..8].copy_from_slice(&rotation.to_le_bytes());
        MessageId(id)
    }

    /// The worked example in [`assign`]'s own doc comment: five hosts, seven chunks, and an id
    /// that lands the rotation on 3. Chunk 0 goes to the fourth host and the round robin runs
    /// from there, wrapping at the end of the region.
    #[test]
    fn assign_is_round_robin_in_sorted_order_from_the_rotation_offset() {
        let targets = assign(&msg_id(3), &hosts(5), 7);

        assert_eq!(
            targets,
            vec![
                host("bn-04"),
                host("bn-05"),
                host("bn-01"),
                host("bn-02"),
                host("bn-03"),
                host("bn-04"),
                host("bn-05"),
            ]
        );
    }
}
