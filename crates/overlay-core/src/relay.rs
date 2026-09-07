//! Which hosts in a remote region carry a small-class batch for the rest of it (§5.4, D20).
//!
//! Sending every batch to every subscribed host in the other region costs the WAN a copy per
//! host; sending it to a few of them and letting each fan it out inside its own region costs a
//! copy per relay and one metro hop. Which few is arithmetic over hostnames, so every origin
//! works it out from its own live view with nothing to ask and nothing to agree on (§3).
//!
//! Spreading is by a hash of the origin's own hostname, so two origins pick different windows of
//! the same region and the load lands on all of it rather than on whichever hosts answer
//! fastest. Round-trip time is not an input: the whole region is one metro hop wide (§5.4), and
//! picking by RTT would make every origin choose the same handful of hosts.

use crate::roster::Hostname;

/// FNV-1a's 64-bit offset basis. The hash is here to spread origins over a pool of a few dozen
/// hosts, which any well-mixed hash does; FNV-1a is the one D20 named, so both ends of a fleet
/// upgrade compute the same window from the same live view.
const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;

/// FNV-1a's 64-bit prime.
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// The `relays_per_remote_region` hosts of `pool_sorted` that carry a batch from `origin`: the
/// window of `n` hosts starting where the origin's hash lands.
///
/// `pool_sorted` is every live host in the remote region that has sent a `SUBS`, in hostname
/// order, and it is the caller's to build: this takes hostnames and no connections, so the
/// arithmetic is a function a test can ask a question of.
pub fn select(origin: &Hostname, pool_sorted: &[Hostname], n: usize) -> Vec<Hostname> {
    let start = (fnv1a64(origin.0.as_bytes()) % pool_sorted.len() as u64) as usize;
    (start..start + n.min(pool_sorted.len()))
        .map(|step| pool_sorted[step % pool_sorted.len()].clone())
        .collect()
}

/// The FNV-1a hash of `bytes`, 64 bits.
fn fnv1a64(bytes: &[u8]) -> u64 {
    bytes.iter().fold(FNV_OFFSET_BASIS, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(FNV_PRIME)
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::roster::Hostname;

    fn host(name: &str) -> Hostname {
        Hostname(name.to_owned())
    }

    /// A remote region's live subscribed hosts, in the hostname order the pool is built in.
    fn pool(hosts: usize) -> Vec<Hostname> {
        (1..=hosts)
            .map(|n| host(&format!("bn-us-{n:02}")))
            .collect()
    }

    /// The window is `n` hosts long and it starts where the origin's hash lands, so two origins
    /// with the same live view load different relays and neither has to ask anyone (§3, D20).
    /// The start is a known answer: `fnv1a64("bn-eu-01") % 5` is 2.
    #[test]
    fn select_takes_n_consecutive_hosts_from_the_sorted_pool_starting_at_the_origin_hash() {
        let relays = select(&host("bn-eu-01"), &pool(5), 3);

        assert_eq!(
            relays,
            vec![host("bn-us-03"), host("bn-us-04"), host("bn-us-05")]
        );
    }

    /// The window is a ring, so an origin that lands near the end of the pool still gets `n`
    /// relays instead of however many hosts are left. Nothing about the pool's order says where
    /// it begins, and cutting the window short would leave the hosts at the top of the region
    /// carrying less than the ones below them.
    #[test]
    fn select_wraps_around_the_end_of_the_pool() {
        let relays = select(&host("bn-eu-01"), &pool(4), 3);

        assert_eq!(
            relays,
            vec![host("bn-us-03"), host("bn-us-04"), host("bn-us-01")]
        );
    }

    /// What the hash is for (D20): the relays of a whole region of origins land on the whole
    /// remote region, not on three hosts that then carry every batch the WAN brings. Twenty
    /// origins over a pool of nine leave at most one host unused.
    #[test]
    fn different_origins_spread_across_all_remote_hosts() {
        let pool = pool(9);

        let used: BTreeSet<Hostname> = (1..=20)
            .flat_map(|n| select(&host(&format!("bn-eu-{n:02}")), &pool, 3))
            .collect();

        assert!(used.len() >= 8, "{used:?}");
    }

    /// A region smaller than the relay count is all relays and no host twice. Sending a host the
    /// same batch two or three times would cost it the WAN copies the relays are there to save.
    #[test]
    fn select_with_fewer_remote_hosts_than_n_returns_all() {
        let relays = select(&host("bn-eu-01"), &pool(2), 3);

        assert_eq!(relays, vec![host("bn-us-01"), host("bn-us-02")]);
    }
}
