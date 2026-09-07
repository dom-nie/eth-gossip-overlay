//! Which hosts in a remote region carry a small-class batch for the rest of it (§5.4, D20).

#[cfg(test)]
mod tests {
    use super::*;
    use crate::roster::Hostname;

    fn host(name: &str) -> Hostname {
        Hostname(name.to_owned())
    }

    /// A remote region's live subscribed hosts, in the hostname order the pool is built in.
    fn pool(hosts: usize) -> Vec<Hostname> {
        (1..=hosts).map(|n| host(&format!("bn-us-{n:02}"))).collect()
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
}
