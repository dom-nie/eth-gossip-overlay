//! One live connection to every other host in the roster, and the live set the router reads.

#[cfg(test)]
mod tests {
    use overlay_core::roster::Hostname;

    use super::*;

    fn host(name: &str) -> Hostname {
        Hostname(name.to_owned())
    }

    /// The tie-break that keeps a pair at one connection without negotiating anything: the
    /// lower hostname dials, the higher one only accepts. Both ends run the same comparison
    /// on the same two strings, so they cannot disagree.
    #[test]
    fn should_dial_is_true_only_for_higher_hostnames() {
        assert!(should_dial(&host("bn-a"), &host("bn-b")));
        assert!(!should_dial(&host("bn-b"), &host("bn-a")));
        assert!(!should_dial(&host("bn-a"), &host("bn-a")));
    }
}
