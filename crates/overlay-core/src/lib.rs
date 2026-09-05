//! Pure logic for the fleet gossip overlay. Everything here is a plain function or a
//! clock-driven struct so it can be tested without sockets, channels or sleeping.

pub mod backoff;
pub mod config;
pub mod fanout;
pub mod identity;
pub mod lanes;
pub mod msgid;
pub mod ratelimit;
pub mod roster;
pub mod seen;
pub mod time;
pub mod topic;

#[cfg(test)]
mod tests {
    #[test]
    fn crate_compiles() {}
}
