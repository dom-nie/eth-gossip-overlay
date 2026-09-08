//! Pure logic for the Eth gossip overlay. Everything here is a plain function or a
//! clock-driven struct so it can be tested without sockets, channels or sleeping.

pub mod backoff;
pub mod batch;
pub mod budget;
pub mod config;
pub mod custody;
pub mod events;
pub mod fanout;
pub mod identity;
pub mod lanes;
pub mod msgid;
pub mod progress;
pub mod protocol;
pub mod pubqueue;
pub mod ratelimit;
pub mod reassemble;
pub mod recent;
pub mod relay;
pub mod repair;
pub mod roster;
pub mod rs;
pub mod seen;
pub mod spec;
pub mod stripe;
pub mod subs;
#[cfg(test)]
mod testlog;
pub mod time;
pub mod topic;
pub mod wire;

#[cfg(test)]
mod tests {
    #[test]
    fn crate_compiles() {}
}
