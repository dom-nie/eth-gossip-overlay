//! Pure logic for the fleet gossip overlay. Everything here is a plain function or a
//! clock-driven struct so it can be tested without sockets, channels or sleeping.

pub mod backoff;
pub mod time;

#[cfg(test)]
mod tests {
    #[test]
    fn crate_compiles() {}
}
