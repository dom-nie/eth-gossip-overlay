#[cfg(test)]
mod tests {
    use super::*;

    /// The frame Lighthouse writes for one imported block: the event name, the JSON payload and
    /// the blank line that closes the frame.
    fn frame(slot: u64, root: &str) -> String {
        format!(
            "event: block\ndata: {{\"slot\":\"{slot}\",\"block\":\"{root}\",\"execution_optimistic\":false}}\n\n"
        )
    }

    /// A block root of one repeated byte, in the `0x`-prefixed form the beacon API reports.
    fn root(byte: u8) -> String {
        format!("0x{}", format!("{byte:02x}").repeat(32))
    }

    #[test]
    fn parses_block_event_slot_and_root() {
        let mut frames = Frames::default();

        let events = frames.feed(frame(7_654_321, &root(0xab)).as_bytes());

        assert_eq!(
            events,
            [BlockEvent {
                slot: 7_654_321,
                block_root: [0xab; 32],
            }]
        );
    }
}
