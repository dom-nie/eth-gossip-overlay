#[cfg(test)]
mod tests {
    use std::io::{self, Write};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, UNIX_EPOCH};

    use overlay_core::config::Log;
    use overlay_core::events::{FirstArrival, Source, emit_first_arrival};
    use overlay_core::msgid::MessageId;
    use overlay_core::roster::{Hostname, Region, SelfIdentity};
    use overlay_core::topic::{Class, Topic};
    use serde_json::{Map, Value};
    use tracing_subscriber::fmt::MakeWriter;

    use super::*;

    /// A moment with a nanosecond part, so a truncating conversion cannot pass.
    const AT_NANOS: u64 = 1_757_000_000_123_456_789;

    /// What the subscriber under test wrote, kept in memory so a test can read it back.
    #[derive(Clone, Default)]
    struct Sink(Arc<Mutex<Vec<u8>>>);

    impl Sink {
        fn text(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
        }

        /// One JSON object per line, which fails the test if any line is not JSON.
        fn objects(&self) -> Vec<Map<String, Value>> {
            self.text()
                .lines()
                .map(|line| serde_json::from_str(line).expect("a JSON line"))
                .collect()
        }
    }

    impl Write for Sink {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().write(buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for Sink {
        type Writer = Self;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// Runs `body` against a subscriber built exactly as [`init`] builds the real one, writing
    /// to memory instead of stdout and taking the terminal and `RUST_LOG` answers as arguments
    /// rather than reading the process.
    fn capture(
        cfg: &Log,
        is_tty: bool,
        rust_log: Option<&str>,
        body: impl FnOnce(&LogHandle),
    ) -> Sink {
        let sink = Sink::default();
        let (dispatch, handle) =
            build(cfg, sink.clone(), is_tty, rust_log.map(str::to_owned), None);
        tracing::dispatcher::with_default(&dispatch, || body(&handle));
        sink
    }

    fn node() -> SelfIdentity {
        SelfIdentity {
            hostname: Hostname("bn-ams1-07".to_owned()),
            region: Region("eu".to_owned()),
            site: Some("ams1".to_owned()),
        }
    }

    fn block() -> Topic {
        Topic::parse("/eth2/00000000/beacon_block/ssz_snappy").unwrap()
    }

    fn arrival<'a>(
        topic: &'a Topic,
        node: &'a SelfIdentity,
        class: Class,
        source: Source<'a>,
    ) -> FirstArrival<'a> {
        FirstArrival {
            id: MessageId([1; 20]),
            class,
            topic,
            node,
            at: UNIX_EPOCH + Duration::from_nanos(AT_NANOS),
            source,
        }
    }

    #[test]
    fn first_arrival_from_bn_emits_one_json_line_with_all_fields() {
        let node = node();
        let topic = block();

        let sink = capture(&Log::default(), false, None, |_| {
            emit_first_arrival(&arrival(&topic, &node, Class::Large, Source::Bn));
        });

        let lines = sink.objects();
        assert_eq!(lines.len(), 1, "{}", sink.text());
        let line = &lines[0];
        assert_eq!(line["level"], "INFO");
        assert_eq!(line["target"], "overlay::event");
        assert_eq!(line["event"], "first_arrival");
        assert_eq!(line["msg_id"], "01".repeat(20));
        assert_eq!(line["class"], "large");
        assert_eq!(line["topic"], "/eth2/00000000/beacon_block/ssz_snappy");
        assert_eq!(line["node"], "bn-ams1-07");
        assert_eq!(line["region"], "eu");
        assert_eq!(line["site"], "ams1");
        assert_eq!(line["first_arrival_ns"], AT_NANOS);
        assert_eq!(line["source"], "bn");
        assert!(line.contains_key("timestamp"), "{line:?}");
    }
}
