//! The process's one subscriber, and the only place `tracing_subscriber::fmt` is constructed
//! (D32).
//!
//! Logs and events share it: both go through one `EnvFilter`, one formatter and one
//! [`tracing_appender::non_blocking`] writer onto stdout, which under systemd is the journal and
//! from there one Loki stream. Events are told apart by their `event` field, not by a second
//! stream, so there is nothing extra for an operator to configure and no way for the two to
//! drift apart.
//!
//! Level and format sit behind [`reload`] layers, because T-043 changes both on SIGHUP without
//! restarting the process, and a peer's connection must not notice.

use std::io::IsTerminal;

use overlay_core::config::{Log, LogFormat, LogLevel};
use tracing::Dispatch;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::{Layer, Layered, SubscriberExt};
use tracing_subscriber::{EnvFilter, Registry, fmt, reload};

/// The variable that overrides `log.level`, and the only way to filter per target.
const RUST_LOG: &str = "RUST_LOG";

/// One rendering of the log stream, boxed so the two formats are one type and can be swapped.
type Rendered = Box<dyn Layer<Registry> + Send + Sync>;

/// The subscriber the filter is added to, once the formatter is in place.
type Stack = Layered<reload::Layer<Rendered, Registry>, Registry>;

/// Builds a formatter for a resolved format, holding the writer both share.
type Renderer = Box<dyn Fn(LogFormat) -> Rendered + Send + Sync>;

/// Installs the subscriber for the whole process and returns the handle that changes it.
///
/// Reads the two things a test cannot stage: whether stdout is a terminal, which is what
/// `format: auto` turns on, and `RUST_LOG`.
pub fn init(cfg: &Log) -> LogHandle {
    let (writer, guard) = tracing_appender::non_blocking(std::io::stdout());
    let (dispatch, handle) = build(
        cfg,
        writer,
        std::io::stdout().is_terminal(),
        std::env::var(RUST_LOG).ok(),
        Some(guard),
    );
    // Nothing else in either binary installs a subscriber, so this can only fail if init ran
    // twice, and the subscriber already in place still writes every line.
    let _ = tracing::dispatcher::set_global_default(dispatch);
    handle
}

/// The subscriber and its handle, with everything it reads from the process passed in.
fn build<W>(
    cfg: &Log,
    writer: W,
    is_tty: bool,
    rust_log: Option<String>,
    guard: Option<WorkerGuard>,
) -> (Dispatch, LogHandle)
where
    W: for<'a> MakeWriter<'a> + Clone + Send + Sync + 'static,
{
    let render: Renderer = Box::new(move |format| match format {
        LogFormat::Json => fmt::layer()
            .json()
            .flatten_event(true)
            .with_writer(writer.clone())
            .boxed(),
        // `resolve` answers Json or Text, never Auto.
        LogFormat::Text | LogFormat::Auto => fmt::layer()
            .with_ansi(is_tty)
            .with_writer(writer.clone())
            .boxed(),
    });
    let (rendering, format) = reload::Layer::new(render(cfg.format.resolve(is_tty)));
    let (filtering, level) = reload::Layer::new(match &rust_log {
        Some(directives) => EnvFilter::new(directives),
        None => EnvFilter::new(directive(cfg.level)),
    });
    let handle = LogHandle {
        format,
        level,
        render,
        is_tty,
        rust_log,
        _guard: guard,
    };
    (
        Dispatch::new(Registry::default().with(rendering).with(filtering)),
        handle,
    )
}

/// What T-043 changes about the running subscriber. The non-blocking writer's worker thread
/// lives as long as this handle, so the app has to hold it for the process's lifetime or lose
/// the lines still in flight.
pub struct LogHandle {
    format: reload::Handle<Rendered, Registry>,
    level: reload::Handle<EnvFilter, Stack>,
    render: Renderer,
    is_tty: bool,
    rust_log: Option<String>,
    _guard: Option<WorkerGuard>,
}

/// The `EnvFilter` directive for a configured level. `log.level` is a closed enum, so this is
/// the whole filter; anything per-target comes from `RUST_LOG`.
fn directive(level: LogLevel) -> &'static str {
    match level {
        LogLevel::Trace => "trace",
        LogLevel::Debug => "debug",
        LogLevel::Info => "info",
        LogLevel::Warn => "warn",
        LogLevel::Error => "error",
    }
}

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

    #[test]
    fn first_arrival_from_overlay_includes_origin_peer() {
        let node = node();
        let topic = block();
        let origin = Hostname("bn-fra1-02".to_owned());

        let sink = capture(&Log::default(), false, None, |_| {
            emit_first_arrival(&arrival(
                &topic,
                &node,
                Class::Large,
                Source::Overlay { origin: &origin },
            ));
            emit_first_arrival(&arrival(&topic, &node, Class::Large, Source::Bn));
        });

        let lines = sink.objects();
        assert_eq!(lines.len(), 2, "{}", sink.text());
        assert_eq!(lines[0]["source"], "overlay");
        assert_eq!(lines[0]["origin_peer"], "bn-fra1-02");
        assert_eq!(lines[1]["source"], "bn");
        assert!(!lines[1].contains_key("origin_peer"), "{:?}", lines[1]);
    }

    #[test]
    fn small_class_emits_nothing() {
        let node = node();
        let attestation = Topic::parse("/eth2/00000000/beacon_attestation_3/ssz_snappy").unwrap();

        let sink = capture(&Log::default(), false, None, |_| {
            emit_first_arrival(&arrival(&attestation, &node, Class::Small, Source::Bn));
        });

        assert!(sink.text().is_empty(), "{}", sink.text());
    }

    #[test]
    fn events_and_ordinary_logs_share_one_writer_and_differ_by_the_event_field() {
        let node = node();
        let topic = block();

        let sink = capture(&Log::default(), false, None, |_| {
            tracing::info!("the overlay is up");
            emit_first_arrival(&arrival(&topic, &node, Class::Large, Source::Bn));
        });

        let lines = sink.objects();
        assert_eq!(lines.len(), 2, "{}", sink.text());
        assert_eq!(lines[0]["message"], "the overlay is up");
        assert!(!lines[0].contains_key("event"), "{:?}", lines[0]);
        assert_eq!(lines[1]["event"], "first_arrival");
        assert_eq!(lines[1]["target"], "overlay::event");
        assert_ne!(lines[0]["target"], lines[1]["target"]);
    }

    #[test]
    fn auto_format_is_json_off_a_tty_and_text_on_one() {
        let piped = capture(&Log::default(), false, None, |_| {
            tracing::info!("the overlay is up");
        });
        let terminal = capture(&Log::default(), true, None, |_| {
            tracing::info!("the overlay is up");
        });

        assert_eq!(
            serde_json::from_str::<Value>(piped.text().trim()).unwrap()["message"],
            "the overlay is up"
        );
        assert!(
            serde_json::from_str::<Value>(terminal.text().trim()).is_err(),
            "{}",
            terminal.text()
        );
        assert!(terminal.text().contains("the overlay is up"));
    }

    #[test]
    fn set_level_and_set_format_take_effect_on_the_next_line() {
        let sink = capture(&Log::default(), false, None, |handle| {
            tracing::debug!("below the configured level");
            handle.set_level("debug");
            tracing::debug!("above it now");
            handle.set_format(LogFormat::Text);
            tracing::debug!("in text now");
        });

        let lines: Vec<&str> = sink.text().lines().collect();
        assert_eq!(lines.len(), 2, "{}", sink.text());
        assert_eq!(
            serde_json::from_str::<Value>(lines[0]).unwrap()["message"],
            "above it now"
        );
        assert!(
            serde_json::from_str::<Value>(lines[1]).is_err(),
            "{}",
            lines[1]
        );
        assert!(lines[1].contains("in text now"), "{}", lines[1]);
    }
}
