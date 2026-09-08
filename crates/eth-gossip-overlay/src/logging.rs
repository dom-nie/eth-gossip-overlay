//! The process's one subscriber, and the only place `tracing_subscriber::fmt` is constructed
//! (D32).
//!
//! Logs and events share it: both go through one `EnvFilter`, one formatter and one
//! [`tracing_appender::non_blocking()`] writer onto stdout, which under systemd is the journal and
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

impl LogHandle {
    /// Changes the level every layer filters on, from the next line onwards.
    ///
    /// A no-op while `RUST_LOG` is set, which is what an operator debugging a running sidecar
    /// expects: the variable they exported outranks the file, and the line says so rather than
    /// leaving them to wonder why the reload did nothing.
    pub fn set_level(&self, level: &str) {
        if let Some(directives) = &self.rust_log {
            tracing::info!(
                rust_log = directives,
                level,
                "RUST_LOG is set, so log.level is not applied"
            );
            return;
        }
        match EnvFilter::try_new(level) {
            // The only way a reload fails is the subscriber being gone, and a process without
            // its subscriber has nowhere to report that.
            Ok(filter) => {
                let _ = self.level.reload(filter);
            }
            Err(error) => tracing::warn!(%error, level, "keeping the level: it does not parse"),
        }
    }

    /// Swaps the formatter, from the next line onwards. `Auto` resolves against the terminal
    /// answer the subscriber was built with, because whether stdout is a terminal cannot change
    /// under a running process.
    pub fn set_format(&self, format: LogFormat) {
        let _ = self
            .format
            .reload((self.render)(format.resolve(self.is_tty)));
    }
}

/// The `EnvFilter` directive for a configured level. `log.level` is a closed enum, so this is
/// the whole filter; anything per-target comes from `RUST_LOG`.
pub(crate) fn directive(level: LogLevel) -> &'static str {
    match level {
        LogLevel::Trace => "trace",
        LogLevel::Debug => "debug",
        LogLevel::Info => "info",
        LogLevel::Warn => "warn",
        LogLevel::Error => "error",
    }
}

/// An in-memory subscriber for the tests in this crate that read back what the log stream
/// rendered. It lives beside the code it builds rather than in this module's own tests,
/// because T-043's reload tests need a [`LogHandle`] whose output they can inspect too.
#[cfg(test)]
pub(crate) mod testing {
    use std::io::{self, Write};
    use std::sync::{Arc, LazyLock, Mutex};

    use overlay_core::config::{Log, LogFormat, LogLevel};
    use serde_json::{Map, Value};
    use tracing::Dispatch;
    use tracing_subscriber::fmt::MakeWriter;

    use super::{LogHandle, build};

    /// What the subscriber under test wrote, kept in memory so a test can read it back.
    #[derive(Clone, Default)]
    pub(crate) struct Sink(Arc<Mutex<Vec<u8>>>);

    impl Sink {
        pub(crate) fn text(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
        }

        /// One JSON object per line, which fails the test if any line is not JSON.
        pub(crate) fn objects(&self) -> Vec<Map<String, Value>> {
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

    /// One subscriber for the whole test binary, kept alive under every thread-scoped one.
    ///
    /// `tracing` settles a call site's interest the first time the call site is reached, by
    /// asking the dispatchers alive at that moment, and a call site reached with none alive
    /// settles on "never" for the rest of the process: a [`with_default`] test that reaches it
    /// afterwards reads an empty sink. A subscriber that never goes away and takes an interest
    /// in every level holds that answer at "sometimes", so each event asks the dispatcher in
    /// force instead. It also keeps the global maximum level at `trace`, which a scoped
    /// subscriber alone lowers for every thread at once. Its own lines go nowhere: what a test
    /// reads back is the rendering of the configuration it asked for, not this one.
    ///
    /// [`with_default`]: tracing::dispatcher::with_default
    static PROCESS_WIDE: LazyLock<()> = LazyLock::new(|| {
        let cfg = Log {
            level: LogLevel::Trace,
            format: LogFormat::Text,
        };
        let discard: fn() -> io::Sink = io::sink;
        let (dispatch, _handle) = build(&cfg, discard, false, None, None);
        // Another global subscriber in this binary would be a bug, but every test that reads a
        // sink would fail on its own assertion, so there is nothing to add by panicking here.
        let _ = tracing::dispatcher::set_global_default(dispatch);
    });

    /// A subscriber built exactly as [`init`](super::init) builds the real one, writing to
    /// memory and taking the terminal and `RUST_LOG` answers as arguments rather than reading
    /// the process.
    ///
    /// Installs [`PROCESS_WIDE`] first, which is why it is every test's way in: a fixture built
    /// here is built before the code under it reaches its first call site.
    pub(crate) fn subscriber(
        cfg: &Log,
        is_tty: bool,
        rust_log: Option<&str>,
    ) -> (Sink, Dispatch, LogHandle) {
        LazyLock::force(&PROCESS_WIDE);
        let sink = Sink::default();
        let (dispatch, handle) =
            build(cfg, sink.clone(), is_tty, rust_log.map(str::to_owned), None);
        (sink, dispatch, handle)
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use overlay_core::config::Log;
    use overlay_core::events::{FirstArrival, Source, emit_first_arrival};
    use overlay_core::msgid::MessageId;
    use overlay_core::roster::{Hostname, Region, SelfIdentity};
    use overlay_core::topic::{Class, Topic};
    use serde_json::{Map, Value};

    use super::testing::Sink;
    use super::*;

    /// A moment with a nanosecond part, so a truncating conversion cannot pass.
    const AT_NANOS: u64 = 1_757_000_000_123_456_789;

    /// Every field of a `first_arrival` line, as the table in `docs/events.md` lists it. The
    /// queries in that file and T-052's dashboard read these names, so one of them changing
    /// without the document changing leaves a panel silently empty.
    const SCHEMA: [&str; 12] = [
        "timestamp",
        "level",
        "target",
        "event",
        "msg_id",
        "class",
        "topic",
        "node",
        "region",
        "site",
        "first_arrival_ns",
        "source",
    ];

    /// The field only an arrival from the overlay carries.
    const ORIGIN_PEER: &str = "origin_peer";

    /// Runs `body` under an in-memory subscriber and returns what it wrote.
    fn capture(
        cfg: &Log,
        is_tty: bool,
        rust_log: Option<&str>,
        body: impl FnOnce(&LogHandle),
    ) -> Sink {
        let (sink, dispatch, handle) = testing::subscriber(cfg, is_tty, rust_log);
        tracing::dispatcher::with_default(&dispatch, || body(&handle));
        sink
    }

    /// A line's field names, sorted, whatever order the formatter wrote them in.
    fn keys(line: &Map<String, Value>) -> Vec<&str> {
        let mut names: Vec<&str> = line.keys().map(String::as_str).collect();
        names.sort_unstable();
        names
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
            header: None,
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

        let text = sink.text();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2, "{text}");
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

    #[test]
    fn rust_log_wins_over_log_level_and_set_level_says_so() {
        let cfg = Log {
            level: LogLevel::Info,
            format: LogFormat::Json,
        };

        let sink = capture(&cfg, false, Some("debug"), |handle| {
            tracing::debug!("RUST_LOG lets this through");
            handle.set_level("error");
            tracing::debug!("and still does");
        });

        let lines = sink.objects();
        assert_eq!(lines.len(), 3, "{}", sink.text());
        assert_eq!(lines[0]["message"], "RUST_LOG lets this through");
        assert_eq!(
            lines[1]["message"],
            "RUST_LOG is set, so log.level is not applied"
        );
        assert_eq!(lines[1]["rust_log"], "debug");
        assert_eq!(lines[2]["message"], "and still does");
    }

    #[test]
    fn field_names_match_the_documented_schema() {
        let node = node();
        let topic = block();
        let origin = Hostname("bn-fra1-02".to_owned());

        let sink = capture(&Log::default(), false, None, |_| {
            emit_first_arrival(&arrival(&topic, &node, Class::Large, Source::Bn));
            emit_first_arrival(&arrival(
                &topic,
                &node,
                Class::Large,
                Source::Overlay { origin: &origin },
            ));
        });

        let lines = sink.objects();
        let mut expected = SCHEMA.to_vec();
        expected.sort_unstable();
        assert_eq!(keys(&lines[0]), expected);
        expected.push(ORIGIN_PEER);
        expected.sort_unstable();
        assert_eq!(keys(&lines[1]), expected);
    }
}
