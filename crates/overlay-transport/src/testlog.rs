//! Everything `tracing` writes in this test binary, for the tests that assert a warning or an
//! error was emitted at all.
//!
//! One process-wide subscriber rather than a thread-scoped one: tracing caches a call site's
//! interest by asking whichever dispatcher first hits it, so a test that reaches a `warn!` with
//! no subscriber installed would cache "never" for that call site, and a thread-scoped
//! subscriber running afterwards would see nothing. It is shared rather than one per module for
//! the same reason and one more: `set_global_default` succeeds once per process.

use std::io::Write;
use std::sync::{Arc, LazyLock, Mutex};

/// The captured stream. Read its length before the code under test runs and [`Log::since`] that
/// mark afterwards, so tests running in parallel do not read each other's lines.
pub static LOG: LazyLock<Log> = LazyLock::new(|| {
    let log = Log::default();
    let sink = log.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(move || sink.clone())
        .finish();
    // Another global subscriber in this binary would be a bug, but the test would still fail on
    // its assertion, so there is no need to panic here.
    let _ = tracing::subscriber::set_global_default(subscriber);
    log
});

/// What the subscriber has written so far.
#[derive(Clone, Default)]
pub struct Log(Arc<Mutex<Vec<u8>>>);

impl Log {
    /// How much has been written, as a mark to read from.
    pub fn len(&self) -> usize {
        self.0.lock().unwrap().len()
    }

    /// What was written after the first `from` bytes.
    pub fn since(&self, from: usize) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()[from..]).into_owned()
    }
}

impl Write for Log {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
