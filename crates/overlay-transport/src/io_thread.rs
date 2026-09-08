//! Which runtime polls the overlay socket (§5.1, §11.1).

#[cfg(test)]
mod tests {
    use overlay_core::config::IoThread;

    use super::*;
    use crate::endpoint::{self, tests::*};
    use crate::testlog::LOG;
    use crate::tls;

    /// The shipped default reserves no core, so the endpoint stays on the runtime that builds
    /// everything else. The one info line carries both halves of the fallback rule, because a
    /// host that did ask for a core and is not on Linux takes the same branch.
    #[tokio::test]
    async fn unset_pin_cpu_runs_on_main_runtime_and_logs_info() {
        let mark = LOG.len();
        let (seeds, pins) = fleet(&["bn-a"]);
        let cfg = config("127.0.0.1:0");
        let server = tls::server_config(pins, &own_key(&seeds, "bn-a")).unwrap();

        let io = spawn(&IoThread::default(), move || {
            endpoint::bind(&cfg, TEST_RECEIVE_WINDOW, server)
        })
        .unwrap();

        assert!(!io.pinned());
        assert_eq!(
            LOG.since(mark)
                .lines()
                .filter(|line| line.contains("overlay endpoint on the main runtime")
                    && line.contains("pin_cpu=None"))
                .count(),
            1
        );
        io.shutdown().await;
    }
}
