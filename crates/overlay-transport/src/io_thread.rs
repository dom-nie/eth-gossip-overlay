//! Which runtime polls the overlay socket (§5.1, §11.1).
//!
//! Everything in E9 is off in the shipped defaults (D30) and everything in it is Linux only.
//! With `overlay.io_thread.pin_cpu` unset, which is what an operator gets unless they went
//! looking, the endpoint is built on the runtime that builds the rest of the sidecar and this
//! module costs one info log.

use overlay_core::config::IoThread;

use crate::endpoint::EndpointError;

/// A bound endpoint and whatever is carrying it.
pub struct IoHandle {
    endpoint: quinn::Endpoint,
    pinned: bool,
}

impl IoHandle {
    /// The endpoint, for the connection manager. quinn shares one socket through clones of this
    /// handle, and every clone reaches the driver task on whichever runtime built it.
    pub fn endpoint(&self) -> quinn::Endpoint {
        self.endpoint.clone()
    }

    /// Whether the endpoint is running on the core `pin_cpu` asked for, which is what
    /// `overlay_io_thread_pinned` reports.
    pub fn pinned(&self) -> bool {
        self.pinned
    }

    /// Ends whatever this handle is carrying. Call it after the connection manager's own
    /// shutdown, which needs the endpoint's driver alive to close the connections politely.
    pub async fn shutdown(self) {}
}

/// Runs the overlay endpoint where `overlay.io_thread` asks for it.
pub fn spawn(
    cfg: &IoThread,
    build: impl FnOnce() -> Result<quinn::Endpoint, EndpointError> + Send + 'static,
) -> Result<IoHandle, EndpointError> {
    tracing::info!(
        pin_cpu = ?cfg.pin_cpu,
        linux = cfg!(target_os = "linux"),
        "overlay endpoint on the main runtime"
    );
    Ok(IoHandle {
        endpoint: build()?,
        pinned: false,
    })
}

#[cfg(test)]
mod tests {
    use overlay_core::config::IoThread;

    use super::*;
    use crate::endpoint::{self, connect, tests::*};
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

    /// The handoff §5.1 draws: the QUIC endpoint on a runtime of its own, the accept loop and
    /// everything above it on the main one. Nothing above the transport changes shape, so what
    /// has to hold is that bytes still cross in both directions with the socket and its reader
    /// on different runtimes.
    #[tokio::test(flavor = "multi_thread")]
    async fn frames_cross_between_runtimes() {
        let (seeds, pins) = fleet(&["bn-a", "bn-b"]);
        let cfg = config("127.0.0.1:0");
        let server = tls::server_config(pins.clone(), &own_key(&seeds, "bn-a")).unwrap();
        let listen = cfg.clone();

        let io = dedicated(None, move || {
            endpoint::bind(&listen, TEST_RECEIVE_WINDOW, server)
        })
        .unwrap();
        let addr = io.endpoint().local_addr().unwrap();
        // The accept loop is the connection manager's, on this runtime, as T-045 runs it.
        let acceptor = io.endpoint();
        let echo = tokio::spawn(async move {
            let connection = acceptor
                .accept()
                .await
                .expect("the endpoint is still open")
                .await
                .unwrap();
            let read = connection
                .accept_uni()
                .await
                .unwrap()
                .read_to_end(64)
                .await
                .unwrap();
            let mut back = connection.open_uni().await.unwrap();
            back.write_all(&read).await.unwrap();
            back.finish().unwrap();
            // Held until the dialler has read it: a dropped connection closes at once, and
            // whatever has not left the buffer goes with it.
            connection
        });

        let dialler = endpoint(&cfg, &pins, &seeds, "bn-b");
        let connection = connect(
            &cfg,
            TEST_RECEIVE_WINDOW,
            &dialler,
            addr,
            dial_config(&pins, &seeds, "bn-b", "bn-a"),
        )
        .await
        .unwrap();
        let mut out = connection.open_uni().await.unwrap();
        out.write_all(b"a chunk").await.unwrap();
        out.finish().unwrap();
        let back = connection
            .accept_uni()
            .await
            .unwrap()
            .read_to_end(64)
            .await
            .unwrap();

        assert_eq!(back, b"a chunk");
        drop(echo.await.unwrap());
        io.shutdown().await;
    }
}
