//! Which runtime polls the overlay socket (§5.1, §11.1).
//!
//! Everything in E9 is off in the shipped defaults (D30) and everything in it is Linux only.
//! With `overlay.io_thread.pin_cpu` unset, which is what an operator gets unless they went
//! looking, the endpoint is built on the runtime that builds the rest of the sidecar and this
//! module costs one info log.

use std::thread;

use overlay_core::config::IoThread;
use tokio::sync::oneshot;

use crate::endpoint::EndpointError;

/// What the I/O thread is called, so `ps -L -o psr,comm` names it beside the core it is on
/// (`docs/performance.md`).
const THREAD_NAME: &str = "overlay-io";

/// Why the overlay could not be brought up.
#[derive(Debug, thiserror::Error)]
pub enum IoThreadError {
    /// The endpoint could not be bound, wherever it was going to run.
    #[error(transparent)]
    Endpoint(#[from] EndpointError),
    /// The thread or its runtime could not be created. A host with no room for one more thread
    /// has something worse wrong with it than an unpinned overlay, so this ends the start
    /// instead of falling back.
    #[error("overlay I/O thread: {0}")]
    Thread(#[from] std::io::Error),
}

/// A bound endpoint and whatever is carrying it.
pub struct IoHandle {
    endpoint: quinn::Endpoint,
    pinned: bool,
    worker: Option<Worker>,
}

/// What the I/O thread sends back once it knows whether it has an endpoint, and whether it is
/// running on the core it was asked for.
type Bound = Result<(quinn::Endpoint, bool), IoThreadError>;

/// The I/O thread and the channel that ends it.
struct Worker {
    stop: oneshot::Sender<()>,
    thread: thread::JoinHandle<()>,
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
    pub async fn shutdown(self) {
        let Some(worker) = self.worker else { return };
        let _ = worker.stop.send(());
        // Joined on the blocking pool, so a shutdown deadline can still fire over a thread that
        // will not end (§11's two seconds).
        let _ = tokio::task::spawn_blocking(move || worker.thread.join()).await;
    }
}

/// Runs the overlay endpoint where `overlay.io_thread` asks for it.
pub fn spawn(
    cfg: &IoThread,
    build: impl FnOnce() -> Result<quinn::Endpoint, EndpointError> + Send + 'static,
) -> Result<IoHandle, IoThreadError> {
    let Some(cpu) = cfg.pin_cpu else {
        tracing::info!(
            pin_cpu = ?cfg.pin_cpu,
            linux = cfg!(target_os = "linux"),
            "overlay endpoint on the main runtime"
        );
        return Ok(IoHandle {
            endpoint: build()?,
            pinned: false,
            worker: None,
        });
    };
    dedicated(Some(cpu), build)
}

/// The endpoint on a `current_thread` runtime of its own, pinned to `cpu` where there is one.
///
/// That runtime owns one epoll instance and registers the overlay socket with it as the
/// endpoint is built, which is the isolation §11.1 asks for and what T-092 will set busy-poll
/// parameters on. Only the endpoint's own driver moves: quinn spawns a connection's driver on
/// whichever runtime created the connection, so a peer's timers stay with the connection
/// manager and what the I/O thread owns is every read off the socket.
///
/// `cpu` is an option so that the thread, the handoff and the join can be driven on a platform
/// that has no core to ask for; a start reaches this with `Some`.
fn dedicated(
    cpu: Option<u32>,
    build: impl FnOnce() -> Result<quinn::Endpoint, EndpointError> + Send + 'static,
) -> Result<IoHandle, IoThreadError> {
    let (ready, bound) = std::sync::mpsc::sync_channel::<Bound>(1);
    let (stop, stopped) = oneshot::channel();
    let thread = thread::Builder::new()
        .name(THREAD_NAME.to_owned())
        .spawn(move || {
            let pinned = cpu.is_some_and(pin_current_thread);
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(err) => {
                    let _ = ready.send(Err(err.into()));
                    return;
                }
            };
            match runtime.block_on(async { build() }) {
                Ok(endpoint) => {
                    if ready.send(Ok((endpoint, pinned))).is_err() {
                        return;
                    }
                    // Drives the endpoint until the handle says to stop; a `current_thread`
                    // runtime runs its spawned tasks inside whatever it is blocking on.
                    runtime.block_on(async {
                        let _ = stopped.await;
                    });
                }
                Err(err) => {
                    let _ = ready.send(Err(err.into()));
                }
            }
        })?;

    let (endpoint, pinned) = bound.recv().map_err(|_| {
        std::io::Error::other("the I/O thread ended before the endpoint was bound")
    })??;
    Ok(IoHandle {
        endpoint,
        pinned,
        worker: Some(Worker { stop, thread }),
    })
}

/// Pins the calling thread to `cpu`, reporting whether the kernel took it.
///
/// A core that does not exist, or one this process is not allowed on, is a warning and not a
/// refusal to start: an operator whose container has a narrower cpuset than the configuration
/// expects should lose the pinning, not the overlay (§11.1). `overlay_io_thread_pinned` is how
/// they find out.
#[cfg(target_os = "linux")]
fn pin_current_thread(cpu: u32) -> bool {
    let mut set = nix::sched::CpuSet::new();
    // Pid zero is the calling thread, which is the one the runtime will run on.
    let pinned = set
        .set(cpu as usize)
        .and_then(|()| nix::sched::sched_setaffinity(nix::unistd::Pid::from_raw(0), &set));
    match pinned {
        Ok(()) => {
            tracing::info!(cpu, "overlay I/O thread pinned");
            true
        }
        Err(err) => {
            tracing::warn!(cpu, %err, "overlay I/O thread not pinned; carrying on unpinned");
            false
        }
    }
}

/// There is no `sched_setaffinity` off Linux. A start never asks for a core there, so this is
/// only what gives the thread body one shape on every platform.
#[cfg(not(target_os = "linux"))]
fn pin_current_thread(_cpu: u32) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

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

    /// §11 gives a stopping sidecar two seconds, and the I/O thread is inside it: the manager
    /// closes the connections, then this thread has to end and be joined. The `Arc` is held by
    /// a task on the I/O runtime, so a count back at one is that runtime gone rather than a
    /// function that returned early.
    #[tokio::test(flavor = "multi_thread")]
    async fn shutdown_joins_the_io_thread_within_the_2_second_budget() {
        let (seeds, pins) = fleet(&["bn-a"]);
        let cfg = config("127.0.0.1:0");
        let server = tls::server_config(pins, &own_key(&seeds, "bn-a")).unwrap();
        let alive = Arc::new(());
        let held = alive.clone();

        let io = dedicated(None, move || {
            tokio::spawn(async move {
                let _held = held;
                std::future::pending::<()>().await;
            });
            endpoint::bind(&cfg, TEST_RECEIVE_WINDOW, server)
        })
        .unwrap();

        tokio::time::timeout(Duration::from_secs(2), io.shutdown())
            .await
            .expect("the I/O thread did not join inside the shutdown budget");
        assert_eq!(
            Arc::strong_count(&alive),
            1,
            "the I/O runtime is still running"
        );
    }

    /// What only a Linux machine can answer. Both names are in the test list on every platform;
    /// off Linux they print why they are not an answer.
    #[cfg(target_os = "linux")]
    mod pinning {
        use super::*;

        /// The highest core this process is allowed on, or `None` where it is allowed on one
        /// only, since pinning to the core everything already runs on would assert nothing.
        /// Read off the affinity mask rather than the core count, because a cgroup can allow
        /// four cores that are not numbered zero to three.
        fn highest_allowed_cpu() -> Option<u32> {
            let allowed = nix::sched::sched_getaffinity(nix::unistd::Pid::from_raw(0)).ok()?;
            let cpus: Vec<u32> = (0..nix::sched::CpuSet::count())
                .filter(|cpu| allowed.is_set(*cpu).unwrap_or(false))
                .map(|cpu| cpu as u32)
                .collect();
            match cpus.len() {
                0 | 1 => None,
                _ => cpus.last().copied(),
            }
        }

        /// The ticket's whole point: the runtime the endpoint runs on is on the core the
        /// configuration named. `sched_getcpu` is read from inside the closure that binds,
        /// which the thread calls after setting its own affinity.
        #[tokio::test(flavor = "multi_thread")]
        async fn io_thread_runs_on_configured_cpu() {
            let Some(cpu) = highest_allowed_cpu() else {
                eprintln!("skipped: this process is allowed on one CPU only");
                return;
            };
            let (seeds, pins) = fleet(&["bn-a"]);
            let cfg = config("127.0.0.1:0");
            let server = tls::server_config(pins, &own_key(&seeds, "bn-a")).unwrap();
            let (running_on, read) = std::sync::mpsc::channel();

            let io = spawn(
                &IoThread {
                    pin_cpu: Some(cpu),
                    ..IoThread::default()
                },
                move || {
                    let _ = running_on.send(nix::sched::sched_getcpu());
                    endpoint::bind(&cfg, TEST_RECEIVE_WINDOW, server)
                },
            )
            .unwrap();

            assert!(io.pinned());
            assert_eq!(read.recv().unwrap().unwrap() as u32, cpu);
            io.shutdown().await;
        }

        /// The configuration typo an operator makes, and the cpuset a container gives them.
        /// Losing the pinning is not a reason to leave the fleet: the endpoint comes up on the
        /// thread it asked for, unpinned, and the warning names the core (§11.1).
        #[tokio::test(flavor = "multi_thread")]
        async fn invalid_cpu_warns_and_continues_unpinned() {
            let mark = LOG.len();
            let (seeds, pins) = fleet(&["bn-a"]);
            let cfg = config("127.0.0.1:0");
            let server = tls::server_config(pins, &own_key(&seeds, "bn-a")).unwrap();
            // Past CPU_SETSIZE, so no machine and no cgroup can make this core exist.
            let absent = nix::sched::CpuSet::count() as u32;

            let io = spawn(
                &IoThread {
                    pin_cpu: Some(absent),
                    ..IoThread::default()
                },
                move || endpoint::bind(&cfg, TEST_RECEIVE_WINDOW, server),
            )
            .unwrap();

            assert!(!io.pinned());
            assert!(io.endpoint().local_addr().is_ok(), "the endpoint is gone");
            assert_eq!(
                LOG.since(mark)
                    .lines()
                    .filter(|line| line.contains("overlay I/O thread not pinned"))
                    .count(),
                1
            );
            io.shutdown().await;
        }
    }

    #[cfg(not(target_os = "linux"))]
    mod pinning {
        #[test]
        fn io_thread_runs_on_configured_cpu() {
            eprintln!("skipped: sched_setaffinity and sched_getcpu are Linux only");
        }

        #[test]
        fn invalid_cpu_warns_and_continues_unpinned() {
            eprintln!("skipped: sched_setaffinity is Linux only");
        }
    }
}
