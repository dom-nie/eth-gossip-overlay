//! Busy polling the overlay's own epoll instance, with the NIC queue's IRQ suspended while a
//! burst is arriving (§11.1).
//!
//! Linux 6.13 added `EPIOCSPARAMS`, an ioctl on an epoll fd that makes `epoll_wait` spin on the
//! queue for a bounded number of microseconds before it sleeps. Paired with the NAPI instance's
//! `irq-suspend-timeout`, set over netdev netlink, the reserved core polls while packets keep
//! coming and the queue's interrupt stays masked; when the burst ends the timeout expires and
//! the queue goes back to interrupts. It is the lowest-latency receive path that does not burn a
//! core permanently, and it is off in the shipped defaults (D30).
//!
//! Everything here degrades to nothing. A kernel before 6.13, a process without `CAP_NET_ADMIN`
//! and a queue with no NAPI id each cost one info line and leave `overlay_busy_poll_enabled` at
//! zero. None of them are an error, because losing a tuning must never cost the mesh.
//!
//! # Where the epoll fd comes from
//!
//! T-091 gave the endpoint a `current_thread` tokio runtime of its own, and that runtime owns
//! one epoll instance. tokio does not expose it, so the ticket offered three ways to reach it:
//! (a) find it through `/proc/self/task/<tid>/fd`, (b) run a mio loop of our own and feed quinn
//! through its `AsyncUdpSocket` trait, (c) io_uring, which §11.1 rules out at these rates.
//!
//! This is **(a)**. File descriptors are per-process and not per-thread, so the directory lists
//! every epoll instance in the sidecar and not just this thread's — but each one's
//! `/proc/self/fdinfo` names the descriptors registered on it, and exactly one epoll instance
//! has the overlay's UDP socket. Asking `getsockname` about each registered descriptor and
//! matching the endpoint's own local address picks it out, which makes this a lookup rather
//! than the guess the ticket feared. It also hands back the socket descriptor, which is where
//! the NAPI id is read from.
//!
//! (b) was the fallback and stays available. It buys certainty about the epoll fd at the price
//! of a hand-written reactor — readiness registration, waker plumbing, write readiness, GSO and
//! GRO segment handling — replacing code quinn maintains, on the receive path of the only
//! transport this product has, for a feature that is off by default. The failure mode of (a) is
//! a missing gauge; the failure mode of (b) is a broken overlay. T-093 wants a socket that
//! exposes control messages for `SO_TIMESTAMPING`, which does need an `AsyncUdpSocket` of our
//! own, but not an epoll of our own: quinn's stock one is built on `tokio::io::unix::AsyncFd`,
//! and one written for T-093 the same way stays registered in this thread's epoll, where the
//! lookup below still finds it.

pub mod napi;

use std::io;
use std::os::fd::RawFd;

/// Whether the kernel took the busy-poll parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Support {
    /// The epoll instance is busy polling: Linux 6.13 or later.
    Enabled,
    /// The ioctl is not there, so nothing was changed. A kernel before 6.13, or not Linux.
    Unsupported,
}

/// `struct epoll_params` from `include/uapi/linux/eventpoll.h`, the argument `EPIOCSPARAMS`
/// reads and `EPIOCGPARAMS` writes back.
///
/// Declared here rather than taken from libc because the ioctl is issued on every build and
/// only Linux has libc's copy; the test holds this one to the same eight bytes and, on Linux,
/// to libc's copy beside it.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EpollParams {
    /// How long `epoll_wait` spins on the queue before it sleeps. §11.1 asks for 50 to 200.
    pub busy_poll_usecs: u32,
    /// How many packets one spin may take. Zero leaves the kernel its own default, which is
    /// also the only value it accepts without `CAP_NET_ADMIN` above `NAPI_POLL_WEIGHT`.
    pub busy_poll_budget: u16,
    /// Whether the queue's IRQ stays masked while the core is spinning.
    pub prefer_busy_poll: u8,
    /// The kernel rejects a non-zero value here.
    pad: u8,
}

impl EpollParams {
    /// Spin on the queue for `usecs` with the IRQ masked, at the kernel's own budget.
    pub fn preferring_busy_poll(usecs: u32) -> Self {
        Self {
            busy_poll_usecs: usecs,
            busy_poll_budget: 0,
            prefer_busy_poll: 1,
            pad: 0,
        }
    }
}

/// The kernel calls this module makes.
///
/// Behind a trait because every answer that decides what an operator sees is one no test can
/// arrange for real: a kernel too old for the ioctl, a process without `CAP_NET_ADMIN`, a queue
/// with no NAPI id. [`Host`] is the one implementation that reaches a kernel, and off Linux
/// even that one only says so.
pub(crate) trait Kernel {
    /// `ioctl(epoll, EPIOCSPARAMS, params)`.
    fn set_epoll_params(&self, epoll: RawFd, params: &EpollParams) -> io::Result<()>;
    /// `ioctl(epoll, EPIOCGPARAMS, …)`, which changes nothing.
    fn epoll_params(&self, epoll: RawFd) -> io::Result<EpollParams>;
    /// `getsockopt(SO_INCOMING_NAPI_ID)`. Zero until the queue has delivered a packet, and on
    /// every device that has no NAPI instance.
    fn napi_id(&self, socket: RawFd) -> io::Result<u32>;
    /// Whether this process holds `CAP_NET_ADMIN`, without which netdev netlink answers nothing.
    fn has_cap_net_admin(&self) -> bool;
    /// `NETDEV_CMD_NAPI_SET` with `irq-suspend-timeout`, which the kernel counts in nanoseconds.
    fn set_irq_suspend_timeout(&self, napi_id: u32, nanos: u64) -> io::Result<()>;
}

/// The running kernel.
pub(crate) struct Host;

#[cfg(target_os = "linux")]
impl Kernel for Host {
    fn set_epoll_params(&self, epoll: RawFd, params: &EpollParams) -> io::Result<()> {
        // The kernel copies eight bytes out of the pointer and writes nothing back, and
        // `params` is a live borrow of exactly that struct.
        let done = unsafe { libc::ioctl(epoll, libc::EPIOCSPARAMS, std::ptr::from_ref(params)) };
        result(done)
    }

    fn epoll_params(&self, epoll: RawFd) -> io::Result<EpollParams> {
        let mut params = EpollParams::default();
        // The kernel writes eight bytes into the pointer, which is a live exclusive borrow of
        // exactly that struct.
        let done =
            unsafe { libc::ioctl(epoll, libc::EPIOCGPARAMS, std::ptr::from_mut(&mut params)) };
        result(done).map(|()| params)
    }

    fn napi_id(&self, socket: RawFd) -> io::Result<u32> {
        let mut id: u32 = 0;
        let mut len = size_of::<u32>() as libc::socklen_t;
        // The kernel writes four bytes through the value pointer and the length it wrote
        // through the other; both are live exclusive borrows of exactly that size.
        let read = unsafe {
            libc::getsockopt(
                socket,
                libc::SOL_SOCKET,
                libc::SO_INCOMING_NAPI_ID,
                std::ptr::from_mut(&mut id).cast(),
                std::ptr::from_mut(&mut len),
            )
        };
        result(read).map(|()| id)
    }

    fn has_cap_net_admin(&self) -> bool {
        /// From `include/uapi/linux/capability.h`.
        const CAP_NET_ADMIN: u32 = 12;

        // A process that cannot read its own status has bigger problems than an unsuspended
        // IRQ, and the caller's answer to both is the same line.
        let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
            return false;
        };
        status
            .lines()
            .find_map(|line| line.strip_prefix("CapEff:"))
            .and_then(|effective| u64::from_str_radix(effective.trim(), 16).ok())
            .is_some_and(|caps| caps & (1 << CAP_NET_ADMIN) != 0)
    }

    fn set_irq_suspend_timeout(&self, napi_id: u32, nanos: u64) -> io::Result<()> {
        napi::netlink::set_irq_suspend_timeout(napi_id, nanos)
    }
}

/// Off Linux there is no epoll instance to set anything on, so the answer is the one every
/// caller already handles: this kernel does not have the ioctl.
#[cfg(not(target_os = "linux"))]
impl Kernel for Host {
    fn set_epoll_params(&self, _epoll: RawFd, _params: &EpollParams) -> io::Result<()> {
        Err(io::Error::from_raw_os_error(libc::ENOTTY))
    }

    fn epoll_params(&self, _epoll: RawFd) -> io::Result<EpollParams> {
        Err(io::Error::from_raw_os_error(libc::ENOTTY))
    }

    /// No NAPI, so no id, which is the same answer a Linux host gives for loopback.
    fn napi_id(&self, _socket: RawFd) -> io::Result<u32> {
        Ok(0)
    }

    /// No capabilities to hold, so the caller stops before it reaches for netlink that is also
    /// not there.
    fn has_cap_net_admin(&self) -> bool {
        false
    }

    fn set_irq_suspend_timeout(&self, _napi_id: u32, _nanos: u64) -> io::Result<()> {
        Err(io::Error::from_raw_os_error(libc::ENOTTY))
    }
}

/// What an ioctl returned, as an error where it failed.
#[cfg(target_os = "linux")]
fn result(returned: libc::c_int) -> io::Result<()> {
    match returned {
        0.. => Ok(()),
        _ => Err(io::Error::last_os_error()),
    }
}

/// Sets `params` on `epoll`, so `epoll_wait` spins on the queue before it sleeps.
///
/// A kernel that does not have the ioctl is [`Support::Unsupported`] and not an error, because
/// losing a tuning must never cost the mesh (§11.1). Anything else the kernel says does come
/// back as an error: the caller logs it and carries on, but it says what happened.
pub fn apply(epoll: RawFd, params: &EpollParams) -> io::Result<Support> {
    apply_with(&Host, epoll, params)
}

fn apply_with(kernel: &dyn Kernel, epoll: RawFd, params: &EpollParams) -> io::Result<Support> {
    match kernel.set_epoll_params(epoll, params) {
        Ok(()) => Ok(Support::Enabled),
        Err(err) if missing_ioctl(&err) => Ok(Support::Unsupported),
        Err(err) => Err(err),
    }
}

/// The busy-poll parameters `epoll` is running with, or `None` from a kernel that has no
/// `EPIOCSPARAMS` at all.
///
/// Reads and changes nothing, so it is both the startup probe that tells a kernel before 6.13
/// from an epoll instance that could not be found, and the read-back `docs/performance.md`
/// gives an operator for confirming that [`apply`] took.
pub fn detect(epoll: RawFd) -> io::Result<Option<EpollParams>> {
    detect_with(&Host, epoll)
}

fn detect_with(kernel: &dyn Kernel, epoll: RawFd) -> io::Result<Option<EpollParams>> {
    match kernel.epoll_params(epoll) {
        Ok(params) => Ok(Some(params)),
        Err(err) if missing_ioctl(&err) => Ok(None),
        Err(err) => Err(err),
    }
}

/// Whether the error says this kernel has no `EPIOCSPARAMS`, rather than that the call went
/// wrong. `ENOTTY` is a kernel before 6.13 answering a number it has never heard of; `EINVAL`
/// is one that knows the number but not on this descriptor.
fn missing_ioctl(err: &io::Error) -> bool {
    matches!(err.raw_os_error(), Some(libc::ENOTTY | libc::EINVAL))
}

#[cfg(test)]
pub(crate) mod tests {
    use std::mem::{align_of, offset_of, size_of};
    use std::sync::Mutex;

    use super::*;

    /// Not a descriptor of anything. Every test here goes through [`Fake`], which never touches
    /// the number, and passing a plausible one would only invite a reader to think it matters.
    const EPOLL: RawFd = -1;

    /// A kernel that answers whatever the test needs, and records what it was asked.
    ///
    /// Every answer worth testing is one no host can be made to give: no development machine
    /// runs a kernel older than the ioctl, and a test cannot take `CAP_NET_ADMIN` away from a
    /// process that holds it or hand it to one that does not.
    #[derive(Default)]
    pub(crate) struct Fake {
        /// What `EPIOCSPARAMS` was handed, in order.
        pub applied: Mutex<Vec<(RawFd, EpollParams)>>,
        /// The errno both epoll ioctls fail with, where the test wants them to fail.
        pub epoll_errno: Option<i32>,
        /// What `EPIOCGPARAMS` reads back.
        pub holds: EpollParams,
        /// What `SO_INCOMING_NAPI_ID` answers. Zero is a queue that has delivered nothing.
        pub napi_id: u32,
        /// Whether the process is allowed to talk to netdev netlink.
        pub cap_net_admin: bool,
        /// The NAPI id and nanoseconds `NETDEV_CMD_NAPI_SET` was handed, in order.
        pub suspended: Mutex<Vec<(u32, u64)>>,
    }

    impl Kernel for Fake {
        fn set_epoll_params(&self, epoll: RawFd, params: &EpollParams) -> io::Result<()> {
            if let Some(errno) = self.epoll_errno {
                return Err(io::Error::from_raw_os_error(errno));
            }
            self.applied.lock().unwrap().push((epoll, *params));
            Ok(())
        }

        fn epoll_params(&self, _epoll: RawFd) -> io::Result<EpollParams> {
            match self.epoll_errno {
                Some(errno) => Err(io::Error::from_raw_os_error(errno)),
                None => Ok(self.holds),
            }
        }

        fn napi_id(&self, _socket: RawFd) -> io::Result<u32> {
            Ok(self.napi_id)
        }

        fn has_cap_net_admin(&self) -> bool {
            self.cap_net_admin
        }

        fn set_irq_suspend_timeout(&self, napi_id: u32, nanos: u64) -> io::Result<()> {
            self.suspended.lock().unwrap().push((napi_id, nanos));
            Ok(())
        }
    }

    /// The whole point of the ticket's "nothing happens and nothing breaks": on a kernel before
    /// 6.13 the ioctl number is one nothing answers to, and the sidecar has to read that as an
    /// answer rather than as a failure. `EINVAL` is the same answer from a kernel that knows the
    /// number but not on this descriptor.
    #[test]
    fn apply_with_enotty_returns_unsupported_and_does_not_error() {
        for errno in [libc::ENOTTY, libc::EINVAL] {
            let kernel = Fake {
                epoll_errno: Some(errno),
                ..Fake::default()
            };

            let support = apply_with(&kernel, EPOLL, &EpollParams::preferring_busy_poll(100));

            assert_eq!(support.unwrap(), Support::Unsupported, "errno {errno}");
            assert!(kernel.applied.lock().unwrap().is_empty());
        }
    }

    /// The other half: a kernel that has the ioctl gets exactly the parameters the
    /// configuration asked for, on the descriptor it was given.
    #[test]
    fn apply_hands_the_kernel_the_parameters_it_was_given() {
        let kernel = Fake::default();
        let params = EpollParams::preferring_busy_poll(200);

        let support = apply_with(&kernel, EPOLL, &params);

        assert_eq!(support.unwrap(), Support::Enabled);
        assert_eq!(*kernel.applied.lock().unwrap(), vec![(EPOLL, params)]);
    }

    /// An errno that is not "no such ioctl" is not an answer, and swallowing it would leave an
    /// operator with a gauge at zero and no line saying why.
    #[test]
    fn apply_passes_on_an_error_that_is_not_a_missing_ioctl() {
        let kernel = Fake {
            epoll_errno: Some(libc::EPERM),
            ..Fake::default()
        };

        let err = apply_with(&kernel, EPOLL, &EpollParams::preferring_busy_poll(100)).unwrap_err();

        assert_eq!(err.raw_os_error(), Some(libc::EPERM));
    }

    /// `EPIOCGPARAMS` is how test 5 and `docs/performance.md` confirm the parameters took, and
    /// how the startup path tells "this kernel is too old" from "the epoll fd was not found".
    #[test]
    fn detect_reads_the_parameters_back_and_says_when_there_are_none() {
        let running = EpollParams::preferring_busy_poll(50);
        let kernel = Fake {
            holds: running,
            ..Fake::default()
        };

        assert_eq!(detect_with(&kernel, EPOLL).unwrap(), Some(running));

        let old = Fake {
            epoll_errno: Some(libc::ENOTTY),
            ..Fake::default()
        };

        assert_eq!(detect_with(&old, EPOLL).unwrap(), None);
    }

    /// `struct epoll_params` is a kernel ABI. The ioctl reads eight bytes at fixed offsets and
    /// says nothing at all if the layout is wrong: it would take whatever happened to sit at
    /// offset 4 as the budget. The numbers here are `include/uapi/linux/eventpoll.h`, and on
    /// Linux the same assertion runs against libc's own declaration, so a release that changes
    /// either one fails here instead of quietly busy-polling with a garbage budget.
    #[test]
    fn epoll_params_struct_layout_matches_kernel_abi() {
        assert_eq!(size_of::<EpollParams>(), 8);
        assert_eq!(align_of::<EpollParams>(), 4);
        assert_eq!(offset_of!(EpollParams, busy_poll_usecs), 0);
        assert_eq!(offset_of!(EpollParams, busy_poll_budget), 4);
        assert_eq!(offset_of!(EpollParams, prefer_busy_poll), 6);
        assert_eq!(offset_of!(EpollParams, pad), 7);

        #[cfg(target_os = "linux")]
        {
            assert_eq!(size_of::<EpollParams>(), size_of::<libc::epoll_params>());
            assert_eq!(offset_of!(libc::epoll_params, busy_poll_usecs), 0);
            assert_eq!(offset_of!(libc::epoll_params, busy_poll_budget), 4);
            assert_eq!(offset_of!(libc::epoll_params, prefer_busy_poll), 6);
            // The request number encodes the direction and the argument's size, so a struct
            // that grew would send the kernel a number it does not answer to.
            assert_eq!(libc::EPIOCSPARAMS as u64, 0x4008_8a01);
            assert_eq!(libc::EPIOCGPARAMS as u64, 0x8008_8a02);
        }
    }
}
