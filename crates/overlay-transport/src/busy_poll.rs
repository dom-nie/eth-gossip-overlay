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

#[cfg(test)]
mod tests {
    use std::mem::{align_of, offset_of, size_of};

    use super::*;

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
