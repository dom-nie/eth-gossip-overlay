//! The NAPI instance behind the overlay's receive queue, and the IRQ suspension §11.1 asks for.
//!
//! Busy polling on its own still takes an interrupt per burst. Masking the queue's IRQ while
//! polling keeps finding packets is what removes them, and that is set per NAPI instance over
//! netdev netlink rather than on the socket, which is why this half needs a capability and the
//! epoll half does not.

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::busy_poll::tests::Fake;
    use crate::testlog::LOG;

    /// Neither is a descriptor or a queue. Every test here goes through the fake kernel.
    const SOCKET: RawFd = -1;
    const NAPI: u32 = 42;

    /// T-046's unit can grant `CAP_NET_ADMIN` with `AmbientCapabilities=`, and an operator can
    /// decide not to. Netdev netlink is the only part of this feature that needs it, so a
    /// process without it says so and leaves the queue's IRQ settings alone. Once, because the
    /// caller is waiting on a NAPI id and retrying, and a line per attempt is a log an operator
    /// stops reading.
    #[test]
    fn missing_cap_net_admin_skips_napi_setting_with_one_log_line() {
        let mark = LOG.len();
        let kernel = Fake::default();

        let asked = set_irq_suspend_timeout_with(&kernel, NAPI, Duration::from_millis(20));

        assert!(!asked.unwrap(), "the kernel was asked anyway");
        assert!(kernel.suspended.lock().unwrap().is_empty());
        assert_eq!(
            LOG.since(mark)
                .lines()
                .filter(|line| line.contains("CAP_NET_ADMIN"))
                .count(),
            1
        );
    }

    /// The kernel counts the suspension in nanoseconds and an operator writes milliseconds, so
    /// the conversion between them is the part that can be wrong by a factor of a million.
    #[test]
    fn set_irq_suspend_timeout_asks_the_kernel_in_nanoseconds() {
        let kernel = Fake {
            cap_net_admin: true,
            ..Fake::default()
        };

        let asked = set_irq_suspend_timeout_with(&kernel, NAPI, Duration::from_millis(20));

        assert!(asked.unwrap());
        assert_eq!(*kernel.suspended.lock().unwrap(), vec![(NAPI, 20_000_000)]);
    }

    /// `SO_INCOMING_NAPI_ID` answers zero both while nothing has arrived and on a device with no
    /// NAPI instance at all, and there is nothing for the caller to do in either case.
    #[test]
    fn a_napi_id_of_zero_reads_as_no_queue() {
        assert_eq!(id_of_with(&Fake::default(), SOCKET).unwrap(), None);

        let arrived = Fake {
            napi_id: NAPI,
            ..Fake::default()
        };

        assert_eq!(id_of_with(&arrived, SOCKET).unwrap(), Some(NAPI));
    }
}
