//! The NAPI instance behind the overlay's receive queue, and the IRQ suspension §11.1 asks for.
//!
//! Busy polling on its own still takes an interrupt per burst. Masking the queue's IRQ while
//! polling keeps finding packets is what removes them, and that is set per NAPI instance over
//! netdev netlink rather than on the socket, which is why this half needs a capability and the
//! epoll half does not.

use std::io;
use std::os::fd::RawFd;
use std::time::Duration;

use super::{Host, Kernel};

/// The NAPI instance that delivered the last packet to `socket`, from `SO_INCOMING_NAPI_ID`.
///
/// `None` where the kernel has no id to give: nothing has arrived on the socket yet, or the
/// device behind it has no NAPI instance at all, which is loopback and most of what a container
/// hands a process.
pub fn id_of(socket: RawFd) -> io::Result<Option<u32>> {
    id_of_with(&Host, socket)
}

fn id_of_with(kernel: &dyn Kernel, socket: RawFd) -> io::Result<Option<u32>> {
    match kernel.napi_id(socket)? {
        0 => Ok(None),
        id => Ok(Some(id)),
    }
}

/// Masks the queue's IRQ for `timeout` while polling keeps finding packets, and reports whether
/// the kernel was asked at all (`NETDEV_CMD_NAPI_SET`, Linux 6.13).
///
/// Netdev netlink needs `CAP_NET_ADMIN`, which T-046's unit grants with `AmbientCapabilities=`.
/// A process without it logs one line and leaves the queue on its interrupts: an operator who
/// did not grant a capability made a decision rather than a mistake, and busy polling without
/// the suspension is still most of the tuning.
pub fn set_irq_suspend_timeout(napi_id: u32, timeout: Duration) -> io::Result<bool> {
    set_irq_suspend_timeout_with(&Host, napi_id, timeout)
}

fn set_irq_suspend_timeout_with(
    kernel: &dyn Kernel,
    napi_id: u32,
    timeout: Duration,
) -> io::Result<bool> {
    if !kernel.has_cap_net_admin() {
        tracing::info!(
            napi_id,
            "overlay IRQ suspension needs CAP_NET_ADMIN; leaving the queue on interrupts"
        );
        return Ok(false);
    }
    // Saturating rather than wrapping. The configuration caps the timeout at a second so this
    // cannot overflow, and a wrap would mask the queue's IRQ for an arbitrary time.
    let nanos = u64::try_from(timeout.as_nanos()).unwrap_or(u64::MAX);
    kernel.set_irq_suspend_timeout(napi_id, nanos)?;
    tracing::info!(
        napi_id,
        timeout_ms = timeout.as_millis(),
        "overlay NIC queue IRQ suspended during bursts"
    );
    Ok(true)
}

/// One `NETDEV_CMD_NAPI_SET` over generic netlink, written out by hand.
///
/// A netlink crate would buy the family resolution, which is the fifteen lines of [`family_id`]
/// below. It would not buy a single one of the netdev numbers, because none of them carry the
/// family, so those would be written out either way. That is not enough to earn a dependency in
/// a crate whose whole list fits on a screen.
#[cfg(target_os = "linux")]
pub(super) mod netlink {
    use std::io;
    use std::os::fd::{AsRawFd, OwnedFd};

    use nix::sys::socket::{
        AddressFamily, MsgFlags, SockFlag, SockProtocol, SockType, recv, send, setsockopt, socket,
        sockopt,
    };
    use nix::sys::time::{TimeVal, TimeValLike};

    /// `include/uapi/linux/netlink.h`: `struct nlmsghdr` and the flags and type it carries.
    const NLMSG_HEADER: usize = 16;
    const NLMSG_ERROR: u16 = 2;
    const NLM_F_REQUEST: u16 = 1;
    const NLM_F_ACK: u16 = 4;

    /// `include/uapi/linux/genetlink.h`: `struct genlmsghdr`, the controller's own family, and
    /// the command that resolves a family name to the number it was given at boot.
    const GENL_HEADER: usize = 4;
    const GENL_VERSION: u8 = 1;
    const GENL_ID_CTRL: u16 = 16;
    const CTRL_CMD_GETFAMILY: u8 = 3;
    const CTRL_ATTR_FAMILY_ID: u16 = 1;
    const CTRL_ATTR_FAMILY_NAME: u16 = 2;

    /// `include/uapi/linux/netdev.h`, Linux 6.13.
    const NETDEV_FAMILY: &[u8] = b"netdev\0";
    const NETDEV_CMD_NAPI_SET: u8 = 14;
    const NETDEV_A_NAPI_ID: u16 = 2;
    const NETDEV_A_NAPI_IRQ_SUSPEND_TIMEOUT: u16 = 7;

    /// A kernel that answers nothing must not hold up a start.
    const REPLY_TIMEOUT_SECONDS: i64 = 1;

    /// Asks netdev to suspend `napi_id`'s IRQ for `nanos` while polling is finding packets.
    pub fn set_irq_suspend_timeout(napi_id: u32, nanos: u64) -> io::Result<()> {
        let socket = open()?;
        let family = family_id(&socket)?;
        let mut attrs = attribute(NETDEV_A_NAPI_ID, &napi_id.to_ne_bytes());
        attrs.extend(attribute(
            NETDEV_A_NAPI_IRQ_SUSPEND_TIMEOUT,
            &nanos.to_ne_bytes(),
        ));
        let request = message(
            family,
            NETDEV_CMD_NAPI_SET,
            NLM_F_REQUEST | NLM_F_ACK,
            2,
            &attrs,
        );
        round_trip(&socket, &request).map(drop)
    }

    /// A generic netlink socket that will not wait forever for an answer.
    fn open() -> io::Result<OwnedFd> {
        let netlink = socket(
            AddressFamily::Netlink,
            SockType::Raw,
            SockFlag::SOCK_CLOEXEC,
            SockProtocol::NetlinkGeneric,
        )?;
        setsockopt(
            &netlink,
            sockopt::ReceiveTimeout,
            &TimeVal::seconds(REPLY_TIMEOUT_SECONDS),
        )?;
        Ok(netlink)
    }

    /// The number the netdev family was given at boot, which is the only thing about it that is
    /// not a constant.
    fn family_id(socket: &OwnedFd) -> io::Result<u16> {
        let request = message(
            GENL_ID_CTRL,
            CTRL_CMD_GETFAMILY,
            NLM_F_REQUEST,
            1,
            &attribute(CTRL_ATTR_FAMILY_NAME, NETDEV_FAMILY),
        );
        let reply = round_trip(socket, &request)?;
        let body = reply.get(NLMSG_HEADER + GENL_HEADER..).ok_or_else(short)?;
        attributes(body)
            .find(|(kind, _)| *kind == CTRL_ATTR_FAMILY_ID)
            .and_then(|(_, value)| value.get(..2))
            .map(|value| u16::from_ne_bytes([value[0], value[1]]))
            .ok_or_else(|| io::Error::other("the kernel has no netdev generic netlink family"))
    }

    /// Sends one message and reads the one datagram that answers it, turning a netlink error
    /// message into the errno it carries.
    fn round_trip(socket: &OwnedFd, request: &[u8]) -> io::Result<Vec<u8>> {
        let fd = socket.as_raw_fd();
        send(fd, request, MsgFlags::empty())?;
        let mut reply = vec![0u8; 4096];
        let read = recv(fd, &mut reply, MsgFlags::empty())?;
        reply.truncate(read);

        let header = reply.get(..NLMSG_HEADER).ok_or_else(short)?;
        if u16::from_ne_bytes([header[4], header[5]]) != NLMSG_ERROR {
            return Ok(reply);
        }
        // `struct nlmsgerr` opens with the negated errno, and zero is the acknowledgement a
        // request that carried NLM_F_ACK gets back.
        let code = reply
            .get(NLMSG_HEADER..NLMSG_HEADER + 4)
            .ok_or_else(short)?;
        match i32::from_ne_bytes([code[0], code[1], code[2], code[3]]) {
            0 => Ok(reply),
            negative => Err(io::Error::from_raw_os_error(-negative)),
        }
    }

    /// One netlink message: the header, the generic netlink header, then the attributes.
    fn message(family: u16, command: u8, flags: u16, seq: u32, attrs: &[u8]) -> Vec<u8> {
        let len = NLMSG_HEADER + GENL_HEADER + attrs.len();
        let mut out = Vec::with_capacity(len);
        out.extend((len as u32).to_ne_bytes());
        out.extend(family.to_ne_bytes());
        out.extend(flags.to_ne_bytes());
        out.extend(seq.to_ne_bytes());
        // The port id, which the kernel fills in when it binds the socket on the first send.
        out.extend(0u32.to_ne_bytes());
        out.push(command);
        out.push(GENL_VERSION);
        out.extend(0u16.to_ne_bytes());
        out.extend(attrs);
        out
    }

    /// One `struct nlattr` and its payload, padded out to four bytes.
    fn attribute(kind: u16, payload: &[u8]) -> Vec<u8> {
        let len = 4 + payload.len();
        let mut out = Vec::with_capacity(len.next_multiple_of(4));
        out.extend((len as u16).to_ne_bytes());
        out.extend(kind.to_ne_bytes());
        out.extend(payload);
        out.resize(len.next_multiple_of(4), 0);
        out
    }

    /// The attributes in a message body, stopping at the first one that does not fit rather
    /// than trusting a length the kernel wrote.
    fn attributes(mut body: &[u8]) -> impl Iterator<Item = (u16, &[u8])> {
        std::iter::from_fn(move || {
            let header = body.get(..4)?;
            let len = usize::from(u16::from_ne_bytes([header[0], header[1]]));
            let kind = u16::from_ne_bytes([header[2], header[3]]);
            let value = body.get(4..len)?;
            body = body.get(len.next_multiple_of(4)..).unwrap_or_default();
            Some((kind, value))
        })
    }

    fn short() -> io::Error {
        io::Error::other("short netlink reply")
    }
}

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
