//! Finding the epoll instance the overlay's I/O thread blocks in, and the socket on it.
//!
//! The reasoning for doing it this way rather than owning an epoll instance outright is in the
//! parent module. What makes it a lookup and not a guess is here: descriptors are per-process,
//! so `/proc/self/fd` lists every epoll instance in the sidecar and not only this thread's, but
//! `/proc/self/fdinfo` names what is registered on each of them, and exactly one has a socket
//! bound to the overlay's listen address.

use std::net::SocketAddr;
use std::os::fd::RawFd;

/// The epoll instance holding the socket bound to `listen`, and that socket, or what to tell an
/// operator when there is no such pair.
///
/// The socket comes back beside the epoll instance because it is where `SO_INCOMING_NAPI_ID`
/// is read from, and finding it is the same walk.
#[cfg(target_os = "linux")]
pub(super) fn find(listen: SocketAddr) -> Result<(RawFd, RawFd), &'static str> {
    for epoll in epoll_instances() {
        if let Some(socket) = registered(epoll)
            .into_iter()
            .find(|fd| bound_to(*fd) == Some(listen))
        {
            return Ok((epoll, socket));
        }
    }
    Err("no epoll instance in this process holds the overlay socket")
}

/// Every epoll instance this process holds, from the one directory that lists them.
#[cfg(target_os = "linux")]
fn epoll_instances() -> Vec<RawFd> {
    /// What `readlink` says about an epoll descriptor, and about nothing else.
    const EVENTPOLL: &str = "anon_inode:[eventpoll]";

    let Ok(entries) = std::fs::read_dir("/proc/self/fd") else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter(|entry| {
            std::fs::read_link(entry.path()).is_ok_and(|target| target.as_os_str() == EVENTPOLL)
        })
        .filter_map(|entry| entry.file_name().to_str()?.parse().ok())
        .collect()
}

/// The descriptors registered on an epoll instance, from the `tfd:` lines of its `fdinfo`.
#[cfg(target_os = "linux")]
fn registered(epoll: RawFd) -> Vec<RawFd> {
    let Ok(info) = std::fs::read_to_string(format!("/proc/self/fdinfo/{epoll}")) else {
        return Vec::new();
    };
    info.lines()
        .filter_map(|line| line.strip_prefix("tfd:"))
        .filter_map(|rest| rest.split_whitespace().next()?.parse().ok())
        .collect()
}

/// Where a descriptor is bound, or `None` where it is not a socket at all, which is what the
/// runtime's own wakeup descriptor is.
#[cfg(target_os = "linux")]
fn bound_to(fd: RawFd) -> Option<SocketAddr> {
    use nix::sys::socket::SockaddrStorage;

    let bound: SockaddrStorage = nix::sys::socket::getsockname(fd).ok()?;
    match (bound.as_sockaddr_in(), bound.as_sockaddr_in6()) {
        (Some(v4), _) => Some(std::net::SocketAddrV4::from(*v4).into()),
        (_, Some(v6)) => Some(std::net::SocketAddrV6::from(*v6).into()),
        _ => None,
    }
}

/// No `/proc`, no epoll, nothing to look for. The caller's one info line carries this reason
/// the same way it carries a kernel that is too old, so a developer reading a laptop's log is
/// told which of the two they are looking at.
#[cfg(not(target_os = "linux"))]
pub(super) fn find(_listen: SocketAddr) -> Result<(RawFd, RawFd), &'static str> {
    Err("per-epoll busy polling is Linux only")
}
