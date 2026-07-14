// Copyright 2026 Cloudflare, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Extensions to the regular TCP APIs

#![allow(non_camel_case_types)]

#[cfg(target_os = "linux")]
use libc::c_ulonglong;
#[cfg(unix)]
use libc::socklen_t;
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
use libc::{c_int, c_void};
use pingora_error::{Error, ErrorType::*, OrErr, Result};
use std::io::{self, ErrorKind};
use std::mem;
use std::net::SocketAddr;
#[cfg(unix)]
use std::os::unix::io::{AsRawFd, RawFd};
#[cfg(windows)]
use std::os::windows::io::{AsRawSocket, RawSocket};
use std::time::Duration;
#[cfg(unix)]
use tokio::net::UnixStream;
use tokio::net::{TcpSocket, TcpStream};

use crate::connectors::l4::BindTo;

/// The (copy of) the kernel struct tcp_info returns
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct TCP_INFO {
    pub tcpi_state: u8,
    pub tcpi_ca_state: u8,
    pub tcpi_retransmits: u8,
    pub tcpi_probes: u8,
    pub tcpi_backoff: u8,
    pub tcpi_options: u8,
    pub tcpi_snd_wscale_4_rcv_wscale_4: u8,
    pub tcpi_delivery_rate_app_limited: u8,
    pub tcpi_rto: u32,
    pub tcpi_ato: u32,
    pub tcpi_snd_mss: u32,
    pub tcpi_rcv_mss: u32,
    pub tcpi_unacked: u32,
    pub tcpi_sacked: u32,
    pub tcpi_lost: u32,
    pub tcpi_retrans: u32,
    pub tcpi_fackets: u32,
    pub tcpi_last_data_sent: u32,
    pub tcpi_last_ack_sent: u32,
    pub tcpi_last_data_recv: u32,
    pub tcpi_last_ack_recv: u32,
    pub tcpi_pmtu: u32,
    pub tcpi_rcv_ssthresh: u32,
    pub tcpi_rtt: u32,
    pub tcpi_rttvar: u32,
    pub tcpi_snd_ssthresh: u32,
    pub tcpi_snd_cwnd: u32,
    pub tcpi_advmss: u32,
    pub tcpi_reordering: u32,
    pub tcpi_rcv_rtt: u32,
    pub tcpi_rcv_space: u32,
    pub tcpi_total_retrans: u32,
    pub tcpi_pacing_rate: u64,
    pub tcpi_max_pacing_rate: u64,
    pub tcpi_bytes_acked: u64,
    pub tcpi_bytes_received: u64,
    pub tcpi_segs_out: u32,
    pub tcpi_segs_in: u32,
    pub tcpi_notsent_bytes: u32,
    pub tcpi_min_rtt: u32,
    pub tcpi_data_segs_in: u32,
    pub tcpi_data_segs_out: u32,
    pub tcpi_delivery_rate: u64,
    pub tcpi_busy_time: u64,
    pub tcpi_rwnd_limited: u64,
    pub tcpi_sndbuf_limited: u64,
    pub tcpi_delivered: u32,
    pub tcpi_delivered_ce: u32,
    pub tcpi_bytes_sent: u64,
    pub tcpi_bytes_retrans: u64,
    pub tcpi_dsack_dups: u32,
    pub tcpi_reord_seen: u32,
    pub tcpi_rcv_ooopack: u32,
    pub tcpi_snd_wnd: u32,
    pub tcpi_rcv_wnd: u32,
    // and more, see include/linux/tcp.h
}

impl TCP_INFO {
    /// Create a new zeroed out [`TCP_INFO`]
    pub unsafe fn new() -> Self {
        mem::zeroed()
    }

    /// Return the size of [`TCP_INFO`]
    #[cfg(unix)]
    pub fn len() -> socklen_t {
        mem::size_of::<Self>() as socklen_t
    }

    /// Return the size of [`TCP_INFO`]
    #[cfg(windows)]
    pub fn len() -> usize {
        mem::size_of::<Self>()
    }
}

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
fn set_opt<T: Copy>(sock: c_int, opt: c_int, val: c_int, payload: T) -> io::Result<()> {
    unsafe {
        let payload = &payload as *const T as *const c_void;
        cvt_linux_error(libc::setsockopt(
            sock,
            opt,
            val,
            payload as *const _,
            mem::size_of::<T>() as socklen_t,
        ))?;
        Ok(())
    }
}

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
fn get_opt<T>(
    sock: c_int,
    opt: c_int,
    val: c_int,
    payload: &mut T,
    size: &mut socklen_t,
) -> io::Result<()> {
    unsafe {
        let payload = payload as *mut T as *mut c_void;
        cvt_linux_error(libc::getsockopt(sock, opt, val, payload as *mut _, size))?;
        Ok(())
    }
}

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
fn get_opt_sized<T>(sock: c_int, opt: c_int, val: c_int) -> io::Result<T> {
    let mut payload = mem::MaybeUninit::zeroed();
    let expected_size = mem::size_of::<T>() as socklen_t;
    let mut size = expected_size;
    get_opt(sock, opt, val, &mut payload, &mut size)?;

    if size != expected_size {
        return Err(std::io::Error::other("get_opt size mismatch"));
    }
    // Assume getsockopt() will set the value properly
    let payload = unsafe { payload.assume_init() };
    Ok(payload)
}

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
fn cvt_linux_error(t: i32) -> io::Result<i32> {
    if t == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(t)
    }
}

#[cfg(target_os = "linux")]
fn ip_bind_addr_no_port(fd: RawFd, val: bool) -> io::Result<()> {
    set_opt(
        fd,
        libc::IPPROTO_IP,
        libc::IP_BIND_ADDRESS_NO_PORT,
        val as c_int,
    )
}

#[cfg(all(unix, not(target_os = "linux")))]
fn ip_bind_addr_no_port(_fd: RawFd, _val: bool) -> io::Result<()> {
    Ok(())
}

/// IP_LOCAL_PORT_RANGE is only supported on Linux 6.3 and higher,
/// ip_local_port_range() is a no-op on unsupported versions.
/// See the [man page](https://man7.org/linux/man-pages/man7/ip.7.html) for more details.
#[cfg(target_os = "linux")]
fn ip_local_port_range(fd: RawFd, low: u16, high: u16) -> io::Result<()> {
    const IP_LOCAL_PORT_RANGE: i32 = 51;
    let range: u32 = (low as u32) | ((high as u32) << 16);

    let result = set_opt(fd, libc::IPPROTO_IP, IP_LOCAL_PORT_RANGE, range as c_int);
    match result {
        Err(e) if e.raw_os_error() != Some(libc::ENOPROTOOPT) => Err(e),
        _ => Ok(()), // no error or ENOPROTOOPT
    }
}

#[cfg(all(unix, not(target_os = "linux")))]
fn ip_local_port_range(_fd: RawFd, _low: u16, _high: u16) -> io::Result<()> {
    Ok(())
}

#[cfg(windows)]
fn ip_local_port_range(_fd: RawSocket, _low: u16, _high: u16) -> io::Result<()> {
    Ok(())
}

/// Allow the socket to bind to and send from a non-local source address, e.g.
/// the intercepted client's, for fully transparent (source-spoofing) proxying.
/// Must be set before bind().
///
/// Linux: IP_TRANSPARENT / IPV6_TRANSPARENT; requires CAP_NET_ADMIN.
#[cfg(target_os = "linux")]
fn set_bind_nonlocal(fd: RawFd, is_ipv6: bool) -> io::Result<()> {
    if is_ipv6 {
        set_opt(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_TRANSPARENT,
            true as c_int,
        )
    } else {
        set_opt(fd, libc::IPPROTO_IP, libc::IP_TRANSPARENT, true as c_int)
    }
}

/// FreeBSD: IP_BINDANY / IPV6_BINDANY; requires PRIV_NETINET_BINDANY (root).
/// The reply flow for the spoofed source is delivered back to this socket by
/// ipfw `fwd`, the FreeBSD analogue of the Linux TPROXY socket-transparent rule.
#[cfg(target_os = "freebsd")]
fn set_bind_nonlocal(fd: RawFd, is_ipv6: bool) -> io::Result<()> {
    if is_ipv6 {
        set_opt(fd, libc::IPPROTO_IPV6, libc::IPV6_BINDANY, true as c_int)
    } else {
        set_opt(fd, libc::IPPROTO_IP, libc::IP_BINDANY, true as c_int)
    }
}

/// Set SO_MARK on the socket for policy routing.
#[cfg(target_os = "linux")]
fn set_so_mark(fd: RawFd, mark: u32) -> io::Result<()> {
    set_opt(fd, libc::SOL_SOCKET, libc::SO_MARK, mark as c_int)
}

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
fn set_so_keepalive(fd: RawFd, val: bool) -> io::Result<()> {
    set_opt(fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE, val as c_int)
}

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
fn set_so_keepalive_idle(fd: RawFd, val: Duration) -> io::Result<()> {
    set_opt(
        fd,
        libc::IPPROTO_TCP,
        libc::TCP_KEEPIDLE,
        val.as_secs() as c_int, // only the seconds part of val is used
    )
}

#[cfg(target_os = "linux")]
fn set_so_keepalive_user_timeout(fd: RawFd, val: Duration) -> io::Result<()> {
    set_opt(
        fd,
        libc::IPPROTO_TCP,
        libc::TCP_USER_TIMEOUT,
        val.as_millis() as c_int, // only the ms part of val is used
    )
}

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
fn set_so_keepalive_interval(fd: RawFd, val: Duration) -> io::Result<()> {
    set_opt(
        fd,
        libc::IPPROTO_TCP,
        libc::TCP_KEEPINTVL,
        val.as_secs() as c_int, // only the seconds part of val is used
    )
}

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
fn set_so_keepalive_count(fd: RawFd, val: usize) -> io::Result<()> {
    set_opt(fd, libc::IPPROTO_TCP, libc::TCP_KEEPCNT, val as c_int)
}

#[cfg(target_os = "linux")]
fn set_keepalive(fd: RawFd, ka: &TcpKeepalive) -> io::Result<()> {
    set_so_keepalive(fd, true)?;
    set_so_keepalive_idle(fd, ka.idle)?;
    set_so_keepalive_interval(fd, ka.interval)?;
    set_so_keepalive_count(fd, ka.count)?;
    set_so_keepalive_user_timeout(fd, ka.user_timeout)
}

/// FreeBSD has no TCP_USER_TIMEOUT; the probe-based knobs are the whole contract.
#[cfg(target_os = "freebsd")]
fn set_keepalive(fd: RawFd, ka: &TcpKeepalive) -> io::Result<()> {
    set_so_keepalive(fd, true)?;
    set_so_keepalive_idle(fd, ka.idle)?;
    set_so_keepalive_interval(fd, ka.interval)?;
    set_so_keepalive_count(fd, ka.count)
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "freebsd"))))]
fn set_keepalive(_fd: RawFd, _ka: &TcpKeepalive) -> io::Result<()> {
    Ok(())
}

#[cfg(windows)]
fn set_keepalive(_sock: RawSocket, _ka: &TcpKeepalive) -> io::Result<()> {
    Ok(())
}

/// Get the kernel TCP_INFO for the given FD.
#[cfg(target_os = "linux")]
pub fn get_tcp_info(fd: RawFd) -> io::Result<TCP_INFO> {
    get_opt_sized(fd, libc::IPPROTO_TCP, libc::TCP_INFO)
}

#[cfg(all(unix, not(target_os = "linux")))]
pub fn get_tcp_info(_fd: RawFd) -> io::Result<TCP_INFO> {
    Ok(unsafe { TCP_INFO::new() })
}

#[cfg(windows)]
pub fn get_tcp_info(_fd: RawSocket) -> io::Result<TCP_INFO> {
    Ok(unsafe { TCP_INFO::new() })
}

/// Set the TCP receive buffer size. See SO_RCVBUF.
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
pub fn set_recv_buf(fd: RawFd, val: usize) -> Result<()> {
    set_opt(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, val as c_int)
        .or_err(ConnectError, "failed to set SO_RCVBUF")
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "freebsd"))))]
pub fn set_recv_buf(_fd: RawFd, _: usize) -> Result<()> {
    Ok(())
}

#[cfg(windows)]
pub fn set_recv_buf(_sock: RawSocket, _: usize) -> Result<()> {
    Ok(())
}

/// Set the TCP send buffer size. See SO_SNDBUF.
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
pub fn set_snd_buf(fd: RawFd, val: usize) -> Result<()> {
    set_opt(fd, libc::SOL_SOCKET, libc::SO_SNDBUF, val as c_int)
        .or_err(ConnectError, "failed to set SO_SNDBUF")
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "freebsd"))))]
pub fn set_snd_buf(_fd: RawFd, _: usize) -> Result<()> {
    Ok(())
}

#[cfg(windows)]
pub fn set_snd_buf(_sock: RawSocket, _: usize) -> Result<()> {
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
pub fn get_recv_buf(fd: RawFd) -> io::Result<usize> {
    get_opt_sized::<c_int>(fd, libc::SOL_SOCKET, libc::SO_RCVBUF).map(|v| v as usize)
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "freebsd"))))]
pub fn get_recv_buf(_fd: RawFd) -> io::Result<usize> {
    Ok(0)
}

#[cfg(windows)]
pub fn get_recv_buf(_sock: RawSocket) -> io::Result<usize> {
    Ok(0)
}

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
pub fn get_snd_buf(fd: RawFd) -> io::Result<usize> {
    get_opt_sized::<c_int>(fd, libc::SOL_SOCKET, libc::SO_SNDBUF).map(|v| v as usize)
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "freebsd"))))]
pub fn get_snd_buf(_fd: RawFd) -> io::Result<usize> {
    Ok(0)
}

#[cfg(windows)]
pub fn get_snd_buf(_sock: RawSocket) -> io::Result<usize> {
    Ok(0)
}

/// Enable client side TCP fast open.
#[cfg(target_os = "linux")]
pub fn set_tcp_fastopen_connect(fd: RawFd) -> Result<()> {
    set_opt(
        fd,
        libc::IPPROTO_TCP,
        libc::TCP_FASTOPEN_CONNECT,
        1 as c_int,
    )
    .or_err(ConnectError, "failed to set TCP_FASTOPEN_CONNECT")
}

#[cfg(all(unix, not(target_os = "linux")))]
pub fn set_tcp_fastopen_connect(_fd: RawFd) -> Result<()> {
    Ok(())
}

#[cfg(windows)]
pub fn set_tcp_fastopen_connect(_sock: RawSocket) -> Result<()> {
    Ok(())
}

/// Enable server side TCP fast open.
#[cfg(target_os = "linux")]
pub fn set_tcp_fastopen_backlog(fd: RawFd, backlog: usize) -> Result<()> {
    set_opt(fd, libc::IPPROTO_TCP, libc::TCP_FASTOPEN, backlog as c_int)
        .or_err(ConnectError, "failed to set TCP_FASTOPEN")
}

#[cfg(all(unix, not(target_os = "linux")))]
pub fn set_tcp_fastopen_backlog(_fd: RawFd, _backlog: usize) -> Result<()> {
    Ok(())
}

#[cfg(windows)]
pub fn set_tcp_fastopen_backlog(_sock: RawSocket, _backlog: usize) -> Result<()> {
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
pub fn set_dscp(fd: RawFd, value: u8) -> Result<()> {
    use super::socket::SocketAddr;
    use pingora_error::OkOrErr;

    let sock = SocketAddr::from_raw_fd(fd, false);
    let addr = sock
        .as_ref()
        .and_then(|s| s.as_inet())
        .or_err(SocketError, "failed to set dscp, invalid IP socket")?;

    if addr.is_ipv6() {
        set_opt(fd, libc::IPPROTO_IPV6, libc::IPV6_TCLASS, value as c_int)
            .or_err(SocketError, "failed to set dscp (IPV6_TCLASS)")
    } else {
        set_opt(fd, libc::IPPROTO_IP, libc::IP_TOS, value as c_int)
            .or_err(SocketError, "failed to set dscp (IP_TOS)")
    }
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "freebsd"))))]
pub fn set_dscp(_fd: RawFd, _value: u8) -> Result<()> {
    Ok(())
}

#[cfg(windows)]
pub fn set_dscp(_sock: RawSocket, _value: u8) -> Result<()> {
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn get_socket_cookie(fd: RawFd) -> io::Result<u64> {
    get_opt_sized::<c_ulonglong>(fd, libc::SOL_SOCKET, libc::SO_COOKIE)
}

#[cfg(all(unix, not(target_os = "linux")))]
pub fn get_socket_cookie(_fd: RawFd) -> io::Result<u64> {
    Ok(0) // SO_COOKIE is a Linux concept
}

#[cfg(target_os = "linux")]
pub fn get_original_dest(fd: RawFd) -> Result<Option<SocketAddr>> {
    use super::socket;
    use pingora_error::OkOrErr;
    use std::net::{SocketAddrV4, SocketAddrV6};

    let sock = socket::SocketAddr::from_raw_fd(fd, false);
    let addr = sock
        .as_ref()
        .and_then(|s| s.as_inet())
        .or_err(SocketError, "failed get original dest, invalid IP socket")?;

    let dest = if addr.is_ipv4() {
        get_opt_sized::<libc::sockaddr_in>(fd, libc::SOL_IP, libc::SO_ORIGINAL_DST).map(|addr| {
            SocketAddr::V4(SocketAddrV4::new(
                u32::from_be(addr.sin_addr.s_addr).into(),
                u16::from_be(addr.sin_port),
            ))
        })
    } else {
        get_opt_sized::<libc::sockaddr_in6>(fd, libc::SOL_IPV6, libc::IP6T_SO_ORIGINAL_DST).map(
            |addr| {
                SocketAddr::V6(SocketAddrV6::new(
                    addr.sin6_addr.s6_addr.into(),
                    u16::from_be(addr.sin6_port),
                    addr.sin6_flowinfo,
                    addr.sin6_scope_id,
                ))
            },
        )
    };
    dest.or_err(SocketError, "failed to get original dest")
        .map(Some)
}

#[cfg(all(unix, not(target_os = "linux")))]
pub fn get_original_dest(_fd: RawFd) -> Result<Option<SocketAddr>> {
    Ok(None)
}

#[cfg(windows)]
pub fn get_original_dest(_sock: RawSocket) -> Result<Option<SocketAddr>> {
    Ok(None)
}

/// connect() to the given address while optionally binding to the specific source address and port range.
///
/// The `set_socket` callback can be used to tune the socket before `connect()` is called.
///
/// If a [`BindTo`] is set with a port range and fallback setting enabled this function will retry
/// on EADDRNOTAVAIL ignoring the port range.
///
/// `IP_BIND_ADDRESS_NO_PORT` is used.
/// `IP_LOCAL_PORT_RANGE` is used if a port range is set on [`BindTo`].
pub(crate) async fn connect_with<F: FnOnce(&TcpSocket) -> Result<()> + Clone>(
    addr: &SocketAddr,
    bind_to: Option<&BindTo>,
    set_socket: F,
) -> Result<TcpStream> {
    if bind_to.as_ref().is_some_and(|b| b.will_fallback()) {
        // if we see an EADDRNOTAVAIL error clear the port range and try again
        let connect_result = inner_connect_with(addr, bind_to, set_socket.clone()).await;
        if let Err(e) = connect_result.as_ref() {
            if matches!(e.etype(), BindError) {
                let mut new_bind_to = BindTo::default();
                new_bind_to.addr = bind_to.as_ref().and_then(|b| b.addr);
                // preserve transparent proxy settings across the retry
                #[cfg(any(target_os = "linux", target_os = "freebsd"))]
                {
                    new_bind_to.bind_nonlocal = bind_to.as_ref().is_some_and(|b| b.bind_nonlocal);
                }
                #[cfg(target_os = "linux")]
                {
                    new_bind_to.so_mark = bind_to.as_ref().and_then(|b| b.so_mark);
                }
                // reset the port range
                new_bind_to.set_port_range(None).unwrap();
                return inner_connect_with(addr, Some(&new_bind_to), set_socket).await;
            }
        }
        connect_result
    } else {
        // not retryable
        inner_connect_with(addr, bind_to, set_socket).await
    }
}

async fn inner_connect_with<F: FnOnce(&TcpSocket) -> Result<()>>(
    addr: &SocketAddr,
    bind_to: Option<&BindTo>,
    set_socket: F,
) -> Result<TcpStream> {
    let socket = if addr.is_ipv4() {
        TcpSocket::new_v4()
    } else {
        TcpSocket::new_v6()
    }
    .or_err(SocketError, "failed to create socket")?;

    #[cfg(unix)]
    {
        ip_bind_addr_no_port(socket.as_raw_fd(), true).or_err(
            SocketError,
            "failed to set socket opts IP_BIND_ADDRESS_NO_PORT",
        )?;

        if let Some(bind_to) = bind_to {
            // The non-local-bind option must be set before bind() so the socket can
            // bind a spoofed (client) source address for full transparency.
            #[cfg(any(target_os = "linux", target_os = "freebsd"))]
            if bind_to.bind_nonlocal {
                set_bind_nonlocal(socket.as_raw_fd(), addr.is_ipv6()).or_err(
                    SocketError,
                    "failed to set socket opts IP_TRANSPARENT/IP_BINDANY",
                )?;
            }

            #[cfg(target_os = "linux")]
            if let Some(mark) = bind_to.so_mark {
                set_so_mark(socket.as_raw_fd(), mark)
                    .or_err(SocketError, "failed to set socket opts SO_MARK")?;
            }

            if let Some((low, high)) = bind_to.port_range() {
                ip_local_port_range(socket.as_raw_fd(), low, high)
                    .or_err(SocketError, "failed to set socket opts IP_LOCAL_PORT_RANGE")?;
            }

            if let Some(baddr) = bind_to.addr {
                // SO_REUSEADDR before bind(): for fully-transparent proxying the
                // upstream socket binds the client's *exact* source ip:port, so a
                // recently-closed upstream connection lingering in TIME_WAIT for
                // that same local address would otherwise make bind() fail with
                // EADDRINUSE under connection churn. SO_REUSEADDR permits rebinding
                // a TIME_WAIT-held local address; it does NOT let two live sockets
                // share an identical 4-tuple, so genuine active collisions still
                // error as before.
                socket
                    .set_reuseaddr(true)
                    .or_err(SocketError, "failed to set socket opts SO_REUSEADDR")?;
                socket
                    .bind(baddr)
                    .or_err_with(BindError, || format!("failed to bind to socket {}", baddr))?;
            }
        }
    }

    #[cfg(windows)]
    if let Some(bind_to) = bind_to {
        if let Some(baddr) = bind_to.addr {
            // See the unix branch: allow rebinding a TIME_WAIT-held source address.
            socket
                .set_reuseaddr(true)
                .or_err(SocketError, "failed to set socket opts SO_REUSEADDR")?;
            socket
                .bind(baddr)
                .or_err_with(BindError, || format!("failed to bind to socket {}", baddr))?;
        };
    };
    // TODO: add support for bind on other platforms

    set_socket(&socket)?;

    socket
        .connect(*addr)
        .await
        .map_err(|e| wrap_os_connect_error(e, format!("Fail to connect to {}", *addr)))
}

/// connect() to the given address while optionally binding to the specific source address.
///
/// `IP_BIND_ADDRESS_NO_PORT` is used
/// `IP_LOCAL_PORT_RANGE` is used if a port range is set on [`BindTo`].
pub async fn connect(addr: &SocketAddr, bind_to: Option<&BindTo>) -> Result<TcpStream> {
    connect_with(addr, bind_to, |_| Ok(())).await
}

/// connect() to the given Unix domain socket
#[cfg(unix)]
pub async fn connect_uds(path: &std::path::Path) -> Result<UnixStream> {
    UnixStream::connect(path)
        .await
        .map_err(|e| wrap_os_connect_error(e, format!("Fail to connect to {}", path.display())))
}

fn wrap_os_connect_error(e: std::io::Error, context: String) -> Box<Error> {
    match e.kind() {
        ErrorKind::ConnectionRefused => Error::because(ConnectRefused, context, e),
        ErrorKind::TimedOut => Error::because(ConnectTimedout, context, e),
        ErrorKind::AddrNotAvailable => Error::because(BindError, context, e),
        ErrorKind::PermissionDenied | ErrorKind::AddrInUse => {
            Error::because(InternalError, context, e)
        }
        _ => match e.raw_os_error() {
            Some(libc::ENETUNREACH | libc::EHOSTUNREACH) => {
                Error::because(ConnectNoRoute, context, e)
            }
            _ => Error::because(ConnectError, context, e),
        },
    }
}

/// The configuration for TCP keepalive
#[derive(Clone, Debug)]
pub struct TcpKeepalive {
    /// The time a connection needs to be idle before TCP begins sending out keep-alive probes.
    pub idle: Duration,
    /// The number of seconds between TCP keep-alive probes.
    pub interval: Duration,
    /// The maximum number of TCP keep-alive probes to send before giving up and killing the connection
    pub count: usize,
    /// the maximum amount of time in milliseconds that transmitted data may
    /// remain unacknowledged, or buffered data may remain untransmitted (due to
    /// zero window size) before TCP will forcibly close the corresponding
    /// connection and return ETIMEDOUT. If the value is specified as 0 (the
    /// default), TCP will use the system default.
    #[cfg(target_os = "linux")]
    pub user_timeout: Duration,
}

impl std::fmt::Display for TcpKeepalive {
    #[cfg(target_os = "linux")]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:?}/{:?}/{}/{:?}",
            self.idle, self.interval, self.count, self.user_timeout
        )
    }
    #[cfg(not(target_os = "linux"))]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}/{:?}/{}", self.idle, self.interval, self.count)
    }
}

/// Apply the given TCP keepalive settings to the given connection
pub fn set_tcp_keepalive(stream: &TcpStream, ka: &TcpKeepalive) -> Result<()> {
    #[cfg(unix)]
    let raw = stream.as_raw_fd();
    #[cfg(windows)]
    let raw = stream.as_raw_socket();
    // TODO: check localhost or if keepalive is already set
    set_keepalive(raw, ka).or_err(ConnectError, "failed to set keepalive")
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_set_recv_buf() {
        use tokio::net::TcpSocket;
        let socket = TcpSocket::new_v4().unwrap();
        #[cfg(unix)]
        set_recv_buf(socket.as_raw_fd(), 102400).unwrap();
        #[cfg(windows)]
        set_recv_buf(socket.as_raw_socket(), 102400).unwrap();

        #[cfg(target_os = "linux")]
        {
            // kernel doubles whatever is set
            assert_eq!(get_recv_buf(socket.as_raw_fd()).unwrap(), 102400 * 2);
        }
        #[cfg(target_os = "freebsd")]
        {
            // FreeBSD reports back exactly what was set (no Linux-style doubling);
            // a silent no-op would read 0 here.
            assert_eq!(get_recv_buf(socket.as_raw_fd()).unwrap(), 102400);
        }
    }

    /// The non-local-bind option is what lets a fully transparent proxy source
    /// its upstream socket from the intercepted client's address. TEST-NET-1 is
    /// guaranteed foreign, so the plain bind failing is the control that proves
    /// the option — not the host's routing table — is what admits the bind.
    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    #[ignore] // requires CAP_NET_ADMIN (Linux) / root (FreeBSD)
    #[test]
    fn test_bind_nonlocal_admits_a_foreign_source() {
        use tokio::net::TcpSocket;
        let foreign: SocketAddr = "192.0.2.1:0".parse().unwrap();

        let plain = TcpSocket::new_v4().unwrap();
        assert!(
            plain.bind(foreign).is_err(),
            "TEST-NET-1 must not be bindable without the non-local option"
        );

        let sock = TcpSocket::new_v4().unwrap();
        set_bind_nonlocal(sock.as_raw_fd(), false).unwrap();
        sock.bind(foreign).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[ignore] // this test requires the Linux system to have net.ipv4.tcp_fastopen set
    #[tokio::test]
    async fn test_set_fast_open() {
        use std::time::Instant;

        // connect once to make sure their is a SYN cookie to use for TFO
        connect_with(&"1.1.1.1:80".parse().unwrap(), None, |socket| {
            set_tcp_fastopen_connect(socket.as_raw_fd())
        })
        .await
        .unwrap();

        let start = Instant::now();
        connect_with(&"1.1.1.1:80".parse().unwrap(), None, |socket| {
            set_tcp_fastopen_connect(socket.as_raw_fd())
        })
        .await
        .unwrap();
        let connection_time = start.elapsed();

        // connect() return right away as the SYN goes out only when the first write() is called.
        assert!(connection_time.as_millis() < 4);
    }
}
