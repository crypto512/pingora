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
use socket2::Socket;
use std::io::{self, ErrorKind};
use std::mem;
use std::net::SocketAddr;
#[cfg(unix)]
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
#[cfg(windows)]
use std::os::windows::io::{AsRawSocket, FromRawSocket, IntoRawSocket, RawSocket};
use std::time::Duration;
#[cfg(unix)]
use tokio::net::UnixStream;
use tokio::net::{TcpSocket, TcpStream};

use crate::connectors::l4::BindTo;

/// FreeBSD's `struct tcp_info`. It shares Linux's name and a few field names and
/// nothing else: the layout differs, several Linux fields do not exist
/// (`tcpi_data_segs_out`, the byte counters), and **the time fields are microseconds**
/// where Linux reports milliseconds. The kernel's own declaration is used rather than a
/// copy, and its fields are read through `Deref`.
#[cfg(target_os = "freebsd")]
#[repr(transparent)]
#[derive(Copy, Clone)]
pub struct TCP_INFO(pub libc::tcp_info);

#[cfg(target_os = "freebsd")]
impl std::ops::Deref for TCP_INFO {
    type Target = libc::tcp_info;
    fn deref(&self) -> &libc::tcp_info {
        &self.0
    }
}

#[cfg(target_os = "freebsd")]
impl std::fmt::Debug for TCP_INFO {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TCP_INFO")
            .field("tcpi_state", &self.0.tcpi_state)
            .field("tcpi_rtt", &self.0.tcpi_rtt)
            .field("tcpi_last_data_recv", &self.0.tcpi_last_data_recv)
            .finish_non_exhaustive()
    }
}

/// The (copy of) the kernel struct tcp_info returns
#[cfg(not(target_os = "freebsd"))]
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
///
/// Each kernel answers in its **own** layout — see [`TCP_INFO`] — and `get_opt_sized`
/// refuses an answer of any other size, so a struct that has drifted from the running
/// kernel's is an error rather than misread fields.
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
pub fn get_tcp_info(fd: RawFd) -> io::Result<TCP_INFO> {
    get_opt_sized(fd, libc::IPPROTO_TCP, libc::TCP_INFO)
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "freebsd"))))]
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

/// The underlying error (if any) and local address from a failed connection attempt.
#[derive(Debug)]
pub(crate) struct ConnectErrorDetails {
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
    local_addr: Option<SocketAddr>,
}

impl ConnectErrorDetails {
    pub(crate) fn new<E>(source: E, local_addr: Option<SocketAddr>) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        Self {
            source: Some(source.into()),
            local_addr,
        }
    }

    fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr
    }
}

impl std::fmt::Display for ConnectErrorDetails {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.source {
            Some(source) => source.fmt(f),
            // No wrapped error (e.g. a TLS handshake failure, whose detail stays in the parent's
            // context): surface the local address so the chain still carries useful information.
            None => match self.local_addr {
                Some(local_addr) => write!(f, "local address {local_addr}"),
                None => Ok(()),
            },
        }
    }
}

impl std::error::Error for ConnectErrorDetails {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_deref()
            .map(|source| source as &(dyn std::error::Error + 'static))
    }
}

/// Internal helper backing [`crate::connectors::l4::ConnectErrorExt::connect_local_addr`].
pub(crate) fn connect_error_local_addr(error: &Error) -> Option<SocketAddr> {
    error
        .root_cause()
        .downcast_ref::<ConnectErrorDetails>()
        .and_then(ConnectErrorDetails::local_addr)
}

/// Attaches the local address to an error from a stage after the socket connected (e.g. a TLS
/// handshake failure) so it stays recoverable via
/// [`crate::connectors::l4::ConnectErrorExt::connect_local_addr`]. Returns `e` unchanged when
/// `local_addr` is `None`.
pub(crate) fn attach_connect_local_addr(
    mut e: Box<Error>,
    local_addr: Option<SocketAddr>,
) -> Box<Error> {
    if let Some(local_addr) = local_addr {
        // Wrap any existing cause and take over as the root cause; the error's own type, retry
        // semantics, and context are left in place.
        e.cause = Some(Box::new(ConnectErrorDetails {
            source: e.cause.take(),
            local_addr: Some(local_addr),
        }));
    }
    e
}

/// State retained across a connection timeout to preserve the assigned local address.
#[derive(Default)]
pub(crate) struct ConnectAttempt {
    local_addr: Option<SocketAddr>,
}

impl ConnectAttempt {
    fn clear(&mut self) {
        self.local_addr = None;
    }

    fn record_local_addr(&mut self, socket: &Socket) {
        self.local_addr = socket.local_addr().ok().and_then(|addr| addr.as_socket());
    }

    pub(crate) fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr
    }
}

#[cfg(unix)]
fn into_socket2(socket: TcpSocket) -> Socket {
    // SAFETY: `into_raw_fd()` transfers sole ownership of the descriptor to `Socket`.
    unsafe { Socket::from_raw_fd(socket.into_raw_fd()) }
}

#[cfg(windows)]
fn into_socket2(socket: TcpSocket) -> Socket {
    // SAFETY: `into_raw_socket()` transfers sole ownership of the socket to `Socket`.
    unsafe { Socket::from_raw_socket(socket.into_raw_socket()) }
}

#[cfg(unix)]
fn connect_in_progress(error: &io::Error) -> bool {
    error.kind() == ErrorKind::WouldBlock || error.raw_os_error() == Some(libc::EINPROGRESS)
}

#[cfg(windows)]
fn connect_in_progress(error: &io::Error) -> bool {
    error.kind() == ErrorKind::WouldBlock
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
    let mut attempt = ConnectAttempt::default();
    connect_with_attempt(addr, bind_to, set_socket, &mut attempt).await
}

/// Connects like [`connect_with`] while recording the assigned local address in `attempt`.
///
/// The caller can inspect [`ConnectAttempt::local_addr`] after this future is cancelled by an
/// external timeout.
pub(crate) async fn connect_with_attempt<F: FnOnce(&TcpSocket) -> Result<()> + Clone>(
    addr: &SocketAddr,
    bind_to: Option<&BindTo>,
    set_socket: F,
    attempt: &mut ConnectAttempt,
) -> Result<TcpStream> {
    if bind_to.as_ref().is_some_and(|b| b.will_fallback()) {
        // if we see an EADDRNOTAVAIL error clear the port range and try again
        let connect_result = inner_connect_with(addr, bind_to, set_socket.clone(), attempt).await;
        if let Err(e) = connect_result.as_ref() {
            if matches!(e.etype(), BindError) {
                let mut new_bind_to = BindTo::default();
                new_bind_to.addr = bind_to.as_ref().and_then(|b| b.addr);
                // reset the port range
                new_bind_to.set_port_range(None).unwrap();
                return inner_connect_with(addr, Some(&new_bind_to), set_socket, attempt).await;
            }
        }
        connect_result
    } else {
        // not retryable
        inner_connect_with(addr, bind_to, set_socket, attempt).await
    }
}

async fn inner_connect_with<F: FnOnce(&TcpSocket) -> Result<()>>(
    addr: &SocketAddr,
    bind_to: Option<&BindTo>,
    set_socket: F,
    attempt: &mut ConnectAttempt,
) -> Result<TcpStream> {
    attempt.clear();
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
            if let Some((low, high)) = bind_to.port_range() {
                ip_local_port_range(socket.as_raw_fd(), low, high)
                    .or_err(SocketError, "failed to set socket opts IP_LOCAL_PORT_RANGE")?;
            }

            if let Some(baddr) = bind_to.addr {
                socket
                    .bind(baddr)
                    .or_err_with(BindError, || format!("failed to bind to socket {}", baddr))?;
            }
        }
    }

    #[cfg(windows)]
    if let Some(bind_to) = bind_to {
        if let Some(baddr) = bind_to.addr {
            socket
                .bind(baddr)
                .or_err_with(BindError, || format!("failed to bind to socket {}", baddr))?;
        };
    };
    // TODO: add support for bind on other platforms

    set_socket(&socket)?;

    // Read off the socket once every step that may bind it has run: the BindTo above and
    // `set_socket`, which may bind the socket itself.
    let source_checked_at_connect = source_checked_at_connect(&socket);

    let socket = into_socket2(socket);
    if let Err(error) = socket.connect(&(*addr).into()) {
        attempt.record_local_addr(&socket);
        if !connect_in_progress(&error) {
            return Err(wrap_os_connect_error(
                error,
                format!("Fail to connect to {}", *addr),
                attempt.local_addr(),
                source_checked_at_connect,
            ));
        }
    } else {
        attempt.record_local_addr(&socket);
    }

    let stream = TcpStream::from_std(socket.into())
        .or_err(SocketError, "failed to register connecting socket")?;
    stream
        .writable()
        .await
        .or_err(ConnectError, "failed to wait for connecting socket")?;

    if let Some(error) = stream
        .take_error()
        .or_err(SocketError, "failed to get connecting socket error")?
    {
        return Err(wrap_os_connect_error(
            error,
            format!("Fail to connect to {}", *addr),
            attempt.local_addr(),
            source_checked_at_connect,
        ));
    }

    Ok(stream)
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
    UnixStream::connect(path).await.map_err(|e| {
        wrap_os_connect_error(
            e,
            format!("Fail to connect to {}", path.display()),
            None,
            false,
        )
    })
}

/// Whether this socket pinned a source (an address, a port, or both) that the kernel will
/// validate only at `connect()` — which is what an `EADDRNOTAVAIL` from `connect()` then
/// reports: the destination is not reachable from that source.
///
/// FreeBSD and macOS check a bound source at `connect()` and pick its port at `bind()`, so
/// there a connect-time `EADDRNOTAVAIL` on a bound socket is a route failure. Linux refuses an
/// unusable source at `bind()` and an unroutable destination as `ENETUNREACH`, so every
/// `EADDRNOTAVAIL` its `connect()` returns is local: the ports a source has towards that
/// destination ran out (`IP_BIND_ADDRESS_NO_PORT` defers the pick to `connect()`), an exact
/// port's 4-tuple is still held, or a port range is exhausted — never asked of the socket
/// there. A socket whose address cannot be read is treated as unbound, so its `EADDRNOTAVAIL`
/// stays a local limit rather than becoming a route failure.
#[cfg(all(unix, not(target_os = "linux")))]
fn source_checked_at_connect(socket: &TcpSocket) -> bool {
    socket
        .local_addr()
        .is_ok_and(|local| !local.ip().is_unspecified() || local.port() != 0)
}

#[cfg(any(target_os = "linux", windows))]
fn source_checked_at_connect(_socket: &TcpSocket) -> bool {
    false
}

/// Classify an error returned by `connect()` (never by `bind()` — those are wrapped as
/// [`BindError`] at the bind call site).
///
/// A connect-time `EADDRNOTAVAIL` is a local limit — a [`BindError`], which the L4 connector
/// reports as an `InternalError` and [`connect_with_attempt`] retries on to widen a port
/// range — except where `source_checked_at_connect` says the kernel validated a bound source
/// only now: then it is a routing failure ([`ConnectNoRoute`]). Read either way everywhere, it
/// is wrong somewhere: as "no route", a Linux source that ran out of ports reads as a dead
/// origin to every caller that fails over on route failures; as a local limit, a FreeBSD
/// unroutable origin reads as an internal fault.
fn wrap_os_connect_error(
    e: std::io::Error,
    context: String,
    local_addr: Option<SocketAddr>,
    source_checked_at_connect: bool,
) -> Box<Error> {
    let etype = match e.kind() {
        ErrorKind::ConnectionRefused => ConnectRefused,
        ErrorKind::TimedOut => ConnectTimedout,
        ErrorKind::AddrNotAvailable if source_checked_at_connect => ConnectNoRoute,
        ErrorKind::AddrNotAvailable => BindError,
        ErrorKind::PermissionDenied | ErrorKind::AddrInUse => InternalError,
        _ => match e.raw_os_error() {
            Some(libc::ENETUNREACH | libc::EHOSTUNREACH) => ConnectNoRoute,
            _ => ConnectError,
        },
    };
    match local_addr {
        Some(local_addr) => Error::because(
            etype,
            context,
            ConnectErrorDetails::new(e, Some(local_addr)),
        ),
        None => Error::because(etype, context, e),
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
            // The invariant under test is that the setter is not a silent no-op — one
            // reads back 0. FreeBSD reports the buffer it actually granted (no
            // Linux-style doubling), and that is bounded by net.inet.tcp.recvbuf_max,
            // a tunable; asserting an exact size would make this test a property of
            // the host's sysctls rather than of the code.
            assert_ne!(
                get_recv_buf(socket.as_raw_fd()).unwrap(),
                0,
                "SO_RCVBUF must reach the kernel; a no-op setter reads back 0"
            );
        }
    }

    #[test]
    fn test_set_snd_buf() {
        use tokio::net::TcpSocket;
        let socket = TcpSocket::new_v4().unwrap();
        #[cfg(unix)]
        set_snd_buf(socket.as_raw_fd(), 102400).unwrap();
        #[cfg(windows)]
        set_snd_buf(socket.as_raw_socket(), 102400).unwrap();

        #[cfg(target_os = "linux")]
        {
            // kernel doubles whatever is set
            assert_eq!(get_snd_buf(socket.as_raw_fd()).unwrap(), 102400 * 2);
        }
        #[cfg(target_os = "freebsd")]
        {
            // Same invariant as the recv test: the setter must not be a silent no-op.
            assert_ne!(
                get_snd_buf(socket.as_raw_fd()).unwrap(),
                0,
                "SO_SNDBUF must reach the kernel; a no-op setter reads back 0"
            );
        }
    }

    #[tokio::test]
    async fn test_failed_connect_records_local_addr() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let remote_addr = listener.local_addr().unwrap();
        drop(listener);

        let mut bind_to = BindTo::default();
        bind_to.addr = Some("127.0.0.1:0".parse().unwrap());
        let error = connect(&remote_addr, Some(&bind_to)).await.unwrap_err();
        let local_addr =
            connect_error_local_addr(&error).expect("local address should be captured");

        assert_eq!(local_addr.ip(), bind_to.addr.unwrap().ip());
        assert_ne!(local_addr.port(), 0);
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
    fn eaddrnotavail(source_checked_at_connect: bool) -> Box<Error> {
        wrap_os_connect_error(
            io::Error::from_raw_os_error(libc::EADDRNOTAVAIL),
            "test".into(),
            None,
            source_checked_at_connect,
        )
    }

    /// A bound source the kernel validates only at `connect()` (FreeBSD, macOS), refused
    /// there: the destination is not reachable from it, a route failure. Reported as a
    /// [`BindError`], the L4 connector escalates it to `InternalError`, so an unroutable
    /// origin would read as an internal fault to every caller and metric.
    #[test]
    fn a_source_checked_at_connect_reports_eaddrnotavail_as_no_route() {
        assert_eq!(eaddrnotavail(true).etype(), &ConnectNoRoute);
    }

    /// Every other connect-time `EADDRNOTAVAIL` is a local limit — ports ran out, an exact
    /// 4-tuple is still held, a range is exhausted. It must stay a [`BindError`]: that is the
    /// signal `connect_with_attempt` retries on to widen a range, and calling it "no route"
    /// makes a caller that fails over on route failures mark a healthy origin dead.
    #[test]
    fn every_other_eaddrnotavail_is_a_local_limit() {
        assert_eq!(eaddrnotavail(false).etype(), &BindError);
    }

    /// The real Linux case, end to end through `connect_with`: a source bound with port 0,
    /// whose port `IP_BIND_ADDRESS_NO_PORT` leaves to `connect()`, runs out of ports towards
    /// one destination. `set_socket` narrows the socket's own range to two ports (no
    /// privilege needed) and binds the source itself, as a full-transparency hook does; the
    /// connect that finds no port left must read as the local limit it is, never as a route.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_linux_source_that_runs_out_of_ports_is_a_local_limit() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let origin: SocketAddr = listener.local_addr().unwrap();
        // A per-socket range narrows the system's and is ignored outside it: take its top two.
        let system = std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range").unwrap();
        let high: u16 = system.split_whitespace().nth(1).unwrap().parse().unwrap();
        let mut held = Vec::new();
        let refused = loop {
            assert!(
                held.len() <= 2,
                "a two-port range let {} connects through: IP_LOCAL_PORT_RANGE unsupported?",
                held.len()
            );
            let attempt = connect_with(&origin, None, |socket| {
                ip_local_port_range(socket.as_raw_fd(), high - 1, high)
                    .or_err(SocketError, "IP_LOCAL_PORT_RANGE")?;
                socket
                    .bind("127.0.0.1:0".parse().unwrap())
                    .or_err(BindError, "bind in set_socket")
            })
            .await;
            match attempt {
                Ok(stream) => held.push(stream),
                Err(e) => break e,
            }
        };
        assert_eq!(refused.etype(), &BindError, "{refused:?}");
    }

    /// The source is read off the socket, never off the request for one, so a socket bound by
    /// the caller's `set_socket` counts exactly like one bound through `BindTo`. An unbound
    /// socket pins nothing; a bound address or a bound port pins a source.
    #[cfg(all(unix, not(target_os = "linux")))]
    #[test]
    fn a_bound_source_is_read_off_the_socket() {
        let unbound = TcpSocket::new_v4().unwrap();
        assert!(!source_checked_at_connect(&unbound));
        for source in ["127.0.0.1:0", "[::1]:0", "0.0.0.0:0"] {
            let source: std::net::SocketAddr = source.parse().unwrap();
            let bound = if source.is_ipv4() {
                TcpSocket::new_v4()
            } else {
                TcpSocket::new_v6()
            }
            .unwrap();
            bound.bind(source).unwrap();
            assert!(source_checked_at_connect(&bound), "{source}");
        }
    }

    /// The real FreeBSD case, end to end through `connect_with`: a source bound by the
    /// caller's `set_socket` is validated at `connect()`, which answers a loopback source
    /// towards a public destination with `EADDRNOTAVAIL` — a route failure, read off the
    /// socket although no `BindTo` named the source. Bounded in time: the refusal is
    /// synchronous there, and a host that let the SYN out instead must not hang the suite.
    #[cfg(target_os = "freebsd")]
    #[tokio::test]
    async fn a_source_bound_by_set_socket_is_read_off_the_socket() {
        let public: SocketAddr = "240.0.0.1:80".parse().unwrap();
        let attempt = connect_with(&public, None, |socket| {
            socket
                .bind("127.0.0.1:0".parse().unwrap())
                .or_err(BindError, "bind in set_socket")
        });
        let err = tokio::time::timeout(Duration::from_secs(10), attempt)
            .await
            .expect("FreeBSD refuses this source at connect, without sending a SYN")
            .unwrap_err();
        assert_eq!(err.etype(), &ConnectNoRoute, "{err:?}");
    }

    /// The reading a caller takes off a connection it has not looked at yet: how long
    /// what the peer sent has been waiting. Both kernels answer it under the same field
    /// name and in different units, which is the whole reason the type is per platform —
    /// a Linux-layout read of the other kernel's struct returns a plausible number.
    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    #[test]
    fn tcp_info_reports_how_long_unread_data_has_waited() {
        use std::io::Write;

        const WAITED: Duration = Duration::from_millis(300);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        client.write_all(b"hello").unwrap();
        std::thread::sleep(WAITED);
        let (accepted, _) = listener.accept().unwrap();

        let info = get_tcp_info(accepted.as_raw_fd()).unwrap();
        #[cfg(target_os = "linux")]
        let waited = Duration::from_millis(info.tcpi_last_data_recv.into());
        #[cfg(target_os = "freebsd")]
        let waited = Duration::from_micros(info.tcpi_last_data_recv.into());

        // A tick short of the sleep at most (the kernel counts in ticks), and nowhere
        // near what the other unit would read: 300 s, or 0.3 ms.
        assert!(
            waited >= WAITED - Duration::from_millis(50) && waited < WAITED * 10,
            "data unread for {WAITED:?} reads as {waited:?}"
        );
    }
}
