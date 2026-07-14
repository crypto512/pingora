// Functional test harness for pingora-core's transparent-proxy socket options.
//
// Exercises the three code paths a transparent proxy relies on:
//   * NAT REDIRECT interception  -> pingora_core ext::get_original_dest (SO_ORIGINAL_DST)
//   * TPROXY interception         -> IP_TRANSPARENT listener + getsockname (local addr)
//   * fully transparent upstream  -> PeerOptions::upstream_tcp_sock_tweak_hook binding the
//                                    client's source after IP_TRANSPARENT
//
// Each subcommand serves exactly one connection, prints a RESULT line, and exits,
// so `run.sh` can orchestrate ordering across network namespaces. Needs
// CAP_NET_ADMIN (run inside the privileged container from run.sh).

use pingora_core::connectors::TransportConnector;
use pingora_core::protocols::l4::ext::get_original_dest;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_core::{ErrorType, OrErr};
use socket2::{Domain, Protocol, Socket, Type};
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::os::unix::io::AsRawFd;
use std::sync::Arc;

// Raw IPV6_TRANSPARENT setsockopt (socket2 only exposes the v4 variant).
fn set_ipv6_transparent(fd: std::os::unix::io::RawFd) -> std::io::Result<()> {
    set_transparent(fd, libc::IPPROTO_IPV6, libc::IPV6_TRANSPARENT)
}

// IP_TRANSPARENT (v4) or IPV6_TRANSPARENT (v6) through libc, the way pingora-core's own
// listener sets it: socket2's v4 setter is named differently across the socket2 versions
// pingora-core accepts, and has no v6 twin.
fn set_transparent(
    fd: std::os::unix::io::RawFd,
    level: libc::c_int,
    name: libc::c_int,
) -> std::io::Result<()> {
    let on: libc::c_int = 1;
    let ret = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            &on as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn usage() -> ! {
    eprintln!(
        "usage:\n  \
         backend <bind>            # accept one conn, print PEER=<addr>\n  \
         proxy-nat <bind>          # normal listener, print ORIGDST via get_original_dest\n  \
         proxy-tproxy <bind>       # IP_TRANSPARENT listener, print ORIGDST via getsockname\n  \
         upstream-spoof <dst> <src># pingora transparent connect, spoofing source <src>"
    );
    std::process::exit(2);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        usage();
    }
    match args[1].as_str() {
        "backend" => backend(&args[2]),
        "proxy-nat" => proxy_nat(&args[2]),
        "proxy-tproxy" => proxy_tproxy(&args[2]),
        "proxy-tproxy-dual" => proxy_tproxy_dual(&args[2]),
        "upstream-spoof" => upstream_spoof(&args[2], &args[3]),
        _ => usage(),
    }
}

// A plain TCP server. Prints the peer address it observed (used to prove
// source-spoofing on the upstream side).
fn backend(bind: &str) {
    let addr: SocketAddr = bind.parse().expect("bad backend addr");
    let listener = std::net::TcpListener::bind(addr).expect("backend bind");
    println!("READY");
    let (mut conn, peer) = listener.accept().expect("backend accept");
    println!("PEER={peer}");
    let mut buf = [0u8; 64];
    let _ = conn.read(&mut buf);
    let _ = conn.write_all(b"ok\n");
}

// NAT REDIRECT mode: a normal (non-transparent) listener. The original
// destination is recovered from conntrack via SO_ORIGINAL_DST, which is exactly
// what pingora_core::protocols::l4::ext::get_original_dest does. In a real proxy
// this is what you'd call on the accepted downstream stream's fd.
fn proxy_nat(bind: &str) {
    let addr: SocketAddr = bind.parse().expect("bad proxy addr");
    let listener = std::net::TcpListener::bind(addr).expect("nat proxy bind");
    println!("READY");
    let (conn, peer) = listener.accept().expect("nat accept");
    match get_original_dest(conn.as_raw_fd()) {
        Ok(Some(orig)) => println!("ORIGDST={orig}"),
        Ok(None) => println!("ORIGDST=none"),
        Err(e) => println!("ORIGDST=err:{e}"),
    }
    eprintln!("(nat) accepted from {peer}");
}

// TPROXY mode: an IP_TRANSPARENT listener. Under TPROXY the kernel preserves the
// original destination as the accepted socket's *local* address (getsockname).
// The set_ip_transparent_v4() call mirrors pingora's apply_tcp_socket_options;
// in a real proxy you set `TcpSocketOptions { ip_transparent: Some(true), .. }`
// and read the original destination via `Session::server_addr()`.
fn proxy_tproxy(bind: &str) {
    let addr: SocketAddr = bind.parse().expect("bad proxy addr");
    let v6 = addr.is_ipv6();
    let domain = if v6 { Domain::IPV6 } else { Domain::IPV4 };
    let sock = Socket::new(domain, Type::STREAM, Some(Protocol::TCP)).expect("socket");
    if v6 {
        // keep the families separate so the test binds a pure-v6 socket
        sock.set_only_v6(true).expect("set IPV6_V6ONLY");
        // socket2 only exposes set_ip_transparent_v4(); set IPV6_TRANSPARENT via
        // raw setsockopt, exactly as pingora's apply_tcp_socket_options does.
        set_ipv6_transparent(sock.as_raw_fd()).expect("set IPV6_TRANSPARENT (needs CAP_NET_ADMIN)");
    } else {
        sock.set_ip_transparent_v4(true)
            .expect("set IP_TRANSPARENT (needs CAP_NET_ADMIN)");
    }
    sock.set_reuse_address(true).expect("reuseaddr");
    sock.bind(&addr.into()).expect("tproxy bind");
    sock.listen(128).expect("listen");
    println!("READY");
    let (conn, _peer) = sock.accept().expect("tproxy accept");
    // local_addr() == original destination that the client dialed
    let local = conn.local_addr().expect("getsockname");
    let local = local.as_socket().expect("inet");
    println!("ORIGDST={local}");
}

// Dual-stack TPROXY: a single `[::]` listener with IPV6_V6ONLY=0 and only
// IPV6_TRANSPARENT set. Because the kernel's IP_TRANSPARENT and IPV6_TRANSPARENT
// setsockopts both toggle the same `inet->transparent` socket flag, this one
// socket also intercepts IPv4 (v4-mapped) TPROXY traffic. getsockname then
// returns the original v4 destination as `::ffff:a.b.c.d`.
fn proxy_tproxy_dual(bind: &str) {
    let addr: SocketAddr = bind.parse().expect("bad proxy addr");
    let sock = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP)).expect("socket");
    sock.set_only_v6(false).expect("enable dual stack");
    set_ipv6_transparent(sock.as_raw_fd()).expect("set IPV6_TRANSPARENT (needs CAP_NET_ADMIN)");
    sock.set_reuse_address(true).expect("reuseaddr");
    sock.bind(&addr.into()).expect("tproxy bind");
    sock.listen(128).expect("listen");
    println!("READY");
    let (conn, _peer) = sock.accept().expect("tproxy accept");
    let local = conn
        .local_addr()
        .expect("getsockname")
        .as_socket()
        .expect("inet");
    println!("ORIGDST={local}");
}

// Fully transparent upstream: pingora's own connector, with the peer's socket hook
// binding a *non-local* source address (spoofing the client). With no `BindTo` the
// connector binds nothing, so the hook receives the socket unbound and sets
// IP_TRANSPARENT / IPV6_TRANSPARENT before its own bind — the order the option needs.
// Requires `ip route add local <src-ip> dev lo` for the return path.
fn upstream_spoof(dst: &str, src: &str) {
    let dst: SocketAddr = dst.parse().expect("bad dst");
    let src: SocketAddr = src.parse().expect("bad src");
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async move {
        let mut peer = HttpPeer::new(dst, false, String::new());
        peer.options.upstream_tcp_sock_tweak_hook = Some(Arc::new(move |sock| {
            let (level, name) = if src.is_ipv6() {
                (libc::IPPROTO_IPV6, libc::IPV6_TRANSPARENT)
            } else {
                (libc::IPPROTO_IP, libc::IP_TRANSPARENT)
            };
            set_transparent(sock.as_raw_fd(), level, name)
                .or_err(ErrorType::SocketError, "set IP_TRANSPARENT")?;
            sock.bind(src)
                .or_err(ErrorType::BindError, "bind the spoofed source")
        }));
        match TransportConnector::new(None).new_stream(&peer).await {
            Ok(mut stream) => {
                use tokio::io::AsyncWriteExt;
                let _ = stream.write_all(b"hi\n").await;
                println!("CONNECTED src={src}");
            }
            Err(e) => println!("CONNECT_ERR={e}"),
        }
    });
}
