// Functional test harness for pingora-core's transparent-proxy socket options.
//
// Exercises the three code paths a transparent proxy relies on:
//   * NAT REDIRECT interception  -> pingora_core ext::get_original_dest (SO_ORIGINAL_DST)
//   * TPROXY interception         -> IP_TRANSPARENT listener + getsockname (local addr)
//   * fully transparent upstream  -> pingora_core ext::connect + BindTo::set_ip_transparent
//
// Each subcommand serves exactly one connection, prints a RESULT line, and exits,
// so `run.sh` can orchestrate ordering across network namespaces. Needs
// CAP_NET_ADMIN (run inside the privileged container from run.sh).

use pingora_core::connectors::l4::BindTo;
use pingora_core::protocols::l4::ext::{connect as pingora_connect, get_original_dest};
use socket2::{Domain, Protocol, Socket, Type};
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::os::unix::io::AsRawFd;

// Raw IPV6_TRANSPARENT setsockopt (socket2 only exposes the v4 variant).
fn set_ipv6_transparent(fd: std::os::unix::io::RawFd) -> std::io::Result<()> {
    let on: libc::c_int = 1;
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_TRANSPARENT,
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

// Fully transparent upstream: use pingora's own connect() with a transparent
// BindTo so the outbound socket binds a *non-local* source address (spoofing the
// client). Requires `ip route add local <src-ip> dev lo` for the return path.
fn upstream_spoof(dst: &str, src: &str) {
    let dst: SocketAddr = dst.parse().expect("bad dst");
    let src: SocketAddr = src.parse().expect("bad src");
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async move {
        let mut bind_to = BindTo::default();
        bind_to.addr = Some(src);
        bind_to.set_ip_transparent(true);
        match pingora_connect(&dst, Some(&bind_to)).await {
            Ok(mut stream) => {
                use tokio::io::AsyncWriteExt;
                let _ = stream.write_all(b"hi\n").await;
                println!("CONNECTED src={src}");
            }
            Err(e) => println!("CONNECT_ERR={e}"),
        }
    });
}
