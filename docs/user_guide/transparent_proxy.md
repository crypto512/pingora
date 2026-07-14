# Transparent proxying (NAT REDIRECT and TPROXY)

A *transparent* proxy intercepts connections that clients did not explicitly
address to it, and (optionally) reaches upstreams while preserving the client's
source IP. Pingora supports both Linux interception mechanisms:

| Mode | iptables target | How the proxy learns the **original destination** | Preserves client dst on the socket? |
|------|-----------------|---------------------------------------------------|--------------------------------------|
| **NAT / REDIRECT** | `-t nat -j REDIRECT` / `DNAT` | `get_original_dest()` (reads `SO_ORIGINAL_DST` from conntrack) | no (dst is rewritten to the proxy) |
| **TPROXY** | `-t mangle -j TPROXY` | `Session::server_addr()` (the accepted socket's local address) | yes (needs `IP_TRANSPARENT`) |

> **Key rule:** the two modes read the original destination **differently**.
> Use `get_original_dest()` for REDIRECT/NAT, and `server_addr()` for TPROXY.
> Calling `get_original_dest()` on a TPROXY connection fails — there is no
> conntrack NAT entry to read.

Optionally, an application can also **spoof the client's source address toward the
upstream** (fully transparent / "TPROXY on both sides") from the peer's socket hook.
See [Fully transparent upstream](#4-fully-transparent-upstream-source-spoofing).

The interception modes and host rules here are Linux's, and need the
`CAP_NET_ADMIN` capability. Section 4 notes what source spoofing needs on FreeBSD.

---

## 1. Linux host setup

### 1.1 Kernel modules

TPROXY needs these modules (present in stock kernels; load them if your kernel
builds them as modules):

```sh
modprobe nf_tproxy_ipv4      # and nf_tproxy_ipv6 for IPv6
modprobe xt_TPROXY
modprobe xt_socket
modprobe nf_conntrack        # (REDIRECT/NAT mode)
```

### 1.2 Capabilities

The proxy process must hold `CAP_NET_ADMIN` to set `IP_TRANSPARENT`.
Either run as root, or grant the binary the capability:

```sh
setcap cap_net_admin+ep /usr/local/bin/my-pingora-proxy
```

Under systemd:

```ini
[Service]
AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN
```

### 1.3 sysctls

```sh
# Required to route/forward intercepted traffic through this host
sysctl -w net.ipv4.ip_forward=1

# TPROXY delivers intercepted packets locally via a policy route on `lo`.
# When packets arrive on a normal interface and are delivered locally, the
# reverse-path filter must not drop them:
sysctl -w net.ipv4.conf.all.rp_filter=0
sysctl -w net.ipv4.conf.all.accept_local=1
```

> **Gotcha (`accept_local`):** without `accept_local=1`, TPROXY'd SYNs match the
> iptables rule but are silently dropped before reaching the socket (the listener
> stays in `LISTEN`, clients time out). This was the single most common reason
> TPROXY "doesn't work" in our testing. `rp_filter=0` is needed for the same
> reason on multi-homed / policy-routed hosts.

---

## 2. NAT / REDIRECT mode

The kernel rewrites the destination to the proxy and remembers the original in
conntrack. The listener is an **ordinary** listener (no `IP_TRANSPARENT`).

### Host rules

```sh
# redirect intercepted TCP to the proxy's port (e.g. 50080)
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j REDIRECT --to-ports 50080
```

### Pingora side

Just add a normal TCP listener on `50080`, then read the original destination
from the accepted downstream connection's fd:

```rust
use pingora_core::protocols::l4::ext::get_original_dest;
use std::os::unix::io::AsRawFd;

// e.g. inside request_filter / upstream_peer, from the downstream Session:
if let Some(stream) = session.stream() {
    if let Ok(Some(orig_dst)) = get_original_dest(stream.as_raw_fd()) {
        // orig_dst is the address the client originally dialed
    }
}
```

---

## 3. TPROXY mode

The kernel delivers the packet **unmodified** to the transparent socket; the
original destination is simply the accepted socket's local address.

### Host rules

```sh
# policy route: locally deliver anything marked by TPROXY
ip rule add fwmark 1 lookup 100
ip route add local 0.0.0.0/0 dev lo table 100

# packets of an established transparent socket: a fast path for intercepted
# connections, and REQUIRED for the replies to a spoofed upstream source (section 4)
iptables -t mangle -N DIVERT
iptables -t mangle -A PREROUTING -p tcp -m socket -j DIVERT
iptables -t mangle -A DIVERT -j MARK --set-mark 1
iptables -t mangle -A DIVERT -j ACCEPT

# intercept new connections -> proxy port 50080, marking them
iptables -t mangle -A PREROUTING -i eth0 -p tcp --dport 80 \
    -j TPROXY --on-port 50080 --tproxy-mark 0x1/0x1
```

### Pingora side

Enable `IP_TRANSPARENT` on the listener via `TcpSocketOptions`:

```rust
use pingora_core::listeners::TcpSocketOptions;

let mut opts = TcpSocketOptions::default();
opts.ip_transparent = Some(true);   // sets IP_TRANSPARENT before bind()

// with the high-level server API:
my_service.add_tcp_with_settings("0.0.0.0:50080", opts);
```

Then read the original destination from the **local** address of the downstream
connection:

```rust
// under TPROXY, server_addr() == the address the client originally dialed
let orig_dst = session.server_addr();
```

---

## 4. Fully transparent upstream (source spoofing)

To make the **upstream** connection appear to come from the client's IP, bind the
outbound socket to the client's address with the non-local-bind option set
*before* bind. The connector binds nothing when the peer sets no `bind_to` and the
server configuration names no `client_bind_to_ipv4`/`client_bind_to_ipv6`, so the
peer's `upstream_tcp_sock_tweak_hook` then receives the socket unbound (before
`connect()`) and can set the option and bind the source itself:

```rust
use std::os::fd::AsRawFd;
use std::sync::Arc;
use pingora_core::{ErrorType, OrErr};

// The client's IP (unmapped: see section 5's dual-stack note), an ephemeral port.
let src = std::net::SocketAddr::new(client_ip, 0);
peer.options.upstream_tcp_sock_tweak_hook = Some(Arc::new(move |sock| {
    let (level, name) = if src.is_ipv6() {
        (libc::IPPROTO_IPV6, libc::IPV6_TRANSPARENT)
    } else {
        (libc::IPPROTO_IP, libc::IP_TRANSPARENT)
    };
    let on: libc::c_int = 1;
    // SAFETY: a live socket's fd and a correctly sized c_int option value.
    let rc = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            level,
            name,
            std::ptr::from_ref(&on).cast(),
            std::mem::size_of_val(&on) as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error())
            .or_err(ErrorType::SocketError, "set IP_TRANSPARENT");
    }
    sock.bind(src).or_err(ErrorType::BindError, "bind the client's source")
}));
```

The connector creates the socket in the **destination's** family, so the source
must be in the same family: unmap a v4-mapped client address, and do not spoof a
client towards an origin of the other family. Bind **port 0**: the client's exact
source port collides `EADDRINUSE` whenever it recycles that port. Set no
`SO_REUSEADDR`: where `bind()` picks the port (FreeBSD), that flag hands out ports
already connected to the same destination. Pingora reuses a pooled connection by
its peer's hash, which does not include the hook: give each client's peer its own
`group_key`, or one client's spoofed connection serves another's requests. The hook
does not run for a peer with `custom_l4` or a CONNECT `proxy` set; such a connection
leaves from the host's own address.

For the upstream **replies** (destined to the spoofed source) to reach this socket,
section 3's DIVERT chain is required, not optional: its `-m socket` match marks them
(they belong to this established transparent socket) and section 3's policy route
delivers marked packets locally. This holds under REDIRECT interception too: add
section 3's policy route and DIVERT chain even though REDIRECT needs no TPROXY rule.
Do **not** mark the upstream socket itself (`SO_MARK`): that same route would
deliver its own outgoing SYN to `lo`, and the connection would never leave the
host.

On **FreeBSD** the option is `IP_BINDANY`/`IPV6_BINDANY` (needs root), at
`IPPROTO_IP`/`IPPROTO_IPV6`. The replies are delivered back to the socket by an
ipfw `fwd` rule for the return flow, the FreeBSD counterpart of the DIVERT chain.

---

## 5. IPv6

All three code paths support IPv6, and pingora selects the right option based on
the address family automatically:

- **Listener:** `TcpSocketOptions { ip_transparent: Some(true), .. }` sets
  `IP_TRANSPARENT` on v4 sockets and `IPV6_TRANSPARENT` on v6 sockets.
- **Original destination:** `get_original_dest()` reads `SO_ORIGINAL_DST` (v4) or
  `IP6T_SO_ORIGINAL_DST` (v6); `server_addr()` works for both under TPROXY.
- **Upstream spoofing:** section 4's hook picks `IPV6_TRANSPARENT` (Linux) /
  `IPV6_BINDANY` (FreeBSD) for a v6 source; the connector creates the socket in the
  destination's family, so a v6 source pairs with a v6 destination.

Use the IPv6 iptables/routing equivalents on the host:

```sh
# forwarding (there is no rp_filter / accept_local to tweak for IPv6)
sysctl -w net.ipv6.conf.all.forwarding=1

# NAT / REDIRECT
ip6tables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j REDIRECT --to-ports 50080

# TPROXY
ip -6 rule add fwmark 1 lookup 100
ip -6 route add local ::/0 dev lo table 100
ip6tables -t mangle -A PREROUTING -i eth0 -p tcp --dport 80 \
    -j TPROXY --on-port 50080 --tproxy-mark 0x1/0x1

# packets of an established transparent socket (REQUIRED for spoofed upstream replies)
ip6tables -t mangle -N DIVERT
ip6tables -t mangle -A PREROUTING -p tcp -m socket -j DIVERT
ip6tables -t mangle -A DIVERT -j MARK --set-mark 1
ip6tables -t mangle -A DIVERT -j ACCEPT
```

> Note: the IPv4-only `rp_filter=0` / `accept_local=1` gotcha does not apply to
> IPv6 (those sysctls don't exist for v6); IPv6 TPROXY works with just the
> policy route above plus `forwarding=1`.

### Dual-stack `[::]` listeners

A single listener bound to `[::]` with `IPV6_V6ONLY=0` (i.e. `ipv6_only` unset /
`Some(false)`) intercepts **both** IPv4 and IPv6 TPROXY traffic. In the kernel
`IP_TRANSPARENT` and `IPV6_TRANSPARENT` toggle the *same* `inet->transparent`
socket flag, so pingora setting `IPV6_TRANSPARENT` on the v6 socket is enough to
also transparently accept IPv4 (v4-mapped) connections — no separate v4 listener
is required. Practical consequences:

- You still need **both** `iptables` (v4) and `ip6tables` (v6) TPROXY rules, all
  pointing at the same `--on-port`; the socket family is not what selects traffic,
  the netfilter rules are.
- For an intercepted IPv4 connection, `server_addr()` (and `getsockname`) returns
  the original destination as an **IPv4-mapped** address, e.g.
  `[::ffff:1.2.3.4]:80`. Normalize it back to `V4` if your logic expects a plain
  IPv4 address:

  ```rust
  use std::net::{IpAddr, SocketAddr};
  fn unmap(a: SocketAddr) -> SocketAddr {
      match a {
          SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
              Some(v4) => SocketAddr::new(IpAddr::V4(v4), a.port()),
              None => a,
          },
          v4 => v4,
      }
  }
  ```

- If you instead want strictly separate v4 and v6 listeners, set
  `ipv6_only: Some(true)` on the `[::]` listener and add a second `0.0.0.0`
  listener; each then reports native (non-mapped) addresses.

## 6. Verifying your setup

A ready-to-run, containerized functional test for all three code paths lives in
[`docs/transparent-proxy/`](../transparent-proxy/README.md). It builds a small
binary against `pingora-core` and drives real traffic through a
`client -> router` network-namespace topology inside a privileged container,
asserting that NAT REDIRECT, TPROXY and upstream source spoofing work. The spoofing
tests bind a source that is foreign to the router (so only the option admits it)
and bring the origin's replies back through section 4's recipe: the `-m socket`
mark, the fwmark rule and the `local` route. They prove the mechanism, not your
interfaces' rules.

```sh
cd docs/transparent-proxy
cargo build
docker run --rm --privileged \
  -v "$PWD/target/debug/transparent-proxy-test:/transparent-proxy-test:ro" \
  -v "$PWD/run.sh:/run.sh:ro" \
  debian:trixie-slim bash /run.sh
# => 7 passed, 0 failed   (NAT/TPROXY/upstream over IPv4 + IPv6, plus dual-stack)
```
