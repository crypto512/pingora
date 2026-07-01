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

Optionally, pingora can also **spoof the client's source address toward the
upstream** (fully transparent / "TPROXY on both sides"). See
[Fully transparent upstream](#fully-transparent-upstream-source-spoofing).

All of this is Linux-only and requires the `CAP_NET_ADMIN` capability.

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

The proxy process must hold `CAP_NET_ADMIN` to set `IP_TRANSPARENT` / `SO_MARK`.
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

# (optional fast-path for already-established transparent sockets)
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
// opts.so_mark = Some(1);          // optional: SO_MARK for the listener

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
outbound socket to the client's address with `IP_TRANSPARENT` set *before* bind.
This is configured on the `Peer` via `BindTo`:

```rust
use pingora_core::connectors::l4::BindTo;

let mut bind_to = BindTo::default();
bind_to.addr = Some(client_src_addr);   // the client's source address to spoof
bind_to.set_ip_transparent(true);       // IP_TRANSPARENT before bind()
// bind_to.set_so_mark(Some(1));         // optional: SO_MARK for policy routing

// e.g. in upstream_peer():
peer.options.bind_to = Some(bind_to);
```

For the upstream **replies** (destined to the spoofed source) to be delivered
back to this host, add a return route, e.g.:

```sh
ip rule add fwmark 1 lookup 100
ip route add local 0.0.0.0/0 dev lo table 100   # or a narrower `local <src>` route
```

and mark the upstream socket with `set_so_mark(Some(1))` so its return traffic
hits that policy route.

> `IP_TRANSPARENT` must be set **before** `bind()`. Pingora does this in the
> connector, which is why it is a first-class `BindTo` option rather than
> something you can set from `upstream_tcp_sock_tweak_hook` (that hook runs
> *after* bind).

---

## 5. Verifying your setup

A ready-to-run, containerized functional test for all three code paths lives in
[`docs/transparent-proxy/`](../transparent-proxy/README.md). It builds a small
binary against `pingora-core` and drives real traffic through a
`client -> router` network-namespace topology inside a privileged container,
asserting that NAT REDIRECT, TPROXY, and upstream source-spoofing all work.

```sh
cd docs/transparent-proxy
cargo build
docker run --rm --privileged \
  -v "$PWD/target/debug/transparent-proxy-test:/transparent-proxy-test:ro" \
  -v "$PWD/run.sh:/run.sh:ro" \
  debian:trixie-slim bash /run.sh
# => 3 passed, 0 failed
```
