# Transparent proxy socket-option test harness

Functional test for the transparent-proxy socket options added to `pingora-core`
(`TcpSocketOptions.ip_transparent` / `so_mark` on the listener, and
`BindTo.ip_transparent` / `so_mark` on the upstream connector).

It builds a small binary that links `pingora-core` and drives real traffic
through a Linux `client -> router` network-namespace topology, covering each
mode over **both IPv4 and IPv6**, plus a dual-stack case (7 tests total):

| Test | Interception | Original destination read via | pingora API exercised |
|------|--------------|-------------------------------|-----------------------|
| NAT REDIRECT | `ip[6]tables -t nat ... -j REDIRECT` | `SO_ORIGINAL_DST` / `IP6T_SO_ORIGINAL_DST` | `ext::get_original_dest` |
| TPROXY | `ip[6]tables -t mangle ... -j TPROXY` | `getsockname` (local addr) | IP_TRANSPARENT / IPV6_TRANSPARENT listener |
| Upstream spoof | — | backend observes client IP | `ext::connect` + `BindTo::set_ip_transparent` |
| Dual-stack | `iptables -j TPROXY` into a `[::]` socket | `getsockname` → `::ffff:a.b.c.d` | IPV6_TRANSPARENT covers v4-mapped |

For the full explanation and production host setup, see
[`../user_guide/transparent_proxy.md`](../user_guide/transparent_proxy.md).

## Requirements

- A Linux host whose kernel has the TPROXY modules (`nf_tproxy_ipv4`,
  `xt_TPROXY`, `xt_socket`) — standard on most distros.
- `docker` (the harness runs in a `--privileged` container so it can set
  `CAP_NET_ADMIN`, create namespaces, and program iptables/routing without
  touching the host network).

## Run

```sh
# from this directory
cargo build                                  # builds ./target/debug/transparent-proxy-test

docker run --rm --privileged \
  -v "$PWD/target/debug/transparent-proxy-test:/transparent-proxy-test:ro" \
  -v "$PWD/run.sh:/run.sh:ro" \
  debian:trixie-slim bash /run.sh
```

Use a base image whose glibc is >= the build host's (e.g. `debian:trixie-slim`
for glibc 2.41), or build the binary inside the container instead of mounting it.

Expected output:

```
### TEST 1: NAT REDIRECT ...        PASS
### TEST 2: TPROXY ...              PASS
### TEST 3: transparent UPSTREAM ...PASS
### TEST 4 (IPv6): NAT REDIRECT ... PASS
### TEST 5 (IPv6): TPROXY ...       PASS
### TEST 6 (IPv6): UPSTREAM ...     PASS
### TEST 7 (dual-stack): [::] intercepts IPv4 TPROXY ... PASS
### RESULT: 7 passed, 0 failed
```
