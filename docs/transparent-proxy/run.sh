#!/bin/bash
# End-to-end test of pingora's transparent-proxy socket options against a real
# kernel, in a client->router two-namespace topology. Tests NAT REDIRECT, TPROXY
# interception, and fully-transparent upstream source spoofing.
#
# Run inside a privileged container (needs CAP_NET_ADMIN + the nf_tproxy/xt_socket
# kernel modules on the host). The `transparent-proxy-test` binary must be built
# first (see README.md). Usage inside the container:
#   BIN=/path/to/transparent-proxy-test bash run.sh
set -u
BIN=${BIN:-/transparent-proxy-test}
PASS=0; FAIL=0
ok(){ echo "  PASS: $1"; PASS=$((PASS+1)); }
no(){ echo "  FAIL: $1"; FAIL=$((FAIL+1)); }

echo "### deps"; apt-get update -qq >/dev/null 2>&1; DEBIAN_FRONTEND=noninteractive apt-get install -y -qq iptables iproute2 procps >/dev/null 2>&1
echo "kernel: $(uname -r)"

# client (cli) <-veth-> router (rtr, runs pingora). Traffic to a foreign IP is
# routed from cli to rtr, where PREROUTING intercepts it.
setup_topo(){
  ip netns add cli; ip netns add rtr
  ip link add veth-c type veth peer name veth-r
  ip link set veth-c netns cli; ip link set veth-r netns rtr
  ip netns exec rtr ip addr add 10.0.0.1/24 dev veth-r
  ip netns exec rtr ip link set veth-r up; ip netns exec rtr ip link set lo up
  ip netns exec rtr sysctl -qw net.ipv4.ip_forward=1
  ip netns exec rtr sysctl -qw net.ipv4.conf.all.rp_filter=0
  ip netns exec rtr sysctl -qw net.ipv4.conf.all.accept_local=1     # allow local delivery of veth-arriving pkts
  ip netns exec rtr sysctl -qw net.ipv4.conf.all.route_localnet=1
  ip netns exec cli ip addr add 10.0.0.2/24 dev veth-c
  ip netns exec cli ip link set veth-c up; ip netns exec cli ip link set lo up
  ip netns exec cli ip route add default via 10.0.0.1
}
teardown_topo(){ ip netns del cli 2>/dev/null; ip netns del rtr 2>/dev/null; }
wait_ready(){ for _ in $(seq 1 40); do grep -q READY "$1" 2>/dev/null && return 0; sleep 0.1; done; return 1; }
client_connect(){ ip netns exec cli timeout 3 bash -c "exec 3<>/dev/tcp/$1/$2; echo hi >&3; sleep 0.3" 2>/dev/null; }

echo; echo "### TEST 1: NAT REDIRECT -> pingora get_original_dest (SO_ORIGINAL_DST)"
setup_topo
ip netns exec rtr iptables -t nat -A PREROUTING -i veth-r -p tcp -d 1.2.3.4 --dport 80 -j REDIRECT --to-ports 50080
out=$(mktemp)
ip netns exec rtr $BIN proxy-nat 0.0.0.0:50080 >"$out" 2>/dev/null &
wait_ready "$out" && client_connect 1.2.3.4 80
sleep 0.4
got=$(grep ORIGDST "$out" | head -1); echo "  proxy said: ${got:-<none>}"
[ "$got" = "ORIGDST=1.2.3.4:80" ] && ok "NAT original dest recovered" || no "NAT original dest ($got)"
teardown_topo; rm -f "$out"

echo; echo "### TEST 2: TPROXY -> IP_TRANSPARENT listener + getsockname"
setup_topo
ip netns exec rtr ip rule add fwmark 1 lookup 100
ip netns exec rtr ip route add local 0.0.0.0/0 dev lo table 100
ip netns exec rtr iptables -t mangle -A PREROUTING -i veth-r -p tcp -d 1.2.3.4 --dport 80 -j TPROXY --on-port 50080 --tproxy-mark 0x1/0x1
out=$(mktemp)
ip netns exec rtr $BIN proxy-tproxy 0.0.0.0:50080 >"$out" 2>/dev/null &
wait_ready "$out" && client_connect 1.2.3.4 80
sleep 0.4
got=$(grep ORIGDST "$out" | head -1); echo "  proxy said: ${got:-<none>}"
[ "$got" = "ORIGDST=1.2.3.4:80" ] && ok "TPROXY original dest via getsockname" || no "TPROXY original dest ($got)"
teardown_topo; rm -f "$out"

echo; echo "### TEST 3: transparent UPSTREAM spoof -> pingora ext::connect + BindTo::set_ip_transparent"
setup_topo
ip netns exec rtr ip route add local 5.5.5.5/32 dev lo   # return path for spoofed source
bout=$(mktemp); cout=$(mktemp)
ip netns exec rtr $BIN backend 127.0.0.1:9001 >"$bout" 2>/dev/null &
wait_ready "$bout"
ip netns exec rtr $BIN upstream-spoof 127.0.0.1:9001 5.5.5.5:0 >"$cout" 2>/dev/null
sleep 0.4
peer=$(grep PEER "$bout" | head -1); conn=$(grep -E 'CONNECTED|CONNECT_ERR' "$cout" | head -1)
echo "  client said:  ${conn:-<none>}"; echo "  backend said: ${peer:-<none>}"
echo "$peer" | grep -q '^PEER=5.5.5.5:' && ok "upstream saw spoofed source 5.5.5.5" || no "upstream source spoof ($peer / $conn)"
teardown_topo; rm -f "$bout" "$cout"

echo; echo "### RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
