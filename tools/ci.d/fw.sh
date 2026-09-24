#!/bin/sh
# fw module CI checks (run by tools/ci.sh with OUT and ROOT, inside its private mount namespace):
#  1. the real home ruleset keeps its forwards, open port, masquerade, NAT loopback and offload;
#  2. the lab config is loaded with `mr fw` (the real fwLoad path) into a "router" network namespace
#     wired to LAN / guest / internet namespaces, and real packets check the security model:
#     WAN input drop, open port, DNAT with WAN subset + source restriction, guest isolation,
#     IPv6 pinholes by interface identifier, traffic rules, device access control (incl. cutting a
#     connection that was established and offloaded before the block), NAT loopback, ICMP policy.
set -eu
: "${OUT:?}" "${ROOT:?}"
MR=$OUT/mr-host
fail() { echo "FAIL: $*"; exit 1; }

echo "-- home ruleset: forwards / open port / NAT / loopback / offload unchanged"
H=$OUT/home/etc/mini-router/gen/nftables.nft
for s in \
	'iifname { "pppoe-wan", "pppoe-wan2" } tcp dport 45000-45100 dnat ip to 192.168.1.241 comment "vps-45000-45100"' \
	'iifname { "pppoe-wan", "pppoe-wan2" } udp dport 45000-45100 dnat ip to 192.168.1.241 comment "vps-45000-45100"' \
	'iifname { "pppoe-wan", "pppoe-wan2" } tcp dport 7443 dnat ip to 192.168.1.66:9999 comment "desktop-7443"' \
	'iifname { "pppoe-wan", "pppoe-wan2" } tcp dport 46001-46020 dnat ip to 192.168.1.237 comment "workstation"' \
	'iifname { "pppoe-wan", "pppoe-wan2" } udp dport 46001-46020 dnat ip to 192.168.1.237 comment "workstation"' \
	'iifname { "pppoe-wan", "pppoe-wan2" } tcp dport 443 accept comment "lucky-https"' \
	'oifname { "pppoe-wan", "pppoe-wan2" } meta nfproto ipv4 masquerade' \
	'iifname "br-lan" oifname "br-lan" ct status dnat ip saddr 192.168.1.0/24 masquerade comment "nat-reflection"' \
	'iifname "br-lan" fib daddr type local ip daddr != 192.168.1.6 tcp dport 7443 dnat ip to 192.168.1.66:9999' \
	'meta l4proto { tcp, udp } ct state established flow add @ft' \
	'flags offload'; do
	grep -qF -- "$s" "$H" || fail "home ruleset lacks: $s"
done
if grep -q 'ac_4\|meta hour' "$H"; then fail "home ruleset has access-control / schedule rules it did not ask for"; fi

echo "-- lab: packets through the lab ruleset"
PY=$OUT/fwnet.py
cat > "$PY" <<'EOF'
import os, socket, struct, sys, time
def fam(a): return socket.AF_INET6 if ":" in a else socket.AF_INET
cmd = sys.argv[1]
if cmd == "serve":  # serve PORT: tell every client its source address
    s = socket.socket(socket.AF_INET6); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0); s.bind(("::", int(sys.argv[2]))); s.listen(64)
    while True:
        c, a = s.accept(); c.sendall(("ok from " + a[0].replace("::ffff:", "") + "\n").encode()); c.close()
elif cmd == "connect":  # connect ADDR PORT [SRC]
    s = socket.socket(fam(sys.argv[2])); s.settimeout(1.5)
    if len(sys.argv) > 4: s.bind((sys.argv[4], 0))
    try:
        s.connect((sys.argv[2], int(sys.argv[3]))); print(s.recv(200).decode().strip())
    except Exception as e:
        print("ERR " + type(e).__name__); sys.exit(1)
elif cmd == "stream":  # stream PORT [transparent|transparent6|fast]: send data forever to the first client
    if len(sys.argv) > 3 and sys.argv[3] == "transparent6":  # IPv6, IPV6_TRANSPARENT (like a tproxy socket)
        s = socket.socket(socket.AF_INET6); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setsockopt(socket.IPPROTO_IPV6, 75, 1); s.bind(("::", int(sys.argv[2]))); s.listen(4)
    elif len(sys.argv) > 3:  # IPv4, IP_TRANSPARENT: answers for any address routed to this host (like a tproxy socket)
        s = socket.socket(socket.AF_INET); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setsockopt(socket.SOL_IP, 19, 1); s.bind(("0.0.0.0", int(sys.argv[2]))); s.listen(4)
    else:
        s = socket.socket(socket.AF_INET6); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0); s.bind(("::", int(sys.argv[2]))); s.listen(4)
    c, a = s.accept()
    pause = 0.001 if sys.argv[3:] == ["fast"] else 0.01
    try:
        while True: c.sendall(b"x" * 1400); time.sleep(pause)
    except Exception: pass
elif cmd == "sink":  # sink ADDR PORT FILE: receive, keep the byte count in FILE
    s = socket.socket(fam(sys.argv[2])); s.settimeout(1.5); s.connect((sys.argv[2], int(sys.argv[3]))); s.settimeout(0.2)
    n = 0
    while True:
        try:
            d = s.recv(65536)
            if not d: break
            n += len(d)
        except socket.timeout: pass
        with open(sys.argv[4] + ".tmp", "w") as f: f.write(str(n))
        os.replace(sys.argv[4] + ".tmp", sys.argv[4])
elif cmd == "ping":  # ping ADDR: one ICMP / ICMPv6 echo
    a = sys.argv[2]; v6 = ":" in a; ident = os.getpid() & 0xffff
    if v6:
        s = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6); pkt = struct.pack("!BBHHH", 128, 0, 0, ident, 1) + b"mrfw"
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP); pkt = struct.pack("!BBHHH", 8, 0, 0, ident, 1) + b"mrfw"
        c = sum(struct.unpack("!%dH" % (len(pkt) // 2), pkt)); c = (c >> 16) + (c & 0xffff); c = ~(c + (c >> 16)) & 0xffff
        pkt = pkt[:2] + struct.pack("!H", c) + pkt[4:]
    s.settimeout(1.5); s.sendto(pkt, (a, 0)); end = time.time() + 1.5
    try:
        while time.time() < end:
            d, _ = s.recvfrom(2000)
            if not v6: d = d[(d[0] & 0xf) * 4:]
            if d[0] == (129 if v6 else 0) and struct.unpack("!H", d[4:6])[0] == ident: print("pong"); sys.exit(0)
    except socket.timeout: pass
    print("ERR timeout"); sys.exit(1)
EOF

P=mrfw$$
R=${P}r W=${P}w L1=${P}a L2=${P}b G=${P}g
cleanup() {
	for n in $R $W $L1 $L2 $G; do
		for p in $(ip netns pids "$n" 2>/dev/null); do kill "$p" 2>/dev/null || true; done
		ip netns del "$n" 2>/dev/null || true
	done
}
trap cleanup EXIT
for n in $R $W $L1 $L2 $G; do ip netns add "$n"; ip -n "$n" link set lo up; done
# veth NS1 NAME1 NS2 NAME2 [MAC2]
veth() {
	ip link add "${P}x" type veth peer name "${P}y"
	ip link set "${P}x" netns "$1"; ip link set "${P}y" netns "$3"
	ip -n "$1" link set "${P}x" name "$2"; ip -n "$3" link set "${P}y" name "$4"
	[ -z "${5:-}" ] || ip -n "$3" link set "$4" address "$5"
	ip -n "$1" link set "$2" up; ip -n "$3" link set "$4" up
}
x() { ns=$1; shift; ip netns exec "$ns" "$@"; }

# router: br-lan (bridge over lan2 + lan3, both flowtable devices), br-guest, two WANs
ip -n "$R" link add br-lan type bridge
ip -n "$R" link set br-lan up
veth "$R" lan2 "$L1" eth0
veth "$R" lan3 "$L2" eth0 aa:bb:cc:dd:ee:03 # MAC of the lab access entry "blocked-tv"
ip -n "$R" link set lan2 master br-lan
ip -n "$R" link set lan3 master br-lan
veth "$R" br-guest "$G" eth0
veth "$R" pppoe-wan "$W" eth0
veth "$R" pppoe-wan2 "$W" eth1
x "$R" sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1
ip -n "$R" addr add 192.168.1.6/24 dev br-lan
ip -n "$R" addr add 2001:db8:1::1/64 dev br-lan nodad
ip -n "$R" addr add 192.168.20.1/24 dev br-guest
ip -n "$R" addr add 203.0.113.1/24 dev pppoe-wan
ip -n "$R" addr add 2001:db8:ffff::1/64 dev pppoe-wan nodad
ip -n "$R" addr add 198.51.100.1/24 dev pppoe-wan2
# LAN server (desktop .66, NAS .241, printer .50; IPv6 with the pinhole IID and one without)
for a in 192.168.1.66/24 192.168.1.241/24 192.168.1.50/24; do ip -n "$L1" addr add "$a" dev eth0; done
ip -n "$L1" addr add 2001:db8:1::211:32ff:fe12:3456/64 dev eth0 nodad
ip -n "$L1" addr add 2001:db8:1::5/64 dev eth0 nodad
ip -n "$L1" route add default via 192.168.1.6
ip -n "$L1" -6 route add default via 2001:db8:1::1
ip -n "$L2" addr add 192.168.1.80/24 dev eth0
ip -n "$L2" addr add 2001:db8:1::80/64 dev eth0 nodad
ip -n "$L2" route add default via 192.168.1.6
ip -n "$L2" -6 route add default via 2001:db8:1::1
ip -n "$G" addr add 192.168.20.50/24 dev eth0
ip -n "$G" route add default via 192.168.20.1
ip -n "$W" addr add 203.0.113.2/24 dev eth0
ip -n "$W" addr add 2001:db8:ffff::2/64 dev eth0 nodad
ip -n "$W" addr add 198.51.100.7/24 dev eth1
ip -n "$W" addr add 198.51.100.99/24 dev eth1
ip -n "$W" -6 route add 2001:db8:1::/64 via 2001:db8:ffff::1

# the real load path: `mr fw` renders against the namespace's netdevs, loads, refreshes sets
mkdir -p /etc/mini-router/gen
cp "$OUT/lab-secrets.yaml" /etc/mini-router/secrets.yaml
load() { # load VARIANT: a = blocked-tv disabled, b = the lab config as is (software offload: veths cannot do PPE)
	# the proxy module's real tproxy rules would take the fake-ip traffic this test routes to its own
	# simulated proxy socket (the real proxy path has its own end-to-end test in tools/ci.d/proxy.sh)
	sed -e 's/offload: hardware/offload: software/' -e '/^proxy:/,/^[a-z]/ s/^  enabled: true/  enabled: false/' "$OUT/lab.yaml" > /etc/mini-router/router.yaml
	grep -A1 '^proxy:' /etc/mini-router/router.yaml | grep -q 'enabled: false' || fail "could not disable the proxy module in the fw test config"
	[ "$1" = b ] || sed -i 's/{name: blocked-tv, macs/{name: blocked-tv, enabled: false, macs/' /etc/mini-router/router.yaml
	x "$R" "$MR" fw || fail "mr fw ($1) failed"
}
load a
ft=$(x "$R" nft list flowtable inet mr ft | tr -d '\n\t')
for d in lan2 lan3 pppoe-wan pppoe-wan2; do
	echo "$ft" | grep -q "$d" || fail "flowtable lacks $d: $ft"
done

# servers
spawn() { setsid -f ip netns exec "$@" >/dev/null 2>&1 < /dev/null; } # detached: cleanup kills them quietly
for p in 443 22 80 53; do spawn "$R" python3 "$PY" serve "$p"; done
for p in 9999 22 9100 443; do spawn "$L1" python3 "$PY" serve "$p"; done
for p in 8080 25; do spawn "$W" python3 "$PY" serve "$p"; done
spawn "$W" python3 "$PY" stream 9000
spawn "$W" python3 "$PY" stream 9004 fast
# a transparent-proxy-like path on the router: L2's traffic to 198.18.0.0/15 and fc00::/18 (fake-ip ranges)
# is policy-routed to a local socket (the way tproxy delivers it), so it passes the input chain instead of
# forward. The router has no IPv6 default route here (as when the IPv6 uplink is down or absent).
ip -n "$R" rule add fwmark 0x1ce lookup 1234
ip -n "$R" route add local 0.0.0.0/0 dev lo table 1234
ip -n "$R" route add 192.168.1.0/24 dev br-lan table 1234 # reverse path of marked packets (src_valid_mark=1)
ip -n "$R" -6 rule add fwmark 0x1ce lookup 1234
ip -n "$R" -6 route add local ::/0 dev lo table 1234
printf 'table inet ciproxy {\n\tchain pre {\n\t\ttype filter hook prerouting priority mangle - 10; policy accept;\n\t\tip daddr 198.18.0.0/15 meta mark set 0x1ce\n\t\tip6 daddr fc00::/18 meta mark set 0x1ce\n\t}\n}\n' | x "$R" nft -f -
spawn "$R" python3 "$PY" stream 9001 transparent
spawn "$R" python3 "$PY" stream 9003 transparent6
sleep 1

ok() { # ok NS ADDR PORT WHAT [SRC] [EXPECT]
	out=$(x "$1" python3 "$PY" connect "$2" "$3" ${5:+"$5"}) || fail "$4: expected to connect, got: $out"
	[ -z "${6:-}" ] || echo "$out" | grep -qF -- "$6" || fail "$4: expected '$6', got: $out"
	echo "ok: $4 ($out)"
}
blocked() { # blocked NS ADDR PORT WHAT [SRC] [EXPECT-ERR]
	if out=$(x "$1" python3 "$PY" connect "$2" "$3" ${5:+"$5"}); then fail "$4: expected to be blocked, got: $out"; fi
	[ -z "${6:-}" ] || echo "$out" | grep -qF -- "$6" || fail "$4: expected '$6', got: $out"
	echo "ok: $4 ($out)"
}
bytes() { cat "$OUT/${1:-fw-sink}" 2>/dev/null || echo 0; }

# a connection of the (not yet controlled) device, established and offloaded before the block
spawn "$L2" python3 "$PY" sink 203.0.113.2 9000 "$OUT/fw-sink"
spawn "$L2" python3 "$PY" sink 198.18.0.1 9001 "$OUT/fw-sink-px"
spawn "$L2" python3 "$PY" sink fc00::1 9003 "$OUT/fw-sink-px6"
sleep 1.5
b0=$(bytes)
[ "$b0" -gt 20000 ] || fail "stream to the LAN device not flowing ($b0 bytes)"
p0=$(bytes fw-sink-px) q0=$(bytes fw-sink-px6)
[ "$p0" -gt 20000 ] || fail "stream through the router's local proxy path not flowing ($p0 bytes)"
[ "$q0" -gt 20000 ] || fail "IPv6 stream through the router's local proxy path not flowing ($q0 bytes)"
echo "ok: streams flowing before the block ($b0 / $p0 / $q0 bytes)"
# a download of a device that is already controlled (address in @ac_4, e.g. by an entry outside its
# window) runs on the CPU path; the reload below must not let one of its packets into the flowtable
# before the learned sets are refilled (it would stay offloaded and could never be cut)
x "$R" nft add element inet mr ac_4 '{ 192.168.1.80 }'
spawn "$L2" python3 "$PY" sink 203.0.113.2 9004 "$OUT/fw-sink-fast"
sleep 1
f0=$(bytes fw-sink-fast)
[ "$f0" -gt 100000 ] || fail "fast stream to the controlled device not flowing ($f0 bytes)"
load b # blocked-tv switched on while the streams run
sleep 1
b1=$(bytes) p1=$(bytes fw-sink-px) q1=$(bytes fw-sink-px6) f1=$(bytes fw-sink-fast)
sleep 2
b2=$(bytes) p2=$(bytes fw-sink-px) q2=$(bytes fw-sink-px6) f2=$(bytes fw-sink-fast)
[ $((b2 - b1)) -lt 10000 ] || fail "established connection of a blocked device kept flowing ($b1 -> $b2 bytes)"
echo "ok: established connection cut by the access rule ($b1 -> $b2 bytes)"
[ $((p2 - p1)) -lt 10000 ] || fail "established proxied connection of a blocked device kept flowing ($p1 -> $p2 bytes)"
echo "ok: established connection through the router's local proxy path cut too ($p1 -> $p2 bytes)"
[ $((q2 - q1)) -lt 10000 ] || fail "established IPv6 proxied connection of a blocked device kept flowing without an IPv6 default route ($q1 -> $q2 bytes)"
echo "ok: IPv6 connection through the local proxy path cut too, with no IPv6 default route ($q1 -> $q2 bytes)"
[ $((f2 - f1)) -lt 10000 ] || fail "CPU-path download of a controlled device slipped into the flowtable during the reload ($f1 -> $f2 bytes)"
echo "ok: CPU-path download of a controlled device cut too: the reload refilled the sets atomically ($f1 -> $f2 bytes)"
x "$R" nft list set inet mr ac1_4 | grep -q 192.168.1.80 || fail "blocked device address not in @ac1_4"
echo "ok: device address learned (@ac1_4)"
# a reload empties the learned sets; fwLoad must put the addresses back (previous sets + neighbour
# table) before any packet could, or a reply-first stream would be offloaded again
for p in $(ip netns pids "$L2"); do kill "$p"; done
ip -n "$L2" link set eth0 down # silent device: nothing can re-teach the sets, the router's neighbour entry stays
sleep 0.3
x "$R" nft add element inet mr ac_4 '{ 192.168.1.99 timeout 100s }' # stale: learned long ago, device gone
load b
x "$R" nft list set inet mr ac_4 | grep -q 192.168.1.80 || fail "reload lost the controlled device's address (@ac_4)"
x "$R" nft list set inet mr ac1_4 | grep -q 192.168.1.80 || fail "reload lost the controlled device's address (@ac1_4)"
echo "ok: reload restores controlled device addresses while the device is silent"
x "$R" nft -j list set inet mr ac_4 | python3 -c 'import json, sys
e = [x["elem"] for s in json.load(sys.stdin)["nftables"] if "set" in s for x in s["set"].get("elem", []) if isinstance(x, dict) and x["elem"].get("val") == "192.168.1.99"]
sys.exit(0 if e and 0 < e[0].get("expires", 0) <= 100 else 1)' || fail "reload dropped a learned address or extended its lifetime: $(x "$R" nft list set inet mr ac_4 | tr -d '\n\t')"
echo "ok: a stale learned address keeps its remaining lifetime across the reload"
ip -n "$L2" link set eth0 up
ip -n "$L2" route replace default via 192.168.1.6
ip -n "$L2" addr replace 2001:db8:1::80/64 dev eth0 nodad # link down may have flushed it
ip -n "$L2" -6 route replace default via 2001:db8:1::1

# WAN → router
ok "$W" 203.0.113.1 443 "WAN -> open port 443 (IPv4)"
ok "$W" 2001:db8:ffff::1 443 "WAN -> open port 443 (IPv6)"
blocked "$W" 203.0.113.1 22 "WAN -> router SSH dropped" "" "TimeoutError"
blocked "$W" 203.0.113.1 80 "WAN -> router web UI dropped"
blocked "$W" 198.51.100.1 53 "WAN2 -> router DNS dropped"
# port forwards
ok "$W" 203.0.113.1 7443 "forward 7443 -> desktop:9999" "" "ok from 203.0.113.2"
ok "$W" 198.51.100.1 2222 "forward 2222 via wan2 from an allowed source" 198.51.100.7
blocked "$W" 198.51.100.1 2222 "forward 2222 from a source that is not allowed" 198.51.100.99
blocked "$W" 203.0.113.1 2222 "forward 2222 on a WAN outside its subset"
# guest isolation
ok "$G" 192.168.20.1 53 "guest -> router DNS"
blocked "$G" 192.168.20.1 80 "guest -> router web UI dropped"
blocked "$G" 192.168.1.6 22 "guest -> router LAN address dropped"
blocked "$G" 192.168.1.66 9999 "guest -> LAN host dropped"
ok "$G" 203.0.113.2 8080 "guest -> internet (masqueraded)" "" "ok from 203.0.113.1"
ok "$G" 192.168.1.50 9100 "guest -> printer allowed by traffic rule guest-printer"
# LAN
ok "$L1" 203.0.113.2 8080 "LAN -> internet (masqueraded)" "" "ok from 203.0.113.1"
blocked "$L1" 203.0.113.2 25 "traffic rule no-smtp-out rejects" "" "ConnectionRefusedError"
# IPv6 pinholes (no NAT): by interface identifier only, only the listed ports
ok "$W" 2001:db8:1::211:32ff:fe12:3456 443 "IPv6 pinhole nas-https (IID)" "" "ok from 2001:db8:ffff::2"
blocked "$W" 2001:db8:1::211:32ff:fe12:3456 22 "IPv6 pinhole: other port dropped"
blocked "$W" 2001:db8:1::5 443 "IPv6: host without pinhole dropped"
# access control: WAN blocked, LAN side still fine (router services, NAT loopback to a LAN server)
blocked "$L2" 203.0.113.2 8080 "blocked device -> internet dropped"
ok "$L2" 192.168.1.6 53 "blocked device -> router DNS still works"
blocked "$L2" 2001:db8:ffff::2 8080 "blocked device -> internet (IPv6) dropped"
x "$L2" python3 "$PY" ping 2001:db8:1::1 >/dev/null || fail "blocked device cannot reach the router over IPv6 (ND / echo)"
echo "ok: blocked device -> router over IPv6 (neighbour discovery + echo) still works"
ok "$L2" 203.0.113.1 7443 "blocked device -> NAT loopback to LAN server" "" "ok from 192.168.1.6"
ok "$L1" 203.0.113.1 7443 "LAN -> NAT loopback (hairpin)"
# ICMP policy: wan_ping false (v4 echo dropped), IPv6 echo + ND always allowed
if x "$W" python3 "$PY" ping 203.0.113.1 >/dev/null; then fail "WAN IPv4 ping answered although wan_ping: false"; fi
echo "ok: WAN IPv4 ping dropped (wan_ping: false)"
x "$W" python3 "$PY" ping 2001:db8:ffff::1 >/dev/null || fail "WAN IPv6 ping to the router not answered"
echo "ok: WAN IPv6 ping answered"
x "$W" python3 "$PY" ping 2001:db8:1::5 >/dev/null || fail "IPv6 echo to a LAN host not forwarded"
echo "ok: IPv6 echo to LAN host forwarded"
# counters
x "$R" nft list chain inet mr input | grep 'wan-in-drop' | grep -qv 'packets 0 ' || fail "wan-in-drop counter did not count"
x "$R" nft list chain inet mr forward | grep '"access:blocked-tv"' | grep -qv 'packets 0 ' || fail "access counter did not count"
x "$R" nft list set inet mr lan6 | grep -q '2001:db8:1::/64' || fail "@lan6 not refreshed with the LAN prefix"
echo "ok: counters and @lan6"
rm -f "$OUT/fw-sink" "$OUT/fw-sink-px" "$OUT/fw-sink-px6" "$OUT/fw-sink-fast"
echo "fw: all packet checks passed"
