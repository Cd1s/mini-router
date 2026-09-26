#!/bin/sh
# dev module CI checks (run by tools/ci.sh with OUT and ROOT, inside its private mount namespace):
#  1. the lab inventory renders: dnsmasq dhcp-host lines per device, names resolved in forwards /
#     access / policy routes / proxy bypass, the policy fallback rule; no runtime pause in any file;
#  2. `mr pause` with real nftables in network namespaces: a paused device's established, offloaded
#     download stops at once (both directions), its new connections fail, the router's DNS still
#     answers it, another device keeps flowing; a firewall reload keeps the pause; it ends by itself
#     (kernel timeout, no reload); `mr unpause` ends it early; pausing by MAC;
#  3. policy_routes fallback: drop: while the policy's WAN has no route the device cannot leave
#     through another WAN; once the WAN's table has a route it works (through that WAN only).
set -eu
: "${OUT:?}" "${ROOT:?}"
MR=$OUT/mr-host
fail() { echo "FAIL: $*"; exit 1; }

echo "-- lab render: inventory resolved, no pause in generated files"
L=$OUT/lab
grep -qx 'dhcp-host=02:00:00:00:10:01,192.168.1.70,office-pc,infinite' "$L/etc/dnsmasq.conf" || fail "dnsmasq: office-pc static lease"
grep -qx 'dhcp-host=aa:bb:cc:00:00:21,aa:bb:cc:00:00:22,192.168.1.121,kid-tablet' "$L/etc/dnsmasq.conf" || fail "dnsmasq: kid-tablet (two MACs)"
grep -qx 'dhcp-host=aa:bb:cc:00:00:23,game-console' "$L/etc/dnsmasq.conf" || fail "dnsmasq: a device without a fixed address"
N=$L/etc/mini-router/gen/nftables.nft
for s in \
	'tcp dport 3390 dnat ip to 192.168.1.70:3389 comment "office-rdp"' \
	'ether saddr { aa:bb:cc:dd:ee:06, aa:bb:cc:00:00:21, aa:bb:cc:00:00:22, aa:bb:cc:00:00:23 } update @ac_4' \
	'ether saddr 02:00:00:00:10:01 ip daddr != { 192.168.1.0/24, 192.168.20.0/24, 192.168.30.0/24 } ct state new ct mark set 0x102' \
	'ether saddr 02:00:00:00:10:01 oifname { "pppoe-wan", "pppoe-isp3", "wan.20", "wan.30" } counter drop comment "fallback:office-wan2-only"' \
	'ether saddr { aa:bb:cc:00:00:21, aa:bb:cc:00:00:22, aa:bb:cc:00:00:23 } ip daddr != { 192.168.1.0/24'; do
	grep -qF -- "$s" "$N" || fail "lab ruleset lacks: $s"
done
if grep -rq '@paused\|set paused' "$L" "$OUT/home"; then fail "a generated file holds runtime pause state"; fi
grep -q 'fallback:\|dhcp-host=.*,office-pc' "$OUT/home/etc/mini-router/gen/nftables.nft" "$OUT/home/etc/dnsmasq.conf" && fail "home output has inventory lines"
echo "ok: lab inventory rendered; home and lab files carry no pause"

echo "-- mr pause / policy fallback: packets through the lab ruleset"
PY=$OUT/devnet.py
cat > "$PY" <<'EOF'
import os, socket, sys, time
cmd = sys.argv[1]
if cmd == "serve":  # serve PORT: tell every client its source address
    s = socket.socket(socket.AF_INET); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", int(sys.argv[2]))); s.listen(64)
    while True:
        c, a = s.accept(); c.sendall(("ok from " + a[0] + "\n").encode()); c.close()
elif cmd == "connect":  # connect ADDR PORT
    s = socket.socket(socket.AF_INET); s.settimeout(1.5)
    try:
        s.connect((sys.argv[2], int(sys.argv[3]))); print(s.recv(200).decode().strip())
    except Exception as e:
        print("ERR " + type(e).__name__); sys.exit(1)
elif cmd == "stream":  # stream PORT: send data forever to every client
    s = socket.socket(socket.AF_INET); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", int(sys.argv[2]))); s.listen(8)
    while True:
        c, a = s.accept()
        if os.fork() == 0:
            try:
                while True: c.sendall(b"x" * 1400); time.sleep(0.01)
            except Exception: pass
            os._exit(0)
elif cmd == "sink":  # sink ADDR PORT FILE: receive, keep the byte count in FILE
    s = socket.socket(socket.AF_INET); s.settimeout(1.5); s.connect((sys.argv[2], int(sys.argv[3]))); s.settimeout(0.2)
    n = 0
    while True:
        try:
            d = s.recv(65536)
            if not d: break
            n += len(d)
        except socket.timeout: pass
        with open(sys.argv[4] + ".tmp", "w") as f: f.write(str(n))
        os.replace(sys.argv[4] + ".tmp", sys.argv[4])
EOF

P=mrdev$$
R=${P}r W=${P}w A=${P}a B=${P}b O=${P}o
cleanup() {
	for n in $R $W $A $B $O; do
		for p in $(ip netns pids "$n" 2>/dev/null); do kill "$p" 2>/dev/null || true; done
		ip netns del "$n" 2>/dev/null || true
	done
	umount /run/mini-router 2>/dev/null || true
}
trap cleanup EXIT
mkdir -p /run/mini-router && mount -t tmpfs tmpfs /run/mini-router # private mount namespace: pause.json, fw.lock
for n in $R $W $A $B $O; do ip netns add "$n"; ip -n "$n" link set lo up; done
veth() { # veth NS1 NAME1 NS2 NAME2 [MAC2]
	ip link add "${P}x" type veth peer name "${P}y"
	ip link set "${P}x" netns "$1"; ip link set "${P}y" netns "$3"
	ip -n "$1" link set "${P}x" name "$2"; ip -n "$3" link set "${P}y" name "$4"
	[ -z "${5:-}" ] || ip -n "$3" link set "$4" address "$5"
	ip -n "$1" link set "$2" up; ip -n "$3" link set "$4" up
}
x() { ns=$1; shift; ip netns exec "$ns" "$@"; }
spawn() { setsid -f ip netns exec "$@" >/dev/null 2>&1 < /dev/null; }

# router: br-lan over lan2 (A = tv-box of the inventory), lan3 (B, not in the inventory), lan4 (O = office-pc)
ip -n "$R" link add br-lan type bridge
ip -n "$R" link set br-lan up
veth "$R" lan2 "$A" eth0 02:00:00:00:10:02
veth "$R" lan3 "$B" eth0 02:00:00:00:10:99
veth "$R" lan4 "$O" eth0 02:00:00:00:10:01
for p in lan2 lan3 lan4; do ip -n "$R" link set "$p" master br-lan; done
veth "$R" pppoe-wan "$W" eth0
veth "$R" pppoe-wan2 "$W" eth1
x "$R" sysctl -qw net.ipv4.ip_forward=1
ip -n "$R" addr add 192.168.1.6/24 dev br-lan
ip -n "$R" addr add 203.0.113.1/24 dev pppoe-wan
ip -n "$R" addr add 198.51.100.1/24 dev pppoe-wan2
ip -n "$R" route add default via 203.0.113.2 dev pppoe-wan # main: wan (wan2's table has no route yet)
ip -n "$A" addr add 192.168.1.60/24 dev eth0
ip -n "$B" addr add 192.168.1.61/24 dev eth0
ip -n "$O" addr add 192.168.1.70/24 dev eth0
for n in $A $B $O; do ip -n "$n" route add default via 192.168.1.6; done
ip -n "$W" addr add 203.0.113.2/24 dev eth0
ip -n "$W" addr add 198.51.100.7/24 dev eth1

mkdir -p /etc/mini-router/gen
cp "$OUT/lab-secrets.yaml" /etc/mini-router/secrets.yaml
# software offload (veths cannot do PPE); the proxy's tproxy rules are not part of this test
sed -e 's/offload: hardware/offload: software/' -e '/^proxy:/,/^[a-z]/ s/^  enabled: true/  enabled: false/' "$OUT/lab.yaml" > /etc/mini-router/router.yaml
x "$R" "$MR" fw || fail "mr fw"

spawn "$R" python3 "$PY" serve 53 # the router's own service (DNS port, TCP)
spawn "$W" python3 "$PY" serve 8080
spawn "$W" python3 "$PY" stream 9000
sleep 1
ok() { # ok NS ADDR PORT WHAT [EXPECT]
	out=$(x "$1" python3 "$PY" connect "$2" "$3") || fail "$4: expected to connect, got: $out"
	[ -z "${5:-}" ] || echo "$out" | grep -qF -- "$5" || fail "$4: expected '$5', got: $out"
	echo "ok: $4 ($out)"
}
blocked() { # blocked NS ADDR PORT WHAT
	if out=$(x "$1" python3 "$PY" connect "$2" "$3"); then fail "$4: expected to be blocked, got: $out"; fi
	echo "ok: $4 ($out)"
}
bytes() { cat "$OUT/$1" 2>/dev/null || echo 0; }
flowing() { # flowing FILE: bytes still arriving
	a=$(bytes "$1"); sleep 1; b=$(bytes "$1")
	[ $((b - a)) -gt 20000 ]
}

ok "$A" 203.0.113.2 8080 "tv-box -> internet before the pause" "ok from 203.0.113.1"
spawn "$A" python3 "$PY" sink 203.0.113.2 9000 "$OUT/dev-a"
spawn "$B" python3 "$PY" sink 203.0.113.2 9000 "$OUT/dev-b"
sleep 1.5
flowing dev-a || fail "tv-box download not flowing"
flowing dev-b || fail "other device's download not flowing"
if x "$R" grep -q 'OFFLOAD' /proc/net/nf_conntrack 2>/dev/null; then echo "ok: downloads are in the flowtable ([OFFLOAD])"; fi

x "$R" "$MR" pause tv-box 20s | grep -q 'paused tv-box (02:00:00:00:10:02)' || fail "mr pause tv-box"
x "$R" nft list set inet mr paused | grep -q '02:00:00:00:10:02' || fail "@paused lacks tv-box"
x "$R" nft list set inet mr paused_4 | grep -q '192.168.1.60' || fail "@paused_4 lacks tv-box's address (neighbour table)"
sleep 0.5
if flowing dev-a; then fail "paused device's established download kept flowing"; fi
echo "ok: the paused device's established (offloaded) download stopped"
flowing dev-b || fail "another device's download stopped too"
echo "ok: another device keeps flowing"
blocked "$A" 203.0.113.2 8080 "paused device -> internet (new connection)"
ok "$A" 192.168.1.6 53 "paused device -> the router's DNS port still works"
ok "$B" 203.0.113.2 8080 "another device -> internet"
x "$R" "$MR" pause list | grep -q '02:00:00:00:10:02  tv-box' || fail "mr pause list: $(x "$R" "$MR" pause list)"
x "$R" "$MR" pause list --json | grep -q '"ref": "tv-box"' || fail "mr pause list --json"
x "$R" "$MR" fw || fail "reload during a pause"
x "$R" nft list set inet mr paused | grep -q '02:00:00:00:10:02' || fail "a reload lost the pause"
blocked "$A" 203.0.113.2 8080 "paused device, after a firewall reload"
x "$R" nft list chain inet mr forward | grep 'comment "pause"' | grep -qv 'packets 0 ' || fail "pause counter did not count"
i=0 # the kernel ends the pause: no reload, no command
while x "$R" nft list set inet mr paused | grep -q '02:00:00:00:10:02'; do
	i=$((i + 1))
	[ $i -lt 30 ] || fail "the pause did not end"
	sleep 1
done
ok "$A" 203.0.113.2 8080 "the pause ended by itself (kernel timeout)" "ok from 203.0.113.1"
x "$R" "$MR" pause list | grep -q 'nothing paused' || fail "ended pause still listed"

x "$R" "$MR" pause 02:00:00:00:10:99 1h > /dev/null || fail "mr pause by MAC"
blocked "$B" 203.0.113.2 8080 "paused by MAC"
ok "$A" 203.0.113.2 8080 "a device that is not paused"
x "$R" "$MR" unpause all | grep -q 'unpaused 02:00:00:00:10:99' || fail "mr unpause all"
ok "$B" 203.0.113.2 8080 "unpaused early (mr unpause)"
x "$R" "$MR" pause nobody 1h 2>/dev/null && fail "pausing an unknown device"
x "$R" "$MR" pause tv-box 9d 2>/dev/null && fail "a pause longer than 7 days"
echo "mr pause: ok"

# office-pc: policy office-wan2-only (via wan2, fallback: drop). wan2's table (0x102 → 102) has no route:
# the mark lookup falls through to main, whose default leaves through pppoe-wan — dropped.
x "$R" ip rule add fwmark 0x102 lookup 102 pref 5300
blocked "$O" 203.0.113.2 8080 "fallback: drop — no way out through another WAN while wan2 has no route"
x "$R" nft list chain inet mr forward | grep '"fallback:office-wan2-only"' | grep -qv 'packets 0 ' || fail "fallback counter did not count"
ok "$B" 203.0.113.2 8080 "a device without the policy still uses the main route" "ok from 203.0.113.1"
x "$R" ip route add default via 198.51.100.7 dev pppoe-wan2 table 102
ok "$O" 203.0.113.2 8080 "fallback: drop — through wan2 once its table has a route" "ok from 198.51.100.1"
rm -f "$OUT/dev-a" "$OUT/dev-b"
echo "dev: all packet checks passed"
