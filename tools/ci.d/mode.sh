#!/bin/sh
# mode bypass / ap (mr/mode.go), run by tools/ci.sh with OUT and ROOT, in network namespaces:
#  1. bypass route-only behind a main router that drops invalid packets (as OpenWrt does): the main router
#     routes what `mr proxy routes` prints to the box; a client whose gateway stays the main router reaches
#     a proxied range through the box's transparent socket, because the reply goes back through the main
#     router (connmark + fwmark rule + table from the rendered ruleset / network.sh). Without the reply
#     rule the same connection breaks (the main router sees only one direction).
#  2. bypass all: a client with the box as gateway reaches the internet; the main router sees the box's
#     address (bypass-nat), not the client's.
#  3. ap: the rendered ruleset loads (no WAN sets, no flowtable).
set -eu
: "${OUT:?}" "${ROOT:?}"
MR=$OUT/mr-host
T=$OUT/mode
mkdir -p "$T"
fail() { echo "FAIL: $*"; exit 1; }

P=mrmd$$
M=${P}m B=${P}b C=${P}c D=${P}d I=${P}i
cleanup() {
	for n in $M $B $C $D $I; do
		for p in $(ip netns pids "$n" 2> /dev/null); do kill "$p" 2> /dev/null || true; done
		ip netns del "$n" 2> /dev/null || true
	done
}
trap cleanup EXIT
for n in $M $B $C $D $I; do
	ip netns add "$n"
	ip -n "$n" link set lo up
done
x() {
	ns=$1
	shift
	ip netns exec "$ns" "$@"
}
VN=0
veth() { # veth NS1 NAME1 NS2 NAME2 — explicit MACs: udev's MACAddressPolicy=persistent derives them from the
	# (reused) creation names, which would give every peer the same address
	VN=$((VN + 1))
	ip link add "${P}x" address "02:00:00:00:0$VN:01" type veth peer name "${P}y" address "02:00:00:00:0$VN:02"
	ip link set "${P}x" netns "$1"
	ip link set "${P}y" netns "$3"
	ip -n "$1" link set "${P}x" name "$2"
	ip -n "$3" link set "${P}y" name "$4"
	ip -n "$1" link set "$2" up
	ip -n "$3" link set "$4" up
}

# the main router: a switch (bridge "lan") with the box, two clients and itself at .1; a WAN to "the internet"
ip -n "$M" link add lan type bridge
ip -n "$M" link set lan up
veth "$M" pb "$B" eth0
veth "$M" pc "$C" eth0
veth "$M" pd "$D" eth0
veth "$M" wan "$I" eth0
for p in pb pc pd; do ip -n "$M" link set "$p" master lan; done
ip -n "$M" addr add 192.168.1.1/24 dev lan
ip -n "$M" addr add 203.0.113.1/24 dev wan
x "$M" sysctl -qw net.ipv4.ip_forward=1 net.ipv4.conf.all.send_redirects=0 net.ipv4.conf.lan.send_redirects=0
cat > "$T/main.nft" << 'EOF'
table inet m {
	chain forward_main {
		type filter hook forward priority filter; policy drop;
		ct state invalid counter drop comment "invalid"
		ct state established,related accept
		iifname "lan" ip saddr 192.168.1.2 oifname "wan" counter accept comment "from-box"
		iifname "lan" ip saddr 192.168.1.60 oifname "wan" counter accept comment "from-client-d"
		iifname "lan" accept
	}
	chain postrouting_main {
		type nat hook postrouting priority srcnat;
		oifname "wan" masquerade
	}
}
EOF
x "$M" nft -f "$T/main.nft"
ip -n "$I" addr add 203.0.113.2/24 dev eth0
ip -n "$I" route add default via 203.0.113.1
for n in $C $D; do x "$n" sysctl -qw net.ipv4.conf.all.accept_redirects=0 net.ipv4.conf.eth0.accept_redirects=0; done
ip -n "$C" addr add 192.168.1.50/24 dev eth0
ip -n "$C" route add default via 192.168.1.1 # route-only: the main router stays the gateway
ip -n "$D" addr add 192.168.1.60/24 dev eth0
ip -n "$D" route add default via 192.168.1.2 # all: the box is the gateway

# the box
cat > "$T/secrets.yaml" << 'EOF'
proxy_n1: "not-a-real-password"
EOF
box() { # box YAML-TAIL: render the side router's config, load its network.sh (without the IRQ tuning) and ruleset
	cat > "$T/box.yaml" << EOF
mode: bypass
system: {hostname: side, ntp: [pool.ntp.org]}
lan: {bridge: br-lan, ports: [eth0], ipv4: 192.168.1.2/24, gateway: 192.168.1.1}
wan: []
policy_routes: []
static_routes: []
firewall: {offload: software}
dhcp: {start: 100, end: 249, lease: 12h, domain: lan}
dns: {cache_size: 4000}
wifi: {radios: []}
services: {}
proxy:
  enabled: true
  ipv4_only: true
  nodes: [{name: n1, server: 203.0.113.7, port: 8388, method: aes-128-gcm, password_secret: proxy_n1}]
  rules: [{name: blocked, outbound: n1, cidrs: [198.51.100.0/24]}]
$1
EOF
	rm -rf "$T/box"
	"$MR" -c "$T/box.yaml" -s "$T/secrets.yaml" render "$T/box" > /dev/null || fail "render: $("$MR" -c "$T/box.yaml" -s "$T/secrets.yaml" validate 2>&1)"
	sed '/^# --- tail/,$d' "$T/box/etc/mini-router/gen/network.sh" > "$T/net.sh"
	x "$B" sh "$T/net.sh" > "$T/net.log" 2>&1 || true
	x "$B" nft -f "$T/box/etc/mini-router/gen/nftables.nft" || fail "box ruleset does not load"
}
x "$B" sysctl -qw net.ipv4.ip_forward=1 net.ipv4.conf.all.send_redirects=0 net.ipv4.conf.default.send_redirects=0
box ""
[ "$(x "$B" ip -4 route show default)" = "default via 192.168.1.1 dev br-lan " ] || fail "box default route: $(x "$B" ip -4 route show default) ($(cat "$T/net.log"))"
x "$B" ip -4 rule | grep -q 'fwmark 0x2000000/0x2000000 lookup 301' || fail "no reply rule: $(x "$B" ip -4 rule)"

# the main router's static routes, as the box prints them
"$MR" -c "$T/box.yaml" -s "$T/secrets.yaml" proxy routes > "$T/routes.txt"
grep -qx '198.18.0.0/15 via 192.168.1.2' "$T/routes.txt" && grep -qx '198.51.100.0/24 via 192.168.1.2' "$T/routes.txt" ||
	fail "mr proxy routes: $(cat "$T/routes.txt")"
while read -r net _ via; do ip -n "$M" route add "$net" via "$via"; done < "$T/routes.txt"

# sing-box stand-in: a transparent socket on the tproxy port that answers for any proxied address
cat > "$T/tp.py" << 'EOF'
import socket
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.setsockopt(socket.SOL_IP, 19, 1)
s.bind(("127.0.0.1", 7893)); s.listen(16)
while True:
    c, a = s.accept()
    c.settimeout(3)
    try:
        d = c.recv(100)
        c.sendall(b"proxied " + d + b" from " + a[0].encode() + b" to " + c.getsockname()[0].encode() + b"\n")
    except Exception:
        pass
    c.close()
EOF
cat > "$T/cl.py" << 'EOF'
import socket, sys
s = socket.socket(); s.settimeout(3)
try:
    s.connect((sys.argv[1], int(sys.argv[2]))); s.sendall(b"hello"); print(s.recv(200).decode().strip())
except Exception as e:
    print("ERR " + type(e).__name__); sys.exit(1)
EOF
cat > "$T/echo.py" << 'EOF'
import socket
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("0.0.0.0", 8080)); s.listen(16)
while True:
    c, a = s.accept(); c.settimeout(3)
    try: c.recv(100); c.sendall(("ok from " + a[0] + "\n").encode())
    except Exception: pass
    c.close()
EOF
spawn() { setsid -f ip netns exec "$@" > /dev/null 2>&1 < /dev/null; }
spawn "$B" python3 "$T/tp.py"
spawn "$I" python3 "$T/echo.py"
sleep 1

# 1. route-only
out=$(x "$C" python3 "$T/cl.py" 198.51.100.7 443) || {
	echo "--- box"; x "$B" nft list ruleset | grep -A8 'chain proxy_'; x "$B" ip rule; x "$B" ip route show table 301
	echo "--- main"; x "$M" ip route; x "$M" nft list ruleset
	fail "route-only: client -> proxied range: $out"
}
[ "$out" = "proxied hello from 192.168.1.50 to 198.51.100.7" ] || fail "route-only: $out"
echo "ok: bypass route-only: $out, the reply went back through the main router"
out=$(x "$C" python3 "$T/cl.py" 198.18.0.9 80) || fail "route-only: fake-ip range: $out"
echo "ok: bypass route-only: fake-ip range answered too"
x "$C" python3 "$T/cl.py" 203.0.113.2 8080 | grep -q '^ok from 203.0.113.1$' || fail "route-only: unproxied traffic stays on the main router"
x "$B" ip -4 rule del pref 5201
if out=$(x "$C" python3 "$T/cl.py" 198.51.100.7 443); then fail "without the reply rule the connection worked: $out"; fi
x "$M" nft list chain inet m forward_main | grep '"invalid"' | grep -qv 'packets 0 ' || fail "control: the main router did not drop anything"
echo "ok: control: without the reply rule the main router drops the client's side as invalid ($out)"

# 2. all: the box is the gateway; the main router sees the box, not the client
box "bypass: {clients: all}"
if x "$B" ip -4 rule | grep -q 'lookup 301'; then fail "all: the reply rule stayed"; fi
x "$D" python3 "$T/cl.py" 203.0.113.2 8080 | grep -q '^ok from 203.0.113.1$' || fail "all: client -> internet through the box"
x "$M" nft list chain inet m forward_main | grep '"from-box"' | grep -qv 'packets 0 ' || fail "all: the main router did not see the box's address"
x "$M" nft list chain inet m forward_main | grep '"from-client-d"' | grep -q 'packets 0 ' || fail "all: the client's own address reached the main router (no bypass-nat)"
out=$(x "$D" python3 "$T/cl.py" 198.51.100.7 443) || fail "all: proxied range: $out"
echo "ok: bypass all: the client reaches the internet through the box (masqueraded) and the proxied range ($out)"

# 3. ap
sed -e 's/^mode: bypass/mode: ap/' -e '/^proxy:/,$d' "$T/box.yaml" > "$T/ap.yaml"
rm -rf "$T/ap"
"$MR" -c "$T/ap.yaml" -s "$T/secrets.yaml" render "$T/ap" > /dev/null || fail "ap render"
x "$B" nft -c -f "$T/ap/etc/mini-router/gen/nftables.nft" || fail "ap ruleset"
grep -q '^net.ipv4.ip_forward=0$' "$T/ap/etc/sysctl.d/90-mini-router.conf" || fail "ap forwards"
echo "ok: ap: ruleset loads, forwarding off"
echo "mode: all checks passed"
