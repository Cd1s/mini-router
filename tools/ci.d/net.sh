#!/bin/sh
# net module CI checks, run by tools/ci.sh (as root, inside its private mount namespace) with
# OUT (rendered trees in $OUT/home, $OUT/lab; host build of mr in $OUT/mr-host) and ROOT.
#  1. generated service instances + health-checker config (shellcheck, expected content)
#  2. functional test in two network namespaces with the real tools: busybox udhcpc + the mr hook
#     against a dnsmasq DHCP server, a static WAN via `mr routes`, and the busybox sh health checker
#     taking a WAN down and up again (routes, rules, balance map in the loaded nft ruleset, DNS).
#  4. PPPoE mtu 1500 (RFC 4638): the rendered link commands give the PPPoE port 1508 and a DHCP VLAN on it
#     1500 in the real kernel; IPv6 renumbering (RFC 9096): after a "reboot" (another boot id in the
#     record) the real `mr hook dhcpcd` puts a prefix that did not come back on the bridge, and a real
#     dnsmasq advertises it to a client with preferred lifetime 0 while the current one stays preferred.
#  3. policy route by domain, end to end in three network namespaces: the rendered nftset= lines in a
#     real dnsmasq (unprivileged, like the router's) fill the rendered nft sets from an upstream's answers,
#     a LAN client's connection to such an address leaves through the policy's WAN (others through the
#     default WAN), the learned addresses survive a firewall reload, a new connection restarts an
#     address's timer, and a changed domain list starts with empty sets.
set -eu
: "${OUT:?}" "${ROOT:?}"
step() { printf '\n== net: %s\n' "$*"; }
fail() {
	echo "net: FAIL: $*"
	exit 1
}
has() { # has WHAT TEXT PATTERN
	printf '%s\n' "$2" | grep -q -- "$3" || fail "$1: missing '$3' in:
$2"
}
hasnt() {
	if printf '%s\n' "$2" | grep -q -- "$3"; then fail "$1: unexpected '$3' in:
$2"; fi
}

step "generated service instances + wanmon.conf (lab)"
L=$OUT/lab
for f in "$L"/etc/init.d/mr-pppoe.* "$L"/etc/init.d/mr-udhcpc.*; do
	[ "$(head -n 1 "$f")" = '#!/sbin/openrc-run' ] || fail "$f: not an openrc-run script"
	shellcheck -s sh -S warning -e SC2034 "$f" # MR_WAN_DEV is read by the sourced script
done
grep -qx 'MR_WAN_DEV=wan.20' "$L/etc/init.d/mr-udhcpc.iptv" || fail "mr-udhcpc.iptv: device"
shellcheck -s sh -S warning -e SC2034 "$L/etc/mini-router/gen/wanmon.conf"
grep -qx 'WANS="wan:pppoe-wan wan2:pppoe-wan2 isp3:pppoe-isp3 iptv:wan.20 office:wan.30"' "$L/etc/mini-router/gen/wanmon.conf" || fail "wanmon.conf WANS"
grep -q 'ct mark set numgen random mod 3 map { 0-1 : 0x200, 2 : 0x102 }' "$L/etc/mini-router/gen/nftables.nft" || fail "lab: balance rule"
grep -q '^nic-wan.500$' "$L/etc/ppp/peers/isp3" || fail "isp3: PPPoE on VLAN"
for s in mr-udhcpc.iptv mr-pppoe.isp3 mr-wanmon igmpproxy; do
	grep -qx "$s" "$L/etc/mini-router/gen/services" || fail "lab services: $s"
done
if grep -q 'mr-udhcpc\|mr-wanmon' "$OUT/home/etc/mini-router/gen/services"; then fail "home: unexpected services"; fi

step "functional: DHCP + static WAN, health checker, failover, balance (network namespaces)"
T=$OUT/net-func
rm -rf "$T" && mkdir -p "$T/bin"
mkdir -p /run/mini-router && mount -t tmpfs tmpfs /run/mini-router
S=mrnet$$s C=mrnet$$c
DS=mrdom$$s DC=mrdom$$c DL=mrdom$$l # policy route by domain (3.)
RR=mrra$$r RC=mrra$$c                # PPPoE MTU / RFC 9096 (4.)
cleanup() {
	[ -f "$T/dnsmasq.pid" ] && kill "$(cat "$T/dnsmasq.pid")" 2> /dev/null
	[ -f "$T/ra-dnsmasq.pid" ] && kill "$(cat "$T/ra-dnsmasq.pid")" 2> /dev/null
	for n in "$S" "$C" "$DS" "$DC" "$DL" "$RR" "$RC"; do
		for p in $(ip netns pids "$n" 2> /dev/null); do kill "$p" 2> /dev/null; done
		ip netns del "$n" 2> /dev/null
	done
	umount /run/mini-router 2> /dev/null
	return 0
}
trap cleanup EXIT
cat > "$T/router.yaml" << 'EOF'
system: {hostname: nettest}
lan: {bridge: br-lan, ports: [lan2], ipv4: 192.168.1.6/24}
wan:
  - {name: wan, device: wan, proto: dhcp, metric: 10, peerdns: true, ipv6: true, ipv6_srcroute: true}
  - {name: wan2, device: wan2, proto: static, ipv4: 10.98.0.2/24, gateway: 10.98.0.1, dns: [10.98.0.53], metric: 20}
multiwan: {mode: balance, targets: [10.99.0.1], interval: 1, timeout: 1, fall: 2, rise: 1}
policy_routes:
  - {name: nas, src: 192.168.1.66, via: wan2}
firewall: {offload: software}
dhcp: {start: 100, end: 200, lease: 12h, domain: lan}
EOF
: > "$T/secrets.yaml"
MRH=$OUT/mr-host
"$MRH" -c "$T/router.yaml" -s "$T/secrets.yaml" validate
"$MRH" -c "$T/router.yaml" -s "$T/secrets.yaml" render "$T/r" > /dev/null
cp "$T/router.yaml" /etc/mini-router/router.yaml # fwLoad re-reads the live config (tmpfs in this namespace)
cp "$T/secrets.yaml" /etc/mini-router/secrets.yaml
printf '#!/bin/sh\nexec %s -c %s -s %s "$@"\n' "$MRH" "$T/router.yaml" "$T/secrets.yaml" > "$T/bin/mr"
printf '#!/bin/sh\necho "$*" >> %s\n' "$T/wanmon.log" > "$T/bin/logger"
chmod 755 "$T/bin/mr" "$T/bin/logger"
ln -s "$(command -v busybox)" "$T/bin/ping" # the router's ping is busybox's
export MR_BIN="$T/bin/mr" PATH="$T/bin:$PATH"
inC() { ip netns exec "$C" "$@"; }

# "internet" side ($S): 10.99.0.1 behind uplink 1 (DHCP server), 10.98.0.1 behind uplink 2
ip netns add "$S"
ip netns add "$C"
ip link add wan netns "$C" type veth peer name up1 netns "$S"
ip link add wan2 netns "$C" type veth peer name up2 netns "$S"
ip -n "$S" addr add 10.99.0.1/24 dev up1
ip -n "$S" addr add 10.98.0.1/24 dev up2
for d in lo up1 up2; do ip -n "$S" link set "$d" up; done
ip -n "$C" link set lo up
ip -n "$C" link add lan2 type dummy
# the router's kernel default (the build host's may differ): deleting a primary address also deletes
# the secondaries in its subnet
inC sh -c 'for d in all default wan wan2; do echo 0 > /proc/sys/net/ipv4/conf/$d/promote_secondaries; done'
ip netns exec "$S" dnsmasq --conf-file=/dev/null --port=0 --interface=up1 --bind-interfaces \
	--dhcp-range=10.99.0.50,10.99.0.60,255.255.255.0,1h --dhcp-option=3,10.99.0.1 --dhcp-option=6,10.99.0.53,10.99.0.54 \
	--dhcp-leasefile="$T/leases" --pid-file="$T/dnsmasq.pid" --user=root --group=root

# network.sh as generated (without the IRQ/RPS tail, which would touch the build host)
sed '/^# --- tail/,$d' "$T/r/etc/mini-router/gen/network.sh" > "$T/net.sh"
inC sh "$T/net.sh" 2> "$T/net.sh.err" || { cat "$T/net.sh.err"; fail "network.sh"; } # veth peers in another netns make ip(8) chatty
rules=$(ip -n "$C" -4 rule show)
has "rules" "$rules" "5299:.*lookup main suppress_prefixlength 0"
has "rules" "$rules" "5300:.*fwmark 0x200 lookup 200"
has "rules" "$rules" "5300:.*fwmark 0x201 lookup 201"
has "wan2 static address" "$(ip -n "$C" -4 addr show dev wan2 2> /dev/null)" "inet 10.98.0.2/24"
has "br-lan" "$(ip -n "$C" -4 addr show dev br-lan)" "inet 192.168.1.6/24"

# DHCP: the real busybox udhcpc with the real event script → `mr wan dhcp bound`
inC busybox udhcpc -f -q -n -t 5 -T 1 -i wan -s "$ROOT/rootfs/usr/libexec/mr/net-udhcpc" > "$T/udhcpc.log" 2>&1 || {
	cat "$T/udhcpc.log"
	fail "udhcpc got no lease"
}
has "wan address" "$(ip -n "$C" -4 addr show dev wan 2> /dev/null)" "inet 10.99.0.[56][0-9]/24"
has "main default" "$(ip -n "$C" route show default)" "default via 10.99.0.1 dev wan metric 10"
has "table 200" "$(ip -n "$C" route show table 200)" "default via 10.99.0.1 dev wan"
has "table 200 LAN route" "$(ip -n "$C" route show table 200)" "192.168.1.0/24 dev br-lan"
has "from-WAN rule" "$(ip -n "$C" -4 rule show)" "5290:.*from 10.99.0.[56][0-9] lookup 200"
has "resolv" "$(cat /run/mini-router/resolv.conf)" "nameserver 10.99.0.53"
has "resolv" "$(cat /run/mini-router/resolv.conf)" "nameserver 10.99.0.54"

# static WAN + firewall: `mr routes` (what mr-network runs at boot)
inC mr routes
has "main default wan2" "$(ip -n "$C" route show default)" "default via 10.98.0.1 dev wan2 metric 20"
has "table 201" "$(ip -n "$C" route show table 201)" "default via 10.98.0.1 dev wan2"
[ "$(grep nameserver /run/mini-router/resolv.conf | tr '\n' ' ')" = "nameserver 10.99.0.53 nameserver 10.99.0.54 nameserver 10.98.0.53 " ] ||
	fail "resolv.conf order: $(cat /run/mini-router/resolv.conf)"
nft=$(inC nft list table inet mr)
has "nft balance" "$nft" "numgen random mod 2 map { 0 : 0x0*200, 1 : 0x0*201 }"
has "nft policy" "$nft" 'ip saddr 192.168.1.66 ip daddr != 192.168.1.0/24 ct state new ct mark set 0x0*201'
has "nft flowtable" "$nft" "flowtable ft"

# health checker, both WANs answer
inC env WANMON_CONF="$T/r/etc/mini-router/gen/wanmon.conf" WANMON_ROUNDS=2 busybox sh "$ROOT/rootfs/usr/libexec/mr/net-wanmon"
st=$(cat /run/mini-router/wan-state.json)
has "state" "$st" '"name":"wan","dev":"wan","state":"up","rtt_ms":[0-9]'
has "state" "$st" '"name":"wan2","dev":"wan2","state":"up","rtt_ms":[0-9]'
has "mr wan status" "$(inC mr wan status)" '"health":"up"'

# uplink 2 dies → down after 2 rounds; comes back → up after 1 good round (one checker run)
ip -n "$S" link set up2 down
inC env WANMON_CONF="$T/r/etc/mini-router/gen/wanmon.conf" WANMON_ROUNDS=12 busybox sh "$ROOT/rootfs/usr/libexec/mr/net-wanmon" &
mon=$!
i=0
until grep -q '"name":"wan2","dev":"wan2","state":"down"' /run/mini-router/wan-state.json 2> /dev/null; do
	i=$((i + 1))
	[ "$i" -le 40 ] || fail "wan2 never marked down: $(cat /run/mini-router/wan-state.json)"
	sleep 0.5
done
sleep 1 # let `mr wan health` finish
has "down: metric raised" "$(ip -n "$C" route show default)" "dev wan2 metric 10020"
has "down: wan keeps its metric" "$(ip -n "$C" route show default)" "default via 10.99.0.1 dev wan metric 10"
hasnt "down: table 201 default" "$(ip -n "$C" route show table 201 2> /dev/null)" "default"
hasnt "down: balance map" "$(inC nft list table inet mr)" "numgen"
[ "$(grep nameserver /run/mini-router/resolv.conf | head -n 1)" = "nameserver 10.99.0.53" ] || fail "resolv: healthy WAN first"
ip -n "$S" link set up2 up
wait "$mon"
has "up again: state" "$(cat /run/mini-router/wan-state.json)" '"name":"wan2","dev":"wan2","state":"up"'
has "up again: metric" "$(ip -n "$C" route show default)" "default via 10.98.0.1 dev wan2 metric 20"
has "up again: table 201" "$(ip -n "$C" route show table 201)" "default via 10.98.0.1 dev wan2"
has "up again: balance map" "$(inC nft list table inet mr)" "numgen random mod 2"
has "wanmon log" "$(cat "$T/wanmon.log")" "wan2 down: no reply"
has "wanmon log" "$(cat "$T/wanmon.log")" "wan2 up again via wan2"

# DHCP lease lost → address, routes, rules, DNS of that WAN go away
inC env interface=wan mr wan dhcp deconfig 2> /dev/null
hasnt "deconfig: address" "$(ip -n "$C" -4 addr show dev wan 2> /dev/null)" "inet "
hasnt "deconfig: default" "$(ip -n "$C" route show default)" "dev wan "
hasnt "deconfig: table 200" "$(ip -n "$C" route show table 200 2> /dev/null)" "default"
hasnt "deconfig: rule" "$(ip -n "$C" -4 rule show)" "5290:.*lookup 200"
hasnt "deconfig: resolv" "$(cat /run/mini-router/resolv.conf)" "10.99.0.53"
[ ! -e /run/mini-router/wan/wan.json ] || fail "deconfig: lease record kept"
# a forged lease must not reach ip(8): garbage address → error, nothing configured
if inC env interface=wan ip='1.2.3.4;reboot' mr wan dhcp bound 2> /dev/null; then fail "forged lease accepted"; fi
if inC env interface=br-lan ip=10.0.0.2 mr wan dhcp bound 2> /dev/null; then fail "non-WAN interface accepted"; fi

# dhcpcd on an ethernet WAN: IPv6 routes go via the RA gateway (a default route without one would
# be "on link" and neighbour-solicit every destination on the WAN)
inC ip -6 route add default via fe80::1 dev wan metric 1034
inC env interface=wan reason=BOUND6 new_delegated_dhcp6_prefix=2001:db8:5::/64 mr hook dhcpcd
has "v6 source route" "$(ip -n "$C" -6 route show)" "default from 2001:db8:5::/64 via fe80::1 dev wan"
has "v6 table 200" "$(ip -n "$C" -6 route show table 200)" "default via fe80::1 dev wan"

# DHCP gives a new address in the same subnet: the new one must survive the removal of the old one
inC env interface=wan ip=10.99.0.77 mask=24 router=10.99.0.1 dns=10.99.0.53 mr wan dhcp bound
inC ip rule add from 10.99.0.78 lookup 999 pref 5290 # left over from an older table numbering
inC env interface=wan ip=10.99.0.78 mask=24 router=10.99.0.1 dns=10.99.0.53 mr wan dhcp bound
hasnt "from-WAN rule of another table" "$(ip -n "$C" -4 rule show)" "lookup 999"
has "from-WAN rule" "$(ip -n "$C" -4 rule show)" "5290:.*from 10.99.0.78 lookup 200"
a=$(ip -n "$C" -4 -o addr show dev wan)
has "new lease in the same subnet" "$a" "inet 10.99.0.78/24"
hasnt "new lease in the same subnet" "$a" "10.99.0.77/"
has "new lease: default" "$(ip -n "$C" route show default)" "default via 10.99.0.1 dev wan metric 10"

# the DHCP WAN leaves router.yaml (back home after travelling): its client's deconfig no longer finds
# the interface, so `mr routes` (run by every apply) removes the address and default route left on it
grep -v 'name: wan, device: wan,\|^multiwan:' "$T/router.yaml" > "$T/router-b.yaml"
printf '#!/bin/sh\nexec %s -c %s -s %s "$@"\n' "$MRH" "$T/router-b.yaml" "$T/secrets.yaml" > "$T/bin/mrb"
chmod 755 "$T/bin/mrb"
"$MRH" -c "$T/router-b.yaml" -s "$T/secrets.yaml" validate
if inC env interface=wan mrb wan dhcp deconfig 2> /dev/null; then fail "deconfig of a removed WAN accepted"; fi
has "removed WAN: leftover before" "$(ip -n "$C" route show default)" "dev wan metric 10"
inC mrb routes
hasnt "removed WAN: default" "$(ip -n "$C" route show default)" "dev wan "
hasnt "removed WAN: address" "$(ip -n "$C" -4 addr show dev wan)" "inet "
[ ! -e /run/mini-router/wan/wan.json ] || fail "removed WAN: lease record kept"
has "removed WAN: wan2 kept" "$(ip -n "$C" route show default)" "default via 10.98.0.1 dev wan2 metric 20"

# a static address changed inside its subnet (network.sh re-run by apply)
inC sh -c 'echo 0 > /proc/sys/net/ipv4/conf/wan2/promote_secondaries'
sed 's#10\.98\.0\.2/24#10.98.0.3/24#g' "$T/net.sh" > "$T/net2.sh"
inC sh "$T/net2.sh" 2> "$T/net.sh.err" || { cat "$T/net.sh.err"; fail "network.sh (static address changed)"; }
a=$(ip -n "$C" -4 -o addr show dev wan2)
has "static address changed" "$a" "inet 10.98.0.3/24"
hasnt "static address changed" "$a" "10.98.0.2/"
echo "net: functional test ok"

step "functional: policy route by domain (dnsmasq nftset -> nft set -> WAN mark), three network namespaces"
# $DS = "internet" (upstream DNS + a server that echoes the source address it sees, reachable through both
# uplinks), $DC = the router (the rendered network.sh, ruleset and nftset= lines), $DL = a LAN client
D=$OUT/net-dom
rm -rf "$D" && mkdir -p "$D/bin"
find /run/mini-router -mindepth 1 -delete # WAN state of the test above
cat > "$D/router.yaml" << 'YAML'
system: {hostname: domtest}
lan: {bridge: br-lan, ports: [lan2], ipv4: 192.168.1.6/24}
wan:
  - {name: wan, device: wan, proto: static, ipv4: 10.97.0.2/24, gateway: 10.97.0.1, metric: 10}
  - {name: wan2, device: wan2, proto: static, ipv4: 10.96.0.2/24, gateway: 10.96.0.1, metric: 20}
policy_routes:
  - {name: video, domains: [video.example], via: wan2}
firewall: {offload: software}
dhcp: {start: 100, end: 200, lease: 12h, domain: lan}
dns: {upstream: manual, servers: [10.97.0.1]}
YAML
"$MRH" -c "$D/router.yaml" -s "$T/secrets.yaml" validate
"$MRH" -c "$D/router.yaml" -s "$T/secrets.yaml" render "$D/r" > /dev/null
cp "$D/router.yaml" /etc/mini-router/router.yaml
printf '#!/bin/sh\nexec %s -c %s -s %s "$@"\n' "$MRH" "$D/router.yaml" "$T/secrets.yaml" > "$D/bin/mr"
chmod 755 "$D/bin/mr"
export MR_BIN="$D/bin/mr" PATH="$D/bin:$PATH"
inD() { ip netns exec "$DC" "$@"; }
for n in "$DS" "$DC" "$DL"; do ip netns add "$n"; done
ip link add wan netns "$DC" type veth peer name up1 netns "$DS"
ip link add wan2 netns "$DC" type veth peer name up2 netns "$DS"
ip link add lan2 netns "$DC" type veth peer name eth0 netns "$DL"
ip -n "$DS" addr add 10.97.0.1/24 dev up1
ip -n "$DS" addr add 10.96.0.1/24 dev up2
for a in 192.0.2.80 192.0.2.81 192.0.2.82; do ip -n "$DS" addr add "$a/32" dev lo; done
for d in lo up1 up2; do ip -n "$DS" link set "$d" up; done
ip -n "$DC" link set lo up
ip -n "$DL" link set lo up
ip -n "$DL" link set eth0 up
ip -n "$DL" addr add 192.168.1.50/24 dev eth0
ip -n "$DL" route add default via 192.168.1.6
inD sysctl -qw net.ipv4.ip_forward=1
ip netns exec "$DS" dnsmasq --conf-file=/dev/null --no-resolv --no-hosts --listen-address=10.97.0.1 --bind-interfaces --local-ttl=300 \
	--address=/video.example/192.0.2.80 --address=/video.example/2001:db8:80::1 --address=/other.example/192.0.2.81 \
	--pid-file="$D/upstream.pid" --user=root --group=root
cat > "$D/echo.py" << 'PY'
import socket, sys
if sys.argv[1] == "serve":  # tell every client the address it came from
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("0.0.0.0", 8080)); s.listen(16)
    while True:
        c, a = s.accept(); c.sendall((a[0] + "\n").encode()); c.close()
try:
    print(socket.create_connection((sys.argv[1], 8080), timeout=2).recv(100).decode().strip())
except OSError as e:
    print("ERR " + type(e).__name__)
PY
setsid -f ip netns exec "$DS" python3 "$D/echo.py" serve > /dev/null 2>&1 < /dev/null
seen() { ip netns exec "$DL" python3 "$D/echo.py" "$1"; } # the source address the server saw

# the router: network.sh as generated, then `mr routes` (static WAN routes, tables, firewall via fwLoad)
sed '/^# --- tail/,$d' "$D/r/etc/mini-router/gen/network.sh" > "$D/net.sh"
inD sh "$D/net.sh" 2> "$D/net.sh.err" || { cat "$D/net.sh.err"; fail "network.sh (domain test)"; }
inD mr routes
nft=$(inD nft list table inet mr)
has "domain sets" "$nft" "set pr_0_4"
has "domain sets" "$nft" "set pr_0_6"
has "domain rule" "$nft" "ip daddr @pr_0_4 ct state new update @pr_0_4 { ip daddr } ct mark set 0x0*201"
has "domain rule" "$nft" "ip6 daddr @pr_0_6 ct state new update @pr_0_6 { ip6 daddr } ct mark set 0x0*201"
# the router's dnsmasq with exactly the rendered nftset= lines, unprivileged like on the router (it must
# keep CAP_NET_ADMIN for the sets by itself)
grep '^nftset=' "$D/r/etc/dnsmasq.conf" > "$D/nftset.conf" || fail "dnsmasq.conf has no nftset= line"
: > "$D/dnsmasq.log" && chmod 666 "$D/dnsmasq.log"
inD dnsmasq --conf-file="$D/nftset.conf" --no-resolv --no-hosts --server=10.97.0.1 --listen-address=127.0.0.1 --bind-interfaces \
	--pid-file="$D/router-dns.pid" --user=nobody --group=nogroup --log-facility="$D/dnsmasq.log"
i=0
until [ "$(seen 192.0.2.81)" = 10.97.0.2 ]; do
	i=$((i + 1))
	[ "$i" -le 30 ] || fail "LAN client never reached the server via the default WAN: $(seen 192.0.2.81)"
	sleep 0.2
done
[ "$(seen 192.0.2.80)" = 10.97.0.2 ] || fail "before any DNS answer, 192.0.2.80 must use the default WAN: $(seen 192.0.2.80)"
for q in "video.example A" "video.example AAAA" "other.example A"; do
	# shellcheck disable=SC2086 # name and type
	inD mr dns query $q > /dev/null || fail "router dnsmasq: query $q: $(cat "$D/dnsmasq.log")"
done
s4=$(inD nft list set inet mr pr_0_4)
has "dnsmasq filled the IPv4 set" "$s4" "192.0.2.80"
hasnt "other names stay out" "$s4" "192.0.2.81"
has "dnsmasq filled the IPv6 set" "$(inD nft list set inet mr pr_0_6)" "2001:db8:80::1"
[ "$(seen 192.0.2.80)" = 10.96.0.2 ] || fail "connection to video.example did not leave via wan2: $(seen 192.0.2.80)"
[ "$(seen 192.0.2.81)" = 10.97.0.2 ] || fail "connection to other.example did not use the default WAN: $(seen 192.0.2.81)"
echo "ok: video.example -> wan2 (10.96.0.2), other.example -> wan (10.97.0.2)"

# a firewall reload replaces the table: the learned addresses must come back in the same load
inD mr fw
has "reload keeps learned addresses" "$(inD nft list set inet mr pr_0_4)" "192.0.2.80"
[ "$(seen 192.0.2.80)" = 10.96.0.2 ] || fail "after a reload video.example left via: $(seen 192.0.2.80)"
echo "ok: learned addresses carried over a firewall reload"

# a new connection to a learned address restarts its timer (with the set's timeout)
inD nft add element inet mr pr_0_4 '{ 192.0.2.82 timeout 100s }'
[ "$(seen 192.0.2.82)" = 10.96.0.2 ] || fail "learned 192.0.2.82 did not leave via wan2: $(seen 192.0.2.82)"
exp=$(inD nft -j list set inet mr pr_0_4 | python3 -c 'import json, sys
for s in json.load(sys.stdin)["nftables"]:
    for e in s.get("set", {}).get("elem", []):
        if isinstance(e, dict) and e["elem"].get("val") == "192.0.2.82": print(e["elem"].get("expires", 0))')
[ "${exp:-0}" -gt 3600 ] || fail "a new connection did not restart the address's timer (expires ${exp:-none})"
echo "ok: a new connection restarts the address's timer (expires in ${exp}s)"

# another domain list: the old addresses are not carried over (a removed domain must not stay on the WAN)
sed 's/domains: \[video.example\]/domains: [video.example, extra.example]/' "$D/router.yaml" > "$D/router-b.yaml"
inD "$MRH" -c "$D/router-b.yaml" -s "$T/secrets.yaml" fw
hasnt "changed list starts empty" "$(inD nft list set inet mr pr_0_4)" "192.0.2.80"
[ "$(seen 192.0.2.80)" = 10.97.0.2 ] || fail "changed list: 192.0.2.80 still left via: $(seen 192.0.2.80)"
echo "net: domain policy test ok"

step "PPPoE mtu 1500 (RFC 4638): link MTUs in the real kernel"
M4=$T/mtu4
mkdir -p "$M4"
cat > "$M4/router.yaml" << 'EOF'
system: {hostname: mtutest}
lan: {bridge: br-lan, ports: [lan2], ipv4: 192.168.1.6/24, ipv6_ra: true}
wan:
  - {name: wan, device: wan, proto: pppoe, username: "test@isp.example", password_secret: pppoe_password, mtu: 1500, metric: 10}
  - {name: tv, device: wan, vlan: 20, proto: dhcp, metric: 20}
firewall: {offload: software}
dhcp: {start: 100, end: 200, lease: 12h, domain: lan, ipv6: {mode: slaac, lease: 30m}}
EOF
echo 'pppoe_password: "x"' > "$M4/secrets.yaml"
"$MRH" -c "$M4/router.yaml" -s "$M4/secrets.yaml" render "$M4/r" > /dev/null
grep -q '^mtu 1500$' "$M4/r/etc/ppp/peers/wan" || fail "peer file does not ask for mtu 1500"
ip netns add "$RR"
ip -n "$RR" link add wan type dummy
ip -n "$RR" link set wan up
grep -E '^ip link set dev [a-z0-9.]+ mtu [0-9]+$|type vlan id' "$M4/r/etc/mini-router/gen/network.sh" > "$M4/links.sh"
ip netns exec "$RR" sh -e "$M4/links.sh"
[ "$(ip netns exec "$RR" cat /sys/class/net/wan/mtu)" = 1508 ] || fail "wan MTU $(ip netns exec "$RR" cat /sys/class/net/wan/mtu), want 1508"
[ "$(ip netns exec "$RR" cat /sys/class/net/wan.20/mtu)" = 1500 ] || fail "wan.20 MTU $(ip netns exec "$RR" cat /sys/class/net/wan.20/mtu), want 1500"
echo "net: PPPoE port 1508, DHCP VLAN 1500"

step "IPv6 renumbering after a reboot (RFC 9096): real mr hook + real dnsmasq + a client's RA"
ip netns add "$RC"
for n in "$RR" "$RC"; do # link-local addresses usable at once (no DAD wait)
	ip netns exec "$n" sysctl -qw net.ipv6.conf.all.accept_dad=0 net.ipv6.conf.default.accept_dad=0
done
ip -n "$RR" link add br-lan type bridge
ip -n "$RR" link add vr type veth peer name vc netns "$RC"
ip -n "$RR" link set vr master br-lan
for l in br-lan vr; do ip -n "$RR" link set "$l" up; done
ip -n "$RC" link set vc up
ip -n "$RR" -6 addr add 2001:db8:2::1/64 dev br-lan noprefixroute nodad
mkdir -p /etc/mini-router/state
printf '{"boot":"an-earlier-boot","addrs":{"br-lan":["2001:db8:1::1/64","2001:db8:2::1/64"]}}' > /etc/mini-router/state/lan6-prefixes.json
ip netns exec "$RR" env interface=br-lan reason=DELEGATED6 "$MRH" -c "$M4/router.yaml" -s "$M4/secrets.yaml" hook dhcpcd || true
ip -n "$RR" -6 addr show dev br-lan | grep -q '2001:db8:1::1/64' || fail "the hook did not put the stale prefix back: $(ip -n "$RR" -6 addr show dev br-lan)"
if grep -q 'an-earlier-boot' /etc/mini-router/state/lan6-prefixes.json; then
	fail "record not rewritten for this boot: $(cat /etc/mini-router/state/lan6-prefixes.json)"
fi
cat > "$T/ra-dnsmasq.conf" << EOF
port=0
interface=br-lan
enable-ra
dhcp-range=::,constructor:br-lan,ra-only,30m
ra-param=br-lan,4,1800
pid-file=$T/ra-dnsmasq.pid
EOF
ip netns exec "$RR" dnsmasq -u root -C "$T/ra-dnsmasq.conf" --log-facility="$T/ra-dnsmasq.log"
cat > "$T/ra.py" << 'PY'
import socket, struct, sys, time
s = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
s.settimeout(1)
s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 255)
idx = socket.if_nametoindex("vc")
seen, deadline = {}, time.time() + 40
while time.time() < deadline:
    try:
        s.sendto(struct.pack("!BBHI", 133, 0, 0, 0), ("ff02::2", 0, 0, idx))
    except OSError:
        time.sleep(0.5)  # the link-local address is not there yet
        continue
    end = time.time() + 2
    while time.time() < end:
        try:
            b = s.recv(2048)
        except socket.timeout:
            continue
        if not b or b[0] != 134:
            continue
        i = 16
        while i + 2 <= len(b) and b[i + 1]:
            t, l = b[i], b[i + 1] * 8
            if t == 3 and l >= 32:
                valid, pref = struct.unpack("!II", b[i + 4:i + 12])
                seen[socket.inet_ntop(socket.AF_INET6, b[i + 16:i + 32])] = (valid, pref)
            i += l
    old, cur = seen.get("2001:db8:1::"), seen.get("2001:db8:2::")
    if old and cur and old[1] == 0 and old[0] > 0 and cur[1] > 0:
        print("old prefix valid %d preferred %d; current preferred %d" % (old[0], old[1], cur[1]))
        sys.exit(0)
print("RA prefixes seen: %r" % seen)
sys.exit(1)
PY
ip netns exec "$RC" python3 "$T/ra.py" || fail "the client never saw the stale prefix deprecated (dnsmasq log: $(tail -5 "$T/ra-dnsmasq.log"))"
echo "net: renumbering test ok"
