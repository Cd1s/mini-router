#!/bin/sh
# net module CI checks, run by tools/ci.sh (as root, inside its private mount namespace) with
# OUT (rendered trees in $OUT/home, $OUT/lab; host build of mr in $OUT/mr-host) and ROOT.
#  1. generated service instances + health-checker config (shellcheck, expected content)
#  2. functional test in two network namespaces with the real tools: busybox udhcpc + the mr hook
#     against a dnsmasq DHCP server, a static WAN via `mr routes`, and the busybox sh health checker
#     taking a WAN down and up again (routes, rules, balance map in the loaded nft ruleset, DNS).
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
cleanup() {
	[ -f "$T/dnsmasq.pid" ] && kill "$(cat "$T/dnsmasq.pid")" 2> /dev/null
	ip netns del "$S" 2> /dev/null
	ip netns del "$C" 2> /dev/null
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
