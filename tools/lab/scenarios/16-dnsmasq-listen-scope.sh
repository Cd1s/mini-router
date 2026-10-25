#!/bin/sh
# dnsmasq (the main one, mr-proxy-dns, mr-parental-dns) listens on the LAN bridges and 127.0.0.1 / ::1 only.
# ss-nodes keeps hundreds of /128 source addresses on lo (twice as many while the ISP's prefix changes); dnsmasq used to
# open a UDP + TCP listener on each of them, ran out of its 1024 descriptors and answered nothing, so `mr proxy check`
# failed and the migration that would have dropped the old addresses never finished. Here 1000 such addresses go on the
# router's lo (under running dnsmasq, then under freshly restarted ones) and come off again: the descriptor count must not
# move, and DNS (IPv4, IPv6, redirect), DHCP, the proxy's fake-ip DNS, parental control and rebind protection must work
# for a parental device, a proxied device and a bypass device the whole time.
# Needs a static sing-box 1.14 with the clash API (the router's minimal build): LAB_SING_BOX=/path/to/sing-box.
NAME=16-dnsmasq-listen-scope
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

SB=${LAB_SING_BOX:-/root/build/sbmin/amd64/sing-box}
[ -x "$SB" ] || {
	printf 'Bail out! %s: a static sing-box with_clash_api is required (LAB_SING_BOX=...)\n' "$SB"
	exit 1
}
isp_ns=mrlab$ID-isp1
CA=mrlab$ID-lan CB=mrlab$ID-b CC=mrlab$ID-c
MAC_B=02:00:00:$(printf '%02x' "$ID"):00:0b MAC_C=02:00:00:$(printf '%02x' "$ID"):00:0c
SRV_PID=
SB_DIR=
cleanup_extra() {
	[ -z "$SRV_PID" ] || kill "$SRV_PID" 2> /dev/null || true
	[ -z "$SB_DIR" ] || rm -rf "$SB_DIR"
	[ "${MRLAB_KEEP:-0}" = 1 ] || for ns in "$CB" "$CC"; do ip netns del "$ns" 2> /dev/null || true; done
}
trap 'cleanup_extra; cleanup' EXIT

step lab reset "$ID"
step lab isp "$ID" 1 pppoe v6=pd \
	--address ok.test=1.1.1.99 --address proxied.test=1.1.1.88 --address rebind.test=192.168.77.7
check "install.sh completes (PPPoE + DHCPv6-PD)" lab install "$ID" --wan-proto pppoe

# the router-grade sing-box (static, clash API) from the ISP namespace, as scenario 11 does
SB_DIR=$(mktemp -d "/tmp/mrlab$ID-sb.XXXXXX")
ln -s "$SB" "$SB_DIR/sing-box"
ip netns exec "$isp_ns" python3 -m http.server "$((18000 + ID))" --bind 203.0.113.1 --directory "$SB_DIR" > "/tmp/mrlab$ID-sb-http.log" 2>&1 &
SRV_PID=$!
sleep 1
step lab console "$ID" "wget -q -O /tmp/sing-box http://203.0.113.1:$((18000 + ID))/sing-box && install -m 0755 /tmp/sing-box /usr/bin/sing-box && rm /tmp/sing-box && sing-box version"
kill "$SRV_PID" 2> /dev/null || true
SRV_PID=

step lab lan "$ID" dhcp
MAC_A=$(lab lan "$ID" exec "cat /sys/class/net/$LAN_DEV/address" | tail -n 1)
R6=$(lab console "$ID" "ip -6 -o addr show dev br-lan scope global | awk 'NR==1{print \$4}' | cut -d/ -f1" | tail -n 1)
PFX=2001:db8:$ID:100
note "parental client $MAC_A, bypass client $MAC_B, proxied client $MAC_C; router IPv6 $R6"
[ -n "$R6" ] || { printf 'Bail out! the router has no global IPv6 address on br-lan\n'; exit 1; }

# two more LAN clients on the same switch port (own MACs): the bypass device (main dnsmasq answers it) and a plain
# proxied one (mr-proxy-dns); the lab's own client is the parental device (mr-parental-dns -> mr-proxy-dns -> main)
mkclient() { # <netns> <iface> <mac> <ipv4 host part>
	step ip netns add "$1"
	step ip -n "$CA" link add "$2" link "$LAN_DEV" address "$3" type macvlan mode bridge
	step ip -n "$CA" link set "$2" netns "$1"
	step ip -n "$1" link set lo up
	step ip -n "$1" link set "$2" up
	step ip -n "$1" addr add "192.168.1.$4/24" dev "$2"
	step ip -n "$1" route add default via 192.168.1.1
}
mkclient "$CB" mvb "$MAC_B" 202
mkclient "$CC" mvc "$MAC_C" 203

step lab console "$ID" "printf 'proxy_lab: AAECAwQFBgcICQoLDA0ODw==\n' >> /etc/mini-router/secrets.yaml"
PATCH='[{"op":"set","path":"dns.redirect","value":true},
 {"op":"set","path":"devices","value":[{"name":"kid","macs":["'$MAC_A'"]},{"name":"direct","macs":["'$MAC_B'"]}]},
 {"op":"set","path":"dns.parental","value":{"devices":["kid"],"safe_search":true,"block":["blocked.test"]}},
 {"op":"set","path":"proxy","value":{"enabled":true,
   "nodes":[{"name":"lab1","server":"203.0.113.7","port":8388,"method":"2022-blake3-aes-128-gcm","password_secret":"proxy_lab"}],
   "rules":[{"name":"lab","outbound":"lab1","domains":["proxied.test"]}],
   "bypass":[{"name":"direct","device":"direct"}]}}]'
check "dns.redirect + proxy + parental control applied" lab change "$ID" "$PATCH"
for ns in "$CB" "$CC"; do
	check "$ns gets an IPv6 address from the delegated prefix" retry 40 ip netns exec "$ns" sh -c "ip -6 addr show scope global -tentative | grep -q 'inet6 $PFX:'"
done

# ---- helpers
# is <netns> <server> <name> <regexp>: dig prints an answer matching it
is() { ip netns exec "$1" dig +short +time=3 +tries=1 @"$2" "$3" A 2> /dev/null | grep -Eq "$4"; }
# not_is <netns> <server> <name> <regexp>: the lookup came back, but without an answer matching it
not_is() {
	_o=$(ip netns exec "$1" dig +time=3 +tries=1 @"$2" "$3" A 2> /dev/null) || return 1
	printf '%s\n' "$_o" | grep -q 'status:' && ! printf '%s\n' "$_o" | grep -Eq "^$3\.[[:space:]].*[[:space:]]A[[:space:]]+$4"
}
nxdomain() { ip netns exec "$1" dig +time=3 +tries=1 @"$2" "$3" A 2> /dev/null | grep -q 'status: NXDOMAIN'; }
# descriptors of every dnsmasq on the router: "main 19" / "proxy 17" / "parental 18"
FDS='for p in $(pgrep dnsmasq); do c=$(tr "\0" " " < /proc/$p/cmdline); case $c in *proxy-dns*) r=proxy;; *parental*) r=parental;; *) r=main;; esac; echo "$r $(ls /proc/$p/fd | wc -l)"; done'
fds_note() { note "$1: dnsmasq descriptors: $(lab console "$ID" "$FDS" | grep -E '^(main|proxy|parental) [0-9]+$' | tr '\n' ' ')"; }
fds_low() { lab console "$ID" "$FDS | awk '{n++; if (\$2 >= 100) bad=1} END {exit !(n == 3 && !bad)}'"; }

suite() { # <label>
	l=$1
	fds_note "$l"
	check "$l: dnsmasq x3 hold fewer than 100 descriptors each" fds_low
	check "$l: no listener on the extra lo addresses" lab console "$ID" "! ss -lnH | grep -q '$PFX::c[0-9a-f]*\]'"
	check "$l: parental client: IPv4 DNS" retry 15 is "$CA" 192.168.1.1 ok.test '^1\.1\.1\.99$'
	check "$l: parental client: IPv6 DNS to the router's global address" retry 15 is "$CA" "$R6" ok.test '^1\.1\.1\.99$'
	check "$l: parental client: blocked domain is NXDOMAIN" nxdomain "$CA" 192.168.1.1 blocked.test
	check "$l: parental client: safe-search address" is "$CA" 192.168.1.1 www.google.com '^216\.239\.38\.120$'
	check "$l: parental client: proxied domain is a fake IP (parental -> proxy-dns -> sing-box)" is "$CA" 192.168.1.1 proxied.test '^198\.1[89]\.'
	check "$l: parental client: DNS sent to 9.9.9.9 is redirected to the parental dnsmasq" is "$CA" 9.9.9.9 ok.test '^1\.1\.1\.99$'
	check "$l: proxied client: IPv4 DNS" retry 15 is "$CC" 192.168.1.1 ok.test '^1\.1\.1\.99$'
	check "$l: proxied client: IPv6 DNS" retry 15 is "$CC" "$R6" ok.test '^1\.1\.1\.99$'
	check "$l: proxied client: proxied domain is a fake IP" is "$CC" 192.168.1.1 proxied.test '^198\.1[89]\.'
	check "$l: proxied client: DNS sent to 9.9.9.9 is redirected to mr-proxy-dns" is "$CC" 9.9.9.9 proxied.test '^198\.1[89]\.'
	check "$l: proxied client: rebind protection drops a private answer" not_is "$CC" 192.168.1.1 rebind.test '192\.168\.77\.7'
	check "$l: bypass client: IPv4 DNS" retry 15 is "$CB" 192.168.1.1 ok.test '^1\.1\.1\.99$'
	check "$l: bypass client: IPv6 DNS" retry 15 is "$CB" "$R6" ok.test '^1\.1\.1\.99$'
	check "$l: bypass client: the real answer for the proxied domain" is "$CB" 192.168.1.1 proxied.test '^1\.1\.1\.88$'
	check "$l: bypass client: DNS sent to 9.9.9.9 is redirected to the main dnsmasq" is "$CB" 9.9.9.9 proxied.test '^1\.1\.1\.88$'
	check "$l: bypass client: rebind protection drops a private answer" not_is "$CB" 192.168.1.1 rebind.test '192\.168\.77\.7'
	check "$l: the router resolves through /etc/resolv.conf (127.0.0.1)" lab console "$ID" 'nslookup ok.test 2>&1 | grep -q "Address: 1.1.1.99"'
	check "$l: main dnsmasq answers on ::1 too" lab console "$ID" 'nslookup ok.test ::1 2>&1 | grep -q "Address: 1.1.1.99"'
	check "$l: mr-proxy-dns answers on 127.0.0.1:1054" lab console "$ID" 'nslookup -port=1054 ok.test 127.0.0.1 2>&1 | grep -q "Address: 1.1.1.99"'
	check "$l: mr-parental-dns answers on 127.0.0.1:5356" lab console "$ID" 'nslookup -port=5356 ok.test 127.0.0.1 2>&1 | grep -q "Address: 1.1.1.99"'
	check "$l: mr proxy check passes" lab console "$ID" 'mr proxy check'
	check "$l: DHCP still answers" lab lan "$ID" dhcp
}

suite "baseline"

# ---- 1000 /128 addresses in the delegated prefix on lo, under the dnsmasq processes that are already running
ADD="seq 1 1000 | awk '{printf \"addr add $PFX::%x/128 dev lo nodad\\n\", 49152 + \$1}' | ip -6 -batch -"
DEL="seq 1 1000 | awk '{printf \"addr del $PFX::%x/128 dev lo\\n\", 49152 + \$1}' | ip -6 -batch -"
step lab console "$ID" "$ADD"
check "1000 extra addresses are on lo" lab console "$ID" '[ "$(ip -6 -o addr show dev lo scope global | wc -l)" -eq 1000 ]'
sleep 3
suite "1000 on lo, dnsmasq running"

# ---- and under freshly started ones: this is where the listeners used to fail ("No file descriptors available")
step lab console "$ID" 'rc-service dnsmasq restart && rc-service mr-proxy-dns restart && rc-service mr-parental-dns restart'
sleep 3
suite "1000 on lo, dnsmasq restarted"

# bind-dynamic still follows the LAN bridge: an address added to br-lan later is served (a new delegated prefix)
step lab console "$ID" "ip -6 addr add $PFX::99/64 dev br-lan nodad"
check "a br-lan address added later is listened on" retry 10 is "$CB" "$PFX::99" ok.test '^1\.1\.1\.99$'
step lab console "$ID" "ip -6 addr del $PFX::99/64 dev br-lan"

# ---- the addresses go away again (the migration finishes): nothing changes
step lab console "$ID" "$DEL"
check "lo has no global address left" lab console "$ID" '[ "$(ip -6 -o addr show dev lo scope global | wc -l)" -eq 0 ]'
sleep 3
suite "1000 removed"
finish
