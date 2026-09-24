#!/bin/sh
# dns module checks. Run by tools/ci.sh inside its private mount namespace, with OUT and ROOT set
# and the lab gen files already copied to /etc/mini-router/gen.
#  1. every rendered stubby.yml listens on 127.0.0.1 only
#  2. the rendered lab dnsmasq.conf runs for real in a throwaway network + mount namespace:
#     the lab's local records answer (`mr dns query`), the CHAOS statistics answer (`mr dns stats`),
#     and `mr dns release` makes dnsmasq drop a lease (DHCPRELEASE, lease file never edited).
set -eu
: "${OUT:?}" "${ROOT:?}"

for t in home lab; do
	f=$OUT/$t/etc/stubby/stubby.yml
	[ -e "$f" ] || continue
	n=$(sed -n '/^listen_addresses:/,/^[a-z]/p' "$f" | grep -c '^  - ' || true)
	if [ "$n" != 1 ] || ! grep -q '^  - 127\.0\.0\.1@[0-9][0-9]*$' "$f"; then
		echo "$f: stubby must listen on exactly one 127.0.0.1 address"
		exit 1
	fi
	echo "ok: $t stubby.yml listens on loopback only"
done

conf=$OUT/lab/etc/dnsmasq.conf
# main LAN = first interface= line; its router address, pool start and netmask from the tagged pool
br=$(sed -n 's/^interface=//p' "$conf" | head -1)
rip=$(sed -n 's/^dhcp-option=tag:lan,option:router,//p' "$conf")
pool=$(sed -n 's/^dhcp-range=set:lan,//p' "$conf")
start=${pool%%,*}
plen=$(echo "$pool" | cut -d, -f3 | awk -F. '{n=0; for(i=1;i<=4;i++){x=$i; while(x>0){n+=x%2; x=int(x/2)}} print n}')
[ -n "$br" ] && [ -n "$rip" ] && [ -n "$start" ] && [ -n "$plen" ] || { echo "cannot find the lan pool in $conf"; exit 1; }

unshare -m -n sh -eu -s "$OUT/mr-host" "$OUT/lab.yaml" "$OUT/lab-secrets.yaml" "$conf" "$br" "$rip/$plen" "$start" <<'EOF'
MR=$1 CFG=$2 SEC=$3 CONF=$4 BR=$5 ADDR=$6 LEASEIP=$7
mr() { "$MR" -c "$CFG" -s "$SEC" "$@"; }
mount -t tmpfs tmpfs /tmp
ip link set lo up
for d in $(sed -n 's/^interface=//p' "$CONF"); do
	ip link add "$d" type dummy
	ip link set "$d" up
done
ip addr add "$ADDR" dev "$BR"
echo "$(($(date +%s) + 3600)) 02:00:5e:00:00:01 $LEASEIP ci-host 01:02:00:5e:00:00:01" > /tmp/dhcp.leases
dnsmasq --conf-file="$CONF" --keep-in-foreground --pid-file= --user=root --group=root --log-facility=/tmp/dnsmasq.log &
pid=$!
trap 'kill $pid 2>/dev/null || true' EXIT
fail() { echo "FAIL: $*"; echo "--- dnsmasq log"; cat /tmp/dnsmasq.log; exit 1; }
i=0
until mr dns query localhost A >/dev/null 2>&1; do
	i=$((i + 1))
	[ "$i" -lt 50 ] || fail "dnsmasq never answered"
	sleep 0.1
done
check() {
	out=$(mr dns query "$1" "$2") || fail "query $1 $2"
	echo "$out" | grep -qF "$3" || fail "$1 $2: want $3, got: $out"
	echo "ok: $1 $2 -> $3"
}
check nas A 192.168.1.10
check nas.lan A 192.168.1.10
check nas.lan AAAA fd00::10
check anything.home.example.com A 192.168.1.6
check home.example.com A 192.168.1.6
check photos.lan A 192.168.1.10
check 192.168.1.11 PTR printer.lan
check _smb._tcp.lan SRV "0 0 445 nas.lan"
check nas.lan TXT "home server; v=1"
mr dns stats | grep -q '"cache_size": 8000' || fail "mr dns stats: $(mr dns stats 2>&1)"
echo "ok: mr dns stats"
grep -q " $LEASEIP " /tmp/dhcp.leases || fail "test lease not loaded"
mr dns release "$LEASEIP" 02:00:5e:00:00:01 || fail "mr dns release"
if grep -q " $LEASEIP " /tmp/dhcp.leases; then fail "lease still present"; fi
echo "ok: mr dns release dropped the lease"
EOF
