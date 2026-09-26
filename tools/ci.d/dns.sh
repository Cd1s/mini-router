#!/bin/sh
# dns module checks. Run by tools/ci.sh inside its private mount namespace, with OUT and ROOT set
# and the lab gen files already copied to /etc/mini-router/gen.
#  1. every rendered stubby.yml listens on 127.0.0.1 only
#  2. the rendered lab dnsmasq.conf runs for real in a throwaway network + mount namespace:
#     the lab's local records answer (`mr dns query`), the CHAOS statistics answer (`mr dns stats`),
#     and `mr dns release` makes dnsmasq drop a lease (DHCPRELEASE, lease file never edited);
#     the Firefox canary and (lab) iCloud Private Relay names answer NXDOMAIN from the router itself;
#     ad blocking: `mr dns adblock update` fetches the lab's lists from a local HTTPS server (plain and
#     hosts format, 150k names) and the real dnsmasq answers them NXDOMAIN, an allowed name under a
#     blocked one is forwarded; dnsmasq's RSS and start time with the list are printed.
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

# dns.parental (lab): its dnsmasq config passes --test, the redirect is in the ruleset; nothing for home
p=$OUT/lab/etc/mini-router/gen/parental-dns.conf
dnsmasq --test --conf-file="$p"
grep -qx 'local=/games.example/' "$p" && grep -qx 'address=/www.google.com/216.239.38.120' "$p" || { echo "$p: block list / safe search missing"; exit 1; }
grep -q 'redirect to :5356 comment "parental-dns"' "$OUT/lab/etc/mini-router/gen/nftables.nft" || { echo "lab ruleset lacks the parental redirect"; exit 1; }
[ ! -e "$OUT/home/etc/mini-router/gen/parental-dns.conf" ] || { echo "home rendered parental-dns.conf"; exit 1; }
echo "ok: parental-dns.conf"

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
# the lab's ad blocking lists over HTTPS (a throwaway CA the mr client trusts through SSL_CERT_FILE)
mkdir -p /tmp/lists
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 -subj /CN=127.0.0.1 \
	-addext subjectAltName=IP:127.0.0.1 -keyout /tmp/lists.key -out /tmp/lists.crt 2>/dev/null
{
	echo "# a plain domain list"
	echo "ads.example"
	echo "track.ads.example"
	echo "*.wild.example"
	echo "example.com##.banner"
	seq 1 150000 | awk '{printf "ad%d.bulk%d.example\n", $1, $1 % 997}'
} > /tmp/lists/ads.txt
printf '127.0.0.1 localhost\n::1 ip6-localhost\n0.0.0.0 hosts-ad.example # tracker\n0.0.0.0 a.example b.example\n0.0.0.0 c.example\n' > /tmp/lists/hosts.txt
python3 - /tmp/lists <<'PY' > /dev/null 2>&1 &
import functools, http.server, ssl, sys
h = functools.partial(http.server.SimpleHTTPRequestHandler, directory=sys.argv[1])
s = http.server.ThreadingHTTPServer(("127.0.0.1", 8453), h)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain("/tmp/lists.crt", "/tmp/lists.key")
s.socket = ctx.wrap_socket(s.socket, server_side=True)
s.serve_forever()
PY
lpid=$!
i=0
until out=$(SSL_CERT_FILE=/tmp/lists.crt mr dns adblock update --no-reload 2>&1); do
	i=$((i + 1))
	[ "$i" -lt 20 ] || { echo "FAIL: mr dns adblock update: $out"; exit 1; }
	sleep 0.2
done
kill $lpid
echo "$out" | grep -q '^150006 domains blocked$' || { echo "FAIL: adblock update: $out (150000 bulk + ads.example + wild.example + 4 from hosts)"; exit 1; }
grep -q '^server=/cdn.ads.example/#$' /etc/mini-router/state/adblock.conf || { echo "FAIL: allowed name not forwarded"; exit 1; }
if grep -q 'track.ads.example\|localhost\|example.com' /etc/mini-router/state/adblock.conf; then echo "FAIL: adblock file keeps a subdomain / localhost / an element-hiding rule"; exit 1; fi
echo "ok: $out"
t0=$(date +%s%N)
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
echo "adblock: dnsmasq answered $((($(date +%s%N) - t0) / 1000000)) ms after start; $(grep VmRSS /proc/$pid/status | tr -s ' \t' ' ') with 150006 blocked names"
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
for n in use-application-dns.net mask.icloud.com mask-h2.icloud.com; do
	# no upstream in this namespace: NXDOMAIN can only come from dnsmasq's own local= answer
	out=$(mr dns query "$n" A 2>&1) || true
	echo "$out" | grep -q 'NXDOMAIN, 0 answers' || fail "$n: want NXDOMAIN, got: $out"
	echo "ok: $n -> NXDOMAIN"
done
for n in ads.example x.track.ads.example ad777.bulk777.example deep.wild.example hosts-ad.example b.example; do
	out=$(mr dns query "$n" A 2>&1) || true
	echo "$out" | grep -q 'NXDOMAIN, 0 answers' || fail "blocked $n: want NXDOMAIN, got: $out"
done
for n in cdn.ads.example img.cdn.ads.example notlisted.example; do
	out=$(mr dns query "$n" A 2>&1) || true
	if echo "$out" | grep -q NXDOMAIN; then fail "$n is not blocked but answers NXDOMAIN"; fi
done
echo "ok: adblock: listed names and their subdomains NXDOMAIN; allowed and unlisted names forwarded"
mr dns stats | grep -q '"cache_size": 8000' || fail "mr dns stats: $(mr dns stats 2>&1)"
echo "ok: mr dns stats"
grep -q " $LEASEIP " /tmp/dhcp.leases || fail "test lease not loaded"
mr dns release "$LEASEIP" 02:00:5e:00:00:01 || fail "mr dns release"
if grep -q " $LEASEIP " /tmp/dhcp.leases; then fail "lease still present"; fi
echo "ok: mr dns release dropped the lease"
EOF
