#!/bin/sh
# mini-router checks. Runs on the build host (never on the Mac):
#   sh tools/ci.sh
# Called automatically by .githooks/pre-push. Several copies may run at once (one per worktree):
# everything runs in a private mount namespace with tmpfs over /etc/mini-router and /etc/lucky,
# and netns names are per-process, so runs never see each other.
set -eu
if [ -z "${MR_CI_NS:-}" ]; then
	mkdir -p /etc/mini-router /etc/lucky
	MR_CI_NS=1 exec unshare -m --propagation private sh "$0" "$@"
fi
mount -t tmpfs tmpfs /etc/mini-router
mount -t tmpfs tmpfs /etc/lucky

[ ! -f /etc/profile.d/buildtools.sh ] || . /etc/profile.d/buildtools.sh # dash: a failing `.` exits the shell
cd "$(dirname "$0")/.."
ROOT=$(pwd)
OUT=$ROOT/out/ci
rm -rf "$OUT" && mkdir -p "$OUT"
step() { printf '\n== %s\n' "$*"; }

for tool in shellcheck nft dnsmasq; do
	command -v "$tool" >/dev/null || { step "install $tool"; apt-get install -y -qq shellcheck nftables dnsmasq-base >/dev/null; break; }
done

step "gofmt"
cd "$ROOT/mr"
bad=$(gofmt -l .)
[ -z "$bad" ] || { echo "not gofmt'ed: $bad"; gofmt -d . | head -80; exit 1; }

step "go vet"
go vet ./...

step "go test"
go test -count=1 ./...

step "build linux/arm64"
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo dev)" -o "$ROOT/out/mr" .
ls -la "$ROOT/out/mr"
go build -o "$OUT/mr-host" .
cd "$ROOT"

step "init cost of mr (every CGI request and hook pays it)"
b=$(GODEBUG=inittrace=1 "$OUT/mr-host" version 2>&1 | sed -n 's/^init main .* clock, \([0-9]*\) bytes.*/\1/p')
if [ -z "$b" ] || [ "$b" -ge 262144 ]; then
	echo "FAIL: init of package main allocates ${b:-?} bytes (budget 256 KiB) — a package-level regexp.MustCompile? use lazyRegexp"
	exit 1
fi
echo "ok: init main allocates $b bytes"

step "shellcheck"
files=$(grep -rlE '^#!/(bin/sh|sbin/openrc-run)' rootfs build tools)
# openrc-run scripts are POSIX sh with openrc-provided variables/functions
# shellcheck disable=SC2086
shellcheck -s sh -S warning -e SC2034,SC2154,SC3043 $files rootfs/etc/dhcpcd.exit-hook

step "web UI script syntax"
if command -v node >/dev/null; then
	for f in rootfs/www/ui/*.js; do node --check "$f"; done
	echo "ok: $(ls rootfs/www/ui/*.js | wc -l) files"
else
	echo "node not found; skipped"
fi

# check_config NAME YAML SECRETS: validate, render, then load the result into the real tools.
check_config() {
	name=$1 yaml=$2 sec=$3
	R=$OUT/$name
	step "[$name] validate + render"
	"$OUT/mr-host" -c "$yaml" -s "$sec" validate
	"$OUT/mr-host" -c "$yaml" -s "$sec" render "$R"

	step "[$name] generated shell scripts"
	shellcheck -s sh -S error "$R"/etc/mini-router/gen/*.sh

	step "[$name] nft -c + load (real nftables, netns with dummy copies of every flowtable device)"
	NS=mrci$$$name
	ip netns add "$NS"
	# shellcheck disable=SC2064
	trap "ip netns del $NS 2>/dev/null" EXIT
	devs=$(sed -n 's/^[[:space:]]*devices = { \(.*\) }/\1/p' "$R/etc/mini-router/gen/nftables.nft" | tr -d '",' )
	for d in $devs br-lan; do
		ip -n "$NS" link add "$d" type dummy 2>/dev/null || true
		ip -n "$NS" link set "$d" up
	done
	# dummy netdevs cannot do hardware offload; everything else is checked by the real kernel
	sed '/flags offload/d' "$R/etc/mini-router/gen/nftables.nft" > "$OUT/$name-nft.nft"
	ip netns exec "$NS" nft -c -f "$OUT/$name-nft.nft"
	ip netns exec "$NS" nft -f "$OUT/$name-nft.nft"
	ip netns exec "$NS" nft list table inet mr > /dev/null
	ip netns del "$NS"
	trap - EXIT

	step "[$name] dnsmasq --test (real dnsmasq)"
	mkdir -p /etc/mini-router/gen
	cp -r "$R/etc/mini-router/gen/." /etc/mini-router/gen/
	for f in $(sed -n 's/^\(addn-hosts\|servers-file\|conf-file\)=//p' "$R/etc/dnsmasq.conf"); do
		[ -e "$f" ] || { mkdir -p "$(dirname "$f")"; : > "$f"; }
	done
	dnsmasq --test --conf-file="$R/etc/dnsmasq.conf"

	step "[$name] hostapd / pppd essentials"
	for f in "$R"/etc/hostapd/hostapd-phy*.conf; do
		[ -e "$f" ] || continue
		for k in driver=nl80211 interface= ssid2= hw_mode= channel= ieee80211ax=1; do
			grep -q "^$k" "$f" || { echo "$f: missing $k"; exit 1; }
		done
		if grep -n "$(printf '\r')" "$f"; then echo "$f: CR in config"; exit 1; fi
	done
	for f in "$R"/etc/ppp/peers/*; do
		[ -e "$f" ] || continue
		grep -q '^plugin pppoe.so' "$f"
	done
}

# 1) the real home config (examples/router.yaml)
mkdir -p /etc/mini-router/dns
cp mr/testdata/split.domains /etc/mini-router/dns/cloudflare-dot.domains
check_config home examples/router.yaml mr/testdata/secrets.yaml
grep -q '^vht_oper_centr_freq_seg0_idx=50$' "$OUT/home/etc/hostapd/hostapd-phy1.conf"

# 2) the lab config: every feature switched on, one fragment per module (examples/lab.d/*.yaml,
#    secrets in mr/testdata/secrets.d/*.yaml). @REPO@ in fragments is replaced by the checkout path.
sed "s#@REPO@#$ROOT#g" examples/lab.d/*.yaml > "$OUT/lab.yaml"
cat mr/testdata/secrets.yaml mr/testdata/secrets.d/*.yaml > "$OUT/lab-secrets.yaml" 2>/dev/null || cp mr/testdata/secrets.yaml "$OUT/lab-secrets.yaml"
check_config lab "$OUT/lab.yaml" "$OUT/lab-secrets.yaml"

# 3) module-specific checks: tools/ci.d/<module>.sh, run with OUT and the rendered trees
#    $OUT/home and $OUT/lab (e.g. `sing-box check`, hostapd key whitelist).
for f in tools/ci.d/*.sh; do
	[ -e "$f" ] || continue
	step "module check $f"
	OUT=$OUT ROOT=$ROOT sh "$f"
done

# 4) web UI login throttle across processes: every request is its own CGI process (mr api)
step "web UI login throttle: 20 wrong passwords at once, 20 CGI processes"
mkdir -p /run/mini-router && mount -t tmpfs tmpfs /run/mini-router # private mount namespace
printf 'correct horse\n' | "$OUT/mr-host" -s /etc/mini-router/secrets.yaml passwd > /dev/null
body='{"password":"wrong guess"}'
i=0
while [ $i -lt 20 ]; do
	i=$((i + 1))
	printf '%s' "$body" | REQUEST_METHOD=POST QUERY_STRING=a=login REMOTE_ADDR=192.0.2.9 HTTP_X_MR=1 \
		CONTENT_LENGTH=${#body} "$OUT/mr-host" api > "$OUT/login.$i" &
done
wait
n401=$(grep -l '^Status: 401' "$OUT"/login.* | wc -l)
n429=$(grep -l '^Status: 429' "$OUT"/login.* | wc -l)
[ "$n401" = 5 ] && [ "$n429" = 15 ] || { echo "FAIL: $n401 x 401, $n429 x 429 (want 5 and 15)"; exit 1; }
body='{"password":"correct horse"}'
printf '%s' "$body" | REQUEST_METHOD=POST QUERY_STRING=a=login REMOTE_ADDR=192.0.2.8 HTTP_X_MR=1 \
	CONTENT_LENGTH=${#body} "$OUT/mr-host" api > "$OUT/login.other"
grep -q '^Set-Cookie: mrsid=' "$OUT/login.other" || { echo "FAIL: another address could not log in"; exit 1; }
rm -f /etc/mini-router/secrets.yaml && umount /run/mini-router
echo "ok: 5 checked, 15 refused (429) without a check; another address logs in"

printf '\nALL CHECKS PASSED\n'
