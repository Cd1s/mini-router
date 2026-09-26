#!/bin/sh
# wifi module CI checks. Run by tools/ci.sh (with OUT = rendered trees $OUT/home and $OUT/lab, ROOT = checkout).
#   sh tools/ci.d/wifi.sh --keys   prints the key list generated from the hostapd 2.11 source, i.e. the body
#                                  of mr/testdata/hostapd-2.11.keys (to refresh it)
#
# 1. every key of every rendered hostapd config is one upstream hostapd 2.11 accepts: the vendored list
#    mr/testdata/hostapd-2.11.keys = hostapd_config_fill() in hostapd/config_file.c, limited to the build
#    options Alpine's package enables, plus noscan/ht_coex from build/hostapd/300-noscan.patch
# 2. the vendored list is exactly what the 2.11 release says (tarball fetched once, sha256-pinned, cached;
#    skipped with a notice when the host is offline)
# 3. the real hostapd 2.11 parses every rendered config (our noscan build when this host has it, else
#    Alpine's package; arm64 under qemu in docker): unknown keys, bad values and hostapd's own consistency
#    checks fail here. Driver init then fails on purpose — a container has no radio.
# 1b (between 1 and 2). tuning (#41): home renders none of it; lab keys per BSS, the cron tick, and
#    `mr wifi tick / health / steer --dry-run` against the lab config with no hostapd running
set -eu
ROOT=${ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}
OUT=${OUT:-$ROOT/out/ci}
KEYS=$ROOT/mr/testdata/hostapd-2.11.keys
PATCH=$ROOT/build/hostapd/300-noscan.patch
URL=https://w1.fi/releases/hostapd-2.11.tar.gz
SHA256=2b3facb632fd4f65e32f4bf82a76b4b72c501f995a4f62e330219fe7aed1747a
CACHE=${MR_CI_CACHE:-${HOME:-/root}/.cache/mr-ci}
APKDIR=${MR_CI_HOSTAPD_APKS:-/root/build/hostapd-noscan/pkgs/main/aarch64}
# preprocessor symbols config_file.c tests that Alpine's hostapd 2.11 build defines
# (aports main/hostapd APKBUILD: defconfig + the options its prepare() enables, as mapped by hostapd/Makefile)
ENABLED="CONFIG_DRIVER_NL80211 CONFIG_RSN_PREAUTH EAP_SERVER CONFIG_ERP CONFIG_DPP CONFIG_DPP2 RADIUS_SERVER
CONFIG_WNM_AP CONFIG_IEEE80211R_AP CONFIG_IEEE80211AC CONFIG_IEEE80211AX CONFIG_IEEE80211BE
CONFIG_FULL_DYNAMIC_VLAN CONFIG_ACS CONFIG_WEP CONFIG_SAE CONFIG_FST CONFIG_MBO CONFIG_AIRTIME_POLICY CONFIG_OCV"

# keys_from_source CONFIG_FILE_C: "key" per line (prefix matches end in '*'), only keys whose #ifdef
# conditions hold for $ENABLED
keys_from_source() {
	awk -v enabled="$ENABLED" '
	BEGIN { n = split(enabled, e, /[ \n]+/); for (i = 1; i <= n; i++) on[e[i]] = 1 }
	/^static int hostapd_config_fill\(/ { infill = 1; next }
	!infill { next }
	/^}/ { exit }
	/^#if(n)?def / { c = $2; if ($1 == "#ifndef") c = "!" c; stk[++depth] = c; next }
	/^#if / { stk[++depth] = "?"; next }
	/^#else/ { c = stk[depth]; if (substr(c, 1, 1) == "!") c = substr(c, 2); else if (c != "?") c = "!" c; stk[depth] = c; next }
	/^#endif/ { depth--; next }
	{
		line = $0
		if (pending) { line = "os_strcmp(buf, " line; pending = 0 }
		if (line ~ /os_strcmp\(buf,[ \t]*$/) { pending = 1; next }
		while (match(line, /os_str(n)?cmp\(buf, *"[^"]*"/)) {
			m = substr(line, RSTART, RLENGTH)
			pre = (m ~ /^os_strncmp/)
			sub(/^[^"]*"/, "", m); sub(/"$/, "", m)
			if (pre) { sub(/=$/, "", m); m = m "*" }
			ok = 1
			for (i = 1; i <= depth; i++) {
				c = stk[i]
				if (c == "?") ok = 0
				else if (substr(c, 1, 1) == "!") { if (substr(c, 2) in on) ok = 0 }
				else if (!(c in on)) ok = 0
			}
			if (ok) print m
			line = substr(line, RSTART + RLENGTH)
		}
	}' "$1" | LC_ALL=C sort -u
}

keys_from_patch() {
	sed -n 's/^+.*os_strcmp(buf, "\([a-z0-9_]*\)").*/\1/p' "$PATCH" | LC_ALL=C sort -u
}

# fetch_source: extracts config_file.c of the pinned release into $CACHE; fails when offline
fetch_source() {
	mkdir -p "$CACHE"
	tgz=$CACHE/hostapd-2.11.tar.gz
	if [ ! -s "$tgz" ] || ! echo "$SHA256  $tgz" | sha256sum -c - >/dev/null 2>&1; then
		curl -fsSL --max-time 60 -o "$tgz.tmp" "$URL" || return 1
		mv "$tgz.tmp" "$tgz"
	fi
	echo "$SHA256  $tgz" | sha256sum -c - >/dev/null || { echo "hostapd-2.11.tar.gz: sha256 mismatch"; rm -f "$tgz"; exit 1; }
	tar -xzf "$tgz" -C "$CACHE" hostapd-2.11/hostapd/config_file.c
	echo "$CACHE/hostapd-2.11/hostapd/config_file.c"
}

if [ "${1:-}" = "--keys" ]; then
	src=$(fetch_source) || { echo "cannot download $URL" >&2; exit 1; }
	keys_from_source "$src"
	echo "# build/hostapd/300-noscan.patch (OpenWrt), the one patch our hostapd carries"
	keys_from_patch
	exit 0
fi

# check_keys FILE...: every "key=" line must be in the whitelist (exact, or a listed "prefix*")
check_keys() {
	awk '
	FNR == NR { if ($0 !~ /^#/ && $0 != "") { if ($0 ~ /\*$/) pre[substr($0, 1, length($0) - 1)] = 1; else k[$0] = 1 }; next }
	/^#/ || /^$/ { next }
	{
		key = $0; sub(/=.*/, "", key)
		if (key in k) next
		for (p in pre) if (index(key, p) == 1) next
		printf "%s:%d: key \"%s\" is not accepted by upstream hostapd 2.11\n", FILENAME, FNR, key; bad = 1
	}
	END { exit bad }' "$KEYS" "$@"
}

confs=$(ls "$OUT"/home/etc/hostapd/hostapd-phy*.conf "$OUT"/lab/etc/hostapd/hostapd-phy*.conf)
echo "[wifi] hostapd keys vs upstream 2.11 whitelist ($(grep -cv '^#' "$KEYS") keys)"
# shellcheck disable=SC2086
check_keys $confs
tmp=$OUT/wifi-keys-selftest.conf
printf 'interface=x\nnot_a_hostapd_key=1\n' > "$tmp"
if check_keys "$tmp" >/dev/null; then echo "whitelist check does not catch unknown keys"; exit 1; fi
echo "ok: $(echo "$confs" | wc -l) configs"

# 1b. tuning (#41): off in the home config (no new keys, no tick), on in the lab: multicast-to-unicast per SSID,
#     bss_transition + rrm_neighbor_report only on the BSSes of the SSID both bands carry, the per-minute tick;
#     `mr wifi tick / health / steer --dry-run` run without hostapd (nothing answers: no action, exit 0)
echo "[wifi] tuning: multicast-to-unicast, band steering, self-heal tick"
if grep -Eq '^(multicast_to_unicast|bss_transition|rrm_neighbor_report)=' "$OUT"/home/etc/hostapd/hostapd-phy*.conf; then
	echo "home: tuning keys rendered although the home config has none"
	exit 1
fi
if grep -q 'mr wifi tick' "$OUT/home/etc/crontabs/root" 2>/dev/null; then echo "home: wifi tick in the crontab"; exit 1; fi
L=$OUT/lab/etc/hostapd
bss_keys() { # bss_keys FILE IFNAME: the tuning keys of one BSS section
	awk -v ifn="$2" '/^(interface|bss)=/ { cur = substr($0, index($0, "=") + 1) } cur == ifn && /^(multicast_to_unicast|bss_transition|rrm_neighbor_report)=/' "$1" | tr '\n' ' '
}
[ "$(bss_keys "$L/hostapd-phy0.conf" phy0-ap0-2)" = "multicast_to_unicast=1 bss_transition=1 rrm_neighbor_report=1 " ] || { echo "lab phy0-ap0-2 (MiniRouter-WPA3): $(bss_keys "$L/hostapd-phy0.conf" phy0-ap0-2)"; exit 1; }
[ "$(bss_keys "$L/hostapd-phy1.conf" phy1-ap0-1)" = "bss_transition=1 rrm_neighbor_report=1 " ] || { echo "lab phy1-ap0-1 (MiniRouter-WPA3): $(bss_keys "$L/hostapd-phy1.conf" phy1-ap0-1)"; exit 1; }
[ "$(bss_keys "$L/hostapd-phy1.conf" phy1-ap0)" = "multicast_to_unicast=1 " ] || { echo "lab phy1-ap0: $(bss_keys "$L/hostapd-phy1.conf" phy1-ap0)"; exit 1; }
for fb in phy0:phy0-ap0 phy0:phy0-ap0-1 phy1:phy1-ap0-2 phy1:phy1-ap0-3; do
	[ -z "$(bss_keys "$L/hostapd-${fb%%:*}.conf" "${fb#*:}")" ] || { echo "lab ${fb#*:}: unexpected tuning keys"; exit 1; }
done
grep -qx '\* \* \* \* \* /usr/sbin/mr wifi tick' "$OUT/lab/etc/crontabs/root" || { echo "lab: no wifi tick in the crontab"; exit 1; }
MR="$OUT/mr-host -c $OUT/lab.yaml -s $OUT/lab-secrets.yaml"
mkdir -p /run/mini-router && mount -t tmpfs tmpfs /run/mini-router # private mount namespace (tools/ci.sh)
# shellcheck disable=SC2086
{ timeout 20 $MR wifi tick && timeout 20 $MR wifi tick; } || { echo "mr wifi tick failed"; umount /run/mini-router; exit 1; }
# shellcheck disable=SC2086
h=$(timeout 20 $MR wifi health) && s=$(timeout 20 $MR wifi steer --dry-run) || { echo "mr wifi health / steer failed"; umount /run/mini-router; exit 1; }
[ -s /run/mini-router/wifi-health.json ] && [ -s /run/mini-router/wifi-steer.json ] || { echo "tick left no state"; umount /run/mini-router; exit 1; }
umount /run/mini-router
echo "$h" | grep -q '"self_heal": true' && echo "$h" | grep -q '"ssid": "MiniRouter-WPA3"' || { echo "health: $h"; exit 1; }
echo "$s" | grep -q '"dry_run": true' && echo "$s" | grep -q '"why": "hostapd not answering or BSS not up"' || { echo "steer: $s"; exit 1; }
echo "ok: home untouched; lab keys per BSS, cron line, tick / health / steer without hostapd"

echo "[wifi] whitelist == hostapd 2.11 source"
if src=$(fetch_source 2>/dev/null); then
	{ keys_from_source "$src"; echo "# build/hostapd/300-noscan.patch (OpenWrt), the one patch our hostapd carries"; keys_from_patch; } > "$OUT/hostapd-keys.gen"
	grep -v '^## ' "$KEYS" > "$OUT/hostapd-keys.vendored" # "## " lines are the file header
	diff -u "$OUT/hostapd-keys.vendored" "$OUT/hostapd-keys.gen" || { echo "mr/testdata/hostapd-2.11.keys is stale: regenerate with sh tools/ci.d/wifi.sh --keys"; exit 1; }
	echo "ok"
else
	echo "SKIP: $URL not reachable (offline); vendored list used as is"
fi

echo "[wifi] real hostapd 2.11 parses every rendered config"
if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
	echo "SKIP: docker not available"
	exit 0
fi
apk=$(ls "$APKDIR"/hostapd-2.11-r*.apk 2>/dev/null | tail -n 1 || true)
if [ -n "$apk" ]; then
	image=mr-ci-hostapd:noscan-$(sha256sum "$apk" | cut -c1-12)
	install="apk add -q --allow-untrusted /pkgs/$(basename "$apk")"
	strip=""
else
	image=mr-ci-hostapd:alpine-3.24
	install="apk add -q hostapd"
	strip="noscan" # Alpine's package lacks the noscan patch; that key is covered by the whitelist
fi
if ! docker image inspect "$image" >/dev/null 2>&1; then
	name=mr-ci-hostapd-$$
	if docker run --platform linux/arm64 --name "$name" ${apk:+-v "$APKDIR:/pkgs:ro"} alpine:3.24 sh -c "$install" >/dev/null 2>&1; then
		docker commit "$name" "$image" >/dev/null
	fi
	docker rm -f "$name" >/dev/null 2>&1 || true
fi
if ! docker image inspect "$image" >/dev/null 2>&1; then
	echo "SKIP: could not prepare $image (no network?)"
	exit 0
fi
if ! docker run --rm --platform linux/arm64 --network none "$image" hostapd -v 2>&1 | grep -q 'hostapd v2\.11'; then
	echo "SKIP: $image does not run here (arm64 emulation / binfmt missing?)"
	exit 0
fi
echo "using $image"
parse() { # parse DIR > LOG: run hostapd on every hostapd-phy*.conf in DIR
	docker run --rm --platform linux/arm64 --network none -v "$1:/etc/hostapd:ro" "$image" \
		sh -c 'for f in /etc/hostapd/hostapd-phy*.conf; do echo "== $f"; timeout 60 hostapd "$f" 2>&1; done; true'
}
# self-test: an unknown key and a consistency error (802.11h without 802.11d) must both be rejected
neg=$OUT/wifi-hostapd-neg
rm -rf "$neg" && mkdir -p "$neg"
{ cat "$OUT/home/etc/hostapd/hostapd-phy1.conf"; echo "not_a_hostapd_key=1"; } > "$neg/hostapd-phy0.conf"
grep -v -e '^country_code=' -e '^ieee80211d=' "$OUT/home/etc/hostapd/hostapd-phy1.conf" > "$neg/hostapd-phy1.conf"
if [ "$(parse "$neg" | grep -c 'errors found in configuration file')" -ne 2 ]; then
	echo "hostapd parse check does not catch bad configs"
	exit 1
fi
echo "ok: self-test (unknown key and 802.11h without 802.11d are rejected)"
for tree in home lab; do
	dir=$OUT/wifi-hostapd-$tree
	rm -rf "$dir" && cp -r "$OUT/$tree/etc/hostapd" "$dir"
	[ -z "$strip" ] || sed -i "/^$strip=/d" "$dir"/hostapd-phy*.conf
	log=$OUT/wifi-hostapd-$tree.log
	parse "$dir" > "$log"
	if grep -E "errors found in configuration file|unknown configuration item|^Line [0-9]+:" "$log"; then
		echo "[$tree] hostapd rejected a generated config (full log: $log)"
		exit 1
	fi
	want=$(ls "$dir"/hostapd-phy*.conf | wc -l)
	got=$(grep -c "Failed to initialize driver 'nl80211'" "$log" || true)
	if [ "$got" -ne "$want" ]; then
		cat "$log"
		echo "[$tree] expected $want configs to parse and reach driver init, saw $got"
		exit 1
	fi
	echo "ok: $tree ($want configs)"
done
