#!/bin/sh
# mon module checks (run by tools/ci.sh with OUT and ROOT set):
#  - rendered files: conntrack accounting sysctl, sampler WAN devices, mr-mon enabled
#  - the busybox-sh history sampler, run for real against this host's /proc (fast interval,
#    tiny ring so the trim path runs), then parsed by `mr mon history`
#  - `mr mon now|procs` produce JSON on a real kernel
set -eu
: "${OUT:?}" "${ROOT:?}"
MR=$OUT/mr-host
for t in home lab; do
	grep -qx 'net.netfilter.nf_conntrack_acct=1' "$OUT/$t/etc/sysctl.d/91-mon.conf"
	grep -qxE 'MON_WAN="[A-Za-z0-9_.@ -]*"' "$OUT/$t/etc/conf.d/mr-mon"
	grep -qx 'mr-mon' "$OUT/$t/etc/mini-router/gen/services"
done
# home: both PPPoE sessions ride the one physical port
grep -qx 'MON_WAN="wan"' "$OUT/home/etc/conf.d/mr-mon"
echo "rendered files ok"

H=$OUT/mon
rm -rf "$H" && mkdir -p "$H"
rc=0
MON_FILE=$H/history MON_INTERVAL=1 MON_KEEP=3 timeout 6 sh "$ROOT/rootfs/usr/libexec/mr/mon-collect" lo nonexistent0 || rc=$?
[ "$rc" -eq 124 ] || { echo "sampler exited early ($rc)"; exit 1; }
cat "$H/history"
n=$(wc -l < "$H/history")
[ "$n" -ge 2 ] && [ "$n" -le 4 ] || { echo "ring not trimmed to MON_KEEP (+slack): $n lines"; exit 1; }
awk 'NF != 8 { exit 1 } { for (i = 1; i <= 8; i++) if ($i !~ /^-?[0-9]+$/) exit 1 }' "$H/history" || { echo "bad sample line"; exit 1; }
[ ! -e "$H/history.tmp" ]
echo "sampler ok ($n samples)"

CFG="-c $ROOT/examples/router.yaml -s $ROOT/mr/testdata/secrets.yaml"
# shellcheck disable=SC2086
"$MR" $CFG mon history "$H/history" > "$H/history.json"
grep -q '"ok": true' "$H/history.json" || { cat "$H/history.json"; echo "history: sampler not seen as running"; exit 1; }
grep -q '"cpu": \[' "$H/history.json"
# shellcheck disable=SC2086
"$MR" $CFG mon now > "$H/now.json"
grep -q '"cpus": \[' "$H/now.json"
if grep -q '"name": "lo"' "$H/now.json"; then echo "lo must be hidden"; exit 1; fi
# shellcheck disable=SC2086
"$MR" $CFG mon procs > "$H/procs.json"
grep -q '"pid": 1,' "$H/procs.json"
# shellcheck disable=SC2086
"$MR" $CFG mon conns '{"proto":"tcp","limit":5}' > "$H/conns.json"
# shellcheck disable=SC2086
if "$MR" $CFG mon conns '{"proto":"tcp; reboot"}' > /dev/null 2>&1; then echo "bad filter accepted"; exit 1; fi
echo "mr mon ok"
