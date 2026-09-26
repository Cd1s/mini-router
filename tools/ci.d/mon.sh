#!/bin/sh
# mon module checks (run by tools/ci.sh with OUT and ROOT set):
#  - rendered files: conntrack accounting sysctl, sampler WAN devices, mr-mon enabled
#  - the busybox-sh history sampler, run for real against this host's /proc (fast interval,
#    tiny ring so the trim path runs), then parsed by `mr mon history`
#  - the sampler's event tick: `mr event tick` (a stub here) only for a changed lease file or a due event.due
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
MON_FILE=$H/history MON_INTERVAL=1 MON_KEEP=3 MON_EVENT_DIR=$H MON_LEASES=$H/none MON_MR=false timeout 6 sh "$ROOT/rootfs/usr/libexec/mr/mon-collect" lo nonexistent0 || rc=$?
[ "$rc" -eq 124 ] || { echo "sampler exited early ($rc)"; exit 1; }
cat "$H/history"
n=$(wc -l < "$H/history")
[ "$n" -ge 2 ] && [ "$n" -le 4 ] || { echo "ring not trimmed to MON_KEEP (+slack): $n lines"; exit 1; }
awk 'NF != 8 { exit 1 } { for (i = 1; i <= 8; i++) if ($i !~ /^-?[0-9]+$/) exit 1 }' "$H/history" || { echo "bad sample line"; exit 1; }
[ ! -e "$H/history.tmp" ]
echo "sampler ok ($n samples)"

# the event tick (sys module): the sampler starts `mr event tick` only when the lease file is newer
# than leases.seen or event.due has come. A stub records each start and marks the leases seen the
# way mr does (a second early).
T=$OUT/mon-tick
rm -rf "$T" && mkdir -p "$T/ev"
cat > "$T/mr" <<'STUB'
#!/bin/sh
echo "$*" >> "${0%/*}/calls"
touch -d "@$(($(date +%s) - 1))" "${0%/*}/ev/leases.seen"
STUB
chmod +x "$T/mr"
sampler() { # seconds
	MON_FILE=$T/history MON_INTERVAL=1 MON_KEEP=3 MON_EVENT_DIR=$T/ev MON_LEASES=$T/leases MON_MR=$T/mr \
		timeout "$1" sh "$ROOT/rootfs/usr/libexec/mr/mon-collect" lo || true
	sleep 0.3 # the last tick runs detached
}
calls() { if [ -e "$T/calls" ]; then wc -l < "$T/calls"; else echo 0; fi; }
sampler 3
[ "$(calls)" = 0 ] || { echo "tick without leases or event.due: $(cat "$T/calls")"; exit 1; }
touch -d "@$(($(date +%s) - 10))" "$T/leases"
sampler 4
[ "$(calls)" = 1 ] || { echo "a new lease file: $(calls) ticks, want 1"; exit 1; }
grep -qx 'event tick' "$T/calls"
read -r up _ < /proc/uptime
echo $((${up%.*} + 3600)) > "$T/ev/event.due"
sampler 3
[ "$(calls)" = 1 ] || { echo "tick before event.due"; exit 1; }
echo 1 > "$T/ev/event.due"
sampler 3
[ "$(calls)" -ge 3 ] || { echo "event.due passed: $(calls) ticks"; exit 1; }
echo garbage > "$T/ev/event.due"
rm -f "$T/calls"
sampler 3
[ "$(calls)" = 0 ] || { echo "tick for a garbage event.due"; exit 1; }
echo "event tick trigger ok"

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
