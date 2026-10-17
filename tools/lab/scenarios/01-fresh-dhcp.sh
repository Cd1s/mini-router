#!/bin/sh
# Fresh Alpine install with a DHCP WAN. Called by lab.sh run <id> 01-fresh-dhcp.
set -u

ID=${1:?usage: 01-fresh-dhcp.sh <lab-id>}
SELF_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
LAB_SH=${LAB_SH:-"$SELF_DIR/../lab.sh"}
LOG=${LAB_SCENARIO_LOG:-/tmp/mrlab${ID}-01-fresh-dhcp.log}
: > "$LOG"

run() {
	printf '+ %s\n' "$*" >> "$LOG"
	"$@" >> "$LOG" 2>&1
}

ok=0
fail=0
check() {
	name=$1; shift
	if "$@" >> "$LOG" 2>&1; then
		ok=$((ok + 1)); printf 'ok %s - %s\n' "$ok" "$name"
	else
		fail=$((fail + 1)); printf 'not ok %s - %s\n' "$((ok + fail))" "$name"
		printf '# evidence: %s\n' "$(tail -8 "$LOG" | tr '\n' ' ')"
	fi
}

run "$LAB_SH" reset "$ID" || true
run "$LAB_SH" up "$ID" || true
run "$LAB_SH" isp "$ID" 1 dhcp || true
run "$LAB_SH" install "$ID" --wan-proto dhcp || true
check "LAN client obtains a DHCP lease" "$LAB_SH" lan "$ID" dhcp
check "LAN client reaches the IPv4 internet" "$LAB_SH" lan "$ID" exec curl -4 -fsS --max-time 8 http://example.com/
check "LAN client resolves a public DNS name" "$LAB_SH" lan "$ID" exec getent hosts example.com
check "LAN client opens the router panel" "$LAB_SH" lan "$ID" exec curl -fsS --max-time 8 http://192.168.1.1/

if [ "$fail" -eq 0 ]; then
	printf '# log: %s\n' "$LOG"
	exit 0
fi
printf '# log: %s\n' "$LOG"
exit 1

