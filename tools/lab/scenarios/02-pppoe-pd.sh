#!/bin/sh
# PPPoE WAN with IPv6 prefix delegation. Called by lab.sh run <id> 02-pppoe-pd.
set -u

ID=${1:?usage: 02-pppoe-pd.sh <lab-id>}
SELF_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
LAB_SH=${LAB_SH:-"$SELF_DIR/../lab.sh"}
LOG=${LAB_SCENARIO_LOG:-/tmp/mrlab${ID}-02-pppoe-pd.log}
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
run "$LAB_SH" isp "$ID" 1 pppoe v6=pd || true
run "$LAB_SH" install "$ID" --wan-proto pppoe || true
check "LAN client obtains IPv4/IPv6 leases" "$LAB_SH" lan "$ID" dhcp

# The client check must verify a global address and an IPv6 path. Keep a direct probe as an
# additional assertion when the helper exposes only a summary line.
check "LAN client has a global IPv6 address" "$LAB_SH" lan "$ID" exec sh -c 'ip -6 addr show scope global | grep -q "scope global"'
check "IPv6 prefix delegation reaches the LAN client" "$LAB_SH" lan "$ID" check
check "client can ping the ISP IPv6 test address" "$LAB_SH" lan "$ID" exec ping6 -c 2 -W 3 "2001:db8:${ID}::1"

printf '# log: %s\n' "$LOG"
[ "$fail" -eq 0 ]

