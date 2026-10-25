#!/bin/sh
# Shared TAP helpers for the lab scenarios: NAME=<scenario>; . "$(dirname "$0")/lib.sh" (reads $1 = lab id)
set -u
ID=${1:?usage: <scenario> <lab-id>}
: "${NAME:?}"
SELF_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
LAB_SH=${LAB_SH:-"$SELF_DIR/../lab.sh"}
LOG=${LAB_SCENARIO_LOG:-/tmp/mrlab$ID-$NAME.log}
: > "$LOG"
n=0
fail=0
# the lab is removed on any exit (pass, fail, Ctrl-C); MRLAB_KEEP=1 leaves it up for inspection
cleanup() {
	[ "${MRLAB_KEEP:-0}" = 1 ] && { printf '# MRLAB_KEEP=1: lab %s left up (lab.sh down %s)\n' "$ID" "$ID"; return; }
	"$LAB_SH" down "$ID" > /dev/null 2>&1 || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

# step <cmd...>: a setup step, output only to the log; the scenario stops when it fails
step() {
	printf '+ %s\n' "$*" >> "$LOG"
	"$@" >> "$LOG" 2>&1 && return 0
	printf 'Bail out! setup step failed: %s\n' "$*"
	tail -6 "$LOG" | cut -c1-200 | sed 's/^/#   /'
	printf '# log: %s\n' "$LOG"
	exit 1
}
# info <cmd...>: diagnostics for the log only; a failure does not matter
info() {
	printf '+ %s\n' "$*" >> "$LOG"
	"$@" >> "$LOG" 2>&1 || true
}
# check <description> <cmd...>: one TAP line; the last log lines are the evidence of a failure
check() {
	d=$1
	shift
	n=$((n + 1))
	printf '+ [check %s] %s\n' "$n" "$*" >> "$LOG"
	if "$@" >> "$LOG" 2>&1; then
		printf 'ok %s - %s\n' "$n" "$d"
	else
		fail=$((fail + 1))
		printf 'not ok %s - %s\n' "$n" "$d"
		tail -6 "$LOG" | cut -c1-200 | sed 's/^/#   /'
	fi
}
# retry <seconds> <cmd...>: run cmd every 3 s until it succeeds or the time is up
retry() {
	t=$1
	shift
	end=$(($(date +%s) + t))
	while :; do
		"$@" && return 0
		[ "$(date +%s)" -lt "$end" ] || return 1
		sleep 3
	done
}
note() { printf '# %s\n' "$*"; printf '# %s\n' "$*" >> "$LOG"; }
lab() { "$LAB_SH" "$@"; }
finish() {
	printf '1..%s\n# log: %s\n' "$n" "$LOG"
	[ "$fail" -eq 0 ]
}

# ---- shared by the two-line scenarios (07, 12, 13): wan on the port's own MAC, wan2 a second PPPoE session
# on the same port (own MAC, macvlan), both dialled at the ISP simulator's isp1 (state/mrlab<ID>/isp1)
WAN2_MAC=02:00:00:$(printf '%02x' "$ID"):00:02
LAN_DEV=mrlab${ID}slp
ISP_DIR=$(dirname "$LAB_SH")/state/mrlab$ID/isp1
# wan2_json <gap>: the wan2 entry; gap > 0 turns require_public_ip on with that require_public_ip_gap
wan2_json() {
	_g=''
	[ "${1:-0}" -le 0 ] || _g=",\"require_public_ip\":true,\"require_public_ip_gap\":$1"
	printf '{"name":"wan2","device":"eth0","proto":"pppoe","username":"lab","password_secret":"pppoe_password","mac":"%s","metric":20,"peerdns":true%s}' "$WAN2_MAC" "$_g"
}
# wan_addr <ifname>: the router's IPv4 address on it
wan_addr() { lab console "$ID" "ip -4 -o addr show $1" 2> /dev/null | sed -n 's/.* inet \([0-9.]*\).*/\1/p' | head -n 1; }
# exit_addr <client source address>: the address the ISP's echo server (192.0.2.99) saw for a request from the LAN client
exit_addr() { lab lan "$ID" exec "curl -4 -fsS --max-time 5 --interface $1 http://192.0.2.99/" 2> /dev/null | tr -d '\r\n '; }
# exits_via <client source address> <wan ifname>: the request left through that WAN
exits_via() { [ "$(exit_addr "$1")" = "$(wan_addr "$2")" ] && [ -n "$(wan_addr "$2")" ]; }
wire() { cat "$ISP_DIR/pppoe-wire.log" 2> /dev/null; }
