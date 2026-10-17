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
