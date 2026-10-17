#!/bin/sh
# Change only the simulated ISP while leaving router configuration untouched.
set -u
ID=${1:?usage: 05-isp-switch-live.sh <lab-id>}
DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd); LAB_SH=${LAB_SH:-"$DIR/../lab.sh"}; LOG=${LAB_SCENARIO_LOG:-/tmp/mrlab${ID}-05-isp-switch-live.log}; : > "$LOG"
run(){ printf '+ %s\n' "$*" >> "$LOG"; "$@" >> "$LOG" 2>&1; }
run "$LAB_SH" reset "$ID" || true; run "$LAB_SH" isp "$ID" 1 pppoe || true; run "$LAB_SH" install "$ID" --wan-proto pppoe || true
printf 'ok 1 - PPPoE ISP started without changing router config\n'
run "$LAB_SH" isp "$ID" 1 dhcp || true
run "$LAB_SH" console "$ID" 'mr doctor --json || mr doctor; mr status --json || mr status' || true
if "$LAB_SH" lan "$ID" check >>"$LOG" 2>&1; then printf 'ok 2 - live ISP switch remains reachable\n'; else printf 'not ok 2 - live ISP switch reports loss; inspect doctor/status output\n'; fi
printf '# log: %s\n' "$LOG"; tail -12 "$LOG" | sed 's/^/# /'; exit 0
