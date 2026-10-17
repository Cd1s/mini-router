#!/bin/sh
# Apply a reversible change, cut power before confirm, and verify the old revision returns.
set -u
ID=${1:?usage: 04-powercut-confirm.sh <lab-id>}
DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd); LAB_SH=${LAB_SH:-"$DIR/../lab.sh"}; LOG=${LAB_SCENARIO_LOG:-/tmp/mrlab${ID}-04-powercut-confirm.log}; : > "$LOG"
run(){ printf '+ %s\n' "$*" >> "$LOG"; "$@" >> "$LOG" 2>&1; }
run "$LAB_SH" up "$ID" || true; run "$LAB_SH" install "$ID" --wan-proto dhcp || true
before=$LOG.before; after=$LOG.after
if "$LAB_SH" api "$ID" GET config >"$before" 2>>"$LOG"; then
  rev=$(jq -r '.rev // empty' "$before" 2>>"$LOG" || true)
  body=$(jq -cn --arg rev "$rev" '{base_rev:$rev,patch:[{op:"set",path:"system.hostname",value:"mrlab-powercut"}],confirm:120,comment:"powercut rollback"}')
  run "$LAB_SH" api "$ID" POST apply "$body" || true
  run "$LAB_SH" powercut "$ID" || true
  sleep 8
  if "$LAB_SH" api "$ID" GET config >"$after" 2>>"$LOG"; then
    got=$(jq -r '.config.system.hostname // empty' "$after" 2>>"$LOG" || true)
    if [ "$got" = mrlab-powercut ]; then printf 'not ok 1 - power cut left unconfirmed hostname applied\n'; else printf 'ok 1 - unconfirmed apply rolled back (hostname=%s)\n' "$got"; fi
  else printf 'not ok 1 - router API unavailable after power cut\n'; fi
else printf 'not ok 1 - baseline config API unavailable\n'; fi
printf '# log: %s\n' "$LOG"; grep -E 'rollback|confirm|error|not ok' "$LOG" | tail -8 | sed 's/^/# /'; exit 0
