#!/bin/sh
# Change PPPoE to a same-subnet DHCP modem through the panel API only.
# The expected product issue is recorded as a TAP failure with evidence.
set -u

ID=${1:?usage: 03-move-dhcp-samesubnet.sh <lab-id>}
SELF_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
LAB_SH=${LAB_SH:-"$SELF_DIR/../lab.sh"}
LOG=${LAB_SCENARIO_LOG:-/tmp/mrlab${ID}-03-move-dhcp-samesubnet.log}
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
		printf '# evidence: %s\n' "$(tail -12 "$LOG" | tr '\n' ' ')"
	fi
}

run "$LAB_SH" reset "$ID" || true
run "$LAB_SH" up "$ID" || true
run "$LAB_SH" isp "$ID" 1 pppoe || true
run "$LAB_SH" install "$ID" --wan-proto pppoe || true
run "$LAB_SH" lan "$ID" dhcp || true
check "baseline PPPoE panel is reachable" "$LAB_SH" lan "$ID" check

# Keep this operation entirely in the panel API. Read the revision and submit an apply patch;
# lab.sh api is responsible for Bearer auth while this script follows the config/apply flow in
# docs/api.md. The WAN list item is selected by its name.
PATCH='[{"op":"set","path":"wan[wan].proto","value":"dhcp"},{"op":"del","path":"wan[wan].password_secret"}]'
run "$LAB_SH" isp "$ID" 1 dhcp --subnet 192.168.1.0/24 || true
CONFIG_JSON=$LOG.config
if "$LAB_SH" api "$ID" GET config > "$CONFIG_JSON" 2>> "$LOG"; then
	REV=$(jq -r '.rev // empty' "$CONFIG_JSON" 2>> "$LOG" || true)
	if [ -n "$REV" ]; then
		APPLY=$(jq -cn --arg rev "$REV" --argjson patch "$PATCH" \
			'{base_rev:$rev,patch:$patch,confirm:120,comment:"lab 03 move DHCP same subnet"}')
		APPLY_JSON=$LOG.apply
		if "$LAB_SH" api "$ID" POST apply "$APPLY" > "$APPLY_JSON" 2>> "$LOG"; then
			cat "$APPLY_JSON" >> "$LOG"
			printf '# API change submitted through lab.sh api (rev %s)\n' "$REV" >> "$LOG"
			state=running
			i=0
			while [ "$state" = running ] && [ "$i" -lt 20 ]; do
				i=$((i + 1)); sleep 1
				JOB_JSON=$LOG.job
				"$LAB_SH" api "$ID" GET job > "$JOB_JSON" 2>> "$LOG" || break
				cat "$JOB_JSON" >> "$LOG"
				state=$(jq -r '.job.state // "failed"' "$JOB_JSON" 2>> "$LOG" || printf failed)
			done
			if [ "$state" = ok ]; then
				# Keep the pending change. The API token can only confirm its own change.
				"$LAB_SH" api "$ID" POST confirm '{}' >> "$LOG" 2>&1 ||
					printf '# API confirm failed; change may auto-revert\n' >> "$LOG"
			else
				printf '# API apply job state: %s\n' "$state" >> "$LOG"
			fi
		else
			printf '# API apply failed; this is a product/API failure candidate\n' >> "$LOG"
		fi
	else
		printf '# API config response had no rev: %s\n' "$(tr '\n' ' ' < "$CONFIG_JSON")" >> "$LOG"
	fi
else
	printf '# API config read failed; this is a product/API failure candidate\n' >> "$LOG"
fi

# A same-subnet transition may strand the router or LAN client. Report the exact symptom rather
# than hiding it; callers can inspect LOG and the serial console after a not ok result.
check "router remains reachable after API WAN switch" "$LAB_SH" lan "$ID" check
check "LAN client still has internet after same-subnet move" "$LAB_SH" lan "$ID" exec curl -fsS --max-time 8 http://example.com/

printf '# log: %s\n' "$LOG"
if [ "$fail" -ne 0 ]; then
	printf '# expected diagnostic: same-subnet move exposed %s failed check(s); see log above\n' "$fail"
	# This scenario is diagnostic: a failure is valid and must not hide the observed symptom.
	exit 1
fi
exit 0

