#!/bin/sh
# First-run setup through the same session/plan/apply/confirm API calls as the web wizard.
NAME=09-first-run-wizard
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

WIZARD_PATCH='[{"op":"set","path":"system.timezone","value":"<+08>-8"},{"op":"set","path":"wan[wan].proto","value":"dhcp"},{"op":"set","path":"wifi.radios","value":[]}]'
WIZARD_REV=

session_wizard() {
	lab api "$ID" GET session | jq -e '.wizard == true'
}

detect_pppoe() {
	result=$(lab api "$ID" POST net.wan_detect '{"port":"eth0","timeout":8}') || return
	printf '%s\n' "$result" | jq -e '.recommendation == "pppoe" and (.pppoe.ac_name | length > 0)'
}

detect_dhcp() {
	result=$(lab api "$ID" POST net.wan_detect '{"port":"eth0","timeout":8}') || return
	printf '%s\n' "$result" | jq -e '.recommendation == "dhcp" and .dhcp.offer == true and (.dhcp.address | length > 0) and (.dhcp.gateway | length > 0) and (.dhcp.dns | length > 0)'
}

detect_lan_conflict() {
	result=$(lab api "$ID" POST net.wan_detect '{"port":"eth0","timeout":8}') || return
	printf '%s\n' "$result" | jq -e '.recommendation == "dhcp" and .lan_conflict == true and (.suggested_lan | length > 0)'
}

read_wizard_revision() {
	WIZARD_REV=$(lab api "$ID" GET config | jq -r '.rev') || return
	[ -n "$WIZARD_REV" ] && [ "$WIZARD_REV" != null ]
}

wizard_plan() {
	body=$(jq -cn --arg rev "$WIZARD_REV" --argjson patch "$WIZARD_PATCH" '{base_rev:$rev,patch:$patch,comment:"first-run wizard"}') || return
	plan=$(lab api "$ID" POST plan "$body") || return
	printf '%s\n' "$plan" | jq -e '.errors == [] and .empty == false and (.files | index("/etc/localtime")) != null'
}

wizard_apply() {
	body=$(jq -cn --arg rev "$WIZARD_REV" --argjson patch "$WIZARD_PATCH" '{base_rev:$rev,patch:$patch,confirm:120,comment:"first-run wizard"}') || return
	response=$(lab api "$ID" POST apply "$body") || return
	printf '%s\n' "$response" | jq -e '.ok == true' >/dev/null || return 1
	i=0
	state=running
	while [ "$i" -lt 180 ]; do
		job=$(lab api "$ID" GET job) || return
		state=$(printf '%s\n' "$job" | jq -r '.job.state // "running"')
		[ "$state" = ok ] && return 0
		[ "$state" = failed ] && return 1
		sleep 2
		i=$((i + 2))
	done
	return 1
}

wizard_confirm() {
	lab api "$ID" POST confirm '{}' | jq -e '.confirmed == true'
}

wizard_config_applied() {
	lab api "$ID" GET config | jq -e '.config.system.timezone == "<+08>-8" and .config.wan[0].proto == "dhcp" and (.config.wifi.radios | length) == 0'
}

wizard_job_confirm_pending() {
	lab api "$ID" GET job | jq -e '.confirm_pending == true and .job.state == "ok"'
}

session_installed() {
	lab api "$ID" GET session | jq -e '.wizard == false'
}

step lab reset "$ID"
step lab isp "$ID" 1 dhcp
step lab install "$ID" --no-apply --wan-proto dhcp
# MR_APPLY=0 deliberately leaves the generated config unapplied. Apply once from the guest
# console so the lab panel is reachable; the wizard marker remains until setup.complete.
step lab console "$ID" 'mr apply'
step lab lan "$ID" dhcp
check "MR_APPLY=0 install enters the first-run wizard" session_wizard

step lab isp "$ID" 1 pppoe
check "WAN discovery recommends PPPoE and reports an access concentrator" detect_pppoe
step lab isp "$ID" 1 dhcp
check "WAN discovery recommends DHCP and includes the OFFER" detect_dhcp
step lab isp "$ID" 1 dhcp --subnet 192.168.1.0/24
check "WAN discovery reports a LAN conflict and suggested subnet" detect_lan_conflict
step lab isp "$ID" 1 dhcp

step read_wizard_revision
check "wizard submits a valid panel plan for timezone, DHCP WAN and WiFi skip" wizard_plan
step wizard_apply
check "wizard apply completes and leaves a confirmation pending" wizard_job_confirm_pending
check "wizard confirms the new configuration" wizard_confirm
check "wizard configuration is installed" wizard_config_applied
check "setup.complete clears the wizard marker" lab api "$ID" POST setup.complete '{}'
check "session reports wizard=false after setup.complete" session_installed
check "LAN client reaches the IPv4 internet" sh -c "\"$LAB_SH\" lan \"$ID\" dhcp >/dev/null && \"$LAB_SH\" lan \"$ID\" exec 'curl -4 -fsS -o /dev/null --max-time 10 http://example.com/'"

# A normal install (MR_APPLY=1) completes setup during installation and must not show the wizard.
step lab install "$ID" --wan-proto dhcp
step lab lan "$ID" dhcp
check "already-installed router (MR_APPLY=1) skips the wizard" session_installed
finish
