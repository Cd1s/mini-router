#!/bin/sh
# Power cut inside the confirm window: an unconfirmed change must be gone after the reboot, a
# confirmed one must stay.
NAME=04-powercut-confirm
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"
step lab reset "$ID"
step lab isp "$ID" 1 dhcp
check "install.sh completes (DHCP WAN)" lab install "$ID" --wan-proto dhcp
step lab lan "$ID" dhcp
hostname_is() { lab api "$ID" GET config | jq -e --arg h "$1" '.config.system.hostname == $h' >/dev/null; }
check "unconfirmed change is applied (hostname lab-pending)" lab change "$ID" '[{"op":"set","path":"system.hostname","value":"lab-pending"}]' --no-confirm
check "power cut and boot" lab powercut "$ID"
check "after the power cut the unconfirmed hostname is rolled back" retry 90 hostname_is mini-router
check "confirmed change is applied (hostname lab-kept)" lab change "$ID" '[{"op":"set","path":"system.hostname","value":"lab-kept"}]'
check "power cut and boot" lab powercut "$ID"
check "after the power cut the confirmed hostname stays" retry 90 hostname_is lab-kept
check "LAN client is online after both power cuts" retry 60 sh -c "\"$LAB_SH\" lan $ID dhcp && \"$LAB_SH\" lan $ID exec 'curl -4 -fsS -o /dev/null --max-time 10 http://example.com/'"
finish
