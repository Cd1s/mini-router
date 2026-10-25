#!/bin/sh
# Policy routes fall back when their via WAN is useless (the 2026-10-26 incident): AIS puts the sessions over
# its concurrent-session limit into a walled garden (100.64/10): PPP is up, there is an address, nothing is
# forwarded. With wan[].require_public_ip the WAN is held out of routing (its table loses the default route),
# so a policy route with fallback: main (the default) uses the main route within a minute and goes back to
# its via WAN when the line has a public address again; fallback: drop stays cut off. Then the same for a line
# that only the multiwan health check can tell is dead (no require_public_ip).
NAME=14-policy-fallback-walled
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"
CL_MAIN=192.168.1.101 # policy pin-main: via wan2, fallback main
CL_DROP=192.168.1.102 # policy pin-drop: via wan2, fallback drop
no_reply() { [ -z "$(exit_addr "$1")" ]; }
default_exits_via() { [ "$(lab lan "$ID" exec 'curl -4 -fsS --max-time 5 http://192.0.2.99/' 2> /dev/null | tr -d '\r\n ')" = "$(wan_addr "$1")" ]; }
step lab reset "$ID"
# the first 99 dials of wan2's session MAC are walled (the ISP counts the old sessions); wan's are public
step lab isp "$ID" 1 pppoe --echo --cgnat-dials 99 --cgnat-mac "$WAN2_MAC"
check "install.sh completes (wan: PPPoE, public address)" lab install "$ID" --wan-proto pppoe
step lab lan "$ID" dhcp
step lab lan "$ID" exec "ip addr add $CL_MAIN/24 dev $LAN_DEV; ip addr add $CL_DROP/24 dev $LAN_DEV"
check "LAN client online over wan (the ISP sees wan's address)" retry 30 exits_via "$CL_MAIN" pppoe-wan

check "API: wan2 (require_public_ip, gap 300 s) + policies pin-main (fallback main) and pin-drop (fallback drop) via wan2" \
	lab change "$ID" "[{\"op\":\"add\",\"path\":\"wan\",\"value\":$(wan2_json 300)},{\"op\":\"add\",\"path\":\"policy_routes\",\"value\":{\"name\":\"pin-main\",\"src\":\"$CL_MAIN\",\"via\":\"wan2\"}},{\"op\":\"add\",\"path\":\"policy_routes\",\"value\":{\"name\":\"pin-drop\",\"src\":\"$CL_DROP\",\"via\":\"wan2\",\"fallback\":\"drop\"}}]"
check "wan2 is up in the walled garden (100.64.x)" retry 150 lab console "$ID" "ip -4 addr show pppoe-wan2 | grep -q 'inet 100.64.'"
check "that session is dead (nothing is forwarded)" lab console "$ID" '! ping -c 2 -W 2 -I pppoe-wan2 192.0.2.99 > /dev/null 2>&1'
check "the walled line's table has no default route" lab console "$ID" '! ip route show table 201 | grep -q "^default"'
check "fallback main: pin-main is online within a minute, through wan" retry 60 exits_via "$CL_MAIN" pppoe-wan
check "fallback drop: pin-drop stays cut off (no reply from the echo server)" no_reply "$CL_DROP"
check "a device without a policy is unaffected (leaves through wan)" default_exits_via pppoe-wan
check "mr doctor: wan2 is a warning that waits for the ISP, not a risk" lab console "$ID" 'mr doctor 2>&1 | grep -E "^WARN +wan.wan2 " | grep -q "waiting for the ISP to release a session slot"'
info lab console "$ID" 'mr doctor 2>&1 | grep -A1 wan2; ip rule; ip route show table 201; ip route'

# the ISP releases its slots: the next dial is public. A manual redial (the panel's button) takes it.
step lab isp-walled "$ID" 1 0
check "API: redial wan2" lab api "$ID" POST net.redial '{"wan":"wan2"}'
check "wan2 gets a public address (203.0.113.x)" retry 120 lab console "$ID" "ip -4 addr show pppoe-wan2 | grep -q 'inet 203.0.113.'"
check "pin-main goes back to wan2 (the ISP sees wan2's address)" retry 60 exits_via "$CL_MAIN" pppoe-wan2
check "pin-drop is online again, through wan2" retry 60 exits_via "$CL_DROP" pppoe-wan2

# a line that only the health check can tell is dead: require_public_ip off, multiwan failover pings through it
step lab isp-walled "$ID" 1 999
check "API: wan2 without require_public_ip, multiwan failover (target = the echo server)" \
	lab change "$ID" '[{"op":"del","path":"wan[wan2].require_public_ip"},{"op":"del","path":"wan[wan2].require_public_ip_gap"},{"op":"set","path":"multiwan","value":{"mode":"failover","targets":["192.0.2.99"],"interval":2,"fall":3,"rise":2}}]'
check "API: redial wan2 (walled again)" lab api "$ID" POST net.redial '{"wan":"wan2"}'
check "wan2 is walled again (100.64.x)" retry 120 lab console "$ID" "ip -4 addr show pppoe-wan2 | grep -q 'inet 100.64.'"
check "the health check marks wan2 down" retry 60 lab console "$ID" 'grep -q "\"name\":\"wan2\",\"dev\":\"pppoe-wan2\",\"state\":\"down\"" /run/mini-router/wan-state.json'
check "fallback main (health check): pin-main is online through wan" retry 60 exits_via "$CL_MAIN" pppoe-wan
step lab isp-walled "$ID" 1 0
check "API: redial wan2 (public again)" lab api "$ID" POST net.redial '{"wan":"wan2"}'
check "the health check marks wan2 up again" retry 120 lab console "$ID" 'grep -q "\"name\":\"wan2\",\"dev\":\"pppoe-wan2\",\"state\":\"up\"" /run/mini-router/wan-state.json'
check "pin-main goes back to wan2 (health check)" retry 60 exits_via "$CL_MAIN" pppoe-wan2
finish
