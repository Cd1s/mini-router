#!/bin/sh
# A reboot must end the PPPoE sessions at the ISP: LCP Terminate-Request + PADT from every session. An ISP that
# never heard a session end keeps counting it (AIS: the next dial lands in the walled garden). Two sessions on
# one port (wan on the port's MAC, wan2 on macvlan with its own MAC), both public.
#  A) the ISP answers the Terminate-Request: both sessions end, and OpenRC stops mr-pppoe.* before it unloads the
#     firewall or touches a link.
#  B) the ISP does not answer (its pppd is stopped): pppd waits for the Terminate-Ack; supervise-daemon's default
#     5 s kill used to come before pppd gave up and sent the PADT (mr-pppoe: retry + lcp-max-terminate 1).
NAME=15-pppoe-reboot-padt
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"
WAN_MAC=52:54:00:$(printf '%02x' "$ID"):01:01
CONSOLE=$(dirname "$LAB_SH")/state/mrlab$ID/console.log
isp_pppds() { ip netns pids "mrlab$ID-isp1" 2> /dev/null | xargs -r ps -o pid=,args= -p 2> /dev/null | awk '/pppd pty/ {print $1}'; }
# ended_cleanly <wire lines before the reboot> <mac>: after them the router sent an LCP Terminate-Request and a PADT
# for that MAC, and the PADT came before the MAC's next PADI (the session was ended, not just dropped by the reboot)
ended_cleanly() {
	wire | tail -n +"$(($1 + 1))" | awk -v m="$2" '
		$2 == "LCP-TERM-REQ" && $3 == "from=" m { term = 1 }
		$2 == "PADT" && $3 == "from=" m && !padi { padt = 1 }
		$2 == "PADI" && $3 == "from=" m { padi = 1 }
		END { exit !(term && padt) }'
}
both_public() { [ -n "$(wan_addr pppoe-wan)" ] && [ -n "$(wan_addr pppoe-wan2)" ] && lab console "$ID" "ip -4 addr show pppoe-wan2 | grep -q 'inet 203.0.113.'"; }
# the last shutdown: line numbers in the serial console
stopped_before() { # <first message> <second message>
	a=$(grep -n "$1" "$CONSOLE" | tail -n 1 | cut -d: -f1)
	b=$(grep -n "$2" "$CONSOLE" | tail -n 1 | cut -d: -f1)
	[ -n "$a" ] && [ -n "$b" ] && [ "$a" -lt "$b" ]
}

step lab reset "$ID"
step lab isp "$ID" 1 pppoe --echo
check "install.sh completes (wan: PPPoE)" lab install "$ID" --wan-proto pppoe
step lab lan "$ID" dhcp
check "API: wan2, a second PPPoE session on the same port (own MAC)" \
	lab change "$ID" "[{\"op\":\"add\",\"path\":\"wan\",\"value\":$(wan2_json 0)}]"
check "both lines have a public address" retry 90 both_public

# A) a responsive ISP
base=$(wire | wc -l)
step lab reboot "$ID"
check "A: wan's session ended with LCP Terminate + PADT" ended_cleanly "$base" "$WAN_MAC"
check "A: wan2's session ended with LCP Terminate + PADT" ended_cleanly "$base" "$WAN2_MAC"
check "A: mr-pppoe.wan2 was stopped before the firewall was unloaded" stopped_before "Stopping mr-pppoe.wan2" "Unloading firewall"
check "A: both lines are back with public addresses" retry 120 both_public

# B) an ISP that does not answer the Terminate-Request
pids=$(isp_pppds)
note "ISP pppd pids frozen: $pids"
# shellcheck disable=SC2086
step kill -STOP $pids
base=$(wire | wc -l)
step lab reboot "$ID"
# shellcheck disable=SC2086
step kill -CONT $pids
info sh -c "wire() { cat '$ISP_DIR/pppoe-wire.log'; }; wire | tail -n +$((base + 1)) | head -20"
check "B: wan's session ended with PADT although the ISP never answered" ended_cleanly "$base" "$WAN_MAC"
check "B: wan2's session ended with PADT although the ISP never answered" ended_cleanly "$base" "$WAN2_MAC"
check "B: both lines are back with public addresses" retry 120 both_public
finish
