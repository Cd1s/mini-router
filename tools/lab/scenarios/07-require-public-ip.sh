#!/bin/sh
# wan[].require_public_ip (#150): AIS puts the PPPoE sessions over its concurrent-session limit into a
# walled garden (100.64.<id>.x, up but dead) until the old sessions time out. The guard redials only the
# line that has a private address, backs off (the plain gap for four redials, then x2 up to 15 minutes),
# never gives up, never touches the line that has a public address, and `mr doctor` says it is waiting.
# Test configuration: gap 2 s (the backoff is 2 2 2 4 8 16 ...) and a guest ticker that runs the
# cron check every 4 s instead of once a minute; the ISP walls the first 7 dials of wan2's session MAC.
NAME=07-require-public-ip
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"
GAP=2
WALLED=7
WAN_MAC=52:54:00:$(printf '%02x' "$ID"):01:01
wan2_dials() { grep -c "mac=$WAN2_MAC" "$ISP_DIR/dials.log" 2> /dev/null || true; }
dials_ge() { [ "$(wan2_dials)" -ge "$1" ]; }
# dial times of wan2: t1 = the first dial, t2.. = redials; a redial n waits at least wait(n) before the next one
backoff_ok() {
	grep "mac=$WAN2_MAC" "$ISP_DIR/dials.log" | awk -v gap="$GAP" '{ t[NR] = $1 }
		END { if (NR < 8) { print "only " NR " dials"; exit 1 }
			w = gap; ok = 1
			for (n = 4; n <= 6; n++) { w *= 2; d = t[n + 2] - t[n + 1]; printf "wait after redial %d: %d s (>= %d)\n", n, d, w - 1; if (d < w - 1) ok = 0 }
			exit !ok }'
}
doctor_waiting() { lab console "$ID" 'mr doctor 2>&1' | grep -E "^WARN +wan.wan2 " | grep -Eq "waiting for the ISP to release a session slot.*redial [0-9]+ done, next in [0-9]+ (s|min)"; }
doctor_no_stop() { ! lab console "$ID" 'mr doctor 2>&1' | grep -Ei "stopped|^RISK +wan\." > /dev/null; }
doctor_wan2_fine() { ! lab console "$ID" 'mr doctor 2>&1' | grep -Eq "^(WARN|RISK) +wan.wan2 "; }
no_wan_frames_since() { [ "$(wire | tail -n +"$(($1 + 1))" | grep -c "from=$WAN_MAC")" -eq 0 ]; }

step lab reset "$ID"
step lab isp "$ID" 1 pppoe --echo --cgnat-dials "$WALLED" --cgnat-mac "$WAN2_MAC"
check "install.sh completes (wan: PPPoE, public address)" lab install "$ID" --wan-proto pppoe
step lab lan "$ID" dhcp
wan_before=$(wan_addr pppoe-wan)
note "wan: $wan_before"
check "API: require_public_ip on wan and on a new wan2, gap $GAP s (confirmed)" \
	lab change "$ID" "[{\"op\":\"set\",\"path\":\"wan[wan].require_public_ip\",\"value\":true},{\"op\":\"set\",\"path\":\"wan[wan].require_public_ip_gap\",\"value\":$GAP},{\"op\":\"add\",\"path\":\"wan\",\"value\":$(wan2_json "$GAP")}]"
check "crontab has the public-check line" lab console "$ID" 'grep -q "mr wan public-check --cron" /etc/crontabs/root'
check "test ticker: the cron check every 4 s" lab console "$ID" 'nohup setsid sh -c "while :; do sleep 4; /usr/sbin/mr wan public-check --cron; done" > /dev/null 2>&1 &'
check "wan2 is up in the walled garden (100.64.x)" retry 120 lab console "$ID" "ip -4 addr show pppoe-wan2 | grep -q 'inet 100.64.'"
base=$(wire | wc -l)
note "ISP wire log: $base frames so far; from here on wan (the public line) must not be touched"
check "mr doctor: wan2 is a warning that waits for the ISP, with the redial count and the next redial" retry 60 doctor_waiting
info lab console "$ID" 'mr doctor 2>&1 | grep -E "^(WARN|RISK) +wan\.wan"'
check "mr doctor: no 'stopped', no risk on a WAN" doctor_no_stop
check "the fast redials are used up and it keeps redialing (wan2 dialled at least 8 times)" retry 420 dials_ge 8
check "wan2 ends up with a public address (203.0.113.x)" retry 120 lab console "$ID" "ip -4 addr show pppoe-wan2 | grep -q 'inet 203.0.113.'"
info sh -c "grep -h 'mac=$WAN2_MAC' '$ISP_DIR/dials.log'"
check "the redials back off: each wait after the fourth redial is at least 2x gap, 4x, 8x" backoff_ok
check "syslog: 'cgnat IPv4 address; redial N, next in S s' beyond the fast phase (N >= 5)" lab console "$ID" 'grep -E "wan wan2: cgnat IPv4 address; redial ([5-9]|[0-9][0-9]), next in [0-9]+ s" /var/log/messages | grep -q .'
check "event: a warning when the fast phase ended" lab console "$ID" 'mr event list 2>&1 | grep -q "redialing continues"'
info lab console "$ID" 'grep -E "redial|wan2" /var/log/messages | tail -30; cat /run/mini-router/require-public-ip.json 2>/dev/null; mr doctor 2>&1 | head -12'
check "the public line was never touched (no PADI / PADT / LCP from wan's MAC at the ISP)" no_wan_frames_since "$base"
check "wan still has the same address" test "$(wan_addr pppoe-wan)" = "$wan_before"
check "the record is gone with the public address" lab console "$ID" '! grep -q wan2 /run/mini-router/require-public-ip.json 2>/dev/null'
check "mr doctor: wan2 is fine again (no warning, no risk)" doctor_wan2_fine
check "LAN client online" retry 60 sh -c "\"$LAB_SH\" lan $ID dhcp >/dev/null && \"$LAB_SH\" lan $ID exec 'curl -4 -fsS -o /dev/null --max-time 10 http://192.0.2.99/'"
finish
