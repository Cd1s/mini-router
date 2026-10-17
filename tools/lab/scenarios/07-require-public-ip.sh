#!/bin/sh
# wan[].require_public_ip (#150): the ISP hands out CGNAT addresses (100.64.<id>.x); with the option
# on, the router redials after the gap (cron re-check), stops after 5 private addresses with a risk
# event, and takes a public address again when the ISP offers one.
NAME=07-require-public-ip
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"
sessions() { grep -c "^remote IP address" "$(dirname "$LAB_SH")/state/mrlab$ID/isp1/pppd.log" 2>/dev/null || echo 0; }
more_sessions() { [ "$(sessions)" -gt "$1" ]; }
step lab reset "$ID"
step lab isp "$ID" 1 pppoe --cgnat
check "install.sh completes (PPPoE WAN behind CGNAT)" lab install "$ID" --wan-proto pppoe
step lab lan "$ID" dhcp
check "router has a CGNAT address (100.64.$ID.x)" lab console "$ID" "ip -4 addr show pppoe-wan | grep -q 'inet 100.64.$ID.'"
before=$(sessions)
note "PPPoE sessions before: $before"
check "API: require_public_ip on, gap 30 s (confirmed)" lab change "$ID" '[{"op":"set","path":"wan[wan].require_public_ip","value":true},{"op":"set","path":"wan[wan].require_public_ip_gap","value":30}]'
check "crontab has the public-check line" lab console "$ID" 'grep -q "mr wan public-check --cron" /etc/crontabs/root'
check "router redials (a new PPPoE session at the ISP within 150 s)" retry 150 more_sessions "$before"
check "syslog: 'cgnat IPv4 address; redial N/4'" retry 60 lab console "$ID" 'grep -qE "wan wan: .*IPv4 address; redial [0-9]/4" /var/log/messages'
check "after 5 private addresses: redial stops with a risk event" retry 420 lab console "$ID" 'mr event list 2>&1 | grep -q "automatic redial stopped"'
n1=$(sessions)
sleep 90
check "stopped: no further redials (sessions stay at $n1)" sh -c "[ \"\$(grep -c '^remote IP address' '$(dirname "$LAB_SH")/state/mrlab$ID/isp1/pppd.log')\" -le $((n1 + 0)) ]"
# a CGNAT session that passes the health check is "ok" in mr doctor by design (#150); the stop is
# recorded as the risk event above
info lab console "$ID" 'mr doctor 2>&1 | grep -A1 "wan.wan"'
info lab console "$ID" 'grep -E "public|redial" /var/log/messages | tail -12; cat /run/mini-router/*public* 2>/dev/null'
step lab isp "$ID" 1 pppoe
check "ISP offers public addresses again: router gets 203.0.113.x" retry 120 lab console "$ID" "ip -4 addr show pppoe-wan | grep -q 'inet 203.0.113.'"
check "LAN client online over the public session" retry 60 sh -c "\"$LAB_SH\" lan $ID dhcp >/dev/null && \"$LAB_SH\" lan $ID exec 'curl -4 -fsS -o /dev/null --max-time 10 http://example.com/'"
finish
