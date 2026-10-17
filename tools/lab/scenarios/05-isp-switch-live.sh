#!/bin/sh
# The ISP changes under a running router (the router config stays PPPoE): outage, recovery, and an
# ISP that silently moves to DHCP. Diagnostic: what the router reports and whether it recovers.
NAME=05-isp-switch-live
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"
online() { lab lan "$ID" exec 'curl -4 -fsS -o /dev/null --max-time 6 http://example.com/'; }
step lab reset "$ID"
step lab isp "$ID" 1 pppoe
check "install.sh completes (PPPoE WAN)" lab install "$ID" --wan-proto pppoe
step lab lan "$ID" dhcp
check "baseline: LAN client online" online
step lab isp "$ID" 1 down
sleep 25
check "outage: mr doctor reports the WAN as a risk" retry 30 lab console "$ID" 'mr doctor 2>&1 | grep -q "^RISK  wan.wan"'
step lab isp "$ID" 1 pppoe
check "ISP back: PPPoE redials and the LAN client is online within 90 s" retry 90 online
step lab isp "$ID" 1 dhcp
sleep 30
info lab console "$ID" 'mr doctor 2>&1 | tail -25; mr status 2>&1 | head -25'
check "ISP moved to DHCP: mr doctor names the cause (no PPPoE server / DHCP on the line)" lab console "$ID" 'mr doctor 2>&1 | grep -iE "pado|no pppoe server|access concentrator|dhcp (offer|server)|改成 dhcp"'
step lab isp "$ID" 1 pppoe
check "ISP back to PPPoE: LAN client online again within 90 s" retry 90 online
finish
