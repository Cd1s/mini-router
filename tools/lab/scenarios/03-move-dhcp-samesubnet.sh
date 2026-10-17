#!/bin/sh
# Moving house: PPPoE today, tomorrow a modem that hands out 192.168.1.0/24 — the router's own LAN.
# The WAN is switched with the panel API only. Diagnostic: product failures are reported as found.
NAME=03-move-dhcp-samesubnet
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"
step lab reset "$ID"
step lab isp "$ID" 1 pppoe
check "install.sh completes (PPPoE WAN)" lab install "$ID" --wan-proto pppoe
check "baseline: LAN client online over PPPoE" sh -c "\"$LAB_SH\" lan $ID dhcp && \"$LAB_SH\" lan $ID exec 'curl -4 -fsS -o /dev/null --max-time 10 http://example.com/'"
step lab isp "$ID" 1 dhcp --subnet 192.168.1.0/24
check "panel API switches the WAN to DHCP (confirmed)" lab change "$ID" '[{"op":"set","path":"wan[wan].proto","value":"dhcp"},{"op":"del","path":"wan[wan].username"},{"op":"del","path":"wan[wan].password_secret"}]'
step lab console "$ID" 'ip -br addr; ip -4 route; mr status 2>&1 | head -30'
check "router still answers the LAN client on 192.168.1.1" retry 60 lab lan "$ID" exec 'curl -fsS -o /dev/null --max-time 5 http://192.168.1.1/'
check "router got a WAN lease from the same-subnet modem" lab console "$ID" 'ip -4 addr show eth0 | grep -q "inet 192.168.1."'
check "LAN client renews and is online again" retry 60 sh -c "\"$LAB_SH\" lan $ID dhcp && \"$LAB_SH\" lan $ID exec 'curl -4 -fsS -o /dev/null --max-time 10 http://example.com/'"
check "router warns that WAN and LAN are the same subnet (mr doctor)" lab console "$ID" 'mr doctor 2>&1 | grep -iE "overlap|same (sub)?net|conflict|重叠|冲突"'
# shellcheck disable=SC2016
check "router has one route for 192.168.1.0/24 (no WAN/LAN duplicate)" lab console "$ID" 'test "$(ip -4 route show 192.168.1.0/24 | wc -l)" = 1'
check "LAN client reaches the modem's own page (upstream 192.168.1.1)" lab lan "$ID" exec 'curl -s --max-time 5 http://192.168.1.1/ | grep -q "Directory listing"'
finish
