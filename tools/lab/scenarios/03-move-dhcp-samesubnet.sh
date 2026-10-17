#!/bin/sh
# Moving house: PPPoE today, tomorrow a modem that hands out 192.168.1.0/24 — the router's own LAN.
# The WAN is switched with the panel API only. Phase 1: the modem is 192.168.1.254 (#138: the
# router reaches it with a /32 route + proxy ARP). Phase 2: the modem takes 192.168.1.1, the
# router's own LAN address — nothing can reach that page; the router must say how to get out.
NAME=03-move-dhcp-samesubnet
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"
online() { lab lan "$ID" dhcp && lab lan "$ID" exec 'curl -4 -fsS -o /dev/null --max-time 10 http://example.com/'; }
modem_page() { lab lan "$ID" exec "curl -s --max-time 5 http://$1/ | grep -q 'Directory listing'"; }
step lab reset "$ID"
step lab isp "$ID" 1 pppoe
check "install.sh completes (PPPoE WAN)" lab install "$ID" --wan-proto pppoe
check "baseline: LAN client online over PPPoE" online
step lab isp "$ID" 1 dhcp --subnet 192.168.1.0/24 --gw 254
check "panel API switches the WAN to DHCP (confirmed)" lab change "$ID" '[{"op":"set","path":"wan[wan].proto","value":"dhcp"},{"op":"del","path":"wan[wan].username"},{"op":"del","path":"wan[wan].password_secret"}]'
info lab console "$ID" 'ip -br addr; ip -4 route; ip neigh show proxy'
check "modem .254: router got a WAN lease in 192.168.1.0/24" lab console "$ID" 'ip -4 addr show eth0 | grep -q "inet 192.168.1."'
check "modem .254: router still answers the LAN client on 192.168.1.1" retry 60 lab lan "$ID" exec 'curl -fsS -o /dev/null --max-time 5 http://192.168.1.1/'
check "modem .254: LAN client renews and is online" retry 60 online
check "modem .254: LAN client opens the modem page 192.168.1.254" retry 30 modem_page 192.168.1.254
check "modem .254: mr doctor warns that upstream and LAN share a subnet" lab console "$ID" 'mr doctor 2>&1 | grep -q "upstream and LAN share a subnet"'
# phase 2: the modem renumbers itself to the router's LAN address; the router renews its lease
step lab isp "$ID" 1 dhcp --subnet 192.168.1.0/24 --gw 1
step lab console "$ID" 'rc-service mr-udhcpc.wan restart; sleep 8; ip -4 route'
# shellcheck disable=SC2016
check "modem .1: 192.168.1.1 is still the router for the LAN client" retry 60 lab lan "$ID" exec 'p=$(curl -fsS --max-time 5 http://192.168.1.1/) && ! printf %s "$p" | grep -q "Directory listing"'
check "modem .1: LAN client is online" retry 60 online
check "modem .1: mr doctor says to move the LAN to another range" lab console "$ID" 'mr doctor 2>&1 | grep -q "change LAN to another range"'
finish
