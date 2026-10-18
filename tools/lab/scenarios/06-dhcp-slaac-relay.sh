#!/bin/sh
# DHCP WAN with an upstream SLAAC /64 and no DHCPv6-PD: relay that /64 to the LAN.
NAME=06-dhcp-slaac-relay
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"
step lab reset "$ID"
step lab isp "$ID" 1 dhcp v6=slaac
step lab install "$ID" --wan-proto dhcp
step lab lan "$ID" dhcp
step lab change "$ID" '[{"op":"set","path":"wan[wan].ipv6_pd","value":false},{"op":"set","path":"wan[wan].ipv6_relay","value":true}]'
check "relay puts the SLAAC prefix on br-lan" retry 60 lab console "$ID" 'ip -6 addr show dev br-lan scope global | grep -q "2001:db8:'"$ID"':1"'
step lab lan "$ID" dhcp
check "LAN client gets the relayed global IPv6 address" retry 30 lab lan "$ID" exec 'ip -6 addr show scope global | grep -q "2001:db8:'"$ID"':1"'
check "LAN client pings the SLAAC ISP address" lab lan "$ID" exec "ping6 -c 2 -W 3 2001:db8:$ID:1::1"
step lab change "$ID" '[{"op":"set","path":"wan[wan].ipv6_relay","value":false}]'
check "disabling relay removes the LAN prefix" retry 30 lab console "$ID" '! ip -6 addr show dev br-lan scope global | grep -q "2001:db8:'"$ID"':1"'
finish
