#!/bin/sh
# DHCP WAN with an upstream SLAAC /64 and no DHCPv6-PD: relay that /64 to the LAN.
NAME=08-dhcp-slaac-relay
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"
step lab reset "$ID"
step lab isp "$ID" 1 dhcp v6=slaac
step lab install "$ID" --wan-proto dhcp
step lab lan "$ID" dhcp
step lab change "$ID" '[{"op":"set","path":"wan[wan].ipv6_pd","value":false}]'
step lab change "$ID" '[{"op":"set","path":"wan[wan].ipv6_relay","value":true}]'
check "relay puts the SLAAC prefix on br-lan" retry 60 lab console "$ID" 'ip -6 addr show dev br-lan scope global | grep -q "2001:db8:'"$ID"':1"'
step lab lan "$ID" dhcp
check "LAN client gets the relayed global IPv6 address" retry 30 lab lan "$ID" exec 'ip -6 addr show scope global | grep -q "2001:db8:'"$ID"':1"'
client_v6=$(lab lan "$ID" exec "ip -6 -o addr show scope global | awk 'NR==1{print \$4}' | cut -d/ -f1")
client_mac=$(lab lan "$ID" exec "cat /sys/class/net/mrlab${ID}slp/address")
step lab console "$ID" "ip -6 neigh replace $client_v6 lladdr $client_mac dev br-lan"
step lab console "$ID" 'mr net ipv6-relay --cron'
step lab console "$ID" 'mr net ipv6-relay --cron'
info lab console "$ID" 'ip -6 route; ip -6 neigh show proxy; cat /run/mini-router/ipv6-relay.json'
check "LAN client pings the ISP-side IPv6 endpoint" lab lan "$ID" exec "ping6 -c 2 -W 3 2001:db8:$ID:99::2"
step lab change "$ID" '[{"op":"set","path":"wan[wan].ipv6_relay","value":false}]'
check "disabling relay deprecates the LAN prefix" retry 30 lab console "$ID" 'ip -6 addr show dev br-lan scope global | grep -q "2001:db8:'"$ID"':1.*deprecated"'
finish
