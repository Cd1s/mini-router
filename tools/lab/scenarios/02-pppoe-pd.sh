#!/bin/sh
# A fresh Alpine machine on PPPoE with DHCPv6 prefix delegation (/60 from 2001:db8:<id>:100::/56).
NAME=02-pppoe-pd
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"
step lab reset "$ID"
step lab isp "$ID" 1 pppoe v6=pd
check "install.sh completes on a fresh Alpine (PPPoE WAN)" lab install "$ID" --wan-proto pppoe
check "router's PPPoE session is up" lab console "$ID" 'ip -4 addr show pppoe-wan | grep -q "inet 203.0.113."'
check "router receives a delegated prefix" retry 90 lab console "$ID" 'ip -6 addr show dev br-lan scope global | grep -q "2001:db8:'"$ID"':1"'
check "LAN client gets a DHCP lease" lab lan "$ID" dhcp
check "LAN client reaches the IPv4 internet over PPPoE" lab lan "$ID" exec 'curl -4 -fsS -o /dev/null --max-time 10 http://example.com/'
check "LAN client resolves names" lab lan "$ID" exec 'getent hosts example.com'
check "LAN client gets a global IPv6 address from the delegated prefix" retry 60 lab lan "$ID" exec 'ip -6 addr show scope global -tentative | grep -q "inet6 2001:db8:'"$ID"':1"'
check "LAN client pings the ISP over IPv6" lab lan "$ID" exec "ping6 -c 2 -W 3 2001:db8:$ID:1::1"
finish
