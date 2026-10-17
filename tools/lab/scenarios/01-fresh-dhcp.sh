#!/bin/sh
# A fresh Alpine machine behind a DHCP modem: install.sh, then everything a LAN user expects.
NAME=01-fresh-dhcp
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"
step lab reset "$ID"
step lab isp "$ID" 1 dhcp
check "install.sh completes on a fresh Alpine (DHCP WAN)" lab install "$ID" --wan-proto dhcp
check "LAN client gets a DHCP lease from the router" lab lan "$ID" dhcp
check "LAN client resolves a public name" lab lan "$ID" exec 'getent hosts example.com'
check "LAN client reaches the IPv4 internet" lab lan "$ID" exec 'curl -4 -fsS -o /dev/null --max-time 10 http://example.com/'
# shellcheck disable=SC2016
check "panel answers 200 on http://192.168.1.1/" lab lan "$ID" exec 'test "$(curl -s -o /dev/null -w %{http_code} --max-time 5 http://192.168.1.1/)" = 200'
check "panel API: login and status" sh -c "\"$LAB_SH\" api $ID GET status | grep -q '\"wan\"'"
finish
