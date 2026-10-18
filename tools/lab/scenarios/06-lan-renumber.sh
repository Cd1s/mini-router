#!/bin/sh
# Changing the LAN subnet from the web UI (#153): 192.168.1.1/24 -> 192.168.1.6/24 (same subnet) ->
# 192.168.2.1/24. The change is confirmed on the new address with the one-time token, the client
# renews, and the change must still be there after the 120 s confirm window.
NAME=06-lan-renumber
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"
# shellcheck disable=SC2016
panel_on() { lab lan "$ID" exec "test \"\$(curl -s -o /dev/null -w %{http_code} --max-time 5 http://$1/)\" = 200"; }
lan_is() { lab console "$ID" "grep -q '^  ipv4: $1\$' /etc/mini-router/router.yaml && ip -4 -o addr show br-lan | grep -q ' $1 '"; }
step lab reset "$ID"
step lab isp "$ID" 1 dhcp
check "install.sh completes (DHCP WAN)" lab install "$ID" --wan-proto dhcp
check "baseline: client online via 192.168.1.1" sh -c "\"$LAB_SH\" lan $ID dhcp && \"$LAB_SH\" lan $ID exec 'curl -4 -fsS -o /dev/null --max-time 10 http://example.com/'"
check "API: LAN 192.168.1.1 -> 192.168.1.6 confirmed on the new address" lab change "$ID" '[{"op":"set","path":"lan.ipv4","value":"192.168.1.6/24"}]'
check ".6: panel answers on 192.168.1.6" retry 30 panel_on 192.168.1.6
check ".6: 192.168.1.1 is gone from br-lan" lab console "$ID" '! ip -4 -o addr show br-lan | grep -q " 192.168.1.1/"'
check ".6: client renewed, gateway 192.168.1.6, online" retry 30 sh -c "\"$LAB_SH\" lan $ID dhcp >/dev/null && \"$LAB_SH\" lan $ID exec 'ip -4 route show default | grep -q \"via 192.168.1.6 \" && curl -4 -fsS -o /dev/null --max-time 10 http://example.com/'"
sleep 130
check ".6: still applied after the confirm window (no rollback)" lan_is 192.168.1.6/24
check "API: LAN 192.168.1.6 -> 192.168.2.1 confirmed on the new address" lab change "$ID" '[{"op":"set","path":"lan.ipv4","value":"192.168.2.1/24"}]'
check "2.1: client lease in 192.168.2.0/24, gateway 192.168.2.1" retry 30 sh -c "\"$LAB_SH\" lan $ID dhcp | grep -q '\"addr\":\"192.168.2.' && \"$LAB_SH\" lan $ID exec 'ip -4 route show default | grep -q \"via 192.168.2.1 \"'"
check "2.1: panel answers on 192.168.2.1" retry 30 panel_on 192.168.2.1
check "2.1: client online and resolves names" retry 30 sh -c "\"$LAB_SH\" lan $ID exec 'getent hosts example.com >/dev/null && curl -4 -fsS -o /dev/null --max-time 10 http://example.com/'"
sleep 130
check "2.1: still applied after the confirm window (no rollback)" lan_is 192.168.2.1/24
check "2.1: no old address left on br-lan" lab console "$ID" '! ip -4 -o addr show br-lan | grep -qE " 192\.168\.1\.(1|6)/"'
check "2.1: API works on the new address (login + status)" sh -c "\"$LAB_SH\" api $ID GET status | grep -q '\"wan\"'"
finish
