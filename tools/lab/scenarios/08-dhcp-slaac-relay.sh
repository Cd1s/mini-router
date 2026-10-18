#!/bin/sh
# DHCP WAN with an upstream SLAAC /64 and no DHCPv6-PD: relay that /64 to the LAN.
# No neighbour is planted by hand: the client only sends traffic, the router's cron run probes and
# proxies it. Also: default deny stays for inbound connections, and LAN hosts that claim an upstream
# address (one that answers ping, one that ignores it) are never proxied.
NAME=08-dhcp-slaac-relay
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"
P=2001:db8:$ID:1
isp_ns=mrlab$ID-isp1
cron() { lab console "$ID" 'mr net ipv6-relay --cron'; }
proxied() { lab console "$ID" "ip -6 neigh show proxy | grep -q '^$1 '"; }
# verdict keys are "<WAN device> <address>"
verdict_is() { lab console "$ID" "grep -q ' $1\":{\"result\":\"$2\"' /run/mini-router/ipv6-relay-probe.json"; }
cron_until_occupied() { cron >/dev/null; verdict_is "$1" occupied; }
step lab reset "$ID"
step lab isp "$ID" 1 dhcp v6=slaac
step lab install "$ID" --wan-proto dhcp
step lab lan "$ID" dhcp
step lab change "$ID" '[{"op":"set","path":"wan[wan].ipv6_pd","value":false}]'
step lab change "$ID" '[{"op":"set","path":"wan[wan].ipv6_relay","value":true}]'
check "relay puts the SLAAC prefix on br-lan" retry 60 lab console "$ID" "ip -6 addr show dev br-lan scope global | grep -q '$P:'"
step lab lan "$ID" dhcp
check "LAN client gets the relayed global IPv6 address" retry 30 lab lan "$ID" exec "ip -6 addr show scope global -tentative | grep -q '$P:'"
client_v6=$(lab lan "$ID" exec "ip -6 -o addr show scope global | awk 'NR==1{print \$4}' | cut -d/ -f1")
relay_addr=$(lab console "$ID" "ip -6 -o addr show dev br-lan scope global | awk 'NR==1{print \$4}' | cut -d/ -f1")
note "client $client_v6, router relay address $relay_addr"
# the client's ordinary traffic makes the router learn its global address; nothing is planted
info lab lan "$ID" exec "ping6 -c 1 -W 3 $relay_addr"
step cron
check "cron probed the client's address: verdict free" verdict_is "$client_v6" free
check "the client is proxied on the WAN" retry 70 proxied "$client_v6"
info lab console "$ID" 'ip -6 route; ip -6 neigh show proxy; cat /run/mini-router/ipv6-relay.json; echo; cat /run/mini-router/ipv6-relay-probe.json'
check "LAN client pings the ISP-side IPv6 endpoint" lab lan "$ID" exec "ping6 -c 2 -W 3 2001:db8:$ID:99::2"
# from the ISP's other /64: hosts of the relayed /64 itself are on-link for LAN clients (docs: limitation)
check "the ISP side reaches the LAN client (echo through the proxy)" ip netns exec "$isp_ns" ping -6 -c 2 -W 3 -I "2001:db8:$ID:99::2" "$client_v6"

# inbound connections stay default-deny, as with PD
lab lan "$ID" exec "cd /tmp && exec python3 -m http.server 8080 --bind :: >/dev/null 2>&1" &
srv=$!
sleep 2
check "the router reaches the client's port 8080 (listener up)" lab console "$ID" "wget -q -T 5 -O /dev/null http://[$client_v6]:8080/"
check "the ISP side cannot open the client's port 8080 (default deny)" sh -c "! ip netns exec $isp_ns curl -6 -s --max-time 5 -o /dev/null http://[$client_v6]:8080/"
kill "$srv" 2>/dev/null; lab lan "$ID" exec 'pkill -f "http.server 8080"' || true

# a LAN host that claims the ISP's own address (answers ping) is never proxied
# the client forgets the router's relay address so its next NS carries the claimed source address
step lab lan "$ID" exec "ip -6 addr add $P::2/64 dev mrlab${ID}slp nodad"
info lab lan "$ID" exec "ip -6 neigh del $relay_addr dev mrlab${ID}slp; ping6 -c 1 -W 3 -I $P::2 $relay_addr"
step cron
check "claimed upstream address $P::2: verdict occupied" retry 70 cron_until_occupied "$P::2"
not_proxied() { ! proxied "$1"; }
check "claimed upstream address $P::2 is not proxied" not_proxied "$P::2"
step lab lan "$ID" exec "ip -6 addr del $P::2/64 dev mrlab${ID}slp"
# ... nor one that ignores ping (it still answers neighbour solicitations)
step ip netns exec "$isp_ns" sh -c "ip -6 addr add $P::3/64 dev mrlab${ID}s1p nodad && sysctl -q -w net.ipv6.icmp.echo_ignore_all=1"
step lab lan "$ID" exec "ip -6 addr add $P::3/64 dev mrlab${ID}slp nodad"
info lab lan "$ID" exec "ip -6 neigh del $relay_addr dev mrlab${ID}slp; ping6 -c 1 -W 3 -I $P::3 $relay_addr"
check "upstream address ignoring ping ($P::3): verdict occupied" retry 70 cron_until_occupied "$P::3"
check "upstream address ignoring ping is not proxied" not_proxied "$P::3"
step lab lan "$ID" exec "ip -6 addr del $P::3/64 dev mrlab${ID}slp"
step ip netns exec "$isp_ns" sh -c "sysctl -q -w net.ipv6.icmp.echo_ignore_all=0; ip -6 addr del $P::3/64 dev mrlab${ID}s1p"
check "the real client stays proxied" proxied "$client_v6"

step lab change "$ID" '[{"op":"set","path":"wan[wan].ipv6_relay","value":false}]'
check "disabling relay deprecates the LAN prefix" retry 30 lab console "$ID" "ip -6 addr show dev br-lan scope global | grep -q '$P:.*deprecated'"
check "disabling relay removes every proxy entry and relay host route" lab console "$ID" "! ip -6 neigh show proxy | grep -q . && ! ip -6 route | grep -q '^$P:.* proto static metric 50'"
finish
