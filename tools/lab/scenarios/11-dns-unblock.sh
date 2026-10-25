#!/bin/sh
# DNS unblock: ISP block page / private sinkhole are retried through a second DNS daemon.
NAME=11-dns-unblock
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

step lab reset "$ID"
step lab isp "$ID" 1 dhcp \
  --address blocked.test=125.26.170.3 \
  --address private.test=10.10.10.10 \
  --address normal.test=1.1.1.99 \
  --address after-stop.test=1.1.1.77 \
  --nxdomain empty.test \
  --nxdomain noanswer.test \
  --trusted blocked.test=1.1.1.53 \
  --trusted private.test=1.1.1.54

# The seeded Alpine mirror only carries sing-box 1.13.11. Serve the static 1.14.1
# test binary from the ISP namespace so this scenario exercises evaluate /
# match_response rather than silently skipping the helper.
SB_PORT=$((18000 + ID))
ip netns exec "mrlab${ID}-isp1" python3 -m http.server "$SB_PORT" --bind "10.$ID.1.1" --directory /tmp >/tmp/mrlab$ID-singbox-http.log 2>&1 &
SB_PID=$!
cleanup_sb() { kill "$SB_PID" 2>/dev/null || true; }
trap 'cleanup_sb; cleanup' EXIT
check "install.sh completes on the DHCP WAN" lab install "$ID" --wan-proto dhcp
step lab console "$ID" "wget -q -O /tmp/sing-box-static http://10.$ID.1.1:$SB_PORT/sing-box-static-1141 && cp /tmp/sing-box-static /usr/bin/sing-box && chmod 0755 /usr/bin/sing-box && /usr/bin/sing-box version"
step lab lan "$ID" dhcp

TRUSTED="10.$ID.1.2"
PATCH="[{\"op\":\"set\",\"path\":\"dns.upstream\",\"value\":\"isp\"},{\"op\":\"set\",\"path\":\"dns.rebind_protection\",\"value\":false},{\"op\":\"set\",\"path\":\"dns.unblock\",\"value\":{\"enabled\":true,\"block_ips\":[\"125.26.170.3\"],\"retry_private\":true,\"retry_empty\":true,\"fallback\":\"custom\",\"protocol\":\"udp\",\"server\":\"$TRUSTED\"}}]"
retry 30 lab change "$ID" "$PATCH"
info lab console "$ID" 'cat /run/mini-router/dns-unblock-upstream.conf 2>&1; grep -E "dns-unblock|resolv-file|server=" /etc/dnsmasq.conf; rc-service mr-dns-unblock status; ss -lunp | grep 5455 || true'
check "blocked.test uses trusted DNS" lab lan "$ID" exec 'getent hosts blocked.test | grep -q "1.1.1.53"'
check "private.test uses trusted DNS" lab lan "$ID" exec 'getent hosts private.test | grep -q "1.1.1.54"'
check "empty answer retries trusted NXDOMAIN" lab lan "$ID" exec '! getent hosts empty.test'
check "empty answer remains NXDOMAIN when both resolvers have no address" lab lan "$ID" exec '! getent hosts noanswer.test'
check "stop helper" lab console "$ID" 'rc-service mr-dns-unblock stop'
check "LAN DNS recovers within 3 seconds after helper stop" lab lan "$ID" exec 't=$(date +%s); getent hosts after-stop.test | grep -q after-stop.test; test $(( $(date +%s) - t )) -le 3'

step lab isp "$ID" 1 dhcp \
  --address blocked.test=125.26.170.3 \
  --address private.test=10.10.10.10 \
  --trusted blocked.test=1.1.1.53 \
  --trusted private.test=1.1.1.54 \
  --hijack53
PATCH_UDP="[{\"op\":\"set\",\"path\":\"dns.unblock\",\"value\":{\"enabled\":true,\"block_ips\":[\"125.26.170.3\"],\"retry_private\":true,\"retry_empty\":true,\"fallback\":\"custom\",\"protocol\":\"udp\",\"server\":\"$TRUSTED\"}}]"
retry 30 lab change "$ID" "$PATCH_UDP"
check "UDP trusted query is intercepted by ISP port-53 hijack" lab lan "$ID" exec 'getent hosts blocked.test | grep -q "125.26.170.3"'
PATCH_TLS="[{\"op\":\"set\",\"path\":\"dns.unblock\",\"value\":{\"enabled\":true,\"block_ips\":[\"125.26.170.3\"],\"retry_private\":true,\"retry_empty\":true,\"fallback\":\"custom\",\"protocol\":\"tls\",\"server\":\"$TRUSTED\"}}]"
retry 30 lab change "$ID" "$PATCH_TLS"
check "TLS path is not affected by UDP port-53 hijack" lab lan "$ID" exec '! getent hosts blocked.test'

retry 30 lab change "$ID" '[{"op":"set","path":"dns.unblock.enabled","value":false}]'
check "disabling restores the ISP block-page answer" lab lan "$ID" exec 'getent hosts blocked.test | grep -q "125.26.170.3"'
finish
