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
info lab console "$ID" 'cat /run/mini-router/resolv-lan.conf 2>&1; grep -E "dns-unblock|resolv-file|server=" /etc/dnsmasq.conf; rc-service mr-dns-unblock status; ss -lunp | grep "127.0.0.2:53" || true'
check "blocked.test uses trusted DNS" retry 20 lab lan "$ID" exec 'getent hosts blocked.test | grep -q "1.1.1.53"'
check "private.test uses trusted DNS" retry 20 lab lan "$ID" exec 'getent hosts private.test | grep -q "1.1.1.54"'
check "empty answer retries trusted NXDOMAIN" lab lan "$ID" exec '! getent hosts empty.test'
check "empty answer remains NXDOMAIN when both resolvers have no address" lab lan "$ID" exec '! getent hosts noanswer.test'
check "reboot keeps DHCP and dnsmasq alive" lab reboot "$ID"
check "DHCP is available after reboot" retry 15 lab lan "$ID" check
check "unblock still works after reboot" retry 20 lab lan "$ID" exec 'getent hosts blocked.test | grep -q "1.1.1.53"'

check "suspend helper" lab console "$ID" 'p=$(pgrep -f "sing-box run.*mr-dns-unblock/config.json" | head -n 1); test -n "$p"; kill -STOP "$p"'
check "helper suspend falls back to ISP within 15 seconds" lab lan "$ID" exec 'for i in $(seq 1 15); do getent hosts after-stop.test 2>/dev/null | grep -q after-stop.test && exit 0; sleep 1; done; exit 1'
check "resume helper" lab console "$ID" 'p=$(pgrep -f "sing-box run.*mr-dns-unblock/config.json" | head -n 1); test -n "$p"; kill -CONT "$p"'
check "helper resumes within 15 seconds and bypasses block page" lab lan "$ID" exec 'for i in $(seq 1 15); do getent hosts blocked.test 2>/dev/null | grep -q "1.1.1.53" && exit 0; sleep 1; done; exit 1'
check "apply preserves helper upstream" lab console "$ID" 'mr apply >/tmp/mr-apply.log 2>&1 || { cat /tmp/mr-apply.log; exit 1; }; grep -q "nameserver 127.0.0.2" /run/mini-router/resolv-lan.conf'
check "apply keeps unblock active" retry 20 lab lan "$ID" exec 'getent hosts blocked.test | grep -q "1.1.1.53"'

step lab isp "$ID" 1 dhcp \
  --address blocked.test=125.26.170.3 \
  --address hijack.test=125.26.170.3 \
  --address private.test=10.10.10.10 \
  --trusted blocked.test=1.1.1.53 \
  --trusted hijack.test=1.1.1.55 \
  --trusted private.test=1.1.1.54 \
  --hijack53
PATCH_UDP="[{\"op\":\"set\",\"path\":\"dns.unblock\",\"value\":{\"enabled\":true,\"block_ips\":[\"125.26.170.3\"],\"retry_private\":true,\"retry_empty\":true,\"fallback\":\"custom\",\"protocol\":\"udp\",\"server\":\"$TRUSTED\"}}]"
retry 30 lab change "$ID" "$PATCH_UDP"
step lab console "$ID" 'rc-service mr-dns-unblock restart'
check "UDP trusted query is intercepted by ISP port-53 hijack" lab lan "$ID" exec 'getent hosts hijack.test | grep -q "125.26.170.3"'
PATCH_TLS="[{\"op\":\"set\",\"path\":\"dns.unblock\",\"value\":{\"enabled\":true,\"block_ips\":[\"125.26.170.3\"],\"retry_private\":true,\"retry_empty\":true,\"fallback\":\"custom\",\"protocol\":\"tls\",\"server\":\"$TRUSTED\"}}]"
retry 30 lab change "$ID" "$PATCH_TLS"
check "TLS path is not affected by UDP port-53 hijack" lab lan "$ID" exec '! getent hosts hijack.test'

step lab isp "$ID" 1 dhcp \
  --address blocked.test=125.26.170.3 \
  --address after-stop.test=1.1.1.77 \
  --trusted blocked.test=1.1.1.53 \
  --trusted after-stop.test=1.1.1.77

PATCH_MANUAL="[{\"op\":\"set\",\"path\":\"dns.upstream\",\"value\":\"manual\"},{\"op\":\"set\",\"path\":\"dns.servers\",\"value\":[\"10.$ID.1.1\"]},{\"op\":\"set\",\"path\":\"dns.unblock\",\"value\":{\"enabled\":true,\"block_ips\":[\"125.26.170.3\"],\"retry_private\":true,\"retry_empty\":true,\"fallback\":\"custom\",\"protocol\":\"udp\",\"server\":\"$TRUSTED\"}}]"
retry 30 lab change "$ID" "$PATCH_MANUAL"
check "manual mode uses helper" retry 20 lab lan "$ID" exec 'getent hosts blocked.test | grep -q "1.1.1.53"'
check "manual mode falls back after helper stop" lab console "$ID" 'rc-service mr-dns-unblock stop'
check "manual mode direct fallback resolves" lab lan "$ID" exec 'for i in $(seq 1 15); do getent hosts after-stop.test 2>/dev/null | grep -q after-stop.test && exit 0; sleep 1; done; exit 1'

retry 30 lab change "$ID" '[{"op":"set","path":"dns.unblock.enabled","value":false}]'
check "disabling restores the ISP block-page answer" lab lan "$ID" exec 'getent hosts blocked.test | grep -q "125.26.170.3"'
finish
