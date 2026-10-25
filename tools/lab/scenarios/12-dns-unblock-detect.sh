#!/bin/sh
# Read-only dns.unblock detection: repeated ISP block-page address and UDP/53 interception.
NAME=12-dns-unblock-detect
. "$(dirname "$0")/lib.sh"

step lab reset "$ID"
step lab isp "$ID" 1 dhcp \
	--address blocked-a.test=125.26.170.3 \
	--address blocked-b.test=125.26.170.3 \
	--address detect-normal.test=1.1.1.88 \
	--trusted blocked-a.test=1.1.1.53 \
	--trusted blocked-b.test=1.1.1.54 \
	--trusted detect-normal.test=1.1.1.88
check "install.sh completes on the DHCP WAN" lab install "$ID" --wan-proto dhcp
step lab lan "$ID" dhcp

TRUSTED="10.$ID.1.2"
PATCH="[{\"op\":\"set\",\"path\":\"dns.upstream\",\"value\":\"isp\"},{\"op\":\"set\",\"path\":\"dns.unblock\",\"value\":{\"enabled\":false,\"block_ips\":[],\"retry_private\":true,\"retry_empty\":true,\"fallback\":\"custom\",\"protocol\":\"udp\",\"server\":\"$TRUSTED\"}}]"
retry 30 lab change "$ID" "$PATCH"
check "detect finds the repeated ISP block-page address" lab console "$ID" 'mr dns unblock detect --json blocked-a.test blocked-b.test detect-normal.test >/tmp/unblock-detect.json && grep -q '"125.26.170.3"' /tmp/unblock-detect.json && grep -q "blocked-a.test" /tmp/unblock-detect.json && grep -q "blocked-b.test" /tmp/unblock-detect.json'
check "a single CDN answer is not marked blocked" lab console "$ID" "! grep -q 'detect-normal.test.*\\\"verdict\\\":\\\"屏蔽\\\"' /tmp/unblock-detect.json"

step lab isp "$ID" 1 dhcp \
	--address blocked-a.test=125.26.170.3 \
	--address blocked-b.test=125.26.170.3 \
	--address detect-normal.test=1.1.1.88 \
	--trusted blocked-a.test=1.1.1.53 \
	--trusted blocked-b.test=1.1.1.54 \
	--trusted detect-normal.test=1.1.1.88 \
	--hijack53
PATCH_BLOCK="[{\"op\":\"set\",\"path\":\"dns.unblock.block_ips\",\"value\":[\"125.26.170.3\"]}]"
retry 30 lab change "$ID" "$PATCH_BLOCK"
check "detect identifies UDP/53 interception" lab console "$ID" "mr dns unblock detect --json blocked-a.test blocked-b.test >/tmp/unblock-detect-hijack.json && grep -q '\"intercepted\": true' /tmp/unblock-detect-hijack.json"
finish
