#!/bin/sh
# DNS unblock: ISP block page / private sinkhole are retried through a second DNS daemon.
NAME=10-dns-unblock
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

step lab reset "$ID"
step lab isp "$ID" 1 dhcp \
  --address blocked.test=125.26.170.3 \
  --address private.test=10.10.10.10 \
  --nxdomain empty.test \
  --trusted blocked.test=198.51.100.53 \
  --trusted private.test=198.51.100.54 \
  --trusted empty.test=198.51.100.55
check "install.sh completes on the DHCP WAN" lab install "$ID" --wan-proto dhcp
step lab lan "$ID" dhcp

PATCH='[{"op":"set","path":"dns.upstream","value":"isp"},{"op":"set","path":"dns.unblock","value":{"enabled":true,"block_ips":["125.26.170.3"],"retry_private":true,"retry_empty":true,"fallback":"custom","protocol":"udp","server":"10.1.1.2#5353"}}]'
retry 30 lab change "$ID" "$PATCH"
check "blocked.test uses trusted DNS" lab lan "$ID" exec 'getent hosts blocked.test | grep -q "198.51.100.53"'
check "private.test uses trusted DNS" lab lan "$ID" exec 'getent hosts private.test | grep -q "198.51.100.54"'
check "normal ISP answer is unchanged" lab lan "$ID" exec 'getent hosts isp.test | grep -q "10.1.1.1"'
check "empty answer remains NXDOMAIN when both resolvers have no address" lab lan "$ID" exec '! getent hosts empty.test'
check "LAN DNS survives helper stop" lab console "$ID" 'rc-service mr-dns-unblock stop'
check "ISP DNS still answers after helper stop" lab lan "$ID" exec 'getent hosts isp.test | grep -q "10.1.1.1"'

retry 30 lab change "$ID" '[{"op":"set","path":"dns.unblock.enabled","value":false}]'
check "disabling restores the ISP block-page answer" lab lan "$ID" exec 'getent hosts blocked.test | grep -q "125.26.170.3"'
finish
