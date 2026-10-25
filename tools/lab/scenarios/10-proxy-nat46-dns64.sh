#!/bin/sh
# NAT46/DNS64 integration: the ISP simulator must return A + NOERROR/NODATA for isp.test so
# unbound's DNS64 module can synthesize 64:ff9b::cb00:7107 from 203.0.113.7.
NAME=10-proxy-nat46-dns64
. "$(dirname "$0")/lib.sh"
step lab reset "$ID"
step lab isp "$ID" 1 static
step lab install "$ID" --wan-proto static
step lab console "$ID" 'apk add unbound >/dev/null'
step lab console "$ID" 'printf "{\"inbounds\":[],\"outbounds\":[]}\n" > /etc/mini-router/proxy-extra.json'
step lab console "$ID" "/usr/sbin/mr set proxy.enabled=true proxy.extra_config=/etc/mini-router/proxy-extra.json proxy.nat46.enabled=true proxy.nat46.dns64.enabled=true dns.upstream=manual dns.servers=[10.$ID.1.1] dns.unblock.enabled=false >/dev/null"
step lab console "$ID" '/usr/sbin/mr render /tmp/mr-render >/dev/null; cp /tmp/mr-render/etc/mini-router/gen/dns64.conf /etc/mini-router/gen/dns64.conf; cp /tmp/mr-render/etc/mini-router/gen/nat46.json /etc/mini-router/gen/nat46.json; /usr/sbin/mr proxy nat46 dns64-sync >/dev/null; rc-service mr-dns64 status'
check "ISP DNS serves the A record" lab console "$ID" "nslookup isp.test 10.$ID.1.1 | grep -q \"Address: 203.0.113.7\""
check "built-in DNS64 synthesizes the AAAA record" lab console "$ID" 'nslookup -type=AAAA -port=1153 isp.test 127.0.0.1 | grep -qi "64:ff9b::cb00:7107"'
finish
