#!/bin/sh
# temporary inspection (not committed)
R=/root/build/mini-router-platform/m3/w/rootfs
docker run --rm --platform linux/arm64 -v "$R:/r:ro" alpine:3.24 sh -c '
for p in ifupdown-ng iproute2-tc iproute2-ss libelf libpcap hiredis gmp readline libncursesw scanelf openrc-user utmps-libs libxtables protobuf-c; do
  echo "$p <- $(apk --root /r info -r $p 2>/dev/null | grep -v "required by\|^$" | tr "\n" " ")"
done
apk --root /r info -s iproute2-tc libelf libxtables ifupdown-ng 2>/dev/null | grep -v "^$"
'
