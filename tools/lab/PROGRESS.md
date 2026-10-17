# Lab progress

This file records milestones for the fresh-environment lab. Add one dated line after each
milestone and commit it with the corresponding implementation change.

- [x] 2026-10-17 image: Alpine 3.24 x86_64 cloud qcow2 downloaded on demand; per-lab qcow2 overlay/reset implemented.
- [x] 2026-10-17 topology: per-lab switch, ISP and LAN namespaces with QEMU taps; teardown removes mrlab-only objects.
- [x] 2026-10-17 host safety: per-namespace resolv.conf, private udhcpc script, host guard on /etc/resolv.conf, /etc/hosts, /etc/ppp.
- [x] 2026-10-17 real install: unmodified install.sh after boot, signed offline apk mirror, no apk stub or fallbacks (A1c).
- [x] 2026-10-17 product bug found: install.sh rolls back on every WiFi-less machine (mr-hostapd); fixed in PR #143.
- [x] 2026-10-17 lts base image (linux-virt has no PPPoE); virtio-serial agent console; PPPoE + kea DHCPv6-PD ISP.
- [x] 2026-10-17 scenarios 01–05 rewritten on scenarios/lib.sh: 01 6/6, 02 8/8, 04 8/8 ok; 03 7/9 and 05 5/6 report product issues.
- [x] 2026-10-17 merged main (#132 #134 #138 #141 #143); daemons never use host config/services (dnsmasq --conf-file=/dev/null, kea with a private /run).
- [x] 2026-10-17 found: #138 made every fresh install roll back (/run/mini-router missing); 03 reworked for #138 (modem .254 and .1). main + fix: 01 6/6, 02 8/8, 03 11/11, 04 8/8, 05 5/6.
