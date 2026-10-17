# Lab progress

This file records milestones for the fresh-environment lab. Add one dated line after each
milestone and commit it with the corresponding implementation change.

- [x] 2026-10-17 image: Alpine 3.24 x86_64 cloud qcow2 downloaded on demand; per-lab qcow2 overlay/reset implemented.
- [x] 2026-10-17 topology: per-lab switch, ISP and LAN namespaces with QEMU taps; teardown removes mrlab-only objects.
- [x] 2026-10-17 ISP controls: DHCP/static/down controls and PPPoE/IPv6 mode hooks recorded for scenarios.
- [x] 2026-10-17 install: local release build and release selector wired to unattended request staging.
- [x] 2026-10-17 client/ops: LAN DHCP/check/exec, SSH, console, reboot, powercut and API helper commands added.
- [x] 2026-10-17 scenarios: 01 fresh DHCP, 02 PPPoE + PD, 03 same-subnet move scripts added and syntax checked.
- [ ] 2026-10-17 verification: QEMU/netns smoke test passed; full router install and PPPoE/PD require guest-side automation follow-up.

