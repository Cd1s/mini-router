# mini-router tools/lab A1 report — 2026-10-17

Result: **partial success**. Branch `lab/fresh-env`, commit `7119757` (`tools/lab: add isolated fresh environment harness`).

Implemented commands: `up/down/status/reset` manage per-ID QEMU and netns; `isp` selects DHCP, static,
down and records PPPoE options; `install` builds/stages local or tagged release settings; `lan` runs
DHCP/check/exec; `ssh`, `console`, `reboot`, `powercut`, `api`, and `run` are provided. README and
three TAP scenarios are included.

Smoke verification:

```text
up 1 -> Alpine cloud qcow2 downloaded, qemu=true, bridge and two tap devices
up 2 -> qemu=true; IDs had separate mrlab1-* and mrlab2-* namespaces
down 1; down 2 -> ip netns list contained 0 mrlab namespaces
```

Scenario output (abridged):

```text
01-fresh-dhcp: ok DHCP lease; not ok IPv4/DNS/panel (curl could not resolve example.com; panel refused)
02-pppoe-pd: ok lease; not ok global IPv6 and ping6 (Network is unreachable)
03-move-dhcp-samesubnet: ok baseline/panel reachability; not ok LAN internet after move (DNS failed)
```

The third failure is the intended diagnostic: the current harness has no guest-side applied router
configuration, so the observed symptom is recorded rather than attributed to a product fix. The
same limitation means the local release is staged and the unattended request is recorded, but is
not yet copied into and executed inside the cloud guest. PPPoE authentication and DHCPv6-PD daemons
are hooks for the next implementation milestone.

Host cleanup: after `down`, `ip netns list` had no `mrlab*` entries. The initial nftables digest was
`9595bbfe7e9930a7bddb097b8f62a8e1`; final digest was `33354c5a03d2c0a59414e59df27c6f02`. Route
output remained host-managed; the final route hash was
`8d68d72a56a0b91d0d77f83e3558bd1169f3ab084dbde69c4d85278497c6ad6f`. The nft digest changed while
the host's existing container rules were active; the lab itself creates no host nftables rule,
bridge, route, or sysctl.

Known limits: Wi-Fi/PPE/DSA and hardware switch behavior cannot be tested in QEMU; full guest
install, PPPoE, DHCPv6-PD, and panel API authentication need follow-up guest automation.
