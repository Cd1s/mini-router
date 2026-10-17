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

## A1 continuation

The continuation fixed the host leak and committed these additional changes:

```text
2847d82 veth pairs stay inside lab namespaces
c7f338c LAN/WAN bridges, cloud-init seed install, scenarios 04/05
ec5c6e0 slirp DNS, PPPoE server/auth variants, IPv6-up radvd/Kea hooks
9f8a00b milestone record
dfacbb7 explicit Alpine kernel boot, package/repository seed, guest fallback services
```

`ip -br link | grep -c mrlab` was 0 both immediately after `up 1; up 2` and after teardown.
The guest cloud-init seed is now discovered as `DataSourceNoCloud [seed=/dev/vdb]` and executes
the real local `install.sh`; the current 200 MiB Alpine base was resized to 512 MiB. On this host,
Alpine's `apk add` still blocks at installer step 1, so the seed records the failure and exposes a
clearly labelled static LAN fallback. This leaves 01/02 as diagnostic failures until the guest
package path is fixed; no product code was changed.

Current five-scenario summary:

```text
01-fresh-dhcp             not ok: guest LAN DHCP/panel unavailable; DNS lookup failed
02-pppoe-pd               not ok: no PPP IPv6/PD; ping6 reported Network is unreachable
03-move-dhcp-samesubnet   not ok: API baseline unavailable after guest install; LAN internet failed
04-powercut-confirm       not ok: baseline API unavailable after guest install
05-isp-switch-live        ok diagnostic: live ISP switch command completed; status/check unavailable
```

Final cleanup check: `ip -br link | grep -c mrlab = 0`, and `ip netns` had zero `mrlab` entries.
The final route hash was `8d68d72a56a0b91d0d77f83e3558bd1169f3ab084dbde69c4d85278497c6ad6f` and
the final nft digest was `f1aaf441dc72ac54cec52f69868c7fff`; the differing nft digest is from
pre-existing host rules changing during the run.

Emergency host safety fix: `lab.sh` now creates and removes `/etc/netns/<lab-namespace>/resolv.conf`,
uses a private `udhcpc -s` hook, and directs all ISP lease/pid/log, PPP, radvd and Kea state into
lab state. Every invocation hashes `/etc/resolv.conf`, `/etc/hosts`, and `/etc/ppp/**` before and
after execution and reports a diff if any changes. A smoke run confirmed the host resolver SHA256
was unchanged and ended with zero host `mrlab` links.
