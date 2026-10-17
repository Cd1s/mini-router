# mini-router fresh environment lab

## Quick reference for test agents

Run as root on IN from the repository root. IDs 1–8 are independent labs and may run at the same
time. Every command checks the host's `/etc/resolv.conf`, `/etc/hosts` and `/etc/ppp/**` before
and after and fails loudly if anything changed.

```sh
L=tools/lab/lab.sh; ID=1
trap '$L down $ID' EXIT                         # always clean up

# 1. a new router: never-booted Alpine 3.24 + the real install.sh (2–3 min)
$L reset $ID                                    # empty lab: namespaces + a fresh disk
$L isp $ID 1 dhcp                               # what the "ISP" offers (see ISP modes)
$L install $ID --wan-proto dhcp                 # ok / the install.sh error; LAN 192.168.1.1, admin labpass1
#   --wan-proto pppoe|static   --lan-ip 10.0.0.1/24   --no-apply (MR_APPLY=0)
#   --tree /path/to/checkout   test another branch (also MR_LAB_TREE=...)
#   --release vX.Y.Z           a published release instead of the working tree

# 2. change the ISP under the running router
$L isp $ID 1 pppoe v6=pd                        # PPPoE (lab/labpass) + DHCPv6-PD /60
$L isp $ID 1 dhcp --subnet 192.168.1.0/24       # a modem on the router's own LAN subnet
$L isp $ID 1 down                               # cable pulled

# 3. check from the LAN client (a netns behind the router's LAN port)
$L lan $ID dhcp                                 # {"dhcp":"ok","addr":...} or exit 1
$L lan $ID check                                # {"ipv4","ipv6","dns","panel"}; exit 1 without IPv4+DNS
$L lan $ID exec 'curl -fsS http://example.com/ >/dev/null && ping6 -c2 2001:db8:1:1::1'

# 4. settings through the web UI API (logs in with labpass1, keeps the session cookie)
$L api $ID GET status
$L change $ID '[{"op":"set","path":"system.hostname","value":"r1"}]'           # apply + confirm
$L change $ID '[{"op":"set","path":"dhcp.lease","value":"1h"}]' --no-confirm   # leave it pending

# 5. inside the router, power
$L console $ID 'mr status; tail -20 /var/log/messages'   # root shell, works with the network down
$L reboot $ID; $L powercut $ID                  # clean reboot / kill -9 QEMU and boot again

# 6. clean up
$L down $ID
ip -br link | grep -c mrlab                     # must print 0
```

Scenarios (TAP output, log in `/tmp/mrlab<ID>-<name>.log`): `$L run $ID 01-fresh-dhcp`,
`02-pppoe-pd`, `03-move-dhcp-samesubnet`, `04-powercut-confirm`, `05-isp-switch-live`.
Each starts with `reset` and removes its lab when it ends (passed, failed or interrupted;
`MRLAB_KEEP=1` leaves it up for inspection), so give every parallel scenario its own ID. A failed
setup step prints `Bail out!` and stops the scenario.

## Dependencies

Root on the IN build host with KVM. Install the **binaries only; do not enable their system
services** — every daemon is started by `lab.sh` inside a lab namespace with its own config, and a
host dnsmasq would listen on the host's port 53:

```sh
# masked first: the packages' postinst would otherwise start radvd / kea on the host for a moment
systemctl mask dnsmasq kea-dhcp6-server radvd
apt-get install --no-install-recommends qemu-system-x86 qemu-utils slirp4netns iproute2 nftables \
  dnsmasq-base ppp pppoe radvd kea-dhcp6-server genisoimage python3 openssh-client curl jq busybox
```

`lab.sh up` refuses to start while one of those services runs (`MRLAB_ALLOW_HOST_SERVICES=1`
overrides). Kea needs only the package's `/etc/kea`
and `/var/lib/kea` directories (its AppArmor profile allows no other paths), which a private mount
namespace replaces with lab directories. Go comes from `/etc/profile.d/buildtools.sh`.

## What a lab is

```text
                      slirp4netns (user-mode NAT to the internet; no host route or rule)
                         |                                 |
               mrlab<ID>-isp1 netns                 mrlab<ID>-isp2 netns   (second WAN, unused yet)
   DHCP / PPPoE / static, DNS, radvd, kea (PD)
                         |
               mrlab<ID>-sw netns: br-wan1, br-wan2, br-lan, QEMU taps
                         | eth0 (WAN)
             +-----------+-----------------------+
             | QEMU: Alpine 3.24, 512 MiB, 1 vCPU|  console: ttyS0 -> state/mrlab<ID>/console.log
             |                                   |  lab agent: virtio-serial "mrlab.agent"
             +-----------+-----------------------+
                         | eth1 (LAN)
               mrlab<ID>-lan netns: the user's computer (udhcpc, SLAAC, curl, ping6)
```

- **Guest**: the official Alpine 3.24 cloud image, booted once offline to add `linux-lts`
  (`alpine-3.24-x86_64-lts.qcow2`, built automatically). `MR_LAB_KERNEL=virt` uses the cloud
  image's `linux-virt` kernel instead — that kernel has no PPPoE (see "Known product findings").
  `install` gives the lab a new disk over the read-only base, so every install is a first boot.
- **Install**: cloud-init only sets the root password (`labpass1`) and a lab SSH key, points apk at
  the seeded mirror and starts the unmodified `install.sh` after OpenRC finished booting
  (`guest/setup.sh`, `guest/install-run.sh`), with `MR_YES=1 MR_LOCAL=... MR_WAN=eth0
  MR_LAN_PORTS=eth1`. Its output is on the serial console; the last line is
  `MRLAB-INSTALL-RC=<n>`. Nothing in the guest is faked: no apk stub, no fallback DHCP or web server.
- **Packages**: `/root/build/mr-lab-images/apk-mirror` holds the official signed APKINDEX of
  main and community plus every package `install.sh` installs (found by installing the base
  image's world and install.sh's list into a scratch root; rebuilt when the list in `install.sh`
  changes). The guest therefore needs no internet during the install, in every ISP mode.
- **Release**: `tools/release.sh` of the chosen tree, cached in `mr-lab-images/release-<hash>`.
- **Console**: `lab.sh console` talks to a root shell on a virtio-serial port (`guest/agent.sh`,
  started at every boot from `/etc/local.d`). A serial UART was not reliable for this. Use it when
  the router's network is down; `ssh` (LAN side, lab key) works when it is up.

## ISP modes

| `isp <id> <wan> ...` | ISP side | router WAN |
| --- | --- | --- |
| `dhcp [--subnet 192.168.1.0/24]` | dnsmasq DHCP + DNS on `10.<id>.<wan>.1/24`; with `--subnet 192.168.1.0/24` it also serves a modem page on 192.168.1.1 | DHCP |
| `static` | `10.<id>.<wan>.1/24` + DNS; `install --wan-proto static` uses `.2/24` | static |
| `pppoe [v6=slaac\|pd] [--badpass] [nopado] [--cgnat]` | pppoe-server, CHAP `lab`/`labpass` (`--badpass`: the server expects another password; `nopado`: no server at all; `--cgnat`: 100.64.<id>.x). After IPv6CP the ISP end is `2001:db8:<id>:<wan>::1/64`; `v6=slaac` adds RAs for that /64, `v6=pd` also kea DHCPv6 delegating /60s from `2001:db8:<id>:<wan>00::/56` | PPPoE |
| `down` | link down | — |

The ISP's own resolver files (`/etc/resolv.conf`, `/etc/ppp`) are per-namespace copies under
`/etc/netns/mrlab<ID>-*`; kea runs under the host's AppArmor profile in a private mount namespace
whose `/etc/kea`, `/run/kea`, `/run/lock/kea` and `/var/lib/kea` are lab directories. Its NAT
is an nftables table inside the ISP namespace only.

## Commands

```text
up|down|reset|status <id>          lab lifecycle (down removes only mrlab<ID>* objects and state)
isp <id> <wan> <mode> [opts]       ISP simulator (table above)
install <id> [opts]                fresh disk + real install.sh; exit 1 with the installer's last lines
lan <id> dhcp|static [a/len [gw]]|check|exec <cmd>
console <id> <cmd>                 MRLAB_TIMEOUT=<s> (default 60)
ssh <id> <cmd>                     LAN-side SSH with the lab key (only when sshd runs)
api <id> GET|POST <action> [json]  docs/api.md; MR_TOKEN=<token> uses a Bearer token instead
change <id> <patch> [--no-confirm] [--secrets json]
reboot|powercut <id>
run <id> <scenario>
mirror [tree]                      (re)build the apk mirror for that tree's install.sh
```

State lives in `tools/lab/state/mrlab<ID>/` (`console.log`, `agent.out`, `install/`, `isp1/`
with the dnsmasq/pppd/radvd/kea logs). Images and caches are in `/root/build/mr-lab-images/`
(about 1.5 GiB).

## Host safety

- No host bridge, route, nftables rule or sysctl is created; all addresses and daemons are inside
  `mrlab<ID>-*` namespaces. slirp4netns gives the ISP namespace internet as a user-mode stack.
- Each namespace has its own `/etc/netns/<ns>/resolv.conf`; the LAN client's DHCP uses a private
  `udhcpc -s` script that writes lab state only (the BusyBox default script would overwrite the
  host's `/etc/resolv.conf`).
- pppd reads `/etc/netns/<isp>/ppp` (bind-mounted over `/etc/ppp` by `ip netns exec`), never the
  host's `/etc/ppp` scripts. The first PPPoE run loads the host's `ppp_generic` module (via
  `/dev/ppp`), which is the only host-kernel side effect.
- pppoe-server and its pppd run in a private mount namespace with their own tmpfs `/run`
  (`/run/ppp0.pid`, `/run/pppd2.tdb` never reach the host); kea likewise. Lab processes are stopped
  with TERM first (pppd cleans up), KILL after 3 s, and only processes inside the lab's namespaces
  or ones whose name matches their pid file are signalled.
- veth pairs are created inside the lab namespaces (`ip -n <sw> link add … peer … netns <ns>`),
  never in the host's.
- The host guard compares every command's before/after manifest and a baseline kept across commands
  (`state/.host-guard/baseline`), so a lab daemon changing a host file between two commands stops
  the next one. Ctrl-C / TERM still run it. If the change was yours: `lab.sh guard-reset`.
- Shared images are initialised under a lock (`mr-lab-images/.build.lock`), with temp directories from
  `mktemp` and loop mounts that are unmounted on every exit.
- After a run: `sha256sum /etc/resolv.conf` unchanged and `ip -br link | grep -c mrlab` = 0.

### Downloads

The cloud image and the minirootfs used for the package chroot are fixed versions with pinned SHA256s
in `lab.sh` (checked against Alpine's published `.sha512` / `.sha256` when pinned); a mismatch stops
the command. apk in the chroot checks every APKINDEX signature against the minirootfs's keys and every
package against the index; the indexes copied into the mirror must be byte-identical to those it
verified, and the guest's apk verifies them again with the cloud image's keys.

Never point the lab at a real LAN or a household device.

## Known product findings

- `install.sh` rolled back on every machine without WiFi (`mr-hostapd` restarted) — fixed in #143.
- Since #138 the first apply of `install.sh` rolls back on every fresh machine: `network.sh` writes
  `/run/mini-router/modem-aliases` before `mr-network` ever created the directory — PR #147.
  Until it is merged run the lab with `MR_LAB_TREE=<checkout of that branch>`.
- Alpine's `linux-virt` kernel has no PPPoE: without a check `install.sh` waited 90 s and rolled
  back — PR #148 (`MR_LAB_KERNEL=virt` reproduces it).
- `05-isp-switch-live` check 5: when the line moves from PPPoE to DHCP, `mr doctor` only reports
  "no IPv4 address on pppoe-wan" (no "no PPPoE server answers" / "DHCP answers on this port").
