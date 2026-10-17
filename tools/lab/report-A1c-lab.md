# mini-router tools/lab — A1c report (2026-10-17)

Branch `lab/fresh-env` (local only, rebased on origin/main 7b5c03e). Product fix: PR
https://github.com/Cd1s/mini-router/pull/143 (issue #142), branch `fix/install-fresh-alpine`, not merged.

## 1. Why "mr-network would not start": both, but the real failure is a product bug

The message is not in the product. It came from a lab that did not run a real install: `/sbin/apk`
was replaced by `exit 0`, a minirootfs package tarball (including its `lib/apk/db/installed`) was
untarred over the guest, `install.sh` ran under `timeout 60`, and the serial console was not logged
(commands to it were also truncated, see below). With all of that removed and the unmodified
`install.sh` running against a real (offline, signed) Alpine repository, the failure is
deterministic and different:

```
restart mr-hostapd
apply failed, rolling back ...: service restart failed:
  mr-hostapd: exit status 1 * no hostapd config for an existing radio (run mr apply)
install: apply failed (it was rolled back)
```

**Product bug (any WiFi-less Alpine machine):** `plan()` in `mr/apply.go` restarts the service of
every changed generated file. On the first apply `/etc/mini-router/gen/wifi-post.sh` is new and maps
to `mr-hostapd`, which the config (`wifi.radios: []`) does not run; its `start_pre` refuses and the
whole apply rolls back. Every VM and most x86 boxes can never be applied. Reproduced 3/3 on main.
Fix: a managed service the config does not enable is disabled, never restarted (+ test
`TestPlanDoesNotRestartServicesTheConfigDoesNotRun`, red without the fix). `sudo tools/ci.sh`:
ALL CHECKS PASSED. Reviewed by 查IN (Gemini): pass, no findings. install.sh untouched (no overlap
with #139).

Repro: `lab.sh reset 1; lab.sh isp 1 1 dhcp; MR_LAB_TREE= lab.sh install 1 --wan-proto dhcp`
(or on any Alpine VM: `MR_YES=1 MR_WAN=eth0 MR_LAN_PORTS=eth1 MR_ADMIN_PASS=... sh install.sh`).

## 2. What changed in the lab

- Real install: cloud-init only sets root password/SSH key, points apk at a seeded mirror and starts
  the unmodified `install.sh` after OpenRC finished booting (`guest/setup.sh`, `guest/install-run.sh`).
  No apk stub, no package tarball, no fallback dnsmasq/httpd, no static "fallback" lease.
- Offline mirror `mr-lab-images/apk-mirror`: official signed APKINDEX (main + community) + the exact
  package set, computed by installing the base world + install.sh's list into a scratch root
  (`apk fetch -R` missed install_if packages like nftables-openrc and resolved dnsmasq to its
  provider). Rebuilt automatically when install.sh's package list changes (main now adds ethtool).
- Guest kernel: base image = cloud image + `linux-lts`, built by one offline boot
  (`guest/prep-lts.yaml`). Reason: Alpine's linux-virt has `# CONFIG_PPPOE is not set`.
  `MR_LAB_KERNEL=virt` keeps the stock VM kernel.
- Console: serial UART input was lost/delayed (QEMU drops unread socket data on hang-up; the 16550
  RX path stalled ~11 s or until more input). The agent is now a root shell on a virtio-serial port
  (pipe chardev, `guest/agent.sh`); 15/15 round trips. ttyS0 output is logged to `console.log`.
- ISP: dhcp mode now actually has its gateway address; static mode gets DNS; PPPoE options fixed
  (invalid `mschap-v2` line, secrets in `/etc/netns/<isp>/ppp` instead of the host's `/etc/ppp`),
  IPv6 via `ipv6-up-script`: ISP address 2001:db8:<id>:<wan>::1, radvd, kea PD /60 from
  2001:db8:<id>:<wan>00::/56 with a route. kea runs under the host AppArmor profile in a private mount
  namespace (lab dirs over /etc/kea, /run/kea, /run/lock/kea, /var/lib/kea) and with the ISP
  link-local re-added without peer (kea binds IFA_ADDRESS = the peer's on ppp). NAT for the
  subscriber is an nft table inside the ISP netns.
- New: `lab.sh change <id> <patch> [--no-confirm]`, `install --tree/MR_LAB_TREE`, strict
  `lan check`, `lan static`, flock around shared mirror/release builds, per-lab kernel flavor.
- README: one-page quick reference on top.

## 3. Scenarios (MR_LAB_TREE = fix branch; 5 labs in parallel)

```
01-fresh-dhcp            6/6 ok   install, lease, DNS, IPv4 internet, panel 200, API login+status
   (stock main 7b5c03e)  0/6      install.sh rolls back at step 5 (mr-hostapd) -> everything after fails
02-pppoe-pd              8/8 ok   PPPoE up, PD 2001:db8:2:100::/60 on br-lan, client IPv4 internet + DNS,
                                  client global IPv6 from the delegated prefix, ping6 2001:db8:2:1::1
03-move-dhcp-samesubnet  7/9      API WAN switch PPPoE->DHCP on 192.168.1.0/24 applied+confirmed, router still
                                  reachable, client online again, mr doctor warns (RISK "LAN and WAN overlap");
                                  not ok: two 192.168.1.0/24 routes (br-lan + eth0), default via 192.168.1.1
                                  dev eth0 (= router's own LAN IP); the modem page 192.168.1.1 is unreachable
04-powercut-confirm      8/8 ok   unconfirmed hostname rolled back after power cut; confirmed one survives;
                                  client online after both
05-isp-switch-live       5/6      outage -> doctor RISK wan.wan; PPPoE redials by itself when the ISP returns
                                  (twice); not ok: when the line moves to DHCP, doctor only says "no IPv4
                                  address on pppoe-wan" + generic "cable, account, ISP"
```

## 4. Product issues

| # | Symptom | Reproduce | Suspected code |
|---|---|---|---|
| P1 | install.sh step 5 rolls back on every machine without WiFi (mr-hostapd restarted) — **fixed in #143** | `MR_LAB_TREE= lab.sh run 1 01-fresh-dhcp` | `mr/apply.go` `plan()` + `mod_wifi.go` `Restart` (wifi-post.sh -> mr-hostapd) |
| P2 | PPPoE on Alpine linux-virt (cloud images, many VMs) can never work: pppd "Couldn't open /dev/ppp … kernel does not support PPPoE"; install.sh rolls back after "PPPoE did not come up within 90s" without naming the cause | `MR_LAB_KERNEL=virt lab.sh reset 1; lab.sh isp 1 1 pppoe; MR_LAB_KERNEL=virt lab.sh install 1 --wan-proto pppoe` | `install.sh` (no preflight: e.g. `modinfo pppoe` -> "apk add linux-lts, reboot"); `rootfs/etc/init.d/mr-pppoe` `modprobe -q pppoe` hides the error; doctor/verify message |
| P3 | WAN DHCP lease inside the LAN subnet is applied and confirmed: duplicate connected /24 routes, default via the router's own LAN address, modem page unreachable (works for internet only by route order). Doctor warns correctly. | `lab.sh run 3 03-move-dhcp-samesubnet` | `mr/hooks.go` WAN-up route handling / `mod_net_render.go`; open PR #138 targets this |
| P4 | Line changes from PPPoE to DHCP: doctor gives no specific cause (no "no PADO / no PPPoE server", no hint that DHCP answers) | `lab.sh run 5 05-isp-switch-live` | `mr/mod_sys_doctor.go` WAN check (pppd log "Timeout waiting for PADO") |
| P5 | (minor, observed, impact not verified) doctor on an Alpine install: "Clock: NTP sync state unknown (no /run/mr-clock: mr-clock of an older image)"; doctor "SSH: off" although the cloud image runs openssh — install.sh only detects dropbear | `lab.sh console 1 'mr doctor; rc-status | grep sshd'` | `mod_sys_doctor.go` clock check; `install.sh` `ssh_enabled` (`/etc/runlevels/default/dropbear`) |

## 5. Host safety

After all runs: `sha256sum /etc/resolv.conf` = 4a6bc9f3ddbb22ebdb5b3a6b4d49d97537b8e5f24204880038b4b8e5b6734028;
`ip -br link | grep -c mrlab` = 0; no mrlab netns, `/etc/netns/mrlab*`, processes or nft tables;
host `/etc/kea`, `/run/kea` untouched. The guard passed on every command. Host-kernel side effect:
pppd loads `ppp_generic` on first use. Pre-existing and not touched: a host `kea-dhcp6` service
(installed 17:49 today, probably by the earlier lab work), `mr-lab-images/alpine-router-packages.tar.gz`
(old package layer, unused now).
