# mini-router fresh environment lab

## Quick reference for test agents

```sh
L=tools/lab/lab.sh; ID=1
$L reset $ID
$L isp $ID 1 dhcp
$L install $ID --wan-proto dhcp       # --no-apply leaves config unapplied
$L lan $ID dhcp; $L lan $ID check
$L api $ID GET status                  # logs in with labpass1 and keeps a cookie jar
$L lan $ID exec curl -fsS http://192.168.1.1/
$L run $ID 01-fresh-dhcp
$L down $ID
```

Use IDs 1–8 concurrently. `isp` accepts `dhcp`, `pppoe`, `static`, `down`; PPPoE variants are
`--badpass`, `nopado`, `--cgnat`, and `v6=pd`. `ssh`, `console`, `reboot`, `powercut`, and
`status` are recovery commands. Scenarios 01–05 emit TAP `ok`/`not ok` lines and leave logs in
`/tmp/mrlab<ID>-*.log`. If the guest DHCP service is not ready, `lan dhcp` reports
`fallback-static` explicitly so a test never mistakes the fallback for a real lease. Always run
`down` in a trap when writing a test agent.

`tools/lab/lab.sh` builds isolated Alpine/QEMU router laboratories. Each lab has its own
network namespaces, bridge, tap devices, QEMU process, ISP simulator and LAN client namespace.
The host's network namespace, routes and firewall are not modified.

## Dependencies

Run the commands as root on the IN build host. The lab needs:

```text
qemu-system-x86_64 qemu-img ip (iproute2) ip netns
slirp4netns ppp pppoe dnsmasq curl jq ssh ssh-keygen
kea-dhcp6-server or radvd ndisc6 socat cloud-image-utils (or genisoimage)
```

The helper installs no packages itself. Alpine 3.24 x86_64 is used for the base image. QEMU
may use KVM when available; each guest is capped at one vCPU and 512 MiB RAM. Base and overlay
images live in `/root/build/mr-lab-images/` and should stay below the 5 GiB disk budget.

The install path builds release assets from the current tree using `tools/release.sh`, then calls
the repository `install.sh` in unattended mode. A local asset directory must contain
`mr-linux-amd64` and `mini-router-rootfs.tar.gz`; a tagged release can instead be selected with
`--release`.

## Host safety

Every lab namespace gets an `/etc/netns/mrlab<ID>-*/resolv.conf` before any `ip netns exec` call.
`lab.sh lan ... dhcp` uses a private `udhcpc -s` hook whose lease DNS is written under that lab's
`tools/lab/state/` directory and then copied to the namespace resolv bind file. It never uses the
BusyBox default script, which can overwrite the host `/etc/resolv.conf` when the namespace bind
file is missing. ISP dnsmasq lease, pid and log files, PPP/PPPoE pid/log files, radvd files and
Kea state are likewise directed into the lab state directory. `down` removes the namespace bind
files. Each `lab.sh` invocation hashes `/etc/resolv.conf`, `/etc/hosts`, and every file under
`/etc/ppp` before and after the command; any difference prints a unified diff and fails the command.
After all scenarios, verify `/etc/resolv.conf` has the same SHA256 as before the run.

## Topology

Every name below is prefixed by `mrlab<ID>`, so labs 1 through 8 can run at the same time:

```text
                         slirp4netns (host internet)
                                  |
             +--------------------+--------------------+
             |                                         |
     mrlab<ID>-isp1 netns                       mrlab<ID>-isp2 netns
       DHCP/PPPoE/static                        optional second WAN
             |                                         |
       mrlab<ID>-sw netns (bridge)                 (WAN2)
             | eth0 WAN1      eth2 WAN2 (optional)
          +--+---------------------------------------+
          | QEMU mini-router VM (512 MiB, 1 vCPU)    |
          +--+---------------------------------------+
             | eth1 LAN
             |
       mrlab<ID>-lan netns (client, DHCP/IPv6 checks)
```

The switch namespace owns the bridge and QEMU taps. ISP and LAN namespaces are connected with
veth pairs. `slirp4netns` provides upstream access from each ISP namespace without a host bridge,
host route, nftables rule, sysctl change or other host network mutation.

## Commands

All commands are run from the repository root or with an absolute path to `lab.sh`:

```sh
tools/lab/lab.sh up <id>                  # create namespaces, taps and start the guest
tools/lab/lab.sh down <id>                # stop guest and remove only this lab's namespaces
tools/lab/lab.sh status <id>              # JSON-ish process/link/namespace status
tools/lab/lab.sh reset <id>               # restore a fresh Alpine overlay
tools/lab/lab.sh install <id> [options]   # build/copy mr and run unattended install.sh
tools/lab/lab.sh isp <id> <wan> <mode> [v6=none|slaac|pd|slaac+pd] [options]
tools/lab/lab.sh lan <id> dhcp            # renew the client IPv4/IPv6 leases
tools/lab/lab.sh lan <id> check           # report IPv4, DNS, IPv6 and panel checks
tools/lab/lab.sh lan <id> exec <command>  # execute in the LAN client namespace
tools/lab/lab.sh ssh <id> <command>       # LAN-side SSH command to the router
tools/lab/lab.sh console <id> <command>   # serial command with an end marker
tools/lab/lab.sh reboot <id>               # guest reboot
tools/lab/lab.sh powercut <id>             # kill -9 QEMU and start it again
tools/lab/lab.sh api <id> GET|POST <path> [json]
tools/lab/lab.sh run <id> <scenario>      # run scenarios/NN-name.sh
```

`isp` modes are `dhcp`, `pppoe`, `static` and `down`. DHCP accepts `--subnet CIDR` for a
same-subnet optical modem and serves its management page at `192.168.1.1`; PPPoE accepts
`--cgnat`, `--badpass` and `nopado`. The fixed lab credentials are `lab` / `labpass`.

The unattended install uses `MR_YES=1 MR_LOCAL=... MR_WAN=eth0 MR_LAN_PORTS=eth1` and the
requested `MR_WAN_PROTO`. `--no-apply` maps to `MR_APPLY=0`, which leaves the first-boot setup
available for a scenario to exercise. `lab.sh api` follows `docs/api.md`: it obtains/uses the lab
apply token, sends `Authorization: Bearer`, reads `rev`, applies a patch, polls `job`, and confirms
the pending change.

## Scenarios

The scripts in `scenarios/` are self-contained TAP-style checks. They accept a lab ID when called
directly and are normally invoked with `lab.sh run`:

```sh
tools/lab/lab.sh run 1 01-fresh-dhcp
tools/lab/lab.sh run 1 02-pppoe-pd
tools/lab/lab.sh run 1 03-move-dhcp-samesubnet
```

`01-fresh-dhcp` resets and installs DHCP, then checks a LAN lease, IPv4 reachability, DNS and the
panel. `02-pppoe-pd` resets and installs PPPoE, switches the ISP to IPv6 prefix delegation,
renews the LAN lease and checks a global IPv6 address plus an ISP-side IPv6 target. `03` starts
from PPPoE and changes only the WAN protocol through the panel API to DHCP on `192.168.1.0/24`;
it records both successful and failed checks because the same-subnet move is expected to expose a
real product failure in some configurations. Its patch also removes the obsolete PPPoE
`password_secret`; the API token guard permits removing a credential reference but refuses to
change a still-secret-bearing WAN.

## Parallel labs and cleanup

Use distinct IDs and separate terminals or CI jobs:

```sh
tools/lab/lab.sh up 1
tools/lab/lab.sh up 2
tools/lab/lab.sh install 1 --wan-proto dhcp
tools/lab/lab.sh install 2 --wan-proto dhcp
```

Do not reuse an ID while another job is running. At the end, run `down` for every ID and compare
the host state captured before the run:

```sh
ip netns list > /tmp/mrlab-netns.before
ip link show > /tmp/mrlab-links.before
ip route show > /tmp/mrlab-route.before
nft list ruleset | md5sum > /tmp/mrlab-nft.before
# ... run labs ...
tools/lab/lab.sh down 1
tools/lab/lab.sh down 2
ip netns list > /tmp/mrlab-netns.after
ip link show > /tmp/mrlab-links.after
ip route show > /tmp/mrlab-route.after
nft list ruleset | md5sum > /tmp/mrlab-nft.after
diff -u /tmp/mrlab-netns.before /tmp/mrlab-netns.after || true
diff -u /tmp/mrlab-links.before /tmp/mrlab-links.after || true
diff -u /tmp/mrlab-route.before /tmp/mrlab-route.after || true
diff -u /tmp/mrlab-nft.before /tmp/mrlab-nft.after || true
```

`down` removes only names beginning `mrlab`; it must not touch existing namespaces, links,
containers, routes or firewall rules. `reset` removes a lab overlay and recreates it from the
read-only Alpine base image. To reclaim all lab disk space after all labs are down, remove only
`/root/build/mr-lab-images/mrlab*` after checking the directory contents.

The VM's serial console is the recovery path when networking is broken. Use `console` or
`status` before attempting a reset. Never connect this lab to a household router or use a real
LAN address as an external target.

The namespace/QEMU plumbing is usable without a guest install and is safe to run in parallel. The
current harness stages the local release and records the unattended install request; completing
the guest-side Alpine cloud-init handoff and a real PPPoE/DHCPv6-PD daemon is a follow-up item.
Those gaps are surfaced by scenario logs rather than hidden as passing checks.

