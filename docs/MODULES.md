# mini-router feature modules — contract

mini-router is the home-server main router (Redmi AX6000, 512 MB RAM, 128 MB NAND). Goals, in order:
**secure, fastest possible (hardware offload stays on for normal traffic), small**. Every feature must
earn its RAM/flash: no daemons that sit idle, no features "because LuCI has them".

`router.yaml` is the single source of truth. `mr` (Go, not resident) validates it, renders every config
file, applies with snapshot + verify + auto-rollback, and serves the web UI API as a CGI.

## Layout

| Module | Prio | Go files | UI file | router.yaml keys | Owner scope |
|---|---|---|---|---|---|
| net   | 10 | `mr/mod_net*.go`, `mr/hooks.go` | `rootfs/www/ui/net.js` | `lan`, `networks`, `wan`, `multiwan`, `policy_routes`, `static_routes`, `multicast` | links, bridges, VLANs, WAN (PPPoE/DHCP), multi-WAN failover, routing, IPv6 WAN side (dhcpcd), port status |
| wifi  | 20 | `mr/mod_wifi*.go` | `ui/wifi.js` | `wifi` | radios, SSIDs, hostapd, stations |
| dns   | 30 | `mr/mod_dns*.go` | `ui/dns.js` | `dhcp`, `dns`, `networks[].dhcp` (type `Pool`) | dnsmasq: DNS, DHCP, RA/DHCPv6, split lists, local records, stubby.yml, query log; `rootfs/etc/conf.d/dnsmasq` |
| fw    | 40 | `mr/mod_fw*.go` | `ui/fw.js` | `firewall` | nftables skeleton + hooks, zones, forwards, rules, NAT, IPv6 pinholes, access control |
| mon   | 50 | `mr/mod_mon*.go` | `ui/mon.js` | — | realtime graphs, per-device traffic, connections, system load |
| proxy | 55 | `mr/mod_proxy*.go` | `ui/proxy.js` | `proxy` | selective transparent proxy: sing-box, fake-ip DNS, tproxy, bypass devices |
| sys   | 70 | `mr/mod_sys*.go` | `ui/sys.js` | `system`, `services`, `schedules` | hostname/time/NTP/sysctl, SSH, add-on services, backup/restore, schedules, logs, diagnostics |
| platform | — | — | — | — | kernel/kmods, sing-box build, image (build/**), preinit, sysupgrade/factory-reset, docs/flash.md |
| core  | —  | `config.go`, `module.go`, `render.go`, `apply.go`, `api.go`, `status.go`, `main.go` | `ui/core.js`, `index.html` | — | loading, apply/rollback, auth, registry, layout (changes need the integrator) |

A module may add files named `mr/mod_<name>_*.go` and `mr/mod_<name>*_test.go`, its UI file, its
lab fragment `examples/lab.d/NN-<name>.yaml`, test secrets `mr/testdata/secrets.d/<name>.yaml`, mock
fixtures `tools/mock/fixtures/<action>.json` / `.post.json` / `config.d/<name>.json`, rootfs files it
owns (`rootfs/etc/init.d/<its services>`, `rootfs/etc/conf.d/...`, `rootfs/usr/libexec/mr/<name>-*`),
and `docs/modules/<name>.md`. **Never edit another module's files**; if you need a new core hook,
say so in your report instead of editing core files.

## Go extension points (`mr/module.go`)

Register exactly one `Module` in `init()`:

- `Defaults(c)` — fill zero values. `Validate(c, v)` — report every problem with `v.Add`. Validation is
  the security boundary: **every string that ends up in a generated file must be validated**
  (`safeText`, `reName`, `reLabel`, `reMAC`, `reDev`, `rePath`, `validPorts`, … in `config.go`).
  Reject newlines / control chars / quotes wherever they could break out of a config line.
- `Render(c, out)` — add generated files (`out.Add(path, mode, data)`); must not touch the system.
- `NetSh(c, phase, b)` — idempotent POSIX sh for `network.sh`, phases `links` → `wifi` → `routes` → `tail`.
- `Nft(c, hook, n)` — nftables lines at hook points (`defs`, `input`, `forward_early`, `forward`,
  `mark`, `dstnat`, `srcnat`, `output`), see `nftHooks`. A module that needs its own base chain
  (different priority) declares it in `defs`. `n.W(format, args...)` writes one line.
- `FlowDevs(c)` — netdevs for the offload flowtable. `Dnsmasq(c)` — extra dnsmasq.conf lines.
- `Services(c)` / `Managed` — OpenRC services wanted / owned. `Restart(path)` — service to restart
  when a generated file changes (`"-"` = none). `RestartOrder` — relative restart order.
- `Verify(c, restarted)` — post-apply checks (failure rolls the apply back).
- `Status(c, st)` — add keys to status JSON. `API` — web UI actions `"<module>.<verb>"`; mutating
  actions must require `r.method == "POST"`; never return secrets; validate every input.
- `Commands` — `mr <name> ...` subcommands (for hooks/daemons).
- `Secrets(c)` — names of every secret this module's config references (so the UI can show 已设置).

**Guard and risk.** `guard:` (core, `guard.go`) holds the owner's baselines — `never_expose` (ssh, panel, dns: no
`firewall.open` or forward to the router reaches their ports from the WAN), `always_bypass` (devices never proxied),
`offload` (minimum flow offload), `ssh_lan_only`; `Config.Validate` checks it after every module, so no path (web UI,
CLI, restore, token, agent) can apply a config that breaks it. Every plan gets a risk level (`risk.go`): low (no
service restarts), medium (restarts, none on the administrator's path), high (the administrator's own path — the
netdev / bridge port / tailscale / SSH their session uses, found with `ip route get` + the bridge fdb — LAN addresses,
WANs, the router's inbound rules, SSH / web UI / tailscale settings, the guard). The web UI keeps low and medium
changes by itself once applied, verified and still reachable; high ones wait for 保留. `mr apply --confirm N --wait`
asks on the terminal and rolls back at once on Ctrl-C / SIGHUP.

Rollback (failed/unconfirmed apply, `mr rollback`) restores files, restarts their services and
reconciles the default runlevel with the restored config (`reconcileRunlevel`). Every apply records a revision
(`history.go`): `<snapshot>.json` next to its snapshot with rev, time, origin, comment, the config-level diff
(from `gen/applied.yaml` + `gen/applied-secrets`, bookkeeping files the plan writes and a rollback restores; secrets
only as "(changed)") and the result (applying → applied | pending → confirmed | rolled back: why); `mr rollback N`
and the web UI's 回滚到此前 apply the config from before change N as a new change (the web UI password stays the
current one). From the snapshot until the
change is accepted (the apply ends without `--confirm`, or `mr confirm`) the marker
`/etc/mini-router/confirm-pending` (JSON: snapshot, state applying | pending | reverting, deadline, origin) is on
flash: if the router goes down in that window, the next boot restores the snapshot before any service starts
(`mr rollback --boot` from mr-preinit, or the `mr-unconfirmed` boot service on Alpine installs) and fixes the
runlevel links (`linkRunlevel`). While the marker exists every other change is refused (`mr apply`, the web UI's
apply, `mr sys restore`: `pendingBlocks`; the marker is claimed with O_EXCL, so two applies started at once cannot
both run); `mr confirm` keeps the change, `mr rollback` (no argument) undoes it. Every API answer to a logged-in
client carries `X-MR-Pending: {"state","via","left"}`, and the web UI shows a banner with 保留 / 回滚 on every page.

Cross-module helpers: `c.LANNets()`, `c.BridgeFor(network)`, `c.LANBridges()`, `c.WANIfnames()`,
`c.WANTable(name)`, `c.WANByName(name)`, `c.Secret(key)`.

Secrets (passwords, keys) live in `secrets.yaml`; router.yaml stores the secret **name**
(`*_secret` fields). The UI sets secrets by name and can never read them back.

Web UI password checks (login, password change) are throttled per source address (IPv6: per /64) in
`/run/mini-router/login.json`, shared by all CGI processes under flock (`api_login.go`): every attempt counts before
the check, the 5th failure in a row locks the source for 30 s, doubling per lock up to 1 h; a locked source gets 429
without a password check. A correct password clears it.

## Web UI (`rootfs/www/ui/<module>.js`)

Each file is wrapped in an IIFE and calls `registerPage(group, id, title, order, render)`.
Groups: `status, network, wireless, proxy, firewall, routing, services, system`.
Use only helpers from `ui/core.js`: `h`, `api`, `S` (state: `S.cfg` = editable config, `S.secrets`),
`touch()` after edits, widgets `inText/inNum/inBool/inSel/inList/inProto/inSecret`, `field/form/card`,
`etable/tableCard/roTable`, `tabs`, `lineChart`, `COLORS`, `modal`, `toast`, `confirmBtn`, `addCSS`,
`fmtBytes/fmtRate/fmtDur`. Live pages may set `S.timer = setInterval(...)` (cleared on navigation).
Hints on the overview: `registerNotice(status => Node | [Node] | null)` is called on every overview refresh with the
`mr status` JSON; build them with `notice(level: warn|bad|info, text, ...buttons)`, `dismissBtn(key)` / `dismissed(key)`
(per browser).
Config edits only change `S.cfg`; the shared "保存并应用" bar runs validate → plan → apply → confirm.
The router.yaml it installs is the live file with only the changed values edited (`yamledit.go`): comments, key
order, quoting and layout stay; if an edit cannot be made in place, or the result would not decode to exactly the
submitted config, the canonical encoding is written instead (comments lost, logged).
Style: professional router UI (think RouterOS/LuCI density), Chinese labels, technical terms as-is.
Pages must work at 360 px width.

Test locally without a router: `python3 tools/mock/mockapi.py 8088` → http://127.0.0.1:8088/
(fixtures in `tools/mock/fixtures/`; add your own for new API actions).

## Checks (Linux, root: network namespaces)

    ./tools/ci.sh

runs gofmt, vet, tests, arm64 build, shellcheck, UI syntax, and renders both the real home config
(`examples/router.yaml`, must keep working unchanged) and the lab config (`examples/lab.d/*.yaml`
concatenated) into real `nft -c`/`nft -f` (in a netns) and `dnsmasq --test`. Formatting: `cd mr && gofmt -w .`.

## Runtime environment (for design decisions)

Alpine 3.24 aarch64, OpenRC + supervise-daemon, busybox (ash, httpd, crond, ntpd, syslogd), dnsmasq,
hostapd 2.11 (+noscan patch), pppd, dhcpcd, nftables, iproute2 (JSON output), iw. Kernel: OpenWrt
6.18 (mt76 + WED + PPE flow offload). Kernel modules must come from the platform build.
