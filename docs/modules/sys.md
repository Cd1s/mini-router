# sys — time, SSH, add-on services, DDNS, schedules, backup / restore, firmware, logs, diagnostics

Everything that is "the router itself" rather than a network feature. Like the other modules it is
on-demand work inside `mr` (CGI for the web UI, `mr sys …` for SSH / agents); the only daemons are the
ones the config switches on (ntpd always, crond only while schedules or the DDNS check exist).

| | |
|---|---|
| Go | `mr/mod_sys.go` (module, types, validation, render), `mod_sys_time.go` (POSIX TZ parser, TZif writer, NTP, `sys.time`), `mod_sys_ssh.go` (dropbear, managed `authorized_keys`), `mod_sys_cron.go` (schedules, `mr sys run`), `mod_sys_ddns.go` (DDNS: addresses, state, Cloudflare client, `mr ddns`), `mod_sys_wol.go` (Wake-on-LAN: `mr wol`, `sys.wol`), `mod_sys_backup.go` (backup / restore), `mod_sys_fw.go` (firmware upload, sysupgrade / factory-reset hooks), `mod_sys_api.go` (diag, service, services, logs, `mr sys`), `mod_sys_linux.go` / `mod_sys_other.go` (adjtimex) |
| UI | `rootfs/www/ui/sys.js` — 服务 (group 服务, with the DDNS card); 系统设置, 管理与 SSH, 计划任务, 备份与升级, 日志, 网络诊断 (group 系统). The 唤醒 (WOL) buttons sit on the dns module's pages (`dns.js`: 终端设备, DHCP 静态分配) |
| rootfs | `rootfs/etc/init.d/{tailscale,mr-panel,mr-zram,lucky,lucky-dns-inotify,dstatus-agent}` (tailscale and mr-panel now read their conf.d) |
| Checks | `mr/mod_sys_test.go`, `mr/mod_sys_ddns_test.go` (fake Cloudflare API), `mr/mod_sys_wol_test.go`, `tools/ci.d/sys.sh` (incl. WOL through a bridge in network namespaces), lab fragment `examples/lab.d/70-sys.yaml` (+ `mr/testdata/secrets.d/sys.yaml`) |
| Mock | `tools/mock/fixtures/sys.*.json` (incl. `sys.ddns.json`, `sys.ddnsupdate.post.json`, `sys.wol.post.json`), `service.post.json`, `diag.post.json`, `config.d/sys.json` |

## Cost

| | |
|---|---|
| Flash | `mr` +192 KiB (arm64, stripped: 5.06 → 5.25 MiB), `sys.js` 45 KB (was 5 KB), mock fixtures only in the repo |
| RAM, always | nothing new. `ntp_server` makes the existing ntpd answer on udp/123 (no extra process) |
| RAM, with schedules | busybox crond (~100 KB private; the busybox text is shared) |
| DDNS | nothing resident: crond (above) plus one short `mr ddns sync` per WAN event / interval; state 1–2 KB in `/run` (tmpfs). `mr` grows by ≈61 KiB of code and data (arm64, stripped; ≈19 KB xz-compressed; the file itself stayed 8.25 MiB thanks to segment padding) — net/http and TLS were already linked for the WAN check. An unchanged address costs no network request |
| RAM, on demand | CGI runs of `mr` while a page is open; during a restore a `mr sys restore-watch` process sleeps until the confirm window is over (≈4 MB for at most ~12 min); a firmware upload sits in `/tmp` (RAM) until it is flashed or deleted |
| WOL | nothing resident, no config; `mr` +≈18 KiB of code and data (arm64, stripped; ≈6 KB xz) — plain socket syscalls, not the net package's listener (that was +30 KiB) |
| CPU | nothing periodic. Services page: one `rc-service status` per service (in parallel) and one `tailscale status --json` |

## router.yaml

```yaml
system:
  hostname: mini-router
  timezone: "<+08>-8"        # POSIX TZ string (Alpine has no zoneinfo); empty = UTC
  ntp: [ntp.tencent.com, ntp1.aliyun.com]   # host names or IPs, max 8; empty = pool.ntp.org
  ntp_server: false          # also answer NTP (udp/123) — only the LAN zone gets through the firewall
  sysctl: {net.ipv4.tcp_congestion_control: bbr}   # added to / overriding 90-mini-router.conf
  zram: true              # zram swap (1/4 of RAM, zstd); also MGLRU min_ttl_ms=1000: OOM kill instead of thrashing
  history: 20             # config snapshots / change records kept (5-200)

services:
  tailscale: {enabled: true, port: 41641}   # tailscaled --port; the same UDP port is opened on the WANs
  lucky: {enabled: true, port: 16601}       # port only feeds the "open Lucky" link in the web UI
  dstatus: {enabled: true}
  stubby: {enabled: true}
  ssh:
    enabled: true
    port: 22
    password_login: false    # dropbear -s -g
    lan_only: false          # true: listen only on the IPv4 address of every LAN-zone network
    authorized_keys:         # managed block in /root/.ssh/authorized_keys (other lines are never touched)
      - ssh-ed25519 AAAAC3Nza... me@laptop
  panel: {enabled: true}     # web UI (busybox httpd on the main LAN address, port 80)
  ddns:                      # dynamic DNS, no daemon (see "DDNS" below)
    enabled: true
    interval: 10             # minutes between safety checks by crond (5-60); 0 = only on WAN events
    records:
      - name: home.example.com         # host name to keep updated (also *.example.com)
        zone: example.com              # the zone at the provider
        provider: cloudflare           # default; the only one so far
        token_secret: cf_ddns_token    # secrets.yaml: API token, permission Zone › DNS › Edit on this zone
        ipv4: active                   # A: active (default) | <wan name> | "off"
        ipv6: router                   # AAAA: "off" (default) | router | "::10" (a LAN device)
        ttl: 0                         # 60-86400; 0 = automatic

schedules:                   # busybox crond; fixed actions only
  - {name: weekly-reboot, cron: "30 4 * * 1", action: reboot}
  - {name: wifi, cron: "0 5 * * *", action: restart, target: mr-hostapd}
  - {name: redial-wan2, cron: "0 */6 * * *", action: reconnect, target: wan2}
  - {name: wake-nas, cron: "0 7 * * 1-5", action: wol, target: nas}   # dhcp.hosts name (or a MAC)
  - {name: paused, enabled: false, cron: "0 3 1 * *", action: reboot}
```

Validation (the security boundary — everything below ends up in a file, a crontab or a command line):

* `timezone`: strict POSIX TZ grammar — names of 3–16 letters or `<…>` (letters, digits, `+`, `-`),
  offsets up to 24:59:59, a DST name needs explicit rules (`Jn`, `n`, `Mm.w.d`, optional `/time`).
  Olson names (`Asia/Bangkok`) are rejected: there is no zoneinfo on the router. The web UI has presets.
* `ntp`: IP address or DNS host name (no `keyno:` prefixes, no leading `-`).
* `sysctl`: key `a.b[.c…]`, value without control characters or `=`; at most 64 keys.
* `ssh.authorized_keys`: `type base64 [comment]`, type one of ed25519 / rsa / ecdsa / sk-*, the base64
  blob must start with the same key type, no options (`command=`, `from=` …), printable comment, no
  duplicates, at most 32. `ssh.port` must not be 53/67/80/123/547 or the tailscale port.
* `schedules`: name `[A-Za-z0-9_.-]{1,40}` and unique; `cron` exactly 5 numeric fields (`*`, `n`,
  `a-b`, `*/n`, `a-b/n`, lists; no names, no `@reboot`), minute a single number (every task runs at
  most once per hour), for `reboot` the hour too (at most once per day). `restart` targets must be a
  service this config enables (not `mr-network`); `reconnect` targets a PPPoE / DHCP WAN; `wol` targets a
  `dhcp.hosts` name (letters, digits, `-`) or a unicast MAC.
* `ddns`: at most 16 records; `name` a DNS name with at least one dot (a leading `*.` allowed), unique, inside
  `zone` (the zone itself or a subdomain); `provider` `cloudflare`; `token_secret` a secret name `[a-z0-9_-]{1,40}`
  that exists, whose value looks like an API token (20–256 of `A-Za-z0-9 - _ . ~ + / =`: it goes into an HTTP
  header); `ipv4` `active`, `off` or a configured WAN; `ipv6` `off`, `router` or `::IID` (upper 64 bits zero,
  lower 64 not); not both off; `ttl` 0 or 60–86400; `interval` 0 or 5–60; `enabled` needs records.

## Generated files

| File | Content | On change |
|---|---|---|
| `/etc/hostname` | hostname | `hostname` |
| `/etc/sysctl.d/90-mini-router.conf` | forwarding, syncookies, fq_codel, `nf_conntrack_max=100000`, no ICMP redirects (`send_redirects=0` for `all` and `default`), hardening (`kptr_restrict=2`, `dmesg_restrict=1`, `bpf_jit_harden=2`), proxy path (`rmem_max` / `wmem_max` 7500000 for QUIC, `tcp_notsent_lowat=131072`, `tcp_slow_start_after_idle=0`), … + `system.sysctl` | sysctl reload |
| `/etc/modules-load.d/mr-sys.conf` | `nf_conntrack` | — (boot) |
| `/etc/conf.d/sysctl` | `rc_after="modules"` | — (boot) |
| `/etc/localtime` | TZif v2 built from `system.timezone` (see below) | restart `syslog` (timestamps) |
| `/etc/profile.d/tz.sh` | `export TZ=…` for login shells | — |
| `/etc/conf.d/ntpd` | `NTPD_OPTS="-N -S /usr/libexec/mr/clock-save -p … [-l]"`（`clock-save` 每小时最多一次把已同步的时间记到闪存，开机时 `mr-clock` 从它恢复——板子没有 RTC） | restart `ntpd` |
| `/etc/conf.d/dropbear` (ssh on) | `DROPBEAR_OPTS="-p [addr:]port … -K 300 [-s -g]"` | restart `dropbear` |
| `/etc/conf.d/tailscale` (on) | `TS_PORT=` (read by `/etc/init.d/tailscale`) | restart `tailscale` |
| `/etc/conf.d/mr-panel` (on) | `PANEL_ADDR=` main LAN address (was a `sed` on router.yaml) | restart `mr-panel` |
| `/etc/conf.d/crond` (schedules) | `CRON_OPTS`, `export TZ=…` | restart `crond` |
| `/etc/crontabs/root` | managed block between markers (schedules; DDNS on with an interval adds `*/N * * * * /usr/sbin/mr ddns sync --cron`); Alpine's periodic lines and anything else kept | — (crond rescans the directory) |
| `/root/.ssh/authorized_keys` | managed block between markers; every other line kept | — (read per login) |

conf.d files of optional services are only rendered while the service is enabled, so switching a
service off never restarts it (the restart for a changed file would start it again).

`crontab` and `authorized_keys` are rendered from the *current* file plus the managed block, so
`mr render` / `mr plan` show exactly what apply would write, the apply snapshot covers them and a
rollback restores them. A begin marker without an end marker swallows the rest of the file (it was
written by mr); stray end markers are dropped. mr never creates either file unless it has something to
put in its block.

### Time zone without zoneinfo

musl (and Go) read `/etc/localtime` when `TZ` is not set, which is the case for every daemon OpenRC
starts. mr writes a TZif v2 file with one standard-time type, a single transition at -2^59 and the POSIX
string as footer; readers apply the footer rule to every time after the last transition, i.e. always,
so DST zones work too. CI compares glibc reading the file with glibc interpreting the POSIX string
directly at 146 instants over two years (home zone and a DST zone); musl was checked once by hand
(Alpine 3.24 container: Bangkok, Berlin, Sydney, New York, India, January and July). crond also gets
`TZ` from its conf.d, so schedules do not depend on the file.

## DDNS

Built into `mr` instead of a resident daemon (the home router ran lucky, ~50 MB RSS, mostly for this).

**When it runs.** Nothing waits in memory; a sync is a short `mr` run:

* WAN events — the net hooks call the core `OnWAN` hook (PPP up, DHCP bound / renew, dhcpcd RA / delegated
  prefix, multi-WAN failover); sys starts `mr ddns sync --hook` in the background. It waits 5 s (a PPPoE
  reconnect brings IPv4, then RA, then the prefix) — only one waiter at a time (flock on `/run/mini-router/ddns.wait`,
  released before the addresses are read, so a later event starts the next waiter) — and every sync holds
  `/run/mini-router/ddns.lock`. A burst of events costs one or two syncs. Only events that can change a published
  value start one: `ipv6` for AAAA records, `up` / `health` for A records, `down` never.
* crond — `*/interval * * * * /usr/sbin/mr ddns sync --cron`: the safety net for missed events and failed updates;
  it also asks the provider once a day whether the record still holds the address (edited by hand?).
* apply — an apply that leaves DDNS on starts one sync (sys `Verify`; it never fails the apply).
* `mr ddns update [--force] [NAME…]` and the web UI's 立即更新 (`sys.ddnsupdate`, always with force).

**Only on change.** The state keeps, per record and type, the address last published. A sync computes the local
address and calls the provider only when they differ (or `--force` / the daily check): an unchanged address costs
no network request. Failures back off 1, 2, 4 … 60 minutes (`retry`); a refused token (HTTP 401 / 403 or
Cloudflare's auth error codes) stops the record (`stopped`) until its config or token changes — 立即更新 still
tries. A config change (zone, name, TTL, token) starts that record's state afresh, so it is pushed at once.

**Values.**

| Setting | Address |
|---|---|
| `ipv4: active` | the WAN lease records the net hooks write (`/run/mini-router/wan/<name>.json`), healthy WANs first, then by metric: the first **public** address. Private (RFC 1918) and CGNAT (100.64/10) addresses are never published — the row says why (`note`) |
| `ipv4: <wan>` | that WAN's address (same rule) |
| `ipv6: router` | the router's own global address: the main LAN bridge's address from the delegated prefix (`<prefix>::1`, stable while the prefix is), else a WAN's global address. Temporary, deprecated, tentative and ULA addresses are skipped |
| `ipv6: "::10"` | that interface ID on the main LAN's delegated /64 — a LAN device with a fixed interface ID (static token / EUI-64). Inbound traffic to it also needs `firewall.ipv6_allow` |

Removing a record from the config stops updating it; mr never deletes DNS records.

**Cloudflare** (API v4, `https://api.cloudflare.com/client/v4`, token in the `Authorization: Bearer` header):
`GET /zones?name=<zone>` (id cached in the state), `GET /zones/<id>/dns_records?type=A|AAAA&name=<name>`, then
`PATCH …/dns_records/<id>` with only `content` (and `ttl` when configured) for every record of that name and type
that differs — proxied (orange cloud), comments and tags stay — or `POST` a new record (not proxied, TTL automatic
unless set) when there is none. At most 3 requests per record and type per change. Ids from answers must be 32
hex digits before they go into a URL path; answers are capped at 1 MiB; timeouts 20 s per request; no proxy from
the environment, no redirects; TLS is verified against the image's CA bundle (`ca-certificates-bundle`). Right
after boot, before NTP, the clock can be off enough for TLS to fail — the backoff retries.

**Secrets.** The token only lives in `secrets.yaml` and in the request header: errors are stripped of URLs and
control characters, the state file (`/run/mini-router/ddns.json`, 0600, tmpfs) keeps a truncated SHA-256 of
config + token to notice changes, and `mr ddns status`, `sys.ddns`, `sys.ddnsupdate` and `mr status` never contain
it (tested).

**A second provider** is one function (`upsert`: make every record of that name and type hold the address) in
`ddnsProviders`, plus its name in the validation.

## Wake-on-LAN

`mr wol MAC|HOST [NETWORK]`, the web UI's 唤醒 buttons (状态 › 终端设备 and DHCP 静态分配, POST `sys.wol`) and the
schedule action `wol HOST` all send the same thing: the magic packet (6 × `ff`, then the MAC 16 times, 102 bytes) as
a UDP datagram to port 9 of the LAN-side network's **directed broadcast** (e.g. `192.168.1.255`), three times, from the
router's address on that network, with the socket bound to its bridge (`SO_BINDTODEVICE` + `SO_BROADCAST`). It can
only leave through that bridge — `255.255.255.255` would follow the default route out of a WAN. No config and nothing
resident:

* `HOST` is a `dhcp.hosts` name (case-insensitive); a MAC may be any unicast address (a known one also finds its host);
* the network is `NETWORK` (`lan` or a `networks[]` name) if given, else the one the host's static address is in, else
  the main LAN (a device the router has never seen still gets woken on the main LAN);
* multicast / broadcast / all-zero MACs, unknown names and networks are refused; every run is logged (`wol: …`), a
  scheduled one also in the change log.

Waking from outside works through the web UI (e.g. over Tailscale); there is deliberately no WOL listener on the WAN.
The device must have Wake-on-LAN enabled (BIOS / NIC driver) and usually needs a wired connection.

### Boot order for `net.netfilter.*`

`nf_conntrack` is a module; before this change the firewall loaded it (via the ct rules) only after the
boot-time `sysctl` service had run, so `nf_conntrack_max` failed with "unknown key" and was **never
applied at boot** (mr-network re-applies 90-mini-router.conf with errors hidden, also before the
firewall). Now the boot `modules` service loads it from `/etc/modules-load.d/mr-sys.conf`, and
`/etc/conf.d/sysctl` orders `sysctl` after `modules` (checked: OpenRC puts `modules` into sysctl's
`iafter` list). Loading the module does not start tracking by itself (hooks register when the
ruleset uses conntrack), so there is no cost before the firewall. The mon module's `91-mon.conf`
(`nf_conntrack_acct`) now applies at boot for the same reason. The platform part may also put
`nf_conntrack` into `/etc/modules`; both together are harmless.

## API (logged-in session)

| Action | Method | Body → result |
|---|---|---|
| `service` | POST | `{name, op: start\|stop\|restart}` — a service the config enables (not `mr-network`); used by several modules' pages |
| `diag` | POST | `{tool: ping\|ping6\|traceroute\|traceroute6\|nslookup, host}` (old `{ipv6: true}` still works) → `{output, command}`; 25 s timeout, argv only |
| `sys.time` | GET | `{now, tz, offset, local, ntp, ntp_server, synced}` (`synced` from adjtimex, `null` if unknown) |
| `sys.sshkeys` | GET | keys in root's authorized_keys: `managed[]`, `other[]` `{type, comment, fingerprint}`, `other_unparsed`, `root_password: set\|locked\|empty` (never the hash) |
| `sys.services` | GET | `services[]` `{name, label, cfg, wanted, installed, running}`, `others[]`, ports, `tailscale` `{state, self, peers[], peers_online, tailnet, auth_url (only while NeedsLogin)}` |
| `sys.logs` | GET / POST | `{level 0-7, tag, q, limit ≤ 5000}` → `lines[]` `[time, level, facility, tag, message]` newest first, `total`, `tags{}` (source `/var/log/messages{.0,}`, `logread` if absent) |
| `sys.schedulecheck` | POST | `{cron, action}` → `{ok, cron \| error}` (editor feedback, no side effects) |
| `sys.ddns` | GET | `{enabled, interval, records[]}` — per record and type: `name, type, source, local, published, note, last_ok, changed, checked, error, error_at, retry, stopped, fails` (local addresses as of now; no provider request; never the token or zone id) |
| `sys.wol` | POST | `{target: MAC \| dhcp.hosts name, network (optional)}` → `{mac, host, network, dev, broadcast}`; 400 for a bad target / network, 500 if sending failed |
| `sys.ddnsupdate` | POST | `{name (optional), force}` → same as `sys.ddns` after an update run (ignores backoff and a stop; `force` also asks the provider for records the state calls published). 409 while DDNS is off |
| `sys.backup` | POST | `{secrets: bool}` → `{name, data (base64 tar.gz), size, files[], restorable}` |
| `sys.restore` | POST | `{data (base64 tar.gz ≤ 2.9 MB), confirm: 60-600}` → starts the apply job; poll `job`, then `confirm` / `revert` as for any apply |
| `sys.fw` | GET | `{sysupgrade, factory_reset (scripts present), tmp_free, max_image, max_chunk, upload {total, received}, run {state: "" \| running \| failed \| done \| stale, rc, message}}` |
| `sys.fwupload` | POST | `{offset, total, data (base64 ≤ 2 MiB)}` → `{received}`; must continue exactly at the end of the file (409 + `received` otherwise, so a lost response can be resumed); `{cancel: true}` deletes it |
| `sys.fwupgrade` | POST | `{sha256}` — must match the uploaded file, then `/usr/libexec/mr/sysupgrade <image>` runs detached |
| `sys.factoryreset` | POST | `{confirm: "RESET"}` → `/usr/libexec/mr/factory-reset` runs detached |

Mutations are POST only. `sys.backup` returns secrets only when asked for (the user's own download),
never the web UI password hash. The firmware image lives in `/tmp/mr-upgrade/` (created 0700 by root;
anything else at that path — a symlink, a foreign directory — is removed first, and the image is opened
with `O_NOFOLLOW`). The platform scripts are started through `sh -c` with a constant command text
(`"$0" "$@"`; the image path is an argument), because they must work even when `router.yaml` does not
load; output and exit code go to `/run/mini-router/fw-run.{log,rc}`.

## Restore in detail

1. The archive is checked: gzip + tar, at most 256 entries / 16 MiB per file / 48 MiB in total, only
   `etc/mini-router/router.yaml` (required), `etc/mini-router/secrets.yaml`, `mr-backup.json` and
   `etc/mini-router/{dns,proxy}/<name>` with `<name>` = `[A-Za-z0-9][A-Za-z0-9_.-]{0,63}`, regular files
   only, list files UTF-8 text. Anything else (absolute paths, `..`, symlinks, other files or
   directories) rejects the whole archive.
2. Secrets: the backup's are laid over the current ones; `webui_password` always stays the current one.
3. List files that differ are saved first as `<time>-restore-lists.tar.gz` in the snapshot history (the
   core snapshot format, so 变更历史 can also roll back to it), then written.
4. The candidate config is validated and rendered; on any error the list files go back and nothing else
   has changed.
5. The candidate is written where the web UI's apply writes it and the core `apply-job` runs:
   snapshot, apply, verify, 120 s confirm countdown, automatic rollback. A small watcher puts the list
   files back if that apply fails or is rolled back (not confirmed, or 立即回滚).

List files that exist on the router but not in the backup are left alone.

## CLI

```
mr sys run reboot | restart SERVICE | reconnect WAN | wol HOST   # what crond runs (checked against the config, logged)
mr wol MAC|HOST [NETWORK]                                # Wake-on-LAN (JSON: mac, host, network, dev, broadcast)
mr sys backup [-secrets] FILE|-                          # same archive as the web UI
mr sys restore [-confirm 60-600] FILE                     # same checks and apply job; then `mr confirm`
mr sys keys                                              # authorized_keys: managed / other, fingerprints
mr ddns status                                           # records: local / published address, last result (offline)
mr ddns update [--force] [NAME...]                       # update now (ignores backoff); --force also re-checks at the provider
mr ddns sync [--hook|--cron]                             # what the WAN hooks (5 s debounce) / crond run
```

`mr status` has `ddns: {records, ok, errors[]}` while DDNS is on (the overview shows failing records).

## Platform interface

* `/usr/libexec/mr/sysupgrade IMAGE` — IMAGE is `/tmp/mr-upgrade/firmware.img`; exit ≠ 0 = refused,
  reason on stderr (shown in the web UI); on success it flashes and reboots. `/tmp` must be a tmpfs
  with room for the image (+8 MiB).
* `/usr/libexec/mr/factory-reset` — wipes the configuration and reboots.
* Boot runlevel must contain `modules` and `sysctl` (build/m2 does).

## Changes to the real home output (examples/router.yaml)

* New files: `/etc/localtime` (+08), `/etc/modules-load.d/mr-sys.conf`, `/etc/conf.d/sysctl`,
  `/etc/conf.d/tailscale` (`TS_PORT=41641`, same as the old hard-coded port), `/etc/conf.d/mr-panel`
  (`PANEL_ADDR=192.168.1.6`, what the old `sed` found). The first apply after the update therefore
  restarts `syslog`, `tailscale` and `mr-panel` once.
* `conf.d/ntpd`, `conf.d/dropbear`, `90-mini-router.conf`, `hostname`, `tz.sh`: byte-identical.
* No crontab, no authorized_keys change (no schedules, no managed keys), crond stays off.
* Log timestamps, the change log and snapshot names switch from UTC to the router's zone (daemons now
  see `/etc/localtime`).

## 怎么用

### 网页

- **服务**（服务分组）：Tailscale、Lucky、dstatus、stubby、SSH、Web 管理、NTP、计划任务、zram 每个一张卡片：
  运行状态、开关（改完点底部“保存并应用”）、“重启”按钮（立即生效）。Tailscale 卡片显示本机地址、在线节点，
  下面有节点表（直连 / 中继、流量、最后在线）；路由器还没登录 Tailscale 时会给出登录链接。Lucky 卡片有
  “打开 Lucky 管理界面”链接。页面底部是其它模块的服务（dnsmasq、hostapd、PPPoE …），也能单独重启。
- **服务 › DDNS 动态域名**（同一页下方）：开关、定时检查间隔；记录表每行一个域名：Zone、Token 引用名和 Token
  （只写入 secrets.yaml，页面不会显示）、A 记录（在用的 WAN / 指定 WAN / 不更新）、AAAA（`off` / `router` /
  `::10` 这样的 LAN 设备后缀）、TTL。改完点“保存并应用”，应用后会立即同步一次。下面的状态表显示每条记录的本机
  地址、已发布地址、上次成功时间和错误；“立即更新”马上向 Cloudflare 核对并更新（忽略退避）。更新失败时总览页有提示。
  Cloudflare Token：My Profile › API Tokens › Create Token › “Edit zone DNS” 模板，Zone Resources 只选这个域。
- **系统设置**：主机名、zram；时间区显示路由器当前时间和 NTP 是否已同步，“立即同步”重启 ntpd；
  时区从列表选（曼谷、北京、东京、柏林、纽约……），列表里没有就选“自定义 POSIX TZ”手填；
  NTP 服务器逗号分隔；“为局域网提供 NTP”打开后 LAN（含 Tailscale）可以把路由器当时间服务器，
  访客网络和外网访问不到——要让设备自动用它，在 DHCP 设置里把 NTP 选项填成路由器地址。
  下面是 sysctl 表和“重启路由器”。
- **管理与 SSH**：SSH 开关、端口、是否允许密码登录、“只监听 LAN 地址”；公钥框每行一个公钥，
  保存后写进 `/root/.ssh/authorized_keys` 的受管区块。下面列出当前生效的受管公钥和文件里其它公钥
  （带指纹）——其它公钥 mr 永远不动，所以不会因为改这里把自己锁在外面。没有任何公钥又禁止密码登录、
  或允许密码登录但 root 没设密码时，页面会提示。还有 Web 管理开关和管理员密码修改，以及“API 令牌”
  （给脚本 / Home Assistant / AI agent 用：生成时只显示一次，列表有最后使用时间和来源，可吊销；见 `docs/api.md`）。
- **网络唤醒（WOL）**：状态 › 终端设备 或 网络 › DHCP / IPv6 RA › 静态分配，在设备那一行点“唤醒”。
  设备要在 BIOS / 网卡设置里打开 Wake-on-LAN，一般要插网线。人在外面时通过 Tailscale 打开网页再点。
  定时唤醒：计划任务里选“唤醒设备 (WOL)”，对象是静态分配里的主机。
- **计划任务**：表格列出任务（可直接开关）；“+ 添加 / 编辑”弹窗里选动作（重启路由器 / 重启服务 /
  重连 WAN / 唤醒设备）、对象、时间（每天 / 每周几 / 每月几号 / 每 N 小时 / 自定义 cron），下面实时显示 cron
  表达式、中文说明和校验结果。重启路由器最多每天一次，其它任务最多每小时一次。
- **备份与升级**：
  - 下载备份：默认只含 router.yaml 和列表文件；勾选“包含机密”才带 PPPoE / WiFi 等密码（明文，
    不含管理员密码）。
  - 恢复：选备份文件 →“校验并恢复”。有问题会列出原因且什么都不改；通过后和平时保存一样应用，
    120 秒内点“保留”，否则自动回滚（列表文件一起回滚）。
  - 固件升级：选镜像 → 浏览器算 SHA-256 → 分块上传（有进度条）→ 确认后刷写，路由器自动重启。
    镜像被平台脚本拒绝时显示原因。当前构建没有升级脚本时显示“当前构建不支持”。
  - 恢复出厂设置：确认两次（第二次要输入 RESET）。
  - 每次应用都记在“变更历史”页面（来源、备注、结果、改了什么），可以对比或回滚到任意一次之前。
- **日志**：按级别（错误及以上、警告及以上……）、服务（下拉里有每个服务的行数）、关键字过滤，
  可选 300–5000 行、自动刷新。时间是路由器时区。
- **网络诊断**：Ping / Ping6 / Traceroute / Traceroute6 / nslookup，有几个常用目标的快捷按钮。

### router.yaml / agent

编辑 `/etc/mini-router/router.yaml` 的 `system` / `services` / `schedules`（格式见上），然后
`mr validate && mr apply --confirm 120`，确认网络正常后 `mr confirm`。例子：

```yaml
system:
  timezone: "CST-8"            # 带路由器去中国
  ntp_server: true
services:
  ssh:
    enabled: true
    port: 22
    password_login: false
    lan_only: true
    authorized_keys:
      - ssh-ed25519 AAAAC3Nza... user@laptop
schedules:
  - {name: weekly-reboot, cron: "30 4 * * 1", action: reboot}          # 每周一 04:30 重启
  - {name: redial-wan2, cron: "0 5 * * *", action: reconnect, target: wan2}   # 每天 05:00 重拨 wan2
```

DDNS：先把 Cloudflare Token 写进 `/etc/mini-router/secrets.yaml`（`cf_ddns_token: <token>`，不要回显到终端），然后

```yaml
services:
  ddns:
    enabled: true
    records:
      - {name: home.example.com, zone: example.com, token_secret: cf_ddns_token, ipv6: router}   # A + AAAA 指向路由器
```

应用后 `mr ddns status` 看结果（几秒后 `published` 应等于 `local`）。

备份 / 恢复：`mr sys backup -secrets /tmp/b.tgz`，拷走；恢复 `mr sys restore /tmp/b.tgz` 然后
`mr confirm`。手动试跑计划任务的动作：`mr sys run restart dnsmasq`。唤醒一台设备：`mr wol nas`（静态分配里的
名字）或 `mr wol aa:bb:cc:dd:ee:ff [网络名]`。

### 排障

- 时间不对：`date`（应显示路由器时区）；`cat /etc/conf.d/ntpd`；网页“系统设置”看 NTP 是否已同步。
  没有电池时钟，开机到 NTP 同步前时间是错的，crond 遇到时间跳变超过 1 小时不会补跑任务。
- 计划任务没执行：`rc-service crond status`；`cat /etc/crontabs/root`；`grep schedule /var/log/messages`。
- DDNS 没更新：`mr ddns status`（`note` 说明为什么没有本机地址，例如 WAN 是 CGNAT / 私网地址、还没有 IPv6 前缀；
  `error` / `stopped` 是 Cloudflare 的回答）；`grep ddns: /var/log/messages`；`mr ddns update --force` 立即重试。
  Token 被拒绝（`stopped`）：检查 Token 权限（Zone › DNS › Edit，覆盖这个 zone），改 secrets.yaml 后应用即恢复。
- SSH 连不上：`cat /etc/conf.d/dropbear`（`lan_only` 时只监听 LAN 地址）；`mr sys keys` 看公钥。
- 开机后 `sysctl net.netfilter.nf_conntrack_max` 应为 100000（或 `system.sysctl` 里的值）。
