# sys — time, SSH, add-on services, DDNS, HTTPS reverse proxy, schedules, backup / restore, firmware, logs, diagnostics, health checks, events, notifications

Everything that is "the router itself" rather than a network feature. Like the other modules it is
on-demand work inside `mr` (CGI for the web UI, `mr sys …` for SSH / agents); the only daemons are the
ones the config switches on (ntpd always, crond only while schedules, the DDNS check or the certificate check
exist, `mr edge serve` only while the reverse proxy is on).

| | |
|---|---|
| Go | `mr/mod_sys.go` (module, types, validation, render), `mod_sys_time.go` (POSIX TZ parser, TZif writer, NTP, `sys.time`), `mod_sys_ssh.go` (dropbear, managed `authorized_keys`), `mod_sys_cron.go` (schedules, `mr sys run`), `mod_sys_ddns.go` (DDNS: addresses, state, Cloudflare client, `mr ddns`), `mod_sys_edge.go` (reverse proxy: config, validation, edge.json, firewall / dnsmasq lines, Verify), `mod_sys_edge_acme.go` (ACME client, DNS-01, certificate files, `mr edge renew / status`, API), `mod_sys_edge_serve.go` (`mr edge serve`), `mod_sys_wol.go` (Wake-on-LAN: `mr wol`, `sys.wol`), `mod_sys_backup.go` (backup / restore), `mod_sys_fw.go` (firmware upload, sysupgrade / factory-reset hooks), `mod_sys_api.go` (diag, service, services, logs, `mr sys`), `mod_sys_doctor.go` (`mr doctor`, `sys.doctor`), `mod_sys_event.go` (event log, `mr event`, `sys.events`), `mod_sys_notify.go` (`notify:`, Telegram / webhooks, `mr notify`, `sys.notifytest`), `mod_sys_linux.go` / `mod_sys_other.go` (NTP sync state) |
| UI | `rootfs/www/ui/sys.js` — 服务 (group 服务, with the DDNS and HTTPS 反向代理 cards); 系统设置, 管理与 SSH, 计划任务, 备份与升级, 日志, 网络诊断 (group 系统); 体检与事件 (group 状态: 体检 / 事件 / 通知). The overview (`core.js`) shows the last health check's problems and the newest events. The 唤醒 (WOL) buttons sit on the dns module's pages (`dns.js`: 终端设备, DHCP 静态分配) |
| rootfs | `rootfs/etc/init.d/{tailscale,mr-panel,mr-zram,lucky,lucky-dns-inotify,dstatus-agent,mr-edge}` (tailscale and mr-panel now read their conf.d); the image and `install.sh` create the user `mr-edge`; events: `mr-bootlog` (`mr event boot` / `shutdown`), `usr/libexec/mr/mon-collect` (the mon module's sampler starts `mr event tick`), NTP sync marker: `mr-clock` + `usr/libexec/mr/clock-save` |
| Checks | `mr/mod_sys_test.go`, `mr/mod_sys_ddns_test.go` (fake Cloudflare API), `mr/mod_sys_wol_test.go`, `mr/mod_sys_edge_test.go`, `mod_sys_edge_acme_test.go` (in-process ACME server + fake Cloudflare), `mod_sys_edge_serve_test.go`, `mr/mod_sys_{doctor,event,notify}_test.go` (fake system, fake Telegram / webhook; `TestMain` keeps every test's events off the host), `tools/ci.d/sys.sh` (incl. WOL through a bridge in network namespaces; events and a local webhook with real processes; `mr doctor` on the build host), `tools/ci.d/sys-edge.sh` (the proxy process in network namespaces, WAN side through the rendered nft lines, memory), `tools/ci.d/mon.sh` (the sampler's tick trigger), `tools/ci.d/net.sh` (WAN / failover events from the real hooks), lab fragment `examples/lab.d/70-sys.yaml` (+ `mr/testdata/secrets.d/sys.yaml`) |
| Mock | `tools/mock/fixtures/sys.*.json` (incl. `sys.ddns.json`, `sys.ddnsupdate.post.json`, `sys.wol.post.json`, `sys.edge.json`, `sys.edgerenew.post.json`, `sys.doctor.json`, `sys.events.json`, `sys.notifytest.post.json`), `service.post.json`, `diag.post.json`, `config.d/sys.json`; `status.json` has `doctor` and `events` |

## Cost

| | |
|---|---|
| Flash | `mr` +192 KiB (arm64, stripped: 5.06 → 5.25 MiB), `sys.js` 45 KB (was 5 KB), mock fixtures only in the repo |
| RAM, always | nothing new. `ntp_server` makes the existing ntpd answer on udp/123 (no extra process) |
| RAM, with schedules | busybox crond (~100 KB private; the busybox text is shared) |
| DDNS | nothing resident: crond (above) plus one short `mr ddns sync` per WAN event / interval; state 1–2 KB in `/run` (tmpfs). `mr` grows by ≈61 KiB of code and data (arm64, stripped; ≈19 KB xz-compressed; the file itself stayed 8.25 MiB thanks to segment padding) — net/http and TLS were already linked for the WAN check. An unchanged address costs no network request |
| RAM, on demand | CGI runs of `mr` while a page is open; during a restore a `mr sys restore-watch` process sleeps until the confirm window is over (≈4 MB for at most ~12 min); a firmware upload sits in `/tmp` (RAM) until it is flashed or deleted |
| WOL | nothing resident, no config; `mr` +≈18 KiB of code and data (arm64, stripped; ≈6 KB xz) — plain socket syscalls, not the net package's listener (that was +30 KiB) |
| Reverse proxy | off: nothing. On: `mr edge serve` resident — idle 17 MB RSS, of which 7 MB anonymous (the rest are pages of the `mr` binary: shared, reclaimable); after 200 concurrent TLS clients × 20 requests 30 MB RSS (18 MB anonymous), peak 38 MB (x86_64 build host, `GOGC=50 GOMEMLIMIT=24MiB` as in the init script, measured by `tools/ci.d/sys-edge.sh` on every CI run); a daily `mr edge renew` that makes no request unless a certificate is due. `mr` +1.13 MiB (arm64, stripped: 9.11 → 10.29 MB): Go's HTTP server, HTTP/2 server, TLS server side and `httputil.ReverseProxy` (the client side was linked already); +57 KiB of it is this feature's own code |
| CPU | nothing periodic. Services page: one `rc-service status` per service (in parallel) and one `tailscale status --json` |
| Doctor, events, notifications | nothing resident. `mr` +128 KiB (arm64, stripped: 8,978,592 → 9,109,664 bytes, segment padding; +48.6 KB xz); `sys.js` +10 KB, `core.js` +1 KB. Runs: one short `mr event tick` per DHCP lease change and when `event.due` comes (a retry, the background doctor: every 30 min by default with channels, ~0.5 s CPU and a few `rc-service status` / one DNS lookup); a detached `mr notify flush` per burst of wanted events. Flash: see "Health checks, events, notifications" (a few lines a day; bounded to ~100 short appends an hour) |

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
  edge:                      # HTTPS reverse proxy + certificates (see "HTTPS reverse proxy" below)
    enabled: true
    port: 443
    open: true
    acme: {token_secret: cf_ddns_token, wildcard: [example.com]}
    routes:
      - {name: nas, host: nas.example.com, to: "http://192.168.1.10:5000"}

schedules:                   # busybox crond; fixed actions only
  - {name: weekly-reboot, cron: "30 4 * * 1", action: reboot}
  - {name: wifi, cron: "0 5 * * *", action: restart, target: mr-hostapd}
  - {name: redial-wan2, cron: "0 */6 * * *", action: reconnect, target: wan2}
  - {name: wake-nas, cron: "0 7 * * 1-5", action: wol, target: nas}   # dhcp.hosts name (or a MAC)
  - {name: paused, enabled: false, cron: "0 3 1 * *", action: reboot}

notify:                      # events pushed to the phone; no daemon (see "Health checks, events, notifications")
  channels:                  # at most 4
    - {name: phone, type: telegram, token_secret: notify_tg_token, chat_id: "123456789"}   # or -100… (group), @channel
    - {name: ntfy, type: webhook, url_secret: notify_ntfy_url, format: text}              # ntfy: plain text + Title header
    - {name: ha, type: webhook, url_secret: notify_ha_url}                                # json (default): Gotify, Bark, HA, Slack …
  events: [wan_down, wan_up, failover, rollback, login_lock, new_device, boot, upgrade, doctor, cert, wifi]   # default: all but apply
  rate: 10                   # messages per channel and hour (1-60); the rest goes out together later
  quiet_hours: "23:00-07:00" # router time: only warn / risk events then, the others wait
  doctor_interval: 30        # minutes between background `mr doctor` runs (5-1440, 0 = off); default 30 with channels
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
* `notify`: at most 4 channels; `name` `[a-z][a-z0-9_-]{0,14}` and unique; `telegram` needs `token_secret` (a secret
  that exists and looks like a bot token, `digits:[A-Za-z0-9_-]{20,80}`) and `chat_id` (a number, `-100…`, or `@name`),
  no `url_secret` / `format`; `webhook` needs `url_secret` (one line, no spaces, ≤ 2048 characters, `http://` or
  `https://` with a host) and `format` `json` | `text`, no `token_secret` / `chat_id`. Messages never repeat a secret.
  `events` known types without duplicates; `rate` 1–60; `quiet_hours` `HH:MM-HH:MM` (not empty); `doctor_interval` 0 or
  5–1440. API tokens and agents can never change `notify` (they must not silence or redirect the owner's alerts).
* `edge`: see "HTTPS reverse proxy" below.

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
| `/etc/crontabs/root` | managed block between markers (schedules; DDNS on with an interval adds `*/N * * * * /usr/sbin/mr ddns sync --cron`; the reverse proxy adds `M H * * * /usr/sbin/mr edge renew --cron`, M and H fixed per router, H 2–5; dns.adblock adds `M * * * * /usr/sbin/mr dns adblock update --cron`; wifi.steering / wifi.self_heal add `* * * * * /usr/sbin/mr wifi tick`); Alpine's periodic lines and anything else kept | — (crond rescans the directory) |
| `/etc/mini-router/gen/edge.json` (edge on) | port, WAN port, certificate directory, routes (host, target, certificate name, allow) — nothing secret, 0644 | restart `mr-edge` |
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

## HTTPS reverse proxy (services.edge)

The built-in replacement for lucky's "443 + SSL" reverse proxy (Cd1s/mini-router#6): HTTPS by host name to
services in the LAN, certificates from Let's Encrypt without port 80 (DNS-01, so it works behind blocked ports
and CGNAT as long as the port you use reaches the router). Off by default; lucky stays in the image until you
migrate (below).

```yaml
services:
  edge:
    enabled: true
    port: 443                 # HTTPS on every router address (default 443)
    open: true                # also from the WANs, IPv4 + IPv6 (default false: LAN zone + tailscale only)
    lan_dns: true             # default: the route hosts resolve to the router's LAN address on the LAN
    acme:
      email: admin@example.com          # optional ACME contact
      provider: cloudflare              # DNS-01 through the Cloudflare API (default; the only one so far)
      token_secret: cf_ddns_token       # secrets.yaml: API token with Zone › DNS › Edit — the DDNS token works
      staging: false                    # true: Let's Encrypt's staging CA (untrusted certificates, for trying it out)
      wildcard: [example.com]           # one certificate example.com + *.example.com for the hosts directly under it
    routes:
      - {name: nas, host: nas.example.com, to: "http://192.168.1.10:5000"}                 # everyone
      - {name: ha,  host: ha.example.com,  to: "http://192.168.1.20:8123", allow: [lan, 198.51.100.0/24]}
      - {name: cam, host: cam.example.org, to: "https://192.168.1.30", allow: [lan]}         # own certificate
      - {name: old, host: old.example.com, to: "http://192.168.1.40", enabled: false}
```

**Processes.** `mr edge serve` (OpenRC `mr-edge`, supervise-daemon, `GOGC=50 GOMEMLIMIT=24MiB`) is the only
resident part, and only while `enabled`. It reads `gen/edge.json` and its certificate files — never router.yaml or
secrets.yaml — so it runs as the user `mr-edge` with only `CAP_NET_BIND_SERVICE` when the image has that user (the M3
image and `install.sh` create it; without it, root). `mr edge renew` is a short run: crond once a day, after an apply
whose routes need a certificate that is missing or due (in the background; it never fails the apply), and the web
UI's 立即申请 / 续期.

**Who may connect.** Which side a connection came from is decided by the listener, not by address lists: with
`open`, nftables redirects the WANs' port (only for the router's own addresses — IPv6 pinholes to LAN hosts on the
same port are untouched) to the internal WAN listener `44300`, and accepts it there only when it was redirected:

    dstnat: iifname { WANs } fib daddr type local tcp dport 443 redirect to :44300 comment "edge"
    input:  iifname { WANs } tcp dport 44300 ct status dnat accept comment "edge"

So everything on the main port came through the LAN zone (LAN networks of zone lan, tailscale0; guest networks
cannot reach the router's ports) — `allow: [lan]` cannot be spoofed from outside, also not by a CGNAT neighbour.
A LAN client that uses the public address (hairpin) is still LAN. For the same reason a `firewall.open` of the edge's
tcp port is refused while the proxy is on (it would deliver WAN connections to the LAN listener): remove it and set
`open: true`. `allow` entries: `lan` and addresses / CIDRs (IPv4 and IPv6, matched against the client on both
listeners); empty = everyone who reaches the port. A refused client fails already in the TLS handshake.

**Proxying.** TLS 1.2+, HTTP/2 and HTTP/1.1 (Go's net/http). The certificate is picked by SNI; an unknown name (or
none — a scan of the address) fails the handshake, so no host names leak. The request's Host must equal the SNI name,
else 421 (with a wildcard certificate browsers may reuse an HTTP/2 connection for another host; 421 makes them open
one of its own). Each route goes to one upstream with `httputil.ReverseProxy`: the original Host, `X-Forwarded-For` /
`-Proto` / `-Host` from the connection (a client's own X-Forwarded-* headers are dropped), WebSocket and other
HTTP/1.1 upgrades passed through (browsers use HTTP/1.1 for WebSockets: extended CONNECT over HTTP/2 is off in Go),
streaming responses flushed at once, 502 when the upstream is down. `https://` upstreams are LAN addresses with
self-signed certificates: encrypted, not verified. No caching, no rewriting, nothing logged per request. Limits:
512 connections, 10 s for the TLS handshake and the request headers, 32 KiB of headers, 2 min idle; no body or
response timeouts (uploads, long polls, WebSockets). Counters per route (requests, 502s, refused) are in
`/run/mr-edge/status.json` (written at start and at most once a minute).

**Certificates.** ACME (RFC 8555) with the Go standard library only (ES256 JWS; no `x/crypto/acme` dependency): the
account key (ECDSA P-256, one per CA, `/etc/mini-router/state/acme/`, 0700 / 0600 root), order, DNS-01 — a TXT record
`_acme-challenge.<host>` created through the Cloudflare API with the DDNS client's code (the zone is the longest suffix
of the host the token can see), a wait until every authoritative name server of the zone answers it (asked directly,
no cache on the way; when they cannot be asked, e.g. port 53 blocked, the CA is asked anyway after 2 minutes), the
challenge, polling, finalize with a new ECDSA P-256 key, the chain checked (leaf = our key, every domain named, valid
now), then `/etc/mini-router/state/edge/<cert>.pem` (chain + key) written atomically, 0600, owned by the service user,
never through a symlink; the TXT records are deleted again in every case. `mr edge serve` reloads on SIGHUP (renew
sends it; `rc-service mr-edge reload` too) and by itself when a file changed. Certificates: one per host, except hosts
directly under a `wildcard` domain, which share `<domain>` + `*.<domain>` (file `_.<domain>.pem`); names under a
wildcard stay out of the certificate transparency logs. A certificate is renewed when it is missing, names other
domains, comes from the other CA (staging ↔ production) or has less than a third of its lifetime left (30 of 90
days); otherwise a run makes no request at all. Failures of automatic runs back off 1, 2, 4 … 24 h (or the CA's
Retry-After); manual runs try at once. Certificates of removed routes are deleted. Results: `/run/mini-router/edge-renew.json`
(tmpfs), `mr edge status`, the web UI, events of type `cert`. Every URL the CA names must be on the directory's host.

**Secrets.** The API token only goes into the `Authorization` header of Cloudflare requests; the account key and the
certificate keys stay in their files. None of them is in edge.json, the state file, `mr edge status`, `sys.edge`, events
or logs (tested). router.yaml's `services.edge.acme` references a secret, so API tokens cannot change it; routes are
config like any other (a token with apply scope can change them; they can only point at the LAN, below). Every change of
`services.edge` is a high-risk change (it decides what the internet reaches).

**Validation.** `port` 1–65535, not SSH / 53 / 67 / 80 / 123 / 547 / 44300 / lucky's UI port (while lucky is on);
`enabled` needs an enabled route and a `token_secret` naming an existing secret that looks like an API token; `provider`
`cloudflare`; `email` an address or empty; `wildcard` lower-case domains, at most 8; routes: at most 32, `name`
`[A-Za-z0-9_.-]{1,40}` unique, `host` a lower-case DNS name with a dot (no wildcard, no `_`) unique, `to`
`http(s)://IP[:port][/]` without user, path or query, the IP the router itself (loopback, a router address), a host
in a LAN-side network, a tailnet address (100.64/10) or an IPv6 ULA — never the proxy's own ports; `allow` `lan` or
addresses / CIDRs (at most 32); no enabled `firewall.open` of the tcp port while on; with `open`, no port forward of
that tcp port. `guard.never_expose`: a route the WAN can use (open, and allow not only `lan`) must not lead to the
router's own SSH / web UI / DNS port. `mr edge serve` checks its edge.json again (it is the process's only input).

**LAN.** With `lan_dns` (default) dnsmasq answers the route hosts with the main LAN address (`host-record=`, A only),
so the LAN reaches them without the public address and while the WAN is down. Guest networks get the same answer but
cannot reach the router's ports.

**Changes to the real home output:** none — `services.edge` is absent there, so no file, service, firewall line,
dnsmasq line or cron line appears (tested).

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

## Health checks, events, notifications

Nothing resident: the checks run when asked, events are appended by the code that sees them, and notifications go out
from short `mr` runs.

**`mr doctor`** (`sys.doctor`, web UI 状态 › 体检与事件 › 体检) — a fixed list of read-only
checks, each finding `ok | warn | risk | skip` with a one-line fix: `config` (validates, guard kept, edits not applied),
`pending` (a change waiting for confirmation, a failed boot rollback), `wan` (IPv4 address, multi-WAN health, CGNAT /
private address behind port forwards, a WAN address inside a LAN subnet — a hotel network on the same range), `routes`
(main default route, every WAN's table), `dns` (an A lookup through
dnsmasq on 127.0.0.1: the first NTP host name), `ipv6` (delegated prefix on the LAN), `offload` (flowtable loaded,
hardware flag, PPE entries), `services` (every service the config wants: installed and running), `wifi` (radios / BSSes
up), `clock` (after the image's build time, NTP synced within 30 min), `storage` (config flash, `/tmp`), `memory`,
`conntrack` (75 / 90 %), `temp` (90 / 105 °C), `crash` (pstore records, oops / BUG / OOM / lockup lines in this boot's
kernel log), `ssh` (password logins). The only programs run are `ip -j`, `nft list flowtable inet mr ft` and
`rc-service NAME status`; the rest is `/proc`, `/sys`, `/run` and the config. The result is kept in
`/run/mini-router/doctor.json`; `mr status` has its problems (`doctor: {time, risk, warn, ok, problems[]}`), the overview
shows them as 问题 (N).

"NTP synced" comes from a marker: busybox ntpd never lowers the kernel's maxerror, so `adjtimex` says "not synchronized"
while the clock is right (seen on the router: offset 0.4 ms, status UNSYNC). `mr-clock` creates `/run/mr-clock` for ntpd's
user, `clock-save` (ntpd `-S`, every 11 minutes while synced) touches `synced` in it and removes it on `unsync`; synced
= touched within 30 minutes. `sys.time` uses the same marker (adjtimex only where the directory does not exist).

**Event log** — `/etc/mini-router/state/events.log`, JSON lines `{seq, t, type, sev, key, msg}`, newest 200 kept
(rewritten at 250 lines or 96 KiB). On flash because the events that matter most (a crash, a power cut, a rollback at
boot) are the ones a RAM log loses. Types and where they come from:

| Type | Source | Severity |
|---|---|---|
| `wan_down` / `wan_up` | the net hooks' `OnWAN` (pppd ip-up / ip-down, udhcpc): a WAN that was up lost its address; it came back (with the downtime). The first up after boot, DHCP renewals and udhcpc's initial deconfig are not events. Expected ones are `info` with the reason: during an apply / rollback, or when the change log of the last 2 minutes names a redial / reconnect / restart of that WAN or its service (web UI, schedule, agent); while the system goes down (a fresh shutdown mark of this boot) they are not events at all | warn / info |
| `failover` | `OnWAN health` (net-wanmon): a WAN fails its health check (and where traffic goes) or passes again; the checker's first view only records | warn / info |
| `apply` / `rollback` | `history.go` `setResult`: a change applied / confirmed, rolled back (and why) | info / warn |
| `login_lock` | the login throttle (`api_login.go`, web UI passwords and API tokens) locked a source | warn |
| `new_device` | `mr event tick`: a DHCPv4 client whose MAC was never seen (`dhcp.hosts` count as known). The list of seen MACs is on flash (`devices.seen`, newest 2048, appended; a reboot reports nothing); the first day after it is created only learns (the lease file is in RAM, the house's devices come back one by one). At most 5 per scan one by one, the rest in one line. Host names come from the network: cleaned, capped | info |
| `boot` / `upgrade` | `mr event boot` (mr-bootlog, the last boot service): clean restart (a mark written by `mr event shutdown` when OpenRC stops the system — reboot and power-off both run the shutdown runlevel; a restart of the service writes none, and a mark of the running boot is dropped; the reason from the change log, e.g. `schedule: reboot`; the downtime once NTP agrees), kernel crash (a new ramoops record in `/sys/fs/pstore`), new firmware (the kexec upgrade leaves no mark), otherwise unexpected restart (power cut, hang, hardware watchdog). A mark left by an older boot is ignored | info / warn |
| `doctor` | the background `mr doctor` run: a finding that is new or worse since the last run, and "fine again". Standing choices and moments of an apply (`ssh` password logins, `offload: off`, `config.unapplied`, a change waiting for confirmation) are left out; the state is in `/run` (a reboot reports what is still wrong once more) | warn / risk / info |
| `wifi` | the wifi module's self-heal (`wifi.self_heal`, `mr wifi tick`, see `docs/modules/wifi.md`): a radio's TX stalled with stations associated — firmware recovery triggered, hostapd restarted, gave up (no automatic reboot) — and TX moving again | warn / risk / info |

Flash writes are bounded: at most 10 lines of one type are kept per hour (a flapping WAN, a DHCP flood with random
MACs, a password-guessing botnet only reach syslog after that), so the worst case is ~100 appends of ≤ 300 bytes and two
rewrites of ≤ 96 KiB an hour (≈ 4 MB a day, UBIFS wear-levels it); a normal day writes a few lines. `devices.seen` gets
18 bytes per new MAC, rewritten (≤ 37 KiB) every 256; the notification cursor (`notify.json`, a few bytes) only after a
message went out; `boot.json` / `shutdown.json` once per boot. Everything else is in `/run/mini-router` (tmpfs):
`events.json` (what the hooks saw, the background doctor's findings), `event.due`, `leases.seen`, `notify.json`
(backoff, rate), `doctor.json`.

**`mr event tick`** is started by the mon module's sampler (`mon-collect`, already running once a minute) — in the
background, only when dnsmasq's lease file is newer than `/run/mini-router/leases.seen` or the uptime in
`/run/mini-router/event.due` has come; any other minute costs two `stat()`s and a `read` in the shell. The tick scans the
leases, runs the background doctor when due, rewrites `event.due` (the earlier of the next doctor run and a notification
retry) and flushes notifications. A tick that is still running makes the next one exit (flock).

**Notifications** (`mod_sys_notify.go`) — an event whose type a channel wants starts `mr notify flush --hook` detached;
it waits 5 s (one waiter at a time, so a burst — a PPPoE reconnect is a down and an up — is one message). Every channel
has a cursor, the last event it got, written only after a message went out: nothing is lost to a failed send, a WAN
outage or a reboot, and the next message carries everything after the cursor (30 lines at most, repeats folded
`(x3, last 15:02)`). A new channel starts at the end of the log (an apply that adds it: `Verify`); a removed one loses
its cursor. A failed send backs off 1, 2, 4 … 30 minutes (the retry is `event.due`); a new event tries at once. `rate`
per channel and hour; `quiet_hours` holds `info` events (a warning takes them along). The events sent while a WAN is
down simply wait for the next working send.

* Telegram: Bot API `sendMessage`, plain text (no parse mode: nothing in an event becomes markup), title line + lines.
* Webhook `json`: `{title, message, body, text, content, priority (5 | 8), severity, host, events[]}` — the keys Gotify,
  Bark, Slack / Mattermost and Discord read; Home Assistant and custom receivers get the events. `text`: the lines as
  the body with `Title` / `Priority` headers (ntfy).
* HTTPS against the system CA bundle, no proxy from the environment, no redirects, answers capped at 64 KiB, 30 s per
  send. The bot token (in the API URL) and the webhook URL (usually a key in it) live only in secrets.yaml: error texts
  drop the request URL and every form of the secret before they are shortened, and nothing of them reaches a state file,
  a log, `mr notify status`, `sys.events` or the web UI (tested with a local receiver in CI).
* The router's own traffic does not use the proxy; a Telegram API that is blocked where the router is needs a webhook
  relay for now.

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
| `sys.time` | GET | `{now, tz, offset, local, ntp, ntp_server, synced}` (`synced` from the ntpd marker in `/run/mr-clock`, else adjtimex; `null` if unknown) |
| `sys.doctor` | GET | runs `mr doctor` now (a few seconds) → `{time, risk, warn, ok, checks[] {id, check, sev, title, detail, fix}}`; a router.yaml that does not load is itself the finding (`config.load`). API tokens: read |
| `sys.events` | GET | `{events[] (newest first, ≤ 200) {seq, t, type, sev, key, msg}, types[], notify[] {name, type, pending, last_ok, error, error_at, retry_in, held: retry \| rate \| quiet_hours}}` — never a secret. API tokens: read |
| `sys.notifytest` | POST | `{name (optional)}` → `{results[] {name, ok, error}}`: a test message now to that channel (or all) of the applied config, ignoring rate, quiet hours and backoff; 409 without channels. Web UI session only |
| `sys.sshkeys` | GET | keys in root's authorized_keys: `managed[]`, `other[]` `{type, comment, fingerprint}`, `other_unparsed`, `root_password: set\|locked\|empty` (never the hash) |
| `sys.services` | GET | `services[]` `{name, label, cfg, wanted, installed, running}`, `others[]`, ports, `tailscale` `{state, self, peers[], peers_online, tailnet, auth_url (only while NeedsLogin)}` |
| `sys.logs` | GET / POST | `{level 0-7, tag, q, limit ≤ 5000}` → `lines[]` `[time, level, facility, tag, message]` newest first, `total`, `tags{}` (source `/var/log/messages{.0,}`, `logread` if absent) |
| `sys.schedulecheck` | POST | `{cron, action}` → `{ok, cron \| error}` (editor feedback, no side effects) |
| `sys.ddns` | GET | `{enabled, interval, records[]}` — per record and type: `name, type, source, local, published, note, last_ok, changed, checked, error, error_at, retry, stopped, fails` (local addresses as of now; no provider request; never the token or zone id) |
| `sys.wol` | POST | `{target: MAC \| dhcp.hosts name, network (optional)}` → `{mac, host, network, dev, broadcast}`; 400 for a bad target / network, 500 if sending failed |
| `sys.edge` | GET | `{enabled, port, open, staging, serving, started, renewing, routes[] {name, host, to, allow, cert, wan, requests, errors, denied}, certs[] {name, domains, state (ok \| due \| missing \| expired \| names changed \| other CA), not_before, not_after, issuer, last_try, last_ok, error, error_at, retry}}` — never a key or the token; token scope `read` |
| `sys.edgerenew` | POST | `{}` → `{started: true}`: `mr edge renew` in the background (what is due or missing, ignoring the backoff); 409 while off or while a renewal runs; poll `sys.edge` (`renewing`). Session only |
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
mr doctor [--json]                                       # health and security checks, problems first with their fix
mr event list [--json] [N]                               # the newest N events (default 50, at most 200)
mr event tick | boot | shutdown                          # what mr-mon's sampler / mr-bootlog run
mr notify status                                         # channels: pending, last success, last error, retry, held
mr notify test [NAME]                                    # a test message now (JSON: name, ok, error)
mr notify flush [--hook]                                 # send what is pending (--hook: the 5 s wait the events start)
mr edge status                                           # reverse proxy: routes (requests), certificates, renewal results (offline)
mr edge renew [--force] [CERT...]                        # issue what is missing / due now (--force: also the others)
mr edge renew --cron | --hook                            # what crond / an apply run (respect the backoff)
mr edge serve [-c FILE]                                  # the proxy process (service mr-edge; no router.yaml / secrets.yaml)
mr edge prepare                                          # the init script: certificate directory owned by the service user
```

`mr status` has `ddns: {records, ok, errors[]}` while DDNS is on (the overview shows failing records), `edge: {routes,
certs, ok, errors[]}` while the reverse proxy is on, `doctor` (the last `mr doctor` run's counts and problems) and `events`
(the newest 8). `mr doctor` has a `certs` check (missing / expired = risk, less than 14 days left or a failed renewal =
warn); issued and failed certificates are events of type `cert`.

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
* Health checks / events (no rendered file changes; `notify` is not in the home config, so nothing is pushed and no
  background doctor runs): with the new image, `mr-bootlog` records why the router started and marks clean stops,
  mr-mon's sampler starts `mr event tick` when the lease file changes (new devices are logged after a day of learning),
  and `clock-save` keeps `/run/mr-clock/synced`, so 系统设置 shows "NTP 已同步" where it used to say 未同步.

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
- **服务 › HTTPS 反向代理（自动证书）**（同一页下方）：开关、端口、“对外网开放”、“局域网解析”；证书部分填邮箱（可空）、
  Cloudflare Token 引用名和 Token（和 DDNS 用同一种，可以就用 `cf_ddns_token`）、通配符域名、是否用测试 CA。站点表每行一个
  域名：名称、域名、转发到（内网服务的 `http://IP:端口` 或 `https://IP:端口`）、允许访问（留空 = 所有人；`lan` = 局域网和
  Tailscale；或者 IP / 网段）。保存并应用后路由器自动申请证书（1–2 分钟），状态表显示每个站点的请求数和 502 次数、
  每张证书的剩余天数和上次签发 / 失败原因；“立即申请 / 续期”马上再试（忽略退避）。防火墙 › 常规 / 安全的“对外暴露检查”
  会列出它开放的端口。
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
- **体检与事件**（状态分组）：
  - 体检：打开就跑一次 `mr doctor`（几秒），风险 / 警告排在前面，每条下面是处理办法；“重新体检”再跑一次。
    总览页顶部的“问题 (N)”卡片显示最近一次体检（网页或后台）发现的问题。
  - 事件：最近 200 条事件（WAN 断线 / 恢复、线路切换、配置更改 / 回滚、登录锁定、新设备、开机原因、固件升级、
    体检），可按类型筛选。总览页的“最近事件”显示最新 8 条。设备名来自网络，只作显示。
  - 通知：添加渠道（Telegram 机器人或 Webhook），Token / URL 只写入 secrets.yaml；勾选推送哪些事件、每小时上限、
    免打扰时段、后台体检间隔，“保存并应用”。应用后点渠道的“发送测试”确认能收到；下面“发送状态”显示待发送条数、
    上次成功、最近错误和重试时间。

  Telegram：找 @BotFather 发 `/newbot` 拿到 Token；给机器人发一条消息，打开
  `https://api.telegram.org/bot<Token>/getUpdates` 找 `chat.id`（群组是 `-100…`）。ntfy：URL 填
  `https://ntfy.sh/<难猜的主题名>`，格式选“纯文本”。Bark / Gotify / Home Assistant：URL 填它们给的完整推送地址，格式 JSON。

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

通知：先把 Token / URL 写进 secrets.yaml（不要回显到终端），然后

```yaml
notify:
  channels:
    - {name: phone, type: telegram, token_secret: notify_tg_token, chat_id: "123456789"}
  quiet_hours: "23:00-07:00"
```

应用后 `mr notify test` 发一条测试消息，`mr notify status` 看状态，`mr event list` 看事件，`mr doctor` 体检。

HTTPS 反向代理：Token 同上（已经有 DDNS 的 `cf_ddns_token` 就直接用），然后

```yaml
services:
  edge:
    enabled: true
    open: true                          # 外网可访问（IPv4 + IPv6 的 443）
    acme: {token_secret: cf_ddns_token, wildcard: [example.com]}
    routes:
      - {name: nas, host: nas.example.com, to: "http://192.168.1.10:5000"}
      - {name: ha, host: ha.example.com, to: "http://192.168.1.20:8123", allow: [lan]}   # 只在家里 / Tailscale 用
```

`mr apply --confirm 120` 之后 `mr edge status`：`serving: true`，证书 1–2 分钟后 `state: ok`（`mr edge renew` 可以前台跑一次看
过程）。域名要在 Cloudflare 上指向路由器（DDNS 记录 `*.example.com` 或每个域名一条）。

从 lucky 迁移（一次 apply 完成，lucky 的配置留着以备回退）：

1. 先在 lucky 里记下每个反代站点的域名和后端地址；确认 `services.ddns` 已经接管 DDNS（lucky 的 DDNS 关掉）。
2. router.yaml：`services.lucky.enabled: false`；删掉 `firewall.open` 里的 `lucky-https`（443 由 `services.edge.open` 打开）；
   `dns.addn_hosts` 里的 `/etc/lucky/dnsmasq.hosts` 可以去掉（`lan_dns` 接替）；按上面加 `services.edge`，
   第一次可以先用 `acme.staging: true` 试，确认签发成功后改回 false。
3. `mr plan`（风险为 high：改了对外开放的站点）→ `mr apply --confirm 120` → `mr edge status` / 外网用手机流量打开一个站点 →
   `mr confirm`。不行就 `mr rollback`，lucky 原样回来。
4. 稳定之后，镜像里的 lucky 可以在以后的镜像中去掉（EXTRA_BINS），省下约 50 MB 内存。

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
- 反向代理打不开：`mr edge status`（`serving` 是否为 true；证书 `state` / `error`）；`rc-service mr-edge status`；
  `grep edge: /var/log/messages`（证书申请和后端连不上都记在这里）。端口被别的程序占用（例如 lucky 还开着 443）时 mr-edge
  起不来，apply 会校验失败并回滚。外网不通先看“对外网开放”和 Cloudflare 上的域名是否指向路由器；局域网能开外网不能开，
  看站点的“允许访问”是不是只有 `lan`。证书一直失败：Token 权限（Zone › DNS › Edit，覆盖这个域）、`mr edge renew` 前台看原因；
  自动重试按 1、2、4 … 24 小时退避，“立即申请 / 续期”不受限。
- SSH 连不上：`cat /etc/conf.d/dropbear`（`lan_only` 时只监听 LAN 地址）；`mr sys keys` 看公钥。
- 开机后 `sysctl net.netfilter.nf_conntrack_max` 应为 100000（或 `system.sysctl` 里的值）。
- 出了问题先 `mr doctor`（每条问题带处理办法），再看 `mr event list`（断线、切换、回滚、重启原因的先后）。
- 收不到通知：`mr notify status`（`error` 是服务的回答或连接错误，`held`：retry 退避中 / rate 超过每小时上限 /
  quiet_hours 免打扰）；`mr notify test` 立即试发；`grep notify /var/log/messages`。断网期间的事件恢复后自动补发。
  `mr event list` 里没有的事件不会推送：同一类型每小时最多记 10 条，其余只进系统日志。
- 重启原因：`mr event list | grep boot`——“clean restart”是正常关机 / 重启（括号里是计划任务或网页），
  “kernel crash”看 `cat /sys/fs/pstore/dmesg-*`（留一份后删掉它，体检里的警告就消失），“unexpected restart”是断电、
  死机或硬件看门狗。
