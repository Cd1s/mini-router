# sys — time, SSH, add-on services, schedules, backup / restore, firmware, logs, diagnostics

Everything that is "the router itself" rather than a network feature. Like the other modules it is
on-demand work inside `mr` (CGI for the web UI, `mr sys …` for SSH / agents); the only daemons are the
ones the config switches on (ntpd always, crond only while schedules exist).

| | |
|---|---|
| Go | `mr/mod_sys.go` (module, types, validation, render), `mod_sys_time.go` (POSIX TZ parser, TZif writer, NTP, `sys.time`), `mod_sys_ssh.go` (dropbear, managed `authorized_keys`), `mod_sys_cron.go` (schedules, `mr sys run`), `mod_sys_backup.go` (backup / restore), `mod_sys_fw.go` (firmware upload, sysupgrade / factory-reset hooks), `mod_sys_api.go` (diag, service, services, logs, `mr sys`), `mod_sys_linux.go` / `mod_sys_other.go` (adjtimex) |
| UI | `rootfs/www/ui/sys.js` — 服务 (group 服务); 系统设置, 管理与 SSH, 计划任务, 备份与升级, 日志, 网络诊断 (group 系统) |
| rootfs | `rootfs/etc/init.d/{tailscale,mr-panel,mr-zram,lucky,lucky-dns-inotify,dstatus-agent}` (tailscale and mr-panel now read their conf.d) |
| Checks | `mr/mod_sys_test.go`, `tools/ci.d/sys.sh`, lab fragment `examples/lab.d/70-sys.yaml` |
| Mock | `tools/mock/fixtures/sys.*.json`, `service.post.json`, `diag.post.json`, `config.d/sys.json` |

## Cost

| | |
|---|---|
| Flash | `mr` +192 KiB (arm64, stripped: 5.06 → 5.25 MiB), `sys.js` 45 KB (was 5 KB), mock fixtures only in the repo |
| RAM, always | nothing new. `ntp_server` makes the existing ntpd answer on udp/123 (no extra process) |
| RAM, with schedules | busybox crond (~100 KB private; the busybox text is shared) |
| RAM, on demand | CGI runs of `mr` while a page is open; during a restore a `mr sys restore-watch` process sleeps until the confirm window is over (≈4 MB for at most ~12 min); a firmware upload sits in `/tmp` (RAM) until it is flashed or deleted |
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

schedules:                   # busybox crond; fixed actions only
  - {name: weekly-reboot, cron: "30 4 * * 1", action: reboot}
  - {name: wifi, cron: "0 5 * * *", action: restart, target: mr-hostapd}
  - {name: redial-wan2, cron: "0 */6 * * *", action: reconnect, target: wan2}
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
  service this config enables (not `mr-network`); `reconnect` targets a PPPoE / DHCP WAN.

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
| `/etc/crontabs/root` | managed block between markers; Alpine's periodic lines and anything else kept | — (crond rescans the directory) |
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
   core snapshot format, so 备份与回滚 can also roll back to it), then written.
4. The candidate config is validated and rendered; on any error the list files go back and nothing else
   has changed.
5. The candidate is written where the web UI's apply writes it and the core `apply-job` runs:
   snapshot, apply, verify, 120 s confirm countdown, automatic rollback. A small watcher puts the list
   files back if that apply fails or is rolled back (not confirmed, or 立即回滚).

List files that exist on the router but not in the backup are left alone.

## CLI

```
mr sys run reboot | restart SERVICE | reconnect WAN   # what crond runs (checked against the config, logged)
mr sys backup [-secrets] FILE|-                          # same archive as the web UI
mr sys restore [-confirm 60-600] FILE                     # same checks and apply job; then `mr confirm`
mr sys keys                                              # authorized_keys: managed / other, fingerprints
```

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
- **系统设置**：主机名、zram；时间区显示路由器当前时间和 NTP 是否已同步，“立即同步”重启 ntpd；
  时区从列表选（曼谷、北京、东京、柏林、纽约……），列表里没有就选“自定义 POSIX TZ”手填；
  NTP 服务器逗号分隔；“为局域网提供 NTP”打开后 LAN（含 Tailscale）可以把路由器当时间服务器，
  访客网络和外网访问不到——要让设备自动用它，在 DHCP 设置里把 NTP 选项填成路由器地址。
  下面是 sysctl 表和“重启路由器”。
- **管理与 SSH**：SSH 开关、端口、是否允许密码登录、“只监听 LAN 地址”；公钥框每行一个公钥，
  保存后写进 `/root/.ssh/authorized_keys` 的受管区块。下面列出当前生效的受管公钥和文件里其它公钥
  （带指纹）——其它公钥 mr 永远不动，所以不会因为改这里把自己锁在外面。没有任何公钥又禁止密码登录、
  或允许密码登录但 root 没设密码时，页面会提示。还有 Web 管理开关和管理员密码修改。
- **计划任务**：表格列出任务（可直接开关）；“+ 添加 / 编辑”弹窗里选动作（重启路由器 / 重启服务 /
  重连 WAN）、对象、时间（每天 / 每周几 / 每月几号 / 每 N 小时 / 自定义 cron），下面实时显示 cron
  表达式、中文说明和校验结果。重启路由器最多每天一次，其它任务最多每小时一次。
- **备份与升级**：
  - 下载备份：默认只含 router.yaml 和列表文件；勾选“包含机密”才带 PPPoE / WiFi 等密码（明文，
    不含管理员密码）。
  - 恢复：选备份文件 →“校验并恢复”。有问题会列出原因且什么都不改；通过后和平时保存一样应用，
    120 秒内点“保留”，否则自动回滚（列表文件一起回滚）。
  - 固件升级：选镜像 → 浏览器算 SHA-256 → 分块上传（有进度条）→ 确认后刷写，路由器自动重启。
    镜像被平台脚本拒绝时显示原因。当前构建没有升级脚本时显示“当前构建不支持”。
  - 恢复出厂设置：确认两次（第二次要输入 RESET）。
  - 每次应用前的自动快照仍在“备份与回滚”页面。
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

备份 / 恢复：`mr sys backup -secrets /tmp/b.tgz`，拷走；恢复 `mr sys restore /tmp/b.tgz` 然后
`mr confirm`。手动试跑计划任务的动作：`mr sys run restart dnsmasq`。

### 排障

- 时间不对：`date`（应显示路由器时区）；`cat /etc/conf.d/ntpd`；网页“系统设置”看 NTP 是否已同步。
  没有电池时钟，开机到 NTP 同步前时间是错的，crond 遇到时间跳变超过 1 小时不会补跑任务。
- 计划任务没执行：`rc-service crond status`；`cat /etc/crontabs/root`；`grep schedule /var/log/messages`。
- SSH 连不上：`cat /etc/conf.d/dropbear`（`lan_only` 时只监听 LAN 地址）；`mr sys keys` 看公钥。
- 开机后 `sysctl net.netfilter.nf_conntrack_max` 应为 100000（或 `system.sysctl` 里的值）。
