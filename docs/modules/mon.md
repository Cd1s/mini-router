# mon — monitoring

Realtime graphs, 24 h history, traffic per device, connection list, processes and kernel log.
Everything is read-only and computed on demand by `mr` (CGI for the web UI, `mr mon …` for SSH /
agents). The only resident piece is a busybox-sh loop that writes one line per minute to RAM.

| | |
|---|---|
| Go | `mr/mod_mon.go` (module, `mon.now`, CLI), `mod_mon_hist.go` (history), `mod_mon_ct.go` (conntrack: devices, connections), `mod_mon_sys.go` (processes, dmesg), `mod_mon_linux.go` / `mod_mon_other.go` (rtnetlink neighbour dump, `syslog(2)`) |
| UI | `rootfs/www/ui/mon.js` — group 状态: 实时监控, 流量统计, 连接, 进程与内核日志 |
| Service | `mr-mon` (`rootfs/etc/init.d/mr-mon`, supervise-daemon) → `rootfs/usr/libexec/mr/mon-collect` |
| Checks | `mr/mod_mon_test.go`, `tools/ci.d/mon.sh` (runs the sampler for real, checks rendered files and `mr mon`) |
| Mock | `tools/mock/fixtures/mon.*.json` (synthetic; dmesg lines from `docs/tests/m1-alpine-boot-dmesg.txt`) |

## Cost

| | |
|---|---|
| Flash | `mr` +128 KiB (arm64, stripped), `mon.js` 26 KB, sampler 2 KB |
| RAM, always | sampler: busybox ash, 1.2 MB RSS of which 76 KB private (the rest is the shared busybox binary), plus its supervise-daemon; history file ≈ 1440 lines × ~70 B ≈ 100 KB in `/run/mr-mon` |
| RAM, conntrack accounting | +32 B per connection (1 000 connections ≈ 32 KB) |
| RAM, only after 流量统计 was opened | `/run/mr-mon/flows`: 24 B per connection |
| CPU | sampler: a few shell builtins per minute (the only forks are `sleep`, an hourly `tail` and, when due, the event tick below); pages: one `mr` CGI run per refresh while a page is open (2 s realtime, 3 s devices/processes, 5 s connections if auto refresh is on, 60 s history) |

No exec in the CGI: `/proc`, `/sys`, rtnetlink and `syslog(2)` are read directly.

The sampler is also the clock of the sys module's event log (`docs/modules/sys.md`, "Health checks, events,
notifications"): after each sample it starts `mr event tick` in the background — detached, so a slow notification never
delays the next sample — but only when dnsmasq's lease file (`/tmp/dhcp.leases`) is newer than
`/run/mini-router/leases.seen` (a new device?) or the uptime in `/run/mini-router/event.due` has come (a notification
retry, events held back, the next background `mr doctor`). Every other minute that is two `stat()`s and a `read`. In a
house that means a tick for each DHCP renewal (a few an hour) plus one per background doctor run (every 30 minutes by
default with notification channels). `MON_EVENT_DIR`, `MON_LEASES`, `MON_MR` exist for CI (`tools/ci.d/mon.sh` runs
the sampler with a stub `mr`).

## router.yaml

None. The module renders two files from the rest of the config and always enables `mr-mon`:

| File | Content | On change |
|---|---|---|
| `/etc/sysctl.d/91-mon.conf` | `net.netfilter.nf_conntrack_acct=1` (per-connection byte counters for 流量统计) | sysctl reload |
| `/etc/conf.d/mr-mon` | `MON_WAN="wan"` — the distinct physical devices of `wan[].device` whose counters the history sums (names that are not plain netdev names are dropped) | restart `mr-mon` |

`mr-mon` also re-applies `91-mon.conf` when it starts, because at boot `nf_conntrack` is only loaded
by the firewall, after the boot-time sysctl run. Accounting only applies to connections created after
it was switched on.

## Data sources and accuracy (read this before trusting a number)

* **Interface counters** (实时 / 24 小时): `/proc/net/dev`. Flow-offloaded packets (software fast
  path *and* PPE/WED hardware) never pass through `pppoe-wan` / `pppoe-wan2`, so those interfaces only
  count the first packets of each connection. The history therefore sums the **physical** WAN device
  (`wan`), which carries both PPPoE sessions. `wan` is port 4 of the MT7531 switch, and in the OpenWrt
  6.18.52 source the `mt7530` DSA driver implements `get_stats64` from the switch's hardware MIB
  counters, so `wan` also counts PPE/WED hardware-forwarded packets (checked in the source, not yet on the
  router: run a speed test once and watch 实时监控 → `wan`; it should show the full speed).
* **Per-device traffic** (流量统计): conntrack byte counters. Offloaded connections only get their
  counters updated by the flowtable GC (about once a second) and **only if the flowtable has the
  `counter` flag**. The current firewall ruleset (fw module) does not set it, so bytes of offloaded
  connections after they were offloaded are missing and the page shows a warning. Fix belongs to the
  fw module: add `counter` to `flowtable ft` (cheap: the hardware stats are polled anyway).
* **Rates per device** are exact per connection: each call stores (connection → bytes) in
  `/run/mr-mon/flows` and the next call diffs against it, so connections opening/closing between
  polls do not distort the numbers. The first call (or one after > 2 min) only sets the baseline.
* "连接内累计" is the sum over connections that are still in the table — not a total since boot.
* **Monthly traffic** (`system.traffic_stats: true`, #33; `mod_mon_traffic.go`): the sampler runs `mr mon account`
  every minute (`--account` from `/etc/conf.d/mr-mon`). Per device: the per-connection deltas since the last run
  (own snapshot `/run/mr-mon/traffic.flows`), so short connections that leave the table between runs and, without
  the flowtable `counter` (above), offloaded bytes are missing — a lower bound. Per physical WAN device: its byte
  counters (exact, offload included). RAM `/run/mr-mon/traffic.json`, flash copy
  `/etc/mini-router/state/traffic.json` at most once an hour and at the month change (router time); current and
  previous month; at most 256 devices a month. Card 本月流量 on 流量统计.
* The sampler stores uptime + raw cumulative counters; `mr` computes rates and wall-clock times when
  asked, so NTP stepping the clock after boot (no RTC) does not break the history. A counter going
  backwards (device re-created) or a gap > 10 min gives an empty point instead of a spike.
* Rows in 流量统计: a device is a MAC (neighbour table on the LAN bridges, then DHCP leases, then
  `dhcp.hosts`), so its IPv4 and IPv6 addresses are summed together. Link-local (`fe80::`) addresses
  count as a LAN device only when the neighbour table of a LAN bridge knows them (every link, WAN
  included, has `fe80::/64`; the ISP's DHCPv6 replies come from its link-local address). Port-forward connections count for
  the LAN host they are forwarded to. Everything without a LAN end (the router's own traffic: Tailscale,
  NTP, DNS upstream …) is the row 路由器自身 / 其他.

## API (web UI, all read-only, logged-in session)

| Action | Method | Returns |
|---|---|---|
| `mon.now` | GET | `t` (unix ms), `up` (uptime s), `hz`, `cpu` / `cpus[]` (user nice system idle iowait irq softirq steal, cumulative), `mem` (KiB: total avail free buffers cached swap_total swap_free), `load[3]`, `procs`, `procs_running`, `ct`, `ct_max`, `temps[]` ({zone, type, mc}), `ifaces[]` ({name, role: wan / wan-dev / lan / port / wifi / vpn, state, rx, tx, rxp, txp, err, drop}) |
| `mon.traffic` | GET | monthly traffic (`system.traffic_stats`): `cur` / `prev` {month, dev: {MAC: {up, down, name}}, wan: {device: {up, down}}}, `saved` (last flash copy), `enabled` |
| `mon.history` | GET | columns `t` (unix s), `rx`, `tx` (bytes/s), `cpu` (%), `mem` (used KiB), `ct`, `temp` (°C), `wtemp` (hottest mt76 radio, °C), `wduty` (its lowest TX duty cycle %, < 100 = thermal throttling; hwmon `mt7*`, #91) — `null` where unknown; `mem_total`, `wan` (devices summed), `collector` {ok, age, samples} |
| `mon.devices` | GET | `devices[]` {id, mac, name, ips[], conns, up, down (bytes in open connections), up_rate, down_rate (bytes/s)}, `other` (same shape), `dt` (0 = baseline only), `acct`, `flowtable`, `flow_counter`, `entries`, `truncated`, `available` |
| `mon.conns` | GET, or POST with a filter | `total`, `matched`, `by_proto`, `by_state` (TCP), `by_offload` {hw, sw, none}, `by_family` (whole table); `top_src`, `top_dst` (top 10 by bytes, filtered set); `conns[]` {p, f, st, ttl (-1 while offloaded), src, dst, sport, dport, icmp, nat_src/nat_sport (SNAT), nat_dst/nat_dport (DNAT), ob, rb, op, rp, off: hw/sw, assured, unreplied, mark}; `names` {ip: name} |
| `mon.procs` | GET | `procs[]` {pid, ppid, name, state, user, rss, vsz (KiB), threads, cpu (ticks), start, kernel, cmd}, `up`, `hz`, `ncpu`, `mem_total` |
| `mon.dmesg` | GET | `lines[]` = [level 0–7, text] (newest 2 000), `up` |

`mon.conns` filter (JSON body; unknown keys and bad values are rejected with 400):

```json
{"proto": "tcp", "family": 4, "ip": "192.168.1.0/24", "port": 443,
 "state": "ESTABLISHED", "offload": "hw", "sort": "bytes", "limit": 200}
```

`proto`: tcp udp icmp icmpv6 sctp gre other · `family`: 0 4 6 · `ip`: address or CIDR, matches any
address of either direction · `port`: any port of either direction · `state`: TCP state ·
`offload`: hw sw any none · `sort`: bytes (default) none · `limit`: 1–2000 (default 200).
At most 30 000 table entries are read per request (`truncated` says so).

Command lines in `mon.procs` have secret-looking values masked (`--authkey ***`, `password=***`).

## CLI (SSH / agent)

```sh
mr mon now                      # same JSON as the web UI
mr mon traffic                  # monthly traffic (mr mon account: the sampler's per-minute run)
mr mon history                  # 24 h columns; `mr mon history FILE` reads another sampler file
mr mon devices                  # call twice a few seconds apart to get rates
mr mon conns '{"ip":"192.168.1.66","limit":20}'
mr mon procs
mr mon dmesg
```

---

## 怎么用

### 网页

左侧「状态」分组里有四个页面：

1. **实时监控**
   * 「实时（2 秒）」：顶部是 WAN 实时速率、CPU、内存（含 zram 已用）、连接数、温度。
     下面「接口流量」画的是选中接口最近 5 分钟的收发曲线，**点表格里的任意接口就切换曲线**；
     默认选中「WAN 物理口」`wan`。「显示空闲接口」可以把没流量的接口也列出来。
     「CPU 使用率（每核）」看每个核的占用，表格里的「软中断」高说明网络包在走 CPU（没被硬件加速）。
   * 「24 小时」：WAN 下载/上传、CPU、内存、连接数、温度的 24 小时曲线（每分钟一个点），
     可切换最近 1 / 6 / 24 小时，WAN 卡片下方有区间总流量、峰值、平均值。
     历史只存在内存里，**重启路由器后从零开始**；如果看到黄色提示「mr-mon 没有在运行」，
     点提示里的「重启 mr-mon」按钮（或 SSH 执行 `rc-service mr-mon restart`）。
2. **流量统计**：每台设备（按 MAC 合并 IPv4 + IPv6）的实时下载 / 上传速率、连接数、连接内累计流量，
   3 秒刷新（打开页面后第一次只建立基准，3 秒后出速率）。点某台设备右边的「连接」直接跳到
   「连接」页并按它的 IP 过滤。最后一行「路由器自身 / 其他」是路由器自己的流量（Tailscale、NTP、DNS 上游等）。
   如果页面顶部出现黄色提示：
   * 「连接字节计数未开启」→ 点提示里的「重启 mr-mon」（启动时会重新应用 `/etc/sysctl.d/91-mon.conf`；
     如果从来没应用过包含 mon 的配置，先「保存并应用」一次）；
   * 「流表没有开启 counter」→ 被硬件加速的连接字节不计入，数字偏低，需要防火墙模块给流表加 `counter`。
3. **连接**：连接跟踪表。可以按协议、IPv4/IPv6、IP 或网段（如 `192.168.1.0/24`）、端口、TCP 状态、
   是否被加速过滤，回车或点「查询」生效；「自动刷新」每 5 秒刷新一次。上方是按协议 / 状态 / 加速的统计，
   中间是「发起方 Top 10」和「目的地址 Top 10」（点一行就按这个 IP 过滤），下面是连接列表：
   NAT 列里 SNAT 是出去时换成的外网地址，DNAT 是端口转发的内网目标；加速列「硬件」= PPE/WED 在转发。
4. **进程与内核日志**：「进程」按内存 / CPU / PID / 名称排序（CPU% 以单核为 100%，3 秒刷新），
   可显示内核线程；「内核日志 (dmesg)」可按级别（error / warning）和关键字过滤，红色是 error，黄色是 warning。

这些页面都是只读的，不会改配置，也不会出现「保存并应用」栏。

### router.yaml

不需要写任何东西。应用配置时 mon 会自动：

* 写 `/etc/sysctl.d/91-mon.conf`（开启连接字节计数）；
* 写 `/etc/conf.d/mr-mon`（`MON_WAN` = 所有 WAN 用到的物理口，家里两条 PPPoE 都在 `wan` 上，所以是 `"wan"`）；
* 启用并启动 `mr-mon`（每分钟采样一次）。

WAN 物理口改了（比如换成 `eth1`）只要改 `wan[].device`，应用后 `mr-mon` 会自动重启用新设备。

### SSH / agent

```sh
mr mon now | jq '.ifaces[] | select(.name=="wan")'      # 当前 wan 计数
mr mon devices >/dev/null; sleep 3; mr mon devices | jq '.devices[] | {name, down_rate, up_rate}'
mr mon conns '{"offload":"hw","limit":10}' | jq '.by_offload'   # 多少连接在硬件加速
mr mon conns '{"ip":"192.168.1.66"}' | jq '.conns[] | "\(.src):\(.sport) -> \(.dst):\(.dport) \(.off)"'
mr mon history | jq '.collector'                           # 采样服务是否正常
rc-service mr-mon status; tail -3 /run/mr-mon/history       # 采样原始数据（uptime 与累计计数）
```

### 排障

| 现象 | 原因 / 处理 |
|---|---|
| 24 小时没有曲线 | `mr-mon` 没跑：点页面提示里的「重启 mr-mon」或 `rc-service mr-mon restart`；刚开机或刚重启服务要等 1–2 分钟 |
| 流量统计全是 0 | `sysctl net.netfilter.nf_conntrack_acct` 不是 1：点提示里的「重启 mr-mon」或 `rc-service mr-mon restart`；只对之后的新连接生效 |
| 设备速率明显比测速低 | 流表没有 `counter`（页面会提示），被加速连接的字节没进 conntrack |
| `wan` 速率比测速低很多 | 按内核源码 `wan` 的计数来自交换机硬件 MIB，应包含硬件转发的包；如果实测仍偏低，说明驱动行为和源码不符，以流量统计为准并反馈 |
| `pppoe-wan` 几乎没流量 | 正常：加速后的包不经过 PPPoE 虚拟接口 |
