# fw — firewall, NAT, port forwards, IPv6 pinholes, traffic rules, device access control

Files: `mr/mod_fw.go` (types, defaults, validation), `mr/mod_fw_nft.go` (the nftables skeleton
`renderNft` + this module's rules + `fwLoad`), `mr/mod_fw_time.go` (weekly windows → nft time
matches, POSIX TZ), `mr/mod_fw_api.go` (`fw.stats`), `mr/mod_fw_test.go`, `rootfs/www/ui/fw.js`,
`examples/lab.d/40-fw.yaml`, `tools/ci.d/fw.sh`. router.yaml key: `firewall`.

Everything is rendered into one nftables table (`table inet mr`), loaded atomically by `mr fw`
(boot, apply, every PPPoE / hostapd event). No daemon: counters and logs are read on demand by the
web UI CGI.

## Security model

Three fixed zones. Their interfaces come from the rest of router.yaml:

| zone | interfaces | may reach the router | may be forwarded to |
|---|---|---|---|
| `lan` (trusted) | `lan.bridge`, every `networks[]` with `zone: lan`, `tailscale0` | everything (incl. web UI / SSH) | anywhere |
| `guest` (internet only) | every `networks[]` with `zone: guest` (the default) | DHCP, DNS, ICMP only | WAN only |
| `wan` | every WAN L3 interface (`pppoe-<name>` or the DHCP device) | established/related, `open` ports, tailscale UDP port (sys module), the ICMP the protocols need, DHCPv6/DHCPv4 client replies | established/related, port forwards, IPv6 pinholes, IPv6 ICMP errors + echo |

Input and forward policies are `drop`. What the WAN can reach on the router (the "对外暴露检查" card
shows this live from the edited config):

- replies of connections the router opened (`ct state established,related`)
- ICMPv4 echo, rate limited 20/s — only with `wan_ping: true` (default)
- ICMPv6 that IPv6 needs (RFC 4890): destination-unreachable, packet-too-big, time-exceeded,
  parameter-problem, neighbour / router discovery, MLD from link-local, echo rate limited 20/s —
  always, not switchable
- DHCPv6 client replies, only link-local/ULA → link-local/ULA (`ip6 saddr fc00::/6 ip6 daddr fc00::/6`, as fw4)
- DHCPv4 client replies (udp 67→68) — only if a WAN uses `proto: dhcp`
- IGMP (for an igmpproxy upstream)
- `firewall.open` entries, and the tailscale port from `services.tailscale`
- everything else is counted (`wan-in-drop`) and dropped; with `log_drops: true` also logged

Rules for traffic *towards the router* can only drop/reject (router ports are opened with `open`);
`accept` rules whose source may be the WAN must name a destination address or port; a rule must match
something (no "drop everything"); a router-bound rule must name at least an address, MAC, protocol
or port. That only stops the crudest lock-out (a rule like `dest: router, proto: [tcp]` still cuts
the web UI and SSH): the apply confirm/rollback is the real safety net, so apply rule changes from
the web UI or with `mr apply --confirm`.

`tailscale0` is trusted like the LAN (tailnet peers can reach the web UI): remote administration
goes through tailscale, never through an open SSH / web port.

Chain order (first match wins):

    input:   [pause] → [access: proxy bypass guard] → ct state (invalid dropped) → lo → [rules towards
             the router] → lan accept → guest DHCP/DNS/ICMP, rest dropped → SYN-flood limit → WAN ping
             → required ICMPv6 / MLD / DHCPv6 / DHCPv4 / IGMP → hook input (open ports, tailscale, …)
             → [log] → counted WAN drop → policy drop
    forward: [pause] → hook forward_first (policy route fallback: drop) → [access control] → flow offload
             → ct state → hook forward_early (traffic rules, …) → lan accept → guest → WAN → DNAT'ed
             accept → hook forward (IPv6 pinholes, …) → IPv6 ICMP errors/echo → policy drop

Every hook in `nftHooks` (module.go) is still emitted at its documented place; the fw-internal
parts (access control, router-bound rules) sit around them. `[pause]` is runtime state (`mr pause`,
[dev.md](dev.md)): fwLoad inserts it in the same transaction while a pause is active; it is never in
the rendered `nftables.nft`. Every reload is serialized by a lock (`/run/mini-router/fw.lock`), so the
state a reload carries over (learned sets, pauses) is never replaced by a stale copy.

## Performance

- Hardware flow offload (PPE + WED) is unchanged for normal traffic:
  `meta l4proto { tcp, udp } ct state established flow add @ft`. Rules only see the first packets
  of a connection (until it is offloaded) and new connections.
- The only exception: devices listed in `access` are never offloaded (so a schedule can cut their
  running connections). With no `access` entries the ruleset has no extra rule at all.
- All matching uses anonymous sets and a few dynamic sets; nothing runs in user space.

## Config reference (`router.yaml` → `firewall`)

```yaml
firewall:
  offload: hardware          # hardware (PPE + WED) | software | off
  synflood_protect: true     # new TCP to the router over 50/s is dropped
  wan_ping: true             # default true: ICMPv4 echo from WAN (rate limited). IPv6 ICMP is always on
  drop_invalid: true         # default true: drop conntrack-invalid packets
  log_drops: false           # rate-limited (10/min) kernel log of dropped WAN input, prefix "mr-drop wan-in: "

  forwards:                  # IPv4 DNAT from WAN, with NAT loopback for the trusted LAN networks
    - name: desktop-7443     # [A-Za-z0-9_.-]{1,40}, unique; also the nft comment
      enabled: true          # default true; false keeps the entry but renders nothing
      proto: [tcp]           # tcp and/or udp
      port: "7443"           # external port or range "45000-45100"
      to: 192.168.1.66       # host inside a LAN-side network (guest networks allowed), not the router,
                             # or a device of the inventory with ip: (to: desktop → its address; dev.md)
      to_port: "9999"        # optional; a range maps only to the same range or to one port
      wan: [wan2]            # optional: only these WANs (default all)
      src_ip: [203.0.113.0/24, 198.51.100.7]   # optional: only these IPv4 sources
      desc: "desktop ssh"   # optional, UI only
      # NAT loopback (LAN client → the router's public address) ignores wan and src_ip: it cannot tell
      # which WAN address was used, so if the same port is forwarded to different hosts on different
      # WANs, LAN clients always reach the first of those forwards.

  open:                      # ports on the router itself, from WAN, IPv4 + IPv6
    - name: lucky-https
      proto: [tcp]
      port: "443"            # "443", "8000-8100", "80,443"
      wan: [wan]             # optional
      src_ip: [203.0.113.0/24, "2001:db8:100::/48"]   # optional, v4 and/or v6
      enabled: true
      desc: ""

  ipv6_allow:                # IPv6 inbound pinholes to LAN-side hosts (no NAT on IPv6)
    - name: nas-https
      iid: "::211:32ff:fe12:3456"   # interface identifier = low 64 bits of the address, or …
      # mac: "00:11:32:12:34:56"   # … derive the EUI-64 identifier from the MAC (exactly one of iid/mac)
      proto: [tcp]
      port: "443,8443"
      src_ip: ["2001:db8:100::/48"] # optional, IPv6 only
      wan: [wan]             # optional
      enabled: true

  rules:                     # ordered traffic rules, before the zone policy, new connections only
    - name: no-smtp-out
      action: reject         # accept | drop | reject (tcp-only rules answer with a TCP reset)
      src: lan               # zone lan | guest | wan; empty = any
      dest: wan              # zone lan | guest | wan | router; empty = any forwarded traffic
      src_ip: [192.168.1.50] # optional CIDRs (v4 and/or v6; the rule is rendered per family)
      src_mac: []            # optional, LAN-side sources only
      dest_ip: []            # optional CIDRs
      proto: [tcp]           # tcp | udp | icmp; empty = any
      dest_port: "25"        # "25", "8000-8100", "80,443" (needs proto tcp and/or udp)
      schedule:              # optional weekly windows (local time), empty = always
        - {days: [mon, tue, wed, thu, fri], time: "08:00-17:30"}
        - {time: "22:00-07:00"}      # no days = every day; crossing midnight ends the next day
      counter: true          # count hits (shown in the UI)
      log: false             # rate-limited kernel log, prefix "mr-rule <name>: "
      enabled: true
      desc: ""

  access:                    # block internet (WAN) for devices; LAN, DHCP, DNS keep working
    - name: kid-bedtime
      macs: ["aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"]
      devices: ["group:kids", tv-box]   # optional: devices / groups of the inventory (dev.md), all their MACs;
                                        # macs and / or devices, 1-64 MACs in total
      schedule:              # blocked only in these windows; empty = always blocked
        - {days: [sun, mon, tue, wed, thu], time: "21:30-07:00"}
        - {days: [fri, sat], time: "23:00-08:00"}
      enabled: true
      desc: ""
```

### Time windows

`days` are the days the window *starts* on (`mon`…`sun`), `time` is `HH:MM-HH:MM` in
`system.timezone`; `24:00` is allowed as an end. The windows are converted to UTC when the ruleset is
rendered and emitted as raw seconds (`meta day { … } meta hour 54000-86399`), split at UTC midnight
and at the kernel's day boundary — nft's own conversion depends on the environment of whoever runs
nft, and the kernel evaluates `meta day` and `meta hour` in different timezones, so neither is
trusted. POSIX TZ strings with DST rules (`CET-1CEST,M3.5.0,M10.5.0/3`) are supported; the offset
in force when the firewall is loaded is used, so a DST change takes effect at the next reload (daily
PPPoE reconnect, apply, `mr fw`).

### How device access control works

1. Every packet a listed device sends through the router records its IPv4/IPv6 source in dynamic
   sets (`@ac_4`/`@ac_6` for all controlled devices, `@acN_4`/`@acN_6` for entry N; 6 h timeout,
   bounded to 4096 / 1024 addresses so a misbehaving device cannot grow them without limit).
2. The offload rule skips those addresses, so the device's connections stay on the CPU path.
3. In a window: packets from the MAC to a WAN are dropped, and packets from a WAN to the learned
   addresses are dropped — running downloads stop immediately, not just new connections.
4. In the input chain the device cannot use the router as a gateway either (traffic not addressed
   to the router itself — `fib daddr type != { local, broadcast, multicast, anycast }` — is dropped,
   e.g. a transparent proxy intercepting to a local socket; this also holds for IPv6 when the router
   has no IPv6 default route, where the fib type of a proxied destination is "unreachable"). This
   rule sits before `ct state`, so the device's running proxied connections are cut too; DHCP, DNS,
   neighbour discovery and anything addressed to the router keep working.
5. A reload empties the sets, so `mr fw` refills them in the same nft transaction that loads the
   new ruleset: the neighbour table and static DHCP leases of the listed MACs (full timeout), plus
   the previous sets' addresses with their remaining lifetime (a reload never extends it, so stale
   addresses still expire). A refill after the load would leave a gap in which a reply packet of a
   running download puts the connection into the flowtable (hardware offload) for good. If the
   combined load fails (e.g. a set is full), the ruleset is loaded alone and the refill is retried.

Limits: a phone using a per-network random MAC must be listed with the MAC it uses on this WiFi
(iOS/Android "private address" is stable per network). A device on a guest network is matched too.

Access control is config (schedules, permanent blocks). For "no internet for this device for the next
hour" without a config change there is `mr pause` / 暂停 (dev module, [dev.md](dev.md)): the same
drops in both chains, but on runtime sets with kernel timeouts, and the device stays offloaded
until it is paused (the pause replaces the ruleset once, which ends every offloaded flow).

## Web UI API

`GET fw.stats` — read-only, no parameters: `{counters: {"<comment>": {packets, bytes}}, log: [...]}`.
Comments: `wan-in-drop`, `rule:<name>` (rules with `counter: true`), `access:<name>`, `v6in:<name>`,
`fallback:<policy>` (policy routes with `fallback: drop`, net module), `pause` (while a pause is active).
`log` = the last 100 kernel log lines from `log_drops` / rule logging (`dmesg`). Mock fixture:
`tools/mock/fixtures/fw.stats.json`; sample config: `tools/mock/fixtures/config.d/fw.json`.

## Requirements

nftables with `meta hour/day` (kernel ≥ 5.4), `fib`, `reject`, dynamic sets; `log_drops` / rule `log`
need `nft_log` + `nf_log_syslog` (OpenWrt kmod-nft-core / kmod-nf-log). If a module is missing,
`nft -c` fails and the apply rolls back with nft's error message.

## Changes to the real home output (examples/router.yaml)

Forwards, the open 443, masquerade, NAT loopback and the offload rule are byte-identical. The input
chain changed intentionally:

- `udp dport 546 accept` (DHCPv6 client) now only from/to link-local/ULA (`fc00::/6`, same as fw4)
- ICMPv6 echo-request from WAN is rate limited (20/s) like ICMPv4; MLD from link-local is accepted
- a final `iifname { WANs } counter drop comment "wan-in-drop"` (same effect as the policy, but counted)
- a `# zones:` comment line; the trusted interface set is ordered `br-lan, tailscale0`

## 怎么用

**网页（防火墙分组）**

- **常规 / 安全**：流量卸载（硬件 PPE + WED）、SYN 洪水防护、是否允许外网 ping（IPv4）、丢弃无效
  连接、记录 WAN 入站拦截；区域表（lan / guest / wan 各有哪些接口、能访问什么）；“开放路由器端口”
  列表；“对外暴露检查”列出外网现在能碰到路由器的所有东西（开放了 SSH / 管理界面端口会标红）；
  “拦截统计”显示 WAN 入站已拦截的包数和最近的拦截日志。
- **端口转发**：列表里可直接开关每条转发；“编辑”弹窗里填外部端口、内部 IP（有已知设备下拉）、
  内部端口，可选只在某条 WAN 上生效、只允许某些来源 IP。NAT 回流自动开启。
- **IPv6 入站**：给内网服务器放行 IPv6 端口。推荐在服务器上固定“接口标识”（地址后 64 位，例如
  `::10`），这里填 `::10`；也可以填 MAC 用 EUI-64 推导（弹窗里会实时显示推导结果）。运营商换前缀
  后规则仍然有效。表格“命中”列是计数。
- **通信规则**：按顺序匹配（↑ 调整顺序）。源 / 目标区域、IP、MAC、协议、端口、生效时间段、计数、
  日志。目标选“路由器本机”可限制某台设备访问路由器服务（只能丢弃 / 拒绝）。
- **设备管控**：选设备（从设备清单选设备 / 分组，或从已知设备下拉填 MAC），选“始终禁止上网”或
  “按时间段禁止”，勾选星期、填时间段（如 `21:30-07:00`，跨午夜自动算到次日）。到点立即断网，已经在
  播的视频也会停；内网、DHCP、DNS 不受影响。临时断网一会儿（不改配置）用 网络 › 设备 或
  状态 › 终端设备 里的“暂停”。
- **端口转发**的内部 IP 也可以直接写设备清单里有固定 IP 的设备名（如 `desktop`）。

改完点底部“保存并应用”：先校验并显示变更计划，应用后 120 秒内点“保留”，否则自动回滚。

**router.yaml / agent**

直接编辑 `/etc/mini-router/router.yaml` 的 `firewall:` 段（格式见上面的配置参考），然后
`mr validate && mr apply --confirm 120`，确认网络正常后 `mr confirm`。常用例子：

```yaml
# 孩子的平板 周日到周四 21:30 到次日 07:00 断网
firewall:
  access:
    - {name: kid-ipad, macs: ["aa:bb:cc:dd:ee:01"], schedule: [{days: [sun, mon, tue, wed, thu], time: "21:30-07:00"}]}
# 只允许办公室 IP 通过 wan2 访问 NAS 的 SSH（外部 2222 → 内部 22）
  forwards:
    - {name: nas-ssh, proto: [tcp], port: "2222", to: 192.168.1.241, to_port: "22", wan: [wan2], src_ip: [203.0.113.0/24]}
# IPv6 放行 NAS 的 443（NAS 上已设置 ip token ::10）
  ipv6_allow:
    - {name: nas-https, iid: "::10", proto: [tcp], port: "443"}
```

设备清单里的名字（dev.md）：`access: [{name: kids-night, devices: ["group:kids"], schedule: …}]`、
`forwards: [{name: nas-https, proto: [tcp], port: "8443", to: nas, to_port: "443"}]`。

查看命中计数：`nft list table inet mr | grep -E 'rule:|access:|v6in:|fallback:|pause|wan-in-drop'`；
查看拦截日志：`dmesg | grep mr-drop`。
