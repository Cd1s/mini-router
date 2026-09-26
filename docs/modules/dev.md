# dev — device inventory, groups, pausing a device

Cd1s/mini-router#15. Files: `mr/mod_dev.go` (inventory, groups, name resolution), `mr/mod_dev_pause.go`
(`mr pause`), `rootfs/www/ui/dev.js` (网络 › 设备), `tools/ci.d/dev.sh`, lab fragment `examples/lab.d/35-dev.yaml`.
Nothing resident, no new package, no new process.

## Inventory (`devices`, `groups`)

A device is a name for one or more MACs (cable + WiFi, a phone's per-network private address),
optionally with a fixed IPv4. Other sections refer to it by name instead of repeating MACs / addresses:

```yaml
devices:
  - name: office-pc                 # [a-z]([a-z0-9-]{0,30}[a-z0-9])?: a DNS label that cannot be read as an IP / MAC / lease time
    macs: ["02:00:00:00:10:01"]     # 1-8 unicast MACs; a MAC belongs to one device and is not also in dhcp.hosts
    ip: 192.168.1.70                # optional fixed IPv4 inside a LAN-side network (a static lease)
    type: pc                        # optional label: pc, phone, tablet, tv, console, iot, server, printer, other, …
    owner: alice                    # optional label (the person)
    desc: ""                        # optional, UI only
  - {name: kid-tablet, macs: ["aa:bb:cc:00:00:21", "aa:bb:cc:00:00:22"], type: tablet, owner: kid}
groups:
  kids: [kid-tablet, game-console]  # name: reName ([a-z][a-z0-9_-]{0,14}); 1-256 devices; written group:kids elsewhere
```

Where names work (resolved when the config is validated and rendered — router.yaml is never rewritten,
the older keys keep working unchanged):

| Key | Takes | Becomes |
|---|---|---|
| `firewall.forwards[].to` | an IPv4 or a device with `ip` | the DNAT target |
| `firewall.access[].devices` | devices, `group:NAME` (next to / instead of `macs`) | all their MACs (1-64 in total) |
| `policy_routes[].device` | a device or `group:NAME` (instead of `mac`) | `ether saddr { its MACs }` |
| `proxy.bypass[].device` | a device or `group:NAME` (instead of `mac`) | its MACs in `@proxy_bypass` |
| `guard.always_bypass` | device names too | every MAC of the device must be bypassed |
| `sys.wol`, `mr wol`, `schedules` `wol` | device names too | the device's first MAC |
| `mr pause`, `dev.pause` | device, `group:NAME`, dhcp.hosts name, MAC | all its MACs |

A name that does not exist is a validation error at the place that uses it
(`firewall.forwards[3].to: unknown device "office-pc" (devices:)`), so deleting a device that is still
referenced lists every reference; a forward to a device without `ip` is refused.

**dhcp.hosts and devices — one source of truth.** Every device is one dnsmasq line, rendered by the dns
module after the `dhcp.hosts` lines: `dhcp-host=MAC[,MAC…][,IP],NAME[,lease]`. The inventory name is the
device's DHCP / DNS name (`office-pc.lan`); `ip:` makes it a static lease exactly like a `dhcp.hosts` entry.
A MAC, name or address may be in `dhcp.hosts` or in `devices`, never in both (validation), so there are
no two places that disagree. `dhcp.hosts` stays as it is (the web UI can move an entry into the inventory:
网络 › 设备 › 从终端添加 › 静态分配); `dhcp.host_leases` accepts device MACs. Several MACs with one `ip`
share it: only one of them can hold the lease at a time (right for cable / WiFi of one laptop; give a
device that uses both at once no `ip`, or two devices). The inventory also names devices in 终端设备,
流量统计 / 连接 (mon), WOL, and new-device events (an inventory MAC is never "new").

## Pausing a device (`mr pause`)

Runtime only: no config change, no confirm window, nothing resident; the kernel ends the pause.

    mr pause kid-tablet 1h          # device, group:kids, a dhcp.hosts name or a MAC; 30m, 2h30m, 1d … (1s – 7d)
    mr pause list [--json]          # MAC, name, what was paused, time left, addresses
    mr unpause kid-tablet | all     # end it early

Web UI: 暂停 on 网络 › 设备 (devices and groups) and 状态 › 终端设备 (every DHCP client; a MAC of the
inventory pauses the whole device), durations 30 分钟 / 1 / 2 小时 / 到明早 7:00 / custom; active pauses
on 总览 with 恢复. API: `GET dev.paused` (read), `POST dev.pause {target, duration}` and
`POST dev.unpause {target}` (operate; recorded in `/etc/router-changes.log` like other web UI actions).

How it works:

- State: `/run/mini-router/pause.json` (tmpfs — a reboot ends every pause): the MACs, when each pause
  ends in **seconds since boot** (the clock the kernel's set timeouts run on, so NTP setting the clock at
  boot changes nothing), who paused it, and the device's addresses (neighbour table, DHCP lease, fixed ip).
- `fwLoad` (every firewall reload: apply, PPPoE / DHCP hooks, `mr fw`, `mr pause`) adds, in the same nft
  transaction as the ruleset: sets `paused` (ether_addr), `paused_4`, `paused_6` with per-element
  timeouts = the time left, and inserts at the top of both chains:

      forward: iifname {LAN-side} ether saddr @paused oifname {WANs} counter drop comment "pause"
               iifname {WANs} ip daddr @paused_4 counter drop comment "pause"      (and ip6 / @paused_6)
      input:   iifname {LAN-side} ether saddr @paused fib daddr type != { local, broadcast, multicast, anycast } drop

  (input: a transparent proxy takes the device's traffic through input; DHCP, DNS, ND to the router keep
  working). None of this is in the rendered `nftables.nft`, so `mr plan` never shows it.
- Cutting what already runs: a pause replaces the whole table. That replaces the flowtable, which sends
  every offloaded flow (PPE / WED or software fast path) back to the CPU path; the paused device's packets
  then meet the drops in both directions (replies from the WAN first — hence the address sets), everyone
  else's flows are offloaded again by their next packet. The issue proposed deleting the device's conntrack
  entries; the platform kernel has no `nf_conntrack_netlink` (checked on the router: no `conntrack` tool,
  no module), and a reload does the same job without one.
- An address another MAC holds now (neighbour table) is left out, so a lease given away while the paused
  device was gone is not cut. The addresses matter only for connections from before the pause.
- The end: the kernel drops the elements; the (then empty) rules stay until the next reload.
- Reloads are serialized (`/run/mini-router/fw.lock`) and read the state under that lock, so a PPPoE hook
  reloading during `mr pause` cannot load a copy without the pause last. `mr pause` checks that the
  loaded `@paused` set holds the MACs and fails otherwise.

Not offloaded while paused (dropped instead); a device that is not paused is never affected.

## Cost

Binary: stripped linux/arm64 `mr` 10 158 240 → 10 223 776 bytes (+64 KiB; text +74.5 KiB) for the whole
issue (inventory, name resolution, pause, policy fallback, API); init allocation unchanged (lazy regexps).
RAM: nothing resident; while a pause is active 3 small sets and 4 rules. Flash: none for a pause from
the CLI; one line in `/etc/router-changes.log` per pause / unpause from the web UI / API. Home config:
no inventory → rendered files unchanged (`tools/ci.d/dev.sh` checks that no pause state is in them).

## Left out (see the issue)

- `watch: true` (online / offline events per device), `firewall.unknown_devices: allow | notify | isolate`
  (new-device *notification* exists: event `new_device`; isolation of unknown MACs needs a default-deny
  set of known MACs and would lock out every phone with a new private address), device type guessing
  (OUI table + DHCP fingerprints), a per-device detail page (lease / signal / traffic / connections /
  rules on one screen), `runtime.json` for all temporary states.

## 怎么用

**网页**

- **网络 › 设备**：设备清单。每行显示名称、类型 / 归属 / 所在分组、MAC（可多个）、IP（固定的或当前租约）、
  是否在线（WiFi 在线 / 有租约）、是否暂停、被几处引用（鼠标悬停看是哪里）。
  - “从终端添加…”：从 DHCP 终端里挑一台加进清单；也可以把“静态分配”里的旧条目移进清单（移完旧条目自动删掉）。
  - “编辑”：改名会同时改掉端口转发、设备管控、策略路由、代理例外、分组里对它的引用；填“固定 IPv4”= 静态分配。
  - “删除”：还有地方在用时列出这些地方，不让删；只在分组里的会顺带移出分组。
  - “暂停”：选 30 分钟 / 1 小时 / 2 小时 / 到明早 7:00 或自己填（如 45m、1d，最长 7 天）。只断外网，内网、
    DHCP、DNS 照常；正在看的视频、在玩的游戏立即断开；到时自动恢复，也可以点“恢复”。不改配置、没有确认倒计时。
  - “分组”：建 `kids` 这样的分组，“暂停整组”一次停掉一家人的设备；其他地方写 `group:kids`。
- **状态 › 终端设备**：每个 DHCP 终端都有“暂停”按钮（属于清单里的设备时整台设备一起暂停）。
- **总览**：有设备在暂停时显示“暂停上网中”卡片，可直接恢复。
- **防火墙 › 设备管控**、**路由 › 策略路由**、**代理 › 例外设备**、**端口转发**：都可以直接选 / 写设备名或 `group:分组`。

清单、分组的改动和其他配置一样点底部“保存并应用”；暂停 / 恢复立即生效，不需要应用。

**命令行 / agent**

```sh
mr pause kid-tablet 1h           # 暂停一小时
mr pause group:kids 9h           # 整组
mr pause aa:bb:cc:dd:ee:ff 30m   # 不在清单里的设备按 MAC
mr pause list                    # 谁在暂停、还剩多久
mr unpause kid-tablet            # 提前恢复（all = 全部）
```

router.yaml（改完 `mr validate` → `mr plan` → `mr apply --confirm 120` → `mr confirm`）：

```yaml
devices:
  - {name: nas, macs: ["aa:bb:cc:dd:ee:10"], ip: 192.168.1.10, type: server}
  - {name: kid-tablet, macs: ["aa:bb:cc:dd:ee:21"], type: tablet, owner: kid}
groups:
  kids: [kid-tablet]
firewall:
  forwards: [{name: nas-https, proto: [tcp], port: "8443", to: nas, to_port: "443"}]
  access: [{name: kids-night, devices: ["group:kids"], schedule: [{days: [sun, mon, tue, wed, thu], time: "21:30-07:00"}]}]
policy_routes:
  - {name: nas-wan2-only, device: nas, via: wan2, fallback: drop}   # wan2 断线时 nas 断网，不换线
```
