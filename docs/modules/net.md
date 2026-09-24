# net 模块：网口、LAN / 网络、WAN、多线路、路由

net 负责路由器的"线"：物理网口和网桥、LAN 与额外网络（访客 / IoT / VLAN）、WAN（PPPoE / DHCP / 静态，可带 VLAN）、
多线路（健康检测主备 + 按连接负载均衡）、策略路由、静态路由、组播、IPv6 的 WAN 侧（dhcpcd），以及接口状态。

设计原则：**正常流量全部留在硬件卸载（PPE + WED）上**，net 只在"新连接的第一个包"上打 fwmark 决定走哪条线，
之后由 conntrack + flowtable 转发；**不常驻 Go 进程**——状态和页面数据都是按需从 `/sys`、`ip -j` 和几个小状态文件算出来的；
唯一的新常驻进程是可选的健康检测，它是一个 busybox sh 循环（`mr-wanmon`，约 1 MB RSS 以内，每轮几次 `ping`）。

## 做了什么

| 功能 | 实现 | 常驻开销 |
|---|---|---|
| PPPoE（已有） | `pppd` + 生成的 `/etc/ppp/peers/<wan>`，服务实例 `mr-pppoe.<wan>` | pppd |
| DHCP WAN | busybox `udhcpc -f`，服务实例 `mr-udhcpc.<wan>`（supervise-daemon 守护）；事件脚本 `/usr/libexec/mr/net-udhcpc` → `mr wan dhcp <event>` 校验租约后配地址、路由、规则、DNS | udhcpc（busybox，≈100 KB） |
| 静态 WAN | `network.sh` 配地址，`mr routes` 装默认路由 | 无 |
| WAN VLAN | `<device>.<vlan>` 802.1Q 子接口（PPPoE / DHCP / 静态都可以跑在上面） | 无 |
| 多线路主备 | `mr-wanmon`：busybox sh 循环，每条线路各自 ping 检测目标；故障线路默认路由 metric +10000，策略路由表去掉默认路由 | sh + 每轮几次 ping |
| 负载均衡 | nft `numgen random` 按权重给新 IPv4 连接打 WAN 标记，connmark 保持 | 无（nftables 规则） |
| 策略路由 | 按 MAC / 源地址 / 目标地址（可组合）指定出口 WAN | 无 |
| VLAN 网络 | 额外网络可带 802.1Q 标签：`<port>.<vlan>` 加入该网络的网桥，端口原来的用途不变 | 无 |
| 接口状态 | `net.ports` 读 `/sys/class/net`：链路、速率、双工、计数、错误；网页显示前面板网口 + 接口表（实时速率） | 无 |
| WAN DNS | 钩子维护 `/run/mini-router/resolv.conf`（在线线路的 DNS，健康的优先），dnsmasq 读它 | 无 |

## 路由表 / 规则 / 标记布局

```
ip rule
  0      local
  5210-5270  tailscale（它自己管）
  5290   from <WAN 地址> lookup <WAN 表>          路由器自己从某条 WAN 地址发出的包走那条 WAN（钩子维护）
  5299   lookup main suppress_prefixlength 0      main 里除默认路由以外的路由优先：LAN / 访客网 / 直连 / 静态路由永远不被标记改走 WAN
  5300   fwmark <WAN 标记> lookup <WAN 表>        每条 WAN 一条（network.sh 维护）
  32766  main
```

- 每条 WAN 一个路由表和一个 fwmark：`200+序号 / 0x200+序号`；第一条带 `table`+`mark` 的策略路由可以指定该 WAN 的表和标记
  （家里配置保留 wan2 = 表 102 / 0x102）。
- nft `mark_pre`（prerouting，优先级 mangle+1）里的顺序：
  1. 从 WAN 进来的新连接：`ct mark` = 该 WAN 的标记（端口转发的回包、入站连接从原线路回去）；
  2. 从 LAN 侧各网桥进来且 `ct mark != 0`：恢复 `meta mark` 并 `return`（已有连接保持线路）；
  3. 策略路由：只标记新连接；
  4. 负载均衡（`mode: balance`）：只处理 `meta mark 0x0` 的新 IPv4 连接，目标不是 LAN 侧网络。
- 健康检测判定某线路故障时：该线路 main 表默认路由 metric +10000（下一条接管，但检测 ping 仍能从它出去），
  它的 WAN 表删掉默认路由（策略路由 / 均衡 / 恢复标记的流量落到 main = 最好的健康线路），并从均衡表里拿掉。恢复后全部还原。
- 状态文件（tmpfs）：`/run/mini-router/wan/<wan>.json`（这条线拿到的地址、网关、DNS、上线时间），
  `/run/mini-router/wan-state.json`（健康检测每轮写），`/run/mini-router/resolv.conf`。

**给其它模块（proxy）的约定**：net 用到的 fwmark 是各 WAN 的标记（默认 0x200-0x2ff，策略路由可指定，例如家里的 0x102）。
net 的 `mark_pre` 链在 mangle+1；LAN 侧有 `ct mark != 0` 的包会被恢复成 `meta mark` 并跳出该链，所以透明代理最好用自己的链
（优先级 mangle 或更早）、用不和上面冲突的标记位，不要改写这些连接的 `ct mark`；负载均衡不会碰已经有 `meta mark` 的包。

## router.yaml 参考

### lan

```yaml
lan:
  bridge: br-lan              # 默认 br-lan
  ports: [lan2, lan3, lan4]   # 不打标签的成员口
  ipv4: 192.168.1.6/24
  ipv6_ra: true               # 向 LAN 通告前缀（dnsmasq）
```

### networks（访客 / IoT / VLAN）

```yaml
networks:
  - name: guest               # [a-z][a-z0-9_-]{0,9}，网桥 br-guest
    ipv4: 192.168.20.1/24
    zone: guest               # guest = 只能上网（默认）；lan = 信任
    ports: [lan3]             # 可选：整个口给这个网络（从 lan.ports 里拿掉）
    ipv6_ra: true
    dhcp: {enabled: true, start: 100, end: 199, lease: 2h}   # 地址池由 dns 模块生成
  - name: iot
    ipv4: 192.168.30.1/24
    zone: lan
    vlan: 10                  # 802.1Q ID
    trunk: [lan4]             # lan4.10 加入 br-iot；lan4 本身仍是 LAN 口（接支持 VLAN 的交换机 / AP）
```

### wan

```yaml
wan:
  - name: wan                 # PPPoE 时接口名 pppoe-<name>，所以最多 9 个字符
    device: wan               # 物理口
    vlan: 0                   # 可选：运营商要求的 VLAN（PPPoE / DHCP / 静态都可用），接口 wan.<vlan>
    mac: 02:55:a3:1c:8d:ed    # 可选：克隆 MAC（作用于物理口，所以同一个口上的几条 WAN 只能用同一个 MAC）
    proto: pppoe              # pppoe | dhcp | static
    username: "user@example-isp"
    password_secret: pppoe_password   # secrets.yaml 里的键名
    mtu: 1492                 # pppoe 默认 1492；dhcp/static 0 = 不改
    metric: 0                 # 默认路由跃点：越小越优先（主备顺序）；每条 WAN 必须不同（同 metric 的默认路由会互相覆盖）
    peerdns: true             # 用运营商下发的 DNS（pppoe / dhcp）
    ipv6: true                # dhcpcd：RA / DHCPv6
    ipv6_pd: true             # 申请前缀放到 LAN
    ipv6_srcroute: false      # 源地址是本线路前缀的 IPv6 从本线路走（多线必开）
  - name: hotel               # 出差：插到别人的网络上
    device: wan
    proto: dhcp
    metric: 50
    peerdns: true
  - name: office
    device: wan
    vlan: 30
    proto: static
    ipv4: 203.0.113.10/29
    gateway: 203.0.113.9      # 必须在 ipv4 的网段里
    dns: [203.0.113.53]       # 最多 3 个；只有 static 用这个字段
    metric: 90
```

同一个物理口可以跑多条 PPPoE（多拨）；DHCP / 静态每个接口（口或 VLAN）只能一条。不打标签的 WAN 口（运营商那根线）
既不能同时是 LAN 口，也不能做任何网络的带标签端口（trunk），否则 LAN 侧网络会被桥到运营商那一侧。
DHCP / 静态 WAN 被删除、改名或换了接口（VLAN / 口）时，应用会删掉它留在旧接口上的地址和默认路由
（按 `/run/mini-router/wan/<wan>.json` 里记录的接口）；改地址时新地址和旧地址在同一网段也不会一起丢（`promote_secondaries`）。

### multiwan

```yaml
multiwan:
  mode: balance               # 空 = 关（仍按 metric 主备：PPPoE 掉线自动切）；failover = 健康检测主备；balance = 负载均衡 + 主备
  targets: [1.1.1.1, 223.5.5.5]   # IPv4，每条线路各自 ping，任一回应算正常（默认 1.1.1.1、8.8.8.8）
  interval: 5                 # 每轮间隔秒数（默认 5）
  timeout: 2                  # 等回应秒数（默认 2）
  fall: 3                     # 连续失败几轮判定故障（默认 3）
  rise: 2                     # 连续成功几轮判定恢复（默认 2）
  weights: {wan: 2, wan2: 1}  # balance：新连接按权重分；不写 = 每条 1；0 = 只做备用
```

负载均衡只分新的 IPv4 连接（同一连接一直走同一条线路）；IPv6 不参与（每条线路前缀不同，按源地址路由）。
策略路由、端口转发 / 入站连接的回包优先于均衡。

### policy_routes

```yaml
policy_routes:
  - name: desktop-via-wan2    # 名称 [A-Za-z0-9_.-]
    mac: 02:c3:06:d6:7f:8a    # 条件（可组合，至少一个）：mac / src / dst
    via: wan2
    table: 102                # 可选：table + mark 一起写 = 指定 wan2 的表 / 标记
    mark: "0x102"
  - name: nas-via-wan
    src: 192.168.1.240/29     # 源地址或网段
    via: wan
  - name: tv-to-iptv
    mac: 02:98:67:90:62:47
    dst: 198.51.100.0/24      # 目标地址或网段
    via: iptv
```

只写 MAC 时 IPv4 + IPv6 都生效；写了 src / dst 就只管那个地址族。访问 LAN 侧网络、tailscale、静态路由的流量不受影响。

### static_routes / multicast（不变）

```yaml
static_routes:
  - {name: lab, target: 10.9.0.0/16, via: 192.168.1.50}
  - {name: v6, target: "2001:db8::/32", dev: pppoe-wan, metric: 0, table: 0}
multicast: {igmp_snooping: false, igmp_proxy: false, upstream: wan2}
```

## 运行时：服务、命令、API

| 名称 | 说明 |
|---|---|
| `mr-pppoe.<wan>` | pppd；实例脚本由 mr 生成（`/etc/init.d/mr-pppoe.<wan>` 只有两行，source 共用的 `mr-pppoe`） |
| `mr-udhcpc.<wan>` | busybox udhcpc；实例脚本由 mr 生成（带 `MR_WAN_DEV`） |
| `mr-wanmon` | 健康检测（`/usr/libexec/mr/net-wanmon`，配置 `/etc/mini-router/gen/wanmon.conf`）；停止时恢复所有线路 |
| `mr wan status` | 每条 WAN 的运行状态 JSON（地址、网关、DNS、表 / 标记、当前 metric、健康、延迟） |
| `mr wan health` | 按健康状态重装路由和防火墙（net-wanmon 在状态变化时调用） |
| `mr wan dhcp <event>` | udhcpc 事件钩子 |
| `mr routes` | 重装所有在线 WAN 的路由 / 规则，重载防火墙 |
| API `net` | 原始 `ip -j` 视图（链路、地址、路由、规则、邻居） |
| API `net.ports` | 网口 / 接口状态（`/sys`） |
| API `net.routes` | 所有表的 v4/v6 路由 + 规则 |
| API `net.wan` | 同 `mr wan status` |
| API `net.redial` | POST `{"wan":"wan2"}`：重启该 WAN 的服务（重新拨号 / 重新获取） |

## 对家里配置（examples/router.yaml）输出的改动（都是有意的）

1. `network.sh` 多了 `ip rule ... lookup main suppress_prefixlength 0 pref 5299`（v4/v6），并且 5300 的 fwmark 规则先清空再加：
   标记（desktop 走 wan2）不会再把去往 LAN 侧 / 直连 / 静态路由的流量带到 WAN 表；改了表 / 标记不会留下旧规则。`wan` 口只 `up` 一次。
2. 生成 `/etc/init.d/mr-pppoe.wan`、`mr-pppoe.wan2` 两行实例脚本（原来靠镜像构建时按示例配置做软链，网页 / agent 新加的 WAN 没有服务）。
   第一次应用会把软链替换成文件，不重启 pppd。
3. dnsmasq 多一行 `resolv-file=/run/mini-router/resolv.conf`：ip-up 钩子把 pppd 给的 DNS1/DNS2 写进去（wan 的 peerdns），
   和 `/run/ppp/resolv.conf` 一起被 dnsmasq 轮询（用最新的那个）；掉线的线路 DNS 会被移除。
   没有任何线路记录了 DNS 时（例如刚升级、PPPoE 还没重拨）这个文件不存在，也绝不会写空文件，dnsmasq 继续用原来的上游。
4. nft、pppd peers、dhcpcd.conf、服务列表与之前相同；多线路默认关闭（家里配置没有 `multiwan`）。

## 怎么用

### 网页

- **状态 → 接口状态**：上面一排是前面板网口（绿 = 千兆以上，黄 = 百兆 / 十兆，灰 = 没插线），下面是全部接口的速率、流量、错误，
  每 3 秒刷新；“邻居表”看 ARP / NDP。
- **网络 → WAN 外网**：每条 WAN 一张卡片，顶部显示当前地址、网关、在线时长、DNS、健康状态。
  “协议”切换 PPPoE / DHCP / 静态，字段跟着变；需要 VLAN 的运营商填 VLAN；“重新拨号 / 重新获取”立即重连这一条线。
  “+ 添加 PPPoE（多拨）”在同一个口上再拨一条；“+ 添加 DHCP / 静态 WAN”用于出差插别人的网络或固定 IP 专线。
- **网络 → 多线路**：上面是实时线路状态（健康、延迟、连续失败、当前默认路由 metric——超过 10000 就是被判故障降级了）。
  下面选模式：关闭 / 主备切换 / 负载均衡 + 主备；检测目标建议填两个不同运营商的地址（在国内可填 223.5.5.5、119.29.29.29）。
  负载均衡时给每条线路设权重，0 = 只做备用。
- **网络 → LAN 与网络**：改 LAN 地址和 LAN 口；“+ 添加网络”建访客 / IoT 网络：选区域（访客只能上网）、给它整个网口，
  或者填 VLAN ID 并勾选带标签端口（接支持 VLAN 的交换机 / AP）；DHCP 地址池也在这里。WiFi 的 SSID 在“无线设置”里选网络。
- **路由 → 策略路由**：按 MAC / 源地址 / 目标地址指定出口 WAN；下面是实时 `ip rule`（v4 / v6）。
- **路由 → 静态路由**：静态路由表格 + 当前所有路由表。
- 所有修改点底部“保存并应用”：先校验、显示变更计划，应用后 120 秒内点“保留”，否则自动回滚。

### router.yaml / agent

- 家里双拨 + 主备 + desktop 走 wan2：就是现在的 `examples/router.yaml`，不用改。想要“连着但不通”也能切换，加：
  ```yaml
  multiwan: {mode: failover, targets: [1.1.1.1, 223.5.5.5]}
  ```
  想两条 PPPoE 一起用（按连接分流，desktop 仍固定走 wan2）：`mode: balance`，`weights: {wan: 1, wan2: 1}`。
- 出差（酒店 / 朋友家，上级是普通路由器）：在 `wan` 口上再加一条 DHCP WAN，和 PPPoE 共用这个口、metric 更大：
  ```yaml
  - {name: travel, device: wan, proto: dhcp, metric: 100, peerdns: true}
  ```
  在家 PPPoE 拨上、DHCP 没有服务器就一直空着；到了外面 PPPoE 拨不上，DHCP 拿到地址自动成为默认线路。
  也可以直接把 `wan` 改成 `proto: dhcp`。应用时如果 DHCP 拿不到地址、而且没有别的线路在线，会自动回滚。
  （一个口 / VLAN 上只能有一条 DHCP 或静态 WAN，PPPoE 可以多条。）
- 运营商要求 VLAN（例如马来西亚 Unifi PPPoE 走 VLAN 500）：在那条 WAN 上加 `vlan: 500`。
- 查看线路：`mr wan status`；手动重拨：`rc-service mr-pppoe.wan2 restart`（或网页按钮）；
  看健康检测日志：`grep wanmon /var/log/messages`。
- agent 改完一定 `mr validate` → `mr plan` → `mr apply --confirm 120` → 验证 → `mr confirm`。

## 限制 / 注意

- 健康检测只看 IPv4（ping 目标是 IPv4）；IPv6 跟着链路状态走（PPPoE 掉线前缀自然失效）。
- 负载均衡只对 IPv4；单个连接不会被拆到两条线路上（下载一个大文件只用一条线）。
- 去掉的 VLAN 子接口 / 网桥在重启前不会自动删除（不影响转发，只是残留一个空接口）。
- DHCP WAN 忽略 option 121（无类静态路由）和服务器下发的 MTU。
