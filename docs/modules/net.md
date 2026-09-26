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
| 策略路由 | 按 MAC / 源地址 / 目标地址 / 域名（可组合）指定出口 WAN | 无 |
| 按域名选 WAN | dnsmasq 的 `nftset=` 把上游应答里的地址写进 nft 集合，新连接的第一个包按集合打 WAN 标记，之后照常 flowtable / PPE（见下文“按域名”） | 无（dnsmasq 本来就在；集合按需占内核内存） |
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
  3. 策略路由：只标记新连接（按域名的规则匹配 `@pr_<序号>_4` / `@pr_<序号>_6`，IPv6 还要求源地址在 `via` 的前缀
     `@pd6_<序号>` 里）；同一连接符合几条时**排在前面的那条生效**（打完标记就 `return`，#64）。策略路由页显示每条域名策略
     已学到的地址数（API `net.routes` 的 `learned`）；
  4. 负载均衡（`mode: balance`）：只处理 `meta mark 0x0` 的新 IPv4 连接，目标不是 LAN 侧网络。
- 健康检测判定某线路故障时：该线路 main 表默认路由 metric +10000（下一条接管，但检测 ping 仍能从它出去），
  它的 WAN 表删掉默认路由（策略路由 / 均衡 / 恢复标记的流量落到 main = 最好的健康线路），并从均衡表里拿掉。恢复后全部还原。
- 状态文件（tmpfs）：`/run/mini-router/wan/<wan>.json`（这条线拿到的地址、网关、DNS、上线时间），
  `/run/mini-router/wan-state.json`（健康检测每轮写），`/run/mini-router/resolv.conf`。

**给其它模块（proxy）的约定**：net 用到的 fwmark 是各 WAN 的标记（默认 0x200-0x2ff，策略路由可指定，例如家里的 0x102）。
net 的 `mark_pre` 链在 mangle+1；LAN 侧有 `ct mark != 0` 的包会被恢复成 `meta mark` 并跳出该链，所以透明代理最好用自己的链
（优先级 mangle 或更早）、用不和上面冲突的标记位，不要改写这些连接的 `ct mark`；负载均衡不会碰已经有 `meta mark` 的包。
按域名的策略路由：net 通过 `Module.Dnsmasq` 给主 dnsmasq 加 `nftset=` 行，proxy 的 mr-proxy-dns 用同一个函数
（`policyNftsetLines`，去掉被代理的域名）；集合 `pr_<序号>_4/6` 在 `defs`，fw 的 `fwLoad` 重载时带回学到的地址
（`policyDomainCarry`）。

## router.yaml 参考

### lan

```yaml
lan:
  bridge: br-lan              # 默认 br-lan
  ports: [lan2, lan3, lan4]   # 不打标签的成员口
  ipv4: 192.168.1.6/24
  ipv6_ra: true               # 向 LAN 通告前缀（dnsmasq）
```

### mode：旁路由 / 纯 AP（core，`mr/mode.go`）

```yaml
mode: bypass                  # router（默认）| bypass | ap
lan:
  bridge: br-lan
  ports: [eth0]               # 一个口也行（ap：把所有口都列上，含原来的 WAN 口）
  ipv4: 192.168.1.2/24        # 固定地址，不要落在主路由的地址池里
  gateway: 192.168.1.1        # 主路由：本机的默认网关和 DNS 上游（dns.upstream 默认 manual + [gateway]）
wan: []
bypass:
  clients: route-only         # route-only（默认）| all | selected
  macs: []                    # selected：以本机为网关 + DNS 的设备
  nat: true                   # all / selected：转发流量伪装成本机地址（默认开）
```

旁路由（`mode: bypass`）三种拓扑：

| clients | 设备的网关 / DNS | 经过本机的流量 | 本机挂了 |
|---|---|---|---|
| `route-only`（推荐） | 网关仍是主路由；主路由的 DHCP 把 DNS 指向本机，并把代理网段（`mr proxy routes` 打印的 fake-ip + 规则 CIDR）静态路由到本机 | 只有被代理的连接 | 只影响被代理的域名；主路由的硬件加速完全不受影响 |
| `all` | 本机发 DHCP（主路由的 DHCP 关掉），网关和 DNS 都是本机 | 全部 | 全家断网 |
| `selected` | 本机发 DHCP；只有 `macs` 里的设备拿到本机，其余设备拿到主路由 | 这些设备的全部流量 | 只影响这些设备 |

- **route-only 的回程**：客户端的请求是主路由转过来的，本机的代理（sing-box 的透明 socket）如果直接把回包发给客户端，主路由
  只看到连接的一个方向，下一个包就被它的连接跟踪当成 invalid 丢掉（OpenWrt 默认就这样）。所以被代理的连接打一个 connmark，
  回包在 output 的 route 链里打 fwmark `0x2000000`，走路由表 301（`default via lan.gateway`），经主路由回去：两个方向都经过主路由。
  CI（`tools/ci.d/mode.sh`）在网络命名空间里用一个丢 invalid 的主路由验证了这一点，并验证去掉这条规则连接就断。
- **all / selected** 默认做 NAT（`iifname br-lan oifname br-lan masquerade`）：不做的话主路由把回包直接交给设备，本机只看到
  一个方向，同样被当成 invalid。接收入站端口转发的服务器不要把旁路由当网关。
- 代理必须 `proxy.ipv4_only: true`：设备的 IPv6 路由和 RA / DNS 仍是主路由的。在主路由上关掉 IPv6 DNS 下发，否则设备会绕过
  本机的 DNS。本机自己用主路由通告的前缀 SLAAC（`accept_ra=2`），不发 RA。
- 不支持（校验会拒绝）：`wan`、`networks`、`multiwan`、`policy_routes`、`firewall.forwards / open / ipv6_allow / access`、src / dest 为
  `wan` 的流量规则、`multicast.igmpproxy`、`lan.ipv6_ra`、`services.edge.open`、`dns.upstream: isp`。整个上游网络都算 LAN 区，
  管理页面靠密码保护。

纯 AP（`mode: ap`）：所有口和 SSID 在一个网桥里，管理地址固定（`lan.ipv4`）+ 主路由做网关；关掉转发（`ip_forward=0`），不做 NAT、
DHCP、RA、代理和 flowtable（桥接流量本来就不经过路由）；input 防火墙照常。多台 AP 同 SSID 用有线回程。

`install.sh` 问“工作模式”：选 bypass / ap 时不问 WAN，本机地址和主路由地址默认沿用现在的（SSH 安装不会断线）。

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
    mac: a4:a9:30:6e:2b:89    # 可选：克隆 MAC（作用于物理口，所以同一个口上的几条 WAN 只能用同一个 MAC）
    proto: pppoe              # pppoe | dhcp | static
    username: "user@example-isp"
    password_secret: pppoe_password   # secrets.yaml 里的键名
    mtu: 1492                 # pppoe 默认 1492，可设 1500（RFC 4638，见下）；dhcp/static 0 = 不改
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

**PPPoE 1500 MTU（RFC 4638）**：`mtu` 大于 1492 时，network.sh 把 PPPoE 所在的物理口设成 `mtu + 8`（1500 → 1508，
VLAN 的父口先设，子接口不能超过它；DSA 端口的 conduit 由内核自动加标签开销），pppd 2.5 的 pppoe 插件就会在发现阶段带上
`PPP-Max-Payload`；运营商不回这个标签时 pppd 按 RFC 4638 自己退回 1492，不会断网。同一个物理口上还有不打 VLAN 的
DHCP / 静态 WAN 时拒绝（它的 IP MTU 会跟着变成 1508）：把它放到 VLAN 上，或者 PPPoE 用 1492。apply 之后若网卡拒绝了这个 MTU，
验证失败并回滚。`mr wan status` 的 `mtu` 是会话实际的 MTU（1500 = 运营商同意了）。AX6000 的 `wan` 口最大 MTU 15338，1508 没问题。

**IPv6 前缀变化（RFC 9096）**：每次 dhcpcd 事件都把 RA 网桥上的前缀按委派它的 WAN 记到 `/etc/mini-router/state/lan6-prefixes.json`
（“这条 WAN 最后一次通告的地址”）。WAN 暂时没有地址（释放、断线、关机时的 RELEASE6 / STOP6 / STOPPED）时保留记录、不写闪存；
这条 WAN 重新委派到网桥、地址与记录不同时（重启之后，或同一次开机里 PPPoE 重拨换了前缀），记录里没回来的地址以首选寿命 10 秒、
有效寿命 = `dhcp.ipv6.lease`（最多 45 分钟）重新挂回网桥：dnsmasq 看到它过期，就把它当旧前缀以首选寿命 0 通告，客户端停止使用。
运营商给回同一个前缀时什么也不做；只有非空的地址集变化时才写闪存。

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

**PPPoE 拨号顺序**（与 `mode` 无关，`mode` 为空也能用；Cd1s/mini-router#109）：同一个账号多拨时，运营商那边有些东西
（例如它自带的 DDNS）只认最后建立的会话。

```yaml
multiwan:
  dial_order: [wan2, wan]     # 这些 PPPoE WAN 按顺序拨号（至少两条，不重复）；不在列表里的照常拨
  dial_wait: 20               # 秒（1–120，默认 20）：每条最多等排在前面的线路这么久，拨不上也不再等
  dial_restore: "04:30"       # off（默认）| now | HH:MM（system.timezone）
```

- 等待：`mr-pppoe.<wan>` 的命令是 `/usr/libexec/mr/pppoe-dial`，它先跑 `mr wan dial-wait <wan>`（等到前面每条线路都有会话、
  即 `/run/mini-router/wan/<名字>.json` 存在，或等满 `dial_wait`），再 exec pppd。等待不在 `start_pre` 里，OpenRC 不会被卡住
  （串行启动时所有线路同时开始等）；只等排在前面的，不会死锁。pppd 退出后 supervise-daemon 重新拉起时也会同样等一次。
- 顺序被打乱：某条在线的线路的会话（`mr wan status` 的 `since`）比排在它前面的某条在线线路的会话旧，即前面的线路后来单独重拨过。
  `now`：ppp-up 钩子脱离进程（setsid）运行 `mr wan dial-restore`，按顺序重拨后面的线路（`rc-service mr-pppoe.<wan> restart`，
  每条等新会话建立后再拨下一条）；`HH:MM`：crond 每天这个时间运行 `mr wan dial-restore`（`M H * * * /usr/sbin/mr wan dial-restore`），
  仍然乱序才重拨。每条线路 10 分钟内最多恢复一次（`/run/mini-router/dial-restore.json`）；每次恢复写事件（类型 `dial`）
  并在 `/etc/router-changes.log` 记一行（这样随之而来的断线 / 恢复事件标为预期）。
- `mr wan status`：`dial_order`、`dial_order_ok`、`dial_late`（拨得太早的线路）、`dial_restore`、`dial_restore_at`（`HH:MM` 模式下
  乱序时，下次重拨的时间，unix 秒）；网页“多线路 → 线路状态”表格下显示一行。

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
  - name: video-via-wan2
    domains: [video.example, "*.cdn.example.net"]   # 按域名：写 example.com = 它和它的所有子域名
    domains_file: /etc/mini-router/video.domains    # 可选：更多域名，一行一个，# 注释
    via: wan2
  - name: office-wan2-only
    device: office-pc         # 代替 mac：设备清单（devices，见 dev.md）里的设备或 group:分组，它的所有 MAC
    via: wan2
    fallback: drop            # main（默认）| drop：见下
    nat6: true                # 可选：别的前缀的 IPv6 也走 via（NPTv6），见下
```

没写 src / dst 时 IPv4 + IPv6 都生效；写了 src / dst 就只管那个地址族。访问 LAN 侧网络、tailscale、静态路由的流量不受影响。

**IPv6 按源前缀**（#63）：一个 IPv6 连接只有源地址属于 `via` 这条 WAN 委派的前缀时才会被送过去（nft 集合 `@pd6_<序号>`，
dhcpcd 钩子把每条 WAN 的前缀记在 `/run/mini-router/wan/<名>.pd6`，防火墙每次加载后重新填入）。两条线都有前缀时，设备用
另一条线的前缀作源地址的连接留在默认路由上——否则上游运营商会按源地址把它丢掉。`via` 没有 IPv6 前缀时，IPv6 连接都走默认路由。

**`nat6: true`**（#108，默认关闭；`via` 须 `ipv6` + `ipv6_pd`，策略不能是纯 IPv4）：设备的 IPv6 不论源地址属于哪个前缀都走 `via`。
源地址不在 `via` 前缀里的新连接跳到 `npt6m_<序号>` 打标记，出 `via` 时在 srcnat 跳到 `npt6n_<序号>` 做 NPTv6
（`snat ip6 prefix to <via 记录的第一个前缀>`，接口 ID 不变，回程由 conntrack 还原）。两条链由 `pd6Script` 与 `pd6_<n>`
同时刷新：`via` 没有前缀时链为空，连接不打标记、走默认路由（不会带着别的前缀从 `via` 出去）。被转换的连接走软件
flowtable（PPE 不做 IPv6 NAT）；源地址本就在 `via` 前缀里的照常硬件加速。DDNS `ipv6: mac:` 对被策略固定到某条 WAN 的设备
优先发布该 WAN 前缀里的地址。

#### 断线兜底（fallback）

`via` 的 WAN 断线（PPPoE 掉线）或健康检测失败时，它的路由表里没有默认路由，打了标记的流量会落到 main 表，
从别的 WAN 出去——这是默认的 `fallback: main`（能上网，但换了出口）。`fallback: drop` = 这些流量只准走 `via`：
filter/forward 最前面（hook `forward_first`，在 flow offload 和“已建立连接放行”之前）加一条
`iifname {LAN} <同样的条件> oifname {其它所有 WAN} counter drop comment "fallback:<名称>"`，所以断线期间
新连接和已有连接都出不去，恢复后自动恢复；访问 LAN、tailscale 不受影响。IPv6 只拦策略本来会路由的流量
（源地址在 `via` 委派的前缀里，`ip6 saddr @pd6_<n>`；`nat6: true` 时该设备的 IPv6 全部）：来自别的 WAN 前缀的源地址照常走默认 WAN；设备的 DNS 仍由路由器经任意线路查询；被透明代理接管的连接走代理。
家里配置没有用它，输出不变。

#### 按域名（domains / domains_file）

域名条件和 MAC / src / dst 一样可以组合（同时满足），也可以单独用。做法（不新增任何进程）：

1. 两个 dnsmasq（主 dnsmasq 和代理用的 mr-proxy-dns）都生成
   `nftset=/域名/.../4#inet#mr#pr_<序号>_4,6#inet#mr#pr_<序号>_6`：上游应答里这些域名（及子域名）的 A / AAAA
   地址被写进 nft 集合 `@pr_<序号>_4` / `@pr_<序号>_6`（序号 = 这条策略在 `policy_routes` 里的位置，从 0 起）。
2. `mark_pre` 里这条策略的规则只看新连接：目标在集合里 → 打上该 WAN 的标记（和其它策略路由一样，connmark 保持）。
   之后整条连接照常进 flowtable，由 PPE / WED 硬件转发——只有第一个包查一次集合。
3. 集合元素默认 1 天过期（dnsmasq 只加不删）；每有一个新连接用到某个地址，它的计时就重新开始，所以正在用的地址
   不会因为 DNS 缓存还指向它而掉出集合。每个集合最多 16384 个地址。
4. 防火墙每次重载（apply、PPPoE 重拨、多线路切换）都会重建整张表：学到的地址在同一次加载里带回新集合，
   剩余时间不变。**域名列表变了**（集合注释里记着列表的哈希）就不带回：删掉的域名不会因为还有人在用就一直走那条线。

注意：

- dnsmasq 只在向上游查询时写集合，从自己缓存回答时不写。刚改完域名 apply 时 dnsmasq 会重启（缓存清空），
  但设备自己缓存的旧应答在过期前仍会走默认线路；已经建立的连接保持原来的线路。
- 设备绕过路由器 DNS 时不生效：写死的 DNS 服务器可以用 `dns.redirect` 收回来，浏览器 / 系统的 DoH、DoT 不行。
- CDN 上几个网站共用 IP 时会一起被分流（这类方案的共性）。
- dnsmasq 用“最具体”的那行匹配：子域名在别的策略里也列了时，那一行同时写入上级域名策略的集合，
  所以每个集合都含它所有域名及子域名的地址；同一连接符合几条策略时以后面那条为准。
- 被代理的域名（proxy 规则）在 mr-proxy-dns 里不写集合：那边的应答是 fake-ip，本来就进代理。
- IPv6：和只写 MAC 的规则一样，AAAA 地址的连接也按标记走该 WAN 的表；设备的源地址是另一条线路的前缀时，
  运营商多半会丢掉这个包（支持 Happy Eyeballs 的应用会退回 IPv4）。目标 WAN 没有 IPv6 时，它的表里没有 IPv6
  默认路由，IPv6 连接照常从有 IPv6 的线路走（能通，但不分流）。
- `domains_file` 改了要 `mr apply` 才生效（dnsmasq 的配置在 apply 时生成）；读不到、有不是域名的行或一个域名都没有时
  apply 报错（报行号，不回显内容）。最多 16 条策略带域名（多的域名放进同一条）。
- 需要带 nftset 的 dnsmasq：M3 镜像装的是 `dnsmasq-dnssec-nftset`；普通 Alpine 安装由 `install.sh` 装它
  （手动：`apk add dnsmasq-dnssec-nftset`，会替换 `dnsmasq`）。不带 nftset 的 dnsmasq 拒绝这份配置，apply 自动回滚。
- 看学到了什么：`nft list set inet mr pr_0_4`（地址和剩余时间）。

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
- **网络 → LAN 与网络 → 工作模式**：选旁路由或纯 AP，填主路由地址。旁路由默认“只管代理”：卡片里列出主路由要添加的静态路由；
  在主路由的 DHCP 里把 DNS 改成本机地址。选“全部设备”或“指定设备”时先关掉主路由的 DHCP。
- **路由 → 策略路由**：按 MAC（或设备清单里的设备名 / `group:分组`）/ 源地址 / 目标地址 / 域名指定出口 WAN（域名一栏填
  `example.com, video.example`，含子域名；更长的列表用 router.yaml 的 `domains_file`）；“该 WAN 断线时”选“断网”=
  只走这条线，断线时不换线（`fallback: drop`）；下面是实时 `ip rule`（v4 / v6）。
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
- 按域名选 WAN 依赖设备用路由器的 DNS（DoH / DoT 绕过它），第一次连接前要先有一次上游应答；细节见上文“按域名”。
