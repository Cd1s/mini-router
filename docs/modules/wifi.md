# wifi 模块

无线部分：两个射频（2.4 GHz / 5 GHz，mt76 + 上游 hostapd 2.11 + OpenWrt noscan 补丁），每个射频最多 4 个
SSID，访客 SSID 可以接到访客网络；终端列表与踢下线；信道分析（survey + 周边扫描）；自动调优（#41，默认全关）：
每个 SSID 的组播转单播、802.11v 频段引导、射频健康与不重启的自愈。

没有常驻进程：状态、终端、信道数据都是 `mr`（CGI）按需从 hostapd 控制 socket 和 `iw` 读出来的；频段引导和自愈
开启后由 crond 每分钟跑一次 `mr wifi tick`（几十毫秒就退出）。
信道、频宽、发射功率、国家码只用你在 router.yaml / 网页里设的值，模块不会自动改（自动调优也不碰它们）。

| 文件 | 作用 |
|---|---|
| `mr/mod_wifi.go` | 配置结构、校验、渲染 hostapd 配置 / MAC 列表 / `wifi-post.sh` / network.sh 片段，模块注册 |
| `mr/mod_wifi_ctrl.go` | hostapd 控制 socket 客户端（Go 直连 `/var/run/hostapd/<ifname>`，不用 hostapd_cli）：状态、应用后校验、踢终端 |
| `mr/mod_wifi_api.go` | `wifi.stations` / `wifi.survey` / `wifi.scan` 的解析与 API，`mr wifi …` 命令 |
| `mr/mod_wifi_steer.go` | 802.11v 频段引导：同名 SSID 配对、hostapd 邻居报告、`BSS_TM_REQ` 与应答、按终端限频 |
| `mr/mod_wifi_health.go` | 射频健康（debugfs / hwmon，`wifi.health`、`mr doctor`）、自愈状态机、`mr wifi tick` 与它的 cron 行 |
| `rootfs/etc/init.d/mr-hostapd` | 启动 hostapd：只加载 AP 网卡还存在的射频配置（删掉的射频留下的旧配置文件不会再发射），随后执行 `wifi-post.sh` 和 `mr fw` |
| `rootfs/www/ui/wifi.js` | 网页：无线设置（含“自动调优”）、无线终端（含空口占用）、信道分析、射频健康 |
| `tools/ci.d/wifi.sh` | CI：hostapd 配置键白名单 + 真实 hostapd 2.11 解析；调优键只出现在该出现的 BSS、cron 行、没有 hostapd 时 tick 也正常退出 |

## 生成的文件

| 路径 | 内容 | 变化时 |
|---|---|---|
| `/etc/hostapd/hostapd-<phy>.conf` (0600) | 一个射频一个文件；第一个 SSID 是 `interface=<phy>-ap0`，其余是 `bss=<phy>-ap0-<i>` | 重启 mr-hostapd |
| `/etc/hostapd/<ifname>.maclist` (0600) | 开了 MAC 过滤的 SSID 的地址列表 | 重启 mr-hostapd |
| `/etc/mini-router/gen/wifi-post.sh` | hostapd 起来后执行：固定发射功率；等额外 SSID 的网卡建好（之后 `mr fw` 把它们加进 flowtable）；隔离 SSID 的网桥端口隔离 | 重启 mr-hostapd |
| `/etc/modprobe.d/mt7915e.conf` | `wed_enable`（跟随 `firewall.offload: hardware`） | 下次加载驱动 / 重启生效 |
| network.sh 的 `wifi` 阶段 | 按频段找到内核 phy，建 `<phy>-ap0`；多 SSID 的射频设置基准 MAC（见下） | network.sh 原地重跑 |
| `/etc/crontabs/root` 里的一行（sys 模块的管理块） | `* * * * * /usr/sbin/mr wifi tick`：只在 `wifi.steering.enabled` 或 `wifi.self_heal` 时存在（此时 crond 也被启用） | crond 重读 |

运行时状态（都在内存盘 `/run/mini-router`，不写闪存）：`wifi-steer.json`（引导记录与计数）、`wifi-health.json`（自愈采样）、
`wifi.tick`（锁：上一个 tick 没跑完，下一个直接退出）。自愈的每一步另记一条事件（`events.log`，类型 `wifi`，见 sys 模块）。

## router.yaml 配置参考

```yaml
wifi:
  country: PA                  # 国家码，两位大写字母；空 = 不写 country_code（此时也不写 802.11d/h）
  steering:                    # 可选，802.11v 频段引导，默认关（见下）
    enabled: false
    min_signal_2g: -60         # dBm，-90..-30；2.4G 信号不低于它才建议换 5G（开启时默认 -60）
    exclude: []                # 从不引导的设备 MAC（最多 64 个）
  self_heal: false             # 可选，射频自愈，默认关（见下）
  radios:
    - phy: phy0                # 我们给射频起的名字 phy0..phy9；实际内核 phy 按 band 查找
      band: 2g                 # 2g | 5g，每个频段只能有一个射频
      channel: auto            # auto 或信道号
      channels: "1-11"         # auto 时 ACS 的候选范围（hostapd chanlist）
      htmode: HE40             # HE20 | HE40（2.4G）；5G 还可 HE80 | HE160
      txpower: 30              # dBm，0 = 驱动默认
      beacon_int: 100          # 可选，TU（1 TU = 1.024 ms），10-10000，默认 100
      dtim_period: 2           # 可选，1-255，默认 2
      legacy_rates: false      # 可选，仅 2.4G：true = 保留 802.11b 速率（1/2/5.5/11 Mbps），默认关
      ssids:                   # 1-4 个
        - ssid: MiniRouter-2.4G   # 1-32 字节，UTF-8 可以（以 ssid2= 十六进制写入），同一射频内不能重名
          key_secret: wifi_key # secrets.yaml 里密码的名字（[a-z0-9_-]{1,40}）；encryption: none 时不需要
          encryption: sae-mixed  # sae-mixed（WPA2/WPA3 混合）| sae（仅 WPA3）| psk2（仅 WPA2）| none（开放）
          pmf: ""              # 可选，802.11w：""（按加密方式）| disabled | optional | required
          hidden: false        # 隐藏 SSID
          isolate: false       # 可选，客户端隔离
          max_clients: 0       # 可选，0 = 不限，最多 2007
          macfilter: ""        # 可选，"" | allow（白名单）| deny（黑名单）
          maclist: []          # macfilter 用的 MAC 列表
          network: ""          # 可选，接入哪个网络：""/lan = 主 LAN，或 networks[] 里的名字（如 guest）
          multicast_to_unicast: false  # 可选，组播转单播（见下）
```

### 加密与 802.11w（PMF）

| encryption | 默认 ieee80211w | 允许的 pmf | 说明 |
|---|---|---|---|
| `sae-mixed` | 1（可选） | optional, required | WPA2 和 WPA3 设备都能连；SAE 设备一定用 PMF（`sae_require_mfp=1`），开 beacon 保护 |
| `sae` | 2（强制） | required | 只允许 WPA3 设备 |
| `psk2` | 1（可选） | disabled, optional, required | `disabled` 给不支持 802.11w 的老 IoT 用（此时只用 `WPA-PSK`，不带需要 PMF 的 SHA256 AKM） |
| `none` | — | 不能设置 | 开放网络，没有 PMF |

密码：8–63 个可打印 ASCII。WPA3 的密码不能包含 `|mac=`、`|vlanid=`、`|pk=`、`|id=`
（hostapd 解析 `sae_password` 时会把它们当成参数截断，等于换了一个密码）。

### 客户端隔离

`isolate: true` 做两件事：
1. hostapd `ap_isolate=1`：同一个 SSID 的终端互相看不到；
2. `wifi-post.sh` 把这个 SSID 的网卡设为网桥隔离端口（`/sys/class/net/<if>/brport/isolated`）：
   不同频段 / 不同 SSID 上开了隔离的终端之间也不通。

隔离的终端照常访问路由器本身（DHCP、DNS）和上网；能不能访问内网由它所在网络的防火墙区域决定
（`networks[].zone: guest` = 只能上网）。访客 SSID 的推荐配置：`network: guest` + `isolate: true`。
隔离只影响网桥转发判断，不影响 PPE/WED 硬件加速。

### MAC 过滤

`macfilter: allow` 只允许 `maclist` 里的设备（列表不能为空，否则谁都连不上）；`deny` 拒绝列表里的设备。
地址统一存成小写。手机默认用“私有/随机 MAC”，要在手机上对这个网络关掉才能匹配。

### 多个 SSID 与 BSSID

hostapd 给额外的 BSS 分配地址时从第一个 BSS 的地址往上加，并要求第一个地址在块内对齐
（`addr & mask == addr`，否则报 “Invalid BSSID mask” 并让整个射频起不来）。出厂 MAC 不一定对齐，所以
**有 2 个以上 SSID 的射频**，network.sh 会把 `<phy>-ap0` 的地址设为：出厂 MAC 置“本地管理”位、
第一个字节 2.4G 再加 4 / 5G 加 8（两个频段不会撞）、最后一字节低 2 位清零（留出 4 个 BSS 的位置）。
用“加”而不是“异或”，是为了让新地址比出厂地址大（出厂 MAC 第一个字节 ≥ 0xf8 时会回绕，这种前缀很少见）：网桥没有固定 MAC 时用它端口里最小的 MAC，
如果 AP 地址比有线口（同一个厂商前缀）小，LAN 的 MAC 就会变成 AP 的，而且 hostapd 每次重启
（离开再加入网桥）都会来回变一次。
只有一个 SSID 的射频（比如现在家里的配置）不动，仍用出厂 MAC。第一次从 1 个 SSID 变成多个时，
主 SSID 的 BSSID 会变一次，终端会自动重连。

额外的 SSID 网卡（`<phy>-ap0-<i>`）要等射频真正起来才由 hostapd 建出来：自动选频（ACS）之后，雷达信道
还要等 CAC（60 秒，气象雷达信道 10 分钟）。`wifi-post.sh` 会等这些网卡都出现（最多共 11 分钟）再结束，
随后的 `mr fw` 才能把它们放进硬件加速的 flowtable；隔离的 SSID 也是在这时设置网桥隔离。

### 应用与校验

改 WiFi 配置 → apply 重启 mr-hostapd（该频段断开几秒）。应用后校验通过 hostapd 控制 socket 的 `STATUS`：
每个射频必须是 `ENABLED`（或 `DFS`：雷达信道正在做 CAC，气象雷达信道可能要 10 分钟，也算配置成功），
且每个 SSID 的 BSS 都在；90 秒内达不到就自动回滚。

### 组播转单播（`multicast_to_unicast`）

`ssids[].multicast_to_unicast: true` → hostapd `multicast_to_unicast=1`：mac80211 把发往这个 SSID 的 ARP / IPv4 /
IPv6 组播（含 802.1Q 里的）复制成给每个终端的单播（目标 MAC 换成终端自己的）。好处：按终端自己的速率发、有确认和
重传（组播只能用最低的基本速率、没有确认），AirPlay / 投屏 / mDNS 发现 / IPTV 更稳更快，省电中的手机也不用等 DTIM。
代价：每个终端一份（终端很多、组播流量很大时多占 CPU 和空口），而且不看 IGMP 订阅，所有终端都收到所有组。

**不需要改网桥**（按 mac80211 源码确认）：转换发生在 AP 网卡自己的发送路径（`ieee80211_subif_start_xmit` →
`ieee80211_multicast_to_unicast`），有线侧经网桥来的组播、同一 SSID 里一个终端发给其他终端的组播（mac80211 在同一个网卡上
`dev_queue_xmit` 转发）都走这里。OpenWrt netifd 给无线网桥端口设的 `brport/multicast_to_unicast` + hairpin 是网桥自己的、
依赖 IGMP/MLD 侦听的另一套机制，这里不用；`multicast.snooping`（net 模块）不受影响。组播本来就不走 PPE/WED 硬件加速。
hostapd 文档提示：接收方看到的是“单播帧里的组播 IP 包”，极少数协议栈对此有假设（例如对这种包不回 ICMP 不可达）。

### 802.11v 频段引导（`steering`）

没有 usteer / DAWN（它们依赖 OpenWrt 给 hostapd 打的 ubus 补丁，Alpine 的 hostapd 没有），也没有常驻进程：开启后
crond 每分钟运行 `mr wifi tick`，直接用 hostapd 控制 socket：

1. **配对**：2.4G 和 5G 上**同名、同加密、同密码引用名、同网络**的 SSID。只有这些 BSS 的配置多出
   `bss_transition=1`（在 beacon 里声明支持 BSS Transition，很多终端只听声明了的 AP 的建议）和 `rrm_neighbor_report=1`
   （hostapd 为自己生成邻居报告）。开启但没有这样的 SSID 时校验失败；同名但加密/密码/网络不同也失败（终端换过去会连不上）。
   **家里现在的配置 2.4G 和 5G 名字不同，要用这个功能得先把两个 SSID 改成同一个名字**（密码相同，已保存 5G 的设备会自动认）。
2. **目标**：5G BSS 自己的邻居报告（`SHOW_NEIGHBOR`：BSSID、BSSID 信息、operating class、信道、PHY 类型、宽带信道子元素，
   都由 hostapd 按实际信道算好），再加候选偏好 255。两个频段各自的报告也互相写进对方的邻居列表（`SET_NEIGHBOR`，
   hostapd 重启后下一分钟补上），终端主动请求邻居报告时就知道另一个频段。
3. **挑终端**（2.4G BSS 上的，`STA-FIRST/STA-NEXT`）：已认证；扩展能力里声明 BSS Transition（bit 19）；如果列出了支持的
   operating class，里面要有 5 GHz 的（115–129）；信号 ≥ `min_signal_2g`；已连接满 1 分钟；不在 `exclude` 里；
   30 分钟内没问过、4 小时内没拒绝过、24 小时内问过不到 3 次；每次最多问 4 台。5G 射频不在“工作中”（例如雷达检测）时不问。
4. **请求**：`BSS_TM_REQ <MAC> pref=1 abridged=1 valid_int=200 dialog_token=N neighbor=<5G>`——只建议、**不带
   disassoc_imminent**，终端可以拒绝，拒绝了也照常连着。随后最多等 2 秒终端的应答（hostapd 只把 `BSS-TM-RESP` 作为事件发给
   attach 的监听者，所以这 2 秒里 attach，完了 detach）。
5. **记录**：`/run/mini-router/wifi-steer.json`：每台设备的次数/结果、计数（建议、接受、拒绝、无应答、出错、之后确实出现在
   5G 上的）、最近 20 条；每次请求一行 syslog。不写闪存、不进事件日志（太频繁）。

2 流终端在 2.4G HE40 和 5G HE160 下的 PHY 速率约差 4.2 倍，所以默认门限 -60 dBm（2.4G 上这么好的信号，换到 5G 一般还有
-65 ~ -70 dBm）。`mr wifi steer --dry-run` 列出现在会问谁、不问谁及原因，不发任何请求。
802.11r 快速漫游（FT-PSK）没有做：同一台 AP 上两个频段之间的切换，终端用 PMKSA 缓存 / SAE 已经很快。

### 射频健康与自愈（`self_heal`）

只读指标（`mr wifi health`、API `wifi.health`、网页“射频健康”、`mr doctor` 的 wifi 检查），按 `<phy>-ap0` 背后的内核 phy：

| 指标 | 来源（在路由器上只读确认过） | 说明 |
|---|---|---|
| 温度 / 降频门限 / 发射占空比 | hwmon `mt7915_<phy>`：`temp1_input`、`temp1_crit`、`throttle1` | 占空比 100 % = 未降频；过热时固件降低占空比 |
| 已确认发送帧 | debugfs `…/mt76/tx_stats`：`Tx single-user / multi-user successful MPDU counts` | 硬件 MIB 计数，**含 WED 硬件转发的流量**；u32，会回绕 |
| 空口公平 | debugfs `…/mt76/vow_atf` | 见下一节 |
| 固件重启次数 | debugfs `…/mt76/sys_recovery` 的 `SYS_RESET_COUNT: WM a, WA b` | 驱动加载以来固件崩溃被驱动恢复的次数 |
| 固件 CPU | debugfs `…/mt76/fw_util_wm` 的 `Busy: N%` | **驱动只在固件调试（`fw_debug_wm`）打开时才输出**，平时只有 Program counter，所以一般显示“未上报”；为了它打开固件日志不值得 |
| 每终端空口时间 | debugfs `…/netdev:<ifname>/stations/<MAC>/airtime`（`RX:` / `TX:` µs） | 加在 `wifi.stations` 里；网页按两次刷新之间的差算占用百分比 |

`mr doctor`：每个射频一条（温度、终端数、ATF；过热降频 / 接近降频温度 / ATF 被关 / 固件重启过 / 发送停滞 → warn，自愈放弃 → risk），
所有射频都没有 `vow_atf` 时一条 skip。

**自愈**（`self_heal: true`，同一个每分钟的 tick）：某个射频有终端在线、但“已确认发送帧”10 分钟没动 = 发送卡死（hostapd 对
空闲终端每 5 分钟发一次 null-data 探测，正常的射频不会 10 分钟一帧都不发）。卡死后每 10 分钟走一步，仍卡着才走下一步：

1. 驱动自带的**全芯片固件恢复（SER）**：`echo 7 > /sys/kernel/debug/ieee80211/<phy>/mt76/sys_recovery`——和固件看门狗触发时
   mt76 自己走的是同一条路径（重新加载固件、重建 DMA/WED 队列、`ieee80211_restart_hw` 恢复所有终端的状态），几秒钟，
   终端一般不掉线。它复位整颗芯片（两个频段），所以同一分钟两个频段都卡死只写一次；
2. **重启 mr-hostapd**（两个频段都断开几秒，终端自动重连）；
3. **放弃**：记一条 risk 事件“需要重启”，**不会自动重启路由器**；之后发送一恢复就记“恢复正常”。

限制：每个射频 24 小时最多 4 次动作；有待确认的更改（apply 正在进行 / 等待保留）时只记录不动作；两次采样相隔超过 5 分钟
（crond 停过、时钟跳变）或内核 phy 变了（驱动重载）就重新开始计时。每一步都是一条 `wifi` 事件（可推送通知）。
`sys_recovery` 的取值（0–8）和写入方式按路由器上的 debugfs 帮助文本和 OpenWrt mt76 2026.09.01 源码确认，**没有在在线路由器上写过**。

### 空口公平（WED 硬件转发的流量）

LAN→WiFi 的流量走 WED 硬件转发时绕过 mac80211 的软件空口公平（`airtime_flags`）和 AQL。OpenWrt mt76 的
“HW ATF support for mt7986+”（openwrt/mt76 6b7b98627bcc）改用固件的 VoW 调度，debugfs `vow_atf` 控制。路由器上只读检查：
**这个内核的 mt76（OpenWrt 包 mt76 2026.09.01~be5ce791）已经带了**，两个 phy 都有 `vow_atf`，值为 1——驱动默认开启
（`init.c`：`vow_atf_en = true`）。所以不需要配置项：`wifi.health` / 网页显示它的状态，被人关掉时 `mr doctor` 警告并给出打开的
命令；换到没有它的 mt76（例如 6.18 内核自带的）时 `mr doctor` 给一条 skip，说明需要更新的 mt76。

## API（`/cgi-bin/api?a=…`，需要登录）

| action | 方法 | 返回 / 参数 |
|---|---|---|
| `wifi.status` | GET | 每个 SSID 一项：`ifname ssid phy band network up state channel htmode clients bssid cac_left` |
| `wifi.stations` | GET | `{stations:[{ifname ssid band network mac signal signal_dbm tx_rate rx_rate tx_mbps rx_mbps tx_bytes rx_bytes tx_retries tx_failed connected inactive_ms mfp airtime_tx_us airtime_rx_us}]}`；tx = 路由器→终端；airtime = 连接以来占用的空口时间（µs，驱动不报时没有这两项） |
| `wifi.health` | GET | `{time, self_heal, radios:[{phy band kphy state stations temp_c crit_c tx_duty fw_busy tx_acked has_tx atf fw_resets ser stalled_s heal_stage heal_actions}], steering:{enabled min_signal_2g excluded pairs counts since recent}}`；API token 的 read 范围 |
| `clients` | GET | 同 `wifi.stations`（旧页面在用） |
| `wifi.kick` | POST | `{mac, ifname?}` → 通过 hostapd `DEAUTHENTICATE` 断开；只接受本机配置里的 BSS；404 = 不在线 |
| `wifi.survey` | GET | `{radios:[{phy band ifname state channel width cac_left config channels:[{freq channel in_use noise active_ms busy_ms rx_ms tx_ms}]}]}` |
| `wifi.scan` | POST | `{phy}` → `iw dev <phy>-ap0 scan flush ap-force`：`{bss:[{bssid ssid freq channel width signal security stations util standard own band}]}`。**扫描期间该频段离开当前信道几秒，终端会卡顿** |

状态 JSON（`mr status` / 总览 / 面板）的 `wifi` 数组也是每个 SSID 一项（字段同 `wifi.status`）。

## 命令行（给 agent 用）

    mr wifi status              # 每个 SSID 的实时状态（JSON）
    mr wifi stations            # 终端列表（JSON）
    mr wifi kick aa:bb:cc:dd:ee:ff [phy1-ap0]
    mr wifi survey              # 各信道噪声 / 繁忙时间
    mr wifi scan phy1           # 周边网络（会打断该频段几秒）
    mr wifi health              # 射频健康 + 自愈状态 + 频段引导统计（JSON）
    mr wifi steer --dry-run     # 现在会建议谁换 5G、不建议谁及原因（不发请求）；不带 --dry-run 立即跑一轮
    mr wifi tick                # crond 每分钟调用：一轮引导 + 一次自愈采样（两个都关时什么也不做）

## CI

- `go test`：家里配置渲染出的 hostapd 配置、`wifi-post.sh`、network.sh 的 wifi 阶段与改动前逐字节相同
  （`mr/testdata/wifi-home/*.golden`）；实验配置 `examples/lab.d/20-wifi.yaml` 覆盖所有功能；
  每个渲染出的 hostapd 键都在 `mr/testdata/hostapd-2.11.keys` 里；控制 socket 用假 hostapd 测试。
- `tools/ci.d/wifi.sh`：
  1. 家里 + 实验配置的每个键都在白名单里（白名单 = hostapd 2.11 `hostapd_config_fill()` 在 Alpine 编译选项下
     接受的键 + noscan 补丁的键）；
  2. 从固定 sha256 的 hostapd-2.11.tar.gz 重新生成白名单并比对（离线时跳过）；
  3. 用真实的 hostapd 2.11（本机有 noscan 版 apk 就用它，否则用 Alpine 包；docker 里 arm64）解析每个配置：
     未知键、非法值、hostapd 自己的一致性检查都会失败；先自测一个坏配置确认能被拒绝。
  4. 调优：家里配置不出现 `multicast_to_unicast` / `bss_transition` / `rrm_neighbor_report`、crontab 里没有 tick；实验配置里
     这些键只出现在对应的 BSS、有 `* * * * * /usr/sbin/mr wifi tick`；没有 hostapd 时 `mr wifi tick` / `health` /
     `steer --dry-run` 都正常退出并写出状态。
  刷新白名单：`sh tools/ci.d/wifi.sh --keys`（在编译机上）。
- `go test`（`mr/mod_wifi_tune_test.go`）：校验、渲染、cron 行；hostapd `STA` 输出（ext_capab / supp_op_classes）、邻居报告转
  候选、`BSS-TM-RESP` 解析；引导决策表；假 hostapd（两个控制 socket）上的完整引导流程（dry-run、请求内容、attach/detach、
  互写邻居、接受 / 拒绝 / 无应答、冷却、每天上限、确认已到 5G、雷达检测中不问）；debugfs/hwmon 解析（用路由器上的真实输出）；
  自愈状态机（阈值、间隔、断档、换 phy、计数回绕、无 SER、每天上限）；假 sysfs 上的自愈全过程（有待确认更改时不动作、同一芯片
  只写一次 SER、重启一次 hostapd、放弃与恢复的事件、tick 的锁）。

## 怎么用

### 网页

**无线 → 无线设置**
1. 顶部“全局”里的国家码按你所在地填（两位大写字母）。
2. 每个频段一个标签页。上面是射频参数：信道、自动选频范围、频宽、发射功率，以及 Beacon 间隔、DTIM；
   2.4G 还有“允许 802.11b 速率”（只有很老的设备才需要）。标题右边显示实时状态（工作中 / 雷达检测 / 信道和频宽）。
3. 下面每个 SSID 一张卡片：名称、接入网络、加密、密码引用名 + 密码、管理帧保护、隐藏、客户端隔离、最大终端数、MAC 过滤。
   - “+ 添加 SSID”：新 SSID 默认 WPA2/WPA3 混合，并有自己的密码名（`wifi_key_<phy>_<n>`），记得填密码。
   - “+ 添加访客 SSID”：自动接到访客网络、打开客户端隔离、密码名 `wifi_guest_key`。需要先在“网络”里建一个
     zone 为 guest 的网络。
   - 多个 SSID 想共用一个密码：把“密码引用名”填成同一个名字。
4. 点底部“保存并应用” → 校验 → 看变更计划 → 应用 → 120 秒内点“保留”。该频段 WiFi 会重启几秒。

**无线 → 无线设置 → 自动调优**（在“全局”下面）
- “频段引导 (802.11v)”：打开后下面会显示“可引导：<SSID>（2.4G 网卡 → 5G 网卡）”；显示黄色提示说明两个频段没有同名、同加密、
  同密码、同网络的 SSID，先到下面的频段标签页把名字改成一样。“引导门限”默认 -60 dBm；“不引导的设备”每行一个 MAC
  （比如只在 2.4G 上稳定的智能家居）。
- “射频自愈”：打开后发送卡死时自动先做固件恢复、再重启 hostapd，不会重启路由器。
- 每个 SSID 卡片里的“组播转单播”：家里有 AirPlay / 投屏 / 智能音箱发现不稳定时打开（一般只开主 SSID）。
- 保存并应用：只改这些开关时该频段 WiFi 会重启几秒（hostapd 配置变了）；只改“射频自愈”不重启 WiFi。

**无线 → 射频健康**：每 5 秒刷新。每个频段：状态、终端数、温度（和降频门限）、发射占空比、每秒已确认发送帧、空口公平、
固件 CPU（一般“未上报”）、固件重启次数、自愈状态和最近的自愈记录。下面是频段引导：门限、配对的 SSID、统计（建议 / 接受 /
拒绝 / 无应答 / 已换到 5G）、最近 20 次建议（设备名来自 DHCP 租约）。

**无线 → 无线终端**：每 5 秒刷新，显示设备名 / IP（来自 DHCP 租约）、SSID、信号、协商速率、流量、空口占用（两次刷新之间该终端
收发占用的空口时间比例，含硬件转发的流量）、在线时长。
- “踢下线”：马上断开（设备一般会自动重连，用来让它重新选频段/重新认证）。
- “拉黑”：马上踢下线，并把它加到该 SSID 的黑名单（白名单模式下则是从白名单删除），点“保存并应用”后永久生效。

**无线 → 信道分析**：每个频段显示当前信道/频宽/状态、各信道的噪声和繁忙率（当前信道另有最近 5 秒的实时繁忙率）。
“扫描周边网络”会列出周围的 AP（SSID、信道、频宽、信号、加密、标准、BSS Load）和每个信道上的 AP 数；
扫描时该频段终端会卡顿几秒，所以会先确认。这里只看数据，要换信道请到“无线设置”里自己改。

### router.yaml / agent

直接编辑 `/etc/mini-router/router.yaml` 的 `wifi:` 段，密码写进 `secrets.yaml`（名字对应 `key_secret`），然后：

    mr validate && mr plan && mr apply --confirm 120 && mr confirm

例：给 5G 加一个访客 SSID（需要 `networks` 里已有 `guest`）

```yaml
        - {ssid: MiniRouter-Guest, key_secret: wifi_guest_key, encryption: sae-mixed,
           network: guest, isolate: true, max_clients: 16}
```

`secrets.yaml` 加一行 `wifi_guest_key: "至少8位的密码"`。

例：只允许两台 IoT 设备连一个隐藏的 2.4G SSID，关 PMF 兼容老芯片

```yaml
        - ssid: MiniRouter-IoT
          key_secret: wifi_iot_key
          encryption: psk2
          pmf: disabled
          hidden: true
          network: iot
          macfilter: allow
          maclist: ["aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02"]
```

踢掉一个设备：`mr wifi kick aa:bb:cc:dd:ee:ff`；想让它连不上，把它加到对应 SSID 的
`macfilter: deny` + `maclist` 再 apply。

例：两个频段用同一个名字，开频段引导、射频自愈，主 SSID 组播转单播

```yaml
wifi:
  steering: {enabled: true, min_signal_2g: -60, exclude: ["aa:bb:cc:00:00:07"]}
  self_heal: true
  radios:
    - phy: phy0
      band: 2g
      ssids:
        - {ssid: Home, key_secret: wifi_key, encryption: sae-mixed, multicast_to_unicast: true}
    - phy: phy1
      band: 5g
      ssids:
        - {ssid: Home, key_secret: wifi_key, encryption: sae-mixed, multicast_to_unicast: true}
```

或者用 `mr set`（保留注释和格式）：

    mr set wifi.steering.enabled=true wifi.self_heal=true 'wifi.radios[phy1].ssids[Home].multicast_to_unicast=true'
    mr plan && mr apply --confirm 120 && mr confirm
    mr wifi steer --dry-run     # 看看会建议谁
    mr wifi health              # 引导统计、温度、自愈状态

看它做了什么：`grep 'wifi steer\|wifi self-heal' /var/log/messages`；自愈的每一步也在 `mr event list`（类型 wifi）。

## 已知限制

- hostapd 崩溃被 supervise-daemon 自动拉起时不会重跑 `wifi-post.sh`：固定发射功率、跨 SSID 网桥隔离、
  以及 flowtable 里后建的 BSS 网卡要等下次 `rc-service mr-hostapd restart` / apply 才恢复（`ap_isolate` 本身不受影响）。
- 雷达信道 CAC（状态“雷达检测”）期间扫描可能被内核拒绝（返回 busy），等状态变成“工作中”再扫。
- 未在真机上跑过（按约定不碰在线路由器）：BSSID 对齐、控制 socket、survey/scan 输出解析都是按 hostapd 2.11 /
  iw 6.9 源码和单元测试验证的，上机时请先用实验配置测一遍。
- 自动调优（#41）同样只在路由器上做了只读检查（debugfs / hwmon 路径和输出、hostapd 编进了 `BSS_TM_REQ` / `SHOW_NEIGHBOR` /
  `ext_capab` / `supp_op_classes` / `multicast_to_unicast`、真实终端的 `STA` 输出）；`BSS_TM_REQ`、`SET_NEIGHBOR` 和
  `sys_recovery` 的写入没有在在线路由器上执行过。第一次开启时看一下 `mr wifi steer --dry-run` 和 syslog。
- 频段引导只在同一个 SSID 的两个频段之间；家里当前的配置两个频段名字不同，开启前要统一名字。终端是否接受建议由终端决定
  （部分 IoT 芯片声明支持 802.11v 却总是拒绝，放进 `exclude` 即可）。
- 固件 CPU 占用只有打开固件调试时驱动才输出，默认看不到。
- 每终端独立密码（PPSK）和第二台 AP（有线回程 / WDS）是 #41 的 P2 部分，没有做。
