# wifi 模块

无线部分：两个射频（2.4 GHz / 5 GHz，mt76 + 上游 hostapd 2.11 + OpenWrt noscan 补丁），每个射频最多 4 个
SSID，访客 SSID 可以接到访客网络；终端列表与踢下线；信道分析（survey + 周边扫描）。

没有常驻进程：状态、终端、信道数据都是 `mr`（CGI）按需从 hostapd 控制 socket 和 `iw` 读出来的。
信道、频宽、发射功率、国家码只用你在 router.yaml / 网页里设的值，模块不会自动改。

| 文件 | 作用 |
|---|---|
| `mr/mod_wifi.go` | 配置结构、校验、渲染 hostapd 配置 / MAC 列表 / `wifi-post.sh` / network.sh 片段，模块注册 |
| `mr/mod_wifi_ctrl.go` | hostapd 控制 socket 客户端（Go 直连 `/var/run/hostapd/<ifname>`，不用 hostapd_cli）：状态、应用后校验、踢终端 |
| `mr/mod_wifi_api.go` | `wifi.stations` / `wifi.survey` / `wifi.scan` 的解析与 API，`mr wifi …` 命令 |
| `rootfs/etc/init.d/mr-hostapd` | 启动 hostapd：只加载 AP 网卡还存在的射频配置（删掉的射频留下的旧配置文件不会再发射），随后执行 `wifi-post.sh` 和 `mr fw` |
| `rootfs/www/ui/wifi.js` | 网页：无线设置、无线终端、信道分析 |
| `tools/ci.d/wifi.sh` | CI：hostapd 配置键白名单 + 真实 hostapd 2.11 解析 |

## 生成的文件

| 路径 | 内容 | 变化时 |
|---|---|---|
| `/etc/hostapd/hostapd-<phy>.conf` (0600) | 一个射频一个文件；第一个 SSID 是 `interface=<phy>-ap0`，其余是 `bss=<phy>-ap0-<i>` | 重启 mr-hostapd |
| `/etc/hostapd/<ifname>.maclist` (0600) | 开了 MAC 过滤的 SSID 的地址列表 | 重启 mr-hostapd |
| `/etc/mini-router/gen/wifi-post.sh` | hostapd 起来后执行：固定发射功率；等额外 SSID 的网卡建好（之后 `mr fw` 把它们加进 flowtable）；隔离 SSID 的网桥端口隔离 | 重启 mr-hostapd |
| `/etc/modprobe.d/mt7915e.conf` | `wed_enable`（跟随 `firewall.offload: hardware`） | 下次加载驱动 / 重启生效 |
| network.sh 的 `wifi` 阶段 | 按频段找到内核 phy，建 `<phy>-ap0`；多 SSID 的射频设置基准 MAC（见下） | network.sh 原地重跑 |

## router.yaml 配置参考

```yaml
wifi:
  country: PA                  # 国家码，两位大写字母；空 = 不写 country_code（此时也不写 802.11d/h）
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

## API（`/cgi-bin/api?a=…`，需要登录）

| action | 方法 | 返回 / 参数 |
|---|---|---|
| `wifi.status` | GET | 每个 SSID 一项：`ifname ssid phy band network up state channel htmode clients bssid cac_left` |
| `wifi.stations` | GET | `{stations:[{ifname ssid band network mac signal signal_dbm tx_rate rx_rate tx_mbps rx_mbps tx_bytes rx_bytes tx_retries tx_failed connected inactive_ms mfp}]}`；tx = 路由器→终端 |
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
  刷新白名单：`sh tools/ci.d/wifi.sh --keys`（在编译机上）。

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

**无线 → 无线终端**：每 5 秒刷新，显示设备名 / IP（来自 DHCP 租约）、SSID、信号、协商速率、流量、在线时长。
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

## 已知限制

- hostapd 崩溃被 supervise-daemon 自动拉起时不会重跑 `wifi-post.sh`：固定发射功率、跨 SSID 网桥隔离、
  以及 flowtable 里后建的 BSS 网卡要等下次 `rc-service mr-hostapd restart` / apply 才恢复（`ap_isolate` 本身不受影响）。
- 雷达信道 CAC（状态“雷达检测”）期间扫描可能被内核拒绝（返回 busy），等状态变成“工作中”再扫。
- 未在真机上跑过（按约定不碰在线路由器）：BSSID 对齐、控制 socket、survey/scan 输出解析都是按 hostapd 2.11 /
  iw 6.9 源码和单元测试验证的，上机时请先用实验配置测一遍。
