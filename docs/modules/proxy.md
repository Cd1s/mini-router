# proxy — 选择性透明代理（sing-box fake-ip + nftables tproxy）

让**指定的域名和 IP 段**经代理出口出去，其它流量完全不受影响：
不经过代理进程，继续走内核快速转发和 PPE/WED 硬件加速。LAN 区的有线 / 无线设备自动生效，
不用在设备上做任何设置；**例外设备**（如 desktop）永远不走代理，DNS 也拿真实地址。

| 项 | 取值 |
|---|---|
| 内核 | sing-box **1.14.1**（官方最新稳定版，固件用完整构建，见“运行依赖”） |
| 代理出口 | Shadowsocks（2022 / AEAD）、VLESS（REALITY、Vision、uTLS）、VMess、Trojan、Hysteria2、TUIC v5、AnyTLS、SOCKS5、HTTP(S)，传输层 ws / gRPC / HTTP/2 / HTTPUpgrade；其它协议（ShadowTLS、Hysteria v1、SSH、WireGuard…）用自定义 JSON 节点 |
| 导入 | 分享链接（ss / vless / vmess / trojan / hysteria2 / hy2 / tuic / anytls / socks / http(s)）和 base64 订阅，先预览再添加 |
| DNS | fake-ip：代理域名只由代理服务器端解析，本地和运营商 DNS 看不到 |
| 透明代理 | nftables `tproxy`（TCP + UDP，IPv4 + IPv6），只接管目标在代理集合里的连接 |
| 常驻内存 | sing-box：只用 SS 时 arm64 精简构建实测 RSS 约 43 MB；CI 里 amd64 官方完整构建（含 tailscale / cloudflared 等无关代码）只用 SS 约 67 MB，每种协议都跑过流量后约 77 MB（`GOMEMLIMIT=48MiB` 软上限，`GOGC=50`）。第二个 dnsmasq 约 5 MB（cache 8000） |
| 闪存 | sing-box 二进制由固件（platform）决定；`mr` 本轮再增加约 192 KB（arm64 5.31 → 5.51 MB） |
| 关闭时 | `proxy.enabled: false`：没有 nft 链、没有服务、没有 DNS 改动 |

## 为什么选 sing-box

- 性能：Go 实现的 AES-GCM 在 arm64 上用硬件指令（A53 有 crypto 扩展），SS aes-128-gcm 系列、TLS 1.3 / REALITY
  的 AES-GCM 都很快；而且**只有匹配规则的连接**才进入 sing-box，其余流量根本不到用户态，所以代理内核的开销只落在
  少量代理流量上。
- 协议全：一个进程支持上面所有协议（包括 REALITY、uTLS、QUIC 系的 Hysteria2 / TUIC），节点类型由 `mr` 结构化
  校验后生成。mihomo 的规则引擎、GeoIP/GeoSite 等对我们无用。
- fake-ip + tproxy + DNS 规则动作 + clash API（测速、切换、连接列表）都是原生能力，配置可由 `mr` 完整生成并用
  `sing-box check` 校验。

## 工作原理

```
LAN 设备 ──DNS──▶ nft proxy_dns (dstnat-5) 重定向 ──▶ mr-proxy-dns (dnsmasq :1054)
                                                   ├─ 代理域名 ──▶ sing-box DNS 127.0.0.1:1053 ─▶ fake-ip 198.18.x.x / fc00::x
                                                   ├─ 本地名字 (.lan / 无点名 / 反查) ──▶ 主 dnsmasq 127.0.0.1:53
                                                   └─ 其它 ──▶ 与主 dnsmasq 相同的上游（PPPoE DNS、dns.split）
LAN 设备 ──TCP/UDP 到 fake-ip 或规则 CIDR──▶ nft proxy_pre (mangle+5): tproxy 到 127.0.0.1/::1:7893 + fwmark 0x1000000
         ──▶ ip rule pref 5200 → table 300 (local default dev lo) ──▶ sing-box ──▶ 按规则选节点 ──▶ 代理服务器
其它所有流量 ──▶ 不匹配 @proxy4/@proxy6 ──▶ 正常转发 + flowtable 硬件加速（不受影响）
```

- **fake-ip**：代理域名的 A/AAAA 由 sing-box 回答 198.18.0.0/15 / fc00::/18 里的假地址；连接进来时 sing-box
  把假地址还原成域名，交给代理服务器去解析和连接。HTTPS/SVCB 等其它类型回答空结果，避免真实地址通过
  hint 泄露。fake-ip 映射保存在 `/run/mr-proxy/cache.db`（内存），服务停止时存到
  `/etc/mini-router/state/proxy-fakeip.db`，重启后恢复——客户端缓存的假地址在重启后仍然有效，闪存只在停服务时写。
- **两个 dnsmasq**：原计划是在主 dnsmasq 里加 `server=/域名/127.0.0.1#1053`。实现时改成了**第二个 dnsmasq 只服务
  被代理的设备**，主 dnsmasq 一行不改，原因：
  1. 路由器自己（`/etc/resolv.conf` → 主 dnsmasq）不会拿到假地址。否则路由器上的 curl / apk / tailscale /
     sing-box 解析节点域名都会拿到 fake-ip，而路由器自身流量不走代理 → 全部失败。
  2. 访客网络（firewall 区 guest）用主 dnsmasq，不会拿到连不通的假地址；访客区的入站规则也不允许重定向到其它端口。
  3. 例外设备不需要重定向，天然就是主 dnsmasq 的真实结果。
  4. 改规则 / 列表只重启 mr-proxy-dns，不影响 DHCP。
  代价：被代理设备的 DNS 依赖 mr-proxy-dns（supervise-daemon 2 秒内自动拉起；配置由 CI 和每次 apply 的 Verify 验证）。
- **dns.split 冲突**：如果一个域名既在 dns.split 列表（例如发往 stubby DoT）又在代理规则里，dnsmasq 会把两个上游
  混用。mr-proxy-dns 里自动去掉被代理域名（及其子域名）对应的 split 行，代理优先。
- **按域名选 WAN**（net 模块的 `policy_routes[].domains`）：被代理的设备用 mr-proxy-dns 解析，所以它也生成同样的
  `nftset=` 行，把真实应答写进 WAN 集合；被代理的域名（及其子域名）不写（应答是 fake-ip，本来就进代理）。
- **只接管匹配的流量**：`proxy_pre` 链只看 LAN 区网桥进来、目标在 `@proxy4/@proxy6`（fake-ip 段 + 规则 CIDR，
  已合并去重）、并且是连接**发起方向**（`ct direction original`）的 TCP/UDP；已建立的 TCP 连接用 `socket transparent`
  快速命中。其它包一条规则就 `return`。端口转发 / IPv6 入站连接的对端即使落在代理 CIDR 里，LAN 主机的回包也照常转发，
  不会被 tproxy 截走。
  被代理的连接在本机终结，所以不会进 flowtable；其它连接的硬件加速不变。
- **失败即断开 (fail closed)**：sing-box 没运行时，发往代理集合的包被丢弃，不会偷偷直连。
- **回滚不会让全家断 DNS**：nft 的代理规则只在 mr-proxy 和 mr-proxy-dns 都在 OpenRC default runlevel 里时才生成
  （`mr apply` 先启用服务再加载防火墙）。原因：回滚（确认超时、“立即回滚”、`mr rollback`）只恢复配置文件，不会重新启用
  被那次 apply 停掉的服务；如果这时照样加载规则，所有被代理设备的 DNS 都会被重定向到一个没运行的 dnsmasq（重启后也一样）。
  现在这种情况下代理只是暂时等于关闭（DNS 走主 dnsmasq、流量直连），下一次 `mr apply` 会重新启用服务并恢复规则。
  sing-box 崩溃（服务仍启用）时照旧 fail closed。
- **rp_filter**：系统开了严格 rp_filter + `src_valid_mark`。IPv4 的 `ip rule` 按网桥写（`iif br-lan fwmark … lookup 300`）：
  反向路径检查查的是 iif lo 的反向流，不会命中这条规则，按正常路由表检查源地址——所以挂在 LAN 侧路由器后面
  （static_routes 指向 LAN 主机）的设备也能正常走代理。CI 端到端测试就是在这种设置下跑的（含这种设备）。
- **优先级**：`proxy_pre` 在 net 模块的策略路由标记链（mangle+1）之后，标记会覆盖策略路由标记（代理流量本来就要进本机）；
  ip rule pref 5200 在 tailscale（5210–5270）和 mr 的 WAN 规则（5290/5300）之前。标记位 0x1000000 与 WAN 标记
  （0x100–0x2ff）和 tailscale（0xff0000）都不冲突；代理开启时，`mr validate` 拒绝带这一位的 `policy_routes[].mark`
  （否则该设备的包会被当成代理流量送进本机）。
- **路由器自身的流量不走代理**（prerouting 看不到本机发出的包）。sing-box 连代理服务器走主路由表（主 WAN）。

## 安全

- sing-box 的 tproxy、DNS、clash API 端口只监听 127.0.0.1 / ::1，LAN 和 WAN 都访问不到；clash API 每次启动生成
  随机 secret（`/run/mr-proxy/api.json`，0600），只有 `mr api` 读取；浏览器永远不直接访问 sing-box。
- 镜像里有 `sing-box` 用户时，sing-box 以该用户运行，只保留 `CAP_NET_ADMIN`（IP_TRANSPARENT 需要）。
- `sing-box.json` 含节点凭据，权限 0600；UUID / 密码 / 混淆密码 / 自定义 JSON / 订阅链接只在 `secrets.yaml`，
  Web UI 只能设置不能读取。
- 校验是边界：节点名 / 组名 / 规则名、域名（`[a-z0-9_-]` 标签）、CIDR（禁止回环、链路本地、组播、与 LAN 重叠）、
  MAC、端口、URL、间隔都在 `mr validate` 检查。节点按类型严格校验：每种类型只允许它用得到的键（写错类型的键直接报错），
  服务器 / SNI / Host 必须是 IP 或主机名，UUID 格式、REALITY 公钥（base64url 32 字节）和 short_id（偶数个十六进制，
  最多 16 位）、ALPN、路径、gRPC serviceName、端口跳跃范围、各种枚举（flow、VMess 加密、uTLS 指纹、拥塞控制…）
  都有白名单；SS 不提供 none 和老的流密码，2022 密钥检查长度。密钥的值也检查（不能含控制字符），报错从不回显密钥值；
  列表文件逐行检查，报错只给行号不回显内容。生成的 sing-box.json 全部用 JSON 编码写出。
- 分享链接解析：报错只给行号和原因，从不回显链接（链接里有密码）；`proxy.parse` / `proxy.fetch` 只把**用户自己提交的
  链接 / 订阅里**的凭据返回给已登录的浏览器（用来预览后存进 secrets.yaml），从不返回已保存的密钥；不写日志。
- 订阅下载：只接受 http(s) URL（无空格、引号、控制字符）；busybox wget 以参数数组调用（URL 在 `--` 之后，不经 shell），
  最多 2 MB、45 秒，进程组整体超时终止；返回内容只有解析成功的节点，错误信息里去掉 URL（订阅链接通常带令牌）。
  订阅链接默认不保存；“保存为订阅”时存进 secrets.yaml。
- Web UI 只能读写 `/etc/mini-router/proxy/<名字>.domains|.cidrs`（拒绝符号链接），不能借规则路径读写其它文件。
- 所有修改类 API（以及会发起网络请求的 `proxy.fetch`、`proxy.parse`）都要求 POST。

## router.yaml 参考

```yaml
proxy:
  enabled: true
  ipv4_only: false          # true: 代理域名不返回 AAAA，客户端只用 IPv4（默认 false：IPv4 + IPv6 都代理）
  log_level: warn           # error | warn（默认）| info | debug，日志进 syslog，标签 sing-box
  # 端口一般不用改（0/不写 = 默认）：tproxy_port 7893、dns_port 1053、api_port 9090 只在回环上；
  # lan_dns_port 1054 是被代理设备的 DNS（nft 透明重定向过来）
  nodes:
    - name: sg1                              # 字母数字 _ . -，最长 40；节点和组共用名字空间
      server: sg1.example.net                # IP 或域名（域名用主 dnsmasq 解析，永远是真实地址）
      port: 8388
      method: 2022-blake3-aes-128-gcm        # 推荐：2022-blake3-aes-128-gcm 或 aes-128-gcm（CPU 有 AES 指令）
      password_secret: proxy_sg1             # secrets.yaml 里的键；2022 方法要 base64 密钥（openssl rand -base64 16）
    - name: jp1
      server: 203.0.113.7
      port: 8389
      method: aes-128-gcm
      password_secret: proxy_jp1
      tcp_only: true                         # 服务器不支持 UDP 转发时打开（QUIC 会回落到 TCP）；除 anytls / http 外所有类型都有
      tfo: true                              # TCP Fast Open：建连省一个往返；服务器也要开（自建节点）；hysteria2 / tuic（QUIC）没有
    - name: hk-reality                       # VLESS + REALITY + Vision（Xray 常见搭配）
      type: vless
      server: 203.0.113.20
      port: 443
      uuid_secret: proxy_hk-reality_uuid
      flow: xtls-rprx-vision                 # 需要 tls + 传输层为 TCP
      tls: true
      sni: www.example.com                   # REALITY：被借用网站的域名
      fingerprint: chrome                    # uTLS；REALITY 不写时默认 chrome
      reality_public_key: LHrjuwEq6GjVwsi-cALKBZ7shC7yUshr_0MQBbg5qQA   # 填了就启用 REALITY
      reality_short_id: 6ba85179e30d4fc2     # 可空
    - {name: vless-ws, type: vless, server: vl.example.net, port: 443, uuid_secret: proxy_vless-ws_uuid, tls: true,
       sni: vl.example.net, alpn: [http/1.1], transport: ws, path: /vl, host: vl.example.net, early_data: 2048}
    - {name: vmess-grpc, type: vmess, server: vm.example.net, port: 443, uuid_secret: proxy_vmess-grpc_uuid,
       security: auto, tls: true, fingerprint: firefox, transport: grpc, service_name: vmgrpc, packet_encoding: xudp}
    - {name: trojan-hu, type: trojan, server: tr.example.net, port: 443, password_secret: proxy_trojan-hu_password,
       tls: true, transport: httpupgrade, path: /tr, host: tr.example.net}
    - {name: hy2, type: hysteria2, server: hy.example.net, port: 443, password_secret: proxy_hy2_password,
       up_mbps: 50, down_mbps: 200, obfs: salamander, obfs_password_secret: proxy_hy2_obfs, hop_ports: "20000-30000",
       sni: hy.example.net}
    - {name: tuic, type: tuic, server: tu.example.net, port: 443, uuid_secret: proxy_tuic_uuid, password_secret: proxy_tuic_password,
       congestion_control: bbr, udp_relay_mode: native, sni: tu.example.net, alpn: [h3]}
    - {name: anytls, type: anytls, server: at.example.net, port: 443, password_secret: proxy_anytls_password, sni: at.example.net}
    - {name: socks, type: socks, server: 203.0.113.30, port: 1080, username: me, password_secret: proxy_socks_password}
    - {name: https-proxy, type: http, server: hp.example.net, port: 443, username: me, password_secret: proxy_https-proxy_password, tls: true}
    - name: us-trojan                        # 任意 sing-box outbound（需固件里的 sing-box 支持该协议）
      type: custom
      json_secret: proxy_us_trojan           # secrets.yaml 里存 JSON 对象，例如 {"type":"shadowtls",...}；tag 由 mr 设置；
                                             # type wireguard 自动放进 sing-box 的 endpoints（1.14 没有 wireguard outbound）
  groups:
    - name: auto
      type: urltest                          # 自动：定时测延迟选最快，故障自动切换
      nodes: [sg1, jp1]
      url: https://www.gstatic.com/generate_204   # 可选
      interval: 3m                                # 可选
    - name: pick
      type: selector                         # 手动：在 Web UI “节点组 → 当前”切换，立即生效，重启后保持
      nodes: [jp1, sg1]
  rules:                                     # 从上到下，先匹配先生效
    - name: ai
      outbound: auto                         # 节点名或组名
      domains: [openai.com, chatgpt.com, claude.ai]   # 后缀匹配：含所有子域名；*.x / +.x / .x 等同 x
      domains_file: /etc/mini-router/proxy/ai.domains # 可选，每行一个，# 注释
    - name: telegram
      outbound: pick
      domains: [telegram.org, t.me]
      cidrs: [91.108.4.0/22, 149.154.160.0/20, "2001:67c:4e8::/48"]   # 也可写单个 IP
      cidr_file: /etc/mini-router/proxy/telegram.cidrs                # 可选
  bypass:                                    # 例外设备：永不代理，DNS 由主 dnsmasq 解析
    - {name: desktop, mac: "02:c3:06:d6:7f:8a"}
    - {name: kids, device: "group:kids"}      # 或设备清单（devices，dev.md）里的设备 / 分组：它的所有 MAC
  subscriptions:                             # 只给 Web UI 的“导入”用：获取 → 预览 → 添加；不会自动更新节点
    - {name: airport, url_secret: proxy_airport_sub}   # 订阅链接（含令牌）在 secrets.yaml
```

secrets.yaml（Web UI 生成的名字是 `proxy_<节点>_<字段>`，手写可以用任意 `[a-z0-9_-]` 名字）：

```yaml
proxy_sg1: "BASE64_16_BYTE_KEY=="
proxy_jp1: "password"
proxy_hk-reality_uuid: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
proxy_hy2_password: "..."
proxy_hy2_obfs: "..."
proxy_us_trojan: '{"type":"shadowtls","server":"st.example.net","server_port":443,"version":3,"password":"...","tls":{"enabled":true,"server_name":"st.example.net"}}'
proxy_airport_sub: "https://sub.example.net/api/v1/client/subscribe?token=..."
```

## 节点类型

| type | 必填 | 可选 | TLS |
|---|---|---|---|
| `shadowsocks`（默认，可不写） | server port method password_secret | tcp_only、tfo | — |
| `vless` | server port uuid_secret | flow（xtls-rprx-vision）、packet_encoding、传输层、tcp_only、tfo | 可选 `tls: true`；uTLS、REALITY |
| `vmess` | server port uuid_secret | security（auto / aes-128-gcm / chacha20-poly1305 / none / zero）、alter_id、packet_encoding、传输层、tcp_only、tfo | 可选；uTLS |
| `trojan` | server port password_secret | 传输层、tcp_only、tfo | 可选（几乎总是开）；uTLS、REALITY |
| `hysteria2` | server port password_secret | up_mbps / down_mbps（不填 = BBR）、obfs: salamander + obfs_password_secret、hop_ports、tcp_only | 总是开（QUIC，无 uTLS） |
| `tuic` | server port uuid_secret password_secret | congestion_control（cubic / new_reno / bbr）、udp_relay_mode（native / quic）、tcp_only | 总是开（QUIC，无 uTLS） |
| `anytls` | server port password_secret | tfo | 总是开；uTLS、REALITY |
| `socks` | server port | username、password_secret、tcp_only、tfo | —（SOCKS5 本身不加密） |
| `http` | server port | username、password_secret、tfo | 可选（HTTPS 代理）；uTLS |
| `custom` | json_secret | — | JSON 里自己写 |

- TLS 键：`tls`（开关）、`sni`（默认 = server）、`alpn`、`insecure`（跳过证书验证，不安全）、`fingerprint`（uTLS：chrome /
  firefox / edge / safari / ios / android / 360 / qq / random / randomized）、`reality_public_key` + `reality_short_id`。
- 传输层键（vless / vmess / trojan）：`transport: ws | grpc | http | httpupgrade`，`path`、`host`（ws / http / httpupgrade），
  `service_name`（grpc），`early_data`（ws 的 0-RTT 字节数，对应 Xray 链接 path 里的 `?ed=2048`）。
- `packet_encoding`：vless 默认 xudp，vmess 默认不封装；`none` 表示关闭。
- 类型用不到的键会被 `mr validate` 拒绝（例如给 vmess 写 `reality_public_key`、给 hysteria2 写 `fingerprint`）。

## 导入分享链接和订阅

- **分享链接**：`ss://`（SIP002 和旧的整段 base64）、`vless://`、`vmess://`（v2rayN 的 base64 JSON，以及 `vmess://uuid@host:port?…`）、
  `trojan://`、`hysteria2://` / `hy2://`（含端口跳跃 `:443,20000-30000` 和 `mport`）、`tuic://`、`anytls://`、
  `socks5://` / `socks://`（含 v2rayN 的 base64 用户名密码）、`http://` / `https://`。一行一个，也可以直接粘贴 base64 订阅内容。
- 链接里的名字（`#…`）变成节点名：只保留字母数字 `_ . -`，国旗 emoji 变成国家代码（`🇭🇰 香港 01` → `HK-01`），
  重名自动加 `-2`。预览表里可以改名、取消勾选；“覆盖同名节点”会替换同名节点（组和规则里的引用不变），否则改名添加。
- 每个节点先经过和 router.yaml 相同的校验，不合格的链接按行列出原因（例如 `ssr://`、Xray 的 VLESS encryption、
  xhttp / kcp 传输、SIP003 插件、TCP HTTP 伪装）；能用但有差异的给出提示（例如 gRPC multi 模式按 gun 模式、
  Xray 专有 uTLS 指纹换成 randomized、pinSHA256 忽略）。
- **订阅**：`proxy.fetch` 在路由器上用 busybox wget 下载（User-Agent `v2rayN/7.0`，服务商据此返回 base64 分享链接），
  最多 2 MB、45 秒；只支持 base64 或纯文本的分享链接列表（Clash / sing-box 配置文件不支持）。服务商返回
  `Subscription-Userinfo` 头时显示已用流量和到期日期。订阅不会自动更新节点：需要时再点“获取”，预览后勾选“覆盖同名节点”添加即可更新。

生成的文件：`/etc/mini-router/gen/sing-box.json`（服务 mr-proxy）、`/etc/mini-router/gen/proxy-dns.conf`
（服务 mr-proxy-dns），nftables 里的 `proxy_*` 集合和链，`network.sh` 里 table 300 的规则和路由。

## 怎么用

### Web 界面

1. **代理 → 代理节点**，两种加节点的方法：
   - **导入**（最常用）：点“导入链接 / 订阅”，把机场或自建服务器给的分享链接粘贴进去（一行一个，或整段 base64），
     点“解析链接”；或者把订阅链接填进“订阅链接”框点“获取订阅”（想以后一键更新就填个名称点“保存为订阅”）。
     在预览表里勾选要的节点、需要时改名，选“加入组”（例如 auto），点“添加选中的节点”。以后更新订阅：在“已保存的订阅”
     点“获取”，勾选“覆盖同名节点”再添加。
   - **手动**：点“+ 添加节点”，在下面的编辑框里先选**类型**（Shadowsocks / VLESS / VMess / Trojan / Hysteria2 / TUIC /
     AnyTLS / SOCKS5 / HTTP / 自定义 JSON），只会显示这个类型用得到的字段：服务器、端口、UUID 或密码，
     VLESS 的 flow、TLS（SNI、ALPN、uTLS 指纹、REALITY 公钥 / short_id）、传输层（WebSocket / gRPC / HTTP/2 / HTTPUpgrade
     的路径、Host、serviceName、0-RTT），Hysteria2 的带宽、混淆、端口跳跃，TUIC 的拥塞控制等。
   UUID、密码、订阅链接只写入 secrets.yaml，界面不会显示（输入框显示“已设置”）。表格里点“编辑”修改已有节点，
   点“测速”经 sing-box 测延迟（所有类型都可以）。
   有多个节点时点“+ 添加组”，类型选“自动（延迟最低）”，勾选成员。打开“启用”。
2. **代理 → 分流规则**：点“+ 添加规则”，选出口（节点或组），在“域名”里每行写一个域名（自动包含子域名），
   在“IP / CIDR”里写 IP 段。列表很长时在下面“列表文件”新建 `xxx.domains` / `xxx.cidrs`，编辑保存后在规则里选中它。
3. **代理 → 例外设备**：从下拉框选 desktop（来自 DHCP 静态分配和租约），它就不会被代理、DNS 也是真实结果。
4. 点底部 **“保存并应用”**：先校验、显示变更计划，应用后 120 秒内点“保留”，否则自动回滚。
5. **代理 → 代理状态**：看 sing-box 是否运行、实时速率、每个组当前用的节点和延迟、所有走代理的连接（来源设备、
   目标域名、出口链、命中规则）。**代理节点**页可以测速、手动切换 selector 组。

提示：设备上的浏览器如果开了“安全 DNS / DoH”，或 Android 把“私人 DNS”设成了指定服务器，它不经过路由器 DNS，
域名规则对它无效（IP 规则仍有效）；
建议在 **网络 → DNS** 打开“劫持 LAN DNS”，这样设备自己写死的 53 端口 DNS 也会被接管（代理开启时，被代理设备的
IPv4 和 IPv6 DNS 都会被接管；关闭“劫持”时只接管发给路由器自己的查询）。

### router.yaml / agent

```sh
vi /etc/mini-router/router.yaml          # 加上面的 proxy: 段；密码写到 secrets.yaml
vi /etc/mini-router/proxy/ai.domains     # 大列表放文件里
mr validate && mr plan
mr apply --confirm 120 && mr confirm     # Verify 会确认 sing-box fake-ip DNS 和 mr-proxy-dns 都在应答，否则自动回滚
mr proxy check                           # 随时自检：fake-ip DNS、代理 DNS、第一条规则的域名能拿到假地址
mr proxy status                          # 运行状态、各组当前节点和延迟、流量、代理连接（JSON，和 Web UI 看到的一样）
mr proxy delay [节点或组]                 # 经 sing-box 测延迟（不写名字 = 所有节点）
mr proxy select pick sg1                 # 手动组切换节点（运行时状态，重启后保持，不改 router.yaml）
mr proxy parse links.txt                 # 分享链接 / base64 订阅（文件或 stdin）→ 可以贴进 router.yaml 的节点行，
                                         # 以及要写进 secrets.yaml 的键名（值默认隐藏，加 --secrets 才打印）
mr proxy fetch airport                   # 下载已保存的订阅（或直接给 URL），输出同上，另带流量 / 到期信息
```

关掉代理：`proxy.enabled: false` 再 `mr apply`（节点和规则保留）。

## 运行依赖

- `/usr/bin/sing-box` 1.14.1（linux/arm64）。构建标签：`with_clash_api`（状态 / 测速 / 切换）、`with_quic`（Hysteria2、
  TUIC）、`with_utls`（uTLS 指纹、REALITY）、`with_wireguard` + `with_gvisor`（WireGuard 自定义节点）；只用 SS / VMess /
  Trojan / VLESS（无 REALITY）/ AnyTLS / SOCKS / HTTP 时只需 `with_clash_api`。缺标签时 `sing-box check`（mr-proxy
  启动前执行）报错，apply 自动回滚。
- 订阅下载：busybox `wget`（Alpine 自带），https 订阅还需要 `ssl_client` 和 CA 证书（`ca-certificates-bundle`）。
- 内核模块：`nft_tproxy`、`nft_socket`、`nf_tproxy_ipv4`、`nf_tproxy_ipv6`、`nf_socket_ipv4`、`nf_socket_ipv6`
  （mr-proxy 启动前 modprobe），以及 DNS 重定向用的 `nft_redir`（nft 加载规则时自动加载）。
- dnsmasq（已有）、`dnsmasq` 用户（Alpine dnsmasq 包自带）。
- 可选：系统用户 `sing-box`（无 shell、无 home），有它时 sing-box 以非 root + `CAP_NET_ADMIN` 运行。
- 持久化：`/etc/mini-router/state/proxy-fakeip.db`（fake-ip 映射和 selector 选择；如果以后用 git 管理数据卷，把 `state/` 排除掉）。

## 已知限制

- 访客区（zone: guest）网络不代理；路由器自己的流量不代理。
- 代理流量从主路由表出去（主 WAN），不跟随按设备的策略路由。
- ping（ICMP）fake-ip 地址不会有回应；应用层连接正常。
- 关闭代理后，`ip rule pref 5200` 会留到下次重启（没有包带这个标记，不影响任何流量）。
- 开机时 mr-proxy-dns 起来之前的几秒，被代理设备的 DNS 查询会失败（重试即可）。
- fake-ip 映射只在服务正常停止（apply 重启、关机）时存到闪存。突然断电后，上次保存之后分配的假地址会丢失：
  设备缓存里的这些假地址连不上，直到它的 DNS 缓存过期（mr-proxy-dns 沿用 `min_cache_ttl`，最长约 1 小时）。
- `dns.servers_file`（自定义 servers 文件）里的域名如果也在代理规则里，mr-proxy-dns 不会去掉它（只处理 `dns.split`），
  dnsmasq 会混用两个上游；这种域名请只放在一边。
- sing-box 不支持、因此导入会拒绝的：ShadowsocksR、SS 的 SIP003 插件（obfs-local / v2ray-plugin）、Xray 的 VLESS
  encryption、xhttp / splithttp / mKCP / QUIC 传输、TCP 的 HTTP 伪装头、`xtls-rprx-vision-udp443` 以外的旧 flow
  （udp443 变体按 vision 导入）。需要时可以用自定义 JSON 节点写 sing-box 支持的等价配置。
- 节点 UUID 必须是标准 UUID 格式（Xray 允许的任意字符串 id 不接受）。
- 订阅只支持 base64 / 纯文本分享链接列表，不自动定时更新（没有常驻进程）；删除已保存的订阅后，它的链接仍留在
  secrets.yaml 里（界面无法删除密钥，不再被引用，无害；需要时手动删）。删除节点同理。
- https 订阅的证书校验由 Alpine 的 `ssl_client` 完成；如果固件里的 busybox wget 不校验证书，中间人可以篡改订阅内容
  （导入前有预览，节点也只在点“添加”后才生效）。
- Hysteria2 / TUIC 不能用 uTLS 指纹（QUIC 没有 uTLS）；SOCKS5 节点不加密，只适合可信线路。

## 测试

- `mr/mod_proxy_test.go`：渲染（sing-box.json、proxy-dns.conf、nft、network.sh）、校验（注入、冲突、非法值）、
  列表文件错误、CIDR 合并、DNS 报文解析、JSON 往返。
- `mr/mod_proxy_node_test.go`：每种节点类型渲染成的 sing-box outbound 与期望 JSON 逐字段比对（含 WireGuard endpoint）；
  每种类型的校验错误（错类型的键、枚举、REALITY、传输层、注入字符、密钥值不回显）；订阅配置；密钥命名。
- `mr/mod_proxy_link_test.go`：真实格式的分享链接（假凭据）逐个解析比对（SIP002 / 2022 / 旧 ss、REALITY、ws + 0-RTT、
  gRPC、v2rayN vmess JSON、trojan、hy2 端口跳跃、tuic、anytls、socks、http）、base64 订阅、每种拒绝原因（报错不含凭据）、
  解析出的节点全部通过 router.yaml 校验并能渲染；`proxy.parse` API；`proxy.fetch` 用假 wget 检查参数数组、大小上限、
  流量头、错误里不含 URL 令牌。
- `mr/mod_proxy_ui_test.go`：在 node 里用极简 DOM 运行真实的 `ui/core.js` + `ui/proxy.js`，点完整个流程（导入链接加入组、
  新建节点换类型、VLESS 改成 VMess 并改名、关混淆、保存订阅、自定义节点、逐个打开每种类型的编辑框），
  再把界面提交的配置和密钥交给 Go 校验和渲染（node 不在时跳过）。
- `examples/lab.d/55-proxy.yaml`：所有功能打开，每种协议至少一个节点（外加 WireGuard 自定义节点和一个订阅），CI 渲染后用
  真实 nft / dnsmasq / `sing-box check` 检查。
- `tools/ci.d/proxy.sh` 端到端（network namespace）：真实 nftables 规则 + 严格 rp_filter，客户端拿到 fake-ip
  （IPv4 + IPv6），TCP（fake-ip v4/v6、CIDR）和 UDP（CIDR）都经本地 Shadowsocks 服务器出去；desktop 的 MAC
  拿到真实 DNS 并直连；开启 DNS 劫持时发往代理网段的 DNS 也被接管；LAN 侧静态路由后面的设备也能走代理；
  对端在代理 CIDR 里的端口转发连接不受影响（回包不被截走）；`mr proxy check/status/select/delay` 对真实
  sing-box 跑通；**每个节点**（SS、VLESS REALITY + Vision、VLESS ws + TLS + 0-RTT、VMess gRPC + TLS + uTLS、VMess ws、
  Trojan HTTPUpgrade / HTTP/2、Hysteria2 + salamander、Hysteria2 insecure、TUIC、AnyTLS、SOCKS5、HTTPS 代理、自定义 Trojan）
  由 selector 切过去后，TCP 和 UDP（节点支持时）都经对应的 sing-box 服务器出去——服务器配置由渲染出的 outbound 反推
  生成，TLS 用测试 CA 做真实证书校验，REALITY 借一个本地 TLS 1.3 站点握手；`mr proxy fetch` 用 busybox wget 下载保存的
  订阅（节点、坏链接报错、流量头、默认隐藏凭据）；sing-box 停掉后代理目标被丢弃而不是直连。
  默认用 `/opt/sing-box/1.14.1/sing-box`（官方完整版）；`SING_BOX=/路径/sing-box tools/ci.sh` 可换成路由器同款构建
  （缺协议标签时对应节点的检查会失败）。
