<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/logo-dark.svg">
    <img src="docs/assets/logo.svg" alt="Mini-Router" width="330">
  </picture>
</p>

<p align="center">
  <b>一个 YAML、一个程序、一个网页——基于 Alpine Linux 的极简路由器系统</b><br>
  <sub>A minimal, declarative router OS on Alpine Linux: one YAML file, one static binary, one web UI.</sub>
</p>

<p align="center">
  <a href="https://github.com/Cd1s/mini-router/actions/workflows/ci.yml"><img src="https://github.com/Cd1s/mini-router/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/Cd1s/mini-router/releases/latest"><img src="https://img.shields.io/github/v/release/Cd1s/mini-router?sort=semver&color=2f6fed" alt="release"></a>
  <img src="https://img.shields.io/badge/arch-amd64%20%C2%B7%20arm64%20%C2%B7%20armv7%20%C2%B7%20armv6%20%C2%B7%20x86%20%C2%B7%20riscv64%20%C2%B7%20ppc64le-16a2b8" alt="architectures">
  <a href="LICENSE"><img src="https://img.shields.io/github/license/Cd1s/mini-router?color=informational" alt="MIT"></a>
</p>

<p align="center">
  <a href="#安装--install">安装</a> ·
  <a href="#功能--features">功能</a> ·
  <a href="#使用--usage">使用</a> ·
  <a href="#ai-agent">AI agent</a> ·
  <a href="#开发--development">开发</a> ·
  <a href="https://github.com/Cd1s/mini-router/releases/latest">下载</a>
</p>

<p align="center"><img src="docs/assets/shot-overview.png" alt="Mini-Router 总览" width="920"></p>

整台路由器就是一个 `router.yaml`。`mr`（静态 Go 程序，不常驻）负责校验、生成所有配置、应用并自检，出问题**自动回滚**。
网页、命令行和 AI agent 走的是同一条路。

## 亮点 / Highlights

- 🛡️ **改不坏**：每次改动先预览、分级；倒计时内不确认就自动回滚，断电也会回滚；完整历史，随时退回。
- ⚡ **快**：普通流量始终走硬件加速（MT7986 PPE + WED），分流、按域名选线路都不影响卸载。
- 🪶 **小**：没有空转的守护进程；DDNS、证书、体检都是按需运行的短命令。
- 🧩 **全**：多线、IPv6、选择性代理、反向代理、去广告、设备管理，一个网页里全部可配。
- 🤖 **为 agent 设计**：配置即代码，命令输出 JSON，作用域 API token，自带 agent skill。

## 截图 / Screenshots

| 手机端 | 选择性代理 | 实时监控（深色） |
|:---:|:---:|:---:|
| <img src="docs/assets/shot-mobile.png" alt="手机端" height="200"> | <img src="docs/assets/shot-proxy.png" alt="代理" height="200"> | <img src="docs/assets/shot-monitor.png" alt="监控" height="200"> |

<sub>截图均为演示数据。</sub>

## 功能 / Features

| 模块 | 功能 |
|---|---|
| **网络** | PPPoE（1500 MTU）/ DHCP / 静态，多线故障切换与负载均衡；策略路由（按设备 / 网段 / **域名**）；双线 IPv6，运营商换前缀自动恢复；访客 / IoT 网络、VLAN；**主路由 / 旁路由 / 纯 AP** 三种模式 |
| **WiFi** | 多 SSID、WPA2/3、访客隔离；组播转单播、802.11v 频段引导、射频健康与自愈；定时开关 |
| **DNS / DHCP** | 静态分配、本地记录、DNS 分流、DoT；**去广告**；DNS 主导权（拦截设备私自 DoH / DoT） |
| **防火墙** | 端口转发、IPv6 入站、通信规则（含时间段）、硬件 / 软件卸载；默认拒绝公网入站 |
| **代理** | sing-box 选择性透明代理（fake-ip + tproxy），全协议节点、订阅、节点组；**按设备全局代理**（IPv4 + IPv6） |
| **设备** | 设备清单与分组、暂停上网、上下线通知；按设备**限速**、**月流量**、**家长控制**；在家 / 离家规则 |
| **服务** | **DDNS**（Cloudflare / 阿里云 / DNSPod / DuckDNS / dyndns2 / webhook）；**HTTPS 反向代理 + 自动证书**；网络唤醒；Tailscale 出口节点 |
| **运维** | `mr doctor` 体检与**一键修复**、事件与通知；**异地备份**（WebDAV / S3 / GitHub）；升级前检查、更新提示；watchcat；测速 |
| **安全变更** | 语义 diff、变更历史、风险分级、底线规则（guard）；作用域 API token、`mr get / set`、`mr schema` |
| **界面** | 中文 / English，手机可用，浅色 / 深色，原文编辑 router.yaml，全局搜索，实时监控与 24 小时历史 |

不做（与极简冲突）：UPnP、SQM、fullcone NAT、WireGuard 服务端（sing-box 已支持 WireGuard 节点）、应用识别 / DPI。

## 安装 / Install

**任意架构的 Alpine Linux**（x86 小主机、虚拟机、树莓派、ARM 板）——装好 Alpine（磁盘模式 `sys`）后：

```sh
wget -O install.sh https://github.com/Cd1s/mini-router/releases/latest/download/install.sh && sh install.sh
```

按提示选模式、网口、WAN 类型和密码，完成后打开 `http://路由器IP/`。只有一个网口？选旁路由（`bypass`）。
详细步骤、单网口、无人值守和卸载：[docs/install-alpine.md](docs/install-alpine.md)。

**Redmi AX6000 固件**——OpenWrt 6.18 内核 + mt76 + WED/PPE 硬件加速，可先在内存里试运行再写入闪存，
之后在网页里升级，失败自动回到旧系统：[docs/flash.md](docs/flash.md)。

## 使用 / Usage

```sh
mr plan                    # 看会改什么（也可以直接在网页里改）
mr apply --confirm 120     # 应用；120 秒内不 mr confirm 就自动回滚
mr confirm
mr set 'wifi.steering.enabled=true'   # 按路径改配置，保留注释
mr doctor                  # 体检；--heal 一键修复
mr status · mr history · mr rollback N · mr ddns status · mr edge status     # JSON 输出
```

各模块配置：[docs/modules/](docs/modules/) · API：[docs/api.md](docs/api.md) · 示例：[examples/](examples/)

## AI agent

[`skills/mini-router`](skills/mini-router/SKILL.md) 是给 Claude Code、Codex 等 agent 的操作手册：安全改动流程、配置速查、诊断命令、禁止事项。

```sh
mkdir -p ~/.claude/skills && cp -r skills/mini-router ~/.claude/skills/
```

## 开发 / Development

- 模块约定：[docs/MODULES.md](docs/MODULES.md)——每个功能 = Go 文件 + 网页文件 + 文档 + CI 片段。
- `sudo ./tools/ci.sh`（Linux）：单元测试，用真实的 `nft` / `dnsmasq` / `hostapd` / `sing-box` 校验生成的配置，
  并在网络命名空间里跑防火墙、多线、代理、反向代理的端到端测试。
- 网页本地调试：`python3 tools/mock/mockapi.py 8088`
- 从源码构建：`./tools/release.sh v0.3.0 out/release`；AX6000 固件：`build/m3/`。

## License

[MIT](LICENSE)。AX6000 镜像包含 sing-box（GPL-3.0）、Linux 内核（GPL-2.0）等上游组件，各自遵循其许可证。
