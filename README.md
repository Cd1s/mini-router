# mini-router

基于 Alpine Linux 的极简路由器系统：**一个 YAML 配置文件 + 一个静态程序 `mr` + 专业的 Web 管理界面**。
面向家庭 / 家庭服务器主路由：安全优先、性能优先（硬件加速保持生效）、不堆没用的功能。

A minimal router OS on Alpine Linux: one YAML file (`router.yaml`), one static binary (`mr`, ~5 MB, any
architecture) and a professional web UI. Every change is validated, snapshotted, verified and rolled back
automatically if something breaks.

## 功能 / Features

| 模块 | 内容 |
|---|---|
| 网络 net | LAN 网桥、访客 / IoT 网络、VLAN；WAN：PPPoE / DHCP / 静态，多拨，**多线故障切换 / 负载均衡**；策略路由（按设备 / 源 / 目的走指定线路）、静态路由、组播（IGMP snooping / proxy）；双线 IPv6（PD + 源地址路由） |
| 无线 wifi | 多 SSID、访客 SSID、客户端隔离、MAC 黑白名单、WPA2/WPA3、终端列表与踢人、信道分析；AX6000 调优档 + 任意网卡的通用档 |
| DNS / DHCP | dnsmasq：DHCP 静态分配与选项、IPv6 RA / DHCPv6、本地记录（A/AAAA/CNAME/SRV…）、DNS 分流、DoT（stubby）、统计 |
| 防火墙 fw | nftables：区域、端口转发（来源限制 / 线路选择 / NAT 回流）、IPv6 入站（按接口标识，前缀变化也有效）、通信规则（含时间段）、设备上网管控、硬件 / 软件流量卸载 |
| 代理 proxy | sing-box 选择性透明代理：fake-ip + nftables tproxy，只有命中规则的域名 / IP 进代理，其余流量照常硬件加速；SS / VLESS(Reality) / VMess / Trojan / Hysteria2 / TUIC / AnyTLS…，分享链接与订阅导入，例外设备 |
| 监控 mon | 实时流量 / CPU / 内存图、24 小时历史、每设备流量、连接表、进程与内核日志 |
| 系统 sys | 时区 / NTP、SSH 与密钥、计划任务、备份恢复、固件升级、服务管理、日志、诊断（ping / traceroute / nslookup） |

每次修改：校验 → 显示变更计划 → 快照 → 应用 → 自检 → 需要时在倒计时内确认，否则**自动回滚**。

## 安装 / Install

### 1. 任意架构的 Alpine Linux（x86_64 / arm64 / armv7 / armv6 / x86 / riscv64 / ppc64le）

适合 x86 小主机、虚拟机、树莓派、各种 ARM 板。先装好 Alpine（至少两个网口，或一个网口 + 无线网卡），然后：

```sh
wget -O install.sh https://raw.githubusercontent.com/Cd1s/mini-router/main/install.sh
sh install.sh
```

脚本会问：WAN 网口与类型（DHCP / PPPoE / 静态）、LAN 网口、路由器 IP、WiFi 名称和密码、网页管理员密码、时区，
然后自动安装软件包、下载对应架构的 `mr`、生成配置并应用。完成后打开 `http://路由器IP/`。

无人值守（所有问题用环境变量回答）：

```sh
MR_YES=1 MR_WAN=eth0 MR_WAN_PROTO=pppoe MR_PPPOE_USER=xxx MR_PPPOE_PASS=xxx \
MR_LAN_PORTS="eth1 eth2" MR_LAN_IP=192.168.1.1/24 MR_ADMIN_PASS=change-me-123 sh install.sh
```

其它变量见 `install.sh` 开头；`MR_APPLY=0` 只安装和写配置，不立即应用。

### 2. 路由器固件镜像（Redmi AX6000）

内核（OpenWrt 6.18 + 开源 mt76 + WED/PPE 硬件加速）+ squashfs 系统 + UBIFS 配置分区。先用 kexec 在内存里试运行，
再写入闪存，全程可回滚到原系统。步骤见 [docs/flash.md](docs/flash.md)，构建见 [docs/modules/platform.md](docs/modules/platform.md)。
其它路由器型号需要各自的内核与设备树，欢迎贡献。

### 3. 从源码构建

```sh
./tools/release.sh v0.1.0 out/release   # 需要 Go；产出 7 个架构的 mr + 系统文件包 + install.sh
MR_LOCAL=out/release sh install.sh      # 在目标机器上离线安装
```

## 使用 / Usage

```sh
vi /etc/mini-router/router.yaml   # 或者在网页里改
mr plan                          # 看会改什么
mr apply --confirm 120           # 应用；120 秒内不执行 mr confirm 就自动回滚
mr confirm
mr status | mr history | mr rollback [快照]
mr passwd < 密码文件              # 重设网页管理员密码
```

各模块的配置项和“怎么用”：[docs/modules/](docs/modules/)。示例配置：[examples/](examples/)。

## 开发 / Development

- 架构与模块约定：[docs/MODULES.md](docs/MODULES.md)。每个功能是一个模块（Go 文件 + 网页页面），通过固定的钩子接入配置渲染、nftables、服务管理和 API。
- 检查：`sudo ./tools/ci.sh`（Linux）——gofmt、vet、单元测试、交叉编译、shellcheck，把真实家庭配置和“全功能”实验配置渲染后装进网络命名空间里的真实 `nft` / `dnsmasq`，并跑防火墙、多线、代理的端到端测试。GitHub Actions 每次推送自动运行。
- 网页界面本地调试：`python3 tools/mock/mockapi.py 8088` → http://127.0.0.1:8088/

## 状态 / Status

早期版本。在 Redmi AX6000 上作为家庭主路由长期运行（双 PPPoE、双线 IPv6、硬件加速、WiFi 6 160 MHz）。
其它硬件通过 `install.sh` 支持，欢迎反馈。

## License

MIT
