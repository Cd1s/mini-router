# 在 Alpine Linux 上安装 / Installing on Alpine Linux

适合 x86 小主机、虚拟机、树莓派和各种 ARM 板。Redmi AX6000 用固件镜像，见 [flash.md](flash.md)。

*English summary at the end.*

## 1. 装好 Alpine

1. 下载 Alpine（<https://alpinelinux.org/downloads/>）：
   - x86 小主机 / 虚拟机：**Standard** 或 **Extended**（x86_64）；
   - 树莓派：**Raspberry Pi** 镜像（aarch64）。
2. 从 U 盘 / SD 卡启动，root 登录（无密码），运行 `setup-alpine`：
   - 键盘、主机名随意；网络先选一个能上网的口用 DHCP（装完 mini-router 会接管网口）；
   - 时区、镜像源按提示；SSH 选 `openssh` 或 `dropbear` 都行；
   - **磁盘选 `sys`**（装到硬盘 / SD 卡）。`diskless` / `data` 模式下 `/etc` 的改动要 `lbu commit` 才能保存，
     mini-router 每次改配置都写 `/etc/mini-router`，不推荐。
3. 重启，确认能上网：`ping -c3 alpinelinux.org`。

## 2. 认出网口

```sh
ip -br link                          # 所有网口：eth0 / enp1s0 / end0 …
cat /sys/class/net/*/carrier         # 1 = 插着线
```

拔插网线再看 `carrier`（或 `ip -br link` 里的 `UP` / `LOWER_UP`），就知道哪个名字是哪个口。USB 网卡通常叫 `eth1` / `enx…`。

要做**主路由**需要两个口：一个接光猫 / 上级路由（WAN），其余接家里的设备（LAN）；或者一个网口 + 一块无线网卡（无线做 LAN）。

## 3. 只有一个网口

两种做法：

**A. 旁路由（推荐）**：接在现有路由器下面，只负责 DNS 和代理，一个口就够。安装时“工作模式”选 `bypass`，
本机地址和主路由地址默认沿用现在的（通过 SSH 安装不会断线）。之后按网页“网络 → LAN 与网络 → 工作模式”卡片的提示，
在主路由上把 DHCP 下发的 DNS 改成本机，并添加列出的静态路由。细节：[modules/net.md](modules/net.md) 的 “mode”。

**B. VLAN 单臂路由**：需要一台支持 VLAN 的交换机（光猫的线进交换机的一个口，打上 VLAN 10，和 mini-router 的口之间用 trunk）。
WAN 走带标签的 VLAN，LAN 走不带标签的同一个口：

```yaml
lan: {bridge: br-lan, ports: [eth0], ipv4: 192.168.1.1/24, ipv6_ra: true}
wan:
  - {name: wan, device: eth0, vlan: 10, proto: pppoe, username: "…", password_secret: pppoe_password, metric: 10}
```

先用 `MR_APPLY=0` 安装（只写配置不应用），按上面改好 `/etc/mini-router/router.yaml`，再 `mr plan` / `mr apply --confirm 120`。

## 4. 安装

```sh
wget -O install.sh https://github.com/Cd1s/mini-router/releases/latest/download/install.sh
sh install.sh
```

问题依次是：工作模式（router / bypass / ap）、网口、WAN 类型（DHCP / PPPoE / 静态）、地址、WiFi、网页管理员密码、时区。
只发现一个网口时，工作模式默认建议 `bypass`。脚本会安装软件包、下载对应架构的 `mr`、生成配置并应用。应用前它停用 Alpine
自己的网络服务（`networking`、`dhcpcd`），把 `/etc/network/interfaces` 改名为 `interfaces.before-mini-router`；`mr apply`
失败时撤销 mr 自己的更改，但不会重新启用那两个服务 —— 需要回到原来的网络设置时按下面的卸载步骤做。
无人值守和离线安装的变量见 `install.sh` 开头。

## 5. 验证

```sh
mr status | head -30      # WAN 地址、服务状态
mr doctor                 # 体检：每项 ok / warn / risk，附修复方法
```

浏览器打开 `http://<LAN 地址>/`，用安装时设的密码登录。“状态 → 体检与事件”里没有红色项就可以了。

## 6. 出问题怎么办

- **改配置后断网**：`mr apply --confirm 120` 应用的更改，120 秒内不 `mr confirm` 就自动回滚；网页上同理（“保留”按钮）。
- **回到以前的配置**：`mr history` 列出每次变更，`mr rollback <编号>` 恢复（本身也是一次需要确认的变更）。
- **卸载**：
  ```sh
  for s in $(ls /etc/init.d | grep '^mr-'); do rc-service "$s" stop; for rl in boot default; do rc-update del "$s" "$rl"; done; done 2>/dev/null
  rm -f /usr/sbin/mr; rm -rf /etc/mini-router /usr/libexec/mr /www /etc/init.d/mr-*
  mv /etc/network/interfaces.before-mini-router /etc/network/interfaces   # 恢复 Alpine 自己的网络配置
  rc-update add networking boot
  reboot
  ```
  安装前的 `/etc/mini-router/router.yaml` 如果存在，被保存为 `router.yaml.before-install`。

---

## English summary

1. Install Alpine (Standard / Extended for x86_64, the Raspberry Pi image for aarch64) with `setup-alpine`, **disk mode
   `sys`** (diskless / data modes need `lbu commit` for every change under `/etc`).
2. Identify ports with `ip -br link` and `/sys/class/net/*/carrier` (unplug / replug a cable). A main router needs two ports
   (WAN + LAN) or one port + a WiFi card.
3. One port only: run it as a **side router** (`mode: bypass`, recommended; the installer keeps the current address and
   gateway), or as a **one-armed router** with a VLAN-capable switch (`wan: [{device: eth0, vlan: 10, …}]`, LAN untagged on
   the same port; install with `MR_APPLY=0`, edit router.yaml, then `mr plan` / `mr apply --confirm 120`).
4. `wget -O install.sh https://github.com/Cd1s/mini-router/releases/latest/download/install.sh && sh install.sh`.
5. Check with `mr status`, `mr doctor` and the web UI (`http://<LAN address>/`).
6. Every change rolls back unless confirmed; `mr history` / `mr rollback N`. The installer disables Alpine's `networking` /
   `dhcpcd` services and renames `/etc/network/interfaces` before the first apply; the uninstall steps above restore them.
