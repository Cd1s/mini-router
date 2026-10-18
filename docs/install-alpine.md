# 在 Alpine Linux 上安装 / Installing on Alpine Linux

适合 x86 小主机、虚拟机、树莓派和各种 ARM 板。Redmi AX6000 用固件镜像，见 [flash.md](flash.md)。

*English summary at the end.*

## 1. 装好 Alpine

1. 下载 Alpine（<https://alpinelinux.org/downloads/>）：
   - x86 小主机 / 虚拟机：**Standard** 或 **Extended**（x86_64）；
   - 树莓派：**Raspberry Pi** 镜像（aarch64）。
2. 从 U 盘 / SD 卡启动，root 登录（无密码），运行 `setup-alpine`：
   - 键盘、主机名随意；网络先选一个能上网的口用 DHCP（装完 mini-router 会接管网口）；
   - 时区、镜像源按提示；SSH 选 `openssh` 或 `dropbear` 都行（OpenSSH 由 Alpine 自己管理，`mr` 只管理 dropbear）；
   - **磁盘选 `sys`**（装到硬盘 / SD 卡）。`diskless` / `data` 模式下 `/etc` 的改动要 `lbu commit` 才能保存，
     mini-router 每次改配置都写 `/etc/mini-router`，不推荐。
3. 重启，确认能上网：`ping -c3 alpinelinux.org`。

mini-router v0.4.0 需要 `ethtool`（用来读取网卡永久 MAC，换 WAN / 多拨时恢复硬件地址）。安装脚本会自动安装它；
如果是从旧版本手工升级，先执行：

```sh
apk add ethtool
```

Mini-Router v0.4.0 requires `ethtool` to read the permanent NIC address. The installer adds it automatically; install it
manually before upgrading an older Alpine installation.

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

先用 `MR_APPLY=0` 安装会只写配置和首次设置标记，不停用 Alpine 网络、不重配网卡；
在控制台编辑 `/etc/mini-router/router.yaml` 后，运行 `mr plan` / `mr apply --confirm 120`
完成接管。这样可以先审核配置，再在正常确认/回滚窗口内切换网络。

## 4. 安装

```sh
wget -O install.sh https://github.com/Cd1s/mini-router/releases/download/v0.4.0/install.sh
MR_VERSION=v0.4.0 sh install.sh
```

问题依次是：工作模式（router / bypass / ap）、网口、WAN 类型（DHCP / PPPoE / 静态）、地址、WiFi、网页管理员密码、时区。
只发现一个网口时，工作模式默认建议 `bypass`。脚本会安装软件包、下载对应架构的 `mr`、生成配置并应用。应用前它停用 Alpine
自己的网络服务（`networking`、`dhcpcd`），把 `/etc/network/interfaces` 改名为 `interfaces.before-mini-router`；`mr apply`
失败时撤销 mr 自己的更改，但不会重新启用那两个服务 —— 需要回到原来的网络设置时按下面的卸载步骤做。
无人值守和离线安装的变量见 `install.sh` 开头。

PPPoE 需要内核的 `pppoe` 模块。Alpine 云镜像和不少虚拟机用的 `linux-virt` 内核没有它：选 PPPoE 时 `install.sh` 会先检查，
不行就停下并提示 `apk add linux-lts && reboot`（`mr doctor` 和 `mr-pppoe` 的日志也会写明原因）。

## 5. 验证

```sh
mr status | head -30      # WAN 地址、服务状态
mr doctor                 # 体检：每项 ok / warn / risk，附修复方法
```

浏览器打开 `http://<LAN 地址>/`，用安装时设的密码登录。“状态 → 体检与事件”里没有红色项就可以了。

### 首次设置向导 / First-run setup wizard

`MR_APPLY=0` 的安装会在 `/etc/mini-router/state/first-run` 写入一次性标记；
已经询问 WAN、密码并完成 apply 的 `MR_APPLY=1` 安装不会写入标记。AX6000 v0.4.0 出厂镜像和新建、擦除后的
`rootfs_data` 由 `mr-preinit` 创建同一标记。因此，AX6000 刷机后或 Alpine 使用 `MR_APPLY=0` 安装后，
第一次打开面板会进入向导；旧用户升级不会弹出向导。

`MR_APPLY=0` writes a one-time marker at `/etc/mini-router/state/first-run`; an install that already asked for the
WAN, password and completed apply does not. The v0.4.0 AX6000 factory image and a new or erased `rootfs_data` get
the same marker from `mr-preinit`. Thus the first panel visit after flashing AX6000, or after an Alpine `MR_APPLY=0`
install, opens the wizard; an upgrade of an existing installation does not.

向导步骤是管理员密码（出厂机）、时区、WAN 自动探测、上游 / LAN 网段冲突检查、WiFi 和变更预览。WAN 步骤中的
“检测上网方式”调用 `mr wan detect <物理网口>`：独立做 PPPoE discovery 和一次性 DHCP DISCOVER，只等待结果，
不拿租约、不写路由。所有修改仍走 validate → plan → apply → confirm；应用失败自动回滚。向导只提示 LAN 冲突，
不会自动修改 LAN 地址。应用确认后标记删除；旧 overlay 不会在升级时重新创建标记。

The wizard covers the administrator password (factory image), time zone, WAN detection, upstream/LAN conflict check,
WiFi and a change preview. “检测上网方式” / “Detect connection type” runs `mr wan detect <physical-port>` with
stateless PPPoE discovery and DHCP DISCOVER: it waits for an answer but takes no lease and installs no route. Changes
use the normal validate → plan → apply → confirm flow and roll back on failure. The wizard suggests a LAN range when it
detects a conflict but never changes it automatically. Confirming the apply removes the marker.

### v0.4.0 升级 / Upgrade to v0.4.0

不要重新运行完整 `install.sh` 来升级，它会重新生成 `router.yaml`。下载与当前架构匹配的 v0.4.0 `mr-linux-*`，
覆盖 `/usr/sbin/mr`，再把 `mini-router-rootfs.tar.gz` 解到 `/`（相当于安装脚本第 2 步）：

```sh
apk add ethtool
install -m 0755 mr-linux-<架构> /usr/sbin/mr
tar -xzf mini-router-rootfs.tar.gz -C /
mr plan
mr apply --confirm 120
```

升级前先读 `mr plan`。首次 apply 会重载防火墙、重启 `mr-panel` 并原地重跑 `network.sh`；面板监听所有地址，
但防火墙只允许 LAN 网桥和 Tailscale，WAN 仍被拒绝。旧安装不会因此进入首次设置向导。

Do not rerun the complete installer: it would regenerate `router.yaml`. Install `ethtool`, replace `/usr/sbin/mr`
with the v0.4.0 binary for the current architecture, unpack `mini-router-rootfs.tar.gz` over `/`, then inspect
`mr plan` and run `mr apply --confirm 120`. The first apply reloads the firewall, restarts `mr-panel` and reruns
`network.sh`; the panel binds all addresses while the firewall still permits only LAN bridges and Tailscale. Existing
installations do not enter the wizard.

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
4. For v0.4.0, download `https://github.com/Cd1s/mini-router/releases/download/v0.4.0/install.sh` and run it with
   `MR_VERSION=v0.4.0`; the installer installs `ethtool`.
5. After an AX6000 v0.4.0 flash or an Alpine `MR_APPLY=0` install, the first panel visit opens the wizard, including
   “Detect connection type” (`mr wan detect`). Existing upgrades do not show it.
6. Check with `mr status`, `mr doctor` and the web UI (`http://<LAN address>/`).
7. Every change rolls back unless confirmed; `mr history` / `mr rollback N`. The installer disables Alpine's `networking` /
   `dhcpcd` services and renames `/etc/network/interfaces` before the first apply; the uninstall steps above restore them.
