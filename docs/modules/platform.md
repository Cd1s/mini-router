# platform — 内核、镜像、启动、升级

没有 `mr` Go 代码。负责：内核和内核模块、sing-box 构建、M3 镜像（squashfs + kexec 测试 initramfs +
sysupgrade 镜像）、`/sbin/mr-preinit`（overlay 根文件系统）、`sysupgrade` / `factory-reset`、配置下发
（`tools/provision.sh`）、刷机和回滚文档（[docs/flash.md](../flash.md)）。

| | |
|---|---|
| 构建脚本 | `build/m3/kernel.sh`、`sing-box.sh`、`build.sh`（→ `build-rootfs.sh` arm64 容器、`pack.sh`）、`fit-offsets.py`、出厂配置 `build/m3/router.yaml` |
| 自测 | `build/m3/selftest.sh`（nandsim 模拟 NAND，真实脚本；手动运行，不进 CI） |
| 镜像里的文件 | `rootfs/sbin/mr-preinit`、`rootfs/usr/libexec/mr/sysupgrade`、`factory-reset`、`rootfs/etc/fstab`、`rootfs/etc/modules` |
| 工具 | `tools/provision.sh`、`tools/kexec-test.sh`、`tools/ubi-restore.sh`、`tools/devmem.c` |
| CI | `tools/ci.d/platform.sh`（出厂配置 + 真实 nft/dnsmasq；sysupgrade -T 正反例；provision.sh；fit-offsets.py） |
| 构建机 | 一切都在 `build-host:/root/build/mini-router-platform/`，产物在 `out/`；原 OpenWrt 树 `/root/build/owrt-main/src` 只读（overlayfs 下层） |

## 内核（build/m3/kernel.sh）

OpenWrt main r36531-98f3808362，Linux 6.18.52，mediatek/filogic，DTS `mt7986a-xiaomi-redmi-router-ax6000-hanwckf`
——和闪存里正在运行的 OpenWrt 同一棵树、同一个 docker 镜像（`owrt-builder`，树挂在 `/w`）。原树只作
overlayfs 的只读下层，构建写到 `mini-router-platform/owrt-upper`，原树（包括 `bin/` 里刷机用的产物）不会被改。

**改动只有一处：选中 `kmod-nft-tproxy`、`kmod-nft-socket`**（自动带上 `kmod-nf-tproxy`、`kmod-nf-socket`）。
内核 `.config` 的全部差异（`out/kernel/kernel-config.diff`）：

```
+CONFIG_NFT_SOCKET=m      +CONFIG_NFT_TPROXY=m
+CONFIG_NF_SOCKET_IPV4=m  +CONFIG_NF_TPROXY_IPV4=m
+CONFIG_NF_SOCKET_IPV6=m  +CONFIG_NF_TPROXY_IPV6=m
```

vmlinux 里唯一的变化是这些选项导出的 `udp4_lib_lookup` / `udp6_lib_lookup`（System.map 对比）；`Image`
大小与闪存版相同。其余需求原来就有：`nft_log` + `nf_log_syslog`（kmod-nft-core / kmod-nf-log）、
`nft_redir`、`nft_numgen`、8021q（内置）、TCP BBR（`CONFIG_TCP_CONG_BBR=m`，`tcp_bbr.ko`，sysctl 选中时内核自动加载）。

产物（`out/kernel/`）：`Image` + `image-mt7986a-xiaomi-redmi-router-ax6000-hanwckf.dtb`（kexec 用）、
`kernel.itb`（闪存 `kernel` 卷的 FIT：OpenWrt 自己的 `*-kernel.bin`，lzma 内核 + DTB，和闪存版同一配方；
脚本核对它与 OpenWrt 同次构建的 sysupgrade.bin 里的 `kernel` 一致）、`kmods-fw.tar.gz`
（`/lib/modules/6.18.52` 全部 66 个模块 + MT7986/MT7976 固件，来自同一次构建的 OpenWrt rootfs）。

**没有加 BCJ ARM64**：这个内核没有 `CONFIG_XZ_DEC_ARM64`，squashfs 用了 `-Xbcj arm64` 就挂载不了。
实测它对本镜像能省约 4%（M2 树 37.1 → 35.7 MB）。要用的话在内核里加 `CONFIG_XZ_DEC_ARM64=y`（几百字节代码），
`pack.sh` 的 mksquashfs 加 `-Xbcj arm64`——超出"其它不改"的范围，留给集成者决定。

## sing-box（build/m3/sing-box.sh）

sing-box **1.14.1**，tag `v1.14.1` = `1ac1a339cb12…`（与官方二进制内嵌的 Revision 一致），按该 tag 的
`.github/workflows/build.yml` 构建：Go **1.26.8**（`GOTOOLCHAIN`，与官方相同）、`CGO_ENABLED=0`、`-trimpath`、
`-ldflags "-X …constant.Version=1.14.1 $(cat release/LDFLAGS) -s -w -buildid="`
（LDFLAGS = `-X runtime.godebugDefault=multipathtcp=0,tlssha1=1 -checklinkname=0`）。

- **可复现性核对**：用官方 linux-arm64 发布版的 tag 组合（`DEFAULT_BUILD_TAGS,with_purego`）再编一次，
  与官方 `sing-box-1.14.1-linux-arm64` **逐字节相同**——工具链和源码与上游完全一致。
- **路由器用的构建**：`release/DEFAULT_BUILD_TAGS_OTHERS`（官方 Makefile 默认、也是官方无 naive 平台的发布标签）：
  `with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme,with_clash_api,with_tailscale,with_ccm,with_ocm,with_cloudflared,with_usbip,with_openvpn,with_openconnect,badlinkname,tfogo_checklinkname0`。
  vless/reality/uTLS、vmess、trojan、shadowsocks、shadowtls、hysteria/hysteria2、tuic、anytls、wireguard、
  naive **入站**、ssh、socks/http 等全部在内。唯一缺的是 **naive 出站**：它要 cronet（官方用 cgo，或 purego +
  另附 glibc 的 `libcronet.so`），在 CGO_ENABLED=0 的 musl 系统上用不了。
- 大小：75,300,990 字节（xz -9e 约 16.2 MB）。`sing-box version`：

  ```
  sing-box version 1.14.1
  Environment: go1.26.8 linux/arm64
  Tags: with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme,with_clash_api,with_tailscale,with_ccm,with_ocm,with_cloudflared,with_usbip,with_openvpn,with_openconnect,badlinkname,tfogo_checklinkname0
  Revision: 1ac1a339cb1223e9c70eae14c44411c75033c02d
  CGO: disabled
  ```
- CI 用的官方 linux-amd64 1.14.1 在 `/opt/sing-box/1.14.1/sing-box`（脚本和官方 tar 包逐字节比对，不同就替换）。

## M3 镜像（build/m3/build.sh）

Alpine 3.24 aarch64（docker arm64 + binfmt）：

- 软件包（`out/m3/packages.txt`）：M2 的集合（busybox + OpenRC、dropbear、iproute2（minimal + ss，不带 tc）、iw、
  nftables、ppp-pppoe、dhcpcd、dnsmasq、hostapd、wireless-regdb、stubby、curl、jq、inotify-tools、busybox-extras）
  + `mtd-utils-ubi`、`kexec-tools`、`ssl_client`（busybox wget 的 https）、`igmpproxy`。不装 `alpine-base`
  里的 alpine-conf（setup 脚本）和 busybox-suid。
- `hostapd` 换成 `build/hostapd` 的 noscan 版二进制（构建时检查）；`/usr/bin/sing-box`（上面那份）；`/usr/sbin/mr`；
  `EXTRA_BINS`（默认 M2 的 `bins.tgz`：tailscaled 1.102.4 精简版、lucky 3.0、dstatus-agent，属主改为 root）。
- 仓库 `rootfs/` 的所有文件（全部 init 脚本：mr-network、mr-firewall、mr-pppoe、mr-udhcpc、mr-wanmon、mr-hostapd、
  mr-mon、mr-proxy、mr-proxy-dns、mr-panel、mr-zram、tailscale、lucky、dstatus-agent …，钩子、Web UI）。
- 内核模块 + 固件：只带 MT7976 用的固件，去掉 `mt7986_wm_mt7975.bin`、`mt7986_rom_patch_mt7975.bin`；
  不带 OpenWrt 的 `/etc/modules.d`；`depmod` 前把 OpenWrt 的 `modules.builtin` 改成 kmod 认的 `kernel/<名>` 格式。
- 系统用户 / 组 `sing-box`（`/sbin/nologin`，home `/var/empty`）：mr-proxy 以它 + `CAP_NET_ADMIN` 运行。
- `/etc/modules`：`nf_conntrack`（boot 阶段在 `sysctl` 之前加载，`nf_conntrack_*` sysctl 开机就生效）、`mt7915e`、`tun`。
- `/etc/fstab`：`/tmp`、`/var/log`（16 MB）是 tmpfs，`/run` 是 OpenRC 的 tmpfs——日志和临时文件不写闪存。
- 运行级：sysinit `devfs dmesg mdev hwdrivers`；boot `modules sysctl hostname bootmisc syslog localmount swclock seedrng`
  （无 RTC：swclock 用上次关机时间，seedrng 保存随机数种子）；shutdown `killprocs`；default = 出厂配置的服务。
- 串口 ttyS0：回车得到 root shell（能接串口 = 能进 U-Boot 救援，密码没有意义）；root 密码锁定，SSH 只认密钥。
- `/etc/mini-router-release`：镜像版本 / 内核版本 / 构建时间。
- **不含任何密钥和用户配置**。出厂 `router.yaml` 在构建时渲染进镜像，默认运行级正好是它的服务。
- 构建时检查：家里的真实配置（`examples/router.yaml`）和实验配置（`examples/lab.d`）用到的每个服务都要有
  init 脚本和它 `command=` 的程序；家里配置缺一个就失败，实验配置的缺口记在 `feature-gaps.txt`。

### 出厂配置（build/m3/router.yaml）

| 项 | 默认 | 理由 |
|---|---|---|
| LAN | `192.168.31.1/24`，lan2–lan4，DHCP .100–.249 | 小米原厂地址；带着路由器出差时，上游网络很少用这个段（192.168.1.x 常见，会和 WAN 冲突导致连不上） |
| WAN | `wan` 口 DHCP（+ DHCPv6 / PD） | 插上就能用的最通用方式 |
| WiFi | **关闭** | 出厂的 Web UI 首次设置密码对 LAN 上任何人开放，不能让空中的人抢先设置 |
| Web UI | `http://192.168.31.1/`，第一次从 LAN 访问时设置管理员密码 | |
| SSH | 开，只认密钥；镜像里没有密钥，所以实际关闭，直到下发 `authorized_keys` | |
| 其它 | 防火墙 + 硬件卸载、zram；时区 UTC；NTP pool.ntp.org / time.cloudflare.com | |

## 闪存布局和启动（rootfs/sbin/mr-preinit）

hanwckf 110M U-Boot，UBI 在 `0x600000` 大小 `0x6e00000`（880 个 128 KiB PEB，约 857 个可用 LEB × 126,976 字节 ≈ 103.8 MiB）。
没有 A/B，三个卷沿用 OpenWrt 的名字：

| UBI 卷 | 内容 | 大小 |
|---|---|---|
| `kernel` | FIT（lzma 内核 + DTB），U-Boot 从这里启动 | 需要时 = 文件 + 1 MiB 余量 |
| `rootfs` | squashfs（xz，256 KiB 块）；内核（OpenWrt 补丁 490–493）自动建 ubiblock 并挂成 `/` | 需要时 = 文件 + 4 MiB 余量 |
| `rootfs_data` | UBIFS，overlay 的上层 `mr/upper`（配置、状态、`apk add` 装的东西） | 其余全部 |

U-Boot 的 bootargs 里没有 `init=`，内核运行 `/sbin/init` → 就是 `mr-preinit`（`/init` 也指向它）：

1. PID 1，挂 `/proc`、`/sys`，看 `/` 的类型。
2. **闪存（squashfs）**：`mount -t ubifs <ubi>:rootfs_data /overlay`（空卷由 UBIFS 自己格式化）；有
   `/overlay/.mr-factory-reset` 就先 `ubiupdatevol -t` 清空再挂；挂不上就用 tmpfs（能启动、能配置，重启丢失，内核日志有提示）。
   overlayfs（下层 `/`、上层 `/overlay/mr/upper`，上层根目录每次强制 0755 root）挂到 `/mnt`，`pivot_root` 进去，
   squashfs 留在 `/rom`，`/proc` `/sys` `/overlay` 移过去，然后 `exec busybox init` → OpenRC。
   卷里如果还留着 OpenWrt 的 `upper/`、`work/`，不会被使用（只用 `mr/`）。
3. **initramfs（RAM）**：有 `/mr-install` → sysupgrade 安装程序；否则是 kexec 测试系统：10 分钟内没有
   `/tmp/keep` 就重启回闪存（内核命令行带 `mr.keep` 则不启用）。
4. 两种情况下，如果有 `/etc/mini-router/.firstboot`（下发的配置），先 `mr validate` + `mr render /`，再让 default
   运行级正好等于 `gen/services`，然后删除标记；配置无效则保留出厂文件和标记，并写内核日志。
5. 任何一步失败都继续往下走，最后总是 `exec busybox init`（最坏情况：只读根）。

日志写 `/dev/kmsg`（`dmesg | grep mr-preinit`）。

## 升级（/usr/libexec/mr/sysupgrade）

镜像 `mini-router-<版本>-sysupgrade.tar` 是 OpenWrt 的 sysupgrade-tar 格式（GNU tar）：
`sysupgrade-xiaomi_redmi-router-ax6000-hanwckf/{CONTROL,kernel,root,mr-meta}`，所以 hanwckf U-Boot 的网页救援理论上也能刷
（未实测）。`mr-meta` 是 `KEY=值`：板子（DT compatible）、版本、两个文件的大小和 sha256，以及 FIT 里内核 / DTB 的
偏移、大小、sha256（busybox 没有 FDT 解析器，sysupgrade 用 tail/head 取出后逐个校验）。

校验（`-T` 只做这一步）：成员集合完全匹配（其它板子、多余成员、`..` 都拒绝）；CONTROL 的 BOARD；mr-meta 每一行
格式（不执行、不 source）；板子 = 运行中设备树的 compatible；各文件大小、sha256、魔数（FIT `d00dfeed`、squashfs `hsqs`）；
FIT 偏移不越界、DTB 的 compatible 是本机；空间够（rootfs_data 至少留 8 MiB）；可选 `--sha256` 核对整个镜像。
`--data` 的 tar.gz 只能有普通文件和目录、相对路径、没有 `..`。

安装：

- **从闪存运行时**：`rootfs` 卷正挂着，不能原地写。先停掉占内存的服务（mr-proxy、tailscale、lucky、dstatus、mr-mon），
  在 `/tmp` 组一个安装用 initramfs（busybox、ubi 工具、本脚本、mr-preinit、新的 FIT 和 squashfs），从新 FIT 里取出
  内核（unlzma）和 DTB，`kexec -l`；停看门狗服务（magic close）后用 devmem 直接把 MT7986 硬件看门狗设成 30 秒单级复位
  （否则内核在 kexec 时会关掉它），`kexec -e`。**新内核**起来（顺带验证它能启动）→ 安装程序接管看门狗 → 写 rootfs →
  回读 sha256 → 写 kernel → 回读 → 重启。kexec 之前任何失败都不改闪存；新内核卡死，看门狗 30 秒后重启回旧系统。
  路由器断网约 2 分钟。
- **从 RAM 系统运行时**（kexec 测试系统，首次刷机就是这种）：直接写，不需要 kexec。
- 卷不够大时：先把 rootfs_data 打包到内存，删掉它，扩大 kernel/rootfs（带余量），重建 rootfs_data 并还原。
- `-n` 清空 rootfs_data；`--data overlay.tar.gz` 清空后用下发包作为新的 `mr/upper`。
- 成功后在 rootfs_data 的 `/etc/router-changes.log` 记一行（面板“最近改动”能看到）。

没有 A/B 的代价：写 rootfs/kernel 的那几十秒里断电，会变成起不来——用 U-Boot 网页救援恢复（[flash.md](../flash.md)）。

## 恢复出厂（/usr/libexec/mr/factory-reset）

`factory-reset [-y] [--no-reboot]`：在 `/overlay/.mr-factory-reset` 做标记并重启，下次开机 preinit 在挂载前
`ubiupdatevol -t` 清空 rootfs_data（清空失败就删除 `mr/`）。只在从闪存运行时可用（RAM 测试系统里的 rootfs_data
属于闪存上的系统，拒绝）。之后路由器是出厂配置：`http://192.168.31.1/` 设密码。

## 配置下发（tools/provision.sh）

`provision.sh [-o 输出目录] 目录`：目录按路由器上的路径摆放（只允许 `etc/`、`root/`、`var/lib/`、`usr/local/`），
输出 `provision.cpio`（追加到测试 initramfs 后面，内核按顺序解开多段 cpio）和 `overlay.tar.gz`（`sysupgrade --data`）。
全部 root 属主；目录 0755（`root/`、`root/.ssh`、`etc/dropbear`、`etc/tailscale` 0700）；文件 0644/0755；密钥类 0600。
拒绝符号链接、设备、奇怪文件名、`etc/passwd|shadow|group|inittab|fstab`、`etc/init.d|runlevels|apk`、OpenWrt 的
`etc/config|rc.d`。输出文件 0600，含密钥，用完删除，不要进 git。macOS（bsdtar/bsdcpio）和 Linux 都能用。

## 大小和内存（2026-09-24 构建）

| | |
|---|---|
| rootfs（解压） | 约 174 MiB（178,496 KiB），其中 Go 程序 137 MB：sing-box 75.3、dstatus-agent 25.6、tailscaled 16.7、lucky 10.0、mr 5.3 |
| squashfs（`rootfs` 卷） | 54,562,816 字节（52.0 MiB） |
| FIT（`kernel` 卷） | 4,735,944 字节 |
| rootfs_data | 约 44 MiB（首次刷机后：857 LEB − kernel 46 − rootfs 462 = 349 LEB；UBIFS 实际可用约 40 MiB） |
| 测试 initramfs | 见 `out/m3/sizes.txt`（解压后整个 rootfs 在内存里） |

内存（估算，未在硬件上测）：M2（initramfs，rootfs 113 MB 常驻内存）实测 used ≈ 150 MB（含 tailscale / lucky / dstatus）。
M3 从闪存运行，rootfs 不占内存（squashfs 页缓存可回收），进程和 M2 相同：**空闲时 used ≈ 150 MB，可用 ≈ 300 MB**
（MemTotal 约 484 MB）；开代理再加 sing-box 约 45 MB。kexec 测试系统里 rootfs 常驻内存，可用约少 170 MB。
sysupgrade 从闪存运行时峰值约 3 × 镜像大小（/tmp 里的镜像、解包、installer cpio，加上 kexec 加载时的副本），所以先停大服务。

## 测试

- `tools/ci.d/platform.sh`（每次 CI）：出厂配置无密钥可校验、可渲染，真实 nft（netns）和 dnsmasq 接受，默认值成立；
  `fit-offsets.py` 解析合成 FIT；`sysupgrade -T` 接受正确镜像、拒绝 21 种篡改；`provision.sh` 的属主 / 权限 / 标记和 6 种拒绝。
- `build/m3/build.sh` 结尾：新镜像用 GNU 工具和 busybox（arm64 容器）各跑一次自己的 `sysupgrade -T`；
  busybox `unlzma` 解出的 FIT 内核与 `Image` 逐字节相同；FIT 里的 DTB 与构建的 dtb 相同。
- `build/m3/selftest.sh`（手动，nandsim 模拟 880 × 128 KiB NAND）：安装 A–E（首次刷机覆盖 OpenWrt 布局 + 扩卷 + 下发、
  原地升级保留数据、扩卷时备份还原数据、-n 清空、错误板子 / 损坏镜像被拒且闪存不变）、R（`ubi-restore.sh` 用整卷 dump
  恢复 OpenWrt，包括 UBIFS 数据卷）；preinit P1–P6 用**真实 arm64 squashfs**（qemu-user，pid namespace 里的 PID 1）：
  空卷格式化、忽略 OpenWrt 的 upper、首次启动渲染下发配置 + 运行级、factory-reset 后回到出厂、无效配置保留出厂、没有
  rootfs_data 用 tmpfs。qemu 不支持 UBI ioctl，所以 preinit 里 `ubiupdatevol -t` 走的是删除 `mr/` 的后备路径；真正的
  `ubiupdatevol -t` 在 D 场景用 x86 工具测过。

## 怎么用

### 构建（在编译机上，不在你的电脑上）

```sh
./build/m3/kernel.sh       # 内核 + 模块，~3 分钟（ccache）
./build/m3/sing-box.sh     # sing-box 1.14.1 + 可复现核对
MR_VERSION=$(git rev-parse --short HEAD) ./build/m3/build.sh   # 镜像
./build/m3/selftest.sh     # 可选：nandsim 自测
```

产物在编译机 `/root/build/mini-router-platform/out/m3/`，`SHA256SUMS` 在同一目录：

| 文件 | 用途 |
|---|---|
| `mini-router-m3-<日期>-<提交>-sysupgrade.tar` | 刷机 / 升级（`sysupgrade`） |
| `mini-router-m3-<日期>-<提交>-initramfs.cpio.xz` | kexec 内存测试 |
| `Image`、`image-…-hanwckf.dtb`、`devmem` | kexec 测试用（`tools/kexec-test.sh`） |
| `kernel.itb`、`root.squashfs` | 两个卷的原始内容（手工写卷时用） |
| `kmods-fw.tar.gz`、`kernel-config.diff`、`sing-box`、`packages.txt`、`sizes.txt`、`mr-meta` | 记录 |
| `provision.sh`、`kexec-test.sh` | 工具副本 |

### 下发配置

```sh
mkdir -p cfg/etc/mini-router cfg/root/.ssh
cp router.yaml secrets.yaml cfg/etc/mini-router/    # 还有 dns/*.domains、proxy/* 等
cp ~/.ssh/id_ed25519.pub cfg/root/.ssh/authorized_keys
# 可选：cfg/etc/dropbear/*_host_key（保持 SSH 主机密钥不变）、cfg/etc/tailscale/tailscaled.state、cfg/etc/lucky/…
sh tools/provision.sh -o out cfg                    # → out/provision.cpio、out/overlay.tar.gz（0600，含密钥）
```

### 内存测试、刷机、升级、回滚

完整步骤见 [docs/flash.md](../flash.md)。日常升级（已经刷了 mini-router）：

```sh
scp mini-router-…-sysupgrade.tar root@路由器:/tmp/
ssh root@路由器 /usr/libexec/mr/sysupgrade -T --sha256 <SHA256SUMS 里的值> /tmp/mini-router-…-sysupgrade.tar
ssh root@路由器 'setsid /usr/libexec/mr/sysupgrade -y --sha256 <值> /tmp/mini-router-…-sysupgrade.tar > /tmp/su.log 2>&1 &'
# 约 2 分钟后路由器回来；dmesg / 面板“最近改动”里有 sysupgrade 记录
```

恢复出厂：`/usr/libexec/mr/factory-reset`（输入 YES），重启后 `http://192.168.31.1/`，网线插 LAN 口。

## 运行依赖 / 给其它模块

- sys 模块以后做 Web UI 的“升级 / 恢复出厂”时，调用 `sysupgrade -T`（校验）和 `setsid sysupgrade -y …`、
  `factory-reset -y`（都要 POST + 确认）；上传放 `/tmp`（tmpfs，默认上限为内存一半）。
- 状态接口可以读 `/etc/mini-router-release`；rootfs_data 不可用时 `/overlay` 是 tmpfs（`mr status` 的 overlay 大小会反映出来）。
- net 模块：Alpine 3.24 的 `igmpproxy` 包**没有 OpenRC 脚本**，`multicast.igmp_proxy` 目前在镜像里起不来——需要 net 模块
  提供 `rootfs/etc/init.d/igmpproxy`（构建时的功能检查会报这个缺口）。

## 已知限制

- 没有 A/B：写卷期间断电需要 U-Boot 网页救援。
- 复位键没有接：长按复位键开机进的是 U-Boot 救援（hanwckf），运行中按复位键没有作用。
- 硬件上还没测过（本次任务禁止接触路由器）：preinit、kexec 安装程序、看门狗交接只在模拟环境和代码层面验证过，
  第一次请按 flash.md 先做内存测试。
