# mini-router 上闪存：内存测试 → 刷机 → 首次启动 → 回滚 → U-Boot 救援

对象：Redmi AX6000（hanwckf 110M U-Boot，UBI 在 `0x600000`/`0x6e00000`，卷 `kernel` / `rootfs` / `rootfs_data`），
现在闪存里是 OpenWrt main 6.18（r36531），路由器 `192.168.1.6`，SSH 别名 `router`。
M3 的设计和校验细节见 [modules/platform.md](modules/platform.md)。**全家断网的时间窗口：刷机约 5 分钟；准备好网线和一台电脑。**

规则：每一步先读、后写；任何一步和预期不符，停下来，不要"修一修继续"。

## 0. 刷机前

1. **备份核对**（集成者已经有）：三个 UBI 卷的整卷 dump（例如 `ubi0_0.bin` kernel、`ubi0_1.bin` rootfs、
   `ubi0_2.bin` rootfs_data）、BL2 / FIP / Factory（mtd dump，Factory 里是无线校准数据）、OpenWrt 固件
   你现在系统的固件和配置备份。在你的电脑上用记录的
   sha256 逐个核对。mini-router 只写 `ubi` 分区里的三个卷，BL2 / FIP / Factory / U-Boot 永远不碰。
2. 记下现在的卷布局（回滚时按它重建）：在 OpenWrt 上 `ubinfo -a > /tmp/ubi-before.txt`，拷回 Mac。
3. 构建机上的产物（[platform.md → 构建](modules/platform.md#怎么用)），拿到 Mac 并核对：

   ```sh
   mkdir -p ~/m3 && scp -r build-host:/root/build/mini-router-platform/out/m3 ~/m3/   # or download the release assets
   cd ~/m3/m3 && shasum -a 256 -c SHA256SUMS
   ```

4. 配置下发目录（**在你的电脑上做，不要放进 git，也不要放到构建机**）。需要的文件：

   ```sh
   mkdir -p ~/m3/cfg/etc/mini-router/dns ~/m3/cfg/root/.ssh ~/m3/cfg/etc/dropbear
   # 可选：服务状态（etc/tailscale、etc/lucky、etc/dstatus-agent …），从旧系统拷过来
   cp examples/router.yaml secrets.yaml ~/m3/cfg/etc/mini-router/
   cp ~/.ssh/<密钥>.pub ~/m3/cfg/root/.ssh/authorized_keys
   # 可选：保持 SSH 主机密钥不变，从 OpenWrt 拷 dropbear 的主机密钥
   ssh root@192.168.1.6 'cat /etc/dropbear/dropbear_ecdsa_host_key' > ~/m3/cfg/etc/dropbear/dropbear_ecdsa_host_key
   ssh root@192.168.1.6 'cat /etc/dropbear/dropbear_ed25519_host_key' > ~/m3/cfg/etc/dropbear/dropbear_ed25519_host_key
   sh tools/provision.sh -o ~/m3 ~/m3/cfg                 # → ~/m3/provision.cpio、~/m3/overlay.tar.gz（0600）
   ```

   `provision.sh` 会拒绝符号链接、系统文件（`etc/passwd` 等）、OpenWrt 的 `etc/config`；按提示整理目录后重跑。

## 1. 内存测试（闪存不动）

路由器现在如果跑的是 早期的内存测试系统，先 `reboot` 回到闪存里的 OpenWrt（约 1 分钟）。然后从 OpenWrt 用 kexec 进 M3：

```sh
cd ~/m3/m3
for f in Image image-mt7986a-xiaomi-redmi-router-ax6000-hanwckf.dtb devmem kexec-test.sh mini-router-*-initramfs.cpio.xz ../provision.cpio; do
	ssh root@192.168.1.6 "cat > /tmp/$(basename "$f")" < "$f"
done
ssh root@192.168.1.6 'chmod +x /tmp/devmem && cd /tmp && sh kexec-test.sh mini-router-*-initramfs.cpio.xz provision.cpio'
```

SSH 会断开；约 30 秒后 M3 在 `192.168.1.6` 起来（用的是下发的 router.yaml；主机密钥不变）。硬件看门狗已设 30 秒：
新内核卡住会自动回到 OpenWrt。**10 分钟内**不 `touch /tmp/keep` 就自动重启回 OpenWrt。

检查（全部通过才继续；不通过就 `reboot` 回 OpenWrt，闪存没动过）：

```sh
touch /tmp/keep
dmesg | grep mr-preinit          # "applied the provisioned router.yaml"
cat /etc/mini-router-release; rc-status; mr status | head -c 2000
```

- 两条 PPPoE 都拨上、IPv4 / IPv6 出网；LAN DHCP、DNS（含 stubby 分流）
- 2.4G / 5G WiFi，设备能连；`nft list flowtables` 有 `flags offload`，`grep -c HW_OFFLOAD /proc/net/nf_conntrack` > 0
- desktop 走 wan2；端口转发两条线都通；tailscale 在线、192.168.60.0/24 可达；lucky / dstatus / Web UI / 面板
- 开了代理的话：`mr proxy check`
- `free -m`：内存测试时整个 rootfs 在内存里，可用内存比刷机后少约 170 MB，属正常

## 2. 刷机（在 M3 内存系统里）

```sh
cd ~/m3/m3
IMG=$(ls mini-router-*-sysupgrade.tar); SHA=$(grep " $IMG\$" SHA256SUMS | cut -d' ' -f1)
ssh root@192.168.1.6 "cat > /tmp/$IMG" < "$IMG"
ssh root@192.168.1.6 'cat > /tmp/overlay.tar.gz' < ../overlay.tar.gz
ssh root@192.168.1.6 "ubinfo -a > /tmp/ubi-before.txt; /usr/libexec/mr/sysupgrade -T --sha256 $SHA /tmp/$IMG"
ssh -t root@192.168.1.6 "/usr/libexec/mr/sysupgrade --sha256 $SHA --data /tmp/overlay.tar.gz /tmp/$IMG"   # 输入 YES
```

内存系统里 sysupgrade 直接写卷（不需要 kexec），会自动 `touch /tmp/keep`，过程约 1–2 分钟，全程有输出：

1. 再校验一次（板子、sha256、大小、魔数、FIT 里的 DTB）。
2. OpenWrt 的 rootfs 卷（约 29 MB）放不下 M3 的 squashfs（约 52 MB）：删除 rootfs_data（旧的 OpenWrt overlay——
   在备份里）、扩大 rootfs（+4 MiB 余量）/ kernel（需要时 +1 MiB）。
3. 写 rootfs，回读 sha256；写 kernel，回读 sha256（各最多重试 3 次）。
4. 重建 rootfs_data（其余全部空间），格式化为 UBIFS，放入 `overlay.tar.gz`（`mr/upper`），在 `/etc/router-changes.log` 记一行。
5. 重启。

**从第 2 步开始到写完之前不能断电。**如果输出里有 `INSTALL FAILED`：不要重启，先看报错；闪存可能已经不完整，
按下面第 4 节回滚（这时还在内存系统里，可以直接用 `ubi-restore.sh`）。

> 也可以直接在现在跑着的 **早期的内存测试系统**里刷：`apk add mtd-utils-ubi`，把 M3 的 `rootfs/usr/libexec/mr/sysupgrade` 拷到
> `/tmp`，`sh /tmp/sysupgrade …`（参数同上）。它同样认出内存根、直接写卷。但这样跳过了 M3 的内存测试，不推荐。

## 3. 首次从闪存启动

U-Boot → `kernel` 卷的 FIT → 内核把 `rootfs` 卷挂成 `/`（squashfs）→ `/sbin/mr-preinit` 挂 UBIFS `rootfs_data`
→ overlay → 渲染下发的 router.yaml、启用它的服务 → OpenRC。约 30 秒后 SSH 可用（主机密钥不变）。

```sh
dmesg | grep mr-preinit          # 没有 "rootfs_data unavailable"
mount | grep -E ' / | /rom | /overlay '   # overlay on / ; squashfs on /rom ; ubifs on /overlay
df -h /overlay; ubinfo -a | grep -E 'Name|Size'
cat /etc/router-changes.log | tail -3
```

重复第 1 节的检查清单，再 `reboot` 一次，确认配置和状态（tailscale 登录、lucky 配置）都保留。

以后的升级：`sysupgrade -T` 校验后 `setsid /usr/libexec/mr/sysupgrade -y --sha256 … /tmp/<镜像> > /tmp/su.log 2>&1 &`。
从闪存运行时它会 kexec 进新内核里的安装程序，路由器断网约 2 分钟；kexec 之前失败不会改动闪存，新内核卡住看门狗会
30 秒后回到旧系统。

## 4. 回滚到原来的 OpenWrt（写回备份的卷）

需要一个**内存里的系统**（闪存的卷在用时不能改）：

- 刚刷完、还在 M3 内存系统里：直接用。
- 已经从闪存跑 mini-router：像第 1 节一样用 `kexec-test.sh` 进 M3 内存系统（`kexec-test.sh` 在 mini-router 上也能用，
  它自带 devmem）。为了给 dump 留内存，provision 目录可以只放 `router.yaml` + `authorized_keys` + 主机密钥，
  或者进去后先停掉大服务：`rc-service tailscale stop; rc-service lucky stop; rc-service dstatus-agent stop; rc-service mr-proxy stop`。

然后（三个 dump 共约 110 MB，放 `/tmp`）：

```sh
ssh root@192.168.1.6 'cat > /tmp/ubi0_0.bin' < ubi0_0.bin      # kernel
ssh root@192.168.1.6 'cat > /tmp/ubi0_1.bin' < ubi0_1.bin      # rootfs
ssh root@192.168.1.6 'cat > /tmp/ubi0_2.bin' < ubi0_2.bin      # rootfs_data（OpenWrt 的 overlay）
ssh root@192.168.1.6 'cat > /tmp/ubi-restore.sh' < tools/ubi-restore.sh
ssh -t root@192.168.1.6 'sha256sum /tmp/ubi0_*.bin; sh /tmp/ubi-restore.sh /tmp/ubi0_0.bin /tmp/ubi0_1.bin /tmp/ubi0_2.bin'   # 输入 YES
ssh root@192.168.1.6 reboot
```

`ubi-restore.sh` 删除三个卷，按 dump 的大小（整 LEB）以 id 0/1/2 重建，写入并回读 sha256，与 `ubi-before.txt` 的布局一致。
只有 kernel + rootfs 的 dump 也行（第三个参数省略）：rootfs_data 建成空卷，OpenWrt 首次启动会格式化，然后在 OpenWrt 里
`sysupgrade -r cfg.tar.gz && reboot` 恢复配置。

## 5. 最后手段：U-Boot 网页救援（hanwckf）

系统完全起不来（写卷时断电、内核坏了）时用。U-Boot 在 NOR/NAND 前面的分区里，mini-router 从不写它。

1. 断电；按住复位键；上电；保持按住约 10 秒，直到指示灯变化（进入 failsafe），松开。
2. 电脑网线接 LAN 口，手动设 IP `192.168.1.2/24`（不要网关）。
3. 浏览器打开 `http://192.168.1.1`，上传 `openwrt-main-618-hanwckf-sysupgrade.bin`（备份里那份，已知能用），等它写完自动重启。
4. OpenWrt 起来后（新配置，`192.168.1.1`），`sysupgrade -r cfg.tar.gz && reboot` 恢复原配置（回到 `192.168.1.6`）；
   需要的话再按第 4 节写回 rootfs_data dump。

mini-router 的 `*-sysupgrade.tar` 用的是和 OpenWrt 相同的 sysupgrade-tar 格式（`sysupgrade-<板>/kernel|root`），理论上
failsafe 页面也能直接刷；**没有实测**，救援时优先用上面已知能用的 OpenWrt 镜像。BL2 / FIP / Factory 的备份只在
U-Boot 本身损坏时才需要（要用编程器或 mtk_uartboot，超出本文范围）。

## 附：恢复出厂

`/usr/libexec/mr/factory-reset`（输入 YES）→ 重启 → 出厂配置：网线接 LAN 口，`http://192.168.31.1/` 设置管理员密码；
WiFi 关闭，SSH 没有密钥。之后可以用 `sysupgrade --data overlay.tar.gz <镜像>`（在内存系统里）或 Web UI 重新配置。
