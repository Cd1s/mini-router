#!/bin/sh
# M3 kernel: the OpenWrt main 6.18 build of the flashed system plus the netfilter modules mini-router
# needs (kmod-nft-tproxy, kmod-nft-socket). Runs on the build host as root:
#
#   ./build/m3/kernel.sh
#
# The original tree (/root/build/owrt-main/src, which built the flashed firmware) is never written:
# it is the read-only lower layer of an overlayfs at $W/owrt, and the build runs there in the same
# docker image (owrt-builder, tree at /w). Outputs in $W/out/kernel:
#   Image, <dtb>          kexec (tools/kexec-test.sh)
#   kernel.itb            FIT for the UBI volume "kernel" (the build's own *-kernel.bin, same recipe as flashed)
#   kmods-fw.tar.gz       /lib/modules/<ver> + the MT7986/MT7976 firmware, for exactly this kernel
#   kernel-config.diff    kernel .config: flashed build -> this build;  openwrt-config.diff likewise
set -eu
W=${MR_PLATFORM_DIR:-/root/build/mini-router-platform}
LOWER=/root/build/owrt-main/src
T=$W/owrt
O=$W/out/kernel
KDIR=build_dir/target-aarch64_cortex-a53_musl/linux-mediatek_filogic
KVER=6.18.52
DTB=image-mt7986a-xiaomi-redmi-router-ax6000-hanwckf.dtb
FIT=xiaomi_redmi-router-ax6000-hanwckf-kernel.bin
PKGS="kmod-nft-tproxy kmod-nft-socket"

mkdir -p "$W/owrt-upper" "$W/owrt-work" "$T" "$O" "$W/logs"
chown 1000:1000 "$W/owrt-upper" # the container user b owns the merged top directory
if ! mountpoint -q "$T"; then
	mount -t overlay overlay -o "lowerdir=$LOWER,upperdir=$W/owrt-upper,workdir=$W/owrt-work" "$T"
fi

# reference: what the flashed system was built with (read from the untouched lower tree)
cp "$LOWER/.config" "$O/openwrt.config.flashed"
cp "$LOWER/$KDIR/linux-$KVER/.config" "$O/kernel.config.flashed"
cp "$LOWER/$KDIR/$FIT" "$O/kernel.itb.flashed-build"

# new outputs only (whiteouts in the upper layer; the lower bin/ stays as it is)
rm -rf "$T/bin/targets"

# mini-router kernel patches (build/m3/patches/99*-*.patch) on top of OpenWrt's; a changed set changes
# the kernel's prepare stamp, so the kernel is re-extracted and rebuilt with them
P=$T/target/linux/mediatek/patches-6.18
REPO=$(cd "$(dirname "$0")/../.." && pwd)
for f in "$P"/99*-*.patch; do
	[ ! -e "$f" ] || [ -e "$REPO/build/m3/patches/${f##*/}" ] || rm -f "$f"
done
cp "$REPO"/build/m3/patches/99*-*.patch "$P/"

cat > "$T/mr-platform-build.sh" << EOF
set -eu
cd /w
for p in $PKGS; do
	grep -q "^CONFIG_PACKAGE_\$p=y" .config || echo "CONFIG_PACKAGE_\$p=y" >> .config
done
make defconfig > /dev/null
for p in $PKGS; do grep -q "^CONFIG_PACKAGE_\$p=y" .config || { echo "\$p not selected"; exit 1; }; done
make -j\$(nproc) world || make -j1 V=s world
EOF
echo "building (log: $W/logs/kernel-build.log)"
if ! docker run --rm -v "$T:/w" owrt-builder bash /w/mr-platform-build.sh > "$W/logs/kernel-build.log" 2>&1; then
	tail -60 "$W/logs/kernel-build.log"
	exit 1
fi
tail -3 "$W/logs/kernel-build.log"
for f in "$REPO"/build/m3/patches/99*-*.patch; do # every mini-router patch made it into the build tree
	grep -q "^+" "$f" && (cd "$T/$KDIR/linux-$KVER" && patch -R -p1 --dry-run -s < "$f" > /dev/null) ||
		{ echo "patch ${f##*/} is not applied in the build tree"; exit 1; }
done

cp "$T/.config" "$O/openwrt.config"
cp "$T/$KDIR/linux-$KVER/.config" "$O/kernel.config"
diff -u "$O/openwrt.config.flashed" "$O/openwrt.config" > "$O/openwrt-config.diff" || :
diff -u "$O/kernel.config.flashed" "$O/kernel.config" > "$O/kernel-config.diff" || :
cp "$T/$KDIR/Image" "$O/Image"
cp "$T/$KDIR/$DTB" "$O/$DTB"
cp "$T/$KDIR/$FIT" "$O/kernel.itb"
cp "$T/$KDIR/$FIT.its" "$O/kernel.its"

# the FIT inside OpenWrt's own sysupgrade image must be the same file
sup=$(ls "$T"/bin/targets/mediatek/filogic/*hanwckf-squashfs-sysupgrade.bin)
tar -xOf "$sup" sysupgrade-xiaomi_redmi-router-ax6000-hanwckf/kernel | cmp - "$O/kernel.itb"

# kernel modules + firmware exactly as the OpenWrt image installs them, minus what Alpine does not use
R=$T/build_dir/target-aarch64_cortex-a53_musl/root-mediatek
rm -rf "$O/kmods" && mkdir -p "$O/kmods/lib/modules" "$O/kmods/lib/firmware/mediatek"
cp -a "$R/lib/modules/$KVER" "$O/kmods/lib/modules/"
for f in mt7986_wa.bin mt7986_wm.bin mt7986_rom_patch.bin mt7986_wo_0.bin mt7986_wo_1.bin; do
	cp "$R/lib/firmware/mediatek/$f" "$O/kmods/lib/firmware/mediatek/"
done
for m in nft_tproxy nft_socket nf_tproxy_ipv4 nf_tproxy_ipv6 nf_socket_ipv4 nf_socket_ipv6 \
	nft_log nf_log_syslog nft_redir nft_numgen tcp_bbr nf_conntrack mt7915e pppoe tun zram; do
	[ -f "$O/kmods/lib/modules/$KVER/$m.ko" ] || { echo "missing module $m.ko"; exit 1; }
done
tar -C "$O/kmods" --owner=0 --group=0 --numeric-owner -czf "$O/kmods-fw.tar.gz" lib
ls "$O/kmods/lib/modules/$KVER" > "$O/modules.txt"
(cd "$O" && sha256sum Image "$DTB" kernel.itb kmods-fw.tar.gz > SHA256SUMS)
cat "$O/SHA256SUMS"
echo "== kernel config changes"
grep '^[-+]CONFIG\|^[-+]# CONFIG' "$O/kernel-config.diff" || echo "(none)"
