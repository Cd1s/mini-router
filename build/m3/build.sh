#!/bin/sh
# M3 image: Alpine 3.24 rootfs (build-rootfs.sh) -> squashfs for the UBI volume "rootfs", the same tree
# as a kexec test initramfs, and the sysupgrade image. Runs on the build host (docker, arm64 via binfmt):
#
#   MR_VERSION=<git short sha> ./build/m3/build.sh
#
# Needs build/m3/kernel.sh and build/m3/sing-box.sh first. Inputs (read only): $W/out/kernel,
# $W/out/sing-box, the noscan hostapd package (build/hostapd) and EXTRA_BINS (tailscaled, lucky,
# dstatus-agent … as a tgz of usr/ paths; default: none). Outputs in $W/out/m3 + SHA256SUMS.
set -eu
REPO=$(cd "$(dirname "$0")/../.." && pwd)
W=${MR_PLATFORM_DIR:-/root/build/mini-router-platform}
KO=$W/out/kernel
SB=$W/out/sing-box
M=$W/m3
O=$W/out/m3
VER=${MR_VERSION:-dev}
IMGVER=m3-$(date -u +%Y%m%d)-$VER
HOSTAPD_APK=${HOSTAPD_APK:-/root/build/hostapd-noscan/pkgs/main/aarch64/hostapd-2.11-r104.apk}
EXTRA_BINS=${EXTRA_BINS-}
BOARD=xiaomi,redmi-router-ax6000-hanwckf
PREFIX=sysupgrade-xiaomi_redmi-router-ax6000-hanwckf
DTB=image-mt7986a-xiaomi-redmi-router-ax6000-hanwckf.dtb
[ ! -f /etc/profile.d/buildtools.sh ] || . /etc/profile.d/buildtools.sh # dash: a failing `.` exits the shell

for f in "$KO/kmods-fw.tar.gz" "$KO/kernel.itb" "$KO/Image" "$KO/$DTB" "$SB/sing-box" "$HOSTAPD_APK"; do
	[ -s "$f" ] || { echo "missing input $f"; exit 1; }
done
rm -rf "$M" "$O" && mkdir -p "$M/w/repo/mr" "$O"
cp "$KO/kmods-fw.tar.gz" "$SB/sing-box" "$M/w/"
cp "$HOSTAPD_APK" "$M/w/hostapd.apk"
if [ -n "$EXTRA_BINS" ]; then cp "$EXTRA_BINS" "$M/w/bins.tgz"; fi
(cd "$REPO/mr" && GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$VER" -o "$M/w/mr" .)
cp -a "$REPO/rootfs" "$REPO/build" "$REPO/tools" "$REPO/examples" "$M/w/repo/"
cp -a "$REPO/mr/testdata" "$M/w/repo/mr/"
docker run --rm --platform linux/arm64 -e MR_IMAGE_VERSION="$IMGVER" -e MR_ADDONS="${EXTRA_BINS:+1}" -v "$M/w:/w" alpine:3.24 sh /w/repo/build/m3/build-rootfs.sh
docker run --rm -v "$M/w:/w" alpine:3.24 sh /w/repo/build/m3/pack.sh

# ---- sysupgrade image: OpenWrt sysupgrade-tar layout + mr-meta
S=$M/sysupgrade/$PREFIX
mkdir -p "$S"
echo "BOARD=${PREFIX#sysupgrade-}" > "$S/CONTROL"
cp "$KO/kernel.itb" "$S/kernel"
cp "$M/w/root.squashfs" "$S/root"
python3 "$REPO/build/m3/fit-offsets.py" "$S/kernel" > "$M/fit.meta"
# the FIT pieces sysupgrade kexecs must be exactly this build's DTB and (lzma'd) Image
python3 - "$S/kernel" "$M/fit.meta" "$KO/$DTB" "$KO/Image" << 'EOF'
import lzma, sys
fit = open(sys.argv[1], "rb").read()
m = dict(l.split("=", 1) for l in open(sys.argv[2]).read().split())
piece = lambda k: fit[int(m[k + "_OFFSET"]):int(m[k + "_OFFSET"]) + int(m[k + "_SIZE"])]
assert piece("FIT_FDT") == open(sys.argv[3], "rb").read(), "FIT fdt != dtb"
assert lzma.decompress(piece("FIT_KERNEL"), format=lzma.FORMAT_ALONE) == open(sys.argv[4], "rb").read(), "FIT kernel != Image"
print("FIT: kernel and dtb match Image and", sys.argv[3].rsplit("/", 1)[1])
EOF
{
	echo "MR_FORMAT=1"
	echo "MR_BOARD=$BOARD"
	echo "MR_VERSION=$IMGVER"
	echo "MR_KERNEL=6.18.52"
	echo "KERNEL_SIZE=$(wc -c < "$S/kernel")"
	echo "KERNEL_SHA256=$(sha256sum "$S/kernel" | cut -d' ' -f1)"
	echo "ROOT_SIZE=$(wc -c < "$S/root")"
	echo "ROOT_SHA256=$(sha256sum "$S/root" | cut -d' ' -f1)"
	cat "$M/fit.meta"
} > "$S/mr-meta"
IMG=mini-router-$IMGVER-sysupgrade.tar
tar -C "$M/sysupgrade" -c --format=gnu --owner=0 --group=0 --numeric-owner --no-recursion \
	--mtime="@$(date +%s)" -f "$O/$IMG" "$PREFIX" "$PREFIX/CONTROL" "$PREFIX/kernel" "$PREFIX/root" "$PREFIX/mr-meta"

# ---- artifacts
cp "$M/w/initramfs.cpio.xz" "$O/mini-router-$IMGVER-initramfs.cpio.xz"
cp "$KO/Image" "$KO/$DTB" "$O/"
cp "$KO/kernel.itb" "$O/kernel.itb"
cp "$M/w/root.squashfs" "$O/root.squashfs"
cp "$KO/kmods-fw.tar.gz" "$KO/kernel-config.diff" "$SB/sing-box" "$O/"
cp "$S/mr-meta" "$M/w/packages.txt" "$M/w/sizes.txt" "$O/"
cp "$REPO/tools/provision.sh" "$REPO/tools/kexec-test.sh" "$REPO/tools/ubi-restore.sh" "$M/w/feature-gaps.txt" "$O/"
# devmem for tools/kexec-test.sh on OpenWrt (static, no Alpine libs needed there)
docker run --rm --platform linux/arm64 -v "$REPO/tools:/src:ro" -v "$O:/o" alpine:3.24 sh -c \
	'apk add -q --no-cache gcc musl-dev > /dev/null && cc -static -Os -s -o /o/devmem /src/devmem.c'

# ---- self-check: the new image passes its own sysupgrade -T, with GNU tools and with busybox
MR_SYSUPGRADE_TEST_COMPAT="$BOARD mediatek,mt7986a" MR_SYSUPGRADE_WORK="$M/su-test" \
	sh "$REPO/rootfs/usr/libexec/mr/sysupgrade" -T "$O/$IMG"
# shellcheck disable=SC2016 # expanded inside the container
docker run --rm --platform linux/arm64 -v "$O:/o:ro" -v "$M/w/rootfs:/r:ro" -e IMG="$IMG" -e PREFIX="$PREFIX" \
	-e MR_SYSUPGRADE_TEST_COMPAT="$BOARD mediatek,mt7986a" alpine:3.24 sh -c '
	set -e
	sh /r/usr/libexec/mr/sysupgrade -T "/o/$IMG"
	cd /tmp && tar -xf "/o/$IMG" "$PREFIX/kernel"
	o=$(sed -n "s/^FIT_KERNEL_OFFSET=//p" /o/mr-meta)
	n=$(sed -n "s/^FIT_KERNEL_SIZE=//p" /o/mr-meta)
	tail -c +$((o + 1)) "$PREFIX/kernel" | head -c "$n" | unlzma | cmp - /o/Image
	echo "busybox: sysupgrade -T ok, unlzma(FIT kernel) = Image"'

(cd "$O" && sha256sum -- * > SHA256SUMS.tmp && mv SHA256SUMS.tmp SHA256SUMS)
echo "== $O"
ls -la "$O"
cat "$O/SHA256SUMS"
