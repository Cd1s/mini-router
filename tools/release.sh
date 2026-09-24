#!/bin/sh
# release.sh VERSION [OUTDIR] — build the release assets on any Linux with Go (no cgo, no root):
#   mr-linux-{amd64,arm64,armv7,armv6,386,riscv64,ppc64le}   the router tool, static
#   mini-router-rootfs.tar.gz   OpenRC services, hooks, web UI (what install.sh unpacks into /)
#   install.sh, SHA256SUMS
# Device firmware images (e.g. Redmi AX6000) are built separately: build/m3/.
set -eu
VER=${1:?usage: release.sh VERSION [OUTDIR]}
OUT=${2:-out/release}
cd "$(dirname "$0")/.."
ROOT=$(pwd)
rm -rf "$OUT" && mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
for t in amd64 arm64 armv7:arm:7 armv6:arm:6 386 riscv64 ppc64le; do
	name=${t%%:*}
	arch=$name goarm=
	case $t in *:*:*) arch=$(echo "$t" | cut -d: -f2) goarm=$(echo "$t" | cut -d: -f3) ;; esac
	(cd mr && GOOS=linux GOARCH=$arch GOARM=$goarm CGO_ENABLED=0 go build -trimpath \
		-ldflags "-s -w -X main.version=$VER" -o "$OUT/mr-linux-$name" .)
	echo "mr-linux-$name $(wc -c < "$OUT/mr-linux-$name")"
done
# the rootfs overlay without the firmware-image-only files (preinit, fstab, module list, flash tools)
tar -C rootfs --owner=0 --group=0 --numeric-owner \
	--exclude=./sbin/mr-preinit --exclude=./etc/fstab --exclude=./etc/modules \
	--exclude=./usr/libexec/mr/sysupgrade --exclude=./usr/libexec/mr/factory-reset \
	-czf "$OUT/mini-router-rootfs.tar.gz" .
cp install.sh "$OUT/install.sh"
(cd "$OUT" && sha256sum mr-linux-* mini-router-rootfs.tar.gz install.sh > SHA256SUMS)
ls -la "$OUT"
echo "release assets for $VER in $OUT (from $ROOT)"
