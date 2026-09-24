#!/bin/sh
# sing-box for the M3 image: full-featured linux/arm64 build from the release tag, CGO_ENABLED=0,
# built exactly like the upstream release workflow (.github/workflows/build.yml of the tag):
# same Go version, -trimpath, release/LDFLAGS, -s -w -buildid=, and the release's CGO-free tag set
# release/DEFAULT_BUILD_TAGS_OTHERS (every protocol except naive outbound, which needs cronet/cgo).
# Runs on the build host:  ./build/m3/sing-box.sh
#
# Also: (1) rebuilds the release's own linux-arm64 variant (DEFAULT_BUILD_TAGS + with_purego) and
# compares it byte for byte with the published binary, proving the toolchain/source match upstream;
# (2) makes sure /opt/sing-box/$V/sing-box is the official linux-amd64 release binary (CI uses it).
# Outputs in $W/out/sing-box: sing-box (arm64, for the image), version.txt, SHA256SUMS, report.txt
set -eu
V=${SING_BOX_VERSION:-1.14.1}
W=${MR_PLATFORM_DIR:-/root/build/mini-router-platform}
S=$W/sing-box/src-$V
O=$W/out/sing-box
D=$W/sing-box/dl
. /etc/profile.d/buildtools.sh 2> /dev/null || :
mkdir -p "$O" "$D"
R=https://github.com/SagerNet/sing-box/releases/download/v$V

fetch() { [ -s "$D/$1" ] || curl -fsSL -o "$D/$1" "$R/$1"; }
fetch "sing-box-$V-linux-amd64.tar.gz"
fetch "sing-box-$V-linux-arm64.tar.gz"
for a in amd64 arm64; do
	tar -xzf "$D/sing-box-$V-linux-$a.tar.gz" -C "$D" "sing-box-$V-linux-$a/sing-box"
done

# official amd64 binary for CI
OFF=/opt/sing-box/$V/sing-box
if ! cmp -s "$D/sing-box-$V-linux-amd64/sing-box" "$OFF"; then
	mkdir -p "${OFF%/*}"
	[ -e "$OFF" ] && mv "$OFF" "$OFF.replaced-$(date +%s)"
	install -m 0755 "$D/sing-box-$V-linux-amd64/sing-box" "$OFF"
	echo "installed the official linux-amd64 binary at $OFF"
fi

if [ ! -d "$S/.git" ]; then
	rm -rf "$S"
	git clone -q --depth 1 --branch "v$V" https://github.com/SagerNet/sing-box.git "$S"
fi
cd "$S"
rev=$(git rev-parse HEAD)
official_rev=$("$OFF" version | sed -n 's/^Revision: //p')
[ "$rev" = "$official_rev" ] || { echo "tag v$V is $rev, the official binary says $official_rev"; exit 1; }
GOV=$(sed -n 's/^ *go-version: *//p' .github/workflows/build.yml | head -1)
export GOTOOLCHAIN="go$GOV" GOFLAGS=-mod=readonly CGO_ENABLED=0 GOOS=linux GOARCH=arm64
go version
LDF="-X 'github.com/sagernet/sing-box/constant.Version=$V' $(cat release/LDFLAGS) -s -w -buildid="

# (1) reproduce the published linux-arm64 binary
go build -trimpath -o "$W/sing-box/sing-box-official-tags" -tags "$(cat release/DEFAULT_BUILD_TAGS),with_purego" -ldflags "$LDF" ./cmd/sing-box
if cmp -s "$W/sing-box/sing-box-official-tags" "$D/sing-box-$V-linux-arm64/sing-box"; then
	repro="identical to the published sing-box-$V-linux-arm64 binary"
else
	repro="DIFFERS from the published sing-box-$V-linux-arm64 binary"
fi

# (2) the router build
# drop with_tailscale: the router runs its own tailscaled; the embedded one adds ~30 MB of flash
TAGS=$(tr ',' '\n' < release/DEFAULT_BUILD_TAGS_OTHERS | grep -vx with_tailscale | paste -sd, -)
go build -trimpath -o "$O/sing-box" -tags "$TAGS" -ldflags "$LDF" ./cmd/sing-box
"$O/sing-box" version > "$O/version.txt" # arm64: runs through the host's qemu-user binfmt
cat "$O/version.txt"
{
	echo "sing-box $V, tag v$V = $rev, $(go version)"
	echo "reproduction of the release arm64 build (tags DEFAULT_BUILD_TAGS,with_purego): $repro"
	echo "router build tags: $TAGS"
	echo "size: $(wc -c < "$O/sing-box") bytes, xz -9e: $(python3 -c 'import lzma, sys; print(len(lzma.compress(open(sys.argv[1], "rb").read(), preset=9 | lzma.PRESET_EXTREME)))' "$O/sing-box") bytes"
} > "$O/report.txt"
cat "$O/report.txt"
(cd "$O" && sha256sum sing-box > SHA256SUMS && cat SHA256SUMS)
