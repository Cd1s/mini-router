set -e
apk add -q alpine-sdk git sudo
cd /work
[ -d aports ] || git clone -q --depth 1 --filter=blob:none --sparse -b 3.24-stable https://gitlab.alpinelinux.org/alpine/aports.git aports
cd aports && git sparse-checkout set main/hostapd && cd main/hostapd
cp /work/300-noscan.patch noscan.diff
sed -i "s/^source=\"/source=\"noscan.diff /" APKBUILD
sed -i "s/^prepare() {/prepare() {\n\t( cd \"\$srcdir\"\/\$pkgname-\$pkgver \&\& patch -p1 < \"\$srcdir\"\/noscan.diff )/" APKBUILD
sed -i "s/^pkgrel=\(.*\)/pkgrel=\1\npkgrel=\$((pkgrel + 100))/" APKBUILD
grep -n -A3 "^prepare" APKBUILD
adduser -D b 2>/dev/null || true; addgroup b abuild; chown -R b /work
su b -c "abuild-keygen -a -n >/dev/null 2>&1; abuild checksum && abuild -r -P /work/pkgs"
