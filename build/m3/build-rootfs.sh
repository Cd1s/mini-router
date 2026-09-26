#!/bin/sh
# M3 root filesystem. Runs inside alpine:3.24 (arm64), started by build/m3/build.sh. /w holds:
#   kmods-fw.tar.gz  sing-box  mr  hostapd.apk  [bins.tgz]  repo/ (rootfs/ build/ tools/ examples/ mr/testdata/)
# Produces /w/rootfs (the tree), /w/root.squashfs (UBI volume "rootfs"), /w/initramfs.cpio.xz (kexec
# test system, the same tree), /w/packages.txt, /w/sizes.txt. No secrets, no user config: the factory
# router.yaml (build/m3/router.yaml) is rendered into the image.
set -eu
W=/w
R=$W/rootfs
KVER=6.18.52
REPO=$W/repo
PKGS="alpine-baselayout alpine-release apk-tools busybox busybox-openrc busybox-mdev-openrc busybox-extras
	openrc musl-utils ca-certificates-bundle
	iproute2-minimal iproute2-ss iw nftables ppp-daemon ppp-pppoe dhcpcd dhcpcd-openrc dnsmasq-dnssec-nftset dnsmasq-openrc hostapd
	wireless-regdb igmpproxy dropbear dropbear-openrc stubby stubby-openrc curl jq
	mtd-utils-ubi kexec-tools ssl_client"

apk add --no-cache kmod squashfs-tools cpio xz gcc musl-dev binutils file > /dev/null
rm -rf "$R" && mkdir -p "$R/etc/apk"
cp -a /etc/apk/keys "$R/etc/apk/" && cp /etc/apk/repositories "$R/etc/apk/repositories"
# shellcheck disable=SC2086
apk --root "$R" --initdb --no-cache add $PKGS > /dev/null
apk --root "$R" info -v 2> /dev/null | sort > "$W/packages.txt"

# kernel modules + firmware of exactly the M3 kernel (build/m3/kernel.sh)
tar -xzf "$W/kmods-fw.tar.gz" -C "$R"
# OpenWrt lists built-in modules without a directory; kmod's depmod wants kernel/<path>
sed -i 's#^[^/]*$#kernel/&#' "$R/lib/modules/$KVER/modules.builtin"
(cd "$R/lib/modules/$KVER" && find . -maxdepth 1 -name '*.ko' | sed 's#^\./##' | sort > modules.order)
depmod -b "$R" "$KVER"
for m in nf_conntrack mt7915e tun pppoe zram nft_tproxy nft_socket; do
	grep -q "^$m\.ko:" "$R/lib/modules/$KVER/modules.dep" || { echo "modules.dep lacks $m"; exit 1; }
done

# binaries
install -m 0755 "$W/mr" "$R/usr/sbin/mr"
install -m 0755 "$W/sing-box" "$R/usr/bin/sing-box"
tar -xzf "$W/hostapd.apk" -C "$R" usr/sbin/hostapd 2> /dev/null # noscan patch (build/hostapd)
grep -q noscan "$R/usr/sbin/hostapd" || { echo "hostapd: not the noscan build"; exit 1; }
if [ -f "$W/bins.tgz" ]; then # tailscaled, dstatus-agent (the M2 set; its old third program is dropped)
	tar -xzf "$W/bins.tgz" -C "$R" 2> /dev/null
	rm -f "$R/usr/bin/lucky"
	for f in $(tar -tzf "$W/bins.tgz" 2> /dev/null); do
		[ -f "$R/$f" ] && chown 0:0 "$R/$f" && file "$R/$f" | sed 's#^/w/rootfs##'
	done
	[ -e "$R/usr/sbin/tailscaled" ] && ln -sf tailscaled "$R/usr/sbin/tailscale"
fi
# MT7986 watchdog register access for sysupgrade's kexec hand-over (tools/devmem.c)
mkdir -p "$R/usr/libexec/mr"
cc -Os -s -Wall -o "$R/usr/libexec/mr/devmem" "$REPO/tools/devmem.c"
chmod 0700 "$R/usr/libexec/mr/devmem"

# every repo rootfs file (init scripts, hooks, web UI, preinit, sysupgrade), owned by root
cp -a "$REPO/rootfs/." "$R/"
(cd "$REPO/rootfs" && find . -mindepth 1) | while read -r f; do chown -h 0:0 "$R/$f"; done
ln -sfn mr-preinit "$R/sbin/init"   # the kernel runs /sbin/init (flash) or /init (initramfs)
ln -sfn /sbin/mr-preinit "$R/init"
mkdir -p "$R/rom" "$R/overlay" "$R/mnt" "$R/var/empty" "$R/root/.ssh"
chmod 0700 "$R/root" "$R/root/.ssh"
rm -f "$R/dev/console" "$R/dev/null" "$R/dev/kmsg"
mknod -m 0600 "$R/dev/console" c 5 1
mknod -m 0666 "$R/dev/null" c 1 3
mknod -m 0644 "$R/dev/kmsg" c 1 11

# unprivileged proxy service (docs/modules/proxy.md): no shell, no home
chroot "$R" addgroup -S sing-box
chroot "$R" adduser -S -D -H -h /var/empty -s /sbin/nologin -G sing-box -g sing-box sing-box
# unprivileged HTTPS reverse proxy (services.edge, docs/modules/sys.md): no shell, no home
chroot "$R" addgroup -S mr-edge
chroot "$R" adduser -S -D -H -h /var/empty -s /sbin/nologin -G mr-edge -g mr-edge mr-edge
sed -i 's#^root:[^:]*:#root:*:#' "$R/etc/shadow" # no password: SSH keys only

# serial console: a root shell on Enter (physical access = the U-Boot failsafe anyway); no VT gettys
sed -i -e '/^tty[1-6]/d' -e '/ttyS0/d' "$R/etc/inittab"
echo 'ttyS0::askfirst:/bin/sh -l' >> "$R/etc/inittab"

# factory configuration: render it inside the image and enable exactly its services
mkdir -p "$R/etc/mini-router"
install -m 0644 "$REPO/build/m3/router.yaml" "$R/etc/mini-router/router.yaml"
touch "$R/etc/router-changes.log"
chroot "$R" /usr/sbin/mr validate
chroot "$R" /usr/sbin/mr render /
for s in devfs dmesg mdev hwdrivers; do ln -sfn "/etc/init.d/$s" "$R/etc/runlevels/sysinit/$s"; done
for s in modules sysctl hostname bootmisc syslog localmount mr-clock seedrng; do
	[ -e "$R/etc/init.d/$s" ] || { echo "missing boot service $s"; exit 1; }
	ln -sfn "/etc/init.d/$s" "$R/etc/runlevels/boot/$s"
done
ln -sfn /etc/init.d/killprocs "$R/etc/runlevels/shutdown/killprocs"
while read -r s; do
	[ -e "$R/etc/init.d/$s" ] || { echo "factory config: missing init script $s"; exit 1; }
	ln -sfn "/etc/init.d/$s" "$R/etc/runlevels/default/$s"
done < "$R/etc/mini-router/gen/services"
echo "factory services: $(tr '\n' ' ' < "$R/etc/mini-router/gen/services")"

# every feature of the home and lab configs must find its init script and daemon in this image
mkdir -p /etc/mini-router/dns
cp "$REPO/mr/testdata/split.domains" /etc/mini-router/dns/cloudflare-dot.domains
sed "s#@REPO@#$REPO#g" "$REPO"/examples/lab.d/*.yaml > /tmp/lab.yaml
cat "$REPO/mr/testdata/secrets.yaml" "$REPO"/mr/testdata/secrets.d/*.yaml > /tmp/lab-secrets.yaml 2> /dev/null ||
	cp "$REPO/mr/testdata/secrets.yaml" /tmp/lab-secrets.yaml
# (home = the user's real config: a gap fails the build; lab = every feature: gaps are reported)
: > "$W/feature-gaps.txt"
for cfg in "home $REPO/examples/router.yaml $REPO/mr/testdata/secrets.yaml" "lab /tmp/lab.yaml /tmp/lab-secrets.yaml"; do
	# shellcheck disable=SC2086
	set -- $cfg
	rm -rf "/tmp/$1" && "$W/mr" -c "$2" -s "$3" render "/tmp/$1" > /dev/null
	gaps=
	while read -r s; do
		f=$R/etc/init.d/$s
		[ -e "$f" ] || f=/tmp/$1/etc/init.d/$s
		if [ ! -e "$f" ]; then
			gaps="$gaps $s(no /etc/init.d/$s)"
			continue
		fi
		cmd=$(sed -n 's/^command=["'"'"']\{0,1\}\([^ "'"'"']*\).*/\1/p' "$f" | head -1)
		case $cmd in
		*'$'*) cmd=$(printf '%s' "$cmd" | sed 's/\${\{0,1\}\(RC_\)\{0,1\}SVCNAME[^}/]*}\{0,1\}/'"${s%%.*}"'/') ;;
		esac
		case $cmd in /*) [ -e "$R$cmd" ] || gaps="$gaps $s(no $cmd)" ;; esac
	done < "/tmp/$1/etc/mini-router/gen/services"
	n=$(wc -l < "/tmp/$1/etc/mini-router/gen/services")
	if [ -z "$gaps" ]; then
		echo "$1 config: every service present ($n)"
	else
		echo "$1 config: $n services, missing in the image:$gaps" | tee -a "$W/feature-gaps.txt"
		# the example home config uses add-ons (tailscale, dstatus, …): required only when they are bundled
		[ "$1" != home ] || [ -z "${MR_ADDONS:-}" ] || exit 1
	fi
done

# release info
cat > "$R/etc/mini-router-release" << EOF
MR_VERSION=${MR_IMAGE_VERSION:-dev}
MR_KERNEL=$KVER
MR_BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF

# minus unused bits
rm -rf "$R/var/cache/apk"/* "$R/usr/share/man" "$R/usr/share/doc" "$R/usr/share/info" \
	"$R/usr/include" "$R/usr/lib/pkgconfig" "$R/usr/share/pkgconfig"
find "$R" -name '*.a' -delete
rm -rf "$R/lib/modules/$KVER/build" "$R/lib/modules/$KVER/source"
echo "rootfs tree ready: $(du -sk "$R" | cut -f1) KiB (images: build/m3/pack.sh)"
