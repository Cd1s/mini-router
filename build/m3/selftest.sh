#!/bin/sh
# M3 self-test on the build host: the image's real sysupgrade, factory-reset and mr-preinit against a
# simulated NAND (nandsim, 880 x 128 KiB like the AX6000's "ubi" partition). Needs root and docker;
# loads nandsim/ubi/ubifs into the host kernel while it runs (one run at a time, refuses when UBI is
# already in use) and removes them afterwards. Not part of tools/ci.sh. Never touches a router.
#
#   ./build/m3/selftest.sh     (after build/m3/build.sh)
#
# installer — sysupgrade in a RAM root (tmpfs chroot, x86_64 Alpine tools, fake /proc/device-tree):
#   A  first flash over the OpenWrt layout with --data: rootfs grows, rootfs_data recreated + seeded
#   B  upgrade in place: both volumes rewritten, rootfs_data kept
#   C  upgrade that must grow the volumes: rootfs_data saved to RAM and restored
#   D  -n: rootfs_data wiped (ubiupdatevol -t)
#   E  wrong board, corrupt image, --install outside a RAM root: refused, flash untouched
# preinit — the real arm64 squashfs (test inittab) under qemu-user as PID 1 of a pid namespace:
#   P1 empty rootfs_data: formatted, overlay root 0755, squashfs at /rom, writes persist
#   P2 OpenWrt's upper/ on rootfs_data: ignored
#   P3 provisioned config (.firstboot): rendered, default runlevel = its services; factory-reset -y
#   P4 the next boot after factory-reset: settings gone, factory config back
#   P5 invalid provisioned router.yaml: factory files and the marker kept
#   P6 no rootfs_data volume: tmpfs overlay
set -eu
REPO=$(cd "$(dirname "$0")/../.." && pwd)
W=${MR_PLATFORM_DIR:-/root/build/mini-router-platform}
O=$W/out/m3
T=$W/selftest
BOARD=xiaomi,redmi-router-ax6000-hanwckf
PREFIX=sysupgrade-xiaomi_redmi-router-ax6000-hanwckf
UBINUM=5 # deliberately not ubi0: everything must find the volumes by name
say() { printf '\n== %s\n' "$*"; }
fail() {
	echo "FAIL: $*"
	exit 1
}

# ======================================================================= inside the x86_64 container
inside() {
	apk add -q --no-cache mtd-utils-ubi squashfs-tools > /dev/null
	U=/dev/ubi$UBINUM
	IMG=/o/$(cd /o && ls mini-router-*-sysupgrade.tar | head -n 1)
	meta() { sed -n "s/^$1=//p" /o/mr-meta; }
	R() { # retry: the host's udev probes new UBI volumes and holds them for a moment (EBUSY)
		_try=0
		until "$@"; do
			_try=$((_try + 1))
			[ $_try -lt 5 ] || return 1
			sleep 1
		done
	}

	nodes() {
		for v in /sys/class/ubi/ubi"$UBINUM" /sys/class/ubi/ubi"$UBINUM"_*; do
			[ -e "$v/dev" ] || continue
			n=/dev/${v##*/}
			d=$(cat "$v/dev")
			[ -c "$n" ] || mknod "$n" c "${d%:*}" "${d#*:}"
		done
	}
	volid() {
		for v in /sys/class/ubi/ubi"$UBINUM"_*; do
			[ "$(cat "$v/name")" = "$1" ] && { echo "${v##*_}"; return 0; }
		done
		return 1
	}
	vsha() { head -c "$2" "$U"_"$(volid "$1")" | sha256sum | cut -d' ' -f1; }
	lebs() { cat /sys/class/ubi/ubi"$UBINUM"_"$(volid "$1")"/reserved_ebs; }
	datamount() {
		mkdir -p /data
		mount -t ubifs "ubi$UBINUM:rootfs_data" /data
	}
	attach() {
		[ -e /sys/class/ubi/ubi$UBINUM ] && ubidetach -d $UBINUM
		ubiformat "/dev/mtd$MTD" -y -q > /dev/null
		ubiattach -m "$MTD" -d $UBINUM > /dev/null
		nodes
	}
	layout_openwrt() { # the flashed system today: OpenWrt kernel/rootfs sized to fit, rootfs_data = rest
		attach
		R ubimkvol $U -N kernel -s "$(wc -c < /t/owrt-kernel)" > /dev/null
		R ubimkvol $U -N rootfs -s "$(wc -c < /t/owrt-root)" > /dev/null
		R ubimkvol $U -N rootfs_data -m > /dev/null
		nodes
		R ubiupdatevol "$U"_"$(volid kernel)" /t/owrt-kernel
		R ubiupdatevol "$U"_"$(volid rootfs)" /t/owrt-root
		datamount
		mkdir -p /data/upper/etc/config /data/work
		echo "config interface 'lan'" > /data/upper/etc/config/network
		umount /data
	}
	check_volumes() {
		[ "$(vsha kernel "$(meta KERNEL_SIZE)")" = "$(meta KERNEL_SHA256)" ] || fail "$1: kernel volume content"
		[ "$(vsha rootfs "$(meta ROOT_SIZE)")" = "$(meta ROOT_SHA256)" ] || fail "$1: rootfs volume content"
	}

	# RAM root for the installer: tmpfs chroot with this container's tools; /proc/device-tree is faked
	ramroot() {
		mkdir -p /ram
		mount -t tmpfs -o size=512m tmpfs /ram
		cp -a /bin /sbin /lib /usr /etc /ram/
		mkdir -p /ram/proc /ram/proc-real /ram/sys /ram/dev /ram/tmp /ram/mnt /ram/o /ram/repo /ram/t
		mount -t proc proc /ram/proc-real
		for d in sys dev o repo t; do mount --bind "/$d" "/ram/$d"; done
		ln -s /proc-real/self /ram/proc/self
		ln -s /proc-real/self/mounts /ram/proc/mounts
		mkdir -p /ram/proc/device-tree /ram/proc/sys/vm
		printf '%s\0mediatek,mt7986a\0' "$BOARD" > /ram/proc/device-tree/compatible
		: > /ram/proc/sys/vm/drop_caches
	}
	su_ram() { chroot /ram /bin/sh /repo/rootfs/usr/libexec/mr/sysupgrade -y --no-reboot "$@"; }

	say "provisioning directory -> overlay.tar.gz (home config, test secrets)"
	P=/t/prov
	mkdir -p "$P/etc/mini-router/dns" "$P/root/.ssh" /t/prov-out
	cp /repo/examples/router.yaml "$P/etc/mini-router/router.yaml"
	cp /repo/mr/testdata/secrets.yaml "$P/etc/mini-router/secrets.yaml"
	cp /repo/mr/testdata/split.domains "$P/etc/mini-router/dns/cloudflare-dot.domains"
	echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIselftest selftest' > "$P/root/.ssh/authorized_keys"
	sh /repo/tools/provision.sh -o /t/prov-out "$P" > /dev/null

	ramroot
	say "A: first flash over the OpenWrt layout (--data)"
	layout_openwrt
	r0=$(lebs rootfs)
	cat "$U"_"$(volid rootfs_data)" > /t/owrt-data # whole-volume dump, like the router backups (for R)
	su_ram --data /t/prov-out/overlay.tar.gz "$IMG"
	nodes
	check_volumes A
	[ "$(lebs rootfs)" -gt "$r0" ] || fail "A: rootfs did not grow"
	datamount
	[ -f /data/mr/upper/etc/mini-router/router.yaml ] || fail "A: provisioned config missing"
	[ -f /data/mr/upper/etc/mini-router/.firstboot ] || fail "A: .firstboot missing"
	[ "$(stat -c %a /data/mr/upper/etc/mini-router/secrets.yaml)" = 600 ] || fail "A: secrets.yaml mode"
	[ "$(stat -c %a /data/mr/upper)" = 755 ] || fail "A: upper dir mode"
	[ "$(stat -c %a /data/mr/upper/etc)" = 755 ] || fail "A: upper etc mode"
	[ ! -e /data/upper ] || fail "A: OpenWrt overlay survived --data"
	grep -q "sysupgrade: installed mini-router $(meta MR_VERSION)" /data/mr/upper/etc/router-changes.log || fail "A: change log"
	umount /data
	echo "A ok: rootfs $r0 -> $(lebs rootfs) LEBs, rootfs_data $(lebs rootfs_data) LEBs"

	say "B: upgrade in place keeps rootfs_data"
	datamount && echo keep > /data/mr/upper/etc/keepme && umount /data
	# make the volumes differ from the image so a missing write shows
	R ubiupdatevol "$U"_"$(volid kernel)" /t/owrt-kernel
	R ubiupdatevol "$U"_"$(volid rootfs)" /t/owrt-root
	su_ram "$IMG"
	nodes
	check_volumes B
	datamount
	[ "$(cat /data/mr/upper/etc/keepme)" = keep ] || fail "B: rootfs_data not kept"
	[ "$(grep -c 'sysupgrade: installed' /data/mr/upper/etc/router-changes.log)" = 2 ] || fail "B: change log"
	umount /data
	echo "B ok"

	say "C: volumes too small: rootfs_data saved and restored"
	R ubirmvol $U -N rootfs_data
	R ubirsvol $U -N rootfs -S 100
	R ubirsvol $U -N kernel -S 10
	R ubimkvol $U -N rootfs_data -m > /dev/null
	nodes
	datamount
	mkdir -p /data/mr/upper/etc /data/mr/work
	echo restore-me > /data/mr/upper/etc/keep2
	head -c 1048576 /dev/urandom > /data/mr/upper/etc/blob
	bsum=$(sha256sum < /data/mr/upper/etc/blob)
	umount /data
	su_ram "$IMG" | tee /t/C.log
	grep -q 'saving rootfs_data to RAM' /t/C.log || fail "C: no backup step"
	nodes
	check_volumes C
	datamount
	[ "$(cat /data/mr/upper/etc/keep2)" = restore-me ] || fail "C: file not restored"
	[ "$(sha256sum < /data/mr/upper/etc/blob)" = "$bsum" ] || fail "C: blob not restored"
	umount /data
	echo "C ok: kernel $(lebs kernel), rootfs $(lebs rootfs), rootfs_data $(lebs rootfs_data) LEBs"

	say "D: -n wipes rootfs_data"
	su_ram -n "$IMG"
	nodes
	check_volumes D
	datamount
	[ -z "$(ls -A /data)" ] || fail "D: rootfs_data not empty: $(ls -A /data)"
	umount /data
	echo "D ok"

	say "E: refusals leave the flash untouched"
	ks=$(vsha kernel "$(meta KERNEL_SIZE)") rs=$(vsha rootfs "$(meta ROOT_SIZE)")
	printf 'xiaomi,mi-router-ax3000t\0mediatek,mt7981\0' > /ram/proc/device-tree/compatible
	if su_ram "$IMG" > /t/E1.log 2>&1; then fail "E: wrong board accepted"; fi
	grep -q "is not $BOARD" /t/E1.log || fail "E: wrong board message: $(cat /t/E1.log)"
	printf '%s\0mediatek,mt7986a\0' "$BOARD" > /ram/proc/device-tree/compatible
	cp "$IMG" /t/bad.tar
	sz=$(wc -c < /t/bad.tar)
	printf 'X' | dd of=/t/bad.tar bs=1 seek=$((sz - 20000)) conv=notrunc 2> /dev/null
	if su_ram /t/bad.tar > /t/E2.log 2>&1; then fail "E: corrupt image accepted"; fi
	grep -q "sha256 mismatch\|size differs\|bad magic" /t/E2.log || fail "E: corrupt image message: $(cat /t/E2.log)"
	if sh /repo/rootfs/usr/libexec/mr/sysupgrade --install /t > /t/E3.log 2>&1; then fail "E: --install ran outside RAM"; fi
	grep -q "only runs from a RAM root" /t/E3.log || fail "E: --install message"
	if sh /repo/rootfs/usr/libexec/mr/factory-reset -y --no-reboot > /t/E4.log 2>&1; then fail "E: factory-reset outside flash"; fi
	[ "$(vsha kernel "$(meta KERNEL_SIZE)")" = "$ks" ] && [ "$(vsha rootfs "$(meta ROOT_SIZE)")" = "$rs" ] || fail "E: flash changed"
	echo "E ok"

	say "R: rollback — tools/ubi-restore.sh puts the saved OpenWrt volumes back"
	chroot /ram /bin/sh /repo/tools/ubi-restore.sh -y /t/owrt-kernel /t/owrt-root /t/owrt-data
	nodes
	[ "$(vsha kernel "$(wc -c < /t/owrt-kernel)")" = "$(sha256sum < /t/owrt-kernel | cut -d' ' -f1)" ] || fail "R: kernel"
	[ "$(vsha rootfs "$(wc -c < /t/owrt-root)")" = "$(sha256sum < /t/owrt-root | cut -d' ' -f1)" ] || fail "R: rootfs"
	[ "$(volid kernel)/$(volid rootfs)/$(volid rootfs_data)" = 0/1/2 ] || fail "R: volume ids"
	datamount
	grep -q "config interface 'lan'" /data/upper/etc/config/network || fail "R: OpenWrt overlay not restored"
	umount /data
	echo "R ok: OpenWrt kernel/rootfs/rootfs_data restored from dumps"

	# ------------------------------------------------------------------ preinit
	say "test squashfs: the image's root with a probe instead of OpenRC"
	rm -rf /t/sq-tree
	unsquashfs -q -d /t/sq-tree /o/root.squashfs > /dev/null
	echo '::sysinit:/bin/sh /selftest-probe' > /t/sq-tree/etc/inittab
	cat > /t/sq-tree/selftest-probe << 'PROBE'
R=/rom/srv
awk '{ print $1, $2, $3 }' /proc/mounts > $R/mounts
stat -c '%a %u %g' / > $R/rootmode
cat /etc/mini-router/gen/services > $R/services 2>&1
ls /etc/runlevels/default > $R/default 2>&1
if [ -e /etc/mini-router/.firstboot ]; then echo yes; else echo no; fi > $R/firstboot
grep -m1 'ipv4:' /etc/mini-router/router.yaml > $R/lan 2>&1
if [ -e /etc/config/network ]; then echo visible; else echo hidden; fi > $R/foreign
if touch /probe-was-here; then echo ok; else echo fail; fi > $R/writable
[ -e /selftest-factory-reset ] && /usr/libexec/mr/factory-reset -y --no-reboot > $R/factory-reset 2>&1
echo done > $R/done
sync
reboot -f
PROBE
	mksquashfs /t/sq-tree /t/test.squashfs -comp gzip -noappend -no-xattrs -quiet -no-progress > /dev/null
	boot() { # boot NAME: run /sbin/init of the test squashfs as PID 1; results in /t/res/NAME
		rm -rf "/t/res/$1" && mkdir -p "/t/res/$1" /sq
		lo=$(losetup -f) # the container's /dev predates new loop devices: make the node
		[ -b "$lo" ] || mknod "$lo" b 7 "${lo#/dev/loop}"
		losetup "$lo" /t/test.squashfs
		mount -t squashfs -o ro "$lo" /sq
		mount --bind "/t/res/$1" /sq/srv
		# preinit logs to /dev/kmsg, i.e. the host's kernel log: take the lines after t0 (never cleared)
		t0=$(cut -d' ' -f1 /proc/uptime)
		timeout 300 unshare -p -f -m --propagation private chroot /sq /sbin/init > /dev/null 2>&1 || :
		dmesg | awk -v t0="$t0" '{ t = $0; sub(/^\[ */, "", t); sub(/\].*/, "", t) } t + 0 >= t0 - 1 && /mr-preinit/' \
			> "/t/res/$1/kmsg" || :
		umount /sq/srv && umount /sq && losetup -d "$lo"
		[ -f "/t/res/$1/done" ] || fail "$1: the probe did not run (kmsg: $(cat "/t/res/$1/kmsg"))"
	}
	has() { grep -q "$2" "/t/res/$1/$3" || fail "$1: $3 lacks '$2': $(cat "/t/res/$1/$3")"; }
	fresh() { # empty kernel/rootfs/rootfs_data like after a flash with -n
		attach
		R ubimkvol $U -N kernel -s 5MiB > /dev/null
		R ubimkvol $U -N rootfs -s 64MiB > /dev/null
		[ "${1:-}" = nodata ] || R ubimkvol $U -N rootfs_data -m > /dev/null
		nodes
	}

	say "P1: empty rootfs_data"
	fresh
	boot P1
	has P1 '^overlay / overlay$' mounts
	has P1 ' /rom squashfs$' mounts
	has P1 "^ubi$UBINUM:rootfs_data /overlay ubifs$" mounts
	has P1 '^755 0 0$' rootmode
	has P1 '192.168.31.1' lan
	has P1 '^ok$' writable
	has P1 '^mr-panel$' default
	datamount
	[ -e /data/mr/upper/probe-was-here ] || fail "P1: write did not reach rootfs_data"
	umount /data
	echo "P1 ok"

	say "P2: OpenWrt's overlay on rootfs_data is ignored"
	layout_openwrt
	boot P2
	has P2 '^hidden$' foreign
	has P2 '^overlay / overlay$' mounts
	datamount
	[ -d /data/upper/etc/config ] && [ -d /data/mr/upper ] || fail "P2: layout"
	umount /data
	echo "P2 ok"

	say "P3: provisioned config is rendered at first boot; then factory-reset -y"
	fresh
	datamount
	mkdir -p /data/mr/upper /data/mr/work
	tar -C /data/mr/upper -xzf /t/prov-out/overlay.tar.gz
	touch /data/mr/upper/selftest-factory-reset
	umount /data
	boot P3
	has P3 '^no$' firstboot
	has P3 '192.168.1.6' lan
	for s in mr-pppoe.wan mr-pppoe.wan2 tailscale lucky stubby dropbear mr-panel; do has P3 "^$s\$" default; done
	sort "/t/res/P3/services" > /t/s1 && sort "/t/res/P3/default" > /t/s2
	cmp -s /t/s1 /t/s2 || fail "P3: default runlevel != gen/services: $(diff /t/s1 /t/s2 | tr '\n' ' ')"
	has P3 'wiped at the next boot' factory-reset
	has P3 'applied the provisioned router.yaml' kmsg
	echo "P3 ok ($(wc -l < /t/res/P3/default) services)"

	say "P4: the boot after factory-reset"
	boot P4
	has P4 'factory reset' kmsg
	has P4 '192.168.31.1' lan
	has P4 '^mr-panel$' default
	if grep -q '^tailscale$' /t/res/P4/default; then fail "P4: provisioned services survived"; fi
	datamount
	[ ! -e /data/.mr-factory-reset ] || fail "P4: flag still set"
	[ ! -e /data/mr/upper/etc/mini-router/secrets.yaml ] || fail "P4: secrets survived"
	umount /data
	echo "P4 ok ($(grep -o 'wiping.*' /t/res/P4/kmsg | head -n 1))"

	say "P5: invalid provisioned router.yaml"
	fresh
	datamount
	mkdir -p /data/mr/upper/etc/mini-router /data/mr/work
	echo 'lan: [' > /data/mr/upper/etc/mini-router/router.yaml
	: > /data/mr/upper/etc/mini-router/.firstboot
	umount /data
	boot P5
	has P5 '^yes$' firstboot
	has P5 '^mr-panel$' default
	has P5 'invalid, keeping the factory files' kmsg
	echo "P5 ok"

	say "P6: no rootfs_data volume"
	fresh nodata
	boot P6
	has P6 '^tmpfs /overlay tmpfs$' mounts
	has P6 '^overlay / overlay$' mounts
	has P6 '^ok$' writable
	has P6 'rootfs_data unavailable' kmsg
	echo "P6 ok"

	ubidetach -d $UBINUM
	umount /ram/proc-real /ram/sys /ram/dev /ram/o /ram/repo /ram/t 2> /dev/null || :
	say "all self-tests passed"
}

if [ "${1:-}" = --inside ]; then
	inside
	exit 0
fi

# ======================================================================= host
[ "$(id -u)" = 0 ] || fail "run as root"
[ -n "$(ls "$O"/mini-router-*-sysupgrade.tar 2> /dev/null)" ] || fail "build the image first (build/m3/build.sh)"
if lsmod | grep -q '^nandsim '; then fail "nandsim is already loaded"; fi
if [ -n "$(ls /sys/class/ubi 2> /dev/null)" ]; then fail "UBI is in use on this host"; fi
OWRT=/root/build/owrt-main/src/bin/targets/mediatek/filogic/openwrt-mediatek-filogic-xiaomi_redmi-router-ax6000-hanwckf-squashfs-sysupgrade.bin
rm -rf "$T" && mkdir -p "$T/res"
tar -xOf "$OWRT" "$PREFIX/kernel" > "$T/owrt-kernel"
tar -xOf "$OWRT" "$PREFIX/root" > "$T/owrt-root"

loaded=
cleanup() {
	docker run --rm --privileged alpine:3.24 sh -c \
		"apk add -q --no-cache mtd-utils-ubi > /dev/null; [ -e /sys/class/ubi/ubi$UBINUM ] && ubidetach -d $UBINUM" > /dev/null 2>&1 || :
	for m in $loaded; do rmmod "$m" 2> /dev/null || :; done
}
trap cleanup EXIT
for m in ubifs ubi nandsim; do lsmod | grep -q "^$m " || loaded="$loaded $m"; done
# 128 KiB blocks, 2 KiB pages (like the AX6000's SPI-NAND); first partition = 880 blocks = 110 MiB
modprobe nandsim first_id_byte=0x2c second_id_byte=0xda third_id_byte=0x90 fourth_id_byte=0x95 parts=880
modprobe ubi
modprobe ubifs
MTD=$(sed -n 's/^mtd\([0-9]*\): .*"NAND simulator partition 0"$/\1/p' /proc/mtd)
[ -n "$MTD" ] || fail "nandsim partition not found"
docker run --rm --privileged -e MTD="$MTD" -v "$REPO:/repo:ro" -v "$O:/o:ro" -v "$T:/t" alpine:3.24 \
	sh /repo/build/m3/selftest.sh --inside
