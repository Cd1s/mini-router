#!/bin/sh
# ubi-restore.sh [-y] KERNEL ROOTFS [ROOTFS_DATA] — put saved UBI volumes back, e.g. the OpenWrt system
# that was on the flash before mini-router (platform, docs/flash.md "回滚").
#
# Run on the router from a RAM system (the M3 kexec test initramfs, or the M2 test system after
# `apk add mtd-utils-ubi`): the volumes cannot be rewritten while a flash root uses them. The three
# volumes kernel / rootfs / rootfs_data are removed and recreated (ids 0 / 1 / 2, each exactly as big
# as its file, rounded up to whole LEBs; rootfs_data takes the rest of the flash when no file is
# given, and is then formatted by the next system), written, and read back against sha256.
# The files are whole-volume dumps (`cat /dev/ubi0_N > file`) or exact images; either works.
set -u
PATH=/usr/sbin:/usr/bin:/sbin:/bin
umask 022
die() {
	echo "ubi-restore: $*" >&2
	exit 1
}
yes=0
[ "${1:-}" = -y ] && { yes=1; shift; }
[ $# -ge 2 ] && [ $# -le 3 ] || die "usage: ubi-restore.sh [-y] KERNEL ROOTFS [ROOTFS_DATA]"
K=$1 R=$2 D=${3:-}
for f in "$K" "$R" ${D:+"$D"}; do [ -s "$f" ] || die "$f: missing or empty"; done
[ "$(id -u)" = 0 ] || die "must run as root"
case $(awk '$2 == "/" { t = $3 } END { print t }' /proc/mounts) in
rootfs | tmpfs | ramfs) ;;
*) die "/ is not a RAM root: boot the kexec test system first" ;;
esac
command -v ubimkvol > /dev/null || die "ubimkvol missing (apk add mtd-utils-ubi)"

UBI=
for v in /sys/class/ubi/ubi*_*; do
	[ -r "$v/name" ] || continue
	n=${v##*/}
	if [ "$(cat "$v/name")" = rootfs ] && { [ -z "${MR_UBI:-}" ] || [ "${n%_*}" = "$MR_UBI" ]; }; then
		UBI=${n%_*}
		break
	fi
done
[ -n "$UBI" ] || die "no UBI device with a rootfs volume"
node() {
	[ -c "/dev/$1" ] && return 0
	d=$(cat "/sys/class/ubi/$1/dev") && mknod "/dev/$1" c "${d%:*}" "${d#*:}"
}
# retry CMD...: a hotplug helper probing a new volume can hold it for a moment (EBUSY)
retry() {
	_try=0
	until "$@"; do
		_try=$((_try + 1))
		[ $_try -lt 5 ] || return 1
		sleep 1
	done
}
node "$UBI" || die "cannot create /dev/$UBI"
if grep -q "^$UBI:\|^/dev/${UBI}_" /proc/mounts; then die "a volume of $UBI is mounted"; fi
leb=$(cat "/sys/class/ubi/$UBI/eraseblock_size")
total=$(cat "/sys/class/ubi/$UBI/avail_eraseblocks")
for v in /sys/class/ubi/"$UBI"_*; do
	[ -r "$v/reserved_ebs" ] && total=$((total + $(cat "$v/reserved_ebs")))
done
need=0
for f in "$K" "$R" ${D:+"$D"}; do need=$((need + ($(wc -c < "$f") + leb - 1) / leb)); done
[ "$need" -le "$total" ] || die "the files need $need LEBs, $UBI has $total"

echo "ubi-restore: $UBI ($total LEBs of $leb bytes): kernel <- $K, rootfs <- $R, rootfs_data <- ${D:-empty}"
if [ "$yes" = 0 ]; then
	printf 'This replaces the whole system on the flash. Type YES: '
	read -r ans
	[ "$ans" = YES ] || die "aborted"
fi
for v in /sys/class/ubi/"$UBI"_*; do
	[ -r "$v/name" ] || continue
	id=${v##*_}
	if [ -e "/sys/block/ubiblock${UBI#ubi}_$id" ]; then
		node "${UBI}_$id" && ubiblock -r "/dev/${UBI}_$id" || die "cannot remove ubiblock${UBI#ubi}_$id"
	fi
done
for n in rootfs_data rootfs kernel; do
	for v in /sys/class/ubi/"$UBI"_*; do
		[ -r "$v/name" ] && [ "$(cat "$v/name")" = "$n" ] && { retry ubirmvol "/dev/$UBI" -N "$n" || die "ubirmvol $n failed"; }
	done
done
write() { # write ID NAME FILE
	retry ubimkvol "/dev/$UBI" -n "$1" -N "$2" -s "$(wc -c < "$3")" > /dev/null || die "ubimkvol $2 failed"
	node "${UBI}_$1" || die "cannot create /dev/${UBI}_$1"
	retry ubiupdatevol "/dev/${UBI}_$1" "$3" || die "writing $2 failed"
	[ "$(head -c "$(wc -c < "$3")" "/dev/${UBI}_$1" | sha256sum | cut -d' ' -f1)" = "$(sha256sum < "$3" | cut -d' ' -f1)" ] ||
		die "$2: read-back differs"
	echo "ubi-restore: $2 written and verified"
}
write 0 kernel "$K"
write 1 rootfs "$R"
if [ -n "$D" ]; then
	write 2 rootfs_data "$D"
else
	retry ubimkvol "/dev/$UBI" -n 2 -N rootfs_data -m > /dev/null || die "ubimkvol rootfs_data failed"
	echo "ubi-restore: rootfs_data created empty"
fi
sync
echo "ubi-restore: done; reboot to start the restored system"
