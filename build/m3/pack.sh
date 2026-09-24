#!/bin/sh
# M3 images from the finished tree /w/rootfs (build-rootfs.sh). Runs in a native alpine:3.24 container
# started by build/m3/build.sh (the tree is plain data; compressing under qemu would be 10x slower):
#   /w/root.squashfs     UBI volume "rootfs": xz, 256 KiB blocks (as OpenWrt), no xattrs. No BCJ
#                        filter: this kernel has no CONFIG_XZ_DEC_ARM64 (see docs/modules/platform.md)
#   /w/initramfs.cpio.xz the same tree for the kexec test (crc32: the kernel's xz decoder needs it)
#   /w/sizes.txt         size report
set -eu
W=/w
R=$W/rootfs
apk add -q --no-cache squashfs-tools cpio xz > /dev/null
cd "$R"
rm -f "$W/root.squashfs" "$W/initramfs.cpio.xz"
mksquashfs "$R" "$W/root.squashfs" -comp xz -b 256K -no-xattrs -noappend -quiet -no-progress > /dev/null
find . | cpio -o -H newc 2> /dev/null | xz --check=crc32 -9e -T0 > "$W/initramfs.cpio.xz"
{
	echo "rootfs (uncompressed): $(du -sk "$R" | cut -f1) KiB"
	echo "squashfs (xz, 256K blocks): $(wc -c < "$W/root.squashfs") bytes"
	echo "initramfs.cpio.xz: $(wc -c < "$W/initramfs.cpio.xz") bytes"
	echo "-- by directory (KiB)"
	du -sk usr/bin usr/sbin usr/lib usr/libexec usr/share lib/modules lib/firmware lib bin sbin etc www 2> /dev/null | sort -rn
	echo "-- biggest files (bytes)"
	find . -type f -size +200k -exec ls -l {} + | awk '{ print $5, $9 }' | sort -rn | head -25
} > "$W/sizes.txt"
cat "$W/sizes.txt"
