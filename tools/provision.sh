#!/bin/sh
# provision.sh [-o OUTDIR] DIR — pack a router's config and service state for a mini-router image,
# so secrets never go into build artifacts (platform, docs/flash.md).
#
# DIR mirrors the router's filesystem below etc/, root/, var/lib/ and usr/local/, e.g.
#   etc/mini-router/router.yaml  (required)      etc/mini-router/secrets.yaml
#   etc/mini-router/dns/*.domains                etc/mini-router/proxy/*.domains|*.cidrs
#   root/.ssh/authorized_keys                    etc/dropbear/dropbear_*_host_key (keep the SSH host key)
#   etc/tailscale/tailscaled.state               etc/lucky/...   etc/dstatus-agent/config.yaml
# Writes, 0600, into OUTDIR (default .):
#   provision.cpio   append to the M3 test initramfs (tools/kexec-test.sh INITRAMFS provision.cpio)
#   overlay.tar.gz   the start of rootfs_data on flash (sysupgrade --data overlay.tar.gz IMAGE)
# Both add etc/mini-router/.firstboot: the first boot renders router.yaml and enables its services.
# Everything is owned by root; directories 0755 (root/, root/.ssh, etc/dropbear, etc/tailscale 0700);
# files 0644 or 0755 if executable; secrets 0600 (secrets.yaml, *_host_key, authorized_keys, *.key,
# *.pem, *.state, open-token, *secrets, etc/dstatus-agent/*, etc/lucky/*.lkcf and the private dirs).
# Refused: symlinks / device nodes, odd characters in names, paths outside the four trees, and files
# that must come from the image (etc/passwd, etc/shadow, etc/group, etc/inittab, etc/fstab,
# etc/init.d, etc/runlevels, etc/apk, and OpenWrt's etc/config, etc/rc.d).
# Works with GNU or BSD (macOS) cpio/tar; with busybox it must run as root.
set -eu
umask 077
die() {
	echo "provision: $*" >&2
	exit 1
}

out=.
if [ "${1:-}" = -o ]; then
	[ $# -ge 2 ] || die "-o OUTDIR"
	out=$2
	shift 2
fi
[ $# -eq 1 ] || die "usage: provision.sh [-o OUTDIR] DIR"
src=$1
[ -d "$src" ] || die "$src: not a directory"
[ -d "$out" ] || die "$out: not a directory"
[ -f "$src/etc/mini-router/router.yaml" ] || die "$src/etc/mini-router/router.yaml missing"
out=$(cd "$out" && pwd)

cd "$src"
bad=$(find . -mindepth 1 ! -type f ! -type d | head -n 3)
[ -z "$bad" ] || die "only plain files and directories allowed (no symlinks or devices): $bad"
bad=$(find . -mindepth 1 -name '*[!A-Za-z0-9._@+=:,-]*' | head -n 3)
[ -z "$bad" ] || die "unsupported character in a name (letters, digits and ._@+=:,- only): $bad"
bad=$(find . -mindepth 1 ! -path ./etc ! -path './etc/*' ! -path ./root ! -path './root/*' \
	! -path ./var ! -path ./var/lib ! -path './var/lib/*' ! -path ./usr ! -path ./usr/local ! -path './usr/local/*' | head -n 3)
[ -z "$bad" ] || die "only etc/, root/, var/lib/ and usr/local/ may be provisioned: $bad"
for p in etc/passwd etc/shadow etc/group etc/inittab etc/fstab etc/init.d etc/runlevels etc/apk etc/config etc/rc.d; do
	[ ! -e "$p" ] || die "$p must come from the image, not from provisioning"
done

tmp=$(mktemp -d "${TMPDIR:-/tmp}/provision.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
st=$tmp/root
mkdir "$st"
cp -R . "$st/"
cd "$st"
: > etc/mini-router/.firstboot

execs=$(find . -type f -perm -0100) # cp -R keeps the owner's x bit (names hold no whitespace)
find . -type d -exec chmod 0755 {} +
find . -type f -exec chmod 0644 {} +
for f in $execs; do chmod 0755 "$f"; done
for d in root root/.ssh etc/dropbear etc/tailscale; do
	if [ -d "$d" ]; then
		chmod 0700 "$d"
		find "$d" -type f -exec chmod 0600 {} +
	fi
done
find . -type f \( -name secrets.yaml -o -name authorized_keys -o -name '*_host_key' -o -name '*.key' \
	-o -name '*.pem' -o -name '*.state' -o -name open-token -o -name '*secrets' \
	-o -path './etc/dstatus-agent/*' -o -path './etc/lucky/*.lkcf' \) -exec chmod 0600 {} +
chmod 0755 .
[ "$(id -u)" != 0 ] || chown -R 0:0 .

# cpio (newc) and tar.gz, both owned by root:root whatever user runs this
own_cpio=
if echo . | cpio -o -H newc -R 0:0 > /dev/null 2>&1; then
	own_cpio="-R 0:0"
elif [ "$(id -u)" != 0 ]; then
	die "this cpio cannot set the owner (-R): run as root or use GNU/BSD cpio"
fi
# shellcheck disable=SC2086
find . | LC_ALL=C sort | cpio -o -H newc $own_cpio > "$out/provision.cpio" 2> /dev/null ||
	die "cpio failed"
case $(tar --version 2> /dev/null | head -n 1) in
*GNU*) set -- --format=gnu --owner=0 --group=0 --numeric-owner ;;
*bsdtar*) set -- --format=ustar --uid 0 --gid 0 --uname root --gname root --no-xattrs --no-mac-metadata ;;
*)
	[ "$(id -u)" = 0 ] || die "this tar cannot set the owner: run as root or use GNU/BSD tar"
	set --
	;;
esac
COPYFILE_DISABLE=1 tar "$@" -czf "$out/overlay.tar.gz" . || die "tar failed"
chmod 0600 "$out/provision.cpio" "$out/overlay.tar.gz"

echo "provisioned (owner root):"
find . -mindepth 1 -type f | LC_ALL=C sort | while read -r f; do
	printf '  %s %s\n' "$(ls -l "$f" | cut -c1-10)" "${f#./}"
done
echo "wrote $out/provision.cpio and $out/overlay.tar.gz (they contain secrets: keep them off git, delete after use)"
