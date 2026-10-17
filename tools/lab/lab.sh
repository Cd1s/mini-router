#!/bin/sh
# Isolated mini-router laboratory.  All links, addresses and daemons live in lab network namespaces;
# the host's network namespace, routes, firewall and sysctls are never touched.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
LABDIR=$ROOT/tools/lab
IMGDIR=${MR_LAB_IMAGE_DIR:-/root/build/mr-lab-images}
RUNDIR=$LABDIR/state
CLOUD=$IMGDIR/alpine-3.24-x86_64.qcow2
# lts (default): the kernel setup-alpine installs on a mini PC. virt: the cloud image's own kernel,
# which has no PPPoE (CONFIG_PPPOE is not set) — use it to reproduce what a VM user gets.
# A lab keeps the flavor it was created with (state/mrlab<ID>/flavor).
use_flavor(){
  FLAVOR=$1
  case $FLAVOR in
    lts) BASE=$IMGDIR/alpine-3.24-x86_64-lts.qcow2;;
    virt) BASE=$CLOUD;;
    *) echo "lab: MR_LAB_KERNEL must be lts or virt" >&2; exit 1;;
  esac
  KERNEL=$IMGDIR/vmlinuz-$FLAVOR
  INITRD=$IMGDIR/initramfs-$FLAVOR
}
use_flavor "${MR_LAB_KERNEL:-lts}"
MIRROR=$IMGDIR/apk-mirror
ALPINE=v3.24
# Downloads used as root on this host are pinned: fixed versions and their SHA256 (checked against
# Alpine's published .sha256 / .sha512 when pinned). A mismatch stops the command.
CDN=https://dl-cdn.alpinelinux.org/alpine/$ALPINE/releases
CLOUD_URL=$CDN/cloud/generic_alpine-3.24.1-x86_64-bios-cloudinit-r0.qcow2
CLOUD_SHA256=6e2e6fe0572b6632527f268d3659e8fccebda4e1ee470fafe2c4d7b85b6a4df6
MINIROOTFS_URL=$CDN/x86_64/alpine-minirootfs-3.24.2-x86_64.tar.gz
MINIROOTFS_SHA256=c5ca053cfe1d85c5b96dff8b9bc57045f7f184a30ffb6b65776409ca90388677
ADMIN_PASS=labpass1
mkdir -p "$IMGDIR" "$RUNDIR"

HOST_GUARD_DIR=$RUNDIR/.host-guard
HOST_GUARD_BASE=$HOST_GUARD_DIR/baseline
host_manifest(){
  sha256sum /etc/resolv.conf /etc/hosts 2>/dev/null || true
  if [ -d /etc/ppp ]; then
    find /etc/ppp \( -type f -o -type l \) -print 2>/dev/null | sort | while IFS= read -r f; do
      if [ -L "$f" ]; then printf 'link %s -> %s\n' "$f" "$(readlink "$f")"; else sha256sum "$f"; fi
    done
  fi
}
# The manifest is compared before/after every command, and against a baseline kept across commands:
# a lab daemon that changes a host file between two commands is caught by the next command.
host_guard_start(){
  mkdir -p "$HOST_GUARD_DIR"
  for f in "$HOST_GUARD_DIR"/*.before; do
    [ -e "$f" ] || continue; gp=${f##*/}; gp=${gp%.before}; [ -d "/proc/$gp" ] || rm -f "$f"
  done
  HOST_GUARD_FILE=$HOST_GUARD_DIR/$$.before
  host_manifest > "$HOST_GUARD_FILE"
  if [ "${1:-}" = guard-reset ] || [ ! -s "$HOST_GUARD_BASE" ]; then cp "$HOST_GUARD_FILE" "$HOST_GUARD_BASE"; fi
  if ! cmp -s "$HOST_GUARD_BASE" "$HOST_GUARD_FILE"; then
    echo "lab: HOST FILES CHANGED since the guard baseline (between lab commands)" >&2
    diff -u "$HOST_GUARD_BASE" "$HOST_GUARD_FILE" >&2 || true
    echo "lab: find the cause first; if the change is not a lab's: tools/lab/lab.sh guard-reset" >&2
    rm -f "$HOST_GUARD_FILE"; exit 1
  fi
}
MNT=; TMPS=
host_guard_end(){
  rc=$?
  umount_image
  # shellcheck disable=SC2086
  [ -z "$TMPS" ] || rm -rf $TMPS
  after=$HOST_GUARD_DIR/$$.after
  host_manifest > "$after"
  if ! cmp -s "$HOST_GUARD_FILE" "$after"; then
    echo "lab: HOST FILES CHANGED during this command" >&2
    diff -u "$HOST_GUARD_FILE" "$after" >&2 || true
    rc=1
  fi
  rm -f "$HOST_GUARD_FILE" "$after"
  exit "$rc"
}
host_guard_start "${1:-}"
trap host_guard_end EXIT
# dash runs the EXIT trap on exit only: turn the signals into exits
trap 'exit 130' INT; trap 'exit 143' TERM; trap 'exit 129' HUP

die(){ echo "lab: $*" >&2; exit 1; }
need(){ command -v "$1" >/dev/null 2>&1 || die "missing dependency: $1"; }
valid_id(){ case ${1:-} in 1|2|3|4|5|6|7|8) ;; *) die "lab id must be 1..8";; esac; }
state(){ echo "$RUNDIR/mrlab$1"; }
sw(){ echo "mrlab$1-sw"; }; isp(){ echo "mrlab$1-isp$2"; }; lan(){ echo "mrlab$1-lan"; }
router_ip(){ cat "$(state "$1")/lan.ip" 2>/dev/null || echo 192.168.1.1; }
run_ns(){ n=$1; shift; ip netns exec "$n" "$@"; }
pidfile(){ echo "$(state "$1")/qemu.pid"; }
# `ip netns exec` bind-mounts /etc/netns/<ns>/* over /etc/*: every lab namespace gets its own
# resolv.conf (and the ISP its own /etc/ppp) so no daemon can write the host's files.
ns_etc_setup(){
  mkdir -p "/etc/netns/$1"
  printf 'nameserver %s\n' "$2" > "/etc/netns/$1/resolv.conf"
}
ns_etc_remove(){ case $1 in mrlab[1-8]-*) rm -rf "/etc/netns/$1";; esac; }
# temp_dir VAR prefix: a new directory under the image dir, removed when the command ends
temp_dir(){ _t=$(mktemp -d "$IMGDIR/.$2.XXXXXX"); TMPS="$TMPS $_t"; eval "$1=\$_t"; }
# one read-only loop mount at a time on a fresh mount point; host_guard_end unmounts it on any exit
mount_image(){
  MNT=$(mktemp -d "$IMGDIR/.mnt.XXXXXX")
  mount -o loop,ro "$1" "$MNT" 2>/dev/null || { rmdir "$MNT"; MNT=; die "cannot mount $1"; }
}
umount_image(){
  [ -n "$MNT" ] || return 0
  umount "$MNT" 2>/dev/null || umount -l "$MNT" 2>/dev/null || true
  rmdir "$MNT" 2>/dev/null || true; MNT=
}
# The shared image directory (base images, kernels, mirror, release cache) is initialised by one
# lab command at a time.
lock_images(){ exec 9>"$IMGDIR/.build.lock"; flock 9; }
unlock_images(){ flock -u 9; }
# fetch_pinned URL SHA256 DEST
fetch_pinned(){
  _fd=; temp_dir _fd dl
  curl -fL --retry 3 -o "$_fd/f" "$1" || die "download failed: $1"
  [ "$(sha256sum < "$_fd/f" | cut -d' ' -f1)" = "$2" ] || die "SHA256 mismatch for $1 (expected $2)"
  mv "$_fd/f" "$3"
}
# verified once per file: SHA256 against the pin, remembered in <file>.ok
verify_pinned(){
  # shellcheck disable=SC3013
  [ "$1.ok" -nt "$1" ] && return 0
  [ "$(sha256sum < "$1" | cut -d' ' -f1)" = "$2" ] || die "SHA256 mismatch for $1 (expected $2): delete it to download again"
  : > "$1.ok"
}

alpine_pkgs(){
  # the lts kernel of the lab base image, the package list of install.sh step 1, then what it adds
  # afterwards (the last word: a separate step)
  echo linux-lts linux-firmware-none
  sed -n '/^PKGS="/,/"$/p' "$1/install.sh" | tr -d '"' | sed 's/^PKGS=//' | tr '\n' ' '
  echo dnsmasq-dnssec-nftset
}
ensure_cloud(){
  if [ ! -s "$CLOUD" ]; then
    need curl; need qemu-img
    echo "lab: downloading the Alpine 3.24 cloud image..." >&2
    fetch_pinned "$CLOUD_URL" "$CLOUD_SHA256" "$CLOUD"
  fi
  verify_pinned "$CLOUD" "$CLOUD_SHA256"
}
# raw_of IMG: RAW = a raw copy next to the qcow2 (for read-only loop mounts), written atomically
raw_of(){
  RAW=${1%.qcow2}.raw; _rd=
  # shellcheck disable=SC3013  # -nt: dash and busybox sh have it
  if [ ! -s "$RAW" ] || [ "$1" -nt "$RAW" ]; then temp_dir _rd raw; qemu-img convert -O raw "$1" "$_rd/r"; mv "$_rd/r" "$RAW"; fi
}
# copies /boot/vmlinuz-<flavor> and initramfs-<flavor> out of a qcow2 image
extract_boot(){
  img=$1; fl=$2
  raw_of "$img"; mount_image "$RAW"
  cp "$MNT/boot/vmlinuz-$fl" "$IMGDIR/vmlinuz-$fl.new"; cp "$MNT/boot/initramfs-$fl" "$IMGDIR/initramfs-$fl.new"
  umount_image
  mv "$IMGDIR/vmlinuz-$fl.new" "$IMGDIR/vmlinuz-$fl"; mv "$IMGDIR/initramfs-$fl.new" "$IMGDIR/initramfs-$fl"
}
# The lts base: the cloud image booted once, offline, with linux-lts installed from the mirror and
# cloud-init's state cleaned, so every lab still starts as a never-booted machine.
ensure_lts_base(){
  lb=$IMGDIR/alpine-3.24-x86_64-lts.qcow2
  [ -s "$lb" ] && [ -s "$IMGDIR/vmlinuz-lts" ] && [ -s "$IMGDIR/initramfs-lts" ] && return 0
  ensure_mirror "$ROOT"
  [ -s "$IMGDIR/vmlinuz-virt" ] || extract_boot "$CLOUD" virt
  pd=; temp_dir pd prep; mkdir -p "$pd/seed"
  qemu-img create -f qcow2 -F qcow2 -b "$CLOUD" "$pd/disk.qcow2" >/dev/null; qemu-img resize "$pd/disk.qcow2" 1G >/dev/null
  cp "$LABDIR/guest/prep-lts.yaml" "$pd/seed/user-data"
  printf 'instance-id: mrlab-prep\n' > "$pd/seed/meta-data"
  genisoimage -quiet -r -J -volid cidata -o "$pd/seed.iso" -graft-points user-data="$pd/seed/user-data" meta-data="$pd/seed/meta-data" apk-mirror="$MIRROR"
  echo "lab: preparing the lts base image (one offline boot)..." >&2
  accel=tcg; [ -e /dev/kvm ] && accel=kvm
  timeout 900 qemu-system-x86_64 -accel "$accel" -m 512 -smp 1 -kernel "$IMGDIR/vmlinuz-virt" -initrd "$IMGDIR/initramfs-virt" \
    -append "root=LABEL=/ rootflags=rw rw modules=sd-mod,usb-storage,virtio_blk,ext4 init=/sbin/init console=ttyS0,115200n8" \
    -drive "file=$pd/disk.qcow2,if=virtio,format=qcow2" -drive "file=$pd/seed.iso,if=virtio,format=raw,readonly=on" \
    -nic none -serial "file:$pd/console.log" -display none -no-reboot </dev/null >/dev/null 2>&1 || true
  grep -q MRLAB-PREP-OK "$pd/console.log" || { cp "$pd/console.log" "$IMGDIR/prep-failed.log"; die "lts base preparation failed (see $IMGDIR/prep-failed.log)"; }
  rm -f "${lb%.qcow2}.raw"
  qemu-img convert -O qcow2 "$pd/disk.qcow2" "$pd/lts.qcow2"
  mv "$pd/lts.qcow2" "$lb"
  extract_boot "$lb" lts
  rm -f "${lb%.qcow2}.raw"
}
ensure_base(){
  ensure_cloud
  if [ "$FLAVOR" = lts ]; then ensure_lts_base; elif [ ! -s "$KERNEL" ] || [ ! -s "$INITRD" ]; then extract_boot "$CLOUD" virt; fi
}
# Offline Alpine repository for the guest: the official signed APKINDEX of main and community plus
# every package the guest's `apk add` will want. That set is found by installing the base image's
# world and install.sh's packages into a scratch root inside an Alpine chroot (apk fetch -R would
# miss install_if packages such as nftables-openrc), minus what the base image already has.
# Trust: the chroot comes from the pinned minirootfs; its apk checks the signature of every APKINDEX
# with the keys in that minirootfs and every package against the index. The index files copied into
# the mirror must be byte-identical to those apk verified. In the guest, apk verifies them again with
# the keys of the (pinned) cloud image.
ensure_mirror(){
  pkgs=$(alpine_pkgs "${1:-$ROOT}")
  [ -s "$MIRROR/$ALPINE/main/x86_64/APKINDEX.tar.gz" ] && [ "$(cat "$MIRROR/.pkgs" 2>/dev/null)" = "$pkgs" ] && return 0
  need curl; ensure_cloud
  mrfs=$IMGDIR/${MINIROOTFS_URL##*/}
  [ -s "$mrfs" ] || fetch_pinned "$MINIROOTFS_URL" "$MINIROOTFS_SHA256" "$mrfs"
  verify_pinned "$mrfs" "$MINIROOTFS_SHA256"
  cr=$IMGDIR/pkgbuild
  # the chroot is always the content of the verified tarball (re-extracted when that changes)
  if [ "$(cat "$cr/.minirootfs" 2>/dev/null)" != "$MINIROOTFS_SHA256" ]; then
    rm -rf "$cr"; mkdir -p "$cr"; tar -xzf "$mrfs" -C "$cr"; echo "$MINIROOTFS_SHA256" > "$cr/.minirootfs"
  fi
  cp /etc/resolv.conf "$cr/etc/resolv.conf"
  printf '%s\n' "https://dl-cdn.alpinelinux.org/alpine/$ALPINE/main" "https://dl-cdn.alpinelinux.org/alpine/$ALPINE/community" > "$cr/etc/apk/repositories"
  raw_of "$CLOUD"; mount_image "$RAW"
  cp "$MNT/etc/apk/world" "$cr/tmp/base-world"
  awk '/^P:/{p=substr($0,3)} /^V:/{print p"-"substr($0,3)}' "$MNT/lib/apk/db/installed" | sort > "$cr/tmp/base-installed"
  umount_image
  new=; temp_dir new apk-mirror
  rm -rf "$cr/tmp/fetch" "$cr/tmp/sim"; mkdir -p "$cr/tmp/fetch" "$cr/tmp/sim"
  chroot "$cr" /sbin/apk update -q
  : > "$cr/tmp/needed"
  # in the same steps as install.sh (and the lts base): dnsmasq first, then dnsmasq-dnssec-nftset
  for step in "$(cat "$cr/tmp/base-world") ${pkgs% *}" "${pkgs##* }"; do
    # shellcheck disable=SC2086
    chroot "$cr" /sbin/apk add -q --root /tmp/sim --initdb --keys-dir /etc/apk/keys --repositories-file /etc/apk/repositories \
      --no-scripts $step
    awk 'NR==FNR {base[$0] = 1; next} /^P:/ {p = substr($0, 3)} /^V:/ {v = substr($0, 3); if (!((p "-" v) in base)) print p}' \
      "$cr/tmp/base-installed" "$cr/tmp/sim/lib/apk/db/installed" >> "$cr/tmp/needed"
  done
  # shellcheck disable=SC2046
  chroot "$cr" /sbin/apk fetch -q -o /tmp/fetch $(sort -u "$cr/tmp/needed")
  rm -rf "$cr/tmp/sim"
  for r in main community; do
    mkdir -p "$new/$ALPINE/$r/x86_64"
    curl -fsS --retry 3 -o "$new/$ALPINE/$r/x86_64/APKINDEX.tar.gz" "https://dl-cdn.alpinelinux.org/alpine/$ALPINE/$r/x86_64/APKINDEX.tar.gz"
    sum=$(sha256sum < "$new/$ALPINE/$r/x86_64/APKINDEX.tar.gz")
    found=0; for f in "$cr"/var/cache/apk/APKINDEX.*.tar.gz; do [ "$(sha256sum < "$f")" = "$sum" ] && found=1; done
    [ "$found" = 1 ] || die "the $r index changed while the mirror was built; run the command again"
    ln -f "$cr"/tmp/fetch/*.apk "$new/$ALPINE/$r/x86_64/"
  done
  printf '%s' "$pkgs" > "$new/.pkgs"
  chmod 755 "$new"; rm -rf "$MIRROR"; mv "$new" "$MIRROR"
}
# Release assets of the working tree (tools/release.sh), cached by the content of the product files.
ensure_release(){
  tree=${1:-$ROOT}
  key=$(cd "$tree" && { git rev-parse HEAD:mr HEAD:rootfs HEAD:install.sh; git status --porcelain -- mr rootfs install.sh; git diff -- mr rootfs install.sh; } 2>/dev/null | sha256sum | cut -c1-16)
  out=$IMGDIR/release-$key
  if [ ! -s "$out/mr-linux-amd64" ]; then
    # shellcheck disable=SC2012
    ls -dt "$IMGDIR"/release-* 2>/dev/null | tail -n +4 | xargs -r rm -rf
    # shellcheck disable=SC1091
    command -v go >/dev/null 2>&1 || { [ -r /etc/profile.d/buildtools.sh ] && . /etc/profile.d/buildtools.sh; }
    need go
    (cd "$tree" && tools/release.sh "lab-$key" "$out") >/dev/null
  fi
  echo "$out"
}

# stop_pids PID...: TERM (pppd then removes its pid files), KILL what is still there after 3 s
stop_pids(){
  [ $# -gt 0 ] || return 0
  kill "$@" 2>/dev/null || true
  _n=0
  while [ "$_n" -lt 15 ]; do
    _alive=
    for _p; do [ -d "/proc/$_p" ] && [ "$(cut -d' ' -f3 "/proc/$_p/stat" 2>/dev/null)" != Z ] && _alive=1; done
    [ -n "$_alive" ] || return 0
    sleep 0.2; _n=$((_n + 1))
  done
  kill -9 "$@" 2>/dev/null || true
}
# kill_pid PIDFILE COMM: only a process that still is what the pid file says (no recycled PID)
kill_pid(){
  [ -s "$1" ] || { rm -f "$1"; return 0; }
  _kp=$(cat "$1"); rm -f "$1"
  [ "$(cat "/proc/$_kp/comm" 2>/dev/null)" = "$2" ] && stop_pids "$_kp"
  return 0
}
# kill_qemu ID [9]: the QEMU whose command line has this lab's overlay (9: no shutdown, a power cut)
kill_qemu(){
  qov=$(state "$1")/overlay.qcow2
  qp=$(ps -eo pid=,args= | awk -v f="$qov" 'index($0,f)>0 && /qemu-system/ {print $1}')
  # shellcheck disable=SC2086
  if [ "${2:-}" = 9 ]; then
    [ -z "$qp" ] || kill -9 $qp 2>/dev/null || true
    # the image lock goes with the process: wait for it before the next QEMU opens the overlay
    for _q in $qp; do _n=0; while [ -d "/proc/$_q" ] && [ "$_n" -lt 50 ]; do sleep 0.1; _n=$((_n + 1)); done; done
  else stop_pids $qp; fi
  rm -f "$(pidfile "$1")"
}
# every process inside a lab namespace belongs to the lab
ns_del(){
  # shellcheck disable=SC2046
  stop_pids $(ip netns pids "$1" 2>/dev/null)
  ip netns del "$1" >/dev/null 2>&1 || true
}
# The ISP namespace reaches the internet through slirp4netns (user-mode NAT, no host routes) and
# masquerades the subscriber side with an nftables table that exists only inside that namespace.
slirp_start(){
  sid=$1; swan=$2; sn=$(isp "$sid" "$swan"); sd=$(state "$sid")/isp$swan; mkdir -p "$sd"
  [ -s "$sd/slirp.pid" ] && kill -0 "$(cat "$sd/slirp.pid")" 2>/dev/null && return 0
  ip netns exec "$sn" sleep 2147483 & echo $! > "$sd/slirp-target.pid"
  slirp4netns --configure --disable-host-loopback "$(cat "$sd/slirp-target.pid")" tap0 >"$sd/slirp.log" 2>&1 & echo $! > "$sd/slirp.pid"
  i=0; while [ "$i" -lt 20 ] && ! run_ns "$sn" ip link show tap0 >/dev/null 2>&1; do sleep 0.2; i=$((i + 1)); done
  run_ns "$sn" sysctl -q -w net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1
  run_ns "$sn" nft -f - <<'EOF'
table ip mrlab {
  chain post { type nat hook postrouting priority 100; oifname "tap0" masquerade; }
}
EOF
}

up(){
  id=$1; valid_id "$id"; d=$(state "$id"); mkdir -p "$d"
  for s in dnsmasq kea-dhcp6-server radvd; do
    if systemctl is-active --quiet "$s" 2>/dev/null && [ "${MRLAB_ALLOW_HOST_SERVICES:-0}" != 1 ]; then
      die "the host service $s runs; the lab only needs the binary: systemctl disable --now $s (or MRLAB_ALLOW_HOST_SERVICES=1)"
    fi
  done
  if [ -s "$d/flavor" ] && [ -e "$d/overlay.qcow2" ]; then use_flavor "$(cat "$d/flavor")"; else echo "$FLAVOR" > "$d/flavor"; fi
  lock_images; ensure_base; unlock_images
  [ -e "$d/overlay.qcow2" ] || { qemu-img create -f qcow2 -F qcow2 -b "$BASE" "$d/overlay.qcow2" >/dev/null; qemu-img resize "$d/overlay.qcow2" 1G >/dev/null; }
  for n in "$(sw "$id")" "$(isp "$id" 1)" "$(isp "$id" 2)" "$(lan "$id")"; do [ -e "/run/netns/$n" ] || ip netns add "$n"; done
  ns_etc_setup "$(sw "$id")" 127.0.0.1
  ns_etc_setup "$(isp "$id" 1)" 10.0.2.3
  ns_etc_setup "$(isp "$id" 2)" 10.0.2.3
  [ -s "/etc/netns/$(lan "$id")/resolv.conf" ] || ns_etc_setup "$(lan "$id")" 192.168.1.1
  for br in br-wan1 br-wan2 br-lan; do
    run_ns "$(sw "$id")" ip link show "$br" >/dev/null 2>&1 || run_ns "$(sw "$id")" ip link add "$br" type bridge
    run_ns "$(sw "$id")" ip link set "$br" up
  done
  connect(){ a=$1; b=$2; target=$3; br=$4
    run_ns "$(sw "$id")" ip link show "$a" >/dev/null 2>&1 && return 0
    # created in the switch namespace with the peer straight in the target: never in the host's
    ip -n "$(sw "$id")" link add "$a" type veth peer name "$b" netns "$target"
    run_ns "$(sw "$id")" ip link set "$a" master "$br"; run_ns "$(sw "$id")" ip link set "$a" up
    run_ns "$target" ip link set lo up; run_ns "$target" ip link set "$b" up
  }
  connect "mrlab${id}s1" "mrlab${id}s1p" "$(isp "$id" 1)" br-wan1
  connect "mrlab${id}s2" "mrlab${id}s2p" "$(isp "$id" 2)" br-wan2
  connect "mrlab${id}sl" "mrlab${id}slp" "$(lan "$id")" br-lan
  [ -s "$d/lan.ip" ] || printf '%s\n' 192.168.1.1 > "$d/lan.ip"
  if [ ! -s "$(pidfile "$id")" ] || ! kill -0 "$(cat "$(pidfile "$id")")" 2>/dev/null; then
    need qemu-system-x86_64
    hexid=$(printf '%02x' "$id")
    accel=tcg; [ -e /dev/kvm ] && accel=kvm
    seedarg=; [ -s "$d/seed.iso" ] && seedarg="-drive file=$d/seed.iso,if=virtio,format=raw,readonly=on"
    # agent port (virtio-serial): QEMU keeps agent.in (a FIFO) open itself, so writers never hang up
    rm -f "$d/serial.sock" "$d/agent.in" "$d/agent.out"; mkfifo "$d/agent.in"; : > "$d/agent.out"
    printf '\n===== MRLAB POWER ON %s =====\n' "$(date '+%F %T')" >> "$d/console.log"
    # shellcheck disable=SC2086
    ip netns exec "$(sw "$id")" qemu-system-x86_64 -accel "$accel" -m 512 -smp 1 \
      -kernel "$KERNEL" -initrd "$INITRD" \
      -append "root=LABEL=/ rootflags=rw rw modules=sd-mod,usb-storage,virtio_blk,ext4 init=/sbin/init console=ttyS0,115200n8" \
      -drive "file=$d/overlay.qcow2,if=virtio,format=qcow2" $seedarg \
      -netdev "tap,id=wan1,ifname=mrlab${id}tap0,script=no,downscript=no" -device "virtio-net-pci,netdev=wan1,mac=52:54:00:${hexid}:01:01" \
      -netdev "tap,id=lan,ifname=mrlab${id}tap1,script=no,downscript=no" -device "virtio-net-pci,netdev=lan,mac=52:54:00:${hexid}:01:02" \
      -chardev "socket,id=ser,path=$d/serial.sock,server=on,wait=off,logfile=$d/console.log,logappend=on" -serial chardev:ser \
      -device virtio-serial-pci -chardev "pipe,id=agent,path=$d/agent" -device virtserialport,chardev=agent,name=mrlab.agent \
      -display none -daemonize -pidfile "$(pidfile "$id")" </dev/null >/dev/null 2>>"$d/qemu.err" || die "qemu failed: $(tail -3 "$d/qemu.err")"
    run_ns "$(sw "$id")" ip link set "mrlab${id}tap0" master br-wan1
    run_ns "$(sw "$id")" ip link set "mrlab${id}tap1" master br-lan
    run_ns "$(sw "$id")" ip link set "mrlab${id}tap0" up
    run_ns "$(sw "$id")" ip link set "mrlab${id}tap1" up
  fi
  echo "{\"id\":$id,\"state\":\"up\",\"switch\":\"$(sw "$id")\"}"
}

teardown(){
  id=$1; kill_qemu "$id"
  for w in 1 2; do kill_pid "$(state "$id")/isp$w/slirp.pid" slirp4netns; done
  for n in "$(lan "$id")" "$(isp "$id" 2)" "$(isp "$id" 1)" "$(sw "$id")"; do ns_del "$n"; ns_etc_remove "$n"; done
  rm -rf "$(state "$id")"
}
down(){ id=$1; valid_id "$id"; teardown "$id"; echo "down $id"; }
reset(){ id=$1; valid_id "$id"; teardown "$id"; up "$id"; }
status(){
  id=$1; valid_id "$id"; p=$(pidfile "$id"); alive=false; [ -s "$p" ] && kill -0 "$(cat "$p")" 2>/dev/null && alive=true
  rc=$(sed -n 's/.*MRLAB-INSTALL-RC=\([0-9]*\).*/\1/p' "$(state "$id")/console.log" 2>/dev/null | tail -1)
  isp1=$(cat "$(state "$id")/isp1/mode" 2>/dev/null || echo none)
  printf '{"id":%s,"qemu":%s,"install_rc":"%s","isp1":"%s","router_ip":"%s"}\n' "$id" "$alive" "$rc" "$isp1" "$(router_ip "$id")"
}

# ---------------------------------------------------------------- ISP simulator
isp_stop(){
  id=$1; wan=$2; n=$(isp "$id" "$wan"); d=$(state "$id")/isp$wan
  # every ISP daemon (dnsmasq, pppoe-server and its pppd/pppoe, the ipv6-up script's radvd and kea, the
  # modem page) lives in the namespace; only the process slirp4netns is attached to stays
  anchor=$(cat "$d/slirp-target.pid" 2>/dev/null || echo none)
  # shellcheck disable=SC2046
  stop_pids $(ip netns pids "$n" 2>/dev/null | grep -vx "$anchor")
  rm -f "$d"/dnsmasq.pid "$d"/pppoe.pid "$d"/radvd.pid "$d"/kea.pid "$d"/http.pid
  run_ns "$n" ip addr flush dev "mrlab${id}s${wan}p" 2>/dev/null || true
  run_ns "$n" ip addr flush dev lo scope global 2>/dev/null || true
  run_ns "$n" ip -6 route flush proto static 2>/dev/null || true
}
isp_cmd(){
  id=$1; wan=$2; mode=$3; shift 3; valid_id "$id"; n=$(isp "$id" "$wan"); d=$(state "$id")/isp$wan; dev=mrlab${id}s${wan}p
  [ -e "/run/netns/$n" ] || die "lab $id is not up"
  mkdir -p "$d"; isp_stop "$id" "$wan"
  v6=none; badpass=0; nopado=0; cgnat=0; subnet=10.$id.$wan; gw=1
  while [ $# -gt 0 ]; do case $1 in
    v6=*) v6=${1#v6=};; --cgnat) cgnat=1;; --badpass) badpass=1;; nopado|--nopado) nopado=1;;
    --subnet) shift; subnet=${1%.*}; subnet=${subnet%/*}; subnet=${subnet%.0};;
    --gw) shift; gw=$1;;
    *) die "isp: unknown option $1";; esac; shift; done
  case $v6 in none|slaac|pd) ;; *) die "isp: v6=none|slaac|pd";; esac
  [ "$mode" = pppoe ] && subnet=203.0.113
  [ "$cgnat" = 1 ] && subnet=100.64.$id
  if [ "$mode" = down ]; then run_ns "$n" ip link set "$dev" down; echo "down" > "$d/mode"; echo "isp $id wan$wan down"; return; fi
  run_ns "$n" ip link set "$dev" up
  slirp_start "$id" "$wan"
  # --conf-file=/dev/null: never the host's /etc/dnsmasq.conf or /etc/dnsmasq.d
  dns="--conf-file=/dev/null --no-resolv --no-hosts --server=10.0.2.3 --address=/isp.test/$subnet.$gw --pid-file=$d/dnsmasq.pid --log-facility=$d/dnsmasq.log --dhcp-leasefile=$d/dnsmasq.leases"
  case $mode in
    dhcp)
      run_ns "$n" ip addr add "$subnet.$gw/24" dev "$dev"
      # a modem on the router's LAN subnet (192.168.1.0/24): its pool stays below the router's
      # DHCP range (.100-.249) and it serves a page ("Directory listing") on its address
      pool="$subnet.10,$subnet.200"; [ "$subnet" = 192.168.1 ] && pool="$subnet.10,$subnet.99"
      # shellcheck disable=SC2086
      run_ns "$n" dnsmasq $dns --interface="$dev" --bind-interfaces --dhcp-range="$pool,255.255.255.0,1h" \
        --dhcp-option=3,"$subnet.$gw" --dhcp-option=6,"$subnet.$gw"
      [ "$subnet" = 192.168.1 ] && { (cd "$d" && exec ip netns exec "$n" python3 -m http.server 80 --bind "$subnet.$gw" >/dev/null 2>&1) & echo $! > "$d/http.pid"; }
      ;;
    static)
      run_ns "$n" ip addr add "$subnet.1/24" dev "$dev"
      # shellcheck disable=SC2086
      run_ns "$n" dnsmasq $dns --interface="$dev" --bind-interfaces
      ;;
    pppoe)
      pe=/etc/netns/$n/ppp; mkdir -p "$pe"
      pass=labpass; [ "$badpass" = 1 ] && pass=wrongpass
      printf 'lab * %s *\n' "$pass" > "$pe/chap-secrets"; cp "$pe/chap-secrets" "$pe/pap-secrets"; : > "$pe/options"
      cat > "$d/pppoe-options" <<EOF
auth
require-chap
mtu 1492
mru 1492
lcp-echo-interval 5
lcp-echo-failure 3
nodefaultroute
ms-dns $subnet.1
+ipv6
logfile $d/pppd.log
ipv6-up-script $d/ipv6-up.sh
EOF
      cat > "$d/ipv6-up.sh" <<EOF
#!/bin/sh
# pppd: \$1 = interface. The ISP's end of the link gets 2001:db8:$id:$wan::1 and announces that /64.
dev=\$1
ip -6 addr add 2001:db8:$id:$wan::1/64 dev "\$dev"
# kea binds the IFA_ADDRESS of a link-local, which is the peer's on a point-to-point link: the same
# local link-local again without the peer (\$4 = local, \$5 = remote link-local)
ip -6 addr del "\$4/128" peer "\$5/128" dev "\$dev" 2>/dev/null && ip -6 addr add "\$4/64" dev "\$dev" nodad
[ "$v6" = none ] && exit 0
printf 'interface %s { AdvSendAdvert on; MinRtrAdvInterval 3; MaxRtrAdvInterval 10; AdvManagedFlag %s; AdvOtherConfigFlag %s; prefix 2001:db8:$id:$wan::/64 { AdvOnLink on; AdvAutonomous on; }; };\n' "\$dev" "$([ "$v6" = pd ] && echo on || echo off)" "$([ "$v6" = pd ] && echo on || echo off)" > $d/radvd.conf
$(command -v radvd) -C $d/radvd.conf -p $d/radvd.pid -m logfile -l $d/radvd.log
[ "$v6" = pd ] || exit 0
# one subscriber per lab: the whole delegation pool is routed down this session
ip -6 route add 2001:db8:$id:${wan}00::/56 dev "\$dev" proto static
# the host's AppArmor profile lets kea use only /etc/kea, /run/kea, /run/lock/kea and /var/lib/kea:
# in a private mount namespace those are lab directories (and /run a tmpfs), so neither the host's
# kea service nor its directories under /run are needed
k=$d/kea; mkdir -p \$k/etc \$k/lib
sed "s/@DEV@/\$dev/" $d/kea6.conf.in > \$k/etc/kea-dhcp6.conf
setsid $(command -v unshare) -m --propagation private sh -c 'mount -t tmpfs mrlab-kea /run && mkdir -p /run/kea /run/lock/kea &&
  mount --bind "\$1/etc" /etc/kea && mount --bind "\$1/lib" /var/lib/kea &&
  KEA_LOCKFILE_DIR=/run/lock/kea exec "\$2" -c /etc/kea/kea-dhcp6.conf' sh \$k $(command -v kea-dhcp6) > $d/kea.log 2>&1 &
echo \$! > $d/kea.pid
EOF
      chmod +x "$d/ipv6-up.sh"
      cat > "$d/kea6.conf.in" <<EOF
{"Dhcp6":{"interfaces-config":{"interfaces":["@DEV@"]},
 "lease-database":{"type":"memfile","persist":false},
 "preferred-lifetime":3000,"valid-lifetime":4000,"renew-timer":1000,"rebind-timer":2000,
 "option-data":[{"name":"dns-servers","data":"2001:db8:$id:$wan::1"}],
 "subnet6":[{"id":1,"subnet":"2001:db8:$id:$wan::/64","interface":"@DEV@",
  "pd-pools":[{"prefix":"2001:db8:$id:${wan}00::","prefix-len":56,"delegated-len":60}]}],
 "loggers":[{"name":"kea-dhcp6","output_options":[{"output":"stdout"}],"severity":"INFO"}]}}
EOF
      run_ns "$n" ip addr add "$subnet.1/32" dev lo
      # shellcheck disable=SC2086
      run_ns "$n" dnsmasq $dns --listen-address="$subnet.1" --bind-interfaces
      if [ "$nopado" = 0 ]; then
        # pppd writes /run/pppN.pid and /run/pppd2.tdb: a private mount namespace with its own /run
        # (the sessions of every lab are ppp0) keeps them off the host's /run
        # shellcheck disable=SC2016
        run_ns "$n" unshare -m --propagation private sh -c 'mount -t tmpfs mrlab-ppp /run && exec "$@"' sh \
          pppoe-server -I "$dev" -O "$d/pppoe-options" -L "$subnet.1" -R "$subnet.10" -N 8 -X "$d/pppoe.pid"
      fi
      ;;
    *) die "unknown ISP mode: $mode (dhcp|pppoe|static|down)";;
  esac
  printf '%s v6=%s cgnat=%s badpass=%s nopado=%s subnet=%s gw=%s\n' "$mode" "$v6" "$cgnat" "$badpass" "$nopado" "$subnet" "$subnet.$gw" > "$d/mode"
  echo "isp $id wan$wan $mode ($(cat "$d/mode"))"
}

# ---------------------------------------------------------------- guest install
install_cmd(){
  id=$1; shift; valid_id "$id"
  proto=dhcp; apply=1; lanip=192.168.1.1/24; release=; tree=${MR_LAB_TREE:-$ROOT}; runinst=1; wait=600
  while [ $# -gt 0 ]; do case $1 in
    --wan-proto) proto=$2; shift 2;; --no-apply) apply=0; shift;; --lan-ip) lanip=$2; shift 2;;
    --release) release=$2; shift 2;; --tree) tree=$(cd "$2" && pwd); shift 2;;
    --no-install) runinst=0; shift;; --timeout) wait=$2; shift 2;;
    *) die "install: unknown option $1";; esac; done
  case $proto in dhcp|pppoe|static) ;; *) die "install: --wan-proto dhcp|pppoe|static";; esac
  need genisoimage
  # labs installing at the same time share the image directory: one mirror / release build at a time
  lock_images
  ensure_mirror "$tree"
  d=$(state "$id"); out=$d/install; rm -rf "$out"; mkdir -p "$out/release" "$out/lab"
  if [ -n "$release" ]; then
    curl -fsSL --retry 2 -o "$out/release/install.sh" "https://raw.githubusercontent.com/Cd1s/mini-router/$release/install.sh"
    for f in mr-linux-amd64 mini-router-rootfs.tar.gz; do curl -fsSL --retry 2 -o "$out/release/$f" "https://github.com/Cd1s/mini-router/releases/download/$release/$f"; done
  else
    rel=$(ensure_release "$tree"); cp "$rel/install.sh" "$rel/mr-linux-amd64" "$rel/mini-router-rootfs.tar.gz" "$out/release/"
  fi
  {
    echo "MRLAB_RUN=$runinst"
    echo "MR_YES=1"; echo "MR_LOCAL=/root/mr-lab-release"; echo "MR_APPLY=$apply"
    echo "MR_WAN=eth0"; echo "MR_LAN_PORTS=eth1"; echo "MR_WAN_PROTO=$proto"; echo "MR_LAN_IP=$lanip"
    echo "MR_ADMIN_PASS=$ADMIN_PASS"; echo "MR_TZ=UTC0"
    [ "$proto" = pppoe ] && { echo "MR_PPPOE_USER=lab"; echo "MR_PPPOE_PASS=labpass"; }
    [ "$proto" = static ] && { echo "MR_WAN_ADDR=10.$id.1.2/24"; echo "MR_WAN_GW=10.$id.1.1"; echo "MR_WAN_DNS='10.$id.1.1'"; }
  } > "$out/release/request.env"
  cp "$LABDIR"/guest/agent.sh "$LABDIR"/guest/setup.sh "$LABDIR"/guest/install-run.sh "$out/lab/"
  [ -s "$d/id_lab" ] || ssh-keygen -q -t ed25519 -N '' -C "mrlab$id" -f "$d/id_lab"
  cp "$d/id_lab.pub" "$out/lab/"
  cat > "$out/user-data" <<EOF
#cloud-config
hostname: mrlab$id
ssh_pwauth: true
chpasswd:
  expire: false
  users: [{name: root, password: $ADMIN_PASS, type: text}]
runcmd:
  - [sh, -c, 'mkdir -p /media/mrlab && mount -t iso9660 -o ro /dev/vdb /media/mrlab && sh /media/mrlab/lab/setup.sh']
EOF
  printf 'instance-id: mrlab%s-%s\nlocal-hostname: mrlab%s\n' "$id" "$(date +%s)" "$id" > "$out/meta-data"
  # what a VM provider (or setup-alpine) gives a fresh machine: DHCP on the first NIC
  printf 'version: 2\nethernets:\n  eth0: {dhcp4: true}\n' > "$out/network-config"
  # kernels are in the base image already: the seed carries only what install.sh may add
  genisoimage -quiet -r -J -volid cidata -o "$d/seed.iso" -m 'linux-lts-*' -m 'linux-virt-*' -m 'linux-firmware-*' -graft-points \
    user-data="$out/user-data" meta-data="$out/meta-data" network-config="$out/network-config" \
    release="$out/release" lab="$out/lab" apk-mirror="$MIRROR"
  unlock_images
  # a fresh machine: new overlay over the pristine Alpine image
  kill_qemu "$id"; rm -f "$d/overlay.qcow2" "$d/api.cookies" "$d/flavor"
  printf '%s\n' "${lanip%/*}" > "$d/lan.ip"
  start=$(wc -c < "$d/console.log" 2>/dev/null || echo 0)
  up "$id" >/dev/null
  echo "install: guest $id booting (wan $proto, isp1: $(cat "$d/isp1/mode" 2>/dev/null || echo none)); log: $d/console.log"
  if [ "$runinst" = 0 ]; then wait_agent "$id" 180 && echo "install: --no-install, guest ready"; return; fi
  i=0; rc=
  while [ "$i" -lt "$wait" ]; do
    rc=$(tail -c +"$((start + 1))" "$d/console.log" | tr -d '\r' | sed -n 's/^MRLAB-INSTALL-RC=\([0-9]*\).*/\1/p' | tail -1)
    [ -n "$rc" ] && break
    sleep 2; i=$((i + 2))
  done
  tail -c +"$((start + 1))" "$d/console.log" | tr -d '\r' | sed -n '/mini-router installer/,/MRLAB-INSTALL-RC/p' | grep -v '^\s*$' | tail -15 | cut -c1-200
  [ -n "$rc" ] || die "install: no result after ${wait}s (see $d/console.log)"
  wait_agent "$id" 60 >/dev/null || true
  [ "$rc" = 0 ] || die "install.sh exited $rc"
  echo "install: ok (http://$(router_ip "$id")/, admin password $ADMIN_PASS)"
}

# ---------------------------------------------------------------- guest console (ttyS1 agent)
agent_exec(){
  _id=$1; _t=$2; shift 2; _d=$(state "$_id"); _log=$_d/agent.out
  if [ ! -p "$_d/agent.in" ] || ! kill -0 "$(cat "$(pidfile "$_id")" 2>/dev/null)" 2>/dev/null; then die "lab $_id: guest is not running"; fi
  _m=MRLAB$$x$(date +%s%N)
  _start=$(wc -c < "$_log" 2>/dev/null || echo 0)
  # shellcheck disable=SC2016
  timeout 5 sh -c 'printf "%s\n" "$1" > "$2"' sh \
    "$(printf 'echo %s_B; ( %s\n) </dev/null 2>&1; echo %s_E $?' "$_m" "$*" "$_m")" "$_d/agent.in" || return 125
  _end=$(($(date +%s) + _t))
  while [ "$(date +%s)" -lt "$_end" ]; do
    if tail -c +"$((_start + 1))" "$_log" | grep -q "${_m}_E [0-9]"; then
      # the end marker may follow output that did not end with a newline
      tail -c +"$((_start + 1))" "$_log" | awk -v b="${_m}_B" -v e="${_m}_E " \
        'on && (k = index($0, e)) { if (k > 1) print substr($0, 1, k - 1); exit } on { print } $0 == b { on = 1 }'
      return "$(tail -c +"$((_start + 1))" "$_log" | sed -n "s/.*${_m}_E \([0-9]*\).*/\1/p" | tail -1)"
    fi
    sleep 0.2
  done
  echo "lab: console: no answer within ${_t}s" >&2; return 124
}
wait_agent(){
  _wid=$1; _wt=$2; _wend=$(($(date +%s) + _wt))
  while [ "$(date +%s)" -lt "$_wend" ]; do agent_exec "$_wid" 3 true >/dev/null 2>&1 && return 0; sleep 2; done
  echo "lab: guest $_wid agent not reachable after ${_wt}s" >&2; return 1
}
console(){ id=$1; shift; valid_id "$id"; t=${MRLAB_TIMEOUT:-60}; agent_exec "$id" "$t" "$@"; }

# ---------------------------------------------------------------- LAN client
udhcpc_script(){
  id=$1; script=$(state "$id")/lan-udhcpc.sh
  cat > "$script" <<'EOF'
#!/bin/sh
case "$1" in
  bound|renew)
    ip addr flush dev "$interface" scope global 2>/dev/null || true
    ip addr add "$ip/${mask:-24}" dev "$interface" 2>/dev/null || true
    [ -n "${router:-}" ] && ip route replace default via "$router" dev "$interface" 2>/dev/null || true
    : > "${UDHCPC_STATE:?}"
    for dns_server in ${dns:-}; do printf 'nameserver %s\n' "$dns_server" >> "$UDHCPC_STATE"; done
    ;;
esac
exit 0
EOF
  chmod +x "$script"
  echo "$script"
}
lan_cmd(){
  id=$1; op=$2; shift 2; valid_id "$id"; n=$(lan "$id"); dev=mrlab${id}slp; d=$(state "$id")
  case $op in
    dhcp)
      script=$(udhcpc_script "$id"); rs=$d/lan.resolv.conf; rm -f "$rs"
      run_ns "$n" ip addr flush dev "$dev" scope global
      run_ns "$n" sysctl -q -w "net.ipv6.conf.$dev.accept_ra=2" "net.ipv6.conf.$dev.autoconf=1"
      run_ns "$n" ip link set "$dev" down; run_ns "$n" ip link set "$dev" up   # restart SLAAC too
      if run_ns "$n" env UDHCPC_STATE="$rs" busybox udhcpc -n -q -t 6 -T 2 -A 1 -s "$script" -i "$dev" >/dev/null 2>&1 && [ -s "$rs" ]; then
        cp "$rs" "/etc/netns/$n/resolv.conf"
        addr=$(run_ns "$n" ip -4 -o addr show dev "$dev" scope global | awk '{print $4; exit}')
        echo "{\"dhcp\":\"ok\",\"addr\":\"$addr\",\"dns\":\"$(awk '{print $2}' "$rs" | paste -sd, -)\"}"
      else
        echo '{"dhcp":"failed"}'; return 1
      fi;;
    static)
      a=${1:-192.168.1.200/24}; gw=${2:-$(router_ip "$id")}
      run_ns "$n" ip addr flush dev "$dev" scope global; run_ns "$n" ip addr add "$a" dev "$dev"
      run_ns "$n" ip route replace default via "$gw"; printf 'nameserver %s\n' "$gw" > "/etc/netns/$n/resolv.conf"
      echo "{\"static\":\"$a\",\"gateway\":\"$gw\"}";;
    check)
      v4=$(run_ns "$n" ip -4 -o addr show dev "$dev" scope global | awk '{print $4; exit}')
      v6=$(run_ns "$n" ip -6 -o addr show dev "$dev" scope global | awk '{print $4; exit}')
      dnsok=false; run_ns "$n" timeout 6 getent hosts example.com >/dev/null 2>&1 && dnsok=true
      panel=$(run_ns "$n" curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://$(router_ip "$id")/" 2>/dev/null || true)
      echo "{\"ipv4\":\"$v4\",\"ipv6\":\"$v6\",\"dns\":$dnsok,\"panel\":\"$panel\"}"
      [ -n "$v4" ] && [ "$dnsok" = true ];;
    exec) run_ns "$n" sh -c "$*";;
    *) die "lan: dhcp|static [addr/len [gw]]|check|exec <cmd>";;
  esac
}
ssh_cmd(){ id=$1; shift; d=$(state "$id"); run_ns "$(lan "$id")" ssh -i "$d/id_lab" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=4 root@"$(router_ip "$id")" "$*"; }

# ---------------------------------------------------------------- web UI API
api_cmd(){
  id=$1; method=$2; path=$3; body=${4:-}; n=$(lan "$id"); jar=$(state "$id")/api.cookies
  base="http://$(router_ip "$id")/cgi-bin/api"; url="$base?a=$path"
  token=${MR_TOKEN:-}
  if [ -n "$token" ]; then
    case $method in GET) run_ns "$n" curl -sS --fail-with-body --max-time 30 -H "Authorization: Bearer $token" "$url";;
      *) run_ns "$n" curl -sS --fail-with-body --max-time 30 -H "Authorization: Bearer $token" -H 'Content-Type: application/json' -d "$body" "$url";; esac
    return
  fi
  # session API: cookie + X-MR header; log in only when the stored session is no longer valid
  if ! run_ns "$n" curl -sS --max-time 10 -b "$jar" -H X-MR:1 "$base?a=session" 2>/dev/null | grep -q '"authenticated":true'; then
    run_ns "$n" curl -sS --fail-with-body --max-time 20 -c "$jar" -H X-MR:1 -H 'Content-Type: application/json' -d "{\"password\":\"$ADMIN_PASS\"}" "$base?a=login" >/dev/null || die "api: login failed"
  fi
  case $method in GET) run_ns "$n" curl -sS --fail-with-body --max-time 30 -b "$jar" -c "$jar" -H X-MR:1 "$url";;
    *) run_ns "$n" curl -sS --fail-with-body --max-time 60 -b "$jar" -c "$jar" -H X-MR:1 -H 'Content-Type: application/json' -d "$body" "$url";; esac
}
# One settings change through the web UI API, the way the panel does it: read rev, apply the patch,
# wait for the job, then confirm (default) or leave the change pending (--no-confirm).
change_cmd(){
  id=$1; patch=$2; shift 2; valid_id "$id"; confirm=1; secrets='{}'
  while [ $# -gt 0 ]; do case $1 in --no-confirm) confirm=0;; --secrets) secrets=$2; shift;; *) die "change: unknown option $1";; esac; shift; done
  need jq
  rev=$(api_cmd "$id" GET config | jq -r .rev) || die "change: cannot read config"
  body=$(jq -cn --arg rev "$rev" --argjson patch "$patch" --argjson sec "$secrets" '{base_rev: $rev, patch: $patch, secrets: $sec, confirm: 120, comment: "lab change"}')
  api_cmd "$id" POST apply "$body" >/dev/null || die "change: apply refused"
  i=0; st=running
  while [ "$st" = running ] && [ "$i" -lt 180 ]; do
    sleep 2; i=$((i + 2))
    # the router may be unreachable for a while when the change moves its own network
    st=$(api_cmd "$id" GET job 2>/dev/null | jq -r '.job.state // "running"' 2>/dev/null) || st=running
  done
  echo "{\"job\":\"$st\"}"
  [ "$st" = ok ] || { api_cmd "$id" GET job 2>/dev/null | jq -r '.job.output // empty' | tail -8 >&2; return 1; }
  [ "$confirm" = 1 ] && { api_cmd "$id" POST confirm '{}' >/dev/null || die "change: confirm failed"; echo '{"confirmed":true}'; }
  return 0
}
run_cmd(){ id=$1; scen=$2; valid_id "$id"; case $scen in */*) f=$scen;; *) f="$LABDIR/scenarios/$scen.sh";; esac; [ -x "$f" ] || die "scenario not found: $f"; LAB_SH="$LABDIR/lab.sh" "$f" "$id"; }
reboot_cmd(){ id=$1; valid_id "$id"; agent_exec "$id" 10 'sync; (sleep 1; reboot) &' >/dev/null || true; sleep 8; wait_agent "$id" 180 && echo "rebooted $id"; }
powercut_cmd(){ id=$1; valid_id "$id"; kill_qemu "$id" 9; up "$id" >/dev/null; wait_agent "$id" 180 && echo "power restored $id"; }

usage(){ die "usage: lab.sh up|down|reset|status <id> | isp <id> <wan> dhcp|pppoe|static|down [opts] | install <id> [opts] | lan <id> dhcp|static|check|exec | console|ssh <id> <cmd> | api <id> GET|POST <action> [json] | change <id> <patch-json> [--no-confirm] | reboot|powercut <id> | run <id> <scenario>"; }
cmd=${1:-}; shift || true
case $cmd in
  up) up "$@";; down) down "$@";; status) status "$@";; reset) reset "$@";;
  isp) isp_cmd "$@";; install) install_cmd "$@";; lan) lan_cmd "$@";;
  ssh) ssh_cmd "$@";; console) console "$@";; api) api_cmd "$@";; change) change_cmd "$@";; run) run_cmd "$@";;
  reboot) reboot_cmd "$@";; powercut) powercut_cmd "$@";; mirror) lock_images; ensure_mirror "${1:-$ROOT}"; echo "$MIRROR";;
  guard-reset) echo "lab: guard baseline reset ($HOST_GUARD_BASE)";;
  *) usage;;
esac
