#!/bin/sh
# Isolated mini-router laboratory.  All links, addresses and daemons live in lab network namespaces;
# the host's network namespace, routes, firewall and sysctls are never touched.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
LABDIR=$ROOT/tools/lab
IMGDIR=${MR_LAB_IMAGE_DIR:-/root/build/mr-lab-images}
RUNDIR=$LABDIR/state
BASE=$IMGDIR/alpine-3.24-x86_64.qcow2
KERNEL=$IMGDIR/vmlinuz-virt
INITRD=$IMGDIR/initramfs-virt
MIRROR=$IMGDIR/apk-mirror
ALPINE=v3.24
ADMIN_PASS=labpass1
mkdir -p "$IMGDIR" "$RUNDIR"

HOST_GUARD_DIR=$RUNDIR/.host-guard
host_manifest(){
  sha256sum /etc/resolv.conf /etc/hosts 2>/dev/null || true
  if [ -d /etc/ppp ]; then
    find /etc/ppp -type f -print 2>/dev/null | sort | while IFS= read -r f; do sha256sum "$f"; done
  fi
}
host_guard_start(){
  mkdir -p "$HOST_GUARD_DIR"
  HOST_GUARD_FILE=$HOST_GUARD_DIR/$$.before
  host_manifest > "$HOST_GUARD_FILE"
}
host_guard_end(){
  rc=$?
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
host_guard_start
trap host_guard_end EXIT

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

alpine_pkgs(){
  # the package list of install.sh step 1, plus what it adds afterwards
  sed -n '/^PKGS="/,/"$/p' "$ROOT/install.sh" | tr -d '"' | sed 's/^PKGS=//' | tr '\n' ' '
  echo dnsmasq-dnssec-nftset
}
ensure_base(){
  [ -s "$BASE" ] && return 0
  need curl; need qemu-img
  tmp=$BASE.part
  echo "Downloading Alpine 3.24 cloud image..."
  curl -fL --retry 3 -o "$tmp" "https://dl-cdn.alpinelinux.org/alpine/$ALPINE/releases/cloud/generic_alpine-3.24.1-x86_64-bios-cloudinit-r0.qcow2"
  mv "$tmp" "$BASE"
  qemu-img info "$BASE" >/dev/null || die "invalid Alpine image"
}
ensure_boot_files(){
  [ -s "$KERNEL" ] && [ -s "$INITRD" ] && return 0
  raw=$IMGDIR/alpine-3.24-x86_64.raw
  [ -s "$raw" ] || qemu-img convert -O raw "$BASE" "$raw"
  mnt=$IMGDIR/.mnt; mkdir -p "$mnt"
  mount -o loop,ro "$raw" "$mnt" 2>/dev/null || die "cannot mount Alpine base image"
  cp "$mnt/boot/vmlinuz-virt" "$KERNEL"; cp "$mnt/boot/initramfs-virt" "$INITRD"
  umount "$mnt"; rmdir "$mnt" 2>/dev/null || true
}
# Offline Alpine repository for the guest: the official signed APKINDEX of main and community plus
# every package the guest's `apk add` will want. That set is found by installing the base image's
# world and install.sh's packages into a scratch root inside an Alpine chroot (apk fetch -R would
# miss install_if packages such as nftables-openrc), minus what the base image already has.
ensure_mirror(){
  pkgs=$(alpine_pkgs)
  [ -s "$MIRROR/$ALPINE/main/x86_64/APKINDEX.tar.gz" ] && [ "$(cat "$MIRROR/.pkgs" 2>/dev/null)" = "$pkgs" ] && return 0
  need curl; ensure_boot_files
  cr=$IMGDIR/pkgbuild
  if [ ! -x "$cr/sbin/apk" ]; then
    mkdir -p "$cr"
    curl -fL --retry 3 -o "$cr/minirootfs.tar.gz" "https://dl-cdn.alpinelinux.org/alpine/$ALPINE/releases/x86_64/alpine-minirootfs-3.24.2-x86_64.tar.gz"
    tar -xzf "$cr/minirootfs.tar.gz" -C "$cr"
  fi
  cp /etc/resolv.conf "$cr/etc/resolv.conf"
  printf '%s\n' "https://dl-cdn.alpinelinux.org/alpine/$ALPINE/main" "https://dl-cdn.alpinelinux.org/alpine/$ALPINE/community" > "$cr/etc/apk/repositories"
  mnt=$IMGDIR/.mnt; mkdir -p "$mnt"
  mount -o loop,ro "$IMGDIR/alpine-3.24-x86_64.raw" "$mnt" || die "cannot mount Alpine base image"
  cp "$mnt/etc/apk/world" "$cr/tmp/base-world"
  awk '/^P:/{p=substr($0,3)} /^V:/{print p"-"substr($0,3)}' "$mnt/lib/apk/db/installed" | sort > "$cr/tmp/base-installed"
  umount "$mnt"; rmdir "$mnt" 2>/dev/null || true
  rm -rf "$MIRROR.new" "$cr/tmp/fetch" "$cr/tmp/sim"; mkdir -p "$cr/tmp/fetch" "$cr/tmp/sim"
  chroot "$cr" /sbin/apk update -q
  : > "$cr/tmp/needed"
  # in the same steps as install.sh: dnsmasq first, then dnsmasq-dnssec-nftset replaces it
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
    mkdir -p "$MIRROR.new/$ALPINE/$r/x86_64"
    curl -fsS --retry 3 -o "$MIRROR.new/$ALPINE/$r/x86_64/APKINDEX.tar.gz" "https://dl-cdn.alpinelinux.org/alpine/$ALPINE/$r/x86_64/APKINDEX.tar.gz"
    sum=$(sha256sum < "$MIRROR.new/$ALPINE/$r/x86_64/APKINDEX.tar.gz")
    found=0; for f in "$cr"/var/cache/apk/APKINDEX.*.tar.gz; do [ "$(sha256sum < "$f")" = "$sum" ] && found=1; done
    [ "$found" = 1 ] || die "the $r index changed while the mirror was built; run the command again"
    ln -f "$cr"/tmp/fetch/*.apk "$MIRROR.new/$ALPINE/$r/x86_64/"
  done
  printf '%s' "$pkgs" > "$MIRROR.new/.pkgs"
  rm -rf "$MIRROR"; mv "$MIRROR.new" "$MIRROR"
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

kill_pid(){
  p=$1
  [ -s "$p" ] || return 0
  pid=$(cat "$p"); kill "$pid" 2>/dev/null || true; sleep 0.3; kill -9 "$pid" 2>/dev/null || true; rm -f "$p"
}
kill_qemu(){
  qov=$(state "$1")/overlay.qcow2
  for qpid in $(ps -eo pid=,args= | awk -v f="$qov" 'index($0,f)>0 && /qemu-system/ {print $1}'); do
    kill "$qpid" 2>/dev/null || true; sleep 1; kill -9 "$qpid" 2>/dev/null || true
  done
  rm -f "$(pidfile "$1")"
}
ns_del(){ ip netns pids "$1" 2>/dev/null | xargs -r kill -9 2>/dev/null || true; ip netns del "$1" >/dev/null 2>&1 || true; }
cleanup_host_links(){
  for x in mrlab$1s1 mrlab$1s1p mrlab$1s2 mrlab$1s2p mrlab$1sl mrlab$1slp; do ip link del "$x" >/dev/null 2>&1 || true; done
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
  id=$1; valid_id "$id"; ensure_base; ensure_boot_files; d=$(state "$id"); mkdir -p "$d"
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
    cleanup_host_links "$id"
    ip link add "$a" type veth peer name "$b"; ip link set "$a" netns "$(sw "$id")"; ip link set "$b" netns "$target"
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
  for w in 1 2; do kill_pid "$(state "$id")/isp$w/slirp.pid"; kill_pid "$(state "$id")/isp$w/slirp-target.pid"; done
  for n in "$(lan "$id")" "$(isp "$id" 2)" "$(isp "$id" 1)" "$(sw "$id")"; do ns_del "$n"; ns_etc_remove "$n"; done
  cleanup_host_links "$id"
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
  for p in dnsmasq pppoe radvd kea http; do kill_pid "$d/$p.pid"; done
  # pppd sessions, radvd and kea started from pppd's ipv6-up script are children of pppoe-server
  for pid in $(ip netns pids "$n" 2>/dev/null); do
    case $(cat "/proc/$pid/comm" 2>/dev/null) in pppd|pppoe|radvd|kea-dhcp6|dnsmasq) kill -9 "$pid" 2>/dev/null || true;; esac
  done
  run_ns "$n" ip addr flush dev "mrlab${id}s${wan}p" 2>/dev/null || true
  run_ns "$n" ip addr flush dev lo scope global 2>/dev/null || true
  run_ns "$n" ip -6 route flush proto static 2>/dev/null || true
}
isp_cmd(){
  id=$1; wan=$2; mode=$3; shift 3; valid_id "$id"; n=$(isp "$id" "$wan"); d=$(state "$id")/isp$wan; dev=mrlab${id}s${wan}p
  [ -e "/run/netns/$n" ] || die "lab $id is not up"
  mkdir -p "$d"; isp_stop "$id" "$wan"
  v6=none; badpass=0; nopado=0; cgnat=0; subnet=10.$id.$wan
  while [ $# -gt 0 ]; do case $1 in
    v6=*) v6=${1#v6=};; --cgnat) cgnat=1;; --badpass) badpass=1;; nopado|--nopado) nopado=1;;
    --subnet) shift; subnet=${1%.*}; subnet=${subnet%/*}; subnet=${subnet%.0};;
    *) die "isp: unknown option $1";; esac; shift; done
  case $v6 in none|slaac|pd) ;; *) die "isp: v6=none|slaac|pd";; esac
  [ "$mode" = pppoe ] && subnet=203.0.113
  [ "$cgnat" = 1 ] && subnet=100.64.$id
  if [ "$mode" = down ]; then run_ns "$n" ip link set "$dev" down; echo "down" > "$d/mode"; echo "isp $id wan$wan down"; return; fi
  run_ns "$n" ip link set "$dev" up
  slirp_start "$id" "$wan"
  dns="--no-resolv --no-hosts --server=10.0.2.3 --address=/isp.test/$subnet.1 --pid-file=$d/dnsmasq.pid --log-facility=$d/dnsmasq.log --dhcp-leasefile=$d/dnsmasq.leases"
  case $mode in
    dhcp)
      run_ns "$n" ip addr add "$subnet.1/24" dev "$dev"
      # shellcheck disable=SC2086
      run_ns "$n" dnsmasq $dns --interface="$dev" --bind-interfaces --dhcp-range="$subnet.10,$subnet.200,255.255.255.0,1h" \
        --dhcp-option=3,"$subnet.1" --dhcp-option=6,"$subnet.1"
      [ "$subnet" = 192.168.1 ] && { (cd "$d" && exec ip netns exec "$n" python3 -m http.server 80 --bind 192.168.1.1 >/dev/null 2>&1) & echo $! > "$d/http.pid"; }
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
[ "$v6" = none ] && exit 0
printf 'interface %s { AdvSendAdvert on; MinRtrAdvInterval 3; MaxRtrAdvInterval 10; AdvManagedFlag %s; AdvOtherConfigFlag %s; prefix 2001:db8:$id:$wan::/64 { AdvOnLink on; AdvAutonomous on; }; };\n' "\$dev" "$([ "$v6" = pd ] && echo on || echo off)" "$([ "$v6" = pd ] && echo on || echo off)" > $d/radvd.conf
radvd -C $d/radvd.conf -p $d/radvd.pid -m logfile -l $d/radvd.log
[ "$v6" = pd ] || exit 0
# one subscriber per lab: the whole delegation pool is routed down this session
ip -6 route add 2001:db8:$id:${wan}00::/56 dev "\$dev" proto static
sed "s/@DEV@/\$dev/" $d/kea6.conf.in > $d/kea6.conf
KEA_PIDFILE_DIR=$d KEA_LOCKFILE_DIR=$d setsid kea-dhcp6 -c $d/kea6.conf > $d/kea.log 2>&1 &
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
        run_ns "$n" pppoe-server -I "$dev" -O "$d/pppoe-options" -L "$subnet.1" -R "$subnet.10" -N 8 -X "$d/pppoe.pid"
      fi
      ;;
    *) die "unknown ISP mode: $mode (dhcp|pppoe|static|down)";;
  esac
  printf '%s v6=%s cgnat=%s badpass=%s nopado=%s subnet=%s\n' "$mode" "$v6" "$cgnat" "$badpass" "$nopado" "$subnet" > "$d/mode"
  echo "isp $id wan$wan $mode ($(cat "$d/mode"))"
}

# ---------------------------------------------------------------- guest install
install_cmd(){
  id=$1; shift; valid_id "$id"
  proto=dhcp; apply=1; lanip=192.168.1.1/24; release=; tree=$ROOT; runinst=1; wait=600
  while [ $# -gt 0 ]; do case $1 in
    --wan-proto) proto=$2; shift 2;; --no-apply) apply=0; shift;; --lan-ip) lanip=$2; shift 2;;
    --release) release=$2; shift 2;; --tree) tree=$(cd "$2" && pwd); shift 2;;
    --no-install) runinst=0; shift;; --timeout) wait=$2; shift 2;;
    *) die "install: unknown option $1";; esac; done
  case $proto in dhcp|pppoe|static) ;; *) die "install: --wan-proto dhcp|pppoe|static";; esac
  need genisoimage; ensure_mirror
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
  genisoimage -quiet -r -J -volid cidata -o "$d/seed.iso" -graft-points \
    user-data="$out/user-data" meta-data="$out/meta-data" network-config="$out/network-config" \
    release="$out/release" lab="$out/lab" apk-mirror="$MIRROR"
  # a fresh machine: new overlay over the pristine Alpine image
  kill_qemu "$id"; rm -f "$d/overlay.qcow2" "$d/api.cookies"
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
run_cmd(){ id=$1; scen=$2; valid_id "$id"; case $scen in */*) f=$scen;; *) f="$LABDIR/scenarios/$scen.sh";; esac; [ -x "$f" ] || die "scenario not found: $f"; LAB_SH="$LABDIR/lab.sh" "$f" "$id"; }
reboot_cmd(){ id=$1; valid_id "$id"; agent_exec "$id" 10 'sync; (sleep 1; reboot) &' >/dev/null || true; sleep 8; wait_agent "$id" 180 && echo "rebooted $id"; }
powercut_cmd(){ id=$1; valid_id "$id"; kill -9 "$(cat "$(pidfile "$id")")" 2>/dev/null || true; kill_qemu "$id"; up "$id" >/dev/null; wait_agent "$id" 180 && echo "power restored $id"; }

usage(){ die "usage: lab.sh up|down|reset|status <id> | isp <id> <wan> dhcp|pppoe|static|down [opts] | install <id> [opts] | lan <id> dhcp|static|check|exec | console|ssh <id> <cmd> | api <id> GET|POST <action> [json] | reboot|powercut <id> | run <id> <scenario>"; }
cmd=${1:-}; shift || true
case $cmd in
  up) up "$@";; down) down "$@";; status) status "$@";; reset) reset "$@";;
  isp) isp_cmd "$@";; install) install_cmd "$@";; lan) lan_cmd "$@";;
  ssh) ssh_cmd "$@";; console) console "$@";; api) api_cmd "$@";; run) run_cmd "$@";;
  reboot) reboot_cmd "$@";; powercut) powercut_cmd "$@";; mirror) ensure_mirror; echo "$MIRROR";;
  *) usage;;
esac
