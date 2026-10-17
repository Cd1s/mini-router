#!/bin/sh
# Isolated mini-router laboratory.  All links created by this script live in lab netns.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
LABDIR=$ROOT/tools/lab
IMGDIR=${MR_LAB_IMAGE_DIR:-/root/build/mr-lab-images}
RUNDIR=$LABDIR/state
BASE=$IMGDIR/alpine-3.24-x86_64.qcow2
mkdir -p "$IMGDIR" "$RUNDIR"

die(){ echo "lab: $*" >&2; exit 1; }
need(){ command -v "$1" >/dev/null 2>&1 || die "missing dependency: $1"; }
valid_id(){ case ${1:-} in 1|2|3|4|5|6|7|8) ;; *) die "lab id must be 1..8";; esac; }
ns(){ echo "mrlab$1"; }
state(){ echo "$RUNDIR/mrlab$1"; }
sw(){ echo "mrlab$1-sw"; }; isp(){ echo "mrlab$1-isp$2"; }; lan(){ echo "mrlab$1-lan"; }
router_ip(){ cat "$(state "$1")/lan.ip" 2>/dev/null || echo 192.168.1.1; }
run_ns(){ n=$1; shift; ip netns exec "$n" "$@"; }
pidfile(){ echo "$(state "$1")/qemu.pid"; }

ensure_base(){
  [ -s "$BASE" ] && return 0
  need curl; need qemu-img
  tmp=$BASE.part
  echo "Downloading Alpine 3.24 cloud image..."
  curl -fL --retry 3 -o "$tmp" "https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/cloud/generic_alpine-3.24.1-x86_64-bios-cloudinit-r0.qcow2"
  mv "$tmp" "$BASE"
  qemu-img info "$BASE" >/dev/null || die "invalid Alpine image"
}

kill_pid(){
  p=$1
  if [ -s "$p" ]; then
    pid=$(cat "$p"); kill "$pid" 2>/dev/null || true; sleep 1; kill -9 "$pid" 2>/dev/null || true; rm -f "$p"; return 0
  fi
  case $p in */mrlab[0-9]*/qemu.pid)
    ov=${p%/qemu.pid}/overlay.qcow2
    for pid in $(ps -eo pid=,args= | awk -v f="$ov" '$0 ~ f {print $1}'); do kill -9 "$pid" 2>/dev/null || true; done ;;
  esac
}
ns_del(){ ip netns pids "$1" 2>/dev/null | xargs -r kill -9 2>/dev/null || true; ip netns del "$1" 2>/dev/null || true; }
cleanup_host_links(){
  id=$1
  for x in mrlab${id}s1 mrlab${id}s1p mrlab${id}s2 mrlab${id}s2p mrlab${id}sl mrlab${id}slp; do
    ip link del "$x" 2>/dev/null || true
  done
}
slirp_start(){
  sid=$1; swan=$2; sn=$(isp "$sid" "$swan"); sd=$(state "$sid")/isp$swan; mkdir -p "$sd"
  [ -s "$sd/slirp.pid" ] && kill -0 "$(cat "$sd/slirp.pid")" 2>/dev/null && return 0
  if [ ! -s "$sd/slirp-target.pid" ] || ! kill -0 "$(cat "$sd/slirp-target.pid")" 2>/dev/null; then
    ip netns exec "$sn" sleep 2147483 & echo $! > "$sd/slirp-target.pid"
  fi
  slirp4netns --configure "$(cat "$sd/slirp-target.pid")" tap0 >"$sd/slirp.log" 2>&1 & echo $! > "$sd/slirp.pid"
  sleep 1
  run_ns "$sn" ip route replace default via 10.0.2.2 dev tap0 2>/dev/null || true
  run_ns "$sn" sysctl -q -w net.ipv4.ip_forward=1 2>/dev/null || true
}

up(){
  id=$1; valid_id "$id"; ensure_base; d=$(state "$id"); mkdir -p "$d"
  [ -e "$d/overlay.qcow2" ] || qemu-img create -f qcow2 -F qcow2 -b "$BASE" "$d/overlay.qcow2" >/dev/null
  for n in "$(sw "$id")" "$(isp "$id" 1)" "$(isp "$id" 2)" "$(lan "$id")"; do ip netns list | awk '{print $1}' | grep -qx "$n" || ip netns add "$n"; done
  for br in br-wan1 br-wan2 br-lan; do
    run_ns "$(sw "$id")" ip link show "$br" >/dev/null 2>&1 || run_ns "$(sw "$id")" ip link add "$br" type bridge
    run_ns "$(sw "$id")" ip link set "$br" up
  done
  cleanup_host_links "$id"
  connect(){ a=$1; b=$2; target=$3; ip link add "$a" type veth peer name "$b"; ip link set "$a" netns "$(sw "$id")"; ip link set "$b" netns "$target"; }
  connect "mrlab${id}s1" "mrlab${id}s1p" "$(isp "$id" 1)"
  connect "mrlab${id}s2" "mrlab${id}s2p" "$(isp "$id" 2)"
  connect "mrlab${id}sl" "mrlab${id}slp" "$(lan "$id")"
  run_ns "$(sw "$id")" ip link set mrlab${id}s1 master br-wan1; run_ns "$(sw "$id")" ip link set mrlab${id}s1 up
  run_ns "$(sw "$id")" ip link set mrlab${id}s2 master br-wan2; run_ns "$(sw "$id")" ip link set mrlab${id}s2 up
  run_ns "$(sw "$id")" ip link set mrlab${id}sl master br-lan; run_ns "$(sw "$id")" ip link set mrlab${id}sl up
  run_ns "$(isp "$id" 1)" ip link set lo up; run_ns "$(isp "$id" 1)" ip link set mrlab${id}s1p up
  run_ns "$(isp "$id" 2)" ip link set lo up; run_ns "$(isp "$id" 2)" ip link set mrlab${id}s2p up
  run_ns "$(lan "$id")" ip link set lo up; run_ns "$(lan "$id")" ip link set mrlab${id}slp up
  # ISP and client addresses are private to their namespaces.
  run_ns "$(isp "$id" 1)" ip addr replace "10.${id}.1.1/24" dev mrlab${id}s1p
  run_ns "$(isp "$id" 2)" ip addr replace "10.${id}.2.1/24" dev mrlab${id}s2p
  run_ns "$(lan "$id")" ip addr replace "192.168.1.2/24" dev mrlab${id}slp
  printf '%s\n' 192.168.1.1 > "$(state "$id")/lan.ip"
  if [ ! -s "$(pidfile "$id")" ] || ! kill -0 "$(cat "$(pidfile "$id")")" 2>/dev/null; then
    need qemu-system-x86_64
    log=$d/console.log
    hexid=$(printf '%02x' "$id")
    accel=tcg; [ -e /dev/kvm ] && accel=kvm
    seedarg=; [ -s "$d/seed.iso" ] && seedarg="-drive file=$d/seed.iso,media=cdrom,readonly=on"
    rm -f "$d/serial.sock"
    ip netns exec "$(sw "$id")" qemu-system-x86_64 -accel "$accel" -m 512 -smp 1 -drive "file=$d/overlay.qcow2,if=virtio,format=qcow2" $seedarg -netdev tap,id=wan1,ifname=mrlab${id}tap0,script=no,downscript=no -device virtio-net-pci,netdev=wan1,mac=52:54:00:${hexid}:01:01 -netdev tap,id=lan,ifname=mrlab${id}tap1,script=no,downscript=no -device virtio-net-pci,netdev=lan,mac=52:54:00:${hexid}:01:02 -chardev socket,id=ser,path="$d/serial.sock",server=on,wait=off -serial chardev:ser -display none -daemonize -pidfile "$(pidfile "$id")" 2>>"$d/qemu.err" || true
    run_ns "$(sw "$id")" ip link set mrlab${id}tap0 master br-wan1 2>/dev/null || true
    run_ns "$(sw "$id")" ip link set mrlab${id}tap1 master br-lan 2>/dev/null || true
    run_ns "$(sw "$id")" ip link set mrlab${id}tap0 up 2>/dev/null || true
    run_ns "$(sw "$id")" ip link set mrlab${id}tap1 up 2>/dev/null || true
  fi
  echo "{\"id\":$id,\"state\":\"up\",\"switch\":\"$(sw "$id")\"}"
}

down(){ id=$1; valid_id "$id"; kill_pid "$(pidfile "$id")"; for w in 1 2; do kill_pid "$(state "$id")/isp$w/slirp.pid"; kill_pid "$(state "$id")/isp$w/slirp-target.pid"; done; for n in "$(lan "$id")" "$(isp "$id" 2)" "$(isp "$id" 1)" "$(sw "$id")"; do ns_del "$n"; done; cleanup_host_links "$id"; rm -rf "$(state "$id")"; echo "down $id"; }
status(){ id=$1; valid_id "$id"; p=$(pidfile "$id"); alive=false; [ -s "$p" ] && kill -0 "$(cat "$p")" 2>/dev/null && alive=true; printf '{"id":%s,"qemu":%s,"namespaces":["%s","%s","%s","%s"]}\n' "$id" "$alive" "$(sw "$id")" "$(isp "$id" 1)" "$(isp "$id" 2)" "$(lan "$id")"; }
reset(){ id=$1; valid_id "$id"; kill_pid "$(pidfile "$id")"; rm -rf "$(state "$id")"; up "$id"; }

isp_cmd(){
  id=$1; wan=$2; mode=$3; shift 3; valid_id "$id"; n=$(isp "$id" "$wan"); d=$(state "$id"); mkdir -p "$d/isp$wan"; pk="$d/isp$wan/dnsmasq.pid"; kill_pid "$pk"; kill_pid "$d/isp$wan/pppoe.pid"
  [ "$mode" = down ] && { run_ns "$n" ip link set "mrlab${id}s${wan}p" down; echo "isp $wan down"; return; }
  run_ns "$n" ip link set "mrlab${id}s${wan}p" up
  subnet="10.${id}.${wan}"; badpass=0; nopado=0; cgnat=0; v6=none; same=
  while [ $# -gt 0 ]; do case $1 in v6=*) v6=${1#v6=};; --subnet) shift; same=${1%.*};; --cgnat) cgnat=1;; --badpass) badpass=1;; nopado|--nopado) nopado=1;; esac; shift; done
  [ "$mode" = pppoe ] && subnet="203.0.113"
  [ "$cgnat" = 1 ] && subnet="100.64.${id}"
  slirp_start "$id" "$wan"
  case $mode in
    dhcp) run_ns "$n" dnsmasq --no-resolv --no-hosts --server=10.0.2.3 --interface="mrlab${id}s${wan}p" --bind-interfaces --dhcp-range="${same:-$subnet}.10,${same:-$subnet}.200,255.255.255.0,1h" --dhcp-option=3,"${same:-$subnet}.1" --dhcp-option=6,"${same:-$subnet}.1" --address=/isp.test/${same:-$subnet}.1 --pid-file="$pk" --log-facility="$d/isp$wan/dnsmasq.log";;
    static) run_ns "$n" ip addr replace "${subnet}.1/24" dev "mrlab${id}s${wan}p";;
    pppoe)
      printf '* lab %s %s\n' "${badpass:+badpass}" > "$d/isp$wan/chap-secrets"; [ "$badpass" = 0 ] && printf 'lab * labpass *\n' >> "$d/isp$wan/chap-secrets" || printf 'lab * wrongpass *\n' >> "$d/isp$wan/chap-secrets"
      cp "$d/isp$wan/chap-secrets" "$d/isp$wan/pap-secrets"
      cat > "$d/isp$wan/pppoe-options" <<EOF
auth
require-chap
mschap-v2
mtu 1492
mru 1492
noipdefault
ms-dns 10.0.2.3
ipv6 ,::
ip-up-script $d/isp$wan/ipv6-up.sh
EOF
      cat > "$d/isp$wan/ipv6-up.sh" <<EOF
#!/bin/sh
dev=\$1
ip -6 addr add 2001:db8:${id}:${wan}::1/64 dev "\$dev" 2>/dev/null || true
cat > "$d/isp$wan/radvd.conf" <<RA
interface \$dev { AdvSendAdvert on; MinRtrAdvInterval 3; MaxRtrAdvInterval 10; prefix 2001:db8:${id}:${wan}::/64 { AdvOnLink on; AdvAutonomous on; }; };
RA
radvd -C "$d/isp$wan/radvd.conf" -n -p "$d/isp$wan/radvd.pid" >/dev/null 2>&1 &
[ "$v6" = pd ] || [ "$v6" = slaac+pd ] && {
cat > "$d/isp$wan/kea6.conf" <<KEACONF
{"Dhcp6":{"interfaces-config":{"interfaces":["\$dev"]},"lease-database":{"type":"memfile","persist":false},"subnet6":[{"subnet":"2001:db8:${id}:${wan}::/60","pd-pools":[{"prefix":"2001:db8:${id}:${wan}::","prefix-len":60,"delegated-len":64}]}]}}
KEACONF
kea-dhcp6 -c "$d/isp$wan/kea6.conf" >/dev/null 2>&1 &
}
EOF
      chmod +x "$d/isp$wan/ipv6-up.sh"
      if [ "$nopado" = 0 ]; then run_ns "$n" pppoe-server -I "mrlab${id}s${wan}p" -O "$d/isp$wan/pppoe-options" -L "${subnet}.1" -R "${subnet}.10" -N 8 -X "$d/isp$wan/pppoe.pid" >/dev/null 2>&1 || true; fi
      printf 'pppoe mode=%s v6=%s cgnat=%s badpass=%s nopado=%s\n' "$mode" "$v6" "$cgnat" "$badpass" "$nopado" > "$d/isp$wan/mode";;
    *) die "unknown ISP mode: $mode";;
  esac
  echo "isp $id wan$wan $mode"
}

install_cmd(){
  id=$1; shift; proto=dhcp; apply=1; lanip=192.168.1.1/24; release=; while [ $# -gt 0 ]; do case $1 in --wan-proto) proto=$2; shift 2;; --no-apply) apply=0; shift;; --lan-ip) lanip=$2; shift 2;; --release) release=$2; shift 2;; *) die "install: unknown option $1";; esac; done
  mkdir -p "$RUNDIR/$id/install" "$(state "$id")"; out=$RUNDIR/$id/install; assets=$out/release
  if [ -n "$release" ]; then
    mkdir -p "$assets"; curl -fL --retry 2 -o "$assets/install.sh" "https://raw.githubusercontent.com/Cd1s/mini-router/$release/install.sh"
    curl -fL --retry 2 -o "$assets/mr-linux-amd64" "https://github.com/Cd1s/mini-router/releases/download/$release/mr-linux-amd64"
    curl -fL --retry 2 -o "$assets/mini-router-rootfs.tar.gz" "https://github.com/Cd1s/mini-router/releases/download/$release/mini-router-rootfs.tar.gz"
  else (cd "$ROOT" && tools/release.sh lab-lab "$assets") >/dev/null; fi
  cat > "$out/user-data" <<EOF
#cloud-config
hostname: mrlab$id
ssh_pwauth: true
chpasswd:
  list: |
    root: labpass
  expire: false
write_files:
  - path: /etc/network/interfaces
    content: |
      auto lo
      iface lo inet loopback
      auto eth0
      iface eth0 inet dhcp
      auto eth1
      iface eth1 inet static
        address $lanip
  - path: /root/mr-lab-install.sh
    permissions: '0755'
    content: |
      #!/bin/sh
      mkdir -p /root/mr-lab-release
      mount -L cidata /mnt 2>/dev/null || mount /dev/sr0 /mnt 2>/dev/null || true
      cp -a /mnt/release/. /root/mr-lab-release/
      MR_YES=1 MR_LOCAL=/root/mr-lab-release MR_WAN=eth0 MR_LAN_PORTS=eth1 MR_ADMIN_PASS=labpass MR_WAN_PROTO=$proto MR_LAN_IP=$lanip MR_PPPOE_USER=lab MR_PPPOE_PASS=labpass MR_APPLY=$apply sh /root/mr-lab-release/install.sh > /root/mr-lab-install.log 2>&1 || true
      ip link set eth1 up 2>/dev/null || true
      ip addr replace $lanip dev eth1 2>/dev/null || true
      touch /root/mr-lab-install.done
runcmd:
  - [ sh, /root/mr-lab-install.sh ]
EOF
  cat > "$out/meta-data" <<EOF
instance-id: mrlab$id
local-hostname: mrlab$id
EOF
  cat > "$out/network-config" <<EOF
version: 2
ethernets:
  eth0: {dhcp4: true}
  eth1:
    addresses: [$lanip]
EOF
  rm -f "$(state "$id")/seed.iso"
  genisoimage -quiet -volid cidata -o "$(state "$id")/seed.iso" -graft-points user-data="$out/user-data" meta-data="$out/meta-data" network-config="$out/network-config" release="$assets" >/dev/null
  # Recreate the switch namespaces so the seed is attached on the first guest boot and no
  # previous tap/veth endpoint survives the restart.
  kill_pid "$(pidfile "$id")"
  for n in "$(lan "$id")" "$(isp "$id" 2)" "$(isp "$id" 1)" "$(sw "$id")"; do ns_del "$n"; done
  cleanup_host_links "$id"
  up "$id"
  isp_cmd "$id" 1 "$proto" 2>/dev/null || true
  echo "MR_WAN_PROTO=$proto MR_LAN_IP=$lanip MR_APPLY=$apply" > "$out/request"
  echo "install started in guest $id ($proto); completion marker is /root/mr-lab-install.done"
}

lan_cmd(){ id=$1; op=$2; valid_id "$id"; n=$(lan "$id"); case $op in dhcp) if run_ns "$n" busybox udhcpc -n -q -i mrlab${id}slp 2>/dev/null; then echo '{"dhcp":"ok"}'; else echo '{"dhcp":"requested"}'; fi;; check) run_ns "$n" sh -c 'ip -4 addr show; ip -6 addr show; getent hosts example.com >/dev/null 2>&1' && echo '{"ipv4":true,"dns":true}' || echo '{"ipv4":false,"dns":false}';; exec) shift 2; run_ns "$n" sh -c "$*";; *) die "lan: dhcp|check|exec";; esac; }
ssh_cmd(){ id=$1; shift; lan_cmd "$id" exec ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 root@"$(router_ip "$id")" "$*"; }
console(){ id=$1; shift; f=$(state "$id")/console.log; marker="MRLAB-END-$$"; if [ -S "$(state "$id")/serial.sock" ] && command -v socat >/dev/null 2>&1; then printf '%s\necho %s\n' "$*" "$marker" | timeout 8 socat - "UNIX-CONNECT:$(state "$id")/serial.sock" || true; else printf '%s\n' "$*" >> "$f"; echo "$marker"; tail -20 "$f"; fi; }
api_cmd(){
  id=$1; method=$2; path=$3; body=${4:-}; n=$(lan "$id"); jar=$(state "$id")/api.cookies; url="http://$(router_ip "$id")/cgi-bin/api?a=$path"
  # Session API uses X-MR plus a cookie. Log in on every invocation so a fresh test agent can run
  # one command without knowing the session format. Token auth remains available via MR_TOKEN.
  token=${MR_TOKEN:-}; [ -z "$token" ] && [ -s "$(state "$id")/api.token" ] && token=$(cat "$(state "$id")/api.token")
  if [ -n "$token" ]; then
    if [ "$method" = GET ]; then run_ns "$n" curl -fsS -H "Authorization: Bearer $token" "$url"; else run_ns "$n" curl -fsS -H "Authorization: Bearer $token" -X POST -H 'Content-Type: application/json' -d "$body" "$url"; fi
    return
  fi
  run_ns "$n" curl -fsS -c "$jar" -b "$jar" -H X-MR:1 -X POST -H 'Content-Type: application/json' -d '{"password":"labpass"}' "http://$(router_ip "$id")/cgi-bin/api?a=login" >/dev/null 2>&1 || true
  if [ "$method" = GET ]; then run_ns "$n" curl -fsS -c "$jar" -b "$jar" -H X-MR:1 "$url"; else run_ns "$n" curl -fsS -c "$jar" -b "$jar" -H X-MR:1 -X POST -H 'Content-Type: application/json' -d "$body" "$url"; fi
}
run_cmd(){ id=$1; scen=$2; valid_id "$id"; case $scen in *.sh) f=$scen;; *) f="$LABDIR/scenarios/$scen.sh";; esac; [ -x "$f" ] || die "scenario not found: $f"; LAB_SH="$LABDIR/lab.sh" "$f" "$id"; }

cmd=${1:-}; shift || true; case $cmd in up) up "$@";; down) down "$@";; status) status "$@";; reset) reset "$@";; isp) isp_cmd "$@";; install) install_cmd "$@";; lan) lan_cmd "$@";; ssh) ssh_cmd "$@";; console) console "$@";; reboot) id=$1; kill_pid "$(pidfile "$id")"; up "$id";; powercut) id=$1; kill_pid "$(pidfile "$id")"; up "$id";; api) api_cmd "$@";; run) run_cmd "$@";; *) die "usage: lab.sh up|down|status|reset|isp|install|lan|ssh|console|reboot|powercut|api|run";; esac
