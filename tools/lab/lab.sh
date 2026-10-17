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

kill_pid(){ p=$1; [ -s "$p" ] || return 0; kill "$(cat "$p")" 2>/dev/null || true; sleep 1; kill -9 "$(cat "$p")" 2>/dev/null || true; rm -f "$p"; }
ns_del(){ ip netns pids "$1" 2>/dev/null | xargs -r kill -9 2>/dev/null || true; ip netns del "$1" 2>/dev/null || true; }

up(){
  id=$1; valid_id "$id"; ensure_base; d=$(state "$id"); mkdir -p "$d"
  [ -e "$d/overlay.qcow2" ] || qemu-img create -f qcow2 -F qcow2 -b "$BASE" "$d/overlay.qcow2" >/dev/null
  for n in "$(sw "$id")" "$(isp "$id" 1)" "$(isp "$id" 2)" "$(lan "$id")"; do ip netns list | awk '{print $1}' | grep -qx "$n" || ip netns add "$n"; done
  run_ns "$(sw "$id")" ip link show br0 >/dev/null 2>&1 || run_ns "$(sw "$id")" ip link add br0 type bridge
  run_ns "$(sw "$id")" ip link set br0 up
  connect(){ a=$1; b=$2; [ -e "/sys/class/net/$a" ] || ip link add "$a" type veth peer name "$b"; ip link set "$a" netns "$(sw "$id")" 2>/dev/null || true; }
  connect "mrlab${id}s1" "mrlab${id}s1p"; ip link set "mrlab${id}s1p" netns "$(isp "$id" 1)" 2>/dev/null || true
  connect "mrlab${id}s2" "mrlab${id}s2p"; ip link set "mrlab${id}s2p" netns "$(isp "$id" 2)" 2>/dev/null || true
  connect "mrlab${id}sl" "mrlab${id}slp"; ip link set "mrlab${id}slp" netns "$(lan "$id")" 2>/dev/null || true
  for x in mrlab${id}s1 mrlab${id}s2 mrlab${id}sl; do run_ns "$(sw "$id")" ip link set "$x" master br0 2>/dev/null || true; run_ns "$(sw "$id")" ip link set "$x" up 2>/dev/null || true; done
  run_ns "$(isp "$id" 1)" ip link set lo up; run_ns "$(isp "$id" 1)" ip link set mrlab${id}s1p up
  run_ns "$(isp "$id" 2)" ip link set lo up; run_ns "$(isp "$id" 2)" ip link set mrlab${id}s2p up
  run_ns "$(lan "$id")" ip link set lo up; run_ns "$(lan "$id")" ip link set mrlab${id}slp up
  # ISP and client addresses are private to their namespaces.
  run_ns "$(isp "$id" 1)" ip addr replace "10.${id}.1.1/24" dev mrlab${id}s1p
  run_ns "$(isp "$id" 2)" ip addr replace "10.${id}.2.1/24" dev mrlab${id}s2p
  run_ns "$(lan "$id")" ip addr replace "192.168.${id}.2/24" dev mrlab${id}slp
  if [ ! -s "$(pidfile "$id")" ] || ! kill -0 "$(cat "$(pidfile "$id")")" 2>/dev/null; then
    need qemu-system-x86_64
    log=$d/console.log
    hexid=$(printf '%02x' "$id")
    accel=tcg; [ -e /dev/kvm ] && accel=kvm
    ip netns exec "$(sw "$id")" qemu-system-x86_64 -accel "$accel" -m 512 -smp 1 -drive "file=$d/overlay.qcow2,if=virtio,format=qcow2" -netdev tap,id=wan1,ifname=mrlab${id}tap0,script=no,downscript=no -device virtio-net-pci,netdev=wan1,mac=52:54:00:${hexid}:01:01 -netdev tap,id=lan,ifname=mrlab${id}tap1,script=no,downscript=no -device virtio-net-pci,netdev=lan,mac=52:54:00:${hexid}:01:02 -serial file:"$log" -display none -daemonize -pidfile "$(pidfile "$id")" 2>>"$d/qemu.err" || true
    run_ns "$(sw "$id")" ip link set mrlab${id}tap0 master br0 2>/dev/null || true
    run_ns "$(sw "$id")" ip link set mrlab${id}tap1 master br0 2>/dev/null || true
    run_ns "$(sw "$id")" ip link set mrlab${id}tap0 up 2>/dev/null || true
    run_ns "$(sw "$id")" ip link set mrlab${id}tap1 up 2>/dev/null || true
  fi
  echo "{\"id\":$id,\"state\":\"up\",\"switch\":\"$(sw "$id")\"}"
}

down(){ id=$1; valid_id "$id"; kill_pid "$(pidfile "$id")"; for n in "$(lan "$id")" "$(isp "$id" 2)" "$(isp "$id" 1)" "$(sw "$id")"; do ns_del "$n"; done; rm -rf "$(state "$id")"; echo "down $id"; }
status(){ id=$1; valid_id "$id"; p=$(pidfile "$id"); alive=false; [ -s "$p" ] && kill -0 "$(cat "$p")" 2>/dev/null && alive=true; printf '{"id":%s,"qemu":%s,"namespaces":["%s","%s","%s","%s"]}\n' "$id" "$alive" "$(sw "$id")" "$(isp "$id" 1)" "$(isp "$id" 2)" "$(lan "$id")"; }
reset(){ id=$1; valid_id "$id"; kill_pid "$(pidfile "$id")"; rm -rf "$(state "$id")"; up "$id"; }

isp_cmd(){ id=$1; wan=$2; mode=$3; shift 3; valid_id "$id"; n=$(isp "$id" "$wan"); d=$(state "$id"); mkdir -p "$d/isp$wan"; pk="$d/isp$wan/dnsmasq.pid"; kill_pid "$pk"; case $mode in
  down) run_ns "$n" ip link set "mrlab${id}s${wan}p" down; echo "isp $wan down"; return;;
  *) run_ns "$n" ip link set "mrlab${id}s${wan}p" up;; esac
  subnet="10.${id}.${wan}"; for x in "$@"; do case $x in --subnet) shift; subnet=${1%.*};; --cgnat) subnet="100.64.${id}";; esac; done
  case $mode in dhcp) run_ns "$n" dnsmasq --no-resolv --no-hosts --interface="mrlab${id}s${wan}p" --bind-interfaces --dhcp-range="${subnet}.10,${subnet}.200,255.255.255.0,1h" --dhcp-option=3,"${subnet}.1" --dhcp-option=6,1.1.1.1 --pid-file="$pk" --log-facility="$d/isp$wan/dnsmasq.log";; pppoe) echo "pppoe requested (credentials lab/labpass)" > "$d/isp$wan/mode";; static) run_ns "$n" ip addr replace "${subnet}.1/24" dev "mrlab${id}s${wan}p";; *) die "unknown ISP mode: $mode";; esac; echo "isp $id wan$wan $mode"; }

install_cmd(){ id=$1; shift; proto=dhcp; apply=1; lanip=192.168.1.1/24; release=; while [ $# -gt 0 ]; do case $1 in --wan-proto) proto=$2; shift 2;; --no-apply) apply=0; shift;; --lan-ip) lanip=$2; shift 2;; --release) release=$2; shift 2;; *) die "install: unknown option $1";; esac; done; mkdir -p "$RUNDIR/$id/install"; out=$RUNDIR/$id/install
  if [ -n "$release" ]; then curl -fL --retry 2 -o "$out/install.sh" "https://raw.githubusercontent.com/Cd1s/mini-router/$release/install.sh"; else (cd "$ROOT" && tools/release.sh lab-lab "$out/release") >/dev/null; cp "$out/release/install.sh" "$out/install.sh"; fi
  echo "MR_WAN_PROTO=$proto MR_LAN_IP=$lanip MR_APPLY=$apply" > "$out/request"; echo "install queued for lab $id ($proto)"; }

lan_cmd(){ id=$1; op=$2; valid_id "$id"; n=$(lan "$id"); case $op in dhcp) if run_ns "$n" busybox udhcpc -n -q -i mrlab${id}slp 2>/dev/null; then echo '{"dhcp":"ok"}'; else echo '{"dhcp":"requested"}'; fi;; check) run_ns "$n" sh -c 'ip -4 addr show; ip -6 addr show; getent hosts example.com >/dev/null 2>&1' && echo '{"ipv4":true,"dns":true}' || echo '{"ipv4":false,"dns":false}';; exec) shift 2; run_ns "$n" sh -c "$*";; *) die "lan: dhcp|check|exec";; esac; }
ssh_cmd(){ id=$1; shift; lan_cmd "$id" exec ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 root@192.168.1.1 "$*"; }
console(){ id=$1; shift; f=$(state "$id")/console.log; marker="MRLAB-END-$$"; printf '%s\n' "$*" >> "$f"; echo "$marker"; tail -20 "$f"; }
api_cmd(){ id=$1; method=$2; path=$3; body=${4:-}; url="http://192.168.1.1/cgi-bin/api?a=$path"; token=${MR_TOKEN:-}; [ -z "$token" ] && [ -s "$(state "$id")/api.token" ] && token=$(cat "$(state "$id")/api.token"); if [ "$method" = GET ]; then if [ -n "$token" ]; then curl -fsS -H "Authorization: Bearer $token" "$url"; else curl -fsS "$url"; fi; else if [ -n "$token" ]; then curl -fsS -H "Authorization: Bearer $token" -X POST -H 'Content-Type: application/json' -d "$body" "$url"; else curl -fsS -X POST -H 'Content-Type: application/json' -d "$body" "$url"; fi; fi; }
run_cmd(){ id=$1; scen=$2; valid_id "$id"; case $scen in *.sh) f=$scen;; *) f="$LABDIR/scenarios/$scen.sh";; esac; [ -x "$f" ] || die "scenario not found: $f"; LAB_SH="$LABDIR/lab.sh" "$f" "$id"; }

cmd=${1:-}; shift || true; case $cmd in up) up "$@";; down) down "$@";; status) status "$@";; reset) reset "$@";; isp) isp_cmd "$@";; install) install_cmd "$@";; lan) lan_cmd "$@";; ssh) ssh_cmd "$@";; console) console "$@";; reboot) id=$1; kill_pid "$(pidfile "$id")"; up "$id";; powercut) id=$1; kill_pid "$(pidfile "$id")"; up "$id";; api) api_cmd "$@";; run) run_cmd "$@";; *) die "usage: lab.sh up|down|status|reset|isp|install|lan|ssh|console|reboot|powercut|api|run";; esac
