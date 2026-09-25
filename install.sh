#!/bin/sh
# mini-router installer — turns an Alpine Linux machine (any architecture: x86_64, aarch64, armv7,
# armv6, x86, riscv64, ppc64le) into a router managed by `mr` and its web UI.
#
#   wget -O install.sh https://raw.githubusercontent.com/Cd1s/mini-router/main/install.sh
#   sh install.sh                 # interactive
#   MR_YES=1 MR_WAN=eth0 MR_LAN_PORTS="eth1 eth2" MR_ADMIN_PASS=... sh install.sh   # unattended
#
# Unattended settings (environment):
#   MR_WAN            WAN interface                      MR_WAN_PROTO   dhcp | pppoe | static
#   MR_PPPOE_USER / MR_PPPOE_PASS                        MR_WAN_ADDR / MR_WAN_GW / MR_WAN_DNS (static)
#   MR_LAN_PORTS      LAN interfaces, space separated    MR_LAN_IP      e.g. 192.168.1.1/24
#   MR_WIFI           1 = set up WiFi (if a radio exists) MR_WIFI_SSID / MR_WIFI_KEY / MR_COUNTRY
#   MR_ADMIN_PASS     web UI password (>= 8 chars)       MR_TZ          POSIX TZ, e.g. UTC0, CST-8
#   MR_VERSION        release tag (default latest)       MR_REPO        GitHub repo (default Cd1s/mini-router)
#   MR_LOCAL          directory with mr-linux-<arch> + mini-router-rootfs.tar.gz (offline install)
#   MR_YES=1          do not ask anything; fail if a required value is missing
#   MR_APPLY=0        install and write the config, but do not apply it (run `mr apply` later)
#
# What it changes: installs Alpine packages, /usr/sbin/mr, OpenRC services (mr-*), the web UI in
# /www, writes /etc/mini-router/{router.yaml,secrets.yaml}, disables Alpine's `networking` service
# (mr-network configures the interfaces from router.yaml) and applies the configuration.
# Run it from the console or from a LAN-side SSH session: the network is reconfigured at the end.
set -eu
REPO=${MR_REPO:-Cd1s/mini-router}
VERSION=${MR_VERSION:-latest}
YES=${MR_YES:-0}
CONF=/etc/mini-router

die() { echo "install: $*" >&2; exit 1; }
say() { printf '\n\033[1m%s\033[0m\n' "$*"; }

# ask VAR "question" [default] — keeps VAR if already set (environment)
ask() {
	eval "cur=\${$1:-}"
	if [ -n "$cur" ]; then return 0; fi
	if [ "$YES" = 1 ]; then
		[ -n "${3:-}" ] || die "$1 is required (MR_YES=1)"
		eval "$1=\$3"
		return 0
	fi
	printf '%s%s: ' "$2" "${3:+ [$3]}"
	read -r ans < /dev/tty || ans=
	[ -n "$ans" ] || ans=${3:-}
	eval "$1=\$ans"
}
ask_secret() {
	eval "cur=\${$1:-}"
	if [ -n "$cur" ]; then return 0; fi
	[ "$YES" = 1 ] && die "$1 is required (MR_YES=1)"
	while :; do
		printf '%s: ' "$2"
		stty -echo < /dev/tty 2> /dev/null || :
		read -r a < /dev/tty || a=
		stty echo < /dev/tty 2> /dev/null || :
		printf '\n%s: ' "再输入一次 / again"
		stty -echo < /dev/tty 2> /dev/null || :
		read -r b < /dev/tty || b=
		stty echo < /dev/tty 2> /dev/null || :
		echo
		if [ "$a" = "$b" ] && [ ${#a} -ge "${3:-1}" ]; then break; fi
		echo "不一致或太短（至少 ${3:-1} 位）/ mismatch or too short"
	done
	eval "$1=\$a"
}
yaml_str() { # single-quoted YAML scalar
	printf "'%s'" "$(printf '%s' "$1" | sed "s/'/''/g")"
}

# ---------------------------------------------------------------- checks
[ "$(id -u)" = 0 ] || die "run as root"
[ -f /etc/alpine-release ] || die "this installer needs Alpine Linux (OpenRC); see README for other options"
command -v rc-update > /dev/null || apk add -q openrc || die "OpenRC not found and could not be installed"
case $(uname -m) in
x86_64) ARCH=amd64 ;;
aarch64 | arm64) ARCH=arm64 ;;
armv7* | armv8l) ARCH=armv7 ;;
armv6* | arm) ARCH=armv6 ;;
i?86 | x86) ARCH=386 ;;
riscv64) ARCH=riscv64 ;;
ppc64le) ARCH=ppc64le ;;
*) die "unsupported architecture $(uname -m)" ;;
esac
say "mini-router installer — Alpine $(cat /etc/alpine-release), $(uname -m) → mr-linux-$ARCH"

# ---------------------------------------------------------------- packages
say "1/5 安装软件包 / installing packages"
PKGS="ca-certificates ssl_client busybox-extras busybox-openrc iproute2 nftables dnsmasq dnsmasq-openrc
ppp-daemon ppp-pppoe dhcpcd iw"
HAVE_WIFI=0
if [ -n "$(ls /sys/class/ieee80211 2> /dev/null)" ]; then
	HAVE_WIFI=1
	PKGS="$PKGS hostapd wireless-regdb"
fi
# shellcheck disable=SC2086
apk add -q $PKGS || die "apk add failed (check /etc/apk/repositories: main + community)"

# ---------------------------------------------------------------- mr + rootfs
say "2/5 下载 mini-router / fetching mini-router ($VERSION)"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
if [ -n "${MR_LOCAL:-}" ]; then
	cp "$MR_LOCAL/mr-linux-$ARCH" "$TMP/mr" && cp "$MR_LOCAL/mini-router-rootfs.tar.gz" "$TMP/rootfs.tgz" ||
		die "MR_LOCAL: need mr-linux-$ARCH and mini-router-rootfs.tar.gz"
else
	if [ "$VERSION" = latest ]; then
		base="https://github.com/$REPO/releases/latest/download"
	else
		base="https://github.com/$REPO/releases/download/$VERSION"
	fi
	wget -q -O "$TMP/mr" "$base/mr-linux-$ARCH" || die "download $base/mr-linux-$ARCH failed"
	wget -q -O "$TMP/rootfs.tgz" "$base/mini-router-rootfs.tar.gz" || die "download rootfs failed"
	wget -q -O "$TMP/SHA256SUMS" "$base/SHA256SUMS" || die "download SHA256SUMS failed"
	(cd "$TMP" &&
		grep " mr-linux-$ARCH\$" SHA256SUMS | sed "s/mr-linux-$ARCH/mr/" | sha256sum -c -s &&
		grep " mini-router-rootfs.tar.gz\$" SHA256SUMS | sed 's/mini-router-rootfs.tar.gz/rootfs.tgz/' | sha256sum -c -s) ||
		die "checksum mismatch"
fi
install -m 0755 "$TMP/mr" /usr/sbin/mr
tar -xzf "$TMP/rootfs.tgz" -C / --no-same-owner
chown -R 0:0 /etc/init.d /usr/libexec/mr /www 2> /dev/null || :
mkdir -p "$CONF/dns" "$CONF/proxy" "$CONF/state"
echo "mr $(/usr/sbin/mr version)"

# ---------------------------------------------------------------- questions
say "3/5 基本设置 / settings"
ifaces=$(for d in /sys/class/net/*; do
	n=${d##*/}
	[ -e "$d/device" ] || continue          # physical NICs only
	[ -d "$d/phy80211" ] && continue          # WiFi is set up separately
	echo "$n"
done | tr '\n' ' ')
if [ -z "$ifaces" ]; then # VMs / containers: virtual NICs
	ifaces=$(for d in /sys/class/net/*; do
		case ${d##*/} in lo | br-* | docker* | veth* | tailscale* | wg* | ifb* | dummy* | sit* | ip6tnl* | tun*) ;; *) echo "${d##*/}" ;; esac
	done | tr '\n' ' ')
fi
[ -n "$ifaces" ] || [ -n "${MR_WAN:-}" ] || die "no network interfaces found"
defwan=$(ip route show default 2> /dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "dev") { print $(i + 1); exit }}')
[ -n "$defwan" ] || defwan=${ifaces%% *}
echo "网卡 / interfaces: $ifaces"
ask MR_WAN "WAN 网口（接光猫/上级路由）/ WAN interface" "$defwan"
[ -e "/sys/class/net/$MR_WAN" ] || die "no interface $MR_WAN"
deflan=$(echo "$ifaces" | tr ' ' '\n' | grep -vx "$MR_WAN" | tr '\n' ' ' | sed 's/ $//')
ask MR_LAN_PORTS "LAN 网口（空格分隔）/ LAN interfaces" "$deflan"
[ -n "$MR_LAN_PORTS" ] || die "at least one LAN interface is needed"
for p in $MR_LAN_PORTS; do
	[ "$p" != "$MR_WAN" ] || die "$p cannot be both WAN and LAN"
	[ -e "/sys/class/net/$p" ] || die "no interface $p"
done
ask MR_WAN_PROTO "WAN 类型 dhcp / pppoe / static" dhcp
case $MR_WAN_PROTO in
pppoe)
	ask MR_PPPOE_USER "PPPoE 账号 / username"
	ask_secret MR_PPPOE_PASS "PPPoE 密码 / password" 1
	;;
static)
	ask MR_WAN_ADDR "WAN 地址/掩码 / address (e.g. 203.0.113.10/24)"
	ask MR_WAN_GW "网关 / gateway"
	ask MR_WAN_DNS "DNS（空格分隔）/ DNS servers" "1.1.1.1 8.8.8.8"
	;;
dhcp) ;;
*) die "WAN type must be dhcp, pppoe or static" ;;
esac
ask MR_LAN_IP "路由器 LAN 地址/掩码 / router LAN address" "192.168.1.1/24"
MR_WIFI=${MR_WIFI:-}
if [ "$HAVE_WIFI" = 1 ]; then
	ask MR_WIFI "发现无线网卡，设置 WiFi？/ set up WiFi? (y/n)" y
	case $MR_WIFI in y | Y | yes | 1) MR_WIFI=1 ;; *) MR_WIFI=0 ;; esac
else
	MR_WIFI=0
fi
if [ "$MR_WIFI" = 1 ]; then
	ask MR_WIFI_SSID "WiFi 名称 / SSID" "mini-router"
	ask_secret MR_WIFI_KEY "WiFi 密码（至少 8 位）/ WiFi password" 8
	ask MR_COUNTRY "国家码 / country code (2 letters)" "US"
fi
ask_secret MR_ADMIN_PASS "网页管理员密码（至少 8 位）/ web UI admin password" 8
ask MR_TZ "时区 POSIX TZ（UTC0、CST-8、<+07>-7 …）/ timezone" "UTC0"

# ---------------------------------------------------------------- router.yaml
say "4/5 生成配置 / writing $CONF/router.yaml"
if [ -f "$CONF/router.yaml" ]; then
	cp "$CONF/router.yaml" "$CONF/router.yaml.before-install"
	echo "existing router.yaml saved as router.yaml.before-install"
fi
host=${MR_LAN_IP%/*}
ssh_enabled=false
[ -e /etc/runlevels/default/dropbear ] && ssh_enabled=true # keep a dropbear the machine already uses
wd=true
[ -e /dev/watchdog ] || wd=false
lan_list=$(printf '%s\n' $MR_LAN_PORTS | sed 's/.*/"&"/' | paste -sd, -)
umask 077
{
	echo "# mini-router config — generated by install.sh; edit here or in the web UI (http://$host/)"
	echo "system:"
	echo "  hostname: mini-router"
	echo "  timezone: $(yaml_str "$MR_TZ")"
	echo "  ntp: [pool.ntp.org, time.cloudflare.com]"
	echo "  sysctl: {net.ipv4.tcp_congestion_control: bbr}"
	echo "  zram: false"
	echo "  watchdog: $wd"
	echo "lan:"
	echo "  bridge: br-lan"
	echo "  ports: [$lan_list]"
	echo "  ipv4: $MR_LAN_IP"
	echo "  ipv6_ra: true"
	echo "wan:"
	echo "  - name: wan"
	echo "    device: $MR_WAN"
	echo "    proto: $MR_WAN_PROTO"
	case $MR_WAN_PROTO in
	pppoe)
		echo "    username: $(yaml_str "$MR_PPPOE_USER")"
		echo "    password_secret: pppoe_password"
		echo "    peerdns: true"
		;;
	static)
		echo "    ipv4: $MR_WAN_ADDR"
		echo "    gateway: $MR_WAN_GW"
		echo "    dns: [$(printf '%s\n' $MR_WAN_DNS | paste -sd, -)]"
		;;
	dhcp) echo "    peerdns: true" ;;
	esac
	echo "    ipv6: true"
	echo "    ipv6_pd: true"
	echo "policy_routes: []"
	echo "static_routes: []"
	echo "multicast: {igmp_snooping: false, igmp_proxy: false}"
	echo "firewall:"
	echo "  offload: software"
	echo "  synflood_protect: true"
	echo "  forwards: []"
	echo "  open: []"
	echo "dhcp:"
	echo "  start: 100"
	echo "  end: 249"
	echo "  lease: 12h"
	echo "  domain: lan"
	echo "  hosts: []"
	echo "dns:"
	echo "  cache_size: 4000"
	echo "  rebind_protection: true"
	echo "  local_service: true"
	echo "  redirect: false"
	echo "wifi:"
	if [ "$MR_WIFI" = 1 ]; then
		echo "  country: $MR_COUNTRY"
		echo "  radios:"
		n=0
		seen=""
		for p in /sys/class/ieee80211/*; do
			info=$(iw phy "${p##*/}" info 2> /dev/null)
			for band in 1 2; do
				echo "$info" | grep -q "Band $band:" || continue
				if [ $band = 1 ]; then b=2g ch=6 mode=HT20; else b=5g ch=36 mode=HT40; fi
				if [ $band = 2 ] && echo "$info" | grep -q "VHT Capabilities"; then mode=VHT80; fi
				if echo "$info" | grep -q "HE Iftypes"; then mode=HE${mode##*HT}; fi
				case " $seen " in *" $b "*) continue ;; esac
				seen="$seen $b"
				suffix=""
				[ $b = 5g ] && suffix="-5G"
				echo "    - {phy: phy$n, band: $b, profile: generic, channel: \"$ch\", htmode: $mode, txpower: 0, ssids: [{ssid: $(yaml_str "$MR_WIFI_SSID$suffix"), key_secret: wifi_key, encryption: psk2}]}"
				n=$((n + 1))
			done
		done
	else
		echo "  radios: []"
	fi
	echo "services:"
	echo "  tailscale: {enabled: false}"
	echo "  lucky: {enabled: false}"
	echo "  dstatus: {enabled: false}"
	echo "  stubby: {enabled: false}"
	echo "  ssh: {enabled: $ssh_enabled, port: 22, password_login: true}"
	echo "  panel: {enabled: true}"
} > "$CONF/router.yaml"
{
	[ "$MR_WAN_PROTO" = pppoe ] && echo "pppoe_password: $(yaml_str "$MR_PPPOE_PASS")"
	[ "$MR_WIFI" = 1 ] && echo "wifi_key: $(yaml_str "$MR_WIFI_KEY")"
	:
} > "$CONF/secrets.yaml"
chmod 600 "$CONF/secrets.yaml"
umask 022
printf '%s\n' "$MR_ADMIN_PASS" | /usr/sbin/mr passwd > /dev/null
/usr/sbin/mr validate || die "router.yaml is not valid (fix $CONF/router.yaml and run: mr apply)"

# ---------------------------------------------------------------- apply
if [ "${MR_APPLY:-1}" = 0 ]; then
	say "MR_APPLY=0: configuration written, nothing applied. Run 'mr apply' when ready."
	exit 0
fi
say "5/5 应用 / applying"
echo "WAN $MR_WAN ($MR_WAN_PROTO) · LAN $MR_LAN_PORTS · $MR_LAN_IP · WiFi $([ "$MR_WIFI" = 1 ] && echo "$MR_WIFI_SSID" || echo off)"
echo "网络会被重新配置 / the network is reconfigured now."
if [ "$YES" != 1 ]; then
	printf '继续？/ continue? (y/n) [y]: '
	read -r go < /dev/tty || go=y
	case ${go:-y} in y | Y | yes) ;; *) die "stopped; run 'mr apply' when ready" ;; esac
fi
# mr-network owns the interfaces from now on; Alpine's ifupdown and its dhcpcd service would fight it
for s in networking dhcpcd; do
	for rl in boot default; do rc-update del "$s" "$rl" > /dev/null 2>&1 || :; done
done
[ -f /etc/network/interfaces ] && mv /etc/network/interfaces /etc/network/interfaces.before-mini-router
# a change that was never confirmed (power cut in the confirm window) is rolled back at the next boot
rc-update add mr-unconfirmed boot > /dev/null 2>&1 || :
/usr/sbin/mr apply || die "apply failed (it was rolled back); see 'mr plan' and /var/log/messages"
say "完成 / done: http://$host/  (admin password as entered)"
echo "配置文件 / config: $CONF/router.yaml · 命令 / commands: mr plan | mr apply | mr status | mr rollback"
