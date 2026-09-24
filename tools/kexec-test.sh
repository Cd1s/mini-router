#!/bin/sh
# kexec-test.sh INITRAMFS [PROVISION_CPIO] — boot a mini-router test system in RAM; the flash is not
# touched (platform, docs/flash.md). Run on the router from the directory holding the files (e.g. /tmp):
#   Image, image-mt7986a-xiaomi-redmi-router-ax6000-hanwckf.dtb, INITRAMFS (build out/m3), devmem
#   (static, out/m3; the mini-router image has its own) and optionally the provision.cpio made by
#   tools/provision.sh, which is appended so the test system boots with the real router.yaml, secrets
#   and service state (they stay in RAM).
# Works from the flashed OpenWrt (procd watchdog) and from a flashed mini-router (watchdog service).
# The hardware watchdog is re-armed (30 s, single stage) right before kexec so a hang during boot
# resets into the flash system; the test system reboots to flash after 600 s unless /tmp/keep exists.
set -u
cd "$(dirname "$0")" || exit 1
DTB=image-mt7986a-xiaomi-redmi-router-ax6000-hanwckf.dtb
INITRD=${1:-}
PROV=${2:-}
[ -n "$INITRD" ] && [ -f "$INITRD" ] || { echo "usage: kexec-test.sh INITRAMFS [PROVISION_CPIO]"; exit 2; }
for f in Image "$DTB"; do [ -f "$f" ] || { echo "missing $f"; exit 1; }; done
DEVMEM=./devmem
[ -x "$DEVMEM" ] || DEVMEM=/usr/libexec/mr/devmem
[ -x "$DEVMEM" ] || { echo "missing devmem"; exit 1; }

if [ -n "$PROV" ]; then
	[ -f "$PROV" ] || { echo "missing $PROV"; exit 1; }
	# the kernel unpacks concatenated archives in order; an uncompressed one must start 4-byte aligned
	umask 077
	cat "$INITRD" > initrd.combined || exit 1
	sz=$(wc -c < "$INITRD")
	pad=$(((4 - sz % 4) % 4))
	[ "$pad" = 0 ] || head -c "$pad" /dev/zero >> initrd.combined
	cat "$PROV" >> initrd.combined || exit 1
	INITRD=initrd.combined
fi

kexec -l Image --dtb="$DTB" --initrd="$INITRD" \
	--command-line="console=ttyS0,115200n1 earlycon=uart8250,mmio32,0x11002000 watchdog.stop_on_reboot=0 loglevel=7" ||
	{ echo "kexec load failed"; rm -f initrd.combined; exit 1; }
rm -f initrd.combined # loaded into kernel memory; it holds secrets
echo "kexec_loaded=$(cat /sys/kernel/kexec_loaded)"

# quiesce_wifi: mt76 keeps DMA-writing RX buffers after kexec into memory the new kernel reuses
# (seen on the router as a random oops ~7 s into the new kernel). Stop WiFi and unload the driver first.
quiesce_wifi() {
	if [ -e /etc/openwrt_release ] && command -v wifi > /dev/null 2>&1; then
		wifi down > /dev/null 2>&1
	else
		rc-service --ifstarted mr-hostapd stop > /dev/null 2>&1
	fi
	sleep 1
	for m in mt7915e mt76_connac_lib mt76; do rmmod "$m" 2> /dev/null; done
	[ ! -d /sys/module/mt7915e ] || echo "warning: mt7915e is still loaded"
}
quiesce_wifi

# release the watchdog cleanly (magic close) so the kernel does not stop it at kexec, then arm it directly
if command -v ubus > /dev/null 2>&1; then
	ubus call system watchdog '{"magicclose":true,"stop":true}' > /dev/null
else
	rc-service watchdog stop > /dev/null 2>&1
fi
sleep 2
"$DEVMEM" 0x1001c004 0xF008 > /dev/null   # TOPRGU WDT_LENGTH: 30 s
"$DEVMEM" 0x1001c008 0x1971 > /dev/null   # WDT_RST: reload
"$DEVMEM" 0x1001c000 0x22000001 > /dev/null # WDT_MODE: enable, single-stage reset
echo "wdt mode=$("$DEVMEM" 0x1001c000) len=$("$DEVMEM" 0x1001c004)"
sync
kexec -e
