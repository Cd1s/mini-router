# hostapd with OpenWrt's noscan patch

Alpine's hostapd 2.11 plus `300-noscan.patch` (from OpenWrt, Felix Fietkau) so 2.4 GHz can stay on
HT40 instead of falling back to 20 MHz after the 20/40 coexistence scan. Nothing else is changed.

Build (on the build host, arm64 Alpine container):

    mkdir -p /root/build/hostapd-noscan && cp build/hostapd/* /root/build/hostapd-noscan/
    docker run --rm --platform linux/arm64 -v /root/build/hostapd-noscan:/work alpine:3.24 sh /work/build.sh

The package lands in `pkgs/main/aarch64/hostapd-2.11-r1xx.apk` (the "untrusted signature / failed
to create index" error at the end is harmless); the image build extracts `/usr/sbin/hostapd` from it.
