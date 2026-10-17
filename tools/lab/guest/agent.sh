#!/bin/sh
# Lab control channel: a root shell on the virtio-serial port "mrlab.agent" (host side:
# state/mrlab<ID>/agent.in and agent.out). Started at every boot from /etc/local.d; lab.sh console
# sends commands framed by markers. Not a tty, so the shell is non-interactive and nothing echoes.
port=
for p in /sys/class/virtio-ports/*; do
	[ "$(cat "$p/name" 2> /dev/null)" = mrlab.agent ] && port=/dev/${p##*/}
done
[ -c "$port" ] || exit 0
if [ -s /run/mrlab-agent.pid ] && kill -0 "$(cat /run/mrlab-agent.pid)" 2> /dev/null; then exit 0; fi
(
	export PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/root
	cd /root || exit 1
	# a virtio port can be opened only once: one read-write descriptor for input and output
	while :; do
		exec 3<> "$port"
		echo "MRLAB-AGENT-READY $(cat /proc/sys/kernel/random/boot_id)" >&3
		sh <&3 >&3 2>&3
		exec 3>&-
		sleep 1
	done
) < /dev/null > /dev/null 2>&1 &
echo $! > /run/mrlab-agent.pid
