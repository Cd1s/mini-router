#!/bin/sh
# Runs the real install.sh with the lab's answers once OpenRC finished the default runlevel.
# Output goes to /root/mr-lab-install.log and the first serial console; the last line is
# MRLAB-INSTALL-RC=<exit code>.
i=0
while [ "$i" -lt 600 ]; do
	[ "$(cat /run/openrc/softlevel 2> /dev/null)" = default ] && [ -z "$(ls /run/openrc/starting 2> /dev/null)" ] && break
	sleep 1
	i=$((i + 1))
done
sleep 2
cd /root || exit 1
{
	env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/root TERM=vt100 sh -c \
		'set -a; . /root/mr-lab-release/request.env; set +a; exec sh /root/mr-lab-release/install.sh'
	echo "MRLAB-INSTALL-RC=$?"
} < /dev/null 2>&1 | tee /root/mr-lab-install.log > /dev/ttyS0
