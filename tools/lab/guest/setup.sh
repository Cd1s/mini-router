#!/bin/sh
# First boot only (cloud-init runcmd): install the lab channel, point apk at the seeded mirror and
# start install.sh in the background so that it runs after the boot finished, like a user would.
set -u
SEED=/media/mrlab
mkdir -p "$SEED"
mountpoint -q "$SEED" || mount -t iso9660 -o ro /dev/vdb "$SEED"
install -D -m 0755 "$SEED/lab/agent.sh" /usr/local/sbin/mrlab-agent
install -D -m 0755 "$SEED/lab/install-run.sh" /usr/local/sbin/mrlab-install
mkdir -p /etc/local.d
printf '#!/bin/sh\nexec /usr/local/sbin/mrlab-agent\n' > /etc/local.d/mrlab-agent.start
chmod 0755 /etc/local.d/mrlab-agent.start
rc-update add local default > /dev/null 2>&1
install -D -m 0600 "$SEED/lab/id_lab.pub" /root/.ssh/authorized_keys
/usr/local/sbin/mrlab-agent
# The ISP simulator has no internet path in every mode (PPPoE, ISP down), so the guest installs from
# a local copy of the Alpine repositories: official signed APKINDEX files plus the needed packages.
rm -rf /var/lib/mrlab-mirror /root/mr-lab-release
cp -a "$SEED/apk-mirror" /var/lib/mrlab-mirror
printf '%s\n' /var/lib/mrlab-mirror/v3.24/main /var/lib/mrlab-mirror/v3.24/community > /etc/apk/repositories
cp -a "$SEED/release" /root/mr-lab-release
umount "$SEED" 2> /dev/null
grep -q '^MRLAB_RUN=0' /root/mr-lab-release/request.env && exit 0
setsid /usr/local/sbin/mrlab-install < /dev/null > /dev/null 2>&1 &
exit 0
