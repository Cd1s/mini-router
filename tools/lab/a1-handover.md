# A1 handover — 2026-10-17

Branch: `lab/fresh-env`

Latest commits:

```text
779e16e tools/lab: continue guest install with offline packages
faefd31 tools/lab: protect host resolver and namespace state
2f50ec2 tools/lab: seed Alpine router package layer for offline install
```

Completed:

- Host resolver leak fixed. Every lab netns has `/etc/netns/<name>/resolv.conf`; DHCP uses a
  private `udhcpc -s` hook and writes state files. Host guard hashes `/etc/resolv.conf`, `/etc/hosts`
  and `/etc/ppp/**` before/after every command.
- ISP netns DNS/HTTPS to Alpine CDN works. Host `/etc/resolv.conf` hash stayed
  `4a6bc9f3ddbb22ebdb5b3a6b4d49d97537b8e5f24204880038b4b8e5b6734028`; host mrlab links and
  namespaces were zero after teardown.
- Alpine package layer is prebuilt in `/root/build/mr-lab-images/alpine-router-packages.tar.gz`
  and included in the cloud-init seed. Admin password is `labpass1`.

Remaining blocker:

- `install.sh` reaches step 5 apply but `mr-network` cannot start in the guest and rolls back.
  The last log showed `mr-network would not start`; `router.yaml` and `/usr/sbin/mr` were written.
  01/02 are not yet green. 03/04/05 remain diagnostic until guest apply succeeds.

Next step: inspect the guest's generated network service/config and boot network state, then rerun
01/02. Do not remove the package layer or bypass the host guard.
