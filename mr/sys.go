package main

import (
	"strconv"
	"strings"
	"syscall"
)

// dfKB returns total and available KiB of the filesystem holding path.
func dfKB(path string) (int64, int64) {
	var s syscall.Statfs_t
	if syscall.Statfs(path, &s) != nil {
		return 0, 0
	}
	bs := int64(s.Bsize)
	return int64(s.Blocks) * bs / 1024, int64(s.Bavail) * bs / 1024
}

// effOper: the state to show for a netdev. PPP and tun devices always report operstate "unknown" (RFC 2863),
// even while they carry traffic, and sysfs "flags" never has the volatile IFF_RUNNING (the kernel computes it
// for ioctls only): for them admin-up (IFF_UP in flags) plus carrier = 1 means up.
func effOper(oper, flags, carrier string) string {
	oper = strings.TrimSpace(oper)
	if oper != "unknown" {
		return oper
	}
	f, err := strconv.ParseUint(strings.TrimPrefix(strings.TrimSpace(flags), "0x"), 16, 32)
	if err != nil {
		return oper
	}
	if f&0x1 != 0 && strings.TrimSpace(carrier) == "1" { // IFF_UP
		return "up"
	}
	return "down"
}
