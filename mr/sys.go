package main

import "syscall"

// dfKB returns total and available KiB of the filesystem holding path.
func dfKB(path string) (int64, int64) {
	var s syscall.Statfs_t
	if syscall.Statfs(path, &s) != nil {
		return 0, 0
	}
	bs := int64(s.Bsize)
	return int64(s.Blocks) * bs / 1024, int64(s.Bavail) * bs / 1024
}
