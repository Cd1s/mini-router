package main

import "syscall"

// clockSynced reports whether NTP keeps the clock right. The image's ntpd hook (clock-save) keeps a
// marker in /run/mr-clock (ntpMarker): busybox ntpd never lowers the kernel's maxerror, so adjtimex
// reports TIME_ERROR / STA_UNSYNC even while it disciplines the clock. adjtimex is the fallback for
// systems without the marker directory. The second result is false when the state cannot be read.
func clockSynced() (bool, bool) {
	if s, known, _ := ntpMarker(); known {
		return s, true
	}
	var tx syscall.Timex
	state, err := syscall.Adjtimex(&tx)
	if err != nil {
		return false, false
	}
	const timeError, staUnsync = 5, 0x0040
	return state != timeError && tx.Status&staUnsync == 0, true
}

// bindToDev pins a socket to one netdev (SO_BINDTODEVICE; Wake-on-LAN: the packet can only leave there).
func bindToDev(fd int, dev string) error {
	return syscall.SetsockoptString(fd, syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, dev)
}
