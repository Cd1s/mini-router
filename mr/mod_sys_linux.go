package main

import (
	"syscall"
	"time"
)

// clockSynced reports whether the kernel clock is marked synchronized (busybox ntpd clears
// STA_UNSYNC once it disciplines the clock; adjtimex then no longer returns TIME_ERROR).
// The second result is false when the state cannot be read.
func clockSynced() (bool, bool) {
	var tx syscall.Timex
	state, err := syscall.Adjtimex(&tx)
	if err != nil {
		return false, false
	}
	const timeError, staUnsync = 5, 0x0040
	return state != timeError && tx.Status&staUnsync == 0, true
}

// setClock steps the system clock (settimeofday). Used once by clockFromHTTP while NTP is not synced.
func setClock(t time.Time) error {
	tv := syscall.NsecToTimeval(t.UnixNano())
	return syscall.Settimeofday(&tv)
}
