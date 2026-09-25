//go:build !linux

package main

import "errors"

// clockSynced: unknown off Linux (the router is Linux-only; this keeps the package portable).
func clockSynced() (bool, bool) {
	s, known, _ := ntpMarker()
	return s, known
}

// bindToDev: no SO_BINDTODEVICE off Linux.
func bindToDev(int, string) error { return errors.New("SO_BINDTODEVICE: Linux only") }
