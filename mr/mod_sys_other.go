//go:build !linux

package main

import "errors"

// clockSynced: unknown off Linux (the router is Linux-only; this keeps the package portable).
func clockSynced() (bool, bool) { return false, false }

// bindToDev: no SO_BINDTODEVICE off Linux.
func bindToDev(int, string) error { return errors.New("SO_BINDTODEVICE: Linux only") }
