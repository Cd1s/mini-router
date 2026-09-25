//go:build !linux

package main

import (
	"errors"
	"time"
)

// clockSynced: unknown off Linux (the router is Linux-only; this keeps the package portable).
func clockSynced() (bool, bool) { return false, false }

// setClock: not supported off Linux (clockFromHTTP never gets here: clockSynced reports unknown).
func setClock(time.Time) error { return errors.New("setClock: Linux only") }
