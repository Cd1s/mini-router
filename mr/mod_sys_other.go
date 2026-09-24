//go:build !linux

package main

// clockSynced: unknown off Linux (the router is Linux-only; this keeps the package portable).
func clockSynced() (bool, bool) { return false, false }
