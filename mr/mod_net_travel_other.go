//go:build !linux

package main

import "syscall"

// bindDevice: no SO_BINDTODEVICE off Linux (the router is Linux-only; this keeps the package portable).
func bindDevice(string) func(network, address string, c syscall.RawConn) error { return nil }
