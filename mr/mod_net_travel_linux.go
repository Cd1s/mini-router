package main

import "syscall"

// bindDevice is a net.Dialer Control that pins the socket to one interface (SO_BINDTODEVICE): the
// route lookup then only sees routes through it, so a check or a DNS query really leaves through
// that WAN, also while another WAN holds the default route or this one is marked down.
// dev "" = no binding.
func bindDevice(dev string) func(network, address string, c syscall.RawConn) error {
	if dev == "" {
		return nil
	}
	return func(_, _ string, c syscall.RawConn) error {
		var err error
		if e := c.Control(func(fd uintptr) {
			err = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, dev)
		}); e != nil {
			return e
		}
		return err
	}
}
