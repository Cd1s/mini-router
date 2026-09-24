//go:build !linux

package main

import (
	"errors"
	"net"
)

func sendDHCPRelease(ifname string, server net.IP, pkt []byte) error {
	return errors.New("DHCP release needs Linux (SO_BINDTODEVICE)")
}
