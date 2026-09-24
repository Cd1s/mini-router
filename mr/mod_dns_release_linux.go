package main

import (
	"net"
	"syscall"
	"time"
)

// sendDHCPRelease sends pkt to dnsmasq's DHCP port as if it arrived on ifname: the socket is bound
// to the LAN bridge and addressed to the router's own address there, so the kernel loops it back
// with that bridge as the incoming interface (the same trick as dnsmasq's dhcp_release).
func sendDHCPRelease(ifname string, server net.IP, pkt []byte) error {
	d := net.Dialer{Timeout: 2 * time.Second, Control: func(network, address string, rc syscall.RawConn) error {
		var serr error
		if err := rc.Control(func(fd uintptr) {
			serr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, ifname)
		}); err != nil {
			return err
		}
		return serr
	}}
	conn, err := d.Dial("udp4", net.JoinHostPort(server.String(), "67"))
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write(pkt)
	return err
}
