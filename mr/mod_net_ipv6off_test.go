package main

import (
	"strings"
	"testing"
)

// A WAN device with no IPv6-enabled DHCP / static WAN on it gets accept_ra 0 and loses its leftover
// global IPv6 state in network.sh (dhcpcd and the WAN-up hook leave both behind when ipv6 is turned off).
func TestWANIPv6OffClearsRA(t *testing.T) {
	c := testConfig(t)
	off := "echo 0 2>/dev/null > /proc/sys/net/ipv6/conf/wan/accept_ra\n"
	flush := "ip -6 route flush dev wan proto ra 2>/dev/null; ip -6 addr flush dev wan scope global 2>/dev/null\n"
	c.WAN = []WAN{{Name: "wan", Device: "wan", Proto: "dhcp", IPv6: true}}
	if sh := renderNetwork(c); strings.Contains(sh, off) || strings.Contains(sh, flush) {
		t.Errorf("DHCP WAN with ipv6 on: its RA handling is cleared:\n%s", sh)
	}
	c.WAN[0].IPv6 = false
	sh := renderNetwork(c)
	if strings.Count(sh, off) != 1 || strings.Count(sh, flush) != 1 {
		t.Errorf("DHCP WAN with ipv6 off: accept_ra / flush missing or repeated:\n%s", sh)
	}
	// PPPoE: the session interface carries IPv6, the ethernet device under it never takes RAs
	c.WAN = []WAN{{Name: "wan", Device: "wan", Proto: "pppoe", IPv6: true}, {Name: "wan2", Device: "wan", Proto: "pppoe"}}
	if sh := renderNetwork(c); strings.Count(sh, off) != 1 {
		t.Errorf("PPPoE device: accept_ra 0 missing or repeated:\n%s", sh)
	}
	// one IPv6 DHCP WAN on the device is enough to keep it
	c.WAN = append(c.WAN, WAN{Name: "wan3", Device: "wan", Proto: "dhcp", IPv6: true})
	if sh := renderNetwork(c); strings.Contains(sh, off) {
		t.Errorf("device shared with an IPv6 DHCP WAN: accept_ra cleared:\n%s", sh)
	}
}
