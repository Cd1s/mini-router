package main

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestParsePPPoEDiscoveryRealOutput(t *testing.T) {
	s := "Access-Concentrator: testAC\nService-Name: testSvc\nCookie: deadbeef\nAC-Ethernet-Address: de:f2:00:00:00:01\n"
	p := parsePPPoEDiscovery(s, true)
	if !p.PADO || p.AC != "testAC" || p.Service != "testSvc" {
		t.Fatalf("pppoe=%+v", p)
	}
	if p := parsePPPoEDiscovery(s, false); p.PADO {
		t.Fatalf("failed command accepted: %+v", p)
	}
}

func TestParseDHCPOffer(t *testing.T) {
	b := make([]byte, 240, 280)
	b[0], b[1] = 2, 1
	binary.BigEndian.PutUint32(b[4:8], 0x12345678)
	b[16], b[17], b[18], b[19] = 192, 168, 1, 50
	copy(b[236:240], []byte{99, 130, 83, 99})
	b = append(b, 53, 1, 2, 1, 4, 255, 255, 255, 0, 3, 4, 192, 168, 1, 1, 6, 8, 1, 1, 1, 1, 8, 8, 8, 8, 255)
	d, ok := parseDHCPOffer(b, 0x12345678)
	if !ok || d.Address != "192.168.1.50" || d.Mask != "255.255.255.0" || d.Gateway != "192.168.1.1" || len(d.DNS) != 2 {
		t.Fatalf("offer=%+v ok=%v", d, ok)
	}
}

func TestDHCPDiscoverUsesPortableIPv4Flags(t *testing.T) {
	p := dhcpDiscover(1, net.HardwareAddr{0, 1, 2, 3, 4, 5})
	f := dhcpEthernetFrame(p, net.HardwareAddr{0, 1, 2, 3, 4, 5})
	if f[20] != 0 || f[21] != 0 {
		t.Fatalf("IPv4 flags set reserved bits: %#x", f[20:22])
	}
}

func TestParseRouterAdvertisement(t *testing.T) {
	b := make([]byte, 16+32)
	b[0], b[5] = 134, 0xc0
	b[16], b[17], b[18], b[19] = 3, 4, 64, 0
	b[32], b[33], b[34], b[35] = 0x20, 0x01, 0x0d, 0xb8
	r := parseRouterAdvertisement(b)
	if !r.Seen || !r.M || !r.O || r.Prefix != "2001:db8::/64" {
		t.Fatalf("ra=%+v", r)
	}
}

func TestSuggestLANAvoidsUpstream(t *testing.T) {
	_, n, _ := net.ParseCIDR("192.168.1.0/24")
	if got := suggestLAN(n); got == "192.168.1.1/24" {
		t.Fatal(got)
	}
}

func TestDetectWANRecommendationAndUnknown(t *testing.T) {
	old := wanDetectProbe
	t.Cleanup(func() { wanDetectProbe = old })
	c := &Config{}
	c.LAN.IPv4 = "192.168.1.1/24"
	wanDetectProbe = func(context.Context, string) (detectObservation, error) {
		return detectObservation{PPPoE: detectPPPoE{PADO: true, AC: "ac"}}, nil
	}
	if got := detectWAN(c, "lo", time.Second).Recommendation; got != "pppoe" {
		t.Fatalf("pppoe recommendation=%q", got)
	}
	wanDetectProbe = func(context.Context, string) (detectObservation, error) { return detectObservation{}, nil }
	if got := detectWAN(c, "lo", time.Second).Recommendation; got != "unknown" {
		t.Fatalf("empty recommendation=%q", got)
	}
}
