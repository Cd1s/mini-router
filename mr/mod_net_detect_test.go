package main

import (
	"encoding/binary"
	"net"
	"testing"
)

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
	if got := suggestLAN(n); got == "192.168.1.1/24" { t.Fatal(got) }
}
