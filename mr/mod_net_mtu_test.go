package main

import (
	"strings"
	"testing"
)

// RFC 4638 (Cd1s/mini-router#46): a PPPoE WAN with mtu above 1492 raises its ethernet device to
// mtu + 8 (pppd 2.5 asks for PPP-Max-Payload only when the link allows it, and falls back to 1492
// when the access concentrator does not echo the tag); other WANs keep their own MTU.
func TestWANLinkMTUs(t *testing.T) {
	c := testConfig(t)
	pppoe := c.WAN[0]
	dev := pppoe.Device
	if got := wanLinkMTUs(c)[dev]; got != 1500 {
		t.Errorf("PPPoE with mtu %d: link MTU %d, want 1500 (plain Ethernet)", pppoe.MTU, got)
	}
	c.WAN[1].MTU = 1500
	if got := wanLinkMTUs(c)[dev]; got != 1508 {
		t.Errorf("PPPoE mtu 1500: link MTU %d, want 1508", got)
	}
	// a DHCP WAN on a VLAN of the same port: the parent carries 1508, the VLAN plain 1500
	c.WAN = append(c.WAN, WAN{Name: "tv", Device: dev, VLAN: 20, Proto: "dhcp", Metric: 90})
	m := wanLinkMTUs(c)
	if m[dev] != 1508 || m[dev+".20"] != 1500 {
		t.Errorf("parent %d, VLAN %d; want 1508, 1500", m[dev], m[dev+".20"])
	}
	if errs := strings.Join(c.Validate(), "\n"); strings.Contains(errs, "also carries PPPoE") {
		t.Errorf("a DHCP WAN on its own VLAN refused: %s", errs)
	}
	// network.sh: the parent's MTU before the VLAN is created (a subinterface cannot exceed it)
	sh := renderNetwork(c)
	p := strings.Index(sh, "ip link set dev "+dev+" mtu 1508\n")
	v := strings.Index(sh, "type vlan id 20")
	if p < 0 || v < 0 || p > v {
		t.Errorf("network.sh: parent MTU at %d, VLAN at %d:\n%s", p, v, sh)
	}
	if !strings.Contains(sh, "ip link set dev "+dev+".20 mtu 1500\n") {
		t.Error("network.sh: the DHCP VLAN is not kept at 1500")
	}
	// untagged DHCP on the same port would get 1508 as its IP MTU: refused
	c.WAN[2].VLAN = 0
	if errs := strings.Join(c.Validate(), "\n"); !strings.Contains(errs, "also carries PPPoE with mtu above 1492") {
		t.Errorf("DHCP on the PPPoE port with 1508 accepted: %s", errs)
	}
}

// The home config (two PPPoE sessions at 1492) keeps its link at 1500 and pppd at 1492.
func TestWANLinkMTUHome(t *testing.T) {
	c := testConfig(t)
	sh := renderNetwork(c)
	if strings.Contains(sh, "mtu 1508") {
		t.Error("home config raises the link above 1500")
	}
	for _, w := range c.WAN {
		if w.Proto == "pppoe" && !strings.Contains(renderPeer(w, "x"), "mtu 1492\nmru 1492\n") {
			t.Errorf("%s: peer file lost mtu/mru 1492", w.Name)
		}
	}
}
