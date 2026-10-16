package main

import (
	"net"
	"testing"
)

// A static route through another router on the LAN (a downstream router's subnet) masquerades LAN traffic
// to that subnet, so the replies come back through us instead of straight from the gateway.
func TestLANGatewayRouteNAT(t *testing.T) {
	c := testConfig(t)
	ip, lnet, _ := net.ParseCIDR(c.LAN.IPv4)
	gw := ip.To4()
	gw = net.IPv4(gw[0], gw[1], gw[2], 254)
	c.Routes = []Route{
		{Name: "down", Target: "10.77.0.0/24", Via: gw.String()},
		{Name: "wan-side", Target: "10.88.0.0/24", Via: "203.0.113.1"},
		{Name: "other-table", Target: "10.99.0.0/24", Via: gw.String(), Table: 100},
		{Name: "v6", Target: "2001:db8:77::/64", Via: "fe80::1", Dev: c.LAN.Bridge},
	}
	rule := `iifname "` + c.LAN.Bridge + `" oifname "` + c.LAN.Bridge + `" ip saddr ` + lnet.String() +
		` ip daddr 10.77.0.0/24 masquerade comment "route-via-lan:10.77.0.0/24"`
	nft := renderNft(c, allExist)
	mustContain(t, "nft", nft, rule)
	for _, x := range []string{"route-via-lan:10.88.0.0/24", "route-via-lan:10.99.0.0/24", "route-via-lan:2001"} {
		mustNotContain(t, "nft", nft, x)
	}
	if errs := c.Validate(); len(errs) > 0 {
		t.Fatalf("config invalid: %v", errs)
	}
}
