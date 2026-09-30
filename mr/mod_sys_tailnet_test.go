package main

import "testing"

// LAN devices reach tailnet addresses through the router: masqueraded to its tailnet address (#118).
func TestSysTailnetFromLAN(t *testing.T) {
	c := testConfig(t)
	c.Services.Tailscale.Enabled = true
	rule := `iifname { "br-lan" } oifname "tailscale0" masquerade comment "tailnet-from-lan"`
	mustContain(t, "nft", renderNft(c, allExist), rule)
	c.Services.Tailscale.Enabled = false
	mustNotContain(t, "nft", renderNft(c, allExist), "tailnet-from-lan")
}
