package main

import (
	"strings"
	"testing"
)

func TestDevLimit(t *testing.T) {
	c := devConfig(t)
	c.Devices[2].Limit = &DevLimit{Down: 20, Up: 5}
	c.defaults()
	if errs := c.Validate(); len(errs) > 0 {
		t.Fatal(errs)
	}
	nft := renderNft(c, allExist)
	wans := "{ " + quoteList(c.WANIfnames()) + " }"
	mustContain(t, "nft", nft,
		"set lim2_4 { type ipv4_addr;", "set ac_4 { type ipv4_addr;",
		`ether saddr aa:bb:cc:00:00:23 update @ac_4 { ip saddr } update @lim2_4 { ip saddr }`,
		`ether saddr aa:bb:cc:00:00:23 oifname `+wans+` limit rate over 625 kbytes/second burst 78 kbytes drop comment "limit:game-console"`,
		`ip daddr @lim2_4 limit rate over 2500 kbytes/second burst 312 kbytes drop comment "limit:game-console"`,
		`ip6 saddr != @ac_6 ip6 daddr != @ac_6 flow add @ft`)
	fwd := nft[strings.Index(nft, "chain forward {"):]
	if strings.Index(fwd, "limit:game-console") > strings.Index(fwd, "flow add") {
		t.Error("the policer must come before flow offload")
	}
	// a reload refills the learned sets from the neighbour table
	if s := fwAccessElements(c, []fwNeigh{{Dst: "192.168.1.150", LLAddr: "aa:bb:cc:00:00:23"}}, nil); !strings.Contains(s, "add element inet mr lim2_4 { 192.168.1.150 }") ||
		!strings.Contains(s, "add element inet mr ac_4 { 192.168.1.150 }") {
		t.Errorf("refill: %s", s)
	}
	c.Devices[2].Limit = &DevLimit{Down: 20000}
	if errs := strings.Join(c.Validate(), "\n"); !strings.Contains(errs, "devices[2].limit: down / up in Mbit/s") {
		t.Errorf("errors: %s", errs)
	}
}
