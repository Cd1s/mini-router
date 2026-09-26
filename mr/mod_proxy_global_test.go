package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestProxyGlobalDevice(t *testing.T) {
	c := proxyTestConfig(t)
	c.Devices = append(c.Devices, Device{Name: "tv-box", MACs: []string{"02:00:00:00:00:31"}}) // no fixed address needed
	c.Proxy.Global = []ProxyGlobal{{Name: "tv", Device: "tv-box", Outbound: "jp1"}}
	if errs := c.Validate(); len(errs) > 0 {
		t.Fatal(errs)
	}
	got := renderMap(t, c)
	var sb map[string]any
	json.Unmarshal([]byte(got[proxyGenJSON]), &sb)
	r1 := sb["route"].(map[string]any)["rules"].([]any)[1].(map[string]any)
	if r1["outbound"] != "jp1" || fmt.Sprint(r1["inbound"]) != "[tproxy4-g0 tproxy6-g0]" || !strings.Contains(got[proxyGenJSON], `"listen_port": 7903`) {
		t.Errorf("first route rule: %v", r1)
	}
	nft := renderNft(c, func(string) bool { return true })
	i, j := strings.Index(nft, "ether saddr @proxy_bypass return"), strings.Index(nft, "ether saddr { 02:00:00:00:00:31 } ip daddr")
	if i < 0 || j < i || !strings.Contains(nft, "ether saddr { 02:00:00:00:00:31 } ip6 daddr != @lan6 ip6 daddr != fc00::/7 meta l4proto { tcp, udp } ct direction original goto proxy_tp6_g0") ||
		!strings.Contains(nft, "tproxy ip6 to [::1]:7903 ") || !strings.Contains(nft, "tproxy ip to 127.0.0.1:7903 ") {
		t.Errorf("nft: bypass must come first, global rules / chains missing\n%s", nft)
	}
	c.Proxy.APIPort = 7903 // collides with the first device's port
	if errs := strings.Join(c.Validate(), "\n"); !strings.Contains(errs, "proxy.global[0]: tproxy port 7903") {
		t.Errorf("port collision not caught: %s", errs)
	}
	c.Proxy.APIPort = 0
	// unknown outbound, a group, both keys
	c.Proxy.Global = []ProxyGlobal{{Name: "a", MAC: "aa:bb:cc:00:00:01", Outbound: "nowhere"}, {Name: "b", Device: "group:kids", Outbound: "jp1"}, {Name: "c", MAC: "aa:bb:cc:00:00:02", Device: "tv-box", Outbound: "jp1"}}
	errs := strings.Join(c.Validate(), "\n")
	for _, s := range []string{"proxy.global[0].outbound", "proxy.global[1].device: unknown device", "proxy.global[2]: set mac or device"} {
		if !strings.Contains(errs, s) {
			t.Errorf("missing %q in\n%s", s, errs)
		}
	}
}
