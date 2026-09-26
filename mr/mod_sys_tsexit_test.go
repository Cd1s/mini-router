package main

import (
	"strings"
	"testing"
)

func TestTailscaleExitNode(t *testing.T) {
	c := testConfig(t)
	c.Services.Tailscale.Enabled = true
	c.Devices = append(c.Devices, Device{Name: "laptop", MACs: []string{"02:00:00:00:00:41"}})
	c.Services.Tailscale.ExitNode = TSExit{Node: "exit-sg", Devices: []string{"laptop"}, KillSwitch: true}
	if errs := c.Validate(); len(errs) > 0 {
		t.Fatal(errs)
	}
	var b strings.Builder
	tsExitNetSh(c, "routes", &b)
	sh := b.String()
	for _, s := range []string{"ip -4 rule add fwmark 0x4000000/0x4000000 lookup 52 pref 5202", "ip -6 rule add fwmark 0x4000000/0x4000000 unreachable pref 5203", "ip -4 rule add goto 5280 pref 5209"} {
		if !strings.Contains(sh, s) {
			t.Errorf("network.sh missing %q", s)
		}
	}
	if strings.Index(sh, "pref 5280\n") > strings.Index(sh, "goto 5280") {
		t.Errorf("goto target must exist first")
	}
	nft := renderNft(c, func(string) bool { return true })
	for _, s := range []string{`ether saddr { 02:00:00:00:00:41 } ct mark set ct mark | 0x4000000`, `oifname "tailscale0" meta mark & 0x4000000 == 0x4000000 masquerade`} {
		if !strings.Contains(nft, s) {
			t.Errorf("nft missing %q", s)
		}
	}
	if got := renderMap(t, c)["/etc/conf.d/tailscale"]; !strings.Contains(got, "TS_EXIT_NODE='exit-sg'\n") {
		t.Errorf("conf.d: %q", got)
	}
	c.Services.Tailscale.ExitNode = TSExit{Node: "x' ;reboot", Devices: []string{"nobody"}}
	errs := strings.Join(c.Validate(), "\n")
	if !strings.Contains(errs, "exit_node.node: a tailnet IP") || !strings.Contains(errs, `unknown device "nobody"`) {
		t.Errorf("errs: %s", errs)
	}
}
