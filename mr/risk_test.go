package main

import (
	"os"
	"strings"
	"testing"
)

// Risk levels from the plan, the config-level diff and the administrator's own path.
func TestClassifyRisk(t *testing.T) {
	os.Unsetenv("SSH_CLIENT")
	for _, tc := range []struct {
		name    string
		p       Plan
		changes []string
		admin   adminPath
		level   string
		reason  string
	}{
		{"files and a firewall reload", Plan{Changed: []File{{Path: "/etc/x"}}, Firewall: true}, []string{"+ firewall.forwards[x]"}, adminPath{}, "low", ""},
		{"dnsmasq restart", Plan{Services: []string{"dnsmasq"}}, []string{"+ dhcp.hosts[x]"}, adminPath{Dev: "br-lan", Port: "lan2"}, "medium", ""},
		{"WiFi restart, admin wired", Plan{Services: []string{"mr-hostapd"}}, []string{"~ wifi.radios[phy1].htmode: HE80 → HE160"}, adminPath{Dev: "br-lan", Port: "lan3"}, "medium", ""},
		{"WiFi restart, admin on WiFi", Plan{Services: []string{"mr-hostapd"}}, []string{"~ wifi.radios[phy1].htmode: HE80 → HE160"}, adminPath{Dev: "br-lan", Port: "phy1-ap0"}, "high", "通过 WiFi"},
		{"tailscale admin", Plan{Services: []string{"tailscale"}}, []string{"~ services.tailscale.port: 1 → 2"}, adminPath{Dev: "tailscale0"}, "high", "Tailscale"},
		{"WAN redial", Plan{Services: []string{"mr-pppoe.wan2"}}, []string{"~ wan[wan2].mtu: 1492 → 1480"}, adminPath{}, "high", "WAN"},
		{"LAN address", Plan{Services: []string{"mr-network"}}, []string{"~ lan.ipv4: 192.0.2.1/24 → 192.0.2.2/24"}, adminPath{}, "high", "LAN"},
		{"router inbound rule", Plan{Firewall: true}, []string{"+ firewall.open[x]"}, adminPath{}, "high", "入站"},
		{"guard", Plan{Changed: []File{{Path: appliedYAML}}}, []string{"- guard.never_expose"}, adminPath{}, "high", "guard"},
	} {
		r := classifyRisk(&tc.p, tc.changes, tc.admin)
		if r.Level != tc.level || tc.reason != "" && !strings.Contains(strings.Join(r.Reasons, "|"), tc.reason) {
			t.Errorf("%s: %+v", tc.name, r)
		}
	}
	r := classifyRisk(&Plan{Services: []string{"mr-hostapd", "mr-pppoe.wan"}}, nil, adminPath{})
	if len(r.Effects) != 2 || !strings.Contains(r.Effects[0], "WiFi") || !strings.Contains(r.Effects[1], "重新拨号") {
		t.Errorf("effects: %v", r.Effects)
	}
}

// --wait: "y" keeps the pending change.
func TestWaitConfirmKeeps(t *testing.T) {
	confirmEnv(t)
	setPending(pendingApply{Snapshot: "/h/a.tar.gz", State: statePending, Deadline: 1})
	rd, wr, _ := os.Pipe()
	old := os.Stdin
	os.Stdin = rd
	t.Cleanup(func() { os.Stdin = old })
	wr.WriteString("y\n")
	wr.Close()
	if err := waitConfirm(30); err != nil {
		t.Fatal(err)
	}
	if _, err := readPending(); err == nil {
		t.Error("y did not keep the change")
	}
	if err := waitConfirm(30); err != nil {
		t.Errorf("nothing pending: %v", err)
	}
}
