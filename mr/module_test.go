package main

import (
	"strings"
	"testing"
)

func TestModulesRegistered(t *testing.T) {
	want := []string{"net", "wifi", "dns", "fw", "mon", "proxy", "sys", "api"}
	var got []string
	for _, m := range modules {
		got = append(got, m.Name)
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("modules in prio order = %v, want %v", got, want)
	}
}

func TestEveryNftHookEmitted(t *testing.T) {
	c := testConfig(t)
	seen := map[string]bool{}
	register(&Module{Name: "probe", Prio: 99, Nft: func(c *Config, hook string, n *Nft) {
		seen[hook] = true
		if hook != "defs" {
			n.W("counter comment %q", "probe-"+hook)
		}
	}})
	defer func() { modules = modules[:len(modules)-1] }()
	out := renderNft(c, func(string) bool { return true })
	for _, h := range nftHooks {
		if !seen[h] {
			t.Errorf("hook %q never emitted by renderNft", h)
		}
		if h != "defs" && !strings.Contains(out, `"probe-`+h+`"`) {
			t.Errorf("hook %q output missing", h)
		}
	}
}

func TestGuestNetwork(t *testing.T) {
	c := testConfig(t)
	c.Networks = []Network{{Name: "guest", IPv4: "192.168.20.1/24", DHCP: Pool{Enabled: true, Start: 100, End: 150}}}
	c.WiFi.Radios[1].SSIDs = append(c.WiFi.Radios[1].SSIDs, SSID{SSID: "Guest", Encryption: "none", Network: "guest"})
	c.defaults()
	if errs := c.Validate(); len(errs) > 0 {
		t.Fatal(errs)
	}
	files, err := Render(c)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, f := range files {
		got[f.Path] = f.Data
	}
	for p, subs := range map[string][]string{
		GenDir + "/network.sh":           {"ip link add br-guest type bridge", "ip addr replace 192.168.20.1/24 dev br-guest"},
		"/etc/dnsmasq.conf":              {"interface=br-guest", "dhcp-range=set:guest,192.168.20.100,192.168.20.150,255.255.255.0,12h", "dhcp-option=tag:guest,option:router,192.168.20.1"},
		"/etc/hostapd/hostapd-phy1.conf": {"bss=phy1-ap0-1", "bridge=br-guest"},
	} {
		for _, s := range subs {
			if !strings.Contains(got[p], s) {
				t.Errorf("%s missing %q", p, s)
			}
		}
	}
	nft := renderNft(c, func(string) bool { return true })
	for _, s := range []string{`iifname "br-guest" drop`, `iifname "br-guest" oifname { "pppoe-wan", "pppoe-wan2" } accept`, `"phy1-ap0-1"`, `dnat ip to 192.168.20.1 comment "dns-redirect"`} {
		if !strings.Contains(nft, s) {
			t.Errorf("nft missing %q", s)
		}
	}
	c.Networks[0].IPv4 = "192.168.1.200/24"
	if !strings.Contains(strings.Join(c.Validate(), "\n"), "overlaps") {
		t.Error("overlapping network not rejected")
	}
}

func TestConfigRejectsInjection(t *testing.T) {
	c := testConfig(t)
	c.WAN[0].Username = "u\nplugin evil.so"
	c.System.Sysctl["net.core.x"] = "1\nkernel.foo=1"
	c.System.Hostname = "a b"
	errs := strings.Join(c.Validate(), "\n")
	for _, s := range []string{"username: control characters", "system.sysctl.net.core.x", "system.hostname"} {
		if !strings.Contains(errs, s) {
			t.Errorf("want error %q in:\n%s", s, errs)
		}
	}
}

// renderMap renders c and returns path -> contents (shared by module tests).
func renderMap(t *testing.T, c *Config) map[string]string {
	t.Helper()
	files, err := Render(c)
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]string{}
	for _, f := range files {
		m[f.Path] = f.Data
	}
	return m
}
