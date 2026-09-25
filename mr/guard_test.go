package main

import (
	"strings"
	"testing"
)

func guardErrs(c *Config) string {
	v := &Validator{}
	guardValidate(c, v)
	return strings.Join(v.errs, "\n")
}

// The guard refuses configs that break the owner's baselines (Cd1s/mini-router#38).
func TestGuard(t *testing.T) {
	base := func() *Config {
		c := testConfig(t)
		c.Guard = Guard{NeverExpose: []string{"ssh", "panel", "dns"}, Offload: "hardware", SSHLANOnly: true}
		c.Services.SSH.Enabled, c.Services.SSH.LANOnly, c.Services.SSH.Port = true, true, 22
		c.Firewall.Offload = "hardware"
		return c
	}
	if e := guardErrs(base()); e != "" {
		t.Fatalf("the home config breaks the guard: %s", e)
	}
	router := strings.Split(base().LAN.IPv4, "/")[0]
	for _, tc := range []struct {
		name string
		mod  func(c *Config)
		want string
	}{
		{"ssh opened to the WAN", func(c *Config) {
			c.Firewall.Open = append(c.Firewall.Open, Open{Name: "x", Proto: []string{"tcp"}, Port: "20-30"})
		},
			"firewall.open[x] opens port 22 (ssh)"},
		{"panel opened", func(c *Config) {
			c.Firewall.Open = append(c.Firewall.Open, Open{Name: "w", Proto: []string{"tcp"}, Port: "80,8080"})
		},
			"firewall.open[w] opens port 80 (panel)"},
		{"dns forwarded to the router", func(c *Config) {
			c.Firewall.Forwards = append(c.Firewall.Forwards, Forward{Name: "d", Proto: []string{"udp"}, Port: "5353", To: router, ToPort: "53"})
		}, "firewall.forwards[d] forwards to the router's port 53 (dns)"},
		{"ssh port moved into an open range", func(c *Config) {
			c.Services.SSH.Port = 2200
			c.Firewall.Open = append(c.Firewall.Open, Open{Name: "r", Proto: []string{"tcp"}, Port: "2000-2999"})
		}, "opens port 2200 (ssh)"},
		{"offload lowered", func(c *Config) { c.Firewall.Offload = "software" }, "firewall.offload may not be below hardware"},
		{"ssh on all addresses", func(c *Config) { c.Services.SSH.LANOnly = false }, "services.ssh.lan_only must stay true"},
		{"unknown service", func(c *Config) { c.Guard.NeverExpose = append(c.Guard.NeverExpose, "telnet") }, `ssh, panel or dns, got "telnet"`},
		{"unknown offload", func(c *Config) { c.Guard.Offload = "max" }, `hardware, software or off, got "max"`},
	} {
		c := base()
		tc.mod(c)
		if e := guardErrs(c); !strings.Contains(e, tc.want) {
			t.Errorf("%s: got %q, want %q", tc.name, e, tc.want)
		}
	}
	// allowed: the same port forwarded to another host, a disabled open entry, SSH off
	c := base()
	c.Firewall.Forwards = append(c.Firewall.Forwards, Forward{Name: "nas", Proto: []string{"tcp"}, Port: "2222", To: "192.0.2.9", ToPort: "22"})
	off := false
	c.Firewall.Open = append(c.Firewall.Open, Open{Name: "old", Enabled: &off, Proto: []string{"tcp"}, Port: "22"})
	if e := guardErrs(c); e != "" {
		t.Errorf("allowed changes refused: %s", e)
	}
}

func TestGuardAlwaysBypass(t *testing.T) {
	c := testConfig(t)
	c.Proxy.Enabled = true
	h := c.DHCP.Hosts[0]
	c.Guard.AlwaysBypass = []string{h.Name}
	c.Proxy.Bypass = nil
	if e := guardErrs(c); !strings.Contains(e, "is not in proxy.bypass") {
		t.Errorf("unbypassed device accepted: %q", e)
	}
	c.Proxy.Bypass = []ProxyDevice{{Name: "other-name", MAC: h.MAC}} // matched through its DHCP reservation's MAC
	if e := guardErrs(c); e != "" {
		t.Errorf("bypass by MAC refused: %s", e)
	}
	c.Proxy.Enabled = false
	c.Proxy.Bypass = nil
	if e := guardErrs(c); e != "" {
		t.Errorf("proxy off: %s", e)
	}
}
