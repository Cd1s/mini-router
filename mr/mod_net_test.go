package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func wantSubs(t *testing.T, what, data string, subs ...string) {
	t.Helper()
	for _, s := range subs {
		if !strings.Contains(data, s) {
			t.Errorf("%s: missing %q", what, s)
		}
	}
}

func wantNone(t *testing.T, what, data string, subs ...string) {
	t.Helper()
	for _, s := range subs {
		if strings.Contains(data, s) {
			t.Errorf("%s: must not contain %q", what, s)
		}
	}
}

func mustValid(t *testing.T, c *Config) {
	t.Helper()
	if errs := c.Validate(); len(errs) > 0 {
		t.Fatalf("unexpected validation errors:\n%s", strings.Join(errs, "\n"))
	}
}

// tempState points the runtime state files at a temp dir for one test.
func tempState(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	a, b, c := wanRunDir, wanStateFile, resolvConf
	wanRunDir, wanStateFile, resolvConf = filepath.Join(d, "wan"), filepath.Join(d, "wan-state.json"), filepath.Join(d, "resolv.conf")
	t.Cleanup(func() { wanRunDir, wanStateFile, resolvConf = a, b, c })
	return d
}

func allExist(string) bool { return true }

// The real home config keeps its behaviour; the changes to its output are the intentional ones
// documented in docs/modules/net.md (suppress rule, generated service instances, WAN DNS file).
func TestNetHomeConfig(t *testing.T) {
	c := testConfig(t)
	mustValid(t, c)
	f := renderMap(t, c)
	sh := f[GenDir+"/network.sh"]
	wantSubs(t, "network.sh", sh,
		"ip -4 rule add lookup main suppress_prefixlength 0 pref 5299",
		"ip -6 rule add lookup main suppress_prefixlength 0 pref 5299",
		"while ip -4 rule del pref 5300 2>/dev/null; do :; done",
		"ip -4 rule add fwmark 0x200 lookup 200 pref 5300",
		"ip -4 rule add fwmark 0x102 lookup 102 pref 5300",
		"ip -6 rule add fwmark 0x102 lookup 102 pref 5300",
		"ip link set wan address a4:a9:30:6e:2b:89",
		"echo e > $f")
	if n := strings.Count(sh, "ip link set wan up\n"); n != 1 {
		t.Errorf("network.sh: wan brought up %d times", n)
	}
	wantSubs(t, "mr-pppoe.wan", f["/etc/init.d/mr-pppoe.wan"], "#!/sbin/openrc-run\n", ". /etc/init.d/mr-pppoe\n")
	wantNone(t, "mr-pppoe.wan", f["/etc/init.d/mr-pppoe.wan"], "MR_WAN_DEV")
	wantSubs(t, "peers/wan2", f["/etc/ppp/peers/wan2"], "nic-wan\n", "ifname pppoe-wan2\n", "ipparam wan2\n", "mtu 1492\n", "persist\n")
	// wan dials after wan2 (multiwan.dial_order): no persist, every redial goes through pppoe-dial
	wantSubs(t, "peers/wan", f["/etc/ppp/peers/wan"], "nodetach\n", "lcp-echo-interval 5\n")
	wantNone(t, "peers/wan", f["/etc/ppp/peers/wan"], "persist\n", "holdoff")
	wantSubs(t, "dnsmasq.conf", f["/etc/dnsmasq.conf"], "resolv-file=/run/ppp/resolv.conf\n", "resolv-file=/run/mini-router/resolv.conf\n")
	wantSubs(t, "services", f[GenDir+"/services"], "mr-pppoe.wan\n", "mr-pppoe.wan2\n", "dhcpcd\n")
	wantNone(t, "services", f[GenDir+"/services"], "mr-wanmon", "mr-udhcpc")
	if _, ok := f[wanmonConf]; ok {
		t.Error("wanmon.conf rendered without multiwan")
	}
	nft := renderNft(c, allExist)
	wantSubs(t, "nft", nft,
		`iifname "br-lan" ether saddr 02:c3:06:d6:7f:8a ip daddr != 192.168.1.0/24 ct state new ct mark set 0x102 meta mark set 0x102 return comment "desktop-via-wan2"`,
		`iifname "br-lan" ether saddr 02:c3:06:d6:7f:8a ip6 saddr @pd6_1 ip6 daddr != @lan6 ct state new ct mark set 0x102 meta mark set 0x102 return comment "desktop-via-wan2"`,
		`iifname "br-lan" ether saddr 02:c3:06:d6:7f:8a ip6 saddr != @pd6_1 ip6 daddr != @lan6 ct state new jump npt6m_0 comment "desktop-via-wan2"`,
		"chain npt6m_0 {\n\t}", "chain npt6n_0 {\n\t}",
		`oifname "pppoe-wan2" meta mark 0x102 ip6 saddr != @pd6_1 jump npt6n_0`)
	wantNone(t, "nft", nft, "numgen")
	// the UI round trip must not add new keys to the home router.yaml
	m, err := configToJSON(c)
	if err != nil {
		t.Fatal(err)
	}
	mw, _ := m["multiwan"].(map[string]any)
	for k := range mw { // the home config sets only the dial order (no health check, no defaults added)
		if k != "dial_order" && k != "dial_restore" {
			t.Errorf("multiwan JSON has key %q", k)
		}
	}
	for _, w := range m["wan"].([]any) {
		for _, k := range []string{"vlan", "ipv4", "gateway", "dns"} {
			if _, ok := w.(map[string]any)[k]; ok {
				t.Errorf("wan JSON has empty key %q", k)
			}
		}
	}
	if serviceFor("/etc/init.d/mr-pppoe.wan") != "" || serviceFor("/etc/ppp/peers/wan") != "mr-pppoe.wan" {
		t.Error("restart mapping for pppoe files")
	}
}

func TestNetWANProtos(t *testing.T) {
	c := testConfig(t)
	c.LAN.Ports = []string{"lan2", "lan3"}
	c.WAN = append(c.WAN,
		WAN{Name: "hotel", Device: "lan4", Proto: "dhcp", Metric: 50, PeerDNS: true, IPv6: true},
		WAN{Name: "fixed", Device: "wan", VLAN: 35, Proto: "static", IPv4: "203.0.113.10/29", Gateway: "203.0.113.9", DNS: []string{"1.1.1.1", "2606:4700:4700::1111"}, Metric: 60, MTU: 1500},
		WAN{Name: "tagged", Device: "wan", VLAN: 500, Proto: "pppoe", Username: "u@isp", Password: "pppoe_password", Metric: 70})
	c.defaults()
	mustValid(t, c)
	f := renderMap(t, c)
	if got := f["/etc/init.d/mr-udhcpc.hotel"]; got != "#!/sbin/openrc-run\n# generated by mr for WAN hotel — service logic in /etc/init.d/mr-udhcpc\nMR_WAN_DEV=lan4\n. /etc/init.d/mr-udhcpc\n" {
		t.Errorf("udhcpc instance:\n%s", got)
	}
	wantSubs(t, "network.sh", f[GenDir+"/network.sh"],
		"ip link show wan.35 >/dev/null 2>&1 || ip link add link wan name wan.35 type vlan id 35\n",
		"ip link add link wan name wan.500 type vlan id 500\n",
		"ip link set dev wan.35 mtu 1500\n",
		"echo 1 2>/dev/null > /proc/sys/net/ipv4/conf/wan.35/promote_secondaries\nip addr replace 203.0.113.10/29 dev wan.35\n",
		`[ "$a" = 203.0.113.10/29 ] || ip addr del "$a" dev wan.35`,
		"ip -4 rule add fwmark 0x202 lookup 202 pref 5300",
		"ip -4 rule add fwmark 0x203 lookup 203 pref 5300")
	wantSubs(t, "peers/tagged", f["/etc/ppp/peers/tagged"], "nic-wan.500\n", "ifname pppoe-tagged\n", "mtu 1492\n")
	wantSubs(t, "dhcpcd.conf", f["/etc/dhcpcd.conf"], "allowinterfaces pppoe-wan pppoe-wan2 lan4\n", "interface lan4\n  ipv6only")
	svcs := f[GenDir+"/services"]
	wantSubs(t, "services", svcs, "mr-udhcpc.hotel\n", "mr-pppoe.tagged\n")
	wantNone(t, "services", svcs, "mr-pppoe.hotel", "mr-udhcpc.fixed", "mr-pppoe.fixed")
	nft := renderNft(c, allExist)
	wantSubs(t, "nft", nft,
		`iifname "lan4" ct state new ct mark set 0x202`,
		`iifname "wan.35" ct state new ct mark set 0x203`,
		`oifname { "pppoe-wan", "pppoe-wan2", "lan4", "wan.35", "pppoe-tagged" } meta nfproto ipv4 masquerade`)
	if serviceFor("/etc/init.d/mr-udhcpc.hotel") != "mr-udhcpc.hotel" {
		t.Error("udhcpc instance change must restart the client")
	}
	if netService(c.WAN[3]) != "" {
		t.Error("static WAN has no service")
	}
	if c.wanByIfname("wan.35").Name != "fixed" || c.wanByIfname("pppoe-tagged").Name != "tagged" {
		t.Error("wanByIfname")
	}
}

func TestNetValidation(t *testing.T) {
	cases := []struct {
		name string
		mod  func(c *Config)
		want string
	}{
		{"proto", func(c *Config) { c.WAN[0].Proto = "l2tp" }, "proto: pppoe|dhcp|static"},
		{"static-no-gw", func(c *Config) {
			c.WAN[1] = WAN{Name: "wan2", Device: "wan", Proto: "static", IPv4: "203.0.113.10/29"}
		}, "gateway: IPv4 inside"},
		{"static-gw-outside", func(c *Config) {
			c.WAN[1] = WAN{Name: "wan2", Device: "wan", Proto: "static", IPv4: "203.0.113.10/29", Gateway: "203.0.113.1"}
		}, "gateway: IPv4 inside"},
		{"static-bad-addr", func(c *Config) {
			c.WAN[1] = WAN{Name: "wan2", Device: "wan", Proto: "static", IPv4: "203.0.113.10", Gateway: "203.0.113.9"}
		}, "ipv4: static needs address/prefix"},
		{"static-mapped-v6", func(c *Config) {
			c.WAN[1] = WAN{Name: "wan2", Device: "wan", Proto: "static", IPv4: "::ffff:203.0.113.10/120", Gateway: "203.0.113.9"}
		}, "ipv4: static needs address/prefix"},
		{"wan-on-bridge", func(c *Config) { c.WAN[1] = WAN{Name: "wan2", Device: "br-lan", Proto: "dhcp"} }, "is a LAN-side bridge"},
		{"wan-on-lan-port", func(c *Config) { c.WAN[1] = WAN{Name: "wan2", Device: "lan3", Proto: "dhcp"} }, "untagged port of lan"},
		{"dns-not-static", func(c *Config) { c.WAN[0].DNS = []string{"1.1.1.1"} }, "only for proto static"},
		{"dns-bad", func(c *Config) {
			c.WAN[1] = WAN{Name: "wan2", Device: "wan", Proto: "static", IPv4: "203.0.113.10/29", Gateway: "203.0.113.9", DNS: []string{"1.1.1.1;reboot"}}
		}, "dns: invalid address"},
		{"pppoe-name-long", func(c *Config) { c.WAN[1].Name = "verylongnm" }, "at most 9 characters"},
		{"device-inject", func(c *Config) { c.WAN[0].Device = "wan;reboot" }, "device: invalid"},
		{"device-dash", func(c *Config) { c.WAN[0].Device = "-f" }, "device: invalid"},
		{"vlan-range", func(c *Config) { c.WAN[0].VLAN = 5000 }, "vlan: 0-4094"},
		{"two-dhcp-one-dev", func(c *Config) {
			c.WAN[0] = WAN{Name: "a", Device: "wan", Proto: "dhcp"}
			c.WAN[1] = WAN{Name: "b", Device: "wan", Proto: "dhcp"}
		}, "already used by wan a"},
		{"metric", func(c *Config) { c.WAN[0].Metric = 10000 }, "metric: 0-9999"},
		{"metric-dup", func(c *Config) { c.WAN[1].Metric = 0 }, "wan[1].metric: 0 already used by wan wan"},
		{"wan-on-trunk-vlan", func(c *Config) {
			c.Networks = []Network{{Name: "iot", IPv4: "192.168.30.1/24", VLAN: 10, Trunk: []string{"lan4"}}}
			c.WAN[1] = WAN{Name: "wan2", Device: "lan4.10", Proto: "dhcp", Metric: 40}
		}, "wan[1].vlan: lan4.10 already used by network iot"},
		{"wan-vlan-is-net-port", func(c *Config) {
			c.Networks = []Network{{Name: "iot", IPv4: "192.168.30.1/24", Ports: []string{"wan.20"}}}
			c.WAN[1] = WAN{Name: "wan2", Device: "wan", VLAN: 20, Proto: "dhcp", Metric: 40}
		}, "wan[1].device: wan.20 is an untagged port of iot"},
		{"mac-conflict", func(c *Config) { c.WAN[1].MAC = "02:00:00:00:00:01" }, "wan[1].mac: wan already gets MAC a4:a9:30:6e:2b:89 from wan wan"},
		{"trunk-on-wan-wire", func(c *Config) {
			c.Networks = []Network{{Name: "iot", IPv4: "192.168.30.1/24", VLAN: 10, Trunk: []string{"wan"}}}
		}, "wan[0].device: wan carries VLAN 10 of network iot"},
		{"mtu", func(c *Config) { c.WAN[0].MTU = 100 }, "mtu: 576-9000"},
		{"policy-empty", func(c *Config) { c.Policy[0].MAC = "" }, "need at least one of mac, device, src, dst"},
		{"policy-family", func(c *Config) { c.Policy[0].Src, c.Policy[0].Dst = "192.168.1.5", "2001:db8::/32" }, "same family"},
		{"policy-src", func(c *Config) { c.Policy[0].Src = "192.168.1.0/33" }, "src: IP or CIDR"},
		{"policy-dst-inject", func(c *Config) { c.Policy[0].Dst = "1.2.3.4 accept" }, "dst: IP or CIDR"},
		{"policy-table-only", func(c *Config) { c.Policy[0].Mark = "" }, "table and mark go together"},
		{"policy-mark-zero", func(c *Config) { c.Policy[0].Mark = "0x0" }, "mark: invalid"},
		{"policy-table-clash", func(c *Config) {
			c.Policy = append(c.Policy, Policy{Name: "x", MAC: "aa:bb:cc:dd:ee:ff", Via: "wan", Table: 102, Mark: "0x333"})
		}, "routing table 102 already used"},
		{"policy-second-table", func(c *Config) {
			c.Policy = append(c.Policy, Policy{Name: "y", MAC: "aa:bb:cc:dd:ee:ff", Via: "wan2", Table: 103, Mark: "0x103"})
		}, "wan wan2 already uses table 102 / mark 0x102"},
		{"policy-name", func(c *Config) { c.Policy[0].Name = `a" accept` }, "name: invalid"},
		{"mw-mode", func(c *Config) { c.MultiWAN.Mode = "roundrobin" }, "multiwan.mode"},
		{"mw-target", func(c *Config) { c.MultiWAN = MultiWAN{Mode: "failover", Targets: []string{"0.0.0.0"}} }, "multiwan.targets"},
		{"mw-target6", func(c *Config) { c.MultiWAN = MultiWAN{Mode: "failover", Targets: []string{"2606:4700::1111"}} }, "multiwan.targets"},
		{"mw-one-wan", func(c *Config) { c.WAN = c.WAN[:1]; c.Policy = nil; c.MultiWAN.Mode = "failover" }, "needs at least two WANs"},
		{"mw-balance-members", func(c *Config) { c.MultiWAN = MultiWAN{Mode: "balance", Weights: map[string]int{"wan": 1}} }, "balance needs at least two"},
		{"mw-weight-unknown", func(c *Config) { c.MultiWAN = MultiWAN{Mode: "balance", Weights: map[string]int{"nope": 1}} }, "unknown wan \"nope\""},
		{"mw-interval", func(c *Config) { c.MultiWAN = MultiWAN{Mode: "failover", Interval: 1000} }, "multiwan.interval"},
		{"trunk-no-vlan", func(c *Config) {
			c.Networks = []Network{{Name: "iot", IPv4: "192.168.30.1/24", Trunk: []string{"lan4"}}}
		}, "trunk ports need a VLAN id"},
		{"vlan-no-trunk", func(c *Config) {
			c.Networks = []Network{{Name: "iot", IPv4: "192.168.30.1/24", VLAN: 10}}
		}, "needs at least one trunk port"},
		{"trunk-inject", func(c *Config) {
			c.Networks = []Network{{Name: "iot", IPv4: "192.168.30.1/24", VLAN: 10, Trunk: []string{"lan4;x"}}}
		}, "trunk: invalid port"},
		{"trunk-dup", func(c *Config) {
			c.Networks = []Network{{Name: "iot", IPv4: "192.168.30.1/24", VLAN: 10, Trunk: []string{"lan4"}}, {Name: "cam", IPv4: "192.168.31.1/24", VLAN: 10, Trunk: []string{"lan4"}}}
		}, "lan4.10 already used by iot"},
		{"net-dup-name", func(c *Config) {
			c.Networks = []Network{{Name: "iot", IPv4: "192.168.30.1/24"}, {Name: "iot", IPv4: "192.168.31.1/24"}}
		}, "name: duplicate \"iot\""},
		{"route-dev", func(c *Config) { c.Routes = []Route{{Name: "r", Target: "10.0.0.0/8", Dev: "-x"}} }, "dev: invalid"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := testConfig(t)
			tc.mod(c)
			c.defaults()
			errs := strings.Join(c.Validate(), "\n")
			if !strings.Contains(errs, tc.want) {
				t.Errorf("want error %q, got:\n%s", tc.want, errs)
			}
		})
	}
}

func TestNetPolicySelectors(t *testing.T) {
	c := testConfig(t)
	c.Policy = append(c.Policy,
		Policy{Name: "nas-v4", Src: "192.168.1.0/28", Via: "wan2"},
		Policy{Name: "v6-dst", Dst: "2001:db8::/32", Via: "wan"},
		Policy{Name: "tv", MAC: "AA:BB:CC:DD:EE:FF", Dst: "1.2.3.4", Via: "wan2"})
	c.Networks = []Network{{Name: "guest", IPv4: "192.168.20.1/24", Zone: "guest"}}
	c.defaults()
	mustValid(t, c)
	nft := renderNft(c, allExist)
	br := `iifname { "br-lan", "br-guest" }`
	wantSubs(t, "nft", nft,
		br+` ip saddr 192.168.1.0/28 ip daddr != { 192.168.1.0/24, 192.168.20.0/24 } ct state new ct mark set 0x102 meta mark set 0x102 return comment "nas-v4"`,
		br+` ip6 saddr @pd6_0 ip6 daddr 2001:db8::/32 ct state new ct mark set 0x200 meta mark set 0x200 return comment "v6-dst"`,
		`set pd6_0 { type ipv6_addr; flags interval; auto-merge; comment "prefixes delegated by wan wan"; }`,
		`set pd6_1 { type ipv6_addr; flags interval; auto-merge; comment "prefixes delegated by wan wan2"; }`,
		br+` ether saddr aa:bb:cc:dd:ee:ff ip daddr 1.2.3.4 ct state new ct mark set 0x102 meta mark set 0x102 return comment "tv"`,
		br+` ether saddr 02:c3:06:d6:7f:8a ip6 saddr @pd6_1 ip6 daddr != @lan6 ct state new`,
		`iifname "br-lan" ct mark != 0x0 meta mark set ct mark return`,
		`iifname "br-guest" ct mark != 0x0 meta mark set ct mark return`)
	if n := strings.Count(nft, `comment "nas-v4"`); n != 1 {
		t.Errorf("IPv4-only policy emitted %d rules", n)
	}
	// connmark restore comes before the policies, so replies / port forwards keep their WAN
	if strings.Index(nft, `iifname "br-guest" ct mark != 0x0`) > strings.Index(nft, `comment "nas-v4"`) {
		t.Error("restore must precede policy rules")
	}
}

func TestNetBalance(t *testing.T) {
	tempState(t)
	c := testConfig(t)
	c.MultiWAN = MultiWAN{Mode: "balance", Weights: map[string]int{"wan": 2, "wan2": 1}}
	c.defaults()
	mustValid(t, c)
	f := renderMap(t, c)
	want := "# generated by mr — edit router.yaml (multiwan) instead\nINTERVAL=5\nTIMEOUT=2\nFALL=3\nRISE=2\nTARGETS=\"1.1.1.1 8.8.8.8\"\nWANS=\"wan:pppoe-wan wan2:pppoe-wan2\"\n"
	if f[wanmonConf] != want {
		t.Errorf("wanmon.conf:\n%s", f[wanmonConf])
	}
	wantSubs(t, "services", f[GenDir+"/services"], "mr-wanmon\n")
	if serviceFor(wanmonConf) != "mr-wanmon" {
		t.Error("wanmon.conf must restart mr-wanmon")
	}
	nft := renderNft(c, allExist)
	rule := `iifname "br-lan" ip daddr != 192.168.1.0/24 ct state new meta mark 0x0 ct mark set numgen random mod 3 map { 0-1 : 0x200, 2 : 0x102 } meta mark set ct mark comment "multiwan-balance"`
	wantSubs(t, "nft", nft, rule)
	if strings.Index(nft, rule) < strings.Index(nft, `comment "desktop-via-wan2"`) {
		t.Error("balancer must come after the policy routes")
	}
	// a WAN whose PPPoE link is down is left out; one member left = no balancing at all
	nft = renderNft(c, func(d string) bool { return d != "pppoe-wan2" })
	wantNone(t, "nft (wan2 link down)", nft, "numgen")
	// a WAN the health checker reports down is left out too
	c.WAN = append(c.WAN, WAN{Name: "wan3", Device: "lan4", Proto: "dhcp", Metric: 50})
	c.LAN.Ports = []string{"lan2", "lan3"}
	c.MultiWAN.Weights["wan3"] = 1
	mustValid(t, c)
	os.WriteFile(wanStateFile, []byte(`{"time":1,"interval":5,"wans":[{"name":"wan","dev":"pppoe-wan","state":"up","rtt_ms":3.1,"since":1,"fails":0},{"name":"wan2","dev":"pppoe-wan2","state":"down","rtt_ms":null,"since":1,"fails":4}]}`), 0644)
	wantSubs(t, "nft (wan2 unhealthy)", renderNft(c, allExist), "numgen random mod 3 map { 0-1 : 0x200, 2 : 0x202 }")
	// failover only: no balancer
	c.MultiWAN.Mode = "failover"
	wantNone(t, "nft (failover)", renderNft(c, allExist), "numgen")
}

func TestNetTrunkVLAN(t *testing.T) {
	c := testConfig(t)
	c.Networks = []Network{{Name: "iot", IPv4: "192.168.30.1/24", Zone: "lan", VLAN: 10, Trunk: []string{"lan4"}}}
	c.defaults()
	mustValid(t, c)
	sh := renderMap(t, c)[GenDir+"/network.sh"]
	wantSubs(t, "network.sh", sh,
		"ip link set lan4 master br-lan", // untagged role unchanged
		"ip link show lan4.10 >/dev/null 2>&1 || ip link add link lan4 name lan4.10 type vlan id 10\n",
		"ip link set lan4.10 master br-iot 2>/dev/null; ip link set lan4.10 up\n")
	if strings.Index(sh, "ip link add br-iot type bridge") > strings.Index(sh, "lan4.10 master br-iot") {
		t.Error("bridge must exist before the VLAN joins it")
	}
	roles := netRoles(c)
	if roles["lan4"] != "LAN, iot (VLAN 10)" || roles["lan4.10"] != "iot" || roles["wan"] != "WAN wan, WAN wan2" {
		t.Errorf("roles: %v", roles)
	}
}

func TestReadPorts(t *testing.T) {
	root := t.TempDir()
	old := sysNet
	sysNet = root
	t.Cleanup(func() { sysNet = old })
	dev := func(name string, attrs map[string]string, dirs ...string) {
		for k, v := range attrs {
			p := filepath.Join(root, name, k)
			os.MkdirAll(filepath.Dir(p), 0755)
			os.WriteFile(p, []byte(v+"\n"), 0644)
		}
		for _, d := range dirs {
			os.MkdirAll(filepath.Join(root, name, d), 0755)
		}
	}
	base := func(extra map[string]string) map[string]string {
		m := map[string]string{"operstate": "up", "mtu": "1500", "address": "02:c6:28:a7:7c:d7", "flags": "0x1003", "carrier": "1", "statistics/rx_bytes": "1000", "statistics/tx_bytes": "2000", "statistics/rx_errors": "3"}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	dev("lo", base(nil))
	dev("wan", base(map[string]string{"speed": "1000", "duplex": "full", "phys_port_name": "p5"}))
	dev("lan2", base(map[string]string{"carrier": "0", "operstate": "lowerlayerdown", "speed": "-1", "phys_port_name": "p1"}))
	dev("lan10", base(map[string]string{"speed": "100", "duplex": "half", "phys_port_name": "p9"}))
	dev("eth0", base(nil), "dsa")
	dev("br-lan", base(nil), "bridge")
	dev("pppoe-wan", base(map[string]string{"type": "512"}))
	dev("phy1-ap0", base(nil), "phy80211")
	dev("tailscale0", base(map[string]string{"type": "65534"}))
	dev("lan4.10", base(map[string]string{"uevent": "DEVTYPE=vlan\nINTERFACE=lan4.10"}))
	os.Symlink("../br-lan", filepath.Join(root, "lan2", "master"))

	c := testConfig(t)
	ps := readPorts(c)
	var names, kinds []string
	for _, p := range ps {
		names = append(names, p.Name)
		kinds = append(kinds, p.Kind)
	}
	if got := strings.Join(names, " "); got != "wan lan2 lan10 eth0 br-lan lan4.10 pppoe-wan phy1-ap0 tailscale0" {
		t.Errorf("order: %s", got)
	}
	if got := strings.Join(kinds, " "); got != "port port port cpu bridge vlan ppp wifi tunnel" {
		t.Errorf("kinds: %s", got)
	}
	w, l2, l10 := ps[0], ps[1], ps[2]
	if w.Speed != 1000 || w.Duplex != "full" || !w.Carrier || !w.AdminUp || w.Role != "WAN wan, WAN wan2" || w.RxBytes != 1000 || w.RxErrors != 3 {
		t.Errorf("wan: %+v", w)
	}
	if l2.Speed != 0 || l2.Carrier || l2.Master != "br-lan" || l2.Role != "LAN" {
		t.Errorf("lan2: %+v", l2)
	}
	if l10.Speed != 100 || l10.Duplex != "half" {
		t.Errorf("lan10: %+v", l10)
	}
}

func TestDHCPHelpers(t *testing.T) {
	for _, tc := range []struct {
		mask, subnet string
		want         int
	}{{"24", "", 24}, {"", "255.255.255.128", 25}, {"x", "bogus", 24}, {"33", "", 24}, {"", "255.255.0.0", 16}} {
		if got := dhcpPrefix(tc.mask, tc.subnet); got != tc.want {
			t.Errorf("dhcpPrefix(%q,%q)=%d want %d", tc.mask, tc.subnet, got, tc.want)
		}
	}
	got := strings.Join(validIPs(3, "1.1.1.1 bogus;reboot 0.0.0.0 8.8.8.8", "::1 9.9.9.9"), " ")
	if got != "1.1.1.1 8.8.8.8 ::1" {
		t.Errorf("validIPs: %s", got)
	}
}

func TestWanStateAndResolv(t *testing.T) {
	tempState(t)
	c := testConfig(t)
	c.MultiWAN = MultiWAN{Mode: "failover"}
	c.defaults()
	if !wanHealthy(c, "wan") {
		t.Error("no state file = healthy")
	}
	os.WriteFile(wanStateFile, []byte(`{"time":5,"interval":5,"wans":[{"name":"wan","dev":"pppoe-wan","state":"down","rtt_ms":null,"since":1,"fails":3},{"name":"wan2","dev":"pppoe-wan2","state":"up","rtt_ms":12.5,"since":1,"fails":0}]}`), 0644)
	if wanHealthy(c, "wan") || !wanHealthy(c, "wan2") {
		t.Error("state file not honoured")
	}
	off := testConfig(t)
	if !wanHealthy(off, "wan") {
		t.Error("without multiwan every WAN is healthy, whatever a stale state file says")
	}
	writeLease("wan", wanLease{IP: "203.0.113.11", DNS: []string{"1.1.1.1", "8.8.8.8"}, Since: 1})
	writeLease("wan2", wanLease{IP: "203.0.113.12", DNS: []string{"9.9.9.9", "1.1.1.1"}, Since: 1})
	writeResolv(c)
	got, _ := os.ReadFile(resolvConf)
	if want := "nameserver 9.9.9.9\nnameserver 1.1.1.1\nnameserver 8.8.8.8\n"; !strings.HasSuffix(string(got), want) {
		t.Errorf("resolv.conf (healthy wan2 first):\n%s", got)
	}
	removeLease("wan2")
	writeResolv(c)
	got, _ = os.ReadFile(resolvConf)
	if want := "nameserver 1.1.1.1\nnameserver 8.8.8.8\n"; !strings.HasSuffix(string(got), want) {
		t.Errorf("resolv.conf after wan2 down:\n%s", got)
	}
	if l, ok := readLease("wan"); !ok || l.IP != "203.0.113.11" {
		t.Errorf("lease: %+v", l)
	}
	// no WAN with DNS left (or none recorded yet, e.g. right after an upgrade): no file at all,
	// never an empty one that dnsmasq would pick as the newest
	removeLease("wan")
	writeResolv(c)
	if _, err := os.Stat(resolvConf); !os.IsNotExist(err) {
		t.Error("empty resolv.conf written")
	}
}

func TestInitInstancesAndRedialInput(t *testing.T) {
	if r := apiNetRedial(apiReq{method: "GET", body: []byte(`{"wan":"wan"}`)}); r.status != 405 {
		t.Errorf("redial via GET: %d", r.status)
	}
	if r := apiNetRedial(apiReq{method: "POST", body: []byte(`{"wan":"../../etc"}`)}); r.status != 400 {
		t.Errorf("redial with bad name: %d", r.status)
	}
}

// A WAN that left router.yaml (or moved to another interface) has its lease record dropped;
// the current WANs keep theirs. (The devices here do not exist: ip(8) only reads and fails.)
func TestDropStaleWANs(t *testing.T) {
	d := tempState(t)
	c := testConfig(t)
	writeLease("wan", wanLease{IP: "203.0.113.11", Dev: "pppoe-wan"})     // current
	writeLease("wan2", wanLease{IP: "203.0.113.12"})                      // current, written without a device
	writeLease("hotel", wanLease{IP: "10.0.0.5", Dev: "mrtestgone0"})     // removed from router.yaml
	writeLease("old", wanLease{IP: "10.0.1.5", Dev: "-f"})                // removed, unsafe device name
	os.WriteFile(filepath.Join(d, "wan", "junk.json"), []byte("{"), 0644) // unreadable, not a WAN
	os.WriteFile(filepath.Join(d, "wan", "keep.tmp"), []byte("x"), 0644)  // not a lease record
	dropStaleWANs(c)
	for name, want := range map[string]bool{"wan.json": true, "wan2.json": true, "hotel.json": false, "old.json": false, "junk.json": false, "keep.tmp": true} {
		if _, err := os.Stat(filepath.Join(d, "wan", name)); (err == nil) != want {
			t.Errorf("%s: kept=%v, want %v", name, err == nil, want)
		}
	}
	// the same WAN name on another interface (VLAN / device changed): the old record goes
	writeLease("wan2", wanLease{IP: "203.0.113.12", Dev: "mrtestold0"})
	dropStaleWANs(c)
	if _, ok := readLease("wan2"); ok {
		t.Error("lease of a WAN that moved to another interface kept")
	}
}

func TestDelegatedPrefixesFromWANEvent(t *testing.T) {
	env := []string{"interface=pppoe-wan2", "reason=REBIND6", "new_dhcp6_ia_pd1_prefix1=2001:db8:b911:994e::",
		"new_dhcp6_ia_pd1_prefix1_length=64", "new_dhcp6_ia_pd1_prefix1_pltime=2592000", "new_dhcp6_ia_pd1_iaid=00000001"}
	got := delegatedPrefixes(env)
	if len(got) != 1 || got[0] != "2001:db8:b911:994e::/64" {
		t.Fatalf("got %v", got)
	}
	if p := delegatedPrefixes([]string{"new_dhcp6_ia_pd1_prefix1=zz;rm", "new_dhcp6_ia_pd1_prefix1_length=64"}); len(p) != 0 {
		t.Fatalf("bad prefix accepted: %v", p)
	}
}

// IPv6 policy routes follow the source prefix (Cd1s/mini-router#63): the prefix sets are filled from
// what the dhcpcd hook recorded per WAN; garbage in the record never reaches nft.
func TestPD6Script(t *testing.T) {
	c := testConfig(t)
	old := wanRunDir
	wanRunDir = t.TempDir()
	t.Cleanup(func() { wanRunDir = old })
	os.WriteFile(pd6File("wan2"), []byte("2001:db8:2::/60\n192.0.2.0/24\n2001:db8:2:10::1/64 dev x\n::ffff:1.2.3.4/128\n"), 0644)
	got := pd6Script(c)
	// the home policy has nat6 (#108): its chains mark and translate to wan2's first prefix
	nat := "flush chain inet mr npt6m_0\nflush chain inet mr npt6n_0\n"
	if got != "flush set inet mr pd6_1\nadd element inet mr pd6_1 { 2001:db8:2::/60, 2001:db8:2:10::/64 }\n"+nat+
		"add rule inet mr npt6m_0 ct mark set 0x102 meta mark set 0x102 accept\nadd rule inet mr npt6n_0 snat ip6 prefix to 2001:db8:2::/60\n" {
		t.Errorf("pd6Script:\n%s", got)
	}
	os.Remove(pd6File("wan2"))
	if got := pd6Script(c); got != "flush set inet mr pd6_1\n"+nat {
		t.Errorf("no record: %q", got)
	}
	c.Policy[0].NAT6 = false
	if got := pd6Script(c); got != "flush set inet mr pd6_1\n" {
		t.Errorf("without nat6: %q", got)
	}
}

// nat6 (#108): validation, no chains without it, fallback: drop covers every source.
func TestNetPolicyNAT6(t *testing.T) {
	c := testConfig(t)
	c.Policy = append(c.Policy,
		Policy{Name: "v4only", Src: "192.168.1.9", Via: "wan2", NAT6: true},
		Policy{Name: "wan-no-pd", MAC: "aa:bb:cc:dd:ee:ff", Via: "wan", NAT6: true})
	c.WAN[0].IPv6PD = false
	c.defaults()
	errs := strings.Join(c.Validate(), "\n")
	for _, w := range []string{"policy_routes[1].nat6: the policy is IPv4-only", "policy_routes[2].nat6: wan wan needs ipv6 and ipv6_pd"} {
		if !strings.Contains(errs, w) {
			t.Errorf("want %q in:\n%s", w, errs)
		}
	}
	c = testConfig(t)
	c.Policy[0].Fallback = "drop"
	nft := renderNft(c, allExist)
	wantSubs(t, "nft", nft, `iifname "br-lan" ether saddr 02:c3:06:d6:7f:8a meta nfproto ipv6 oifname "pppoe-wan" counter drop comment "fallback:desktop-via-wan2"`)
	c.Policy[0].NAT6 = false
	nft = renderNft(c, allExist)
	wantSubs(t, "nft", nft, `iifname "br-lan" ether saddr 02:c3:06:d6:7f:8a ip6 saddr @pd6_1 oifname "pppoe-wan" counter drop comment "fallback:desktop-via-wan2"`)
	wantNone(t, "nft", nft, "npt6", "!= @pd6")
}

// Cd1s/mini-router#97: the router's own IPv6 leaves each WAN with a source from that WAN's prefix.
func TestSrcDefaults6(t *testing.T) {
	addrs := []string{"2001:db8:2::6", "fd00::1", "2001:db8:1:5::6"}
	if got := wanSrc6([]string{"2001:db8:1::/56"}, addrs); got != "2001:db8:1:5::6" {
		t.Fatalf("wan's address: %q", got)
	}
	if got := wanSrc6([]string{"2001:db8:3::/64", "bad"}, addrs); got != "" {
		t.Fatalf("no address in the prefix: %q", got)
	}
	w := &WAN{Metric: 0}
	if m := src6Metric(w, true); m != 1 { // metric 0 would be 1024 for IPv6
		t.Fatalf("metric %d", m)
	}
	if m := src6Metric(w, false); m != 1+downMetric {
		t.Fatalf("down metric %d", m)
	}
	got := strings.Join(src6Args("wan", []string{"via", "fe80::1"}, "2001:db8:1::6", 11), " ")
	if want := "-6 route replace default via fe80::1 dev wan src 2001:db8:1::6 proto 97 metric 11"; got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}
