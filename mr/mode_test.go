package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// modeYAML: a small box behind a main router at 192.168.1.1.
const modeYAML = `mode: bypass
system: {hostname: side, ntp: [pool.ntp.org]}
lan: {bridge: br-lan, ports: [eth0], ipv4: 192.168.1.2/24, gateway: 192.168.1.1}
wan: []
policy_routes: []
static_routes: []
firewall: {offload: software}
dhcp: {start: 100, end: 249, lease: 12h, domain: lan, hosts: [{name: tv, mac: "02:00:00:00:00:21", ip: 192.168.1.21}]}
dns: {cache_size: 4000}
wifi: {radios: []}
services: {}
`

func modeConfig(t *testing.T, yml string) *Config {
	t.Helper()
	p := filepath.Join(t.TempDir(), "router.yaml")
	os.WriteFile(p, []byte(yml), 0644)
	c, err := loadConfig(p, filepath.Join(t.TempDir(), "none.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	c.secrets["proxy_n1"] = "x"
	return c
}

func modeFiles(t *testing.T, c *Config) map[string]string {
	t.Helper()
	fs, err := Render(c)
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]string{}
	for _, f := range fs {
		m[f.Path] = f.Data
	}
	return m
}

func wantLines(t *testing.T, what, text string, lines ...string) {
	t.Helper()
	for _, l := range lines {
		if !strings.Contains(text, l) {
			t.Errorf("%s lacks %q", what, l)
		}
	}
}

func noLines(t *testing.T, what, text string, lines ...string) {
	t.Helper()
	for _, l := range lines {
		if strings.Contains(text, l) {
			t.Errorf("%s has %q", what, l)
		}
	}
}

func TestModeValidate(t *testing.T) {
	for name, tc := range map[string]struct {
		edit func(c *Config)
		want string
	}{
		"bad mode":         {func(c *Config) { c.Mode = "bridge" }, `mode: router, bypass or ap, got "bridge"`},
		"no gateway":       {func(c *Config) { c.LAN.Gateway = "" }, "lan.gateway: the main router's address is required in mode bypass"},
		"gateway outside":  {func(c *Config) { c.LAN.Gateway = "192.168.2.1" }, "is not inside lan.ipv4"},
		"gateway is me":    {func(c *Config) { c.LAN.Gateway = "192.168.1.2" }, "this box's own address"},
		"a wan":            {func(c *Config) { c.WAN = []WAN{{Name: "wan", Device: "eth1", Proto: "dhcp"}} }, "wan: not in mode bypass"},
		"forwards":         {func(c *Config) { c.Firewall.Forwards = []Forward{{Name: "x"}} }, "firewall.forwards: not in mode bypass"},
		"ra":               {func(c *Config) { c.LAN.IPv6RA = true }, "lan.ipv6_ra: not in mode bypass"},
		"isp dns":          {func(c *Config) { c.DNS.Upstream = "isp" }, "dns.upstream isp: not in mode bypass"},
		"bad clients":      {func(c *Config) { c.Bypass.Clients = "some" }, "bypass.clients: route-only, all or selected"},
		"selected no macs": {func(c *Config) { c.Bypass.Clients = "selected" }, "bypass.macs: clients selected needs at least one MAC"},
		"macs not selected": {func(c *Config) { c.Bypass.MACs = []string{"02:00:00:00:00:01"} },
			"bypass.macs: only with clients selected"},
		"dup macs": {func(c *Config) {
			c.Bypass.Clients, c.Bypass.MACs = "selected", []string{"02:00:00:00:00:0a", "02:00:00:00:00:0A"}
		}, "bypass.macs[1]: duplicate"},
		"nat route-only": {func(c *Config) { c.Bypass.NAT = boolp(false) }, "bypass.nat: only with clients all or selected"},
		"proxy v6": {func(c *Config) {
			c.Proxy = Proxy{Enabled: true, Nodes: []ProxyNode{{Name: "n1", Server: "203.0.113.7", Port: 8388, Method: "aes-128-gcm", Password: "proxy_n1"}},
				Rules: []ProxyRule{{Name: "r", Outbound: "n1", CIDRs: []string{"198.51.100.0/24"}}}}
		}, "proxy.ipv4_only: must be true in mode bypass"},
		"ap proxy": {func(c *Config) {
			c.Mode = "ap"
			c.Proxy = Proxy{Enabled: true, IPv4Only: true, Nodes: []ProxyNode{{Name: "n1", Server: "203.0.113.7", Port: 8388, Method: "aes-128-gcm", Password: "proxy_n1"}},
				Rules: []ProxyRule{{Name: "r", Outbound: "n1", CIDRs: []string{"198.51.100.0/24"}}}}
		}, "proxy: not in mode ap"},
		"ap bypass": {func(c *Config) { c.Mode, c.Bypass.Clients = "ap", "all" }, "bypass: only in mode bypass"},
		"router gateway": {func(c *Config) {
			c.Mode = ""
			c.WAN = []WAN{{Name: "wan", Device: "eth1", Proto: "dhcp", Metric: 10}}
		}, "lan.gateway: only in mode bypass or ap"},
		"router no wan": {func(c *Config) { c.Mode, c.LAN.Gateway = "router", "" }, "wan: at least one WAN required (or mode bypass / ap)"},
	} {
		c := modeConfig(t, modeYAML)
		tc.edit(c)
		if errs := strings.Join(c.Validate(), "\n"); !strings.Contains(errs, tc.want) {
			t.Errorf("%s: want %q in:\n%s", name, tc.want, errs)
		}
	}
	c := modeConfig(t, modeYAML)
	mustValid(t, c)
	if c.DNS.Upstream != "manual" || strings.Join(c.DNS.Servers, ",") != "192.168.1.1" {
		t.Errorf("bypass DNS defaults: %s %v", c.DNS.Upstream, c.DNS.Servers)
	}
}

// route-only: no DHCP, no NAT, a default route via the main router; the proxy's replies go back
// through it (connmark + fwmark rule + table).
func TestModeBypassRouteOnly(t *testing.T) {
	old := proxyRunlevel
	proxyRunlevel = t.TempDir()
	t.Cleanup(func() { proxyRunlevel = old })
	os.WriteFile(filepath.Join(proxyRunlevel, "mr-proxy"), nil, 0644)
	os.WriteFile(filepath.Join(proxyRunlevel, "mr-proxy-dns"), nil, 0644)
	c := modeConfig(t, modeYAML+`proxy:
  enabled: true
  ipv4_only: true
  nodes: [{name: n1, server: 203.0.113.7, port: 8388, method: aes-128-gcm, password_secret: proxy_n1}]
  rules: [{name: blocked, outbound: n1, cidrs: [198.51.100.0/24]}]
`)
	mustValid(t, c)
	f := modeFiles(t, c)
	sh := f[GenDir+"/network.sh"]
	wantLines(t, "network.sh", sh,
		"ip -4 route replace default via 192.168.1.1 dev br-lan\n",
		"echo 2 > /proc/sys/net/ipv6/conf/br-lan/accept_ra\n",
		"ip -4 rule add fwmark 0x2000000/0x2000000 lookup 301 pref 5201\n",
		"ip -4 route replace default via 192.168.1.1 dev br-lan table 301\n",
		"ip link set eth0 master br-lan")
	conf := f["/etc/dnsmasq.conf"]
	wantLines(t, "dnsmasq.conf", conf, "no-resolv\nserver=192.168.1.1\n")
	noLines(t, "dnsmasq.conf", conf, "dhcp-range", "dhcp-option", "enable-ra")
	nft := renderNft(c, func(string) bool { return true })
	wantLines(t, "ruleset", nft,
		"ct mark set ct mark | 0x1000000",
		"type route hook output priority mangle; policy accept;",
		"ct direction reply ct mark & 0x1000000 == 0x1000000 meta mark set 0x2000000")
	noLines(t, "ruleset", nft, "masquerade", "wan-in-drop", "{  }", "{ }")
	if !strings.Contains(sysctlOf(f), "net.ipv4.ip_forward=1\n") {
		t.Error("bypass must forward")
	}
}

func sysctlOf(f map[string]string) string { return f["/etc/sysctl.d/90-mini-router.conf"] }

// all: this box is the DHCP server, gateway and DNS of everyone; forwarded traffic is masqueraded.
// selected: only the listed devices get this box (their own tag beats the range's).
func TestModeBypassDHCP(t *testing.T) {
	c := modeConfig(t, modeYAML+"bypass: {clients: all}\n")
	mustValid(t, c)
	conf := modeFiles(t, c)["/etc/dnsmasq.conf"]
	wantLines(t, "all: dnsmasq.conf", conf, "dhcp-range=set:lan,192.168.1.100,192.168.1.249,255.255.255.0,12h\n",
		"dhcp-option=tag:lan,option:router,192.168.1.2\n", "dhcp-option=tag:lan,option:dns-server,192.168.1.2\n")
	nft := renderNft(c, func(string) bool { return true })
	wantLines(t, "all: ruleset", nft, `iifname "br-lan" oifname "br-lan" meta nfproto ipv4 masquerade comment "bypass-nat"`)
	c.Bypass.NAT = boolp(false)
	if strings.Contains(renderNft(c, func(string) bool { return true }), "bypass-nat") {
		t.Error("nat: false still masquerades")
	}

	c = modeConfig(t, modeYAML+`bypass: {clients: selected, macs: ["02:00:00:00:00:21", "02:00:00:00:00:22"]}`+"\n")
	mustValid(t, c)
	conf = modeFiles(t, c)["/etc/dnsmasq.conf"]
	wantLines(t, "selected: dnsmasq.conf", conf,
		"dhcp-option=tag:lan,option:router,192.168.1.1\ndhcp-option=tag:lan,option:dns-server,192.168.1.1\n",
		"dhcp-option=tag:bypass,option:router,192.168.1.2\ndhcp-option=tag:bypass,option:dns-server,192.168.1.2\n",
		"dhcp-host=02:00:00:00:00:21,set:bypass,192.168.1.21,tv\n", // the static host keeps one line
		"dhcp-host=02:00:00:00:00:22,set:bypass\n")
	if strings.Count(conf, "02:00:00:00:00:21") != 1 {
		t.Error("a selected device with a static lease has two dhcp-host lines")
	}
}

// ap: bridging only — forwarding off, no flowtable, no NAT, no DHCP.
func TestModeAP(t *testing.T) {
	c := modeConfig(t, strings.Replace(modeYAML, "mode: bypass", "mode: ap", 1))
	mustValid(t, c)
	f := modeFiles(t, c)
	sc := sysctlOf(f)
	wantLines(t, "sysctl", sc, "net.ipv4.ip_forward=0\n", "net.ipv6.conf.all.forwarding=0\n")
	nft := renderNft(c, func(string) bool { return true })
	noLines(t, "ruleset", nft, "flowtable", "masquerade", "wan-in-drop")
	noLines(t, "dnsmasq.conf", f["/etc/dnsmasq.conf"], "dhcp-range")
	wantLines(t, "network.sh", f[GenDir+"/network.sh"], "ip -4 route replace default via 192.168.1.1 dev br-lan\n")
	noLines(t, "network.sh", f[GenDir+"/network.sh"], "lookup 301")
}
