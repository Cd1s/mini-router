package main

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// proxyTestConfig: the home config plus a proxy section like the lab fragment.
func proxyTestConfig(t *testing.T) *Config {
	t.Helper()
	c := testConfig(t)
	dir := t.TempDir()
	dom := filepath.Join(dir, "ai.domains")
	cidr := filepath.Join(dir, "tg.cidrs")
	os.WriteFile(dom, []byte("# AI\nopenai.com\n*.anthropic.com   # wildcard = suffix\n\n+.claude.ai\nexample-b.net\n"), 0644)
	os.WriteFile(cidr, []byte("91.108.4.0/22\n91.108.8.0/22 # dup-ish\n91.108.8.1\n2001:67c:4e8::/48\n"), 0644)
	c.secrets["proxy_sg1"] = "AAECAwQFBgcICQoLDA0ODw=="
	c.secrets["proxy_jp1"] = "not-a-real-password"
	c.Proxy = Proxy{
		Enabled: true,
		Nodes: []ProxyNode{
			{Name: "sg1", Server: "sg1.example.net", Port: 8388, Method: "2022-blake3-aes-128-gcm", Password: "proxy_sg1"},
			{Name: "jp1", Server: "203.0.113.7", Port: 8389, Method: "aes-128-gcm", Password: "proxy_jp1", TCPOnly: true},
		},
		Groups: []ProxyGroup{{Name: "auto", Type: "urltest", Nodes: []string{"sg1", "jp1"}, Interval: "3m"}, {Name: "pick", Type: "selector", Nodes: []string{"jp1", "sg1"}}},
		Rules: []ProxyRule{
			{Name: "ai", Outbound: "auto", Domains: []string{"Chat.OpenAI.com.", "x.ai"}, DomainsFile: dom},
			{Name: "tg", Outbound: "pick", Domains: []string{"telegram.org"}, CIDRs: []string{"149.154.160.0/20"}, CIDRFile: cidr},
		},
		Bypass: []ProxyDevice{{Name: "Desktop", MAC: "02:C3:06:D6:7F:8A"}},
	}
	return c
}

func TestProxyOffLeavesEverythingElseAlone(t *testing.T) {
	c := testConfig(t)
	got := renderMap(t, c)
	for _, p := range []string{proxyGenJSON, proxyGenDNS} {
		if _, ok := got[p]; ok {
			t.Errorf("%s rendered while proxy is absent", p)
		}
	}
	if strings.Contains(got[GenDir+"/network.sh"], "proxy") || strings.Contains(got[GenDir+"/services"], "mr-proxy") {
		t.Error("proxy leaked into network.sh / services")
	}
	if strings.Contains(renderNft(c, func(string) bool { return true }), "proxy") {
		t.Error("proxy chains rendered while proxy is absent")
	}
	// disabled but configured: validated, nothing rendered
	c = proxyTestConfig(t)
	c.Proxy.Enabled = false
	if errs := c.Validate(); len(errs) > 0 {
		t.Fatal(errs)
	}
	if strings.Contains(renderNft(c, func(string) bool { return true }), "proxy") || renderMap(t, c)[proxyGenJSON] != "" {
		t.Error("disabled proxy rendered something")
	}
}

func TestProxyRender(t *testing.T) {
	c := proxyTestConfig(t)
	if errs := c.Validate(); len(errs) > 0 {
		t.Fatal(errs)
	}
	got := renderMap(t, c)

	var sb map[string]any
	if err := json.Unmarshal([]byte(got[proxyGenJSON]), &sb); err != nil {
		t.Fatalf("sing-box.json: %v", err)
	}
	js := got[proxyGenJSON]
	for _, s := range []string{
		`"type": "fakeip"`, `"inet4_range": "198.18.0.0/15"`, `"inet6_range": "fc00::/18"`,
		`"type": "tproxy"`, `"listen": "::1"`, `"listen_port": 7893`, `"listen_port": 1053`,
		`"method": "2022-blake3-aes-128-gcm"`, `"password": "AAECAwQFBgcICQoLDA0ODw=="`, `"network": "tcp"`,
		`"type": "urltest"`, `"interval": "3m"`, `"interrupt_exist_connections": true`,
		`"action": "hijack-dns"`, `"default_domain_resolver": "local"`, `"final": "direct"`,
		`"store_fakeip": true`, `"external_controller": "127.0.0.1:9090"`, `"rcode": "NOERROR"`,
		`"chat.openai.com"`, `"anthropic.com"`, `"claude.ai"`, `"91.108.8.1/32"`, `"2001:67c:4e8::/48"`, `"149.154.160.0/20"`,
	} {
		if !strings.Contains(js, s) {
			t.Errorf("sing-box.json missing %s", s)
		}
	}
	route := sb["route"].(map[string]any)["rules"].([]any)
	if len(route) != 3 || route[1].(map[string]any)["outbound"] != "auto" || route[2].(map[string]any)["outbound"] != "pick" {
		t.Errorf("route rules: %v", route)
	}

	dns := got[proxyGenDNS]
	for _, s := range []string{
		"port=1054", "interface=br-lan", "no-dhcp-interface=br-lan", "bind-dynamic", "cache-size=8000", "min-cache-ttl=3600",
		"resolv-file=/run/ppp/resolv.conf", "stop-dns-rebind", "rebind-domain-ok=/lan/", "rebind-domain-ok=//",
		"server=/lan/127.0.0.1", "server=//127.0.0.1", "rev-server=192.168.1.0/24,127.0.0.1", "addn-hosts=/etc/lucky/dnsmasq.hosts",
		"server=/example-a.com/127.0.0.1#5453", "server=/openai.com/127.0.0.1#1053", "server=/telegram.org/127.0.0.1#1053",
		"server=/example-b.net/127.0.0.1#1053",
	} {
		if !strings.Contains(dns, s+"\n") {
			t.Errorf("proxy-dns.conf missing %q", s)
		}
	}
	// a split domain that is also proxied must not keep its split upstream (dnsmasq would mix both)
	if strings.Contains(dns, "server=/example-b.net/127.0.0.1#5453") {
		t.Error("proxied domain still in the split list")
	}
	for _, bad := range []string{"dhcp-range", "enable-ra", "domain-needed"} {
		if strings.Contains(dns, bad) {
			t.Errorf("proxy-dns.conf must not contain %s", bad)
		}
	}

	sh := got[GenDir+"/network.sh"]
	for _, s := range []string{
		"while ip -4 rule del pref 5200 2>/dev/null; do :; done\n",
		"ip -4 rule add iif br-lan fwmark 0x1000000/0x1000000 lookup 300 pref 5200", "ip -6 rule add fwmark 0x1000000/0x1000000 lookup 300 pref 5200",
		"ip -4 route replace local 0.0.0.0/0 dev lo table 300", "ip -6 route replace local ::/0 dev lo table 300",
	} {
		if !strings.Contains(sh, s) {
			t.Errorf("network.sh missing %q", s)
		}
	}
	// the IPv4 rule is per bridge (iif) so strict rp_filter's reverse lookup (iif lo) never sees table 300
	if strings.Contains(sh, "ip -4 rule add fwmark 0x1000000") || strings.Contains(sh, "dev br-lan table 300") {
		t.Errorf("IPv4 proxy rule must be iif-scoped:\n%s", sh)
	}
	if !strings.Contains(got[GenDir+"/services"], "mr-proxy\nmr-proxy-dns") {
		t.Error("services missing mr-proxy / mr-proxy-dns")
	}

	nft := renderNft(c, func(string) bool { return true })
	for _, s := range []string{
		"chain proxy_pre {\n\t\ttype filter hook prerouting priority mangle + 5; policy accept;",
		`iifname != { "br-lan" } return`, "ether saddr @proxy_bypass return", "elements = { 02:c3:06:d6:7f:8a }",
		"ip daddr @proxy4 meta l4proto { tcp, udp } ct direction original goto proxy_tp4",
		"ip6 daddr @proxy6 meta l4proto { tcp, udp } ct direction original goto proxy_tp6",
		"meta l4proto tcp socket transparent 1 meta mark set 0x1000000 accept",
		"tproxy ip to 127.0.0.1:7893 meta mark set 0x1000000 accept", "tproxy ip6 to [::1]:7893 meta mark set 0x1000000 accept",
		"91.108.4.0/22, 91.108.8.0/22, 149.154.160.0/20, 198.18.0.0/15", "2001:67c:4e8::/48, fc00::/18",
		"type nat hook prerouting priority dstnat - 5;",
		// dns.redirect is on in the home config: every DNS query of a proxied client is taken
		`iifname { "br-lan" } ether saddr != @proxy_bypass meta l4proto { tcp, udp } th dport 53 redirect to :1054`,
	} {
		if !strings.Contains(nft, s) {
			t.Errorf("nft missing %q", s)
		}
	}
	if strings.Contains(nft, "91.108.8.1/32") {
		t.Error("contained prefix not merged away")
	}
	if !strings.Contains(nft, "chain proxy_tp4 {\n\t\tfib daddr type local return\n\t\tmeta l4proto { tcp, udp } th dport 53 return") {
		t.Error("with dns.redirect, DNS to a proxied range must be hijacked, not tunnelled")
	}
	c.DNS.Redirect = false
	nft = renderNft(c, func(string) bool { return true })
	if !strings.Contains(nft, "th dport 53 fib daddr type local redirect to :1054") || strings.Contains(nft, "th dport 53 return") {
		t.Error("without dns.redirect only queries to the router are redirected")
	}
}

// A rollback can restore an enabled proxy while mr-proxy / mr-proxy-dns stay out of the runlevel
// (the rolled-back apply disabled them): the nft rules, which send every proxied client's DNS to
// mr-proxy-dns, must then not be loaded, or the whole LAN loses DNS.
func TestProxyNftNeedsEnabledServices(t *testing.T) {
	c := proxyTestConfig(t)
	old := proxyRunlevel
	defer func() { proxyRunlevel = old }()
	proxyRunlevel = t.TempDir()
	nft := func() string { return renderNft(c, func(string) bool { return true }) }
	if strings.Contains(nft(), "chain proxy_") {
		t.Error("proxy rules rendered while neither service is in the runlevel")
	}
	os.WriteFile(filepath.Join(proxyRunlevel, "mr-proxy-dns"), nil, 0644)
	if strings.Contains(nft(), "chain proxy_") {
		t.Error("proxy rules rendered with only mr-proxy-dns in the runlevel")
	}
	os.Symlink("/etc/init.d/mr-proxy", filepath.Join(proxyRunlevel, "mr-proxy")) // dangling here, like OpenRC's links off-target
	if n := nft(); !strings.Contains(n, "chain proxy_pre") || !strings.Contains(n, "chain proxy_dns") {
		t.Error("proxy rules missing with both services in the runlevel")
	}
	proxyRunlevel = filepath.Join(proxyRunlevel, "no-such-dir")
	if !strings.Contains(nft(), "chain proxy_pre") {
		t.Error("without an OpenRC runlevel directory (CI, tests) the rules must always render")
	}
}

func TestProxyIPv4OnlyAndCustomNode(t *testing.T) {
	c := proxyTestConfig(t)
	c.Proxy.IPv4Only = true
	c.Proxy.Rules[1].CIDRFile = ""
	c.secrets["proxy_x"] = `{"type":"trojan","tag":"ignored","server":"t.example.net","server_port":443,"password":"p","tls":{"enabled":true}}`
	c.Proxy.Nodes = append(c.Proxy.Nodes, ProxyNode{Name: "tro", Type: "custom", JSON: "proxy_x"})
	if errs := c.Validate(); len(errs) > 0 {
		t.Fatal(errs)
	}
	got := renderMap(t, c)
	js := got[proxyGenJSON]
	if strings.Contains(js, "inet6_range") || strings.Contains(js, "tproxy6") || !strings.Contains(js, `"tag": "tro"`) || strings.Contains(js, "ignored") {
		t.Errorf("ipv4_only / custom node wrong:\n%s", js)
	}
	nft := renderNft(c, func(string) bool { return true })
	if strings.Contains(nft, "proxy6") || strings.Contains(nft, "tproxy ip6") {
		t.Error("ipv4_only still renders IPv6 tproxy")
	}
	if strings.Contains(got[GenDir+"/network.sh"], "ip -6 rule add fwmark 0x1000000") {
		t.Error("ipv4_only still adds the IPv6 rule")
	}
	c.Proxy.Rules[0].CIDRs = []string{"2001:db8::/32"}
	if !strings.Contains(strings.Join(c.Validate(), "\n"), "ipv4_only") {
		t.Error("IPv6 CIDR accepted with ipv4_only")
	}
}

func TestProxyValidation(t *testing.T) {
	c := proxyTestConfig(t)
	p := &c.Proxy
	c.secrets["proxy_bad"] = "c2hvcnQ=" // 5 bytes
	c.secrets["proxy_js"] = `["not","an","object"]`
	p.TProxyPort = 22
	p.DNSPort = 1054 // collides with lan_dns_port default
	p.LogLevel = "trace"
	p.Nodes = append(p.Nodes,
		ProxyNode{Name: "sg1", Server: "x.example", Port: 1, Method: "aes-128-gcm", Password: "proxy_jp1"},
		ProxyNode{Name: "direct", Server: "-oProxyCommand=x", Port: 70000, Method: "rc4-md5", Password: "Bad Name"},
		ProxyNode{Name: "k", Server: "1.2.3.4", Port: 1, Method: "2022-blake3-aes-256-gcm", Password: "proxy_bad"},
		ProxyNode{Name: "j", Type: "custom", JSON: "proxy_js"},
		ProxyNode{Name: "m", Server: "1.2.3.4", Port: 1, Method: "aes-128-gcm", Password: "proxy_missing"},
	)
	p.Groups = append(p.Groups, ProxyGroup{Name: "g", Type: "fallback", Nodes: []string{"nope", "sg1", "sg1"}, URL: "https://x.example/\"; rm", Interval: "5 minutes"})
	p.Rules = append(p.Rules,
		ProxyRule{Name: "ai", Outbound: "nowhere"},
		ProxyRule{Name: "bad", Outbound: "auto", Domains: []string{"evil.com/1.2.3.4", "a.com\nserver=/x/1.1.1.1", "ok.com"}, CIDRs: []string{"192.168.1.0/25", "127.0.0.1", "0.0.0.0/0", "fe80::1", "nonsense"}, DomainsFile: "relative.txt"},
	)
	p.Bypass = append(p.Bypass, ProxyDevice{Name: "dup", MAC: "02:c3:06:d6:7f:8a"}, ProxyDevice{Name: "x\ny", MAC: "zz"})
	errs := strings.Join(c.Validate(), "\n")
	for _, s := range []string{
		"proxy.tproxy_port: 1024-65535", "proxy.tproxy_port: port 22 already used by services.ssh.port", "proxy.lan_dns_port: port 1054 already used by proxy.dns_port",
		"proxy.log_level", `"sg1" already used`, `"direct" is reserved`, "nodes[3].server", "nodes[3].port", "nodes[3].method", "nodes[3].password_secret: secret name",
		"nodes[4].password_secret: 2022 methods need a base64 key of 32 bytes", "nodes[5].json_secret: not a JSON object", `secret "proxy_missing" missing`,
		"groups[2].type", `unknown node "nope"`, `"sg1" listed twice`, "groups[2].url", "groups[2].interval",
		`rules[2].name: duplicate "ai"`, `rules[2].outbound`, "rules[2]: needs domains",
		`invalid domain "evil.com/1.2.3.4"`, `invalid domain "a.com\nserver=/x/1.1.1.1"`,
		"192.168.1.0/25 overlaps LAN network", "127.0.0.1 overlaps reserved", "0.0.0.0/0 overlaps", "fe80::1 overlaps reserved", `invalid CIDR/IP "nonsense"`,
		"domains_file: absolute path", "bypass[1].mac: duplicate", "bypass[2].name", `bypass[2].mac: invalid "zz"`,
	} {
		if !strings.Contains(errs, s) {
			t.Errorf("want error %q in:\n%s", s, errs)
		}
	}
	if strings.Contains(errs, "ok.com") {
		t.Error("valid domain rejected")
	}
	c = proxyTestConfig(t)
	c.Proxy.Nodes = nil
	c.Proxy.Groups, c.Proxy.Rules = nil, nil
	if !strings.Contains(strings.Join(c.Validate(), "\n"), "no nodes") {
		t.Error("enabled without nodes accepted")
	}
	// a policy-route mark carrying the proxy bit would be routed to the local stack by the proxy's ip rule
	c = proxyTestConfig(t)
	c.Policy[0].Mark = "0x1000102"
	if !strings.Contains(strings.Join(c.Validate(), "\n"), "policy_routes[0].mark: 0x1000102 sets bit 0x1000000") {
		t.Error("policy mark colliding with the proxy mark accepted")
	}
	c.Proxy.Enabled = false
	if errs := c.Validate(); len(errs) > 0 {
		t.Errorf("the mark is only reserved while the proxy is on: %v", errs)
	}
}

func TestProxyListFileErrors(t *testing.T) {
	c := proxyTestConfig(t)
	bad := filepath.Join(t.TempDir(), "bad.domains")
	os.WriteFile(bad, []byte("good.com\nroot:x:0:0:secret:/root:/bin/sh\n"), 0644)
	c.Proxy.Rules[0].DomainsFile = bad
	_, err := Render(c)
	if err == nil || !strings.Contains(err.Error(), "line 2: not a domain") || strings.Contains(err.Error(), "secret") {
		t.Errorf("want line-numbered error without file content, got %v", err)
	}
	c.Proxy.Rules[0].DomainsFile = "/nonexistent/x.domains"
	if _, err := Render(c); err == nil {
		t.Error("missing list file accepted")
	}
	// the nft hook cannot fail: it skips what it cannot read
	if !strings.Contains(renderNft(c, func(string) bool { return true }), "149.154.160.0/20") {
		t.Error("nft lost the other rules' CIDRs")
	}
}

func TestProxyMerge(t *testing.T) {
	var in []netip.Prefix
	for _, s := range []string{"10.1.0.0/16", "10.0.0.0/8", "10.0.0.0/24", "11.0.0.0/8", "fc00::/18", "fc00::1/128", "2001:db8::/32"} {
		in = append(in, netip.MustParsePrefix(s))
	}
	var out []string
	for _, p := range proxyMerge(in) {
		out = append(out, p.String())
	}
	if strings.Join(out, " ") != "10.0.0.0/8 11.0.0.0/8 2001:db8::/32 fc00::/18" {
		t.Errorf("merge = %v", out)
	}
}

func TestProxyNormalize(t *testing.T) {
	for in, want := range map[string]string{"*.Example.COM.": "example.com", "+.a.b": "a.b", ".c.d": "c.d", "xn--fiqs8s.cn": "xn--fiqs8s.cn", "cn": "cn"} {
		if got, ok := proxyNormDomain(in); !ok || got != want {
			t.Errorf("proxyNormDomain(%q) = %q,%v", in, got, ok)
		}
	}
	for _, bad := range []string{"", "a..b", "-a.com", "a b.com", "a.com/x", "a.com#5353", "例子.com", "a;b"} {
		if _, ok := proxyNormDomain(bad); ok {
			t.Errorf("proxyNormDomain(%q) accepted", bad)
		}
	}
	for in, want := range map[string]string{"1.2.3.4": "1.2.3.4/32", "1.2.3.4/24": "1.2.3.0/24", "2001:db8::1": "2001:db8::1/128"} {
		if got, ok := proxyNormCIDR(in); !ok || got.String() != want {
			t.Errorf("proxyNormCIDR(%q) = %v,%v", in, got, ok)
		}
	}
	for _, bad := range []string{"fe80::1%eth0", "::ffff:1.2.3.4", "1.2.3.4/33", "x"} {
		if _, ok := proxyNormCIDR(bad); ok {
			t.Errorf("proxyNormCIDR(%q) accepted", bad)
		}
	}
}

func TestProxyCheckList(t *testing.T) {
	c := proxyTestConfig(t)
	data, errs := proxyCheckList(c, "domains", "# c\r\n a.com \n\nb.org # x\n")
	if len(errs) > 0 || data != "# c\na.com\n\nb.org # x\n" {
		t.Errorf("clean list: %q %v", data, errs)
	}
	_, errs = proxyCheckList(c, "domains", "ok.com\nbad/x\n")
	if len(errs) != 1 || !strings.Contains(errs[0], "line 2") {
		t.Errorf("errors: %v", errs)
	}
	_, errs = proxyCheckList(c, "cidrs", "1.1.1.0/24\n192.168.1.7\n")
	if len(errs) != 1 || !strings.Contains(errs[0], "LAN") {
		t.Errorf("cidr errors: %v", errs)
	}
	for _, bad := range []string{"../x.domains", "a.txt", "a/b.cidrs", ".domains", "a b.domains"} {
		if reProxyListFile.MatchString(bad) {
			t.Errorf("list file name %q accepted", bad)
		}
	}
}

func TestProxyConfigJSONRoundTrip(t *testing.T) {
	c := proxyTestConfig(t)
	m, err := configToJSON(c)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(m)
	back, _, err := configFromJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !back.Proxy.Enabled || len(back.Proxy.Nodes) != 2 || back.Proxy.Nodes[1].TCPOnly != true || back.Proxy.Rules[1].CIDRs[0] != "149.154.160.0/20" || back.Proxy.Bypass[0].MAC != c.Proxy.Bypass[0].MAC {
		t.Fatalf("round trip lost proxy data: %+v", back.Proxy)
	}
}

func TestClashParse(t *testing.T) {
	code, body, err := clashParse([]byte("HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n{\"version\":\"1.14.1\"}"))
	if err != nil || code != 200 || string(body) != `{"version":"1.14.1"}` {
		t.Fatalf("got %d %q %v", code, body, err)
	}
	if code, _, err := clashParse([]byte("HTTP/1.1 204 No Content\r\n\r\n")); err != nil || code != 204 {
		t.Errorf("204: %d %v", code, err)
	}
	for _, bad := range []string{"", "garbage", "HTTP/1.0 abc\r\n\r\n", "SSH-2.0-x\r\n\r\n", "HTTP/1.0 200 OK\r\n"} {
		if _, _, err := clashParse([]byte(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	p := &Proxy{APIPort: 1}
	if err := clashCall(p, "GET", "/x y", nil, nil, 0); err == nil || !strings.Contains(err.Error(), "bad API path") {
		t.Errorf("path with space not rejected: %v", err)
	}
}

func TestDNSParseA(t *testing.T) {
	// response to id 0x1234: question "a.b" A IN, one CNAME (skipped) and one A 198.18.0.5 (compressed names)
	m := []byte{0x12, 0x34, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0,
		1, 'a', 1, 'b', 0, 0, 1, 0, 1,
		0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 2, 0xc0, 14,
		0xc0, 12, 0, 1, 0, 1, 0, 0, 2, 88, 0, 4, 198, 18, 0, 5}
	ip, rc, err := dnsParseA(m, 0x1234)
	if err != nil || rc != 0 || ip.String() != "198.18.0.5" {
		t.Fatalf("got %v %d %v", ip, rc, err)
	}
	if _, _, err := dnsParseA(m, 0x9999); err == nil {
		t.Error("wrong id accepted")
	}
	if _, _, err := dnsParseA(m[:15], 0x1234); err == nil {
		t.Error("truncated response accepted")
	}
}
