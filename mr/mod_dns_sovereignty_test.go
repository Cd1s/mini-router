package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The Firefox canary is on by default in both dnsmasq instances; Private Relay is only blocked on
// request; the home config asks for no refusals, so its ruleset has no dns_guard chain.
func TestSovereigntyDnsmasq(t *testing.T) {
	c := testConfig(t)
	conf := renderDnsmasq(c)
	if !strings.Contains(conf, "local=/use-application-dns.net/\n") || strings.Contains(conf, "mask.icloud.com") {
		t.Errorf("home dnsmasq.conf: canary missing or Private Relay blocked:\n%s", conf)
	}
	px, err := proxyDnsmasq(c, nil)
	if err != nil || !strings.Contains(px, "local=/use-application-dns.net/\n") {
		t.Errorf("proxy dnsmasq lacks the canary (%v)", err)
	}
	if nft := renderNft(c, func(string) bool { return true }); strings.Contains(nft, "dns_guard") {
		t.Error("home ruleset has a dns_guard chain it did not ask for")
	}
	off := false
	c.DNS.Sovereignty = DNSSovereignty{FirefoxCanary: &off, PrivateRelay: "block"}
	conf = renderDnsmasq(c)
	if strings.Contains(conf, "use-application-dns") || !strings.Contains(conf, "local=/mask.icloud.com/\nlocal=/mask-h2.icloud.com/\n") {
		t.Errorf("canary off + relay blocked:\n%s", conf)
	}
	if px, _ := proxyDnsmasq(c, nil); !strings.Contains(px, "local=/mask-h2.icloud.com/\n") {
		t.Error("proxy dnsmasq does not block Private Relay")
	}
}

func TestSovereigntyValidate(t *testing.T) {
	c := testConfig(t)
	c.DNS.Sovereignty = DNSSovereignty{PrivateRelay: "maybe", DoHBlocklist: "doh.ips"}
	errs := strings.Join(c.Validate(), "\n")
	for _, want := range []string{"private_relay: allow|block", "doh_blocklist_file: absolute path required"} {
		if !strings.Contains(errs, want) {
			t.Errorf("want %q in:\n%s", want, errs)
		}
	}
	c.DNS.Sovereignty.DoHBlocklist = "/tmp/x\nconf-file=/etc/shadow"
	if !strings.Contains(strings.Join(c.Validate(), "\n"), "doh_blocklist_file: absolute path required") {
		t.Error("a path with a newline accepted")
	}
}

// The blocklist: addresses and CIDRs of both families (an IPv4-mapped one is IPv4), comments; a bad
// line stops the render naming the line but not its content; the nft hook skips instead.
func TestDoHBlocklist(t *testing.T) {
	c := testConfig(t)
	p := filepath.Join(t.TempDir(), "doh.ips")
	os.WriteFile(p, []byte("# resolvers\n8.8.8.8\n1.1.1.0/24 # cloudflare\n2606:4700:4700::1111\n::ffff:9.9.9.9\n2001:db8::/32\n"), 0644)
	c.DNS.Sovereignty = DNSSovereignty{DoHBlocklist: p, BlockDoT: true}
	v4, v6, err := dohBlocklist(c, true)
	if err != nil || len(v4) != 3 || len(v6) != 2 || v4[2].String() != "9.9.9.9/32" || v4[1].String() != "1.1.1.0/24" {
		t.Fatalf("v4 %v v6 %v err %v", v4, v6, err)
	}
	nft := renderNft(c, func(string) bool { return true })
	for _, want := range []string{
		"chain dns_guard {\n\t\ttype filter hook prerouting priority mangle - 1; policy accept;",
		"iifname != { \"br-lan\" } return",
		"tcp dport 853 counter reject with tcp reset",
		"udp dport 853 counter reject",
		"ip daddr @doh4 tcp dport 443 counter reject with tcp reset",
		"ip6 daddr @doh6 udp dport 443 counter reject",
		"1.1.1.0/24",
	} {
		if !strings.Contains(nft, want) {
			t.Errorf("ruleset lacks %q", want)
		}
	}
	os.WriteFile(p, []byte("8.8.8.8\nsecret-token-value\n"), 0644)
	if _, _, err := dohBlocklist(c, true); err == nil || !strings.Contains(err.Error(), "line 2") || strings.Contains(err.Error(), "secret") {
		t.Errorf("bad line: %v", err)
	}
	if v4, _, err := dohBlocklist(c, false); err != nil || len(v4) != 1 {
		t.Errorf("non-strict: %v %v", v4, err)
	}
	if _, err := Render(c); err == nil || !strings.Contains(err.Error(), "doh_blocklist_file") {
		t.Errorf("render with a bad blocklist line: %v", err)
	}
	os.Remove(p)
	if _, _, err := dohBlocklist(c, true); err == nil {
		t.Error("missing file accepted by the render")
	}
	// block_dot alone: the chain, no sets
	c.DNS.Sovereignty.DoHBlocklist = ""
	nft = renderNft(c, func(string) bool { return true })
	if !strings.Contains(nft, "dns: DoT refused") || strings.Contains(nft, "@doh4") {
		t.Error("block_dot alone")
	}
}
