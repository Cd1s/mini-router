package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// domainTestConfig: the home config plus two policy routes by domain (synthetic names and addresses).
// The home config's own policy stays at index 0, so the domain policies are 1 and 2.
func domainTestConfig(t *testing.T) *Config {
	t.Helper()
	c := testConfig(t)
	f := filepath.Join(t.TempDir(), "video.domains")
	os.WriteFile(f, []byte("# comment\nvideo.example.org\n\nstatic.example.com   # below example.com\n+.Img.Example.NET.\n"), 0644)
	c.Policy = append(c.Policy,
		Policy{Name: "video", Domains: []string{"Example.com.", "*.cdn.example.net", "example.com"}, DomainsFile: f, Via: "wan2"},
		Policy{Name: "docs-v4", Src: "192.168.1.240/29", Domains: []string{"docs.example.com"}, Via: "wan"})
	c.defaults()
	return c
}

func TestNetPolicyDomainsRender(t *testing.T) {
	c := domainTestConfig(t)
	mustValid(t, c)
	pds, err := policyDomains(c, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(pds) != 2 || pds[0].idx != 1 || pds[1].idx != 2 {
		t.Fatalf("policyDomains = %+v", pds)
	}
	if got := strings.Join(pds[0].domains, " "); got != "cdn.example.net example.com img.example.net static.example.com video.example.org" {
		t.Errorf("expanded domains: %s", got)
	}
	gen := pds[0].comment()
	if !regexp.MustCompile(`^domains [0-9a-f]{12}$`).MatchString(gen) {
		t.Errorf("set comment %q", gen)
	}

	nft := renderNft(c, allExist)
	wantSubs(t, "nft", nft,
		fmt.Sprintf("\tset pr_1_4 { type ipv4_addr; size 16384; flags dynamic,timeout; timeout 1d; comment %q; }\n", gen),
		fmt.Sprintf("\tset pr_1_6 { type ipv6_addr; size 16384; flags dynamic,timeout; timeout 1d; comment %q; }\n", gen),
		"\tset pr_2_4 { type ipv4_addr;",
		`iifname "br-lan" ip daddr @pr_1_4 ct state new update @pr_1_4 { ip daddr } ct mark set 0x102 meta mark set 0x102 comment "video"`,
		`iifname "br-lan" ip6 daddr @pr_1_6 ct state new update @pr_1_6 { ip6 daddr } ct mark set 0x102 meta mark set 0x102 comment "video"`,
		`iifname "br-lan" ip saddr 192.168.1.240/29 ip daddr @pr_2_4 ct state new update @pr_2_4 { ip daddr } ct mark set 0x200 meta mark set 0x200 comment "docs-v4"`)
	// src decides the family: no IPv6 set / rule for docs-v4; the learned set replaces "not the LAN"
	wantNone(t, "nft", nft, "pr_2_6", `ip daddr != 192.168.1.0/24 ip daddr @pr_`)
	// the connmark restore comes first: a connection keeps the WAN it started on
	if strings.Index(nft, `ct mark != 0x0 meta mark set ct mark return`) > strings.Index(nft, `comment "video"`) {
		t.Error("restore must precede the domain rules")
	}

	f := renderMap(t, c)
	conf := f["/etc/dnsmasq.conf"]
	wantSubs(t, "dnsmasq.conf", conf,
		"# policy_routes domains -> nft sets (route by domain)\n",
		"nftset=/cdn.example.net/example.com/img.example.net/static.example.com/video.example.org/4#inet#mr#pr_1_4,6#inet#mr#pr_1_6\n",
		// dnsmasq uses only the most specific line: a subdomain listed by another policy names the parent's sets too
		"nftset=/docs.example.com/4#inet#mr#pr_1_4,6#inet#mr#pr_1_6,4#inet#mr#pr_2_4\n")
	if n := strings.Count(conf, "nftset="); n != 2 {
		t.Errorf("dnsmasq.conf: %d nftset lines", n)
	}

	// the set comment follows the domain list, not its order or spelling
	c2 := domainTestConfig(t)
	c2.Policy[1].Domains = []string{"example.com", "cdn.example.net"}
	if p2, _ := policyDomains(c2, true); p2[0].comment() != gen {
		t.Error("same domains, other order: comment changed")
	}
	c2.Policy[1].Domains = append(c2.Policy[1].Domains, "new.example")
	if p2, _ := policyDomains(c2, true); p2[0].comment() == gen {
		t.Error("domain added: comment unchanged (old addresses would be carried over)")
	}
}

// Without domains nothing changes: the home config renders no nftset line and no domain set.
func TestNetPolicyDomainsOff(t *testing.T) {
	c := testConfig(t)
	f := renderMap(t, c)
	wantNone(t, "dnsmasq.conf", f["/etc/dnsmasq.conf"], "nftset", "policy_routes")
	wantNone(t, "nft", renderNft(c, allExist), "pr_0", "update @")
	if s := policyDomainCarry(c); s != "" {
		t.Errorf("carry without domain policies: %q", s)
	}
}

func TestNetPolicyDomainsValidation(t *testing.T) {
	cases := []struct {
		name string
		mod  func(c *Config)
		want string
	}{
		{"domain-space", func(c *Config) { c.Policy[1].Domains = []string{"exa mple.com"} }, `domains: invalid domain "exa mple.com"`},
		{"domain-slash", func(c *Config) { c.Policy[1].Domains = []string{"a.com/4#inet#mr#x"} }, "domains: invalid domain"},
		{"domain-quote", func(c *Config) { c.Policy[1].Domains = []string{`a.com"`} }, "domains: invalid domain"},
		{"domain-newline", func(c *Config) { c.Policy[1].Domains = []string{"a.com\nserver=1.2.3.4"} }, "domains: invalid domain"},
		{"domain-empty", func(c *Config) { c.Policy[1].Domains = []string{"*."} }, "domains: invalid domain"},
		{"file-relative", func(c *Config) { c.Policy[1].DomainsFile = "video.domains" }, "domains_file: absolute path required"},
		{"file-inject", func(c *Config) { c.Policy[1].DomainsFile = "/tmp/x\nnftset=/a/b" }, "domains_file: absolute path required"},
		{"too-many", func(c *Config) {
			for i := 0; i < policyDomainMax; i++ {
				c.Policy = append(c.Policy, Policy{Name: fmt.Sprintf("d%d", i), Domains: []string{"example.org"}, Via: "wan"})
			}
		}, "at most 16 routes with domains"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := domainTestConfig(t)
			tc.mod(c)
			errs := strings.Join(c.Validate(), "\n")
			if !strings.Contains(errs, tc.want) {
				t.Errorf("want error %q, got:\n%s", tc.want, errs)
			}
		})
	}
	// domains alone are a selector
	c := domainTestConfig(t)
	c.Policy[1].DomainsFile = ""
	mustValid(t, c)
}

// A domains_file that cannot be used stops the render (and names the line, not its content); the
// nft / dnsmasq renderers keep the policy's sets, so its rule never matches every destination.
func TestNetPolicyDomainsFileErrors(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.domains")
	os.WriteFile(bad, []byte("ok.example\nsecret value here\n"), 0644)
	empty := filepath.Join(dir, "empty.domains")
	os.WriteFile(empty, []byte("# nothing yet\n"), 0644)
	for _, tc := range []struct{ file, want string }{
		{filepath.Join(dir, "missing.domains"), "domains_file:"},
		{bad, "bad.domains line 2: not a domain"},
		{empty, "no domains"},
	} {
		c := domainTestConfig(t)
		c.Policy[1].Domains = nil
		c.Policy[1].DomainsFile = tc.file
		mustValid(t, c)
		_, err := Render(c)
		if err == nil || !strings.Contains(err.Error(), tc.want) || strings.Contains(err.Error(), "secret") {
			t.Errorf("%s: render error %v, want %q", filepath.Base(tc.file), err, tc.want)
		}
		nft := renderNft(c, allExist)
		wantSubs(t, "nft ("+filepath.Base(tc.file)+")", nft, "set pr_1_4 {", `ip daddr @pr_1_4 ct state new`)
		wantNone(t, "nft ("+filepath.Base(tc.file)+")", nft, `ip daddr != 192.168.1.0/24 ct state new ct mark set 0x102 meta mark set 0x102 comment "video"`)
	}
}

// Long lists share lines, every line stays below dnsmasq's 1024-byte limit and names each domain once.
func TestNetPolicyDomainsLongList(t *testing.T) {
	c := domainTestConfig(t)
	var ds []string
	for i := 0; i < 300; i++ {
		ds = append(ds, fmt.Sprintf("host-%03d.long-list.example.org", i))
	}
	c.Policy[1] = Policy{Name: "video", Domains: ds, Via: "wan2"}
	mustValid(t, c)
	lines := policyNftsetLines(c, nil)
	seen := map[string]int{}
	for _, l := range lines {
		if len(l) >= 1000 {
			t.Errorf("line of %d bytes", len(l))
		}
		if !strings.HasPrefix(l, "nftset=/") {
			t.Errorf("line %q", l)
		}
		parts := strings.Split(strings.TrimPrefix(l, "nftset=/"), "/")
		for _, d := range parts[:len(parts)-1] {
			seen[d]++
		}
	}
	if len(lines) < 10 || len(seen) != 300+1 { // + docs.example.com of docs-v4
		t.Errorf("%d lines, %d domains", len(lines), len(seen))
	}
	for d, n := range seen {
		if n != 1 {
			t.Errorf("%s on %d lines", d, n)
		}
	}
}

// The proxy's dnsmasq fills the same sets, except for names it answers with fake IPs.
func TestNetPolicyDomainsProxyDNS(t *testing.T) {
	c := proxyTestConfig(t)
	c.Policy = append(c.Policy, Policy{Name: "video", Domains: []string{"video.example.org", "claude.ai", "openai.com"}, Via: "wan2"})
	c.defaults()
	mustValid(t, c)
	f := renderMap(t, c)
	line := "nftset=/claude.ai/openai.com/video.example.org/4#inet#mr#pr_1_4,6#inet#mr#pr_1_6\n"
	wantSubs(t, "dnsmasq.conf", f["/etc/dnsmasq.conf"], line)
	wantSubs(t, "proxy-dns.conf", f[proxyGenDNS], "nftset=/video.example.org/4#inet#mr#pr_1_4,6#inet#mr#pr_1_6\n")
	wantNone(t, "proxy-dns.conf", f[proxyGenDNS], "nftset=/claude.ai", "/openai.com/4#")
}

func TestNetPolicyDomainsCarry(t *testing.T) {
	js := func(comment string) []byte {
		return []byte(`{"nftables": [{"metainfo": {"version": "1.1.6"}}, {"set": {"family": "inet", "name": "pr_1_4", "table": "mr",
		  "type": "ipv4_addr", "handle": 9, "comment": "` + comment + `", "size": 16384, "flags": ["timeout", "dynamic"], "timeout": 86400,
		  "elem": [{"elem": {"val": "192.0.2.80", "expires": 86000}}, {"elem": {"val": "192.0.2.81", "timeout": 3600, "expires": 100}},
		    {"elem": {"val": "2001:db8::1", "expires": 50}}, {"elem": {"val": "192.0.2.9 } ; flush ruleset ; add element inet mr x {", "expires": 9}},
		    {"elem": {"val": "192.0.2.82"}}, "192.0.2.83"]}}]}`)
	}
	want := "add element inet mr pr_1_4 { 192.0.2.80 timeout 86000s, 192.0.2.81 timeout 100s }\n"
	if got := policyCarryScript("pr_1_4", 4, "domains abc", js("domains abc")); got != want {
		t.Errorf("same list:\n%q\nwant\n%q", got, want)
	}
	if got := policyCarryScript("pr_1_4", 4, "domains abc", js("domains def")); got != "" {
		t.Errorf("changed list must start empty, got %q", got)
	}
	if got := policyCarryScript("pr_1_4", 4, "domains abc", []byte(`{"nftables": [{"set": {"name": "pr_1_4", "comment": "domains abc"}}]}`)); got != "" {
		t.Errorf("empty set: %q", got)
	}
	if got := policyCarryScript("pr_1_4", 4, "domains abc", []byte("Error: No such file or directory")); got != "" {
		t.Errorf("no set: %q", got)
	}
}
