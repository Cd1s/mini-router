package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDNSUnblockDefaultOffIsEmpty(t *testing.T) {
	c := testConfig(t)
	c.DNS.Unblock = &DNSUnblock{}
	c.defaults()
	got := renderMap(t, c)
	if got[dnsUnblockConf] != "" {
		t.Fatalf("default-off config rendered dns-unblock config: %q", got[dnsUnblockConf])
	}
	if strings.Contains(got[GenDir+"/services"], "mr-dns-unblock") {
		t.Fatal("default-off config enabled mr-dns-unblock")
	}
	if got := dnsUpstreamLines(c); strings.Contains(strings.Join(got, "\n"), "127.0.0.1#5455") {
		t.Fatalf("default-off upstreams unexpectedly use dns-unblock: %v", got)
	}
}

func TestDNSUnblockRenderRulesAndUpstreams(t *testing.T) {
	c := testConfig(t)
	tr, te := true, true
	c.DNS.Unblock = &DNSUnblock{Enabled: true, BlockIPs: []string{"125.26.170.3", "2001:db8::3"}, RetryPrivate: &tr, RetryEmpty: &te, Fallback: "custom", Protocol: "udp", Server: "192.0.2.53#5353", Port: 5455}
	c.DNS.Fallback = []string{"9.9.9.9", "8.8.8.8"}
	c.defaults()
	if errs := c.Validate(); len(errs) > 0 {
		t.Fatal(errs)
	}
	f := renderMap(t, c)
	var got map[string]any
	if err := json.Unmarshal([]byte(f[dnsUnblockConf]), &got); err != nil {
		t.Fatal(err)
	}
	if got["log"].(map[string]any)["level"] != "warn" {
		t.Fatalf("log: %#v", got["log"])
	}
	dns := got["dns"].(map[string]any)
	servers := dns["servers"].([]any)
	if len(servers) != 3 || servers[0].(map[string]any)["tag"] != "isp1" || servers[2].(map[string]any)["tag"] != "trusted" {
		t.Fatalf("servers: %#v", servers)
	}
	rules := dns["rules"].([]any)
	if len(rules) != 9 {
		t.Fatalf("rules length = %d, want 9: %#v", len(rules), rules)
	}
	if rules[0].(map[string]any)["action"] != "evaluate" || rules[0].(map[string]any)["server"] != "isp1" {
		t.Fatalf("first rule: %#v", rules[0])
	}
	if rules[2].(map[string]any)["action"] != "route" || rules[2].(map[string]any)["server"] != "trusted" {
		t.Fatalf("block rule: %#v", rules[1])
	}
	if got["inbounds"].([]any)[0].(map[string]any)["listen_port"] != float64(5455) {
		t.Fatalf("inbound: %#v", got["inbounds"])
	}
	lines := dnsUpstreamLines(c)
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, dnsUnblockUpstreamConf) {
		t.Fatalf("upstream lines: %v", lines)
	}
	if got := dnsUnblockServices(c); len(got) != 1 || got[0] != "mr-dns-unblock" {
		t.Fatalf("services = %v, want mr-dns-unblock", got)
	}
}

func TestDNSUnblockValidation(t *testing.T) {
	c := testConfig(t)
	c.DNS.Unblock = &DNSUnblock{Enabled: true, BlockIPs: []string{"bad", "1.2.3.4\nserver=x"}, Fallback: "custom", Server: "not-an-ip", Port: 53}
	c.DNS.Upstream = "dot"
	c.defaults()
	errs := strings.Join(c.Validate(), "\n")
	for _, want := range []string{"dns.unblock: only valid with dns.upstream: isp or manual", "dns.unblock.block_ips: invalid IP", "dns.unblock.server: ip[#port]", "dns.unblock.port: 1024-65535 and not 53"} {
		if !strings.Contains(errs, want) {
			t.Errorf("missing %q in:\n%s", want, errs)
		}
	}
}

func TestSingBoxVersion(t *testing.T) {
	for _, tc := range []struct {
		v  string
		ok bool
	}{
		{"sing-box version 1.13.2", false},
		{"sing-box version 1.14.0", true},
		{"sing-box version 1.16.1", true},
		{"unknown", false},
	} {
		if got := singBoxVersionOK(tc.v); got != tc.ok {
			t.Errorf("singBoxVersionOK(%q)=%v, want %v", tc.v, got, tc.ok)
		}
	}
}

func TestDNSUnblockInitialServersManualUsesTwo(t *testing.T) {
	c := testConfig(t)
	c.DNS.Upstream = "manual"
	c.DNS.Servers = []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"}
	c.DNS.Unblock = &DNSUnblock{Enabled: true}
	c.defaults()
	got := dnsUnblockInitialServers(c)
	if strings.Join(got, ",") != "1.1.1.1,2.2.2.2" {
		t.Fatalf("manual servers = %v", got)
	}
}

func TestDNSUnblockRefreshCheckAndNoChange(t *testing.T) {
	c := testConfig(t)
	c.DNS.Unblock = &DNSUnblock{Enabled: true, Fallback: "custom", Protocol: "udp", Server: "9.9.9.9"}
	c.defaults()
	d := t.TempDir()
	oldPath, oldRun := dnsUnblockConfigPath, dnsUnblockRun
	dnsUnblockConfigPath = filepath.Join(d, "dns-unblock.json")
	calls := 0
	dnsUnblockRun = func(name string, args ...string) (string, error) { calls++; return "", nil }
	t.Cleanup(func() { dnsUnblockConfigPath, dnsUnblockRun = oldPath, oldRun })
	dnsUnblockRefresh(c, []string{"1.1.1.1"})
	if _, err := os.Stat(dnsUnblockConfigPath); err != nil || calls == 0 {
		t.Fatalf("refresh did not write/check config: err=%v calls=%d", err, calls)
	}
	first := calls
	dnsUnblockRefresh(c, []string{"1.1.1.1"})
	if calls != first {
		t.Fatalf("unchanged refresh called commands: %d -> %d", first, calls)
	}
}
