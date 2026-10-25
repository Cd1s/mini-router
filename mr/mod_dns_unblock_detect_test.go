package main

import (
	"strings"
	"testing"
	"time"
)

func TestDNSUnblockDetectFindsRepeatedBlockPageAndPrivateSinkhole(t *testing.T) {
	c := testConfig(t)
	c.DNS.Upstream = "manual"
	c.DNS.Servers = []string{"192.0.2.53"}
	c.DNS.Unblock = &DNSUnblock{Enabled: true, Fallback: "custom", Protocol: "tls", Server: "198.51.100.53"}
	c.defaults()
	old := dnsUnblockDetectQuery
	dnsUnblockDetectQuery = func(server, protocol, serverName, domain string, _ time.Duration) dnsUnblockProbeResult {
		if server == "192.0.2.53:53" {
			switch domain {
			case "blocked-one.test", "blocked-two.test":
				return dnsUnblockProbeResult{RCode: 0, IPs: []string{"203.0.113.99"}}
			case "private.test":
				return dnsUnblockProbeResult{RCode: 0, IPs: []string{"10.0.0.7"}}
			case "normal.test":
				return dnsUnblockProbeResult{RCode: 0, IPs: []string{"198.51.100.10"}}
			}
		}
		if server == "198.51.100.53:853" && protocol == "tls" {
			return dnsUnblockProbeResult{RCode: 0, IPs: []string{"198.51.100.20"}}
		}
		if server == "1.1.1.1:53" && serverName == "" {
			return dnsUnblockProbeResult{RCode: 0, IPs: []string{"203.0.113.99"}}
		}
		return dnsUnblockProbeResult{RCode: 3}
	}
	t.Cleanup(func() { dnsUnblockDetectQuery = old })

	got, err := dnsUnblockDetectFor(c, []string{"blocked-one.test", "blocked-two.test", "private.test", "normal.test"})
	if err != nil {
		t.Fatal(err)
	}
	if !got.Intercepted {
		t.Fatalf("plain Cloudflare interception was not detected: %#v", got)
	}
	if len(got.BlockIPs) != 1 || got.BlockIPs[0] != "203.0.113.99" {
		t.Fatalf("block IPs = %v", got.BlockIPs)
	}
	if len(got.Blocked) != 3 {
		t.Fatalf("blocked = %#v, want three domains", got.Blocked)
	}
	if got.Recommend.Protocol != "tls" || !got.Recommend.Enable {
		t.Fatalf("recommendation = %#v", got.Recommend)
	}
	for _, row := range got.Results {
		if row.Domain == "normal.test" && strings.Contains(row.Verdict, "屏蔽") {
			t.Fatalf("single CDN mismatch was falsely blocked: %#v", row)
		}
	}
}

func TestDNSUnblockDetectJSONShape(t *testing.T) {
	c := testConfig(t)
	c.DNS.Upstream = "manual"
	c.DNS.Servers = []string{"192.0.2.53"}
	c.DNS.Unblock = &DNSUnblock{Enabled: true}
	c.defaults()
	old := dnsUnblockDetectQuery
	dnsUnblockDetectQuery = func(_, _, _, _ string, _ time.Duration) dnsUnblockProbeResult { return dnsUnblockProbeResult{RCode: 3} }
	t.Cleanup(func() { dnsUnblockDetectQuery = old })
	got, err := dnsUnblockDetectFor(c, []string{"example.test"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Blocked == nil || got.BlockIPs == nil || got.Latency == nil {
		t.Fatalf("JSON fields must be non-nil: %#v", got)
	}
	if got.Recommend.Enable {
		t.Fatalf("empty detection should not recommend enable: %#v", got.Recommend)
	}
}
