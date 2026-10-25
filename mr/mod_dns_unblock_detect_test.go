package main

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---- helpers --------------------------------------------------------------------------------

func pAns(ips ...string) dnsUnblockProbeResult {
	return dnsUnblockProbeResult{IPs: ips, Latency: 5}
}
func pNX() dnsUnblockProbeResult  { return dnsUnblockProbeResult{RCode: 3, Latency: 5} }
func pErr() dnsUnblockProbeResult { return dnsUnblockProbeResult{Err: "i/o timeout", Latency: 2000} }

// The fake network. Upstream servers are 192.0.2.x, the trusted resolver is 198.51.100.53 and the
// plain interception probe is 1.1.1.1:53; every test only answers for those.
func probeKind(server string) string {
	switch {
	case strings.HasPrefix(server, "192.0.2."):
		return "up"
	case strings.HasPrefix(server, "198.51.100.53:"):
		return "trusted"
	case server == "1.1.1.1:53":
		return "plain"
	}
	return "?"
}

type fakeNet struct {
	up      func(server, domain string) dnsUnblockProbeResult
	trusted func(protocol, domain string) dnsUnblockProbeResult
	plain   func(domain string) dnsUnblockProbeResult
}

func (f fakeNet) install(t *testing.T) {
	t.Helper()
	old := dnsUnblockDetectQuery
	dnsUnblockDetectQuery = func(server, protocol, _, domain string, _ time.Duration) dnsUnblockProbeResult {
		switch probeKind(server) {
		case "up":
			if f.up != nil {
				return f.up(server, domain)
			}
		case "trusted":
			if f.trusted != nil {
				return f.trusted(protocol, domain)
			}
		case "plain":
			if f.plain != nil {
				return f.plain(domain)
			}
		}
		return pErr()
	}
	t.Cleanup(func() { dnsUnblockDetectQuery = old })
}

func detectCfg(t *testing.T, protocol string, servers ...string) *Config {
	t.Helper()
	c := testConfig(t)
	c.DNS.Upstream = "manual"
	if len(servers) == 0 {
		servers = []string{"192.0.2.53"}
	}
	c.DNS.Servers = servers
	c.DNS.Unblock = &DNSUnblock{Enabled: true, Fallback: "custom", Protocol: protocol, Server: "198.51.100.53"}
	c.defaults()
	return c
}

func rowOf(t *testing.T, r dnsUnblockDetectReport, domain string) dnsUnblockDetectRow {
	t.Helper()
	for _, row := range r.Results {
		if row.Domain == domain {
			return row
		}
	}
	t.Fatalf("no row for %s in %#v", domain, r.Results)
	return dnsUnblockDetectRow{}
}

func blockedDomains(r dnsUnblockDetectReport) string {
	var d []string
	for _, b := range r.Blocked {
		d = append(d, b.Domain)
	}
	return strings.Join(d, ",")
}

// ---- reproductions from the review of PR 173 ------------------------------------------------

// A TLS server that accepts the TCP connection and then says nothing (a filtering middlebox) must
// not hang the probe: connect, handshake and exchange all share the per-query deadline.
func TestDetectDoTHandshakeHangHonorsTimeout(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var held []net.Conn
	var mu sync.Mutex
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			held = append(held, c)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		mu.Lock()
		for _, c := range held {
			c.Close()
		}
		mu.Unlock()
	})
	done := make(chan error, 1)
	go func() {
		_, _, err := dnsUnblockQueryTLS(ln.Addr().String(), "example.com", "example.org", 300*time.Millisecond)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a silent server cannot have answered")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("DoT probe is still blocked 10x past its 300 ms deadline (handshake has no timeout)")
	}
}

// 50 domains must be probed concurrently (bounded), not one after another.
func TestDetectRunsDomainsConcurrentlyWithBound(t *testing.T) {
	var inflight, peak int64
	slow := func(r dnsUnblockProbeResult) dnsUnblockProbeResult {
		n := atomic.AddInt64(&inflight, 1)
		for {
			p := atomic.LoadInt64(&peak)
			if n <= p || atomic.CompareAndSwapInt64(&peak, p, n) {
				break
			}
		}
		time.Sleep(40 * time.Millisecond)
		atomic.AddInt64(&inflight, -1)
		return r
	}
	fakeNet{
		up:      func(string, string) dnsUnblockProbeResult { return slow(pAns("198.51.100.10")) },
		trusted: func(string, string) dnsUnblockProbeResult { return slow(pAns("198.51.100.10")) },
		plain:   func(string) dnsUnblockProbeResult { return slow(pAns("198.51.100.10")) },
	}.install(t)
	var extra []string
	for i := 0; i < 20; i++ {
		extra = append(extra, fmt.Sprintf("custom%d.test", i))
	}
	start := time.Now()
	r, err := dnsUnblockDetect(detectCfg(t, "tls"), extra)
	if err != nil {
		t.Fatal(err)
	}
	if got := time.Since(start); got > 2500*time.Millisecond {
		t.Fatalf("%d domains took %v: probes are serial", len(r.Results), got)
	}
	if p := atomic.LoadInt64(&peak); p > 16 {
		t.Fatalf("peak in-flight queries = %d, want a small bound", p)
	}
	if len(r.Results) < 50 {
		t.Fatalf("results = %d, want the 30 built-in + 20 custom", len(r.Results))
	}
}

// Review problem 3: the trusted resolver is unreachable, so nothing can be judged. Two unrelated
// names behind the same CDN address must NOT become "block page" addresses or a recommendation.
func TestDetectTrustedDownGivesNoRecommendation(t *testing.T) {
	fakeNet{
		up: func(_, d string) dnsUnblockProbeResult {
			if d == "cdn-one.test" || d == "cdn-two.test" {
				return pAns("104.21.5.5")
			}
			return pAns("198.51.100.10")
		},
		trusted: func(string, string) dnsUnblockProbeResult { return pErr() },
		plain:   func(string) dnsUnblockProbeResult { return pAns("104.21.5.5") },
	}.install(t)
	r, err := dnsUnblockDetectFor(detectCfg(t, "tls"), []string{"cdn-one.test", "cdn-two.test", "normal.test"})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.BlockIPs) != 0 || len(r.Blocked) != 0 {
		t.Fatalf("judged with no trusted answers: block_ips=%v blocked=%s", r.BlockIPs, blockedDomains(r))
	}
	if r.Recommend.Enable || len(r.Recommend.BlockIPs) != 0 {
		t.Fatalf("recommendation without evidence: %#v", r.Recommend)
	}
}

// Rows whose own trusted query failed take no part in the verdicts, even when other rows work.
func TestDetectFailedTrustedRowsAreNotJudged(t *testing.T) {
	fakeNet{
		up: func(_, d string) dnsUnblockProbeResult {
			switch d {
			case "bad-one.test", "bad-two.test":
				return pAns("203.0.113.99")
			}
			return pAns("198.51.100.10")
		},
		trusted: func(_, d string) dnsUnblockProbeResult {
			switch d {
			case "bad-one.test", "bad-two.test":
				return pErr()
			}
			return pAns("198.51.100.10")
		},
		plain: func(string) dnsUnblockProbeResult { return pAns("198.51.100.10") },
	}.install(t)
	r, _ := dnsUnblockDetectFor(detectCfg(t, "tls"), []string{"bad-one.test", "bad-two.test", "ok-1.test", "ok-2.test", "ok-3.test", "ok-4.test"})
	if len(r.BlockIPs) != 0 {
		t.Fatalf("block_ips inferred from rows whose trusted query failed: %v", r.BlockIPs)
	}
}

// Review problem 5: an upstream timeout/error is not an upstream "no result".
func TestDetectUpstreamErrorIsNotBlocked(t *testing.T) {
	fakeNet{
		up:      func(string, string) dnsUnblockProbeResult { return pErr() },
		trusted: func(string, string) dnsUnblockProbeResult { return pAns("198.51.100.20") },
		plain:   func(string) dnsUnblockProbeResult { return pAns("198.51.100.20") },
	}.install(t)
	r, _ := dnsUnblockDetectFor(detectCfg(t, "tls"), []string{"a.test", "b.test"})
	if len(r.Blocked) != 0 || r.Recommend.Enable {
		t.Fatalf("a dead ISP resolver was reported as blocking: blocked=%s recommend=%#v", blockedDomains(r), r.Recommend)
	}
}

// One SERVFAIL among the built-in list must not make the panel recommend enabling the feature.
func TestDetectSingleOddAnswerDoesNotRecommendEnable(t *testing.T) {
	fakeNet{
		up: func(_, d string) dnsUnblockProbeResult {
			if d == "1xbet.com" {
				return dnsUnblockProbeResult{RCode: 2, Latency: 5}
			}
			return pAns("198.51.100.10")
		},
		trusted: func(string, string) dnsUnblockProbeResult { return pAns("198.51.100.10") },
		plain:   func(string) dnsUnblockProbeResult { return pAns("198.51.100.10") },
	}.install(t)
	r, _ := dnsUnblockDetect(detectCfg(t, "tls"), nil)
	if r.Recommend.Enable {
		t.Fatalf("one odd answer recommended enabling: %#v blocked=%s", r.Recommend, blockedDomains(r))
	}
}

// "Two different registered domains", not two host names; and the trusted resolver must never have
// returned the address for ANY name.
func TestDetectBlockPageNeedsTwoRegisteredDomains(t *testing.T) {
	cases := []struct {
		name    string
		domains []string
		trusted map[string]string // domain -> address the trusted resolver returns
		want    bool
	}{
		{"same registered domain", []string{"shared.test", "www.shared.test"}, map[string]string{"shared.test": "203.0.113.77", "www.shared.test": "203.0.113.78"}, false},
		{"same registered domain under co.uk", []string{"a.shop.co.uk", "b.shop.co.uk"}, map[string]string{"a.shop.co.uk": "203.0.113.77", "b.shop.co.uk": "203.0.113.78"}, false},
		{"two registered domains under co.uk", []string{"x.co.uk", "y.co.uk"}, map[string]string{"x.co.uk": "203.0.113.77", "y.co.uk": "203.0.113.78"}, true},
		{"two unrelated domains", []string{"blocked-a.test", "blocked-b.test"}, map[string]string{"blocked-a.test": "203.0.113.77", "blocked-b.test": "203.0.113.78"}, true},
		{"trusted returned it for another name", []string{"blocked-a.test", "blocked-b.test", "third.test"}, map[string]string{"blocked-a.test": "203.0.113.77", "blocked-b.test": "203.0.113.78", "third.test": "198.0.2.9"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fakeNet{
				up: func(_, d string) dnsUnblockProbeResult {
					if d == "third.test" {
						return pAns("198.0.2.9")
					}
					return pAns("198.18.7.7")
				},
				trusted: func(_, d string) dnsUnblockProbeResult {
					if d == "third.test" {
						return pAns("198.18.7.7") // the "block page" address is a real address of another name
					}
					return pAns(tc.trusted[d])
				},
				plain: func(d string) dnsUnblockProbeResult { return pAns(tc.trusted[d]) },
			}.install(t)
			r, _ := dnsUnblockDetectFor(detectCfg(t, "tls"), tc.domains)
			got := len(r.BlockIPs) == 1 && r.BlockIPs[0] == "198.18.7.7"
			if got != tc.want {
				t.Fatalf("block page address found = %v, want %v (block_ips=%v)", got, tc.want, r.BlockIPs)
			}
		})
	}
}

// Regional CDNs: the ISP resolver (with ECS) and the trusted one return different edges of the same
// network for two unrelated sites; that must not look like a block page.
func TestDetectRegionalCDNEdgeIsNotBlockPage(t *testing.T) {
	fakeNet{
		up:      func(string, string) dnsUnblockProbeResult { return pAns("157.240.15.35") },
		trusted: func(string, string) dnsUnblockProbeResult { return pAns("157.240.22.35") },
		plain:   func(string) dnsUnblockProbeResult { return pAns("157.240.22.35") },
	}.install(t)
	r, _ := dnsUnblockDetectFor(detectCfg(t, "tls"), []string{"cdn-a.test", "cdn-b.test"})
	if len(r.BlockIPs) != 0 || r.Recommend.Enable {
		t.Fatalf("regional CDN edge reported as block page: %v %#v", r.BlockIPs, r.Recommend)
	}
}

// Review problem 6: with protocol: udp configured the trusted answer must still come encrypted,
// otherwise an ISP that hijacks port 53 rewrites the "trusted" answer too.
func TestDetectTrustedIsAlwaysEncrypted(t *testing.T) {
	var plainTrusted int64
	fakeNet{
		up: func(string, string) dnsUnblockProbeResult { return pAns("125.26.170.3") },
		trusted: func(protocol, d string) dnsUnblockProbeResult {
			if protocol == "udp" { // what a port-53 hijacker would answer
				atomic.AddInt64(&plainTrusted, 1)
				return pAns("125.26.170.3")
			}
			return pAns(map[string]string{"blocked-a.test": "203.0.113.1", "blocked-b.test": "203.0.113.2"}[d]) // honest, differs per name
		},
		plain: func(string) dnsUnblockProbeResult { return pAns("125.26.170.3") }, // hijacked
	}.install(t)
	r, _ := dnsUnblockDetectFor(detectCfg(t, "udp"), []string{"blocked-a.test", "blocked-b.test"})
	if n := atomic.LoadInt64(&plainTrusted); n != 0 {
		t.Fatalf("trusted resolver queried in plaintext %d times", n)
	}
	if len(r.Blocked) != 2 || !r.Intercepted {
		t.Fatalf("hijack with protocol: udp not detected: blocked=%s intercepted=%v", blockedDomains(r), r.Intercepted)
	}
	if r.Recommend.Protocol != "tls" {
		t.Fatalf("recommended protocol = %q, want tls", r.Recommend.Protocol)
	}
}

// Review problem 7: NXDOMAIN-style blocking plus a hijacked port 53 (the plaintext probe is empty too).
func TestDetectNXDOMAINBlockWithHijackRecommendsTLS(t *testing.T) {
	fakeNet{
		up:      func(string, string) dnsUnblockProbeResult { return pNX() },
		trusted: func(string, string) dnsUnblockProbeResult { return pAns("198.51.100.20") },
		plain:   func(string) dnsUnblockProbeResult { return pNX() },
	}.install(t)
	r, _ := dnsUnblockDetectFor(detectCfg(t, "tls"), []string{"blocked-a.test", "blocked-b.test"})
	if !r.Intercepted || r.Recommend.Protocol != "tls" {
		t.Fatalf("intercepted=%v protocol=%q, want a detected hijack and tls", r.Intercepted, r.Recommend.Protocol)
	}
}

// udp is only recommended when the plaintext probe demonstrably works and matches the encrypted one.
func TestDetectUDPNotRecommendedWhenPlainProbeFailed(t *testing.T) {
	fakeNet{
		up:      func(string, string) dnsUnblockProbeResult { return pNX() },
		trusted: func(string, string) dnsUnblockProbeResult { return pAns("198.51.100.20") },
		plain:   func(string) dnsUnblockProbeResult { return pErr() },
	}.install(t)
	r, _ := dnsUnblockDetectFor(detectCfg(t, "tls"), []string{"blocked-a.test", "blocked-b.test"})
	if r.Recommend.Protocol == "udp" {
		t.Fatalf("udp recommended although the plain 1.1.1.1 probe never answered: %#v", r.Recommend)
	}
}

// Review problem 8: upstream servers are asked in the configured order; the answer used is the first
// healthy one, never "whoever answered first".
func TestDetectUpstreamOrderIsNotARace(t *testing.T) {
	for _, slow := range []string{"192.0.2.53:53", "192.0.2.54:53"} {
		fakeNet{
			up: func(server, _ string) dnsUnblockProbeResult {
				if server == slow {
					time.Sleep(60 * time.Millisecond)
				}
				if server == "192.0.2.53:53" {
					return pAns("125.26.170.3")
				}
				return pAns("198.51.100.77")
			},
			trusted: func(string, string) dnsUnblockProbeResult { return pAns("198.51.100.77") },
			plain:   func(string) dnsUnblockProbeResult { return pAns("198.51.100.77") },
		}.install(t)
		r, _ := dnsUnblockDetectFor(detectCfg(t, "tls", "192.0.2.53", "192.0.2.54"), []string{"x.test"})
		if got := rowOf(t, r, "x.test").Upstream; len(got) != 1 || got[0] != "125.26.170.3" {
			t.Fatalf("slow=%s: upstream answer = %v, want the first configured server's 125.26.170.3", slow, got)
		}
	}
}

// ---- API / CLI ------------------------------------------------------------------------------

func TestDetectAPIRequiresPOST(t *testing.T) {
	if got := apiDNSUnblockDetect(apiReq{method: "GET", action: "dns.unblock.detect"}); got.status != 405 {
		t.Fatalf("GET status = %d, want 405", got.status)
	}
}

func TestDetectAPIRejectsTooManyOrBadDomains(t *testing.T) {
	var many []string
	for i := 0; i < 21; i++ {
		many = append(many, fmt.Sprintf(`"d%d.test"`, i))
	}
	if got := apiDNSUnblockDetect(apiReq{method: "POST", body: []byte(`{"domains":[` + strings.Join(many, ",") + `]}`)}); got.status != 400 {
		t.Fatalf("21 custom domains: status = %d, want 400", got.status)
	}
	if got := apiDNSUnblockDetect(apiReq{method: "POST", body: []byte(`{"domains":["https://example.com/x"]}`)}); got.status != 400 {
		t.Fatalf("URL as a domain: status = %d, want 400", got.status)
	}
}

func TestDetectTokenScopeIsOperate(t *testing.T) {
	if got := tokenActions["dns.unblock.detect"]; got != "operate" {
		t.Fatalf("token scope of dns.unblock.detect = %q, want operate", got)
	}
}

func TestDetectCLIRejectsTooManyDomains(t *testing.T) {
	fakeNet{}.install(t) // nothing may reach the network from a unit test
	args := []string{"unblock", "detect"}
	for i := 0; i < 21; i++ {
		args = append(args, fmt.Sprintf("d%d.test", i))
	}
	if err := dnsCommand(detectCfg(t, "tls"), args); err == nil || !strings.Contains(err.Error(), "20") {
		t.Fatalf("21 domains on the command line: err = %v", err)
	}
}

// ---- built-in list --------------------------------------------------------------------------

func TestDetectBuiltinListIsSane(t *testing.T) {
	if n := len(dnsUnblockDetectDomains); n != 30 {
		t.Fatalf("built-in list has %d names; the panel text and docs/modules/dns.md say 30", n)
	}
	seen := map[string]bool{}
	for _, d := range dnsUnblockDetectDomains {
		if !validDNSName(d) || strings.ToLower(d) != d {
			t.Errorf("bad built-in name %q", d)
		}
		if seen[d] {
			t.Errorf("duplicate %q", d)
		}
		seen[d] = true
	}
	// one company's brands share CDN addresses; they must not be able to look like "two domains"
	if seen["facebook.com"] && seen["instagram.com"] {
		t.Error("facebook.com and instagram.com are one company (shared edge addresses)")
	}
}
