package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// ---- DoT / DoH client against local TLS servers ----------------------------------------------

func testDNSAnswer(q []byte, rcode int, ips ...string) []byte {
	i := 12
	for q[i] != 0 {
		i += int(q[i]) + 1
	}
	i += 5
	resp := append([]byte{}, q[:2]...)
	resp = binary.BigEndian.AppendUint16(resp, 0x8180|uint16(rcode))
	resp = append(resp, 0, 1, byte(len(ips)>>8), byte(len(ips)), 0, 0, 0, 0)
	resp = append(resp, q[12:i]...)
	for _, ip := range ips {
		resp = append(resp, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4)
		resp = append(resp, net.ParseIP(ip).To4()...)
	}
	return resp
}

// testTLS returns a certificate usable for 127.0.0.1 / example.com and the pool that trusts it.
func testTLS(t *testing.T) (*tls.Config, *x509.CertPool) {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.NotFoundHandler())
	srv.StartTLS()
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return &tls.Config{Certificates: srv.TLS.Certificates}, pool
}

func trustPool(t *testing.T, pool *x509.CertPool) {
	t.Helper()
	old := dnsDetectRootCAs
	dnsDetectRootCAs = pool
	t.Cleanup(func() { dnsDetectRootCAs = old })
}

// dotServer answers every query with ips (rcode 0), or stays silent after the handshake when silent.
func dotServer(t *testing.T, cfg *tls.Config, silent bool, ips ...string) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				head := make([]byte, 2)
				if _, err := io.ReadFull(c, head); err != nil {
					return
				}
				q := make([]byte, binary.BigEndian.Uint16(head))
				if _, err := io.ReadFull(c, q); err != nil || silent {
					time.Sleep(3 * time.Second)
					return
				}
				a := testDNSAnswer(q, 0, ips...)
				c.Write(append([]byte{byte(len(a) >> 8), byte(len(a))}, a...))
			}(c)
		}
	}()
	return ln.Addr().String()
}

func TestDetectDoTAnswersAndVerifiesCertificate(t *testing.T) {
	cfg, pool := testTLS(t)
	addr := dotServer(t, cfg, false, "203.0.113.5")

	trustPool(t, pool)
	rc, rrs, err := dnsUnblockQueryTLS(addr, "example.com", "blocked.test", 2*time.Second)
	if err != nil || rc != 0 || len(rrs) != 1 || rrs[0].Data != "203.0.113.5" {
		t.Fatalf("good certificate: rc=%d rrs=%v err=%v", rc, rrs, err)
	}
	// the name must match the certificate
	if _, _, err := dnsUnblockQueryTLS(addr, "not-the-name.test", "blocked.test", 2*time.Second); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("wrong server name accepted: %v", err)
	}
	// and the certificate must chain to a trusted root (no InsecureSkipVerify anywhere)
	dnsDetectRootCAs = nil
	if _, _, err := dnsUnblockQueryTLS(addr, "example.com", "blocked.test", 2*time.Second); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("untrusted certificate accepted: %v", err)
	}
	// through the real transport entry point as well
	if p := dnsUnblockQueryReal(addr, "tls", "example.com", "blocked.test", 2*time.Second); p.Err == "" {
		t.Fatalf("dnsUnblockQueryReal accepted an untrusted certificate: %#v", p)
	}
}

func TestDetectDoTSilentAfterHandshakeHonorsTimeout(t *testing.T) {
	cfg, pool := testTLS(t)
	addr := dotServer(t, cfg, true)
	trustPool(t, pool)
	start := time.Now()
	_, _, err := dnsUnblockQueryTLS(addr, "example.com", "blocked.test", 300*time.Millisecond)
	if err == nil || time.Since(start) > 1500*time.Millisecond {
		t.Fatalf("err=%v after %v", err, time.Since(start))
	}
}

func dohServer(t *testing.T, h http.HandlerFunc) (string, *x509.CertPool) {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return srv.Listener.Addr().String(), pool
}

func TestDetectDoHAnswersAndVerifiesCertificate(t *testing.T) {
	var gotCT, gotMethod string
	addr, pool := dohServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotCT, gotMethod = r.Header.Get("Content-Type"), r.Method
		q, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(testDNSAnswer(q, 0, "198.51.100.9"))
	})
	trustPool(t, pool)
	rc, rrs, err := dnsUnblockQueryHTTPS(addr, "example.com", "blocked.test", 2*time.Second)
	if err != nil || rc != 0 || len(rrs) != 1 || rrs[0].Data != "198.51.100.9" {
		t.Fatalf("rc=%d rrs=%v err=%v", rc, rrs, err)
	}
	if gotMethod != "POST" || gotCT != "application/dns-message" {
		t.Fatalf("request = %s %s", gotMethod, gotCT)
	}
	dnsDetectRootCAs = nil
	if _, _, err := dnsUnblockQueryHTTPS(addr, "example.com", "blocked.test", 2*time.Second); err == nil {
		t.Fatal("untrusted DoH certificate accepted")
	}
}

func TestDetectDoHRefusesRedirectsErrorsAndStalls(t *testing.T) {
	addr, pool := dohServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://127.0.0.1:1/elsewhere", http.StatusFound)
	})
	trustPool(t, pool)
	if _, _, err := dnsUnblockQueryHTTPS(addr, "example.com", "blocked.test", time.Second); err == nil || !strings.Contains(err.Error(), "302") {
		t.Fatalf("redirect: err = %v (must not follow, must fail)", err)
	}

	addr, pool = dohServer(t, func(w http.ResponseWriter, r *http.Request) { http.Error(w, "no", http.StatusBadGateway) })
	trustPool(t, pool)
	if _, _, err := dnsUnblockQueryHTTPS(addr, "example.com", "blocked.test", time.Second); err == nil || !strings.Contains(err.Error(), "502") {
		t.Fatalf("HTTP 502: err = %v", err)
	}

	addr, pool = dohServer(t, func(w http.ResponseWriter, r *http.Request) { time.Sleep(2 * time.Second) })
	trustPool(t, pool)
	start := time.Now()
	if _, _, err := dnsUnblockQueryHTTPS(addr, "example.com", "blocked.test", 300*time.Millisecond); err == nil || time.Since(start) > 1500*time.Millisecond {
		t.Fatalf("stalled DoH: err=%v after %v", err, time.Since(start))
	}
}

// ---- limits of a whole run -------------------------------------------------------------------

func withTimeouts(t *testing.T, total, query time.Duration) {
	t.Helper()
	oldT, oldQ := dnsDetectTotalTimeout, dnsDetectQueryTimeout
	dnsDetectTotalTimeout, dnsDetectQueryTimeout = total, query
	t.Cleanup(func() { dnsDetectTotalTimeout, dnsDetectQueryTimeout = oldT, oldQ })
}

func TestDetectTotalDeadlineReturnsPartialResult(t *testing.T) {
	withTimeouts(t, 500*time.Millisecond, 200*time.Millisecond)
	slow := func(r dnsUnblockProbeResult) dnsUnblockProbeResult { time.Sleep(150 * time.Millisecond); return r }
	fakeNet{
		up:      func(string, string) dnsUnblockProbeResult { return slow(pAns("198.51.100.10")) },
		trusted: func(string, string) dnsUnblockProbeResult { return slow(pAns("198.51.100.10")) },
		plain:   func(string) dnsUnblockProbeResult { return slow(pAns("198.51.100.10")) },
	}.install(t)
	start := time.Now()
	r, err := dnsUnblockDetect(detectCfg(t, "tls"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := time.Since(start); got > 1200*time.Millisecond {
		t.Fatalf("run took %v with a 500 ms budget", got)
	}
	if !r.Truncated || r.Probed >= r.Total || r.Probed == 0 || len(r.Results) != r.Probed {
		t.Fatalf("truncated=%v probed=%d total=%d results=%d", r.Truncated, r.Probed, r.Total, len(r.Results))
	}
	if r.Status != "partial" || !strings.Contains(r.Message, "超时") {
		t.Fatalf("status=%q message=%q", r.Status, r.Message)
	}
}

func TestDetectBlackholedTrustedResolverIsGivenUpOn(t *testing.T) {
	withTimeouts(t, 5*time.Second, 300*time.Millisecond)
	var trustedCalls int64
	fakeNet{
		up: func(string, string) dnsUnblockProbeResult { return pAns("198.51.100.10") },
		trusted: func(string, string) dnsUnblockProbeResult {
			atomic.AddInt64(&trustedCalls, 1)
			time.Sleep(300 * time.Millisecond)
			return pErr()
		},
		plain: func(string) dnsUnblockProbeResult { return pAns("198.51.100.10") },
	}.install(t)
	start := time.Now()
	r, _ := dnsUnblockDetect(detectCfg(t, "tls"), nil)
	if got := time.Since(start); got > 2*time.Second {
		t.Fatalf("a black-holed resolver cost %v", got)
	}
	if n := atomic.LoadInt64(&trustedCalls); n > dnsDetectBreakerFail+dnsDetectWorkers {
		t.Fatalf("trusted resolver was asked %d times", n)
	}
	if r.Status != "inconclusive" || r.Conclusive || !strings.Contains(r.Message, "可信服务器不可用") {
		t.Fatalf("status=%q conclusive=%v message=%q", r.Status, r.Conclusive, r.Message)
	}
	if len(r.Blocked) != 0 || r.Recommend.Enable || len(r.Recommend.BlockIPs) != 0 {
		t.Fatalf("recommendation although nothing could be judged: %#v", r)
	}
	if len(r.Errors) == 0 || !strings.Contains(strings.Join(r.Errors, "\n"), "i/o timeout") {
		t.Fatalf("errors not reported: %v", r.Errors)
	}
}

// ---- the report ------------------------------------------------------------------------------

func TestDetectVerdictKindsAndRecommendation(t *testing.T) {
	c := detectCfg(t, "tls")
	c.DNS.Unblock.BlockIPs = []string{"125.26.170.3"}
	up := map[string]dnsUnblockProbeResult{
		"cfg-block.test": pAns("125.26.170.3"),
		"page-a.test":    pAns("203.0.113.99"),
		"page-b.test":    pAns("203.0.113.99"),
		"fake.test":      pAns("10.1.2.3"),
		"nx.test":        pNX(),
		"up-err.test":    pErr(),
	}
	fakeNet{
		up: func(_, d string) dnsUnblockProbeResult {
			if r, ok := up[d]; ok {
				return r
			}
			return pAns("198.51.100.10")
		},
		trusted: func(_, d string) dnsUnblockProbeResult {
			switch d {
			case "page-a.test":
				return pAns("192.0.2.200")
			case "page-b.test":
				return pAns("192.0.2.201")
			case "fake.test", "nx.test", "cfg-block.test", "up-err.test":
				return pAns("192.0.2.77")
			}
			return pAns("198.51.100.10")
		},
		plain: func(d string) dnsUnblockProbeResult {
			if r, ok := up[d]; ok && d != "up-err.test" {
				return r // plain 1.1.1.1 repeats the ISP: port 53 is hijacked
			}
			return pAns("198.51.100.10")
		},
	}.install(t)
	r, err := dnsUnblockDetectFor(c, []string{"cfg-block.test", "page-a.test", "page-b.test", "fake.test", "nx.test", "up-err.test", "fine.test", "fine2.test"})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][2]string{
		"cfg-block.test": {"block_page", "屏蔽（屏蔽页地址）"},
		"page-a.test":    {"block_page", "屏蔽（屏蔽页地址）"},
		"page-b.test":    {"block_page", "屏蔽（屏蔽页地址）"},
		"fake.test":      {"fake_address", "屏蔽（假地址）"},
		"nx.test":        {"empty", "屏蔽（不返回结果）"},
		"up-err.test":    {"error", "错误"},
		"fine.test":      {"ok", "正常或需人工确认"},
	}
	for d, w := range want {
		if row := rowOf(t, r, d); row.Kind != w[0] || row.Verdict != w[1] {
			t.Errorf("%s: kind=%q verdict=%q, want %q %q", d, row.Kind, row.Verdict, w[0], w[1])
		}
	}
	if got := rowOf(t, r, "cfg-block.test").Reason; got != "命中已配置的屏蔽页地址" {
		t.Errorf("configured address reason = %q", got)
	}
	if rowOf(t, r, "up-err.test").Error == "" {
		t.Error("upstream error not shown on the row")
	}
	if blockedDomains(r) != "cfg-block.test,page-a.test,page-b.test,fake.test,nx.test" {
		t.Errorf("blocked = %s", blockedDomains(r))
	}
	if strings.Join(r.BlockIPs, ",") != "125.26.170.3,203.0.113.99" {
		t.Errorf("block_ips = %v (configured + detected, sorted)", r.BlockIPs)
	}
	if !r.Conclusive || r.Status != "ok" || !r.Recommend.Enable || strings.Join(r.Recommend.BlockIPs, ",") != "125.26.170.3,203.0.113.99" {
		t.Errorf("report = %q conclusive=%v recommend=%#v", r.Status, r.Conclusive, r.Recommend)
	}
	if !r.Intercepted || r.Interception != "yes" || r.Recommend.Protocol != "tls" {
		t.Errorf("interception=%q protocol=%q", r.Interception, r.Recommend.Protocol)
	}
}

func TestDetectNoHijackAndHealthyPlainRecommendsUDP(t *testing.T) {
	fakeNet{
		up:      func(string, string) dnsUnblockProbeResult { return pNX() },
		trusted: func(string, string) dnsUnblockProbeResult { return pAns("198.51.100.20") },
		plain:   func(string) dnsUnblockProbeResult { return pAns("198.51.100.20") },
	}.install(t)
	r, _ := dnsUnblockDetectFor(detectCfg(t, "tls"), []string{"blocked-a.test", "blocked-b.test"})
	if r.Interception != "no" || r.Intercepted || r.Recommend.Protocol != "udp" || !r.Recommend.Enable {
		t.Fatalf("interception=%q recommend=%#v", r.Interception, r.Recommend)
	}
}

func TestDetectLatencyOnlyCountsAnsweredQueries(t *testing.T) {
	fakeNet{
		up: func(string, string) dnsUnblockProbeResult {
			return dnsUnblockProbeResult{IPs: []string{"198.51.100.10"}, Latency: 10}
		},
		trusted: func(_, d string) dnsUnblockProbeResult {
			if d == "slow.test" {
				return dnsUnblockProbeResult{Err: "i/o timeout", Latency: 2000}
			}
			return dnsUnblockProbeResult{IPs: []string{"198.51.100.10"}, Latency: 30}
		},
		plain: func(string) dnsUnblockProbeResult {
			return dnsUnblockProbeResult{IPs: []string{"198.51.100.10"}, Latency: 6}
		},
	}.install(t)
	r, _ := dnsUnblockDetectFor(detectCfg(t, "tls"), []string{"a.test", "b.test", "c.test", "slow.test"})
	if r.Latency["upstream_ms"] != 10 || r.Latency["trusted_ms"] != 30 || r.Latency["plain_cf_ms"] != 6 {
		t.Fatalf("latency = %v (a 2000 ms timeout must not be averaged in)", r.Latency)
	}
}

func TestDetectUpstreamServersAreAskedInConfiguredOrder(t *testing.T) {
	var seen []string
	fakeNet{
		up: func(server, _ string) dnsUnblockProbeResult {
			if server == "192.0.2.53:53" {
				return dnsUnblockProbeResult{RCode: 2, Latency: 4} // SERVFAIL: the helper moves on to the next server
			}
			return pAns("198.51.100.77")
		},
		trusted: func(string, string) dnsUnblockProbeResult { return pAns("198.51.100.77") },
		plain:   func(string) dnsUnblockProbeResult { return pAns("198.51.100.77") },
	}.install(t)
	r, _ := dnsUnblockDetectFor(detectCfg(t, "tls", "192.0.2.53", "192.0.2.54#9953"), []string{"x.test"})
	row := rowOf(t, r, "x.test")
	for _, s := range row.Servers {
		seen = append(seen, s.Server+"="+s.RCode)
	}
	if strings.Join(seen, " ") != "192.0.2.53:53=SERVFAIL 192.0.2.54:9953=NOERROR" {
		t.Fatalf("servers = %v", seen)
	}
	if len(row.Upstream) != 1 || row.Upstream[0] != "198.51.100.77" {
		t.Fatalf("upstream = %v", row.Upstream)
	}
}

func TestDetectLoopbackUpstreamIsNotProbed(t *testing.T) {
	fakeNet{}.install(t)
	c := detectCfg(t, "tls", "127.0.0.1#5455")
	if _, err := dnsUnblockDetectFor(c, []string{"x.test"}); err == nil || !strings.Contains(err.Error(), "no ISP DNS servers") {
		t.Fatalf("the helper itself was accepted as the ISP resolver: %v", err)
	}
}

func TestDetectTrustedTransportFollowsConfiguration(t *testing.T) {
	cases := []struct {
		proto, server, wantProto, wantTarget string
	}{
		{"tls", "198.51.100.53", "tls", "198.51.100.53:853"},
		{"tls", "198.51.100.53#8853", "tls", "198.51.100.53:8853"},
		{"https", "198.51.100.53", "https", "198.51.100.53:443"},
		{"udp", "198.51.100.53", "tls", "198.51.100.53:853"},
		{"udp", "198.51.100.53#5353", "tls", "198.51.100.53:853"},
	}
	for _, tc := range cases {
		var gotProto, gotTarget string
		old := dnsUnblockDetectQuery
		dnsUnblockDetectQuery = func(server, protocol, _, _ string, _ time.Duration) dnsUnblockProbeResult {
			if probeKind(server) == "trusted" {
				gotProto, gotTarget = protocol, server
			}
			return pAns("198.51.100.10")
		}
		c := detectCfg(t, tc.proto)
		c.DNS.Unblock.Server = tc.server
		dnsUnblockDetectFor(c, []string{"x.test"})
		dnsUnblockDetectQuery = old
		if gotProto != tc.wantProto || gotTarget != tc.wantTarget {
			t.Errorf("%s %s: trusted probed with %s %s, want %s %s", tc.proto, tc.server, gotProto, gotTarget, tc.wantProto, tc.wantTarget)
		}
	}
}

// ---- input rules, API ------------------------------------------------------------------------

func TestDetectCustomDomainRules(t *testing.T) {
	ok := func(in ...string) string {
		t.Helper()
		out, err := dnsDetectCustomDomains(in)
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		return strings.Join(out, ",")
	}
	if got := ok(" Example.COM. ", "example.com", "", "b.example.co.uk", "1xbet.com"); got != "example.com,b.example.co.uk" {
		t.Fatalf("normalised = %q (lower-cased, trimmed, de-duplicated, built-in names dropped)", got)
	}
	for _, bad := range []string{"https://example.com/", "example.com:80", "localhost", "192.0.2.1", "a b.com", "-x.com", "a..com", strings.Repeat("a", 64) + ".com", "x\n.com"} {
		if _, err := dnsDetectCustomDomains([]string{bad}); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	var twenty, twentyOne []string
	for i := 0; i < 21; i++ {
		d := "d" + string(rune('a'+i)) + ".test"
		if i < 20 {
			twenty = append(twenty, d)
		}
		twentyOne = append(twentyOne, d)
	}
	if _, err := dnsDetectCustomDomains(twenty); err != nil {
		t.Fatalf("20 allowed: %v", err)
	}
	if _, err := dnsDetectCustomDomains(twentyOne); err == nil {
		t.Fatal("21 accepted")
	}
}

func TestDNSRegisteredDomain(t *testing.T) {
	for in, want := range map[string]string{
		"example.com": "example.com", "www.example.com": "example.com", "a.b.example.com": "example.com",
		"x.co.uk": "x.co.uk", "www.x.co.uk": "x.co.uk", "shop.com.br": "shop.com.br", "a.shop.com.br": "shop.com.br",
		"blocked-a.test": "blocked-a.test", "WWW.Example.Com.": "example.com", "com": "com",
	} {
		if got := dnsRegisteredDomain(in); got != want {
			t.Errorf("%s -> %s, want %s", in, got, want)
		}
	}
}

func stubDetectLoad(t *testing.T, c *Config) {
	t.Helper()
	old := dnsUnblockDetectLoad
	dnsUnblockDetectLoad = func() (*Config, error) { return c, nil }
	t.Cleanup(func() { dnsUnblockDetectLoad = old })
}

func TestDetectAPIReturnsReportWithoutSecrets(t *testing.T) {
	c := detectCfg(t, "tls")
	stubDetectLoad(t, c)
	fakeNet{
		up:      func(string, string) dnsUnblockProbeResult { return pNX() },
		trusted: func(string, string) dnsUnblockProbeResult { return pAns("198.51.100.20") },
		plain:   func(string) dnsUnblockProbeResult { return pNX() },
	}.install(t)
	got := apiDNSUnblockDetect(apiReq{method: "POST", action: "dns.unblock.detect", body: []byte(`{"domains":["blocked-a.test"," Blocked-B.test "]}`)})
	if got.status != 0 && got.status != 200 {
		t.Fatalf("status %d: %v", got.status, got.body)
	}
	rep, ok := got.body.(dnsUnblockDetectReport)
	if !ok {
		t.Fatalf("body is %T", got.body)
	}
	if rep.Total != len(dnsUnblockDetectDomains)+2 {
		t.Fatalf("total = %d: the two custom names were not added to the built-in list", rep.Total)
	}
	b, _ := json.Marshal(rep)
	for _, secret := range []string{"test-pw-not-real", "test-key-123456", "home-token-not-real"} {
		if strings.Contains(string(b), secret) {
			t.Fatalf("report contains a secret: %s", secret)
		}
	}
}

func TestDetectOneAtATime(t *testing.T) {
	stubDetectLoad(t, detectCfg(t, "tls"))
	fakeNet{}.install(t)
	ln, err := net.Listen("unix", "@mini-router-dns-unblock-detect")
	if err != nil {
		t.Skipf("abstract sockets unavailable: %v", err)
	}
	defer ln.Close()
	if got := apiDNSUnblockDetect(apiReq{method: "POST", body: []byte(`{}`)}); got.status != 409 {
		t.Fatalf("second detection while one runs: status %d", got.status)
	}
	if _, err := dnsUnblockDetectLocked(detectCfg(t, "tls"), nil); !errors.Is(err, errDetectBusy) {
		t.Fatalf("CLI path: %v", err)
	}
}

func TestDetectAPIBadBody(t *testing.T) {
	if got := apiDNSUnblockDetect(apiReq{method: "POST", body: []byte(`{"domains":`)}); got.status != 400 {
		t.Fatalf("bad JSON: status %d", got.status)
	}
	if got := apiDNSUnblockDetect(apiReq{method: "POST", body: []byte(`{"domains":["` + strings.Repeat("a", dnsDetectMaxBody) + `.com"]}`)}); got.status != 400 {
		t.Fatalf("huge body: status %d", got.status)
	}
}

func TestDetectRefusesDotUpstream(t *testing.T) {
	c := detectCfg(t, "tls")
	c.DNS.Upstream = "dot"
	if _, err := dnsUnblockDetectFor(c, []string{"x.test"}); err == nil {
		t.Fatal("dot upstream accepted")
	}
}

// ---- docs ------------------------------------------------------------------------------------

func TestDetectBuiltinListIsDocumented(t *testing.T) {
	b, err := os.ReadFile("../docs/modules/dns.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(b)
	for _, d := range dnsUnblockDetectDomains {
		if !strings.Contains(doc, "`"+d+"`") {
			t.Errorf("docs/modules/dns.md does not list the built-in probe name %s", d)
		}
	}
}

func TestDetectErrorTextDropsSocketAddresses(t *testing.T) {
	for in, want := range map[string]string{
		"read tcp 10.9.0.3:39338->10.9.0.3:853: i/o timeout":               "i/o timeout",
		"dial tcp 10.9.0.3:853: connect: connection refused":               "connect: connection refused",
		"write tcp [2001:db8::2]:5->[2001:db8::3]:853: write: broken pipe": "write: broken pipe",
		"read udp 10.0.0.1:5353->192.0.2.53:53: read: connection refused":  "read: connection refused",
		"tls: failed to verify certificate: x509: unknown authority":       "tls: failed to verify certificate: x509: unknown authority",
		"context deadline exceeded":                                        "context deadline exceeded",
	} {
		if got := dnsDetectCleanErr(errors.New(in)); got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}
}
