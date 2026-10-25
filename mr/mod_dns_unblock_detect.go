package main

// Automatic diagnostics for dns.unblock. Detection is deliberately read-only: it probes the
// current ISP resolvers, the configured trusted resolver, and plain 1.1.1.1, then returns a
// recommendation for the user to review and apply through the normal config flow.

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

var dnsUnblockDetectDomains = []string{
	"1xbet.com", "bet365.com", "betway.com", "pornhub.com", "xvideos.com", "xhamster.com",
	"thepiratebay.org", "1337x.to", "nyaa.si", "torrentgalaxy.to", "rutracker.org", "kickass.com",
	"vpn.ac", "protonvpn.com", "torproject.org", "signal.org", "telegram.org", "reddit.com",
	"x.com", "facebook.com", "instagram.com", "tiktok.com", "bbc.com", "dw.com", "nytimes.com",
	"archive.org", "duckduckgo.com", "cloudflare-dns.com", "quad9.net", "medium.com",
}

type dnsUnblockProbeResult struct {
	RCode   int
	IPs     []string
	Err     string
	Latency int64
}

type dnsUnblockDetectRow struct {
	Domain     string   `json:"domain"`
	Upstream   []string `json:"upstream"`
	Trusted    []string `json:"trusted"`
	Plain      []string `json:"plain,omitempty"`
	Verdict    string   `json:"verdict"`
	Reason     string   `json:"reason,omitempty"`
	upstreamMS int64
	trustedMS  int64
	plainMS    int64
}

type dnsUnblockDetectRecommend struct {
	Enable   bool     `json:"enable"`
	BlockIPs []string `json:"block_ips"`
	Protocol string   `json:"protocol"`
}

type dnsUnblockDetectReport struct {
	Blocked     []dnsUnblockDetectRow     `json:"blocked"`
	BlockIPs    []string                  `json:"block_ips"`
	Intercepted bool                      `json:"intercepted"`
	Latency     map[string]int64          `json:"latency"`
	Recommend   dnsUnblockDetectRecommend `json:"recommend"`
	Results     []dnsUnblockDetectRow     `json:"results"`
}

// The seam is at the DNS transport boundary: tests can provide deterministic answers while the
// CLI, API and panel all exercise the same classification code.
var dnsUnblockDetectQuery = dnsUnblockQueryReal

func dnsUnblockDetect(c *Config, extra []string) (dnsUnblockDetectReport, error) {
	domains := append([]string{}, dnsUnblockDetectDomains...)
	domains = append(domains, extra...)
	return dnsUnblockDetectFor(c, domains)
}

func dnsUnblockDetectFor(c *Config, domains []string) (dnsUnblockDetectReport, error) {
	var report = dnsUnblockDetectReport{
		Blocked:  []dnsUnblockDetectRow{},
		BlockIPs: []string{},
		Latency:  map[string]int64{"upstream_ms": 0, "trusted_ms": 0, "plain_cf_ms": 0},
		Results:  []dnsUnblockDetectRow{},
	}
	if c == nil {
		return report, fmt.Errorf("cannot load router configuration")
	}
	if c.DNS.Upstream == "dot" {
		return report, fmt.Errorf("dns.unblock detect requires dns.upstream: isp or manual; dot is already encrypted")
	}
	if c.DNS.Upstream != "isp" && c.DNS.Upstream != "manual" {
		return report, fmt.Errorf("dns.unblock detect requires dns.upstream: isp or manual")
	}
	u := DNSUnblock{}
	if c.DNS.Unblock != nil {
		u = *c.DNS.Unblock
	}
	dnsUnblockDefaults(&u)
	servers := dnsUnblockDirectServers(c)
	if len(servers) == 0 {
		servers = dnsUnblockInitialServers(c)
	}
	if len(servers) == 0 {
		return report, fmt.Errorf("no ISP DNS servers are available; connect a WAN or configure dns.servers")
	}
	trusted, trustedName, trustedPort := dnsUnblockResolver(u)
	if u.Protocol == "tls" && trustedPort == 53 {
		trustedPort = 853
	}
	if u.Protocol == "https" && trustedPort == 53 {
		trustedPort = 443
	}
	trustedTarget := dnsDetectTarget(trusted, trustedPort)

	seenDomains := map[string]bool{}
	for _, raw := range domains {
		d := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
		if d == "" || !validDNSName(d) || seenDomains[d] {
			continue
		}
		seenDomains[d] = true
		report.Results = append(report.Results, dnsUnblockDetectOne(d, servers, trustedTarget, trustedName, u.Protocol))
	}
	for _, row := range report.Results {
		report.Latency["upstream_ms"] += row.upstreamMS
		report.Latency["trusted_ms"] += row.trustedMS
		report.Latency["plain_cf_ms"] += row.plainMS
	}
	if n := int64(len(report.Results)); n > 0 {
		for k := range report.Latency {
			report.Latency[k] /= n
		}
	}

	// A CDN can legitimately return a different address in each country. Only an address reused
	// by at least two unrelated names is promoted to a blocking-page candidate.
	count := map[string]int{}
	for _, row := range report.Results {
		for _, ip := range row.Upstream {
			if net.ParseIP(ip) != nil && !dnsDetectContains(row.Trusted, ip) {
				count[ip]++
			}
		}
	}
	blockSet := map[string]bool{}
	if c.DNS.Unblock != nil {
		for _, ip := range c.DNS.Unblock.BlockIPs {
			if net.ParseIP(ip) != nil {
				blockSet[net.ParseIP(ip).String()] = true
			}
		}
	}
	for ip, n := range count {
		if n >= 2 {
			blockSet[ip] = true
		}
	}
	for _, row := range report.Results {
		blocked, reason := dnsUnblockClassifyRow(row, blockSet, count)
		if blocked {
			row.Verdict, row.Reason = "屏蔽", reason
			report.Blocked = append(report.Blocked, row)
		} else if row.Verdict == "" {
			row.Verdict = "正常或需人工确认"
		}
		for i := range report.Results {
			if report.Results[i].Domain == row.Domain {
				report.Results[i] = row
				break
			}
		}
	}
	for ip := range blockSet {
		report.BlockIPs = append(report.BlockIPs, ip)
	}
	sort.Strings(report.BlockIPs)
	report.Intercepted = dnsUnblockDetectIntercepted(report.Results)
	report.Recommend = dnsUnblockMakeRecommend(report)
	return report, nil
}

func dnsUnblockDetectOne(domain string, servers []string, trusted, trustedName, protocol string) dnsUnblockDetectRow {
	row := dnsUnblockDetectRow{Domain: domain, Upstream: []string{}, Trusted: []string{}}
	type answer struct {
		result dnsUnblockProbeResult
		server string
	}
	ch := make(chan answer, len(servers))
	var wg sync.WaitGroup
	for _, s := range servers {
		target := dnsDetectTargetHost(s)
		wg.Add(1)
		go func(server string) {
			defer wg.Done()
			ch <- answer{dnsUnblockDetectQuery(server, "udp", "", domain, 2*time.Second), server}
		}(target)
	}
	go func() { wg.Wait(); close(ch) }()
	var first dnsUnblockProbeResult
	for a := range ch {
		if first.RCode == 0 && len(first.IPs) == 0 && first.Err == "" {
			first = a.result
		}
		if a.result.RCode == 0 && len(a.result.IPs) > 0 {
			first = a.result
			break
		}
	}
	row.Upstream = append(row.Upstream, first.IPs...)
	row.upstreamMS = first.Latency
	trustedResult := dnsUnblockDetectQuery(trusted, protocol, trustedName, domain, 2*time.Second)
	row.Trusted = append(row.Trusted, trustedResult.IPs...)
	row.trustedMS = trustedResult.Latency
	plain := dnsUnblockDetectQuery("1.1.1.1:53", "udp", "", domain, 2*time.Second)
	row.Plain = append(row.Plain, plain.IPs...)
	row.plainMS = plain.Latency
	return row
}

func dnsUnblockClassifyRow(row dnsUnblockDetectRow, blockSet map[string]bool, count map[string]int) (bool, string) {
	for _, ip := range row.Upstream {
		if blockSet[ip] {
			if count[ip] >= 2 {
				return true, "同一地址被多个域名返回，且可信 DNS 未返回"
			}
			return true, "命中配置的屏蔽页地址"
		}
		parsed := net.ParseIP(ip)
		if parsed != nil && (parsed.IsPrivate() || parsed.IsLoopback() || parsed.IsUnspecified()) && hasPublicIP(row.Trusted) {
			return true, "上游返回私网/回环假地址，可信 DNS 返回公网地址"
		}
	}
	if (len(row.Upstream) == 0 || strings.Contains(row.Verdict, "NXDOMAIN")) && len(row.Trusted) > 0 {
		return true, "上游无结果，可信 DNS 有地址"
	}
	return false, ""
}

func dnsUnblockDetectIntercepted(rows []dnsUnblockDetectRow) bool {
	for _, row := range rows {
		if row.Verdict == "屏蔽" && len(row.Upstream) > 0 && sameIPs(row.Upstream, row.Plain) {
			return true
		}
	}
	return false
}

func dnsUnblockMakeRecommend(r dnsUnblockDetectReport) dnsUnblockDetectRecommend {
	return dnsUnblockDetectRecommend{Enable: len(r.Blocked) > 0, BlockIPs: append([]string{}, r.BlockIPs...), Protocol: map[bool]string{true: "tls", false: "udp"}[r.Intercepted]}
}

func hasPublicIP(ips []string) bool {
	for _, s := range ips {
		if ip := net.ParseIP(s); ip != nil && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsUnspecified() {
			return true
		}
	}
	return false
}

func sameIPs(a, b []string) bool {
	if len(a) != len(b) || len(a) == 0 {
		return false
	}
	seen := map[string]bool{}
	for _, ip := range a {
		seen[ip] = true
	}
	for _, ip := range b {
		if !seen[ip] {
			return false
		}
	}
	return true
}

func dnsDetectContains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func dnsDetectTarget(host string, port int) string {
	h, _ := splitServer(host)
	return net.JoinHostPort(h, fmt.Sprint(port))
}

func dnsDetectTargetHost(server string) string {
	h, p := splitServer(server)
	return net.JoinHostPort(h, fmt.Sprint(p))
}

func dnsUnblockQueryReal(server, protocol, serverName, domain string, timeout time.Duration) dnsUnblockProbeResult {
	start := time.Now()
	result := dnsUnblockProbeResult{}
	var rc int
	var rrs []dnsRR
	var err error
	switch protocol {
	case "udp":
		rc, rrs, err = dnsQuery(server, domain, dnsTypeA, dnsClassIN, timeout)
	case "tls":
		rc, rrs, err = dnsUnblockQueryTLS(server, serverName, domain, timeout)
	case "https":
		rc, rrs, err = dnsUnblockQueryHTTPS(server, serverName, domain, timeout)
	default:
		err = fmt.Errorf("unsupported DNS protocol %q", protocol)
	}
	result.RCode, result.Latency = rc, time.Since(start).Milliseconds()
	if err != nil {
		result.Err = err.Error()
		return result
	}
	for _, rr := range rrs {
		if rr.Type == "A" && net.ParseIP(rr.Data) != nil {
			result.IPs = append(result.IPs, rr.Data)
		}
	}
	return result
}

func dnsUnblockQueryPacket(conn net.Conn, domain string, timeout time.Duration) (int, []dnsRR, error) {
	var idb [2]byte
	_, _ = io.ReadFull(bytes.NewReader([]byte{byte(time.Now().UnixNano()), byte(time.Now().UnixNano() >> 8)}), idb[:])
	id := binary.BigEndian.Uint16(idb[:])
	q, err := dnsEncodeQuery(id, domain, dnsTypeA, dnsClassIN)
	if err != nil {
		return 0, nil, err
	}
	conn.SetDeadline(time.Now().Add(timeout))
	if _, err = conn.Write(append([]byte{byte(len(q) >> 8), byte(len(q))}, q...)); err != nil {
		return 0, nil, err
	}
	head := make([]byte, 2)
	if _, err = io.ReadFull(conn, head); err != nil {
		return 0, nil, err
	}
	n := int(binary.BigEndian.Uint16(head))
	if n < 12 || n > 65535 {
		return 0, nil, fmt.Errorf("dns: invalid TLS response length %d", n)
	}
	msg := make([]byte, n)
	if _, err = io.ReadFull(conn, msg); err != nil {
		return 0, nil, err
	}
	return dnsParseResponse(msg, id)
}

func dnsUnblockQueryTLS(server, serverName, domain string, timeout time.Duration) (int, []dnsRR, error) {
	conn, err := net.DialTimeout("tcp", server, timeout)
	if err != nil {
		return 0, nil, err
	}
	defer conn.Close()
	if serverName == "" {
		serverName, _, _ = net.SplitHostPort(server)
	}
	tlsConn := tls.Client(conn, &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12})
	if err := tlsConn.Handshake(); err != nil {
		return 0, nil, err
	}
	defer tlsConn.Close()
	return dnsUnblockQueryPacket(tlsConn, domain, timeout)
}

func dnsUnblockQueryHTTPS(server, serverName, domain string, timeout time.Duration) (int, []dnsRR, error) {
	q, err := dnsEncodeQuery(uint16(time.Now().UnixNano()), domain, dnsTypeA, dnsClassIN)
	if err != nil {
		return 0, nil, err
	}
	host, port, err := net.SplitHostPort(server)
	if err != nil {
		host, port = server, "443"
	}
	if serverName == "" {
		serverName = host
	}
	url := "https://" + net.JoinHostPort(host, port) + "/dns-query"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(q))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	client := &http.Client{Timeout: timeout, Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12}}}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, nil, fmt.Errorf("DoH HTTP %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
	if err != nil {
		return 0, nil, err
	}
	return dnsParseResponse(body, binary.BigEndian.Uint16(q[:2]))
}

func dnsUnblockDetectText(r dnsUnblockDetectReport) []string {
	lines := make([]string, 0, len(r.Results)+2)
	for _, row := range r.Results {
		lines = append(lines, fmt.Sprintf("%-32s 上游=%s 可信=%s 结果=%s", row.Domain, strings.Join(row.Upstream, ","), strings.Join(row.Trusted, ","), row.Verdict))
	}
	lines = append(lines, fmt.Sprintf("明文 1.1.1.1 劫持：%v；建议 protocol=%s，block_ips=%s", r.Intercepted, r.Recommend.Protocol, strings.Join(r.Recommend.BlockIPs, ",")))
	return lines
}

func apiDNSUnblockDetect(r apiReq) apiResp {
	c, err := loadConfig(ConfigPath, SecretsPath)
	if err != nil {
		return errResp(500, "%v", err)
	}
	var in struct {
		Domains []string `json:"domains"`
	}
	if len(r.body) > 0 {
		if err := json.Unmarshal(r.body, &in); err != nil {
			return errResp(400, "bad JSON: %v", err)
		}
	}
	report, err := dnsUnblockDetect(c, in.Domains)
	if err != nil {
		return errResp(400, "%v", err)
	}
	return apiResp{body: report}
}
