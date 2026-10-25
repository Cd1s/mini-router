package main

// Automatic diagnostics for dns.unblock. Detection is deliberately read-only: it probes the
// current ISP resolvers, the configured trusted resolver (always encrypted) and plain 1.1.1.1, and
// returns a recommendation for the user to review and apply through the normal config flow.
//
// Limits (they are what keeps the web panel usable while a detection runs):
//   - every query has its own 2 s deadline covering connect, TLS handshake and exchange;
//   - the whole run has a hard 11 s deadline; what is not finished is reported as truncated;
//   - at most 8 queries are in flight, at most 20 custom domains, one detection at a time;
//   - a resolver that failed its first 4 queries without a single answer is not asked again.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// The built-in probe names: well-known sites that DNS blocking commonly hits, a few per category.
// docs/modules/dns.md lists the same names (a test keeps them in step). At most one name per company,
// because one company's brands share edge addresses and could look like "one block page, two sites".
var dnsUnblockDetectDomains = []string{
	// gambling
	"1xbet.com", "bet365.com", "betway.com",
	// adult
	"pornhub.com", "xvideos.com", "xhamster.com",
	// torrents / piracy
	"thepiratebay.org", "1337x.to", "nyaa.si", "torrentgalaxy.to", "rutracker.org", "kickass.com",
	// VPN / privacy / messaging
	"vpn.ac", "protonvpn.com", "torproject.org", "signal.org", "telegram.org",
	// social
	"reddit.com", "x.com", "facebook.com", "tiktok.com",
	// news / reference
	"bbc.com", "dw.com", "nytimes.com", "archive.org", "wikipedia.org", "medium.com",
	// public DNS (a blocked DoH/DoT name matters for the trusted resolver)
	"duckduckgo.com", "cloudflare-dns.com", "quad9.net",
}

const (
	dnsDetectMaxCustom   = 20  // custom domains per detection
	dnsDetectWorkers     = 8   // queries in flight
	dnsDetectBreakerFail = 4   // failures without any answer before a resolver is given up on
	dnsDetectMinTrusted  = 0.5 // share of working trusted queries below which nothing is judged
	dnsDetectMaxUpstream = 3   // ISP servers probed (the helper itself uses the first two)
	dnsDetectMaxBody     = 8192
)

var (
	dnsDetectQueryTimeout = 2 * time.Second
	dnsDetectTotalTimeout = 11 * time.Second
	// dnsDetectRootCAs is for tests; nil means the system roots (SSL_CERT_FILE / SSL_CERT_DIR still
	// apply, which is how the lab trusts its own stand-in). Certificates are always verified.
	dnsDetectRootCAs *x509.CertPool
	// dnsUnblockDetectLoad reads the live config for the API (a variable so tests can supply one).
	dnsUnblockDetectLoad = func() (*Config, error) { return loadConfig(ConfigPath, SecretsPath) }
)

var errDetectBusy = errors.New("another DNS unblock detection is running; try again in a few seconds")

type dnsUnblockProbeResult struct {
	RCode   int
	IPs     []string
	Err     string
	Latency int64
	Skip    string // "" = queried; "breaker" = resolver given up on; "deadline" = run out of time
}

func (p dnsUnblockProbeResult) answered() bool { return p.Skip == "" && p.Err == "" }

// worked: the resolver gave a usable answer (the name exists or definitely does not).
func (p dnsUnblockProbeResult) worked() bool {
	return p.answered() && (p.RCode == 0 || p.RCode == 3)
}

type dnsDetectUpstreamResult struct {
	Server    string   `json:"server"`
	IPs       []string `json:"ips"`
	RCode     string   `json:"rcode,omitempty"`
	Error     string   `json:"error,omitempty"`
	LatencyMS int64    `json:"latency_ms"`
}

type dnsUnblockDetectRow struct {
	Domain   string                    `json:"domain"`
	Custom   bool                      `json:"custom,omitempty"`
	Upstream []string                  `json:"upstream"` // the addresses the helper would see (first healthy ISP server)
	Trusted  []string                  `json:"trusted"`
	Plain    []string                  `json:"plain,omitempty"`
	Servers  []dnsDetectUpstreamResult `json:"servers"`
	Kind     string                    `json:"kind"` // ok | block_page | fake_address | empty | error | unknown
	Verdict  string                    `json:"verdict"`
	Reason   string                    `json:"reason,omitempty"`
	Error    string                    `json:"error,omitempty"`

	upMS, trMS, plMS int64
	upOK, plOK       bool
	trWorked         bool
	partial          bool // some query was not made because time ran out: the row is dropped
	chosen           dnsUnblockProbeResult
	trusted          dnsUnblockProbeResult
	plain            dnsUnblockProbeResult
}

type dnsUnblockDetectRecommend struct {
	Enable   bool     `json:"enable"`
	BlockIPs []string `json:"block_ips"`
	Protocol string   `json:"protocol"`
}

type dnsUnblockDetectReport struct {
	Status       string                    `json:"status"` // ok | partial | inconclusive
	Conclusive   bool                      `json:"conclusive"`
	Message      string                    `json:"message,omitempty"`
	Blocked      []dnsUnblockDetectRow     `json:"blocked"`
	BlockIPs     []string                  `json:"block_ips"`
	Intercepted  bool                      `json:"intercepted"`
	Interception string                    `json:"interception"` // yes | no | unknown
	Latency      map[string]int64          `json:"latency"`
	Recommend    dnsUnblockDetectRecommend `json:"recommend"`
	Results      []dnsUnblockDetectRow     `json:"results"`
	Errors       []string                  `json:"errors"`
	Upstreams    []string                  `json:"upstreams"`
	Trusted      string                    `json:"trusted"`
	Total        int                       `json:"total"`
	Probed       int                       `json:"probed"`
	Truncated    bool                      `json:"truncated,omitempty"`
	TrustedTried int                       `json:"trusted_tried"`
	TrustedOK    int                       `json:"trusted_ok"`
}

// The seam is at the DNS transport boundary: tests provide deterministic answers while the CLI, API
// and panel all exercise the same classification code. timeout is the whole budget of one query.
var dnsUnblockDetectQuery = dnsUnblockQueryReal

// ---- input ----------------------------------------------------------------------------------

// dnsDetectCustomDomains validates the user's extra names: DNS names with at least two labels, not
// IP literals, no duplicates, at most dnsDetectMaxCustom. Bad input is an error, never silently dropped.
func dnsDetectCustomDomains(in []string) ([]string, error) {
	builtin := map[string]bool{}
	for _, d := range dnsUnblockDetectDomains {
		builtin[d] = true
	}
	seen := map[string]bool{}
	var out, bad []string
	for _, raw := range in {
		d := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
		if d == "" {
			continue
		}
		labels := strings.Split(d, ".")
		if _, err := strconv.Atoi(labels[len(labels)-1]); !validDNSName(d) || len(labels) < 2 || err == nil {
			bad = append(bad, d)
			continue
		}
		if seen[d] || builtin[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	if len(bad) > 0 {
		if len(bad) > 3 {
			bad = bad[:3]
		}
		return nil, fmt.Errorf("not a domain name: %q (use plain names such as example.com)", bad)
	}
	if len(out) > dnsDetectMaxCustom {
		return nil, fmt.Errorf("at most %d custom domains, got %d", dnsDetectMaxCustom, len(out))
	}
	return out, nil
}

// ---- running a detection --------------------------------------------------------------------

// dnsUnblockDetectLocked runs one detection at a time (a held abstract unix socket, so nothing is
// written to disk and a crashed process cannot leave the lock behind).
func dnsUnblockDetectLocked(c *Config, extra []string) (dnsUnblockDetectReport, error) {
	ln, err := net.Listen("unix", "@mini-router-dns-unblock-detect")
	if err != nil {
		if errors.Is(err, syscall.EADDRINUSE) {
			return dnsUnblockDetectReport{}, errDetectBusy
		}
		// no way to take the lock here: a lone detection is still fine
	} else {
		defer ln.Close()
	}
	return dnsUnblockDetect(c, extra)
}

func dnsUnblockDetect(c *Config, extra []string) (dnsUnblockDetectReport, error) {
	custom, err := dnsDetectCustomDomains(extra)
	if err != nil {
		return dnsUnblockDetectReport{}, err
	}
	return dnsUnblockDetectFor(c, append(append([]string{}, dnsUnblockDetectDomains...), custom...))
}

type dnsDetectGate struct{ ok, fail int32 }

func (g *dnsDetectGate) open() bool {
	return atomic.LoadInt32(&g.ok) > 0 || atomic.LoadInt32(&g.fail) < dnsDetectBreakerFail
}
func (g *dnsDetectGate) note(p dnsUnblockProbeResult) {
	if p.Skip != "" {
		return
	}
	if p.Err == "" {
		atomic.AddInt32(&g.ok, 1)
	} else {
		atomic.AddInt32(&g.fail, 1)
	}
}

type dnsDetectRun struct {
	ctx         context.Context
	deadline    time.Time
	sem         chan struct{}
	upstreams   []string // host:port, config order
	upGates     []*dnsDetectGate
	trusted     string
	trustedName string
	trustedPort int
	trustedProt string
	trGate      dnsDetectGate
	plGate      dnsDetectGate
}

func (rn *dnsDetectRun) q(g *dnsDetectGate, server, protocol, name, domain string) dnsUnblockProbeResult {
	if !g.open() {
		return dnsUnblockProbeResult{Skip: "breaker", Err: "not asked again: no answer from this resolver so far"}
	}
	select {
	case rn.sem <- struct{}{}:
		defer func() { <-rn.sem }()
	case <-rn.ctx.Done():
		return dnsUnblockProbeResult{Skip: "deadline"}
	}
	timeout := dnsDetectQueryTimeout
	if left := time.Until(rn.deadline); left < timeout {
		timeout = left
	}
	if timeout < 20*time.Millisecond {
		return dnsUnblockProbeResult{Skip: "deadline"}
	}
	res := dnsUnblockDetectQuery(server, protocol, name, domain, timeout)
	g.note(res)
	return res
}

func (rn *dnsDetectRun) probe(domain string) dnsUnblockDetectRow {
	row := dnsUnblockDetectRow{Domain: domain}
	ups := make([]dnsUnblockProbeResult, len(rn.upstreams))
	var wg sync.WaitGroup
	for i, s := range rn.upstreams {
		wg.Add(1)
		go func(i int, s string) {
			defer wg.Done()
			ups[i] = rn.q(rn.upGates[i], s, "udp", "", domain)
		}(i, s)
	}
	wg.Add(2)
	go func() {
		defer wg.Done()
		row.trusted = rn.q(&rn.trGate, net.JoinHostPort(rn.trusted, strconv.Itoa(rn.trustedPort)), rn.trustedProt, rn.trustedName, domain)
	}()
	go func() {
		defer wg.Done()
		row.plain = rn.q(&rn.plGate, "1.1.1.1:53", "udp", "", domain)
	}()
	wg.Wait()

	// What the helper would see: the first ISP server (config order) that answers NOERROR, else the
	// first one that answers at all; never "whoever was fastest".
	pick := -1
	for i, u := range ups {
		if u.answered() && u.RCode == 0 {
			pick = i
			break
		}
	}
	if pick < 0 {
		for i, u := range ups {
			if u.answered() {
				pick = i
				break
			}
		}
	}
	for i, u := range ups {
		row.Servers = append(row.Servers, dnsDetectServerView(rn.upstreams[i], u))
	}
	if pick >= 0 {
		row.chosen = ups[pick]
		row.upOK = true
		row.Upstream = append([]string{}, ups[pick].IPs...)
		row.upMS = ups[pick].Latency
	} else if len(ups) > 0 {
		row.chosen = ups[0]
		row.Upstream = []string{}
		row.Error = dnsDetectFirstErr("ISP DNS", ups)
	}
	row.Upstream = append([]string{}, row.Upstream...)
	row.partial = row.trusted.Skip == "deadline" || row.plain.Skip == "deadline"
	for _, u := range ups {
		row.partial = row.partial || u.Skip == "deadline"
	}
	row.trWorked = row.trusted.worked()
	row.Trusted = append([]string{}, row.trusted.IPs...)
	row.trMS = row.trusted.Latency
	row.plOK = row.plain.worked()
	row.Plain = append([]string{}, row.plain.IPs...)
	row.plMS = row.plain.Latency
	if row.Error == "" && !row.trWorked {
		row.Error = dnsDetectFirstErr("可信 DNS", []dnsUnblockProbeResult{row.trusted})
	}
	return row
}

func dnsDetectServerView(server string, p dnsUnblockProbeResult) dnsDetectUpstreamResult {
	v := dnsDetectUpstreamResult{Server: server, IPs: append([]string{}, p.IPs...), LatencyMS: p.Latency}
	switch {
	case p.Skip == "deadline":
		v.Error = "not asked (time ran out)"
	case p.Err != "":
		v.Error = p.Err
	default:
		v.RCode = rcodeName(p.RCode)
	}
	return v
}

func dnsDetectFirstErr(what string, ps []dnsUnblockProbeResult) string {
	for _, p := range ps {
		if p.Err != "" && p.Skip == "" {
			return what + ": " + dnsDetectShort(p.Err)
		}
	}
	for _, p := range ps {
		if p.Skip == "breaker" {
			return what + ": no answer"
		}
	}
	return ""
}

func dnsDetectShort(s string) string {
	if len(s) > 100 {
		return s[:100] + "…"
	}
	return s
}

// dnsDetectUpstreams: the ISP resolvers in the order the helper asks them. A loopback entry is the
// helper itself (or a hand-made one) and would only ever show already-cleaned answers.
func dnsDetectUpstreams(c *Config) []string {
	var out []string
	add := func(s string) {
		host, port := splitServer(s)
		if ip := net.ParseIP(host); ip != nil && !ip.IsLoopback() {
			out = append(out, net.JoinHostPort(host, strconv.Itoa(port)))
		}
	}
	if c.DNS.Upstream == "manual" {
		for _, s := range c.DNS.Servers {
			add(s)
		}
	} else {
		for _, s := range dnsUnblockDirectServers(c) {
			add(s)
		}
		if len(out) == 0 {
			for _, s := range dnsUnblockInitialServers(c) {
				add(s)
			}
		}
	}
	if len(out) > dnsDetectMaxUpstream {
		out = out[:dnsDetectMaxUpstream]
	}
	return out
}

func dnsUnblockDetectFor(c *Config, domains []string) (dnsUnblockDetectReport, error) {
	report := dnsUnblockDetectReport{
		Blocked: []dnsUnblockDetectRow{}, BlockIPs: []string{}, Results: []dnsUnblockDetectRow{}, Errors: []string{},
		Latency:   map[string]int64{"upstream_ms": 0, "trusted_ms": 0, "plain_cf_ms": 0},
		Recommend: dnsUnblockDetectRecommend{BlockIPs: []string{}}, Interception: "unknown",
	}
	if c == nil {
		return report, fmt.Errorf("cannot load router configuration")
	}
	if c.DNS.Upstream != "isp" && c.DNS.Upstream != "manual" {
		return report, fmt.Errorf("dns.unblock detect requires dns.upstream: isp or manual (dot is already encrypted)")
	}
	u := DNSUnblock{}
	if c.DNS.Unblock != nil {
		u = *c.DNS.Unblock
	}
	dnsUnblockDefaults(&u)
	upstreams := dnsDetectUpstreams(c)
	if len(upstreams) == 0 {
		return report, fmt.Errorf("no ISP DNS servers are available to probe; connect a WAN or configure dns.servers")
	}
	host, name, port := dnsUnblockResolver(u)
	// The trusted resolver is always asked encrypted: a provider that hijacks port 53 rewrites plain
	// answers too, which would hide exactly what this is looking for.
	prot := u.Protocol
	if prot != "https" {
		prot = "tls"
	}
	if u.Protocol == "udp" || port == 53 {
		port = map[string]int{"tls": 853, "https": 443}[prot]
	}
	report.Upstreams = upstreams
	report.Trusted = prot + "://" + net.JoinHostPort(host, strconv.Itoa(port))

	builtin := map[string]bool{}
	for _, d := range dnsUnblockDetectDomains {
		builtin[d] = true
	}
	var list []string
	seen := map[string]bool{}
	for _, raw := range domains {
		d := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
		if d != "" && validDNSName(d) && !seen[d] {
			seen[d] = true
			list = append(list, d)
		}
	}
	report.Total = len(list)

	ctx, cancel := context.WithTimeout(context.Background(), dnsDetectTotalTimeout)
	defer cancel()
	rn := &dnsDetectRun{ctx: ctx, deadline: time.Now().Add(dnsDetectTotalTimeout), sem: make(chan struct{}, dnsDetectWorkers),
		upstreams: upstreams, trusted: host, trustedName: name, trustedPort: port, trustedProt: prot}
	for range upstreams {
		rn.upGates = append(rn.upGates, &dnsDetectGate{})
	}
	rows := make([]dnsUnblockDetectRow, len(list))
	done := make([]bool, len(list))
	var next int64
	var wg sync.WaitGroup
	for w := 0; w < dnsDetectWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := int(atomic.AddInt64(&next, 1) - 1)
				if i >= len(list) || ctx.Err() != nil {
					return
				}
				rows[i] = rn.probe(list[i])
				rows[i].Custom = !builtin[list[i]]
				done[i] = !rows[i].partial
			}
		}()
	}
	wg.Wait()
	for i := range rows {
		if done[i] {
			report.Results = append(report.Results, rows[i])
		}
	}
	report.Probed = len(report.Results)
	report.Truncated = report.Probed < report.Total
	dnsDetectJudge(c, u, &report)
	return report, nil
}

// ---- judging --------------------------------------------------------------------------------

func dnsDetectJudge(c *Config, u DNSUnblock, r *dnsUnblockDetectReport) {
	// latency: only queries that were answered
	var sum, n [3]int64
	for _, row := range r.Results {
		if row.upOK {
			sum[0] += row.upMS
			n[0]++
		}
		if row.trusted.answered() {
			sum[1] += row.trMS
			n[1]++
		}
		if row.plain.answered() {
			sum[2] += row.plMS
			n[2]++
		}
	}
	for i, k := range []string{"upstream_ms", "trusted_ms", "plain_cf_ms"} {
		if n[i] > 0 {
			r.Latency[k] = sum[i] / n[i]
		}
	}
	r.Errors = dnsDetectErrorSummary(r)

	upAnswered := 0
	for _, row := range r.Results {
		r.TrustedTried += btoi(row.trusted.Skip != "deadline")
		r.TrustedOK += btoi(row.trWorked)
		upAnswered += btoi(row.upOK)
	}
	configured := map[string]bool{}
	if c.DNS.Unblock != nil {
		for _, s := range c.DNS.Unblock.BlockIPs {
			if ip := net.ParseIP(s); ip != nil {
				configured[ip.String()] = true
			}
		}
	}
	for ip := range configured {
		r.BlockIPs = append(r.BlockIPs, ip)
	}
	sort.Strings(r.BlockIPs)

	switch {
	case r.Probed == 0:
		r.Message = "无法判断：检测超时，没有完成任何一个域名" // i18n-ignore: CLI/API text; the panel composes its own
	case r.TrustedTried == 0 || float64(r.TrustedOK) < dnsDetectMinTrusted*float64(r.TrustedTried):
		r.Message = fmt.Sprintf("无法判断：可信服务器不可用（%d/%d 个加密查询成功）", r.TrustedOK, r.TrustedTried) // i18n-ignore: CLI/API text; the panel composes its own
	case upAnswered == 0:
		r.Message = "无法判断：运营商 DNS 没有应答" // i18n-ignore: CLI/API text; the panel composes its own
	}
	if r.Message != "" {
		r.Status = "inconclusive"
		for i := range r.Results {
			row := &r.Results[i]
			row.Kind, row.Verdict = "unknown", "无法判断"
			if !row.upOK {
				row.Kind, row.Verdict = "error", "错误"
			}
		}
		return
	}
	r.Conclusive = true
	r.Status = "ok"
	if r.Truncated {
		r.Status = "partial"
		r.Message = fmt.Sprintf("检测超时：只完成了 %d/%d 个域名，结果仅供参考", r.Probed, r.Total) // i18n-ignore: CLI/API text; the panel composes its own
	}

	// Every address the trusted resolver returned for any name: such an address is a real server.
	trustedAll := map[string]bool{}
	for _, row := range r.Results {
		if row.trWorked {
			for _, ip := range row.trusted.IPs {
				trustedAll[ip] = true
			}
		}
	}
	// An address the ISP returned for >= 2 different registered domains that the trusted resolver
	// never returned (and is not a neighbour of the trusted answer for the same name: regional CDNs
	// hand out different edges of one network) is a block page.
	cand := map[string]map[string]bool{}
	for _, row := range r.Results {
		if !row.trWorked || !row.upOK {
			continue
		}
		for _, ip := range row.chosen.IPs {
			p := net.ParseIP(ip)
			if p == nil || p.To4() == nil || !dnsDetectPublic(p) || trustedAll[ip] || sameNet16(ip, row.trusted.IPs) {
				continue
			}
			if cand[ip] == nil {
				cand[ip] = map[string]bool{}
			}
			cand[ip][dnsRegisteredDomain(row.Domain)] = true
		}
	}
	detected := map[string]bool{}
	for ip, doms := range cand {
		if len(doms) >= 2 {
			detected[ip] = true
		}
	}

	customBlocked := 0
	for i := range r.Results {
		row := &r.Results[i]
		row.Kind, row.Verdict = "ok", "正常或需人工确认"
		switch {
		case !row.upOK:
			row.Kind, row.Verdict = "error", "错误"
			continue
		case !row.trWorked:
			row.Kind, row.Verdict = "unknown", "无法判断"
			continue
		}
		for _, ip := range row.chosen.IPs {
			if p := net.ParseIP(ip); p != nil && (configured[p.String()] || detected[p.String()]) {
				row.Kind, row.Verdict = "block_page", "屏蔽（屏蔽页地址）"
				row.Reason = "同一地址被多个注册域返回，且可信 DNS 从未返回过它"
				if configured[p.String()] {
					row.Reason = "命中已配置的屏蔽页地址"
				}
				break
			}
		}
		if row.Kind == "ok" {
			for _, ip := range row.chosen.IPs {
				if p := net.ParseIP(ip); p != nil && !dnsDetectPublic(p) && hasPublicIP(row.trusted.IPs) {
					row.Kind, row.Verdict = "fake_address", "屏蔽（假地址）"
					row.Reason = "运营商返回私网/回环地址，可信 DNS 返回公网地址"
					break
				}
			}
		}
		if row.Kind == "ok" && len(row.chosen.IPs) == 0 && len(row.trusted.IPs) > 0 {
			row.Kind, row.Verdict = "empty", "屏蔽（不返回结果）"
			row.Reason = "运营商返回 " + rcodeName(row.chosen.RCode) + " 或没有地址，可信 DNS 有地址"
		}
		if row.Kind != "ok" {
			r.Blocked = append(r.Blocked, *row)
			customBlocked += btoi(row.Custom)
		}
	}
	for ip := range detected {
		configured[ip] = true
	}
	r.BlockIPs = r.BlockIPs[:0]
	for ip := range configured {
		r.BlockIPs = append(r.BlockIPs, ip)
	}
	sort.Strings(r.BlockIPs)

	// Port 53 interception: for the names the ISP blocks, plain 1.1.1.1 repeats the ISP's answer
	// (the same addresses, or the same nothing) instead of what the encrypted trusted resolver says.
	plainAnswered, hijacked := 0, 0
	for _, row := range r.Blocked {
		if !row.plOK {
			continue
		}
		plainAnswered++
		same := sameIPSet(row.plain.IPs, row.chosen.IPs) && !sameIPSet(row.plain.IPs, row.trusted.IPs)
		if same || (len(row.plain.IPs) == 0 && len(row.chosen.IPs) == 0) {
			hijacked++
		}
	}
	plainTried, plainWorked := 0, 0
	for _, row := range r.Results {
		plainTried += btoi(row.plain.Skip != "deadline")
		plainWorked += btoi(row.plOK)
	}
	if plainAnswered > 0 {
		r.Interception = "no"
		if hijacked*2 >= plainAnswered {
			r.Interception = "yes"
		}
	}
	r.Intercepted = r.Interception == "yes"

	r.Recommend.BlockIPs = append([]string{}, r.BlockIPs...)
	r.Recommend.Enable = len(r.Blocked) >= 2 || customBlocked > 0
	base := "tls"
	if u.Protocol == "https" {
		base = "https"
	}
	r.Recommend.Protocol = base
	if r.Interception == "no" && plainWorked > 0 && float64(plainWorked) >= dnsDetectMinTrusted*float64(plainTried) {
		r.Recommend.Protocol = "udp"
	}
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

func dnsDetectErrorSummary(r *dnsUnblockDetectReport) []string {
	count := map[string]int{}
	var order []string
	add := func(who string, p dnsUnblockProbeResult) {
		if p.Err == "" || p.Skip != "" {
			return
		}
		k := who + ": " + dnsDetectShort(p.Err)
		if count[k] == 0 {
			order = append(order, k)
		}
		count[k]++
	}
	for _, row := range r.Results {
		for _, s := range row.Servers {
			if s.Error != "" && !strings.HasPrefix(s.Error, "not ") {
				k := "ISP DNS " + s.Server + ": " + dnsDetectShort(s.Error)
				if count[k] == 0 {
					order = append(order, k)
				}
				count[k]++
			}
		}
		add("trusted "+r.Trusted, row.trusted)
		add("plain 1.1.1.1", row.plain)
	}
	out := []string{}
	for _, k := range order {
		if len(out) == 8 {
			break
		}
		out = append(out, fmt.Sprintf("%s (x%d)", k, count[k]))
	}
	return out
}

func dnsDetectPublic(p net.IP) bool {
	return !p.IsPrivate() && !p.IsLoopback() && !p.IsUnspecified() && !p.IsLinkLocalUnicast() && !p.IsMulticast()
}

func hasPublicIP(ips []string) bool {
	for _, s := range ips {
		if ip := net.ParseIP(s); ip != nil && dnsDetectPublic(ip) {
			return true
		}
	}
	return false
}

func sameNet16(ip string, others []string) bool {
	a := net.ParseIP(ip).To4()
	for _, o := range others {
		if b := net.ParseIP(o).To4(); a != nil && b != nil && a[0] == b[0] && a[1] == b[1] {
			return true
		}
	}
	return false
}

func sameIPSet(a, b []string) bool {
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

// The common two-label public suffixes (a subset of the public suffix list; no new dependency).
// A name under a suffix that is not listed counts as one registered domain too many apart, which can
// only make detection more cautious (e.g. two *.example.com.xx hosts count as one domain "com.xx").
var dnsSecondLevelSuffix = map[string]bool{}

func init() {
	for _, s := range strings.Fields(`co.uk org.uk me.uk ltd.uk plc.uk net.uk sch.uk ac.uk gov.uk
		com.au net.au org.au edu.au gov.au co.nz net.nz org.nz govt.nz
		co.jp ne.jp or.jp ac.jp go.jp co.kr or.kr ne.kr go.kr ac.kr
		com.cn net.cn org.cn gov.cn edu.cn com.hk org.hk net.hk edu.hk com.tw org.tw net.tw
		com.sg edu.sg com.my net.my org.my com.ph com.vn net.vn
		co.th in.th or.th ac.th go.th co.id or.id web.id go.id
		co.in net.in org.in firm.in gen.in ind.in com.pk com.bd com.lk com.np com.kh com.mm
		com.br net.br org.br gov.br com.mx org.mx gob.mx com.ar gob.ar com.co com.pe com.ve com.ec com.uy
		com.tr org.tr net.tr gov.tr com.ua com.ru com.pl com.es com.gr com.pt com.ro com.cy com.mt
		co.za org.za co.ke com.ng com.eg com.sa com.qa com.kw com.om com.jo com.lb co.il org.il co.at or.at`) {
		dnsSecondLevelSuffix[s] = true
	}
}

// dnsRegisteredDomain approximates the registrable domain (eTLD+1): the last two labels, or the last
// three under a known two-label suffix such as co.uk.
func dnsRegisteredDomain(name string) string {
	labels := strings.Split(strings.TrimSuffix(strings.ToLower(name), "."), ".")
	n := len(labels)
	if n <= 2 {
		return strings.Join(labels, ".")
	}
	if dnsSecondLevelSuffix[labels[n-2]+"."+labels[n-1]] {
		return strings.Join(labels[n-3:], ".")
	}
	return strings.Join(labels[n-2:], ".")
}

// ---- transports -----------------------------------------------------------------------------

func dnsUnblockQueryReal(server, protocol, serverName, domain string, timeout time.Duration) dnsUnblockProbeResult {
	start := time.Now()
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
	result := dnsUnblockProbeResult{RCode: rc, Latency: time.Since(start).Milliseconds()}
	if err != nil {
		result.Err = dnsDetectCleanErr(err)
		return result
	}
	for _, rr := range rrs {
		if rr.Type == "A" && net.ParseIP(rr.Data) != nil {
			result.IPs = append(result.IPs, rr.Data)
		}
	}
	return result
}

var dnsDetectNetPrefix = regexp.MustCompile(`^(read|write|dial) (tcp|udp)[46]? \S+: `)

// dnsDetectCleanErr drops the socket addresses (random local ports) from a net error so equal
// failures read, and count, the same: "read tcp 10.0.0.1:41234->1.1.1.1:853: i/o timeout" -> "i/o timeout".
func dnsDetectCleanErr(err error) string {
	return dnsDetectNetPrefix.ReplaceAllString(err.Error(), "")
}

func dnsDetectTLSConfig(serverName string) *tls.Config {
	return &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12, RootCAs: dnsDetectRootCAs}
}

// dnsUnblockQueryPacket sends one DNS-over-TCP framed query on conn and reads the framed answer.
func dnsUnblockQueryPacket(conn net.Conn, domain string, deadline time.Time) (int, []dnsRR, error) {
	var idb [2]byte
	if _, err := rand.Read(idb[:]); err != nil {
		return 0, nil, err
	}
	id := binary.BigEndian.Uint16(idb[:])
	q, err := dnsEncodeQuery(id, domain, dnsTypeA, dnsClassIN)
	if err != nil {
		return 0, nil, err
	}
	conn.SetDeadline(deadline)
	if _, err = conn.Write(append([]byte{byte(len(q) >> 8), byte(len(q))}, q...)); err != nil {
		return 0, nil, err
	}
	head := make([]byte, 2)
	if _, err = io.ReadFull(conn, head); err != nil {
		return 0, nil, err
	}
	n := int(binary.BigEndian.Uint16(head))
	if n < 12 {
		return 0, nil, fmt.Errorf("dns: invalid TLS response length %d", n)
	}
	msg := make([]byte, n)
	if _, err = io.ReadFull(conn, msg); err != nil {
		return 0, nil, err
	}
	return dnsParseResponse(msg, id)
}

// dnsUnblockQueryTLS: DNS over TLS. timeout bounds connect + handshake + exchange together, and the
// certificate is verified against serverName (the host itself when empty).
func dnsUnblockQueryTLS(server, serverName, domain string, timeout time.Duration) (int, []dnsRR, error) {
	deadline := time.Now().Add(timeout)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	if serverName == "" {
		serverName, _, _ = net.SplitHostPort(server)
	}
	d := tls.Dialer{NetDialer: &net.Dialer{}, Config: dnsDetectTLSConfig(serverName)}
	conn, err := d.DialContext(ctx, "tcp", server)
	if err != nil {
		return 0, nil, err
	}
	defer conn.Close()
	return dnsUnblockQueryPacket(conn, domain, deadline)
}

// dnsUnblockQueryHTTPS: DNS over HTTPS (RFC 8484, POST). No proxy, no redirects, no connection reuse.
func dnsUnblockQueryHTTPS(server, serverName, domain string, timeout time.Duration) (int, []dnsRR, error) {
	var idb [2]byte
	if _, err := rand.Read(idb[:]); err != nil {
		return 0, nil, err
	}
	id := binary.BigEndian.Uint16(idb[:])
	q, err := dnsEncodeQuery(id, domain, dnsTypeA, dnsClassIN)
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
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+net.JoinHostPort(host, port)+"/dns-query", bytes.NewReader(q))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	client := &http.Client{
		Timeout:       timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSClientConfig: dnsDetectTLSConfig(serverName),
			TLSHandshakeTimeout: timeout, ResponseHeaderTimeout: timeout},
	}
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
	return dnsParseResponse(body, id)
}

// ---- output ---------------------------------------------------------------------------------

func dnsDetectCell(ips []string, err string) string {
	switch {
	case err != "":
		return "错误"
	case len(ips) == 0:
		return "（空）"
	}
	return strings.Join(ips, ",")
}

func dnsUnblockDetectText(r dnsUnblockDetectReport) []string {
	lines := make([]string, 0, len(r.Results)+8)
	for _, row := range r.Results {
		upErr, trErr := "", ""
		if !row.upOK {
			upErr = "x"
		}
		if !row.trWorked {
			trErr = "x"
		}
		line := fmt.Sprintf("%-30s 运营商=%s 可信=%s 判定=%s", row.Domain, dnsDetectCell(row.Upstream, upErr), dnsDetectCell(row.Trusted, trErr), row.Verdict) // i18n-ignore: CLI/API text; the panel composes its own
		if row.Reason != "" {
			line += "（" + row.Reason + "）"
		} else if row.Error != "" {
			line += "（" + row.Error + "）"
		}
		lines = append(lines, line)
	}
	if r.Message != "" {
		lines = append(lines, "!! "+r.Message)
	}
	if r.Conclusive {
		inter := map[string]string{"yes": "是", "no": "否", "unknown": "未知（没有可比较的屏蔽结果）"}[r.Interception]                                                                                     // i18n-ignore: CLI/API text; the panel composes its own
		lines = append(lines, fmt.Sprintf("明文 1.1.1.1 被劫持：%s；建议启用=%v protocol=%s block_ips=%s", inter, r.Recommend.Enable, r.Recommend.Protocol, strings.Join(r.Recommend.BlockIPs, ","))) // i18n-ignore: CLI/API text; the panel composes its own
	}
	lines = append(lines, fmt.Sprintf("平均延迟：运营商 %d ms，可信（加密）%d ms，明文 1.1.1.1 %d ms；可信服务器 %s", r.Latency["upstream_ms"], r.Latency["trusted_ms"], r.Latency["plain_cf_ms"], r.Trusted)) // i18n-ignore: CLI/API text; the panel composes its own
	for _, e := range r.Errors {
		lines = append(lines, "错误："+e) // i18n-ignore: CLI/API text; the panel composes its own
	}
	return lines
}

func apiDNSUnblockDetect(r apiReq) apiResp {
	if r.method != "POST" {
		return errResp(405, "POST required")
	}
	if len(r.body) > dnsDetectMaxBody {
		return errResp(400, "request too large")
	}
	var in struct {
		Domains []string `json:"domains"`
	}
	if len(r.body) > 0 {
		if err := json.Unmarshal(r.body, &in); err != nil {
			return errResp(400, "bad JSON: %v", err)
		}
	}
	custom, err := dnsDetectCustomDomains(in.Domains)
	if err != nil {
		return errResp(400, "%v", err)
	}
	c, err := dnsUnblockDetectLoad()
	if err != nil {
		return errResp(500, "%v", err)
	}
	report, err := dnsUnblockDetectLocked(c, custom)
	if errors.Is(err, errDetectBusy) {
		return errResp(409, "%v", err)
	}
	if err != nil {
		return errResp(400, "%v", err)
	}
	return apiResp{body: report}
}
