package main

// dns.unblock: ask an ISP DNS first and retry answers that look like a blocking
// page, private sinkhole, or empty error through a trusted resolver. The helper
// is deliberately a separate sing-box process so dns.split and proxy DNS keep
// their existing behaviour.

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type DNSUnblock struct {
	Enabled      bool     `yaml:"enabled,omitempty"`
	BlockIPs     []string `yaml:"block_ips,omitempty"`
	RetryPrivate *bool    `yaml:"retry_private,omitempty"`
	RetryEmpty   *bool    `yaml:"retry_empty,omitempty"`
	Fallback     string   `yaml:"fallback,omitempty"` // cloudflare | google | quad9 | custom
	Protocol     string   `yaml:"protocol,omitempty"` // udp | tls | https
	Server       string   `yaml:"server,omitempty"`   // custom: ip[#port]
	Port         int      `yaml:"port,omitempty"`     // loopback listener
}

const (
	dnsUnblockConf = GenDir + "/dns-unblock.json"
	dnsUnblockPort = 5455
)

func dnsUnblockDefaults(u *DNSUnblock) {
	if u.Port == 0 {
		u.Port = dnsUnblockPort
	}
	if u.Fallback == "" {
		u.Fallback = "cloudflare"
	}
	if u.Protocol == "" {
		u.Protocol = "tls"
	}
}

func (u DNSUnblock) retryPrivate() bool { return u.RetryPrivate == nil || *u.RetryPrivate }
func (u DNSUnblock) retryEmpty() bool   { return u.RetryEmpty == nil || *u.RetryEmpty }

func dnsUnblockValidate(c *Config, v *Validator) {
	if c.DNS.Unblock == nil {
		return
	}
	u := c.DNS.Unblock
	if !u.Enabled {
		return
	}
	if c.DNS.Upstream == "dot" {
		v.Add("dns.unblock: only valid with dns.upstream: isp or manual")
	} else if c.DNS.Upstream != "isp" && c.DNS.Upstream != "manual" {
		v.Add("dns.unblock: only valid with dns.upstream: isp or manual")
	}
	if len(u.BlockIPs) > 32 {
		v.Add("dns.unblock.block_ips: at most 32 addresses")
	}
	seen := map[string]bool{}
	for _, s := range u.BlockIPs {
		ip := net.ParseIP(s)
		if ip == nil || (ip.To4() == nil && !strings.Contains(s, ":")) {
			v.Add("dns.unblock.block_ips: invalid IP %q", s)
			continue
		}
		key := ip.String()
		if seen[key] {
			v.Add("dns.unblock.block_ips: duplicate %q", s)
		}
		seen[key] = true
	}
	if u.Port < 1 || u.Port > 65535 || u.Port == 53 {
		v.Add("dns.unblock.port: 1-65535 and not 53 (dnsmasq), got %d", u.Port)
	}
	switch u.Fallback {
	case "cloudflare", "google", "quad9":
		if u.Server != "" {
			v.Add("dns.unblock.server: only valid with fallback: custom")
		}
	case "custom":
		if !validServer(u.Server) {
			v.Add("dns.unblock.server: ip[#port], got %q", u.Server)
		}
	default:
		v.Add("dns.unblock.fallback: cloudflare|google|quad9|custom, got %q", u.Fallback)
	}
	if u.Protocol != "udp" && u.Protocol != "tls" && u.Protocol != "https" {
		v.Add("dns.unblock.protocol: udp|tls|https, got %q", u.Protocol)
	}
}

func dnsUnblockResolver(u DNSUnblock) (server, name string, port int) {
	name = ""
	switch u.Fallback {
	case "google":
		server, name, port = "8.8.8.8", "dns.google", 53
	case "quad9":
		server, name, port = "9.9.9.9", "dns.quad9.net", 53
	case "custom":
		server, port = splitServer(u.Server)
		name = server
	default:
		server, name, port = "1.1.1.1", "cloudflare-dns.com", 53
	}
	return
}

func splitServer(s string) (string, int) {
	parts := strings.SplitN(s, "#", 2)
	p := 53
	if len(parts) == 2 {
		p, _ = strconv.Atoi(parts[1])
	}
	return parts[0], p
}

func dnsUnblockServer(tag, server, name string, port int, protocol string) map[string]any {
	o := map[string]any{"type": protocol, "tag": tag, "server": server}
	if port != 53 || protocol != "udp" {
		o["server_port"] = port
	}
	if protocol == "tls" || protocol == "https" {
		o["tls"] = map[string]any{"enabled": true, "server_name": name}
	}
	if protocol == "https" {
		o["path"] = "/dns-query"
	}
	return o
}

func renderDNSUnblockJSON(c *Config, isp []string) (string, error) {
	if c.DNS.Unblock == nil {
		return "", fmt.Errorf("dns.unblock is disabled")
	}
	u := *c.DNS.Unblock
	if len(isp) == 0 {
		return "", fmt.Errorf("no ISP DNS servers")
	}
	servers := make([]any, 0, len(isp)+1)
	for i, s := range isp {
		addr, port := splitServer(s)
		servers = append(servers, dnsUnblockServer("isp"+strconv.Itoa(i+1), addr, "", port, "udp"))
	}
	trusted, name, port := dnsUnblockResolver(u)
	if u.Protocol == "tls" && port == 53 {
		port = 853
	}
	if u.Protocol == "https" && port == 53 {
		port = 443
	}
	servers = append(servers, dnsUnblockServer("trusted", trusted, name, port, u.Protocol))
	rules := make([]any, 0, len(isp)+4)
	for i := range isp {
		rules = append(rules, map[string]any{"action": "evaluate", "server": "isp" + strconv.Itoa(i+1)})
	}
	if len(u.BlockIPs) > 0 {
		rules = append(rules, map[string]any{"match_response": true, "ip_cidr": u.BlockIPs, "action": "route", "server": "trusted"})
	}
	if u.retryPrivate() {
		rules = append(rules, map[string]any{"match_response": true, "ip_is_private": true, "action": "route", "server": "trusted"})
	}
	if u.retryEmpty() {
		rules = append(rules, map[string]any{"match_response": true, "response_rcode": []string{"NXDOMAIN", "REFUSED", "SERVFAIL"}, "action": "route", "server": "trusted"})
		rules = append(rules, map[string]any{"match_response": true, "query_type": []string{"A", "AAAA", "HTTPS"}, "ip_accept_any": true, "invert": true, "action": "route", "server": "trusted"})
	}
	rules = append(rules, map[string]any{"match_response": true, "ip_accept_any": true, "action": "respond"})
	tr := map[string]any{"log": map[string]any{"level": "warn"},
		"dns":      map[string]any{"servers": servers, "rules": rules, "final": "trusted"},
		"inbounds": []any{map[string]any{"type": "direct", "tag": "dns-in", "listen": "127.0.0.1", "listen_port": u.Port}},
		"route":    map[string]any{"rules": []any{map[string]any{"inbound": "dns-in", "action": "hijack-dns"}}, "default_domain_resolver": map[string]any{"server": "trusted"}},
	}
	b, err := json.MarshalIndent(tr, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b) + "\n", nil
}

func dnsUnblockInitialServers(c *Config) []string {
	if c.DNS.Upstream == "manual" {
		out := append([]string{}, c.DNS.Servers...)
		if len(out) > 2 {
			out = out[:2]
		}
		return out
	}
	if c.DNS.Upstream != "isp" {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, w := range sortedWANs(c, wanHealthMap(c)) {
		if w.Proto == "static" {
			for _, s := range w.DNS {
				if validServer(s) && !seen[s] {
					seen[s] = true
					out = append(out, s)
				}
			}
		}
		if l, ok := readLease(w.Name); ok {
			for _, s := range append(l.DNS, l.DNS6...) {
				if net.ParseIP(s) != nil && !seen[s] {
					seen[s] = true
					out = append(out, s)
				}
			}
		}
	}
	if len(out) == 0 && c.DNS.Upstream == "isp" {
		for _, s := range c.DNS.Fallback {
			if net.ParseIP(s) != nil && !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	if len(out) > 2 {
		out = out[:2]
	}
	return out
}

func dnsUnblockRender(c *Config, out *Out) error {
	if c.DNS.Unblock == nil || !c.DNS.Unblock.Enabled || (c.DNS.Upstream != "isp" && c.DNS.Upstream != "manual") {
		return nil
	}
	servers := dnsUnblockInitialServers(c)
	if len(servers) == 0 {
		return nil // WAN hooks will create it once a lease supplies DNS.
	}
	data, err := renderDNSUnblockJSON(c, servers)
	if err != nil {
		return err
	}
	out.Add(dnsUnblockConf, 0600, data)
	return nil
}

var dnsUnblockRun = func(name string, args ...string) (string, error) { return run(name, args...) }

func dnsUnblockRefresh(c *Config, servers []string) {
	if c == nil || c.DNS.Unblock == nil || !c.DNS.Unblock.Enabled || (c.DNS.Upstream != "isp" && c.DNS.Upstream != "manual") || len(servers) == 0 {
		return
	}
	data, err := renderDNSUnblockJSON(c, servers)
	if err != nil || readFile(dnsUnblockConf) == data {
		return
	}
	tmp := dnsUnblockConf + ".tmp"
	if err := writeAtomic(tmp, []byte(data), 0600); err != nil {
		logf("dns-unblock: %v", err)
		return
	}
	if _, err := dnsUnblockRun(singBoxBin, "check", "-c", tmp); err != nil {
		os.Remove(tmp)
		logf("dns-unblock: sing-box check failed: %v", err)
		return
	}
	if err := os.Rename(tmp, dnsUnblockConf); err != nil {
		os.Remove(tmp)
		return
	}
	if _, err := dnsUnblockRun("rc-update", "add", "mr-dns-unblock", "default"); err != nil {
		logf("dns-unblock: enable: %v", err)
	}
	if _, err := dnsUnblockRun("rc-service", "mr-dns-unblock", "restart"); err != nil {
		_, _ = dnsUnblockRun("rc-service", "mr-dns-unblock", "start")
	}
}

func dnsUnblockServices(c *Config) []string {
	if c.DNS.Unblock != nil && c.DNS.Unblock.Enabled && len(dnsUnblockInitialServers(c)) > 0 {
		return []string{"mr-dns-unblock"}
	}
	return nil
}

func dnsUnblockRestart(path string) string {
	if path == dnsUnblockConf {
		return "mr-dns-unblock"
	}
	return ""
}

func dnsUnblockDetectServer(c *Config) (bool, string) {
	if c.DNS.Unblock == nil || !c.DNS.Unblock.Enabled {
		return false, ""
	}
	_, err := os.Stat(singBoxBin)
	if err != nil {
		return false, "sing-box not installed (need >= 1.14.0)"
	}
	out, err := exec.Command(singBoxBin, "version").CombinedOutput()
	if err != nil || !singBoxVersionOK(string(out)) {
		return false, "sing-box >= 1.14.0 required"
	}
	return true, ""
}

func singBoxVersionOK(s string) bool {
	for _, f := range strings.Fields(s) {
		f = strings.TrimPrefix(f, "v")
		parts := strings.SplitN(f, ".", 3)
		if len(parts) < 2 {
			continue
		}
		major, e1 := strconv.Atoi(parts[0])
		minor, e2 := strconv.Atoi(parts[1])
		if e1 == nil && e2 == nil && (major > 1 || major == 1 && minor >= 14) {
			return true
		}
	}
	return false
}

var dnsUnblockResolve = func(addr, name string) error {
	rc, _, err := dnsQuery(addr, name, dnsTypeA, dnsClassIN, 2*time.Second)
	if err != nil {
		return err
	}
	if rc != 0 {
		return fmt.Errorf("answer code %d", rc)
	}
	return nil
}

func dnsUnblockDoctor(c *Config, e *docEnv) []docFinding {
	if c.DNS.Unblock == nil || !c.DNS.Unblock.Enabled {
		return nil
	}
	if ok, detail := dnsUnblockDetectServer(c); !ok {
		return []docFinding{{ID: "dns.unblock.version", Sev: "risk", Title: "DNS unblock", Detail: detail, Fix: "install sing-box 1.14.0 or newer"}}
	}
	if len(dnsUnblockInitialServers(c)) == 0 {
		if _, err := os.Stat(dnsUnblockConf); err != nil {
			return []docFinding{{ID: "dns.unblock", Sev: "skip", Title: "DNS unblock", Detail: "waiting for an ISP DNS lease"}}
		}
	}
	status := e.running([]string{"mr-dns-unblock"})
	if !status["mr-dns-unblock"] {
		return []docFinding{{ID: "dns.unblock.service", Sev: "risk", Title: "DNS unblock", Detail: "mr-dns-unblock is not running", Fix: "mr doctor --heal (or rc-service mr-dns-unblock restart)"}}
	}
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(c.DNS.Unblock.Port))
	if err := dnsUnblockResolve(addr, "example.com"); err != nil {
		return []docFinding{{ID: "dns.unblock.query", Sev: "risk", Title: "DNS unblock", Detail: fmt.Sprintf("%s does not resolve example.com: %s", addr, eventClean(err.Error(), 120)), Fix: "rc-service mr-dns-unblock status; mr dns query example.com  A " + addr}}
	}
	return []docFinding{docOK("DNS unblock", "trusted DNS helper resolves example.com")}
}
