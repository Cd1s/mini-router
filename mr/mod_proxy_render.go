package main

// proxy module: generated files (sing-box.json, proxy-dns.conf), network.sh fragment, nftables.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// proxyRuleSet is one rule with its inline entries and list files expanded and normalized.
type proxyRuleSet struct {
	Rule    ProxyRule
	Domains []string
	CIDRs   []netip.Prefix
}

// proxyLANNets: the LAN-side networks whose clients are proxied (firewall zone "lan"; guest-zone
// networks keep using the main dnsmasq and are never proxied).
func proxyLANNets(c *Config) []LANNet {
	var out []LANNet
	for _, n := range c.LANNets() {
		if n.Zone == "lan" {
			out = append(out, n)
		}
	}
	return out
}

func proxyBridges(c *Config) []string {
	var out []string
	for _, n := range proxyLANNets(c) {
		out = append(out, n.Bridge)
	}
	return out
}

func (p *Proxy) ipv6() bool { return !p.IPv4Only }

// proxyReadList returns the non-comment lines of a list file with their line numbers.
func proxyReadList(path string) ([]string, []int, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	var lines []string
	var nums []int
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		t := strings.TrimSpace(sc.Text())
		if i := strings.IndexByte(t, '#'); i >= 0 {
			t = strings.TrimSpace(t[:i])
		}
		if t != "" {
			lines = append(lines, t)
			nums = append(nums, n)
		}
	}
	return lines, nums, sc.Err()
}

// proxyLoad expands every rule. strict (render): any unreadable file or bad line is an error.
// Non-strict (nftables hook, which cannot fail): skip what cannot be used.
// Error messages name the file and line but never echo file content.
func proxyLoad(c *Config, strict bool) ([]proxyRuleSet, error) {
	var out []proxyRuleSet
	for i, r := range c.Proxy.Rules {
		rs := proxyRuleSet{Rule: r}
		where := fmt.Sprintf("proxy.rules[%d] (%s)", i, r.Name)
		seenD := map[string]bool{}
		addD := func(d string) {
			if !seenD[d] {
				seenD[d] = true
				rs.Domains = append(rs.Domains, d)
			}
		}
		seenC := map[netip.Prefix]bool{}
		addC := func(p netip.Prefix) {
			if !seenC[p] {
				seenC[p] = true
				rs.CIDRs = append(rs.CIDRs, p)
			}
		}
		for _, d := range r.Domains {
			if n, ok := proxyNormDomain(d); ok {
				addD(n)
			} else if strict {
				return nil, fmt.Errorf("%s: invalid domain %q", where, d)
			}
		}
		for _, s := range r.CIDRs {
			if p, ok := proxyNormCIDR(s); ok && proxyCIDRProblem(c, p) == "" {
				addC(p)
			} else if strict {
				return nil, fmt.Errorf("%s: CIDR %q not allowed", where, s)
			}
		}
		if r.DomainsFile != "" {
			lines, nums, err := proxyReadList(r.DomainsFile)
			if err != nil && strict {
				return nil, fmt.Errorf("%s: domains_file: %v", where, err)
			}
			for k, l := range lines {
				if n, ok := proxyNormDomain(l); ok {
					addD(n)
				} else if strict {
					return nil, fmt.Errorf("%s: %s line %d: not a domain", where, r.DomainsFile, nums[k])
				}
			}
		}
		if r.CIDRFile != "" {
			lines, nums, err := proxyReadList(r.CIDRFile)
			if err != nil && strict {
				return nil, fmt.Errorf("%s: cidr_file: %v", where, err)
			}
			for k, l := range lines {
				p, ok := proxyNormCIDR(l)
				msg := "not a CIDR or IP address"
				if ok {
					msg = proxyCIDRProblem(c, p)
				}
				if ok && msg == "" {
					addC(p)
				} else if strict {
					return nil, fmt.Errorf("%s: %s line %d: %s", where, r.CIDRFile, nums[k], msg)
				}
			}
		}
		out = append(out, rs)
	}
	return out, nil
}

// proxyMerge sorts prefixes and drops the ones contained in another (nft interval sets reject overlaps).
func proxyMerge(ps []netip.Prefix) []netip.Prefix {
	s := append([]netip.Prefix{}, ps...)
	sort.Slice(s, func(i, j int) bool {
		if c := s[i].Addr().Compare(s[j].Addr()); c != 0 {
			return c < 0
		}
		return s[i].Bits() < s[j].Bits()
	})
	var out []netip.Prefix
	for _, p := range s {
		if n := len(out); n > 0 && out[n-1].Bits() <= p.Bits() && out[n-1].Contains(p.Addr()) {
			continue
		}
		out = append(out, p)
	}
	return out
}

// proxySets returns the merged destination sets for nftables: fake-ip ranges + every rule CIDR.
func proxySets(c *Config, sets []proxyRuleSet) (v4, v6 []netip.Prefix) {
	all := []netip.Prefix{netip.MustParsePrefix(proxyFake4)}
	if c.Proxy.ipv6() {
		all = append(all, netip.MustParsePrefix(proxyFake6))
	}
	for _, rs := range sets {
		all = append(all, rs.CIDRs...)
	}
	for _, p := range proxyMerge(all) {
		if p.Addr().Is4() {
			v4 = append(v4, p)
		} else if c.Proxy.ipv6() {
			v6 = append(v6, p)
		}
	}
	return v4, v6
}

func proxyRender(c *Config, out *Out) error {
	if !c.Proxy.Enabled {
		return nil
	}
	sets, err := proxyLoad(c, true)
	if err != nil {
		return err
	}
	js, err := proxySingBox(c, sets)
	if err != nil {
		return err
	}
	conf, err := proxyDnsmasq(c, sets)
	if err != nil {
		return err
	}
	out.Add(proxyGenJSON, 0600, js) // contains node passwords
	out.Add(proxyGenDNS, 0644, conf)
	return nil
}

type proxyObj = map[string]any

// proxySingBox renders the sing-box configuration (format of sing-box 1.14: typed DNS servers,
// rule actions, default_domain_resolver).
func proxySingBox(c *Config, sets []proxyRuleSet) (string, error) {
	p := &c.Proxy
	level := p.LogLevel
	if level == "" {
		level = "warn"
	}
	fake := proxyObj{"type": "fakeip", "tag": "fakeip", "inet4_range": proxyFake4}
	if p.ipv6() {
		fake["inet6_range"] = proxyFake6
	}
	inbounds := []any{
		proxyObj{"type": "direct", "tag": "dns-in", "listen": "127.0.0.1", "listen_port": p.dnsPort()},
		proxyObj{"type": "tproxy", "tag": "tproxy4", "listen": "127.0.0.1", "listen_port": p.tproxyPort()},
	}
	if p.ipv6() {
		inbounds = append(inbounds, proxyObj{"type": "tproxy", "tag": "tproxy6", "listen": "::1", "listen_port": p.tproxyPort()})
	}
	outbounds := []any{proxyObj{"type": "direct", "tag": "direct"}}
	var endpoints []any
	for i := range p.Nodes {
		o, endpoint, err := proxyNodeOutbound(c, &p.Nodes[i])
		if err != nil {
			return "", err
		}
		if endpoint {
			endpoints = append(endpoints, o)
		} else {
			outbounds = append(outbounds, o)
		}
	}
	for _, g := range p.Groups {
		o := proxyObj{"type": g.Type, "tag": g.Name, "outbounds": g.Nodes}
		if g.Type == "urltest" {
			if g.URL != "" {
				o["url"] = g.URL
			}
			if g.Interval != "" {
				o["interval"] = g.Interval
			}
		} else {
			o["interrupt_exist_connections"] = true // a manual switch moves existing connections too
		}
		outbounds = append(outbounds, o)
	}
	rules := []any{proxyObj{"inbound": []string{"dns-in"}, "action": "hijack-dns"}}
	for _, rs := range sets {
		if len(rs.Domains) == 0 && len(rs.CIDRs) == 0 {
			continue // an empty sing-box rule would match everything
		}
		r := proxyObj{"action": "route", "outbound": rs.Rule.Outbound}
		if len(rs.Domains) > 0 {
			r["domain_suffix"] = rs.Domains
		}
		if len(rs.CIDRs) > 0 {
			var cs []string
			for _, p := range rs.CIDRs {
				cs = append(cs, p.String())
			}
			r["ip_cidr"] = cs
		}
		rules = append(rules, r)
	}
	cfg := proxyObj{
		"log": proxyObj{"level": level, "timestamp": false},
		"dns": proxyObj{
			"servers": []any{
				proxyObj{"type": "udp", "tag": "local", "server": "127.0.0.1", "server_port": 53}, // main dnsmasq: real answers
				fake,
			},
			"rules": []any{
				proxyObj{"inbound": []string{"dns-in"}, "query_type": []string{"A", "AAAA"}, "action": "route", "server": "fakeip"},
				// HTTPS/SVCB/MX/... of proxied domains: empty answer, so no real address leaks out as a hint
				proxyObj{"inbound": []string{"dns-in"}, "action": "predefined", "rcode": "NOERROR"},
			},
			"final": "local",
		},
		"inbounds":  inbounds,
		"outbounds": outbounds,
		"route": proxyObj{
			"rules": rules,
			// a fake-ip whose domain no longer matches a rule (lists changed) still works, directly
			"final":                   "direct",
			"default_domain_resolver": "local",
		},
		"experimental": proxyObj{
			// fake-ip ↔ domain mapping and selector choices survive restarts (mr-proxy saves it to flash on stop)
			"cache_file": proxyObj{"enabled": true, "path": proxyRunDir + "/cache.db", "store_fakeip": true},
			// loopback only; the secret is added at start by the init script (/run/mr-proxy/api.json)
			"clash_api": proxyObj{"external_controller": fmt.Sprintf("127.0.0.1:%d", p.apiPort())},
		},
	}
	if len(endpoints) > 0 {
		cfg["endpoints"] = endpoints
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b) + "\n", nil
}

// proxyCovered reports whether d or one of its parent domains is in set.
func proxyCovered(d string, set map[string]bool) bool {
	for {
		if set[d] {
			return true
		}
		i := strings.IndexByte(d, '.')
		if i < 0 {
			return false
		}
		d = d[i+1:]
	}
}

// proxyDnsmasq renders the dnsmasq instance for proxied LAN clients: same upstreams and cache
// options as the main dnsmasq, local names from the main dnsmasq, proxied domains to sing-box.
func proxyDnsmasq(c *Config, sets []proxyRuleSet) (string, error) {
	p, d := &c.Proxy, &c.DNS
	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f+"\n", a...) }
	w("# generated by mr (proxy module) — DNS for proxied LAN clients; edit router.yaml instead")
	w("port=%d", p.lanDNSPort())
	for _, br := range proxyBridges(c) {
		w("interface=%s\nno-dhcp-interface=%s", br, br)
	}
	w("bind-dynamic\nlocalise-queries\nexpand-hosts\ndomain=%s", c.DHCP.Domain)
	if d.Rebind {
		// local names (below) legitimately resolve to private addresses
		w("stop-dns-rebind\nrebind-localhost-ok\nrebind-domain-ok=/%s/\nrebind-domain-ok=//", c.DHCP.Domain)
	}
	if d.LocalService {
		w("local-service")
	}
	if d.CacheSize > 0 {
		w("cache-size=%d", d.CacheSize)
	}
	if d.MinTTL > 0 {
		w("min-cache-ttl=%d", d.MinTTL)
	}
	if d.StaleCache > 0 {
		w("use-stale-cache=%d", d.StaleCache)
	}
	if d.NoNegCache {
		w("no-negcache")
	}
	if d.EDNS > 0 {
		w("edns-packet-max=%d", d.EDNS)
	}
	for _, l := range dnsUpstreamLines(c) {
		w("%s", l)
	}
	for _, h := range d.AddnHosts {
		w("addn-hosts=%s", h)
	}
	for _, l := range append(dnsLocalOnly(c), adblockLines(c)...) {
		w("%s", l)
	}
	w("# local names (DHCP leases, static hosts, the router) come from the main dnsmasq")
	w("server=/%s/127.0.0.1\nserver=//127.0.0.1", c.DHCP.Domain)
	for _, n := range c.LANNets() {
		if pf, err := netip.ParsePrefix(n.IPv4); err == nil {
			w("rev-server=%s,127.0.0.1", pf.Masked())
		}
	}
	proxied := map[string]bool{}
	for _, rs := range sets {
		for _, x := range rs.Domains {
			proxied[x] = true
		}
	}
	if d.ServersFile != "" {
		w("servers-file=%s", d.ServersFile)
	} else if len(d.Split) > 0 {
		w("# dns.split, minus domains that are proxied")
		for _, sp := range d.Split {
			lines, _, err := proxyReadList(sp.DomainsFile)
			if err != nil {
				return "", fmt.Errorf("dns.split %q: %w", sp.Name, err)
			}
			for _, x := range lines {
				// same normalization as the dns module's split list
				x = strings.TrimPrefix(strings.TrimSuffix(x, "."), ".")
				if strings.ContainsAny(x, " /#\t") || !safeText(x) {
					return "", fmt.Errorf("dns.split %q: bad domain in %s", sp.Name, sp.DomainsFile)
				}
				if !proxyCovered(strings.ToLower(x), proxied) {
					w("server=/%s/%s", x, sp.Server)
				}
			}
		}
	}
	w("# proxied domains -> sing-box fake-ip DNS")
	var all []string
	for x := range proxied {
		all = append(all, x)
	}
	sort.Strings(all)
	for _, x := range all {
		w("server=/%s/127.0.0.1#%d", x, p.dnsPort())
	}
	// policy_routes domains (net module): proxied clients resolve here, so this instance fills the
	// same nft sets as the main dnsmasq; proxied names get fake-ip answers and are left out
	if lines := policyNftsetLines(c, func(d string) bool { return proxyCovered(d, proxied) }); len(lines) > 0 {
		w("# policy_routes domains -> nft sets (route by domain)")
		for _, l := range lines {
			w("%s", l)
		}
	}
	return b.String(), nil
}

// proxyNetSh: tproxied (marked) packets are routed to the local stack, where sing-box owns them.
// Nothing is emitted when the proxy is off (a leftover rule is inert: no packet carries the mark).
func proxyNetSh(c *Config, phase string, b *strings.Builder) {
	p := &c.Proxy
	if phase != "routes" || !p.Enabled {
		return
	}
	b.WriteString("# proxy: packets marked by the tproxy rules are delivered to sing-box on this host\n")
	// IPv4: one rule per proxied bridge (iif). Strict rp_filter with src_valid_mark=1 repeats the lookup
	// for the reversed flow with iif lo, so the reverse-path check skips table 300 and uses the normal
	// tables: clients behind LAN-side routers (static routes) pass it like unproxied traffic does.
	fmt.Fprintf(b, "while ip -4 rule del pref %d 2>/dev/null; do :; done\n", proxyRulePref)
	for _, br := range proxyBridges(c) {
		fmt.Fprintf(b, "ip -4 rule add iif %s fwmark %s/%s lookup %d pref %d\n", br, proxyMark, proxyMark, proxyTable, proxyRulePref)
	}
	fmt.Fprintf(b, "ip -4 route replace local 0.0.0.0/0 dev lo table %d\n", proxyTable)
	if p.ipv6() {
		// IPv6 has no rp_filter
		fmt.Fprintf(b, "while ip -6 rule del pref %d 2>/dev/null; do :; done; ip -6 rule add fwmark %s/%s lookup %d pref %d\n",
			proxyRulePref, proxyMark, proxyMark, proxyTable, proxyRulePref)
		fmt.Fprintf(b, "ip -6 route replace local ::/0 dev lo table %d\n", proxyTable)
	}
}

// nftElems writes a set's elements, a few per line.
func nftElems(ps []netip.Prefix) string {
	var lines []string
	for i := 0; i < len(ps); i += 8 {
		var chunk []string
		for _, p := range ps[i:min(i+8, len(ps))] {
			chunk = append(chunk, p.String())
		}
		lines = append(lines, strings.Join(chunk, ", "))
	}
	return strings.Join(lines, ",\n\t\t\t")
}

// proxyRunlevel is OpenRC's default runlevel directory (a variable so tests can point it elsewhere).
var proxyRunlevel = "/etc/runlevels/default"

// proxyServicesEnabled reports whether mr-proxy and mr-proxy-dns are enabled in the runlevel.
// The proxy's nftables rules depend on both services: every proxied client's DNS is redirected to
// mr-proxy-dns. `mr apply` enables the services before it loads the firewall, but a rollback
// (confirm timeout, 立即回滚, `mr rollback`) restores router.yaml without re-enabling services that
// the rolled-back apply disabled. Loading the proxy rules then would send every LAN client's DNS to
// a dnsmasq that is not running, also after a reboot; without them the proxy is simply off (real
// DNS, direct traffic) until the next apply enables the services again. Off the router (no OpenRC
// runlevel directory: CI, tests, `mr render` on a PC) the rules are always rendered.
func proxyServicesEnabled() bool {
	if _, err := os.Stat(proxyRunlevel); err != nil {
		return true
	}
	for _, s := range []string{"mr-proxy", "mr-proxy-dns"} {
		if _, err := os.Lstat(filepath.Join(proxyRunlevel, s)); err != nil {
			return false
		}
	}
	return true
}

// proxyNft: sets + two base chains of our own (declared at the "defs" hook).
//
//	proxy_pre  filter prerouting mangle+5 (after the net module's policy marks at mangle+1):
//	           LAN-zone traffic to @proxy4/@proxy6 → tproxy to sing-box + mark; nothing else is touched,
//	           so everything else keeps the flowtable / hardware offload path.
//	proxy_dns  nat prerouting dstnat-5 (before the dns module's redirect at dstnat): DNS of proxied
//	           clients → mr-proxy-dns. Bypass devices, guests and the router keep the main dnsmasq.
func proxyNft(c *Config, hook string, n *Nft) {
	p := &c.Proxy
	if !p.Enabled || hook != "defs" || !proxyServicesEnabled() {
		return
	}
	sets, _ := proxyLoad(c, false)
	v4, v6 := proxySets(c, sets)
	lans := quoteList(proxyBridges(c))

	n.W("set proxy_bypass {\n\t\ttype ether_addr")
	if len(p.Bypass) > 0 {
		var macs []string
		for _, d := range p.Bypass {
			macs = append(macs, proxyBypassMACs(c, d)...)
		}
		if macs = dedup(macs); len(macs) > 0 { // a bypass group may be empty of devices
			n.W("\telements = { %s }", strings.Join(macs, ", "))
		}
	}
	n.W("}")
	n.W("set proxy4 {\n\t\ttype ipv4_addr\n\t\tflags interval\n\t\tauto-merge\n\t\telements = { %s }\n\t}", nftElems(v4))
	if p.ipv6() {
		n.W("set proxy6 {\n\t\ttype ipv6_addr\n\t\tflags interval\n\t\tauto-merge\n\t\telements = { %s }\n\t}", nftElems(v6))
	}

	tp := p.tproxyPort()
	n.W("chain proxy_pre {\n\t\ttype filter hook prerouting priority mangle + 5; policy accept;")
	n.W("\tiifname != { %s } return", lans)
	n.W("\tether saddr @proxy_bypass return")
	// ct direction original: replies of inbound connections (port forwards, pinholes) whose remote peer
	// is inside a proxied range are forwarded normally; only connections a LAN client opens are proxied
	n.W("\tip daddr @proxy4 meta l4proto { tcp, udp } ct direction original goto proxy_tp4")
	if p.ipv6() {
		n.W("\tip6 daddr @proxy6 meta l4proto { tcp, udp } ct direction original goto proxy_tp6")
	}
	n.W("}")
	// with dns.redirect a DNS query to a server inside a proxied range is hijacked (proxy_dns), not tunnelled
	dnsSkip := func() {
		if c.DNS.Redirect {
			n.W("\tmeta l4proto { tcp, udp } th dport 53 return")
		}
	}
	n.W("chain proxy_tp4 {")
	n.W("\tfib daddr type local return")
	dnsSkip()
	if c.bypassReplyRoute() {
		// mode bypass route-only: the main router sent the request here; its reply goes back that way (mode.go)
		n.W("\tct mark set ct mark | %s", proxyMark)
	}
	n.W("\tmeta l4proto tcp socket transparent 1 meta mark set %s accept", proxyMark)
	n.W("\tmeta l4proto { tcp, udp } tproxy ip to 127.0.0.1:%d meta mark set %s accept", tp, proxyMark)
	n.W("\tcounter drop comment \"proxy down: fail closed\"")
	n.W("}")
	if p.ipv6() {
		n.W("chain proxy_tp6 {")
		n.W("\tip6 daddr @lan6 return")
		n.W("\tfib daddr type local return")
		dnsSkip()
		n.W("\tmeta l4proto tcp socket transparent 1 meta mark set %s accept", proxyMark)
		n.W("\tmeta l4proto { tcp, udp } tproxy ip6 to [::1]:%d meta mark set %s accept", tp, proxyMark)
		n.W("\tcounter drop comment \"proxy down: fail closed\"")
		n.W("}")
	}

	if c.bypassReplyRoute() {
		n.W("chain proxy_reply {\n\t\ttype route hook output priority mangle; policy accept;")
		n.W("\tct direction reply ct mark & %s == %s meta mark set %s", proxyMark, proxyMark, bypassReplyMark)
		n.W("}")
	}

	// with dns.redirect every DNS query of a proxied client is taken (like the dns module does);
	// otherwise only queries addressed to the router itself
	only := " fib daddr type local"
	if c.DNS.Redirect {
		only = ""
	}
	n.W("chain proxy_dns {\n\t\ttype nat hook prerouting priority dstnat - 5; policy accept;")
	n.W("\tiifname { %s } ether saddr != @proxy_bypass meta l4proto { tcp, udp } th dport 53%s redirect to :%d comment \"proxy-dns\"", lans, only, p.lanDNSPort())
	n.W("}")
}
