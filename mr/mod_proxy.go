package main

// proxy module: selective transparent proxy. Owns: router.yaml proxy. Docs: docs/modules/proxy.md.
//
// Only traffic that matches a rule enters the proxy; everything else keeps the kernel fast path and
// hardware flow offload. Design:
//
//   - sing-box (mr-proxy) answers fake-ip DNS on 127.0.0.1:dns_port and takes tproxied TCP/UDP on
//     127.0.0.1/::1:tproxy_port; it maps fake IPs back to domains, so the proxy server resolves them.
//   - A second dnsmasq (mr-proxy-dns, lan_dns_port) serves DNS to proxied LAN clients: proxied
//     domains go to sing-box, everything else resolves exactly like the main dnsmasq. nftables
//     redirects port 53 of LAN-zone clients (except bypass devices) to it. The main dnsmasq is
//     untouched, so the router itself, guest networks and bypass devices always get real answers.
//   - nftables (chain proxy_pre, prerouting mangle+5) tproxies LAN-zone traffic whose destination
//     is in @proxy4/@proxy6 (fake-ip ranges + rule CIDRs) and marks it; ip rule fwmark → table
//     with `local default dev lo` delivers it to sing-box.
//
// Files: node types (validation + outbound rendering) mod_proxy_node.go, share-link parser
// mod_proxy_link.go, import / subscription API + CLI mod_proxy_sub.go, sing-box / dnsmasq / nft
// rendering mod_proxy_render.go, verify / status / clash API mod_proxy_api.go.

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// Proxy is router.yaml `proxy`.
type Proxy struct {
	Enabled    bool          `yaml:"enabled"`
	IPv4Only   bool          `yaml:"ipv4_only,omitempty"`    // proxied domains get no AAAA (clients use IPv4)
	LogLevel   string        `yaml:"log_level,omitempty"`    // sing-box: error | warn (default) | info | debug
	TProxyPort int           `yaml:"tproxy_port,omitempty"`  // default 7893 (loopback only)
	DNSPort    int           `yaml:"dns_port,omitempty"`     // sing-box fake-ip DNS, default 1053 (loopback only)
	LANDNSPort int           `yaml:"lan_dns_port,omitempty"` // dnsmasq for proxied clients, default 1054
	APIPort    int           `yaml:"api_port,omitempty"`     // sing-box clash API, default 9090 (loopback only)
	Nodes      []ProxyNode   `yaml:"nodes,omitempty"`
	Groups     []ProxyGroup  `yaml:"groups,omitempty"`
	Rules      []ProxyRule   `yaml:"rules,omitempty"`
	Bypass     []ProxyDevice `yaml:"bypass,omitempty"`
	// share-link subscriptions for the web UI's node import (URL in secrets.yaml)
	Subscriptions []ProxySub `yaml:"subscriptions,omitempty"`
}

// ProxyNode is one proxy server (one sing-box outbound). Types and their keys: mod_proxy_node.go,
// docs/modules/proxy.md. Credentials are secret NAMES (*_secret, values in secrets.yaml).
type ProxyNode struct {
	Name   string `yaml:"name"`
	Type   string `yaml:"type,omitempty"` // shadowsocks (default) | vless | vmess | trojan | hysteria2 | tuic | anytls | socks | http | custom
	Server string `yaml:"server,omitempty"`
	Port   int    `yaml:"port,omitempty"`
	// shadowsocks cipher
	Method   string `yaml:"method,omitempty"`
	Password string `yaml:"password_secret,omitempty"` // shadowsocks, trojan, hysteria2, tuic, anytls, socks, http
	UUID     string `yaml:"uuid_secret,omitempty"`     // vless, vmess, tuic
	Username string `yaml:"username,omitempty"`        // socks, http
	// vless / vmess
	Flow           string `yaml:"flow,omitempty"`            // vless: xtls-rprx-vision
	Security       string `yaml:"security,omitempty"`        // vmess cipher: auto (default) | none | zero | aes-128-gcm | chacha20-poly1305
	AlterID        int    `yaml:"alter_id,omitempty"`        // vmess: 0 = AEAD (only legacy servers use more)
	PacketEncoding string `yaml:"packet_encoding,omitempty"` // UDP: xudp | packetaddr | none (vless default xudp, vmess none)
	// hysteria2
	UpMbps       int    `yaml:"up_mbps,omitempty"` // 0 (both): BBR congestion control
	DownMbps     int    `yaml:"down_mbps,omitempty"`
	Obfs         string `yaml:"obfs,omitempty"` // salamander
	ObfsPassword string `yaml:"obfs_password_secret,omitempty"`
	HopPorts     string `yaml:"hop_ports,omitempty"` // port hopping: 20000-30000[,40000-50000]
	// tuic
	CongestionControl string `yaml:"congestion_control,omitempty"` // cubic (default) | new_reno | bbr
	UDPRelayMode      string `yaml:"udp_relay_mode,omitempty"`     // native (default) | quic
	// TLS: optional for vless, vmess, trojan, http (tls: true); always on for hysteria2, tuic, anytls
	TLS            bool     `yaml:"tls,omitempty"`
	SNI            string   `yaml:"sni,omitempty"` // TLS server_name (default: server)
	ALPN           []string `yaml:"alpn,omitempty"`
	Insecure       bool     `yaml:"insecure,omitempty"`           // skip certificate verification (unsafe)
	Fingerprint    string   `yaml:"fingerprint,omitempty"`        // uTLS client hello: chrome | firefox | safari | ...
	RealityKey     string   `yaml:"reality_public_key,omitempty"` // REALITY (vless, trojan, anytls)
	RealityShortID string   `yaml:"reality_short_id,omitempty"`
	// V2Ray transport (vless, vmess, trojan): ws | grpc | http | httpupgrade
	Transport   string `yaml:"transport,omitempty"`
	Path        string `yaml:"path,omitempty"`         // ws, http, httpupgrade
	Host        string `yaml:"host,omitempty"`         // ws, http, httpupgrade
	ServiceName string `yaml:"service_name,omitempty"` // grpc
	EarlyData   int    `yaml:"early_data,omitempty"`   // ws 0-RTT bytes (share links: path ?ed=2048)
	TCPOnly     bool   `yaml:"tcp_only,omitempty"`     // server has no UDP relay
	TFO         bool   `yaml:"tfo,omitempty"`          // TCP Fast Open to the server (it must enable it too: own servers)
	// custom: secrets.yaml key whose value is a sing-box outbound JSON object (any protocol the
	// sing-box build supports; type wireguard becomes an endpoint); mr only sets its tag.
	JSON string `yaml:"json_secret,omitempty"`
}

// ProxySub is a saved subscription. Only the web UI uses it (fetch → preview → add nodes); the URL
// usually carries an access token, so it is a secret.
type ProxySub struct {
	Name string `yaml:"name"`
	URL  string `yaml:"url_secret"`
}

// ProxyGroup picks one node: urltest = lowest latency with automatic failover, selector = manual.
type ProxyGroup struct {
	Name     string   `yaml:"name"`
	Type     string   `yaml:"type"` // urltest | selector
	Nodes    []string `yaml:"nodes"`
	URL      string   `yaml:"url,omitempty"`      // urltest probe URL (sing-box default: gstatic generate_204)
	Interval string   `yaml:"interval,omitempty"` // urltest probe interval, e.g. 3m
}

// ProxyRule sends domains (suffix match: example.com = example.com + *.example.com) and IP ranges
// to an outbound (node or group). Rules are checked in order; the first match wins.
type ProxyRule struct {
	Name        string   `yaml:"name"`
	Outbound    string   `yaml:"outbound"`
	Domains     []string `yaml:"domains,omitempty"`
	DomainsFile string   `yaml:"domains_file,omitempty"` // one domain per line, # comments
	CIDRs       []string `yaml:"cidrs,omitempty"`
	CIDRFile    string   `yaml:"cidr_file,omitempty"` // one CIDR / IP per line, # comments
}

// ProxyDevice is never proxied and always gets real DNS answers (matched by MAC, so dynamic
// IPv4 and IPv6 addresses are covered).
type ProxyDevice struct {
	Name string `yaml:"name"`
	MAC  string `yaml:"mac"`
}

const (
	proxyMark     = "0x1000000" // fwmark bit for tproxied packets (WAN marks use 0x100-0x2ff, tailscale 0xff0000)
	proxyMarkBit  = 0x1000000   // the same bit as a number
	proxyTable    = 300         // routing table: local default dev lo
	proxyRulePref = 5200        // before tailscale's rules (5210-5270) and mr's WAN rules (5290/5300)
	proxyFake4    = "198.18.0.0/15"
	proxyFake6    = "fc00::/18"
	proxyListDir  = "/etc/mini-router/proxy" // list files the web UI may create and edit
	proxyRunDir   = "/run/mr-proxy"          // sing-box runtime dir (config copy, API secret, fake-ip cache)
	proxyGenJSON  = GenDir + "/sing-box.json"
	proxyGenDNS   = GenDir + "/proxy-dns.conf"
)

// proxyPortOr returns p if set, else the default.
func proxyPortOr(p, def int) int {
	if p == 0 {
		return def
	}
	return p
}

func (p *Proxy) tproxyPort() int { return proxyPortOr(p.TProxyPort, 7893) }
func (p *Proxy) dnsPort() int    { return proxyPortOr(p.DNSPort, 1053) }
func (p *Proxy) lanDNSPort() int { return proxyPortOr(p.LANDNSPort, 1054) }
func (p *Proxy) apiPort() int    { return proxyPortOr(p.APIPort, 9090) }

// proxySSMethods: supported Shadowsocks methods → key length of the 2022 methods (0 = any password).
// No "none" and no legacy stream ciphers. The A53 cores have AES instructions: aes-128-gcm variants are fastest.
var proxySSMethods = map[string]int{
	"2022-blake3-aes-128-gcm":       16,
	"2022-blake3-aes-256-gcm":       32,
	"2022-blake3-chacha20-poly1305": 32,
	"aes-128-gcm":                   0,
	"aes-192-gcm":                   0,
	"aes-256-gcm":                   0,
	"chacha20-ietf-poly1305":        0,
	"xchacha20-ietf-poly1305":       0,
}

// tags used by the generated sing-box config; node/group names must not collide with them
var proxyReserved = map[string]bool{"direct": true, "local": true, "fakeip": true, "dns-in": true, "tproxy4": true, "tproxy6": true, "GLOBAL": true}

var (
	reProxyHost     = lazyRegexp(`^[A-Za-z0-9]([A-Za-z0-9-]{0,62})(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62}))*$`)
	reProxyDomain   = lazyRegexp(`^[a-z0-9_]([a-z0-9_-]{0,62})(\.[a-z0-9_]([a-z0-9_-]{0,62}))*$`)
	reProxySecret   = lazyRegexp(`^[a-z0-9_-]{1,40}$`)
	reProxyURL      = lazyRegexp(`^https?://[A-Za-z0-9._~:/?&=%+-]{1,200}$`)
	reProxyInterval = lazyRegexp(`^[1-9][0-9]{0,3}[smh]$`)
	reProxyOutType  = lazyRegexp(`^[a-z0-9-]{1,20}$`)
)

func init() {
	register(&Module{
		Name: "proxy",
		Prio: 55,
		Secrets: func(c *Config) []string {
			var out []string
			for _, n := range c.Proxy.Nodes {
				out = append(out, n.secretRefs()...)
			}
			for _, sub := range c.Proxy.Subscriptions {
				out = append(out, sub.URL)
			}
			return out
		},
		Validate: proxyValidate,
		Render:   proxyRender,
		NetSh:    proxyNetSh,
		Nft:      proxyNft,
		Services: func(c *Config) []string {
			if !c.Proxy.Enabled {
				return nil
			}
			return []string{"mr-proxy", "mr-proxy-dns"}
		},
		Managed: []string{"mr-proxy", "mr-proxy-dns"},
		Restart: func(path string) string {
			switch path {
			case proxyGenJSON:
				return "mr-proxy"
			case proxyGenDNS:
				return "mr-proxy-dns"
			}
			return ""
		},
		RestartOrder: []string{"mr-proxy", "mr-proxy-dns"},
		Verify:       proxyVerify,
		API: map[string]func(r apiReq) apiResp{
			"proxy.status": apiProxyStatus,
			"proxy.delay":  apiProxyDelay,
			"proxy.select": apiProxySelect,
			"proxy.lists":  apiProxyLists,
			"proxy.parse":  apiProxyParse,
			"proxy.fetch":  apiProxyFetch,
			"proxy.routes": apiProxyRoutes,
		},
		Commands: map[string]func(c *Config, args []string) error{"proxy": proxyCmd},
	})
}

// proxyNormDomain lower-cases a domain list entry and strips wildcard / dot decorations
// ("*.x.com", "+.x.com", ".x.com", "x.com." all mean x.com and its subdomains).
func proxyNormDomain(s string) (string, bool) {
	d := strings.ToLower(strings.TrimSpace(s))
	for _, p := range []string{"*.", "+.", "."} {
		d = strings.TrimPrefix(d, p)
	}
	d = strings.TrimSuffix(d, ".")
	if d == "" || len(d) > 253 || !reProxyDomain.MatchString(d) {
		return "", false
	}
	return d, true
}

// proxyNormCIDR parses a CIDR or a bare address (→ /32, /128) and masks it.
func proxyNormCIDR(s string) (netip.Prefix, bool) {
	s = strings.TrimSpace(s)
	if p, err := netip.ParsePrefix(s); err == nil {
		if p.Addr().Is4In6() {
			return netip.Prefix{}, false
		}
		return p.Masked(), true
	}
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" || a.Is4In6() {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(a, a.BitLen()), true
}

// proxyForbidden: ranges a rule may never send to the proxy (local, link-local, multicast, and the LAN itself).
var proxyForbidden = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{"0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/3", "::/127", "fe80::/10", "ff00::/8"} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

// proxyCIDRProblem explains why a rule CIDR is not allowed ("" = fine).
func proxyCIDRProblem(c *Config, p netip.Prefix) string {
	for _, f := range proxyForbidden {
		if p.Overlaps(f) {
			return "overlaps reserved range " + f.String()
		}
	}
	for _, ln := range c.LANNets() {
		if lp, err := netip.ParsePrefix(ln.IPv4); err == nil && p.Overlaps(lp.Masked()) {
			return "overlaps LAN network " + lp.Masked().String()
		}
	}
	if c.Proxy.IPv4Only && p.Addr().Is6() {
		return "IPv6 range but proxy.ipv4_only is set"
	}
	return ""
}

func proxyValidate(c *Config, v *Validator) {
	p := &c.Proxy
	switch p.LogLevel {
	case "", "error", "warn", "info", "debug":
	default:
		v.Add("proxy.log_level: error|warn|info|debug, got %q", p.LogLevel)
	}
	used := map[int]string{c.Services.SSH.Port: "services.ssh.port", 53: "DNS", 67: "DHCP", 80: "web UI"}
	if c.Services.Tailscale.Enabled {
		used[c.Services.Tailscale.Port] = "services.tailscale.port"
	}
	for _, x := range []struct {
		key      string
		set, eff int
	}{{"tproxy_port", p.TProxyPort, p.tproxyPort()}, {"dns_port", p.DNSPort, p.dnsPort()}, {"lan_dns_port", p.LANDNSPort, p.lanDNSPort()}, {"api_port", p.APIPort, p.apiPort()}} {
		if x.set != 0 && (x.set < 1024 || x.set > 65535) {
			v.Add("proxy.%s: 1024-65535 (0 = default), got %d", x.key, x.set)
		}
		if o, ok := used[x.eff]; ok {
			v.Add("proxy.%s: port %d already used by %s", x.key, x.eff, o)
		}
		used[x.eff] = "proxy." + x.key
	}

	names := map[string]string{} // node and group names share the sing-box tag namespace
	nameOK := func(path, name string) {
		if !reLabel.MatchString(name) {
			v.Add("%s.name: letters, digits, _ . - (max 40), got %q", path, name)
		} else if proxyReserved[name] {
			v.Add("%s.name: %q is reserved", path, name)
		} else if o, dup := names[name]; dup {
			v.Add("%s.name: %q already used by %s", path, name, o)
		}
		names[name] = path
	}
	// secret values are checked whenever they are there; missing ones only matter with the proxy on
	secret := func(k string) (string, bool) { s, ok := c.secrets[k]; return s, ok }
	nodes := map[string]bool{}
	for i := range p.Nodes {
		n := &p.Nodes[i]
		path := fmt.Sprintf("proxy.nodes[%d]", i)
		nameOK(path, n.Name)
		nodes[n.Name] = true
		for _, e := range proxyNodeProblems(n, secret, p.Enabled) {
			v.Add("%s.%s", path, e)
		}
	}
	subs := map[string]bool{}
	for i, sub := range p.Subscriptions {
		path := fmt.Sprintf("proxy.subscriptions[%d]", i)
		if !reLabel.MatchString(sub.Name) {
			v.Add("%s.name: letters, digits, _ . - (max 40), got %q", path, sub.Name)
		} else if subs[sub.Name] {
			v.Add("%s.name: duplicate %q", path, sub.Name)
		}
		subs[sub.Name] = true
		if !reProxySecret.MatchString(sub.URL) {
			v.Add("%s.url_secret: secret name [a-z0-9_-]{1,40} required, got %q", path, sub.URL)
		} else if u, ok := secret(sub.URL); !ok {
			v.Add("%s.url_secret: secret %q missing from secrets.yaml", path, sub.URL)
		} else if !proxySubURLOK(u) {
			v.Add("%s.url_secret: the secret is not an http(s) URL (no spaces, quotes or control characters)", path)
		}
	}
	outs := map[string]bool{}
	for k := range nodes {
		outs[k] = true
	}
	for i, g := range p.Groups {
		path := fmt.Sprintf("proxy.groups[%d]", i)
		nameOK(path, g.Name)
		outs[g.Name] = true
		if g.Type != "urltest" && g.Type != "selector" {
			v.Add("%s.type: urltest|selector, got %q", path, g.Type)
		}
		if len(g.Nodes) == 0 {
			v.Add("%s.nodes: at least one node", path)
		}
		seen := map[string]bool{}
		for _, m := range g.Nodes {
			if !nodes[m] {
				v.Add("%s.nodes: unknown node %q", path, m)
			}
			if seen[m] {
				v.Add("%s.nodes: %q listed twice", path, m)
			}
			seen[m] = true
		}
		if g.URL != "" && !reProxyURL.MatchString(g.URL) {
			v.Add("%s.url: http(s) URL without spaces or quotes, got %q", path, g.URL)
		}
		if g.Interval != "" && !reProxyInterval.MatchString(g.Interval) {
			v.Add("%s.interval: e.g. 30s, 3m, 1h; got %q", path, g.Interval)
		}
	}
	ruleNames := map[string]bool{}
	for i, r := range p.Rules {
		path := fmt.Sprintf("proxy.rules[%d]", i)
		if !reLabel.MatchString(r.Name) {
			v.Add("%s.name: letters, digits, _ . - (max 40), got %q", path, r.Name)
		}
		if ruleNames[r.Name] {
			v.Add("%s.name: duplicate %q", path, r.Name)
		}
		ruleNames[r.Name] = true
		if !outs[r.Outbound] {
			v.Add("%s.outbound: must be a node or group name, got %q", path, r.Outbound)
		}
		if len(r.Domains) == 0 && r.DomainsFile == "" && len(r.CIDRs) == 0 && r.CIDRFile == "" {
			v.Add("%s: needs domains, domains_file, cidrs or cidr_file", path)
		}
		for _, d := range r.Domains {
			if _, ok := proxyNormDomain(d); !ok {
				v.Add("%s.domains: invalid domain %q", path, d)
			}
		}
		for _, s := range r.CIDRs {
			pf, ok := proxyNormCIDR(s)
			if !ok {
				v.Add("%s.cidrs: invalid CIDR/IP %q", path, s)
			} else if msg := proxyCIDRProblem(c, pf); msg != "" {
				v.Add("%s.cidrs: %s %s", path, s, msg)
			}
		}
		for key, f := range map[string]string{"domains_file": r.DomainsFile, "cidr_file": r.CIDRFile} {
			if f != "" && !rePath.MatchString(f) {
				v.Add("%s.%s: absolute path required, got %q", path, key, f)
			}
		}
	}
	macs := map[string]bool{}
	for i, d := range p.Bypass {
		path := fmt.Sprintf("proxy.bypass[%d]", i)
		if !safeText(d.Name) || len(d.Name) > 64 {
			v.Add("%s.name: printable text up to 64 bytes", path)
		}
		if !reMAC.MatchString(d.MAC) {
			v.Add("%s.mac: invalid %q", path, d.MAC)
		}
		m := strings.ToLower(d.MAC)
		if macs[m] {
			v.Add("%s.mac: duplicate %s", path, d.MAC)
		}
		macs[m] = true
	}
	if p.Enabled && len(p.Nodes) == 0 {
		v.Add("proxy: enabled but no nodes configured")
	}
	if p.Enabled {
		// a policy mark with the proxy bit would hit `ip rule fwmark 0x1000000/0x1000000 lookup 300` (local
		// delivery): every packet of that device, and replies of its WAN's inbound connections, would be dropped
		for i, pr := range c.Policy {
			if m, err := strconv.ParseUint(pr.Mark, 0, 32); err == nil && m&proxyMarkBit != 0 {
				v.Add("policy_routes[%d].mark: %s sets bit %s, which the proxy uses for its tproxy mark", i, pr.Mark, proxyMark)
			}
		}
	}
}

// proxyCheckSSPassword: 2022 methods need base64 keys of the method's length ("iPSK:uPSK" allowed).
func proxyCheckSSPassword(pw string, keyLen int) string {
	if pw == "" {
		return "empty password"
	}
	if keyLen == 0 {
		return ""
	}
	for _, part := range strings.Split(pw, ":") {
		k, err := base64.StdEncoding.DecodeString(part)
		if err != nil || len(k) != keyLen {
			return fmt.Sprintf("2022 methods need a base64 key of %d bytes (e.g. `openssl rand -base64 %d`)", keyLen, keyLen)
		}
	}
	return ""
}

// proxyCustomOutbound parses a custom node: a JSON object with a "type" (tag is set by mr).
// endpoint=true for WireGuard, which sing-box 1.14 only has as an endpoint (usable like an outbound).
// Errors never quote the JSON (it holds credentials).
func proxyCustomOutbound(raw string) (m map[string]any, endpoint bool, err error) {
	if err := json.Unmarshal([]byte(raw), &m); err != nil || m == nil {
		var se *json.SyntaxError
		if errors.As(err, &se) {
			return nil, false, fmt.Errorf("not a JSON object (syntax error at byte %d)", se.Offset)
		}
		return nil, false, fmt.Errorf("not a JSON object")
	}
	t, _ := m["type"].(string)
	if !reProxyOutType.MatchString(t) {
		return nil, false, fmt.Errorf("JSON object needs a sing-box outbound \"type\"")
	}
	switch t {
	case "direct", "block", "dns", "selector", "urltest", "tailscale":
		return nil, false, fmt.Errorf("type %q not allowed for a node", t)
	}
	delete(m, "tag")
	return m, t == "wireguard", nil
}
