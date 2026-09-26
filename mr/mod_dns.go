package main

// dns module: dnsmasq (DNS cache/forwarding, local records, DHCP, RA / DHCPv6), DNS split lists,
// DNS redirect, and the stubby (DNS-over-TLS) config. Nothing resident besides dnsmasq/stubby:
// statistics, lease release and query logging are computed on demand by `mr`.
// Owns: router.yaml dhcp, dns, networks[].dhcp (type Pool). Docs: docs/modules/dns.md.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

type DHCP struct {
	Start      int    `yaml:"start"` // host part
	End        int    `yaml:"end"`
	Lease      string `yaml:"lease"`
	Domain     string `yaml:"domain"`
	DHCPOpts   `yaml:",inline"`
	IPv6       RA                `yaml:"ipv6"` // RA / DHCPv6 on the main LAN (used when lan.ipv6_ra is on)
	Hosts      []Host            `yaml:"hosts"`
	HostLeases map[string]string `yaml:"host_leases"` // per-host lease time: MAC -> lease (default: the pool's)
}

// Pool is a DHCP address pool of an extra network (host parts relative to the network address).
type Pool struct {
	Enabled  bool   `yaml:"enabled"`
	Start    int    `yaml:"start,omitempty"`
	End      int    `yaml:"end,omitempty"`
	Lease    string `yaml:"lease,omitempty"`
	DHCPOpts `yaml:",inline"`
	IPv6     RA `yaml:"ipv6"` // RA / DHCPv6 on this network (used when networks[].ipv6_ra is on)
}

// DHCPOpts are the DHCPv4 options handed out on one network.
type DHCPOpts struct {
	DNS     []string  `yaml:"dns"`     // option 6 (default: the router's address on that network)
	NTP     []string  `yaml:"ntp"`     // option 42
	Search  []string  `yaml:"search"`  // option 119 (domain search list)
	Options []DHCPOpt `yaml:"options"` // any other option by number, strictly validated
}

type DHCPOpt struct {
	Code  int    `yaml:"code"`
	Value string `yaml:"value"` // comma-separated tokens, e.g. "192.168.1.10" or "10.8.0.0/24,192.168.1.10"
}

// RA configures IPv6 router advertisements (and optionally DHCPv6) on one network.
type RA struct {
	Mode     string   `yaml:"mode"`        // slaac (ra-only, default) | stateless (ra-stateless) | stateful (DHCPv6 range + SLAAC)
	Start    string   `yaml:"start"`       // stateful: first interface id, e.g. "::1000"
	End      string   `yaml:"end"`         // stateful: last interface id, e.g. "::ffff"
	Lease    string   `yaml:"lease"`       // prefix / DHCPv6 lease lifetime (default 12h)
	DNS      []string `yaml:"dns"`         // RDNSS + DHCPv6 DNS; empty = the router ("::" = its global address)
	Interval int      `yaml:"ra_interval"` // seconds between unsolicited RAs (default 60)
	Lifetime int      `yaml:"ra_lifetime"` // router lifetime in seconds (default 1800)
	Priority string   `yaml:"ra_priority"` // "" (medium) | high | low
	MTU      int      `yaml:"ra_mtu"`      // advertised MTU (0 = not advertised)
}

type Host struct {
	Name string `yaml:"name"`
	MAC  string `yaml:"mac"`
	IP   string `yaml:"ip"`
}

type DNS struct {
	CacheSize    int      `yaml:"cache_size"`
	MinTTL       int      `yaml:"min_cache_ttl"`
	StaleCache   int      `yaml:"use_stale_cache"`
	NoNegCache   bool     `yaml:"no_negcache"`
	EDNS         int      `yaml:"edns_packet_max"`
	Upstream     string   `yaml:"upstream"` // isp (DNS from PPPoE, default) | manual (servers) | dot (stubby)
	Servers      []string `yaml:"servers"`  // manual upstreams: ip[#port]
	DoT          DoT      `yaml:"dot"`      // stubby, used when services.stubby is enabled
	ServersFile  string   `yaml:"servers_file"`
	AddnHosts    []string `yaml:"addn_hosts"`
	Rebind       bool     `yaml:"rebind_protection"`
	LocalService bool     `yaml:"local_service"`
	Redirect     bool     `yaml:"redirect"` // hijack LAN DNS to the router
	Records      []Record `yaml:"records"`  // local DNS records (home servers)
	Split        []Split  `yaml:"split"`    // per-domain upstream (DNS 分流)

	// keep LAN devices on the router's DNS (mod_dns_sovereignty.go); ad blocking (mod_dns_adblock.go)
	Sovereignty DNSSovereignty `yaml:"sovereignty"`
	Adblock     Adblock        `yaml:"adblock"`
}

// DoT is the stubby (DNS-over-TLS) forwarder. It listens on 127.0.0.1:Port only.
type DoT struct {
	Port      int         `yaml:"port"`      // default 5453
	Servers   []DoTServer `yaml:"servers"`   // default: Cloudflare 1.1.1.1 / 1.0.0.1
	Bootstrap []string    `yaml:"bootstrap"` // upstream=dot: plain DNS for NTP host names (default: the DoT servers on port 53)
}

type DoTServer struct {
	Address string `yaml:"address"`        // IPv4 or IPv6 address
	Name    string `yaml:"name"`           // TLS authentication name, e.g. cloudflare-dns.com
	Port    int    `yaml:"port,omitempty"` // default 853
}

// Split sends every domain listed in DomainsFile (one per line, # comments) to Server.
// Server is dnsmasq syntax: "127.0.0.1#5453", "1.1.1.1", "8.8.8.8#53".
type Split struct {
	Name        string `yaml:"name"`
	DomainsFile string `yaml:"domains_file"`
	Server      string `yaml:"server"`
}

const (
	ResolvPPP     = "/run/ppp/resolv.conf" // DNS servers learned from PPPoE (usepeerdns)
	StubbyConf    = "/etc/stubby/stubby.yml"
	defaultDoTPrt = 5453
)

var defaultDoT = []DoTServer{{Address: "1.1.1.1", Name: "cloudflare-dns.com"}, {Address: "1.0.0.1", Name: "cloudflare-dns.com"}}

func dnsDefaults(c *Config) {
	for i := range c.Networks {
		n := &c.Networks[i]
		if n.DHCP.Enabled && n.DHCP.Lease == "" {
			n.DHCP.Lease = "12h"
		}
		// also when RA is off but a mode is set: a stateful block without start/end must not make
		// the config invalid just because RA was switched off on that network
		if n.IPv6RA || n.DHCP.IPv6.Mode != "" {
			raDefaults(&n.DHCP.IPv6)
		}
	}
	raDefaults(&c.DHCP.IPv6)
	if c.DNS.Upstream == "" {
		c.DNS.Upstream = "isp"
	}
	if c.DNS.Sovereignty.FirefoxCanary == nil {
		c.DNS.Sovereignty.FirefoxCanary = boolp(true)
	}
	if c.DNS.DoT.Port == 0 {
		c.DNS.DoT.Port = defaultDoTPrt
	}
	if len(c.DNS.DoT.Servers) == 0 {
		c.DNS.DoT.Servers = append([]DoTServer{}, defaultDoT...)
	}
}

func raDefaults(r *RA) {
	if r.Mode == "" {
		r.Mode = "slaac"
	}
	if r.Lease == "" {
		r.Lease = "12h"
	}
	if r.Interval == 0 {
		r.Interval = 60
	}
	if r.Lifetime == 0 {
		r.Lifetime = 1800
	}
	if r.Mode == "stateful" && r.Start == "" && r.End == "" {
		r.Start, r.End = "::1000", "::ffff"
	}
}

// renderSplit expands each split rule's domain list into dnsmasq server=/domain/upstream lines.
func renderSplit(c *Config) (string, error) {
	var b strings.Builder
	b.WriteString("# generated by mr from dns.split — edit router.yaml / the domain lists instead\n")
	for _, sp := range c.DNS.Split {
		f, err := os.Open(sp.DomainsFile)
		if err != nil {
			return "", fmt.Errorf("dns.split %q: %w", sp.Name, err)
		}
		fmt.Fprintf(&b, "# %s -> %s\n", sp.Name, sp.Server)
		n := 0
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			d := strings.TrimSpace(sc.Text())
			if d == "" || strings.HasPrefix(d, "#") {
				continue
			}
			d = strings.TrimPrefix(strings.TrimSuffix(d, "."), ".")
			if strings.ContainsAny(d, " /#\t") {
				f.Close()
				return "", fmt.Errorf("dns.split %q: bad domain %q in %s", sp.Name, d, sp.DomainsFile)
			}
			fmt.Fprintf(&b, "server=/%s/%s\n", d, sp.Server)
			n++
		}
		f.Close()
		if err := sc.Err(); err != nil {
			return "", err
		}
		if n == 0 {
			return "", fmt.Errorf("dns.split %q: %s has no domains", sp.Name, sp.DomainsFile)
		}
	}
	return b.String(), nil
}

// dhcpNet is one LAN-side network as the DHCP/RA renderer sees it.
type dhcpNet struct {
	tag, bridge, cidr string
	pool              bool // DHCPv4 pool enabled
	start, end        int
	lease             string
	opts              DHCPOpts
	ra                bool // lan.ipv6_ra / networks[].ipv6_ra
	ipv6              RA
}

func dhcpNets(c *Config) []dhcpNet {
	out := []dhcpNet{{tag: "lan", bridge: c.LAN.Bridge, cidr: c.LAN.IPv4, pool: true, start: c.DHCP.Start, end: c.DHCP.End,
		lease: c.DHCP.Lease, opts: c.DHCP.DHCPOpts, ra: c.LAN.IPv6RA, ipv6: c.DHCP.IPv6}}
	for _, n := range c.Networks {
		out = append(out, dhcpNet{tag: n.Name, bridge: n.BridgeName(), cidr: n.IPv4, pool: n.DHCP.Enabled, start: n.DHCP.Start,
			end: n.DHCP.End, lease: n.DHCP.Lease, opts: n.DHCP.DHCPOpts, ra: n.IPv6RA, ipv6: n.DHCP.IPv6})
	}
	return out
}

func renderDnsmasq(c *Config) string {
	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f+"\n", a...) }
	b.WriteString("# generated by mr — edit router.yaml instead\n")
	for _, n := range c.LANNets() {
		w("interface=%s", n.Bridge)
	}
	b.WriteString("bind-dynamic\nlisten-address=127.0.0.1\n")
	b.WriteString("domain-needed\nlocalise-queries\nexpand-hosts\ndhcp-authoritative\n")
	// router advertisements are logged once per RA on every LAN (~95% of the RAM log): keep them out
	b.WriteString("quiet-ra\n")
	w("local=/%s/\ndomain=%s", c.DHCP.Domain, c.DHCP.Domain)
	if c.DNS.Rebind {
		b.WriteString("stop-dns-rebind\nrebind-localhost-ok\n")
	}
	if c.DNS.LocalService {
		b.WriteString("local-service\n")
	}
	if c.DNS.CacheSize > 0 {
		w("cache-size=%d", c.DNS.CacheSize)
	}
	if c.DNS.MinTTL > 0 {
		w("min-cache-ttl=%d", c.DNS.MinTTL)
	}
	if c.DNS.StaleCache > 0 {
		w("use-stale-cache=%d", c.DNS.StaleCache)
	}
	if c.DNS.NoNegCache {
		b.WriteString("no-negcache\n")
	}
	if c.DNS.EDNS > 0 {
		w("edns-packet-max=%d", c.DNS.EDNS)
	}
	for _, l := range dnsUpstreamLines(c) {
		b.WriteString(l + "\n")
	}
	if c.DNS.ServersFile != "" {
		w("servers-file=%s", c.DNS.ServersFile)
	} else if len(c.DNS.Split) > 0 {
		w("servers-file=%s/dns-split.servers", GenDir)
	}
	for _, h := range c.DNS.AddnHosts {
		w("addn-hosts=%s", h)
	}
	for _, l := range recordLines(c) {
		b.WriteString(l + "\n")
	}
	for _, l := range append(dnsLocalOnly(c), adblockLines(c)...) {
		b.WriteString(l + "\n")
	}
	w("dhcp-leasefile=%s", LeaseFile)
	// one tagged pool per network; router/DNS options follow the tag so each network gets its own gateway
	ra := false
	for _, n := range dhcpNets(c) {
		ip, nn, err := net.ParseCIDR(n.cidr)
		if err != nil {
			continue
		}
		if n.pool {
			w("dhcp-range=set:%s,%s,%s,%s,%s", n.tag, hostIn(nn, n.start), hostIn(nn, n.end), net.IP(nn.Mask).String(), n.lease)
			dns := ip.String()
			if len(n.opts.DNS) > 0 {
				dns = strings.Join(n.opts.DNS, ",")
			}
			w("dhcp-option=tag:%s,option:router,%s\ndhcp-option=tag:%s,option:dns-server,%s", n.tag, ip, n.tag, dns)
			if len(n.opts.NTP) > 0 {
				w("dhcp-option=tag:%s,option:ntp-server,%s", n.tag, strings.Join(n.opts.NTP, ","))
			}
			if len(n.opts.Search) > 0 {
				w("dhcp-option=tag:%s,option:domain-search,%s", n.tag, strings.Join(n.opts.Search, ","))
			}
			for _, o := range n.opts.Options {
				w("dhcp-option=tag:%s,%d,%s", n.tag, o.Code, o.Value)
			}
		}
		if n.ra {
			ra = true
			renderRA(&b, n.bridge, n.ipv6)
		}
	}
	for _, h := range c.DHCP.Hosts {
		line := "dhcp-host=" + strings.ToLower(h.MAC) + "," + h.IP
		if h.Name != "" {
			line += "," + h.Name
		}
		if l := hostLease(c, h.MAC); l != "" {
			line += "," + l
		}
		b.WriteString(line + "\n")
	}
	if ra {
		b.WriteString("enable-ra\n")
	}
	for _, l := range dnsmasqExtra(c) {
		b.WriteString(l + "\n")
	}
	return b.String()
}

// renderRA: router advertisements (and DHCPv6) on one bridge. The prefix comes from whatever
// global address the bridge has (constructor:), i.e. the delegated prefix dhcpcd put there.
func renderRA(b *strings.Builder, bridge string, r RA) {
	raDefaults(&r)
	switch r.Mode {
	case "stateless":
		fmt.Fprintf(b, "dhcp-range=::,constructor:%s,ra-stateless,%s\n", bridge, r.Lease)
	case "stateful":
		// "slaac" keeps the A flag so clients without DHCPv6 (Android) still get an address
		fmt.Fprintf(b, "dhcp-range=%s,%s,constructor:%s,slaac,64,%s\n", r.Start, r.End, bridge, r.Lease)
	default:
		fmt.Fprintf(b, "dhcp-range=::,constructor:%s,ra-only,%s\n", bridge, r.Lease)
	}
	param := bridge + ","
	if r.MTU > 0 {
		param += fmt.Sprintf("mtu:%d,", r.MTU)
	}
	if r.Priority != "" {
		param += r.Priority + ","
	}
	fmt.Fprintf(b, "ra-param=%s%d,%d\n", param, r.Interval, r.Lifetime)
	if len(r.DNS) > 0 {
		var a []string
		for _, d := range r.DNS {
			a = append(a, "["+d+"]")
		}
		// every DHCP/RA request is tagged with the interface it arrived on
		fmt.Fprintf(b, "dhcp-option=tag:%s,option6:dns-server,%s\n", bridge, strings.Join(a, ","))
	}
}

// hostLease: per-host lease override from dhcp.host_leases (keys compared case-insensitively).
func hostLease(c *Config, mac string) string {
	for k, v := range c.DHCP.HostLeases {
		if strings.EqualFold(k, mac) {
			return v
		}
	}
	return ""
}

// ntpHostnames: NTP servers from system.ntp that need a DNS lookup.
func ntpHostnames(c *Config) []string {
	var out []string
	for _, s := range c.System.NTP {
		if net.ParseIP(s) == nil && validDNSName(s) {
			out = append(out, s)
		}
	}
	return out
}

// dotBootstrap: plain-DNS servers used (only) for NTP names when every other query goes over DoT.
func dotBootstrap(c *Config) []string {
	if len(c.DNS.DoT.Bootstrap) > 0 {
		return c.DNS.DoT.Bootstrap
	}
	var out []string
	for _, s := range c.DNS.DoT.Servers {
		out = append(out, s.Address)
	}
	return dedup(out)
}

func renderStubby(c *Config) string {
	var b strings.Builder
	b.WriteString("# generated by mr from dns.dot — edit router.yaml instead\n")
	b.WriteString("resolution_type: GETDNS_RESOLUTION_STUB\n")
	b.WriteString("dns_transport_list:\n  - GETDNS_TRANSPORT_TLS\n")
	b.WriteString("tls_authentication: GETDNS_AUTHENTICATION_REQUIRED\n")
	b.WriteString("tls_min_version: GETDNS_TLS1_2\n")
	b.WriteString("tls_query_padding_blocksize: 128\n")
	b.WriteString("edns_client_subnet_private: 1\n")
	b.WriteString("round_robin_upstreams: 1\n")
	b.WriteString("idle_timeout: 10000\n")
	// getdns backs a failed upstream off for an hour by default; at boot TLS fails until NTP has set
	// the clock, so retry after a minute instead
	b.WriteString("tls_backoff_time: 60\n")
	// loopback only: dnsmasq is the only client
	fmt.Fprintf(&b, "listen_addresses:\n  - 127.0.0.1@%d\n", c.DNS.DoT.Port)
	b.WriteString("upstream_recursive_servers:\n")
	for _, s := range c.DNS.DoT.Servers {
		fmt.Fprintf(&b, "  - address_data: %s\n    tls_auth_name: \"%s\"\n", s.Address, s.Name)
		if s.Port != 0 && s.Port != 853 {
			fmt.Fprintf(&b, "    tls_port: %d\n", s.Port)
		}
	}
	return b.String()
}

// hostIn returns the address with host part n inside network nn (IPv4).
func hostIn(nn *net.IPNet, n int) string {
	base := nn.IP.Mask(nn.Mask).To4()
	ip := make(net.IP, 4)
	copy(ip, base)
	v := uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
	v += uint32(n)
	return net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v)).String()
}

// splitFile resolves a DNS split list by name; only files referenced by router.yaml are reachable.
func splitFile(name string) (string, bool) {
	c, err := loadConfig(ConfigPath, SecretsPath)
	if err != nil {
		return "", false
	}
	for _, s := range c.DNS.Split {
		if s.Name == name && s.DomainsFile != "" {
			return s.DomainsFile, true
		}
	}
	return "", false
}

var domainRe = lazyRegexp(`^[A-Za-z0-9_*.-]+$`)

func apiDNSList(r apiReq) apiResp {
	var in struct {
		Name    string `json:"name"`
		Content string `json:"content"`
		Save    bool   `json:"save"`
	}
	json.Unmarshal(r.body, &in)
	path, ok := splitFile(in.Name)
	if !ok {
		return errResp(404, "no split list %q", in.Name)
	}
	if !in.Save {
		return apiResp{body: map[string]any{"name": in.Name, "path": path, "content": readFile(path)}}
	}
	if r.method != "POST" {
		return errResp(405, "POST required")
	}
	var lines []string
	for _, l := range strings.Split(strings.ReplaceAll(in.Content, "\r", ""), "\n") {
		t := strings.TrimSpace(l)
		if t != "" && !strings.HasPrefix(t, "#") && !domainRe.MatchString(t) {
			return errResp(400, "bad domain line %q", t)
		}
		lines = append(lines, t)
	}
	data := strings.TrimRight(strings.Join(lines, "\n"), "\n") + "\n"
	if err := writeAtomic(path, []byte(data), 0644); err != nil {
		return errResp(500, "%v", err)
	}
	appendChangeLog("webui: dns split list " + in.Name + " saved")
	return apiResp{body: map[string]any{"ok": true}}
}

func init() {
	register(&Module{
		Name:     "dns",
		Prio:     30,
		Defaults: dnsDefaults,
		Validate: dnsValidate,
		Render: func(c *Config, out *Out) error {
			out.Add("/etc/resolv.conf", 0644, "nameserver 127.0.0.1\nsearch "+c.DHCP.Domain+"\n")
			split, err := renderSplit(c)
			if err != nil {
				return err
			}
			out.Add(GenDir+"/dns-split.servers", 0644, split)
			if _, _, err := dohBlocklist(c, true); err != nil {
				return err
			}
			adblockRender(c, out)
			out.Add("/etc/dnsmasq.conf", 0644, renderDnsmasq(c))
			if c.Services.Stubby.Enabled {
				out.Add(StubbyConf, 0644, renderStubby(c))
			}
			return nil
		},
		Nft: func(c *Config, hook string, n *Nft) {
			if hook == "defs" {
				sovereigntyNft(c, n)
			}
			if hook != "dstnat" || !c.DNS.Redirect {
				return
			}
			for _, ln := range c.LANNets() {
				ip, _, err := net.ParseCIDR(ln.IPv4)
				if err != nil {
					continue
				}
				for _, p := range []string{"udp", "tcp"} {
					n.W("iifname %q meta nfproto ipv4 %s dport 53 ip daddr != %s dnat ip to %s comment \"dns-redirect\"", ln.Bridge, p, ip, ip)
				}
			}
		},
		Services: func(c *Config) []string { return []string{"dnsmasq"} },
		Restart: func(path string) string {
			switch path {
			case "/etc/dnsmasq.conf", GenDir + "/dns-split.servers":
				return "dnsmasq"
			case StubbyConf:
				return "stubby"
			case adblockConf:
				return "dnsmasq"
			case "/etc/resolv.conf":
				return "-"
			}
			return ""
		},
		// stubby first: dnsmasq may forward to it as soon as it starts
		RestartOrder: []string{"stubby", "dnsmasq"},
		Verify:       dnsVerify,
		Status: func(c *Config, st map[string]any) {
			v4, _ := readLeases(c)
			st["leases"] = v4
		},
		API: map[string]func(r apiReq) apiResp{
			"dnslist":      apiDNSList,
			"dns.stats":    apiDNSStats,
			"dns.leases":   apiDNSLeases,
			"dns.release":  apiDNSRelease,
			"dns.querylog": apiDNSQueryLog,
			"dns.adblock":  apiDNSAdblock,
		},
		Commands: map[string]func(c *Config, args []string) error{
			"dns": dnsCommand,
		},
	})
}

var reDomain = lazyRegexp(`^[A-Za-z0-9]([A-Za-z0-9-]{0,62}\.)*[A-Za-z0-9-]{1,63}$`)

var (
	reLease    = lazyRegexp(`^([0-9]+[smhdw]?|infinite)$`)
	reLeaseV6  = lazyRegexp(`^([0-9]+[smhdw]|infinite)$`) // unit required: a bare number would read as a prefix length
	reHostname = lazyRegexp(`^[A-Za-z0-9]([A-Za-z0-9-]{0,62})$`)
	reOptTok   = lazyRegexp(`^[A-Za-z0-9._:/@+=-]{1,200}$`)
	// dhcp-host fields dnsmasq reads as a lease time or a keyword instead of a host name
	// ("12345", "5m", "infinite", "ignore" = never answer this MAC)
	reNotHostname = lazyRegexp(`^([0-9]+[smhdwSMHDW]?|infinite|ignore)$`)
)

// dhcpOptReserved: option numbers the router sets itself or that belong to the DHCP protocol.
var dhcpOptReserved = map[int]string{
	1: "netmask (from the network)", 3: "router (always this router)", 6: "use dns", 12: "hostname",
	15: "domain (dhcp.domain)", 42: "use ntp", 119: "use search",
	50: "protocol", 51: "lease time", 52: "protocol", 53: "protocol", 54: "protocol", 55: "protocol",
	56: "protocol", 57: "protocol", 58: "renewal time", 59: "rebinding time", 60: "protocol", 61: "protocol",
}

// validDNSName: a DNS name made of 1-63 character labels of letters, digits, '-' and '_'
// (underscore for SRV/TXT owner names), no leading/trailing '-' in a label, at most 253 chars.
func validDNSName(s string) bool {
	s = strings.TrimSuffix(s, ".")
	if s == "" || len(s) > 253 {
		return false
	}
	for _, l := range strings.Split(s, ".") {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for i := 0; i < len(l); i++ {
			ch := l[i]
			if !(ch == '-' || ch == '_' || ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z') {
				return false
			}
		}
	}
	return true
}

// validServer: dnsmasq upstream "ip" or "ip#port".
func validServer(s string) bool {
	host, port, hasPort := strings.Cut(s, "#")
	if net.ParseIP(host) == nil {
		return false
	}
	if hasPort {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
			return false
		}
	}
	return true
}

// serverLoops reports whether an upstream points back at dnsmasq itself: port 53 on loopback
// (127.0.0.0/8, ::1) or on the router's own address in a LAN-side network (bind-dynamic listens there).
func serverLoops(c *Config, s string) bool {
	host, port, _ := strings.Cut(s, "#")
	ip := net.ParseIP(host)
	if ip == nil || (port != "" && port != "53") {
		return false
	}
	if ip.IsLoopback() {
		return true
	}
	for _, n := range c.LANNets() {
		if rip, _, err := net.ParseCIDR(n.IPv4); err == nil && rip.Equal(ip) {
			return true
		}
	}
	return false
}

func isIPv4(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.To4() != nil && !strings.Contains(s, ":")
}

func isIPv6(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && strings.Contains(s, ":") && ip.To4() == nil
}

// dnsUpstreamLines: where dnsmasq forwards queries it cannot answer locally. Shared by the main
// dnsmasq and the proxy module's second instance so both always use the same upstreams.
//
//	isp    — the nameservers of every WAN that is up, kept by the net hooks in one resolv file
//	         (healthy WAN first); falls back to pppd's own file when no WAN supplies DNS
//	manual — dns.servers
//	dot    — stubby on 127.0.0.1, with plain-DNS bootstrap for the NTP host names
func dnsUpstreamLines(c *Config) []string {
	var out []string
	switch c.DNS.Upstream {
	case "manual":
		out = append(out, "no-resolv")
		for _, s := range c.DNS.Servers {
			out = append(out, "server="+s)
		}
	case "dot":
		out = append(out, "no-resolv", fmt.Sprintf("server=127.0.0.1#%d", c.DNS.DoT.Port))
		// TLS needs a correct clock and the clock needs NTP: NTP host names resolve over plain DNS
		for _, h := range ntpHostnames(c) {
			for _, s := range dotBootstrap(c) {
				out = append(out, fmt.Sprintf("server=/%s/%s", h, s))
			}
		}
	default:
		// dnsmasq polls every resolv file and uses the newest: pppd's own file covers the moments
		// before the net hooks have written the merged one (e.g. right after boot or an upgrade)
		out = append(out, "resolv-file="+ResolvPPP)
		if wanDNSFromPeers(c) {
			out = append(out, "resolv-file="+resolvConf)
		}
	}
	return out
}

func dnsValidate(c *Config, v *Validator) {
	if c.DHCP.Start < 2 || c.DHCP.End > 254 || c.DHCP.Start > c.DHCP.End {
		v.Add("dhcp: start/end must be 2..254 with start<=end, got %d-%d", c.DHCP.Start, c.DHCP.End)
	}
	if !reDomain.MatchString(c.DHCP.Domain) {
		v.Add("dhcp.domain: invalid %q", c.DHCP.Domain)
	}
	if !reLease.MatchString(c.DHCP.Lease) {
		v.Add("dhcp.lease: e.g. 12h, 30m, 1d or infinite, got %q", c.DHCP.Lease)
	}
	validOpts(v, "dhcp", c.DHCP.DHCPOpts)
	validRA(v, "dhcp.ipv6", c.DHCP.IPv6)
	ips := map[string]bool{}
	macs := map[string]bool{}
	for i, h := range c.DHCP.Hosts {
		p := fmt.Sprintf("dhcp.hosts[%d]", i)
		if !reMAC.MatchString(h.MAC) {
			v.Add("%s.mac: invalid %q", p, h.MAC)
		}
		macs[strings.ToLower(h.MAC)] = true
		if h.Name != "" && !reHostname.MatchString(h.Name) {
			v.Add("%s.name: letters, digits, '-' only, got %q", p, h.Name)
		} else if reNotHostname.MatchString(h.Name) {
			v.Add("%s.name: dnsmasq would read %q as a lease time / keyword, not a name", p, h.Name)
		}
		t := net.ParseIP(h.IP)
		inside := false
		for _, ln := range c.LANNets() {
			if _, nn, err := net.ParseCIDR(ln.IPv4); err == nil && t != nil && nn.Contains(t) {
				inside = true
			}
		}
		if t == nil || t.To4() == nil || !inside {
			v.Add("%s.ip: must be inside %s or another network, got %q", p, c.LAN.IPv4, h.IP)
		}
		if ips[h.IP] {
			v.Add("%s.ip: duplicate %s", p, h.IP)
		}
		ips[h.IP] = true
	}
	for mac, l := range c.DHCP.HostLeases {
		if !macs[strings.ToLower(mac)] {
			v.Add("dhcp.host_leases: %q is not the MAC of a dhcp.hosts entry", mac)
		}
		if !reLease.MatchString(l) {
			v.Add("dhcp.host_leases[%s]: e.g. 12h, 30m, 1d or infinite, got %q", mac, l)
		}
	}
	for i, n := range c.Networks {
		d := n.DHCP
		validRA(v, fmt.Sprintf("networks[%d].dhcp.ipv6", i), d.IPv6)
		if !d.Enabled {
			continue
		}
		p := fmt.Sprintf("networks[%d].dhcp", i)
		_, nn, err := net.ParseCIDR(n.IPv4)
		size := 0
		if err == nil {
			ones, bits := nn.Mask.Size()
			size = 1<<(bits-ones) - 1
		}
		if d.Start < 1 || d.End >= size || d.Start > d.End {
			v.Add("%s: start/end must be host numbers inside %s with start<=end", p, n.IPv4)
		}
		if !reLease.MatchString(d.Lease) {
			v.Add("%s.lease: invalid %q", p, d.Lease)
		}
		validOpts(v, p, d.DHCPOpts)
	}
	validUpstream(c, v)
	for i, sp := range c.DNS.Split {
		p := fmt.Sprintf("dns.split[%d]", i)
		if !reLabel.MatchString(sp.Name) {
			v.Add("%s.name: invalid %q", p, sp.Name)
		}
		if !rePath.MatchString(sp.DomainsFile) {
			v.Add("%s.domains_file: absolute path required, got %q", p, sp.DomainsFile)
		}
		switch {
		case !validServer(sp.Server):
			v.Add("%s.server: ip[#port], got %q", p, sp.Server)
		case serverLoops(c, sp.Server):
			v.Add("%s.server: %s is dnsmasq itself", p, sp.Server)
		case sp.Server == fmt.Sprintf("127.0.0.1#%d", c.DNS.DoT.Port) && !c.Services.Stubby.Enabled:
			v.Add("%s.server: %s is stubby (DoT) but services.stubby is disabled", p, sp.Server)
		}
	}
	validRecords(c, v)
	sovereigntyValidate(c, v)
	adblockValidate(c, v)
	for _, h := range c.DNS.AddnHosts {
		if !rePath.MatchString(h) {
			v.Add("dns.addn_hosts: absolute path required, got %q", h)
		}
	}
	if c.DNS.ServersFile != "" && !rePath.MatchString(c.DNS.ServersFile) {
		v.Add("dns.servers_file: absolute path required, got %q", c.DNS.ServersFile)
	}
	if c.DNS.CacheSize < 0 || c.DNS.CacheSize > 100000 {
		v.Add("dns.cache_size: 0-100000, got %d", c.DNS.CacheSize)
	}
	if c.DNS.MinTTL < 0 || c.DNS.MinTTL > 3600 {
		v.Add("dns.min_cache_ttl: 0-3600 (dnsmasq limit), got %d", c.DNS.MinTTL)
	}
	if c.DNS.StaleCache < 0 || c.DNS.EDNS < 0 || c.DNS.EDNS > 65535 {
		v.Add("dns.use_stale_cache / edns_packet_max: out of range")
	}
}

func validOpts(v *Validator, p string, o DHCPOpts) {
	if len(o.DNS) > 8 || len(o.NTP) > 8 || len(o.Search) > 8 || len(o.Options) > 32 {
		v.Add("%s: too many dns/ntp/search/options entries", p)
	}
	for _, s := range o.DNS {
		if !isIPv4(s) {
			v.Add("%s.dns: IPv4 address required, got %q", p, s)
		}
	}
	for _, s := range o.NTP {
		if !isIPv4(s) {
			v.Add("%s.ntp: IPv4 address required (DHCP option 42 carries addresses), got %q", p, s)
		}
	}
	for _, s := range o.Search {
		if !reDomain.MatchString(s) {
			v.Add("%s.search: invalid domain %q", p, s)
		}
	}
	seen := map[int]bool{}
	for i, x := range o.Options {
		q := fmt.Sprintf("%s.options[%d]", p, i)
		if x.Code < 1 || x.Code > 254 {
			v.Add("%s.code: 1-254, got %d", q, x.Code)
		} else if why, bad := dhcpOptReserved[x.Code]; bad {
			v.Add("%s.code: option %d cannot be set here (%s)", q, x.Code, why)
		}
		if seen[x.Code] {
			v.Add("%s.code: duplicate option %d", q, x.Code)
		}
		seen[x.Code] = true
		toks := strings.Split(x.Value, ",")
		if len(x.Value) > 250 {
			v.Add("%s.value: too long", q)
		}
		// RFC 3442: a client that gets classless static routes ignores the router option
		if (x.Code == 121 || x.Code == 249) && toks[0] != "0.0.0.0/0" {
			v.Add("%s.value: option %d must start with the default route 0.0.0.0/0,<router> (clients then ignore option 3)", q, x.Code)
		}
		for _, t := range toks {
			if !reOptTok.MatchString(t) {
				v.Add("%s.value: comma-separated tokens of letters, digits and . _ : / @ + = - only, got %q", q, x.Value)
				break
			}
		}
	}
}

func validRA(v *Validator, p string, r RA) {
	switch r.Mode {
	case "", "slaac", "stateless", "stateful":
	default:
		v.Add("%s.mode: slaac|stateless|stateful, got %q", p, r.Mode)
	}
	if r.Lease != "" && !reLeaseV6.MatchString(r.Lease) {
		v.Add("%s.lease: e.g. 12h, 1d or infinite (unit required), got %q", p, r.Lease)
	}
	if r.Mode == "stateful" || r.Start != "" || r.End != "" {
		s, e := ifaceID(r.Start), ifaceID(r.End)
		if s == nil || e == nil {
			v.Add("%s.start/end: interface ids like ::1000 and ::ffff (the prefix comes from the WAN), got %q-%q", p, r.Start, r.End)
		} else if string(s) > string(e) {
			v.Add("%s: start must not be above end", p)
		}
	}
	if len(r.DNS) > 8 {
		v.Add("%s.dns: at most 8 servers", p)
	}
	for _, d := range r.DNS {
		if !isIPv6(d) {
			v.Add("%s.dns: IPv6 address required (\"::\" = the router), got %q", p, d)
		}
	}
	if r.Interval != 0 && (r.Interval < 4 || r.Interval > 1800) {
		v.Add("%s.ra_interval: 4-1800 seconds, got %d", p, r.Interval)
	}
	if r.Lifetime != 0 && (r.Lifetime < 60 || r.Lifetime > 9000 || r.Lifetime < r.Interval) {
		v.Add("%s.ra_lifetime: 60-9000 seconds and not below ra_interval, got %d", p, r.Lifetime)
	}
	switch r.Priority {
	case "", "high", "low":
	default:
		v.Add("%s.ra_priority: high|low or empty (medium), got %q", p, r.Priority)
	}
	if r.MTU != 0 && (r.MTU < 1280 || r.MTU > 9000) {
		v.Add("%s.ra_mtu: 1280-9000 or 0, got %d", p, r.MTU)
	}
}

// ifaceID parses "::1000" style interface identifiers (upper 64 bits must be zero).
func ifaceID(s string) net.IP {
	ip := net.ParseIP(s)
	if ip == nil || !strings.Contains(s, ":") || ip.To4() != nil {
		return nil
	}
	for _, x := range ip[:8] {
		if x != 0 {
			return nil
		}
	}
	return ip
}

func validUpstream(c *Config, v *Validator) {
	d := c.DNS
	switch d.Upstream {
	case "isp":
	case "manual":
		if len(d.Servers) == 0 {
			v.Add("dns.servers: upstream manual needs at least one server")
		}
	case "dot":
		if !c.Services.Stubby.Enabled {
			v.Add("dns.upstream: dot needs services.stubby.enabled")
		}
	default:
		v.Add("dns.upstream: isp|manual|dot, got %q", d.Upstream)
	}
	if len(d.Servers) > 16 {
		v.Add("dns.servers: at most 16")
	}
	for _, s := range d.Servers {
		if !validServer(s) {
			v.Add("dns.servers: ip[#port], got %q", s)
		} else if serverLoops(c, s) {
			v.Add("dns.servers: %s is dnsmasq itself", s)
		}
	}
	if d.DoT.Port < 1 || d.DoT.Port > 65535 || d.DoT.Port == 53 {
		v.Add("dns.dot.port: 1-65535 and not 53 (dnsmasq), got %d", d.DoT.Port)
	}
	if len(d.DoT.Servers) > 8 {
		v.Add("dns.dot.servers: at most 8")
	}
	for i, s := range d.DoT.Servers {
		p := fmt.Sprintf("dns.dot.servers[%d]", i)
		if net.ParseIP(s.Address) == nil {
			v.Add("%s.address: IP address required, got %q", p, s.Address)
		}
		if !validDNSName(s.Name) || strings.Contains(s.Name, "_") {
			v.Add("%s.name: TLS host name required (e.g. cloudflare-dns.com), got %q", p, s.Name)
		}
		if s.Port < 0 || s.Port > 65535 {
			v.Add("%s.port: 1-65535 (default 853), got %d", p, s.Port)
		}
	}
	for _, s := range d.DoT.Bootstrap {
		if !validServer(s) || serverLoops(c, s) {
			v.Add("dns.dot.bootstrap: ip[#port] of a plain DNS server, got %q", s)
		}
	}
}
