package main

// sys module: HTTPS reverse proxy with automatic certificates (services.edge, Cd1s/mini-router#6) —
// the built-in replacement for lucky's "443 + SSL" reverse proxy.
//
//	mr edge serve   the only resident part, run by the OpenRC service mr-edge while services.edge is on:
//	                terminates TLS (1.2+, HTTP/1.1 and HTTP/2) for the route hosts and proxies each to one
//	                LAN service (mod_sys_edge_serve.go). Unprivileged (user mr-edge + CAP_NET_BIND_SERVICE)
//	                when the image has that user; it reads only gen/edge.json (no secrets) and its
//	                certificates, never router.yaml / secrets.yaml.
//	mr edge renew   short-lived (crond once a day, after an apply that needs a certificate, the web UI's
//	                立即申请): Let's Encrypt over ACME (RFC 8555) with DNS-01 through the Cloudflare API —
//	                the DDNS client's code and token kind (mod_sys_edge_acme.go). No port 80 is needed.
//
// Which side a connection came from is decided by the listener, not by address lists: WAN connections
// (services.edge.open) are redirected by nftables from the WANs' port to edgeWANPort, so everything on
// the main port came through the LAN zone (the LAN networks of zone lan, tailscale0) — `allow: [lan]`
// cannot be spoofed from outside. That is also why a firewall.open of the same port is refused.
//
// Files: /etc/mini-router/gen/edge.json (routes, rendered), /etc/mini-router/state/edge/<cert>.pem
// (chain + private key, 0600, owned by the service user; flash), /etc/mini-router/state/acme/ (ACME
// account keys, 0700 root), /run/mr-edge/status.json (the serving process: pid, requests),
// /run/mini-router/edge-renew.json (renewal results; tmpfs). Docs: docs/modules/sys.md (反向代理).

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Edge is services.edge.
type Edge struct {
	Enabled bool `yaml:"enabled"`
	// Port: HTTPS on every router address (default 443). From the WANs only with Open.
	Port int `yaml:"port,omitempty"`
	// Open: also accept the port from the WANs (IPv4 + IPv6). Off: LAN zone and tailscale only.
	Open bool `yaml:"open,omitempty"`
	// LANDNS: the route hosts resolve to the router's LAN address in dnsmasq (default true), so the LAN
	// reaches them without the public address (and while the WAN is down).
	LANDNS *bool       `yaml:"lan_dns,omitempty"`
	ACME   EdgeACME    `yaml:"acme,omitempty"`
	Routes []EdgeRoute `yaml:"routes,omitempty"`
}

// EdgeACME: where the certificates come from (Let's Encrypt, DNS-01).
type EdgeACME struct {
	Email    string `yaml:"email,omitempty"`    // optional ACME account contact
	Provider string `yaml:"provider,omitempty"` // DNS-01 through: cloudflare (default)
	Token    string `yaml:"token_secret"`       // secrets.yaml key of the API token (Zone › DNS › Edit)
	Staging  bool   `yaml:"staging,omitempty"`  // Let's Encrypt's staging CA (untrusted certificates, for tests)
	// Wildcard: domains that get one certificate for domain + *.domain, used by the routes directly
	// under them (their names never appear in the certificate transparency logs). Other hosts: one each.
	Wildcard []string `yaml:"wildcard,omitempty"`
}

// EdgeRoute: one host name proxied to one LAN service.
type EdgeRoute struct {
	Name    string   `yaml:"name"`
	Enabled *bool    `yaml:"enabled,omitempty"` // default true
	Host    string   `yaml:"host"`              // nas.example.com
	To      string   `yaml:"to"`                // http://192.168.1.10:5000 or https://…:5001 (not verified)
	Allow   []string `yaml:"allow,omitempty"`   // lan and / or CIDRs; empty = everyone who reaches the port
	Desc    string   `yaml:"desc,omitempty"`
}

const (
	edgeDefaultPort = 443
	// edgeWANPort: where nftables redirects the WANs' connections (services.edge.open); the serving
	// process treats everything on this listener as coming from the WAN.
	edgeWANPort   = 44300
	edgeMaxRoutes = 32
	edgeMaxAllow  = 32
	edgeUser      = "mr-edge" // the service user, when the image has it (build/m3/build-rootfs.sh)
)

// paths (variables so tests can use a temp dir)
var (
	edgeConfFile  = GenDir + "/edge.json"
	edgeCertDir   = "/etc/mini-router/state/edge"
	edgeAcctDir   = "/etc/mini-router/state/acme"
	edgeRunDir    = "/run/mr-edge"
	edgeStateFile = RunDir + "/edge-renew.json"
	edgeLockFile  = RunDir + "/edge-renew.lock"
	edgeNow       = time.Now
	// edgeKick starts a background `mr edge renew --hook` unless a renewal is running.
	edgeKick = func() {
		if f := ddnsTryLock(edgeLockFile); f != nil {
			f.Close()
			self, args := selfCmd("edge", "renew", "--hook")
			startDetached(self, args...)
		}
	}
)

func edgeOn(c *Config) bool { return c.Services.Edge.Enabled }

// edgeRoutes: the enabled routes.
func edgeRoutes(c *Config) []EdgeRoute {
	var out []EdgeRoute
	for _, r := range c.Services.Edge.Routes {
		if on(r.Enabled) {
			out = append(out, r)
		}
	}
	return out
}

func edgeLANDNS(c *Config) bool { return c.Services.Edge.LANDNS == nil || *c.Services.Edge.LANDNS }

func edgeDefaults(c *Config) {
	e := &c.Services.Edge
	if !e.Enabled && len(e.Routes) == 0 { // an absent section stays absent (plan / history)
		return
	}
	if e.Port == 0 {
		e.Port = edgeDefaultPort
	}
	if e.ACME.Provider == "" {
		e.ACME.Provider = "cloudflare"
	}
}

// edgeCert: one certificate the routes need.
type edgeCert struct {
	Name    string   `json:"name"`    // file name: the host, or "_.example.com" for example.com + *.example.com
	Domains []string `json:"domains"` // subject alternative names, the first one is also the subject
}

// edgeCertFor: the certificate that covers host (a wildcard domain it sits directly under, else its own).
func edgeCertFor(a EdgeACME, host string) edgeCert {
	host = strings.ToLower(host)
	for _, w := range a.Wildcard {
		w = strings.ToLower(strings.TrimSuffix(w, "."))
		if sub, ok := strings.CutSuffix(host, "."+w); host == w || ok && !strings.Contains(sub, ".") {
			return edgeCert{Name: "_." + w, Domains: []string{w, "*." + w}}
		}
	}
	return edgeCert{Name: host, Domains: []string{host}}
}

// edgeCerts: every certificate the enabled routes need, in route order.
func edgeCerts(c *Config) []edgeCert {
	var out []edgeCert
	seen := map[string]bool{}
	for _, r := range edgeRoutes(c) {
		ct := edgeCertFor(c.Services.Edge.ACME, r.Host)
		if !seen[ct.Name] {
			seen[ct.Name] = true
			out = append(out, ct)
		}
	}
	return out
}

// ---- validation (the security boundary: hosts go into dnsmasq.conf and file names, targets into the proxy) ----

var (
	reEdgeEmail = lazyRegexp(`^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,190}$`)
	reEdgeHost  = lazyRegexp(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$`)
)

// edgeHostOK: a lower-case host name with at least one dot, no wildcard, no underscore.
func edgeHostOK(h string) bool {
	return reEdgeHost.MatchString(h) && validDNSName(h) && strings.Contains(h, ".") && !strings.Contains(h, "..")
}

// edgeTarget parses a route's `to`: http(s)://IP[:port][/] (an IPv6 address in brackets).
func edgeTarget(s string) (scheme string, ip netip.Addr, port int, err error) {
	bad := func(why string) (string, netip.Addr, int, error) {
		return "", netip.Addr{}, 0, fmt.Errorf("http://IP:port or https://IP:port (%s), got %q", why, s)
	}
	if !safeText(s) || len(s) > 200 {
		return bad("printable, at most 200 characters")
	}
	u, perr := url.Parse(s)
	if perr != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Opaque != "" {
		return bad("scheme http or https")
	}
	if u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery {
		return bad("no user, path or query")
	}
	ip, perr = netip.ParseAddr(u.Hostname())
	if perr != nil || ip.Zone() != "" || ip.Is4In6() {
		return bad("the host must be an IP address")
	}
	port = 80
	if u.Scheme == "https" {
		port = 443
	}
	if p := u.Port(); p != "" {
		n, perr := strconv.Atoi(p)
		if perr != nil || n < 1 || n > 65535 || strconv.Itoa(n) != p {
			return bad("port 1-65535")
		}
		port = n
	}
	return u.Scheme, ip, port, nil
}

// edgeTargetOK: a target must be the router itself (loopback, a router address), a host inside a
// LAN-side network, a tailnet peer (100.64/10) or an IPv6 ULA — never an arbitrary internet host.
func edgeTargetOK(c *Config, ip netip.Addr) bool {
	if ip.IsLoopback() {
		return true
	}
	if ip.Is6() {
		return netip.MustParsePrefix("fc00::/7").Contains(ip) // ULA
	}
	if netip.MustParsePrefix("100.64.0.0/10").Contains(ip) { // tailnet peers
		return true
	}
	for _, ln := range c.LANNets() {
		if p, err := netip.ParsePrefix(ln.IPv4); err == nil && p.Masked().Contains(ip) {
			return true
		}
	}
	return false
}

// edgeToRouter: whether a target is the router itself.
func edgeToRouter(c *Config, ip netip.Addr) bool {
	return ip.IsLoopback() || ip.IsUnspecified() || c.isRouterAddr(ip.String())
}

// edgeAllow parses an allow list: "lan" and CIDRs / addresses (normalized to CIDRs).
func edgeAllow(list []string) (lan bool, nets []netip.Prefix, err error) {
	for _, a := range list {
		if a == "lan" {
			lan = true
			continue
		}
		p, perr := netip.ParsePrefix(a)
		if perr != nil {
			ip, ierr := netip.ParseAddr(a)
			if ierr != nil || ip.Zone() != "" {
				return false, nil, fmt.Errorf("lan or an address / CIDR, got %q", a)
			}
			p = netip.PrefixFrom(ip, ip.BitLen())
		}
		if p.Addr().Zone() != "" || p.Addr().Is4In6() {
			return false, nil, fmt.Errorf("lan or an address / CIDR, got %q", a)
		}
		nets = append(nets, p.Masked())
	}
	return lan, nets, nil
}

// edgeReservedPort: why port cannot be the edge's HTTPS port ("" = free as far as mr knows).
func edgeReservedPort(c *Config, port int) string {
	sv := c.Services
	switch {
	case port == sv.SSH.Port || port == 22:
		return "SSH"
	case port == 80:
		return "the web UI (busybox httpd)"
	case port == 53 || port == 67 || port == 123 || port == 547:
		return "DNS / DHCP / NTP"
	case port == edgeWANPort:
		return "the edge's internal WAN port"
	case sv.Lucky.Enabled && port == sv.Lucky.Port:
		return "lucky's web UI"
	}
	return ""
}

func validateEdge(c *Config, v *Validator) {
	e := c.Services.Edge
	const p = "services.edge"
	if !e.Enabled && len(e.Routes) == 0 {
		return
	}
	if e.Port < 1 || e.Port > 65535 {
		v.Add("%s.port: 1-65535, got %d", p, e.Port)
	} else if why := edgeReservedPort(c, e.Port); why != "" {
		v.Add("%s.port: %d is used by %s", p, e.Port, why)
	}
	if e.Enabled && len(edgeRoutes(c)) == 0 {
		v.Add("%s: enabled without routes", p)
	}
	// the main port must only be reachable through the LAN zone (see the file comment)
	for _, o := range c.Firewall.Open {
		if on(o.Enabled) && e.Enabled && portIn(o.Port, e.Port) && slicesHas(o.Proto, "tcp") {
			v.Add("%s: firewall.open[%s] opens tcp %d to the WAN; remove it and set services.edge.open: true (WAN connections must reach the proxy through its WAN listener)", p, o.Name, e.Port)
		}
	}
	if e.Open && e.Enabled {
		for _, f := range c.Firewall.Forwards {
			if on(f.Enabled) && portIn(f.Port, e.Port) && slicesHas(f.Proto, "tcp") {
				v.Add("%s.open: firewall.forwards[%s] already forwards tcp %d from the WAN", p, f.Name, e.Port)
			}
		}
	}
	a := e.ACME
	if a.Provider != "cloudflare" {
		v.Add("%s.acme.provider: cloudflare, got %q", p, a.Provider)
	}
	if a.Email != "" {
		_, dom, _ := strings.Cut(a.Email, "@")
		if !reEdgeEmail.MatchString(a.Email) || !validDNSName(dom) || !strings.Contains(dom, ".") {
			v.Add("%s.acme.email: an e-mail address (or empty), got %q", p, a.Email)
		}
	}
	if e.Enabled || a.Token != "" {
		if !reDDNSSecret.MatchString(a.Token) {
			v.Add("%s.acme.token_secret: secret name [a-z0-9_-]{1,40} required (a Cloudflare API token with Zone › DNS › Edit), got %q", p, a.Token)
		} else if tok, err := c.Secret(a.Token); err != nil {
			v.Add("%s.acme.token_secret: %v", p, err)
		} else if !reDDNSToken.MatchString(tok) {
			v.Add("%s.acme.token_secret: the secret is not an API token (20-256 letters, digits, - _ . ~ + / =)", p)
		}
	}
	if len(a.Wildcard) > 8 {
		v.Add("%s.acme.wildcard: at most 8 domains", p)
	}
	seenW := map[string]bool{}
	for _, w := range a.Wildcard {
		if !edgeHostOK(w) {
			v.Add("%s.acme.wildcard: a lower-case domain like example.com, got %q", p, w)
		} else if seenW[w] {
			v.Add("%s.acme.wildcard: duplicate %q", p, w)
		}
		seenW[w] = true
	}
	if len(e.Routes) > edgeMaxRoutes {
		v.Add("%s.routes: at most %d", p, edgeMaxRoutes)
	}
	names, hosts := map[string]bool{}, map[string]bool{}
	for i, r := range e.Routes {
		rp := fmt.Sprintf("%s.routes[%d]", p, i)
		if reLabel.MatchString(r.Name) {
			rp = fmt.Sprintf("%s.routes[%s]", p, r.Name)
		}
		fwCheckName(v, rp, r.Name, names)
		fwCheckDesc(v, rp, r.Desc)
		if !edgeHostOK(r.Host) {
			v.Add("%s.host: a lower-case host name like nas.example.com (no wildcard), got %q", rp, r.Host)
		} else if hosts[r.Host] {
			v.Add("%s.host: duplicate %q", rp, r.Host)
		}
		hosts[r.Host] = true
		_, ip, port, err := edgeTarget(r.To)
		switch {
		case err != nil:
			v.Add("%s.to: %v", rp, err)
		case !edgeTargetOK(c, ip):
			v.Add("%s.to: %s is not the router, a host in a LAN-side network, a tailnet address or an IPv6 ULA", rp, ip)
		case edgeToRouter(c, ip) && (port == e.Port || port == edgeWANPort):
			v.Add("%s.to: the proxy itself (a loop)", rp)
		}
		if len(r.Allow) > edgeMaxAllow {
			v.Add("%s.allow: at most %d entries", rp, edgeMaxAllow)
		}
		if _, _, err := edgeAllow(r.Allow); err != nil {
			v.Add("%s.allow: %v", rp, err)
		}
	}
}

func slicesHas(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

// edgeWANReachable: whether a route can be used from the WAN (the port is open and its allow list
// is not LAN-only).
func edgeWANReachable(c *Config, r EdgeRoute) bool {
	if !c.Services.Edge.Open {
		return false
	}
	lan, nets, _ := edgeAllow(r.Allow)
	return len(nets) > 0 || !lan
}

// edgeGuard: guard.never_expose — a route that the WAN can use must not lead to one of the router's
// own guarded ports (the proxy would expose the web UI / SSH / DNS). Called by guardValidate.
func edgeGuard(c *Config, v *Validator, svc string, ports []int) {
	if !edgeOn(c) {
		return
	}
	for _, r := range edgeRoutes(c) {
		_, ip, port, err := edgeTarget(r.To)
		if err != nil || !edgeToRouter(c, ip) || !edgeWANReachable(c, r) {
			continue
		}
		for _, gp := range ports {
			if port == gp {
				v.Add("guard.never_expose: services.edge.routes[%s] makes the router's port %d (%s) reachable from the WAN (use allow: [lan])", r.Name, gp, svc)
			}
		}
	}
}

// ---- render ----

// edgeConf is gen/edge.json: everything `mr edge serve` needs, and nothing secret.
type edgeConf struct {
	Port    int             `json:"port"`
	WANPort int             `json:"wan_port,omitempty"` // 0: not open to the WANs
	Certs   string          `json:"certs"`
	Routes  []edgeConfRoute `json:"routes"`
}

type edgeConfRoute struct {
	Name  string   `json:"name"`
	Host  string   `json:"host"`
	To    string   `json:"to"`
	Cert  string   `json:"cert"`
	Allow []string `json:"allow,omitempty"` // "lan" and CIDRs; empty = everyone
}

func edgeConfOf(c *Config) edgeConf {
	e := c.Services.Edge
	ec := edgeConf{Port: e.Port, Certs: edgeCertDir, Routes: []edgeConfRoute{}}
	if e.Open {
		ec.WANPort = edgeWANPort
	}
	for _, r := range edgeRoutes(c) {
		lan, nets, _ := edgeAllow(r.Allow)
		var allow []string
		if lan {
			allow = append(allow, "lan")
		}
		for _, n := range nets {
			allow = append(allow, n.String())
		}
		ec.Routes = append(ec.Routes, edgeConfRoute{Name: r.Name, Host: r.Host, To: r.To,
			Cert: edgeCertFor(e.ACME, r.Host).Name, Allow: allow})
	}
	return ec
}

func edgeRender(c *Config, out *Out) {
	if !edgeOn(c) {
		return
	}
	b, _ := json.MarshalIndent(edgeConfOf(c), "", " ")
	out.Add(edgeConfFile, 0644, string(b)+"\n")
}

// edgeNft: with open, the WANs' connections to the port are redirected to the WAN listener (only for
// the router's own addresses: IPv6 pinholes to LAN hosts on the same port are untouched) and accepted
// there; nothing else from the WAN reaches either port.
func edgeNft(c *Config, hook string, n *Nft) {
	e := c.Services.Edge
	wans := c.WANIfnames()
	if !edgeOn(c) || !e.Open || len(wans) == 0 {
		return
	}
	switch hook {
	case "input":
		n.W("iifname { %s } tcp dport %d ct status dnat accept comment \"edge\"", quoteList(wans), edgeWANPort)
	case "dstnat":
		n.W("iifname { %s } fib daddr type local tcp dport %d redirect to :%d comment \"edge\"", quoteList(wans), e.Port, edgeWANPort)
	}
}

// edgeDnsmasq: the route hosts resolve to the main LAN address on the LAN (A only; AAAA queries get no
// answer, so clients use IPv4 to the router).
func edgeDnsmasq(c *Config) []string {
	ip, _, ok := strings.Cut(c.LAN.IPv4, "/")
	if !edgeOn(c) || !edgeLANDNS(c) || !ok {
		return nil
	}
	var out []string
	for _, r := range edgeRoutes(c) {
		out = append(out, fmt.Sprintf("host-record=%s,%s", r.Host, ip))
	}
	return out
}

// edgeCronLine: the daily renewal check, at a minute and hour (02:00-05:59) fixed per router.
func edgeCronLine(c *Config) []string {
	if !edgeOn(c) {
		return nil
	}
	h := fnv.New32a()
	h.Write([]byte(c.System.Hostname + "|" + c.Services.Edge.ACME.Email))
	n := h.Sum32()
	return []string{"# edge certificates (services.edge)", fmt.Sprintf("%d %d * * * %s edge renew --cron", n%60, 2+(n/60)%4, mrBin)}
}

// ---- Verify ----

// edgeVerify: after mr-edge (re)started, its status file must name the rendered config and a live
// process within 30 s (a port another program holds makes it exit and respawn instead). A missing or
// due certificate starts a background renewal (never fails the apply).
func edgeVerify(c *Config, restarted []string) []string {
	if !edgeOn(c) {
		return nil
	}
	if edgeAnyDue(c) {
		edgeKick()
	}
	if !slicesHas(restarted, "mr-edge") {
		return nil
	}
	want := edgeConfHash(readFile(edgeConfFile))
	ok := waitFor(time.Now().Add(30*time.Second), func() bool {
		st, err := edgeReadRun()
		return err == nil && st.Conf == want && pidAlive(st.PID)
	})
	if !ok {
		return []string{fmt.Sprintf("mr-edge: not serving on port %d (port in use by another program? see /var/log/messages)", c.Services.Edge.Port)}
	}
	return nil
}

func edgeConfHash(data string) string {
	h := sha256.Sum256([]byte(data))
	return hex.EncodeToString(h[:8])
}

func pidAlive(pid int) bool {
	return pid > 0 && syscall.Kill(pid, 0) == nil
}

// ---- status of the serving process (written by `mr edge serve`) ----

type edgeRouteStat struct {
	Requests int64 `json:"requests"`
	Errors   int64 `json:"errors"` // upstream unreachable / failed (502)
	Denied   int64 `json:"denied"` // allow list, Host ≠ SNI
}

type edgeRun struct {
	PID     int                      `json:"pid"`
	Started int64                    `json:"started"`
	Updated int64                    `json:"updated"`
	Conf    string                   `json:"conf"` // hash of the edge.json it serves
	Port    int                      `json:"port"`
	WANPort int                      `json:"wan_port,omitempty"`
	Routes  map[string]edgeRouteStat `json:"routes"`
}

func edgeReadRun() (edgeRun, error) {
	var st edgeRun
	b, err := os.ReadFile(edgeRunDir + "/status.json")
	if err != nil {
		return st, err
	}
	if err := json.Unmarshal(b, &st); err != nil {
		return st, errors.New("status.json: " + err.Error())
	}
	return st, nil
}
