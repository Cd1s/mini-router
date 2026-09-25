package main

// net module, travel helpers (hotels, airports, other people's routers):
//
//   - connectivity / captive-portal check: `mr wan check [WAN...]` GETs a plain-HTTP 204 endpoint
//     through one WAN (bound to its interface, names resolved by that WAN's own DNS servers, never
//     through the proxy): 204 = online, another answer = a login portal (its URL is kept), no
//     answer = offline. One-shot: the DHCP / PPP hooks start it in the background when a WAN comes
//     up or renews (wan[].portal), the web UI's 重新检测 runs it, the network LED turns amber while
//     every WAN that is up waits for a portal login. An online answer's Date header also sets a
//     clock that NTP has not synced yet (mod_sys_time.go: clockFromHTTP).
//   - WAN / LAN subnet conflicts: a DHCP lease that overlaps a LAN-side network is not installed
//     (the LAN would break with it); the web UI shows it with a free subnet to move the LAN to, and
//     the lease is asked for again as soon as the config no longer overlaps (retryConflicts).
//   - address class of a WAN (private / CGNAT): port forwards and inbound IPv4 cannot work there.
//
// Nothing resident. State under /run/mini-router/wan-check (tmpfs):
//
//	<wan>.json           last check (wanCheck)
//	<wan>.conflict.json  a DHCP lease refused for overlapping a LAN-side network (wanConflict)

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

var checkDir = RunDir + "/wan-check" // a variable so tests can use a temp dir

// defaultCheckURLs answer 204 over plain HTTP. Two operators: one of them blocked or broken by a
// network's DNS does not make the WAN look offline.
var defaultCheckURLs = []string{"http://connectivitycheck.gstatic.com/generate_204", "http://cp.cloudflare.com/generate_204"}

// connCheckURLs: system.connectivity_check, else the defaults.
func connCheckURLs(c *Config) []string {
	if len(c.System.ConnCheck) > 0 {
		return c.System.ConnCheck
	}
	return defaultCheckURLs
}

// validCheckURL: http://host[:port][/path][?query] with a DNS name or an IPv4 address; no user
// info, fragment, spaces or quotes. Plain HTTP only: portals intercept HTTP, and HTTP needs no
// correct clock (the check is also how the clock gets set).
func validCheckURL(s string) bool {
	if s == "" || len(s) > 200 || !safeText(s) || strings.ContainsAny(s, " \"'`<>\\") {
		return false
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "http" || u.User != nil || u.Opaque != "" || u.Fragment != "" || strings.Contains(s, "#") {
		return false
	}
	host := u.Hostname()
	if strings.Contains(host, ":") { // IPv6: the check runs from the WAN's IPv4 address
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() {
			return false
		}
	} else if !validDNSName(host) {
		return false
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return false
		}
	}
	return true
}

// wanCheck is the result of one check (also the answer of `mr wan check` and API net.check).
type wanCheck struct {
	WAN       string `json:"wan"`
	State     string `json:"state"` // online | portal | offline
	Checked   int64  `json:"checked"`
	Dev       string `json:"dev,omitempty"`
	IP        string `json:"ip,omitempty"`         // WAN address the check ran from (a new address = a stale result)
	URL       string `json:"url,omitempty"`        // check URL that answered
	Code      int    `json:"code,omitempty"`       // its HTTP status
	PortalURL string `json:"portal_url,omitempty"` // login page (Location, meta refresh, RFC 8908 API), validated
	PortalAPI string `json:"portal_api,omitempty"` // RFC 8910 DHCP option 114 (RFC 8908 API URI), validated
	RTT       int64  `json:"rtt_ms,omitempty"`
	Error     string `json:"error,omitempty"`
	ClockSkew *int64 `json:"clock_skew,omitempty"` // server Date minus the router clock, seconds (online answers)
	ClockSet  bool   `json:"clock_set,omitempty"`  // the router clock was stepped to that Date (NTP not synced)
}

func readJSONFile(path string, v any) bool {
	b, err := os.ReadFile(path)
	return err == nil && json.Unmarshal(b, v) == nil
}

func writeJSONFile(path string, v any) {
	b, _ := json.Marshal(v)
	if err := writeAtomic(path, b, 0644); err != nil {
		logf("%s: %v", path, err)
	}
}

func readCheck(name string) *wanCheck {
	var r wanCheck
	if !readJSONFile(filepath.Join(checkDir, name+".json"), &r) {
		return nil
	}
	return &r
}

// ---- the check ----

// classify maps one answer to a state: 204 (or an empty 200, which some transparent proxies make of
// a 204) = online; any other 2xx / 3xx, or 511 Network Authentication Required = a captive portal.
// Anything else says nothing about the network ("": the next URL is tried).
func classify(code int, bodyLen int) string {
	switch {
	case code == 204, code == 200 && bodyLen == 0:
		return "online"
	case code >= 200 && code < 400, code == 511:
		return "portal"
	}
	return ""
}

var (
	reMetaRefresh = regexp.MustCompile(`(?is)<meta[^>]+http-equiv\s*=\s*["']?refresh["']?[^>]*?content\s*=\s*["'][^"';]*;\s*url\s*=\s*['"]?([^"'>\s]+)`)
	reJSLocation  = regexp.MustCompile(`(?i)\blocation(?:\.href)?\s*=\s*["']([^"']+)["']|\blocation\.(?:replace|assign)\(\s*["']([^"']+)["']`)
)

// portalFromBody finds the login page of a portal that answers 200 with a page that moves on by
// itself (meta refresh or a script setting location).
func portalFromBody(body []byte) string {
	if m := reMetaRefresh.FindSubmatch(body); m != nil {
		return string(m[1])
	}
	if m := reJSLocation.FindSubmatch(body); m != nil {
		if len(m[1]) > 0 {
			return string(m[1])
		}
		return string(m[2])
	}
	return ""
}

// cleanURL checks a URL that came from the network (Location header, page, DHCP option, portal
// API): http(s) only (https only with httpsOnly), a host, no user info, printable, no quotes or
// angle brackets, at most 512 bytes. Relative URLs are resolved against base. "" = rejected.
func cleanURL(raw string, base *url.URL, httpsOnly bool) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 512 || !safeText(raw) || strings.ContainsAny(raw, " \"'`<>\\") {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	if base != nil {
		u = base.ResolveReference(u)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || (httpsOnly && u.Scheme != "https") || u.Host == "" || u.User != nil {
		return ""
	}
	s := u.String()
	if len(s) > 512 || !safeText(s) || strings.ContainsAny(s, " \"'`<>\\") {
		return ""
	}
	return s
}

// probe GETs one check URL (redirects are not followed) and classifies the answer. date is the
// answer's Date header (zero if none) and sent the moment the server most likely wrote it.
func probe(client *http.Client, raw string) (r wanCheck, date, sent time.Time, err error) {
	req, err := http.NewRequest("GET", raw, nil)
	if err != nil {
		return r, date, sent, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (mini-router connectivity check)")
	req.Header.Set("Cache-Control", "no-cache")
	t0 := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return r, date, sent, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
	rtt := time.Since(t0)
	r.State = classify(resp.StatusCode, len(body))
	if r.State == "" {
		return r, date, sent, fmt.Errorf("%s: HTTP %d", req.URL.Host, resp.StatusCode)
	}
	r.URL, r.Code, r.RTT = raw, resp.StatusCode, rtt.Milliseconds()
	if r.State == "portal" {
		r.PortalURL = cleanURL(resp.Header.Get("Location"), req.URL, false)
		if r.PortalURL == "" {
			r.PortalURL = cleanURL(portalFromBody(body), req.URL, false)
		}
	}
	if d, e := http.ParseTime(resp.Header.Get("Date")); e == nil {
		date, sent = d, t0.Add(rtt/2)
	}
	return r, date, sent, nil
}

// portalAPI reads an RFC 8908 captive-portal API answer. captive is nil when the answer does not
// say; the user-portal-url must be https (RFC 8908 §5).
func portalAPI(body []byte) (captive *bool, user string) {
	var j struct {
		Captive *bool  `json:"captive"`
		User    string `json:"user-portal-url"`
	}
	if json.Unmarshal(body, &j) != nil {
		return nil, ""
	}
	return j.Captive, cleanURL(j.User, nil, true)
}

func fetchPortalAPI(client *http.Client, api string) (*bool, string) {
	req, err := http.NewRequest("GET", api, nil)
	if err != nil {
		return nil, ""
	}
	req.Header.Set("Accept", "application/captive+json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, ""
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
	return portalAPI(body)
}

// checkClient is an HTTP client whose connections leave through dev (SO_BINDTODEVICE, so the
// WAN's own route is used even while another WAN holds the default route) and whose names are
// resolved by dns (the WAN's servers, also through dev; the system resolver when there are none).
// Nothing goes through the proxy: the router's own traffic never does.
func checkClient(dev string, dns []string, timeout time.Duration) *http.Client {
	d := &net.Dialer{Timeout: 4 * time.Second, Control: bindDevice(dev)}
	res := net.DefaultResolver
	if len(dns) > 0 {
		var mu sync.Mutex
		n := 0
		res = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			mu.Lock()
			s := dns[n%len(dns)] // every retry of the resolver goes to the next server
			n++
			mu.Unlock()
			return d.DialContext(ctx, network, net.JoinHostPort(s, "53"))
		}}
	}
	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			var ips []net.IP
			if ip := net.ParseIP(host); ip != nil {
				ips = []net.IP{ip}
			} else if ips, err = res.LookupIP(ctx, "ip4", host); err != nil {
				return nil, err
			}
			err = errors.New(host + ": no IPv4 address")
			for i, ip := range ips {
				if i == 2 {
					break
				}
				var cn net.Conn
				if cn, err = d.DialContext(ctx, "tcp4", net.JoinHostPort(ip.String(), port)); err == nil {
					return cn, nil
				}
			}
			return nil, err
		},
		DisableKeepAlives:      true,
		ResponseHeaderTimeout:  5 * time.Second,
		TLSHandshakeTimeout:    5 * time.Second,
		MaxResponseHeaderBytes: 16 << 10,
	}
	return &http.Client{Transport: tr, Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// checkWAN runs the check through one WAN. The first URL that gives an answer decides.
func checkWAN(c *Config, w *WAN) wanCheck {
	r := wanCheck{WAN: w.Name, Checked: time.Now().Unix(), Dev: w.Ifname()}
	addrs := ipv4Addrs(r.Dev)
	if len(addrs) == 0 {
		r.State, r.Error = "offline", "no IPv4 address"
		return r
	}
	r.IP = strings.SplitN(addrs[0], "/", 2)[0]
	l, _ := readLease(w.Name)
	r.PortalAPI = l.PortalAPI
	dns := l.DNS // the WAN's own servers: dnsmasq's upstream may be DoT, which needs the clock this may set
	if len(dns) == 0 {
		dns = l.OfferedDNS
	}
	client := checkClient(r.Dev, dns, 6*time.Second)
	var errs []string
	for _, u := range connCheckURLs(c) {
		p, date, sent, err := probe(client, u)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		r.State, r.URL, r.Code, r.RTT, r.PortalURL = p.State, p.URL, p.Code, p.RTT, p.PortalURL
		if p.State == "online" && !date.IsZero() {
			skew, set := clockFromHTTP(date, sent, u)
			r.ClockSkew, r.ClockSet = &skew, set
		}
		break
	}
	if r.State == "" {
		r.State = "offline"
		if e := strings.Join(errs, "; "); len(e) > 300 {
			r.Error = e[:300]
		} else {
			r.Error = e
		}
	}
	// RFC 8908: the network announced a portal API (DHCP option 114). It names the login page, and
	// says "captive" even where the portal lets the check URLs through unanswered.
	if r.PortalAPI != "" && r.State != "online" {
		if captive, user := fetchPortalAPI(client, r.PortalAPI); captive != nil && *captive {
			r.State = "portal"
			if user != "" {
				r.PortalURL = user
			}
		}
	}
	return r
}

// runChecks checks the WANs in parallel, stores and logs the results and updates the LEDs.
func runChecks(c *Config, ws []*WAN) []wanCheck {
	out := make([]wanCheck, len(ws))
	var wg sync.WaitGroup
	for i, w := range ws {
		wg.Add(1)
		go func(i int, w *WAN) {
			defer wg.Done()
			out[i] = checkWAN(c, w)
		}(i, w)
	}
	wg.Wait()
	for _, r := range out {
		prev := readCheck(r.WAN)
		if prev == nil || prev.State != r.State || prev.IP != r.IP || prev.PortalURL != r.PortalURL {
			switch r.State {
			case "portal":
				logf("wan %s: captive portal (HTTP %d from %s) — log in from any LAN device: %s", r.WAN, r.Code, r.URL, orNone(r.PortalURL))
			case "online":
				logf("wan %s: online (%s answered %d in %d ms)", r.WAN, r.URL, r.Code, r.RTT)
			default:
				logf("wan %s: no internet through %s: %s", r.WAN, r.Dev, r.Error)
			}
		}
		writeJSONFile(filepath.Join(checkDir, r.WAN+".json"), r)
	}
	updateLEDs(c)
	return out
}

func orNone(s string) string {
	if s == "" {
		return "(no login URL; open any http:// page)"
	}
	return s
}

// wanCheckCommand: `mr wan check [WAN...]` — the named WANs, or every WAN that has an address.
func wanCheckCommand(c *Config, names []string) error {
	var ws []*WAN
	for _, n := range names {
		w := c.WANByName(n)
		if w == nil {
			return fmt.Errorf("unknown wan %q", n)
		}
		ws = append(ws, w)
	}
	if len(names) == 0 {
		for i := range c.WAN {
			if hasIPv4(c.WAN[i].Ifname()) {
				ws = append(ws, &c.WAN[i])
			}
		}
	}
	return json.NewEncoder(os.Stdout).Encode(runChecks(c, ws))
}

// selfCmd is this mr binary with the same -c / -s files, to run a subcommand in the background.
func selfCmd(args ...string) (string, []string) {
	self, err := os.Executable()
	if err != nil {
		self = "/usr/sbin/mr"
	}
	var pre []string
	for _, f := range []string{"c", "s"} {
		if fl := flag.Lookup(f); fl != nil && fl.Value.String() != fl.DefValue {
			pre = append(pre, "-"+f, fl.Value.String())
		}
	}
	return self, append(pre, args...)
}

// spawnCheck starts `mr wan check NAME` in the background (a hook must return at once) for a WAN
// that came up or renewed, unless it was checked from the same address within the last minute.
func spawnCheck(w *WAN, ip string) {
	if !w.PortalCheck() {
		return
	}
	if r := readCheck(w.Name); r != nil && r.IP == ip && time.Now().Unix()-r.Checked < 60 {
		return
	}
	self, args := selfCmd("wan", "check", w.Name)
	startDetached(self, args...)
}

// apiNetCheck: POST {"wan": NAME} runs the check for that WAN now (≤ ~6 s per check URL) and returns it.
func apiNetCheck(r apiReq) apiResp {
	if r.method != "POST" {
		return errResp(405, "POST required")
	}
	var in struct {
		WAN string `json:"wan"`
	}
	json.Unmarshal(r.body, &in)
	if !reName.MatchString(in.WAN) {
		return errResp(400, "bad wan name")
	}
	c, err := loadConfig(ConfigPath, SecretsPath)
	if err != nil {
		return errResp(500, "%v", err)
	}
	w := c.WANByName(in.WAN)
	if w == nil {
		return errResp(404, "no wan %q", in.WAN)
	}
	return apiResp{body: runChecks(c, []*WAN{w})[0]}
}

// portalAPIFromEnv: DHCP option 114 as busybox udhcpc exports it (requested with -O 114; unknown
// options arrive as opt<N>=<hex>). An https URL or "".
func portalAPIFromEnv() string {
	b, err := hex.DecodeString(os.Getenv("opt114"))
	if err != nil || len(b) == 0 {
		return ""
	}
	return cleanURL(string(b), nil, true)
}

// ---- WAN / LAN subnet conflicts ----

// wanConflict: a DHCP lease that was not installed because it overlaps a LAN-side network.
type wanConflict struct {
	Lease   string `json:"lease"` // address/prefix the upstream offered
	Gateway string `json:"gateway,omitempty"`
	Network string `json:"network"`           // the LAN-side network it collides with (lan, guest, ...)
	Net     string `json:"net"`               // that network's subnet
	Suggest string `json:"suggest,omitempty"` // a free subnet to move that network to (router address/prefix)
	Since   int64  `json:"since"`
}

func readConflict(name string) *wanConflict {
	var k wanConflict
	if !readJSONFile(filepath.Join(checkDir, name+".conflict.json"), &k) {
		return nil
	}
	return &k
}

func clearConflict(name string) { os.Remove(filepath.Join(checkDir, name+".conflict.json")) }

func overlaps(a, b *net.IPNet) bool { return a.Contains(b.IP) || b.Contains(a.IP) }

// lanConflict reports the LAN-side network an IPv4 WAN address ip/prefix (gateway gw, may be nil)
// collides with: the subnets overlap, or the address or the gateway lies inside the network.
func lanConflict(c *Config, ip net.IP, prefix int, gw net.IP) (LANNet, *net.IPNet, bool) {
	ip = ip.To4()
	if ip == nil || prefix < 0 || prefix > 32 {
		return LANNet{}, nil, false
	}
	wn := &net.IPNet{IP: ip.Mask(net.CIDRMask(prefix, 32)), Mask: net.CIDRMask(prefix, 32)}
	for _, n := range c.LANNets() {
		_, nn, err := net.ParseCIDR(n.IPv4)
		if err != nil || nn.IP.To4() == nil {
			continue
		}
		if overlaps(wn, nn) || (gw != nil && nn.Contains(gw)) {
			return n, nn, true
		}
	}
	return LANNet{}, nil, false
}

// lanCandidates: subnets suggested for a LAN-side network that collides with the upstream network.
// Hotels and home routers mostly use 192.168.0-1.x / 10.0.0.x; tailscale owns 100.64.0.0/10.
var lanCandidates = []string{"10.77.0.1/24", "172.22.77.1/24", "192.168.77.1/24", "10.177.0.1/24", "172.23.177.1/24"}

// suggestLAN: the first candidate that overlaps neither the WAN subnet nor any LAN-side network
// other than the colliding one (which is the one that would move).
func suggestLAN(c *Config, wan *net.IPNet, moving string) string {
next:
	for _, s := range lanCandidates {
		_, sn, _ := net.ParseCIDR(s)
		if overlaps(sn, wan) {
			continue
		}
		for _, n := range c.LANNets() {
			if _, nn, err := net.ParseCIDR(n.IPv4); err == nil && n.Name != moving && overlaps(sn, nn) {
				continue next
			}
		}
		return s
	}
	return ""
}

// refuseLease records (and logs, once) a lease that collides with LAN-side network n (subnet nn),
// and makes sure nothing of this WAN stays configured (an earlier lease, before the LAN was changed).
func refuseLease(c *Config, w *WAN, iface string, ip net.IP, prefix int, gw string, n LANNet, nn *net.IPNet) {
	lease := fmt.Sprintf("%s/%d", ip, prefix)
	k := wanConflict{Lease: lease, Gateway: gw, Network: n.Name, Net: nn.String(), Since: time.Now().Unix()}
	if old := readConflict(w.Name); old != nil && old.Lease == k.Lease && old.Network == k.Network {
		k.Since = old.Since
	} else {
		logf("wan %s: DHCP lease %s (gateway %s) overlaps LAN-side network %s %s: not installed — move that network to another subnet",
			w.Name, lease, orDash(gw), n.Name, nn)
	}
	k.Suggest = suggestLAN(c, &net.IPNet{IP: ip.Mask(net.CIDRMask(prefix, 32)), Mask: net.CIDRMask(prefix, 32)}, n.Name)
	writeJSONFile(filepath.Join(checkDir, w.Name+".conflict.json"), k)
	if _, had := readLease(w.Name); had {
		wanDown(c, w)
	}
	run("ip", "-4", "addr", "flush", "dev", iface)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// retryConflicts: a refused lease is asked for again (the WAN's DHCP client restarts) once the
// config no longer collides with it, e.g. right after an apply that moved the LAN. Run by
// refreshRoutes (after every apply / rollback, at boot, on health changes).
func retryConflicts(c *Config) {
	for i := range c.WAN {
		w := &c.WAN[i]
		k := readConflict(w.Name)
		if k == nil {
			continue
		}
		ip, n, err := net.ParseCIDR(k.Lease)
		if err != nil || w.Proto != "dhcp" { // switched away from DHCP: nothing to ask for
			clearConflict(w.Name)
			continue
		}
		ones, _ := n.Mask.Size()
		if _, _, bad := lanConflict(c, ip, ones, net.ParseIP(k.Gateway)); bad {
			continue
		}
		clearConflict(w.Name)
		svc := netService(*w)
		if _, err := os.Stat("/etc/init.d/" + svc); err == nil {
			logf("wan %s: %s no longer overlaps a LAN-side network, asking for a lease again", w.Name, k.Lease)
			startDetached("rc-service", svc, "restart")
		}
	}
}

// ---- address class, LED ----

var cgnatNet = &net.IPNet{IP: net.IPv4(100, 64, 0, 0).To4(), Mask: net.CIDRMask(10, 32)}

// addrClass: "cgnat" (100.64.0.0/10), "private" (RFC 1918, link-local) or "" (public) — behind the
// first two there is another NAT: port forwards and inbound IPv4 cannot reach the router.
func addrClass(ip string) string {
	a := net.ParseIP(ip).To4()
	switch {
	case a == nil:
		return ""
	case cgnatNet.Contains(a):
		return "cgnat"
	case a.IsPrivate(), a.IsLinkLocalUnicast():
		return "private"
	}
	return ""
}

// wanLEDState: "down" when no WAN has an IPv4 address, "portal" when every WAN that has one is
// waiting for a portal login (per its last check from that address), else "up".
func wanLEDState(c *Config) string {
	up, portal := 0, 0
	for _, w := range c.WAN {
		a := ipv4Addrs(w.Ifname())
		if len(a) == 0 {
			continue
		}
		up++
		if r := readCheck(w.Name); r != nil && r.State == "portal" && r.IP == strings.SplitN(a[0], "/", 2)[0] {
			portal++
		}
	}
	switch {
	case up == 0:
		return "down"
	case portal == up:
		return "portal"
	}
	return "up"
}

// travelStatus: what status / `mr wan status` show about a WAN beyond its address.
func travelStatus(name, ip string) (check *wanCheck, conflict *wanConflict, class string) {
	if ip != "" {
		if r := readCheck(name); r != nil && r.IP == ip {
			check = r
		}
		class = addrClass(ip)
	}
	return check, readConflict(name), class
}

// dropStaleChecks removes check / conflict records of WANs that are no longer configured.
func dropStaleChecks(c *Config) {
	ents, _ := os.ReadDir(checkDir)
	for _, e := range ents {
		name := strings.TrimSuffix(strings.TrimSuffix(e.Name(), ".json"), ".conflict")
		if c.WANByName(name) == nil {
			os.Remove(filepath.Join(checkDir, e.Name()))
		}
	}
}
