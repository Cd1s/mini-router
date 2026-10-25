package main

// net module runtime: hooks called by pppd (ip-up/ip-down), udhcpc (net-udhcpc), dhcpcd (exit-hook)
// and the health checker (net-wanmon). They install per-WAN routes, rules and upstream DNS.
//
// State under /run/mini-router (tmpfs):
//
//	wan/<name>.json   what the WAN got when it came up (address, gateway, DNS, since) — written here
//	wan-state.json    health of every WAN — written by net-wanmon each round
//	resolv.conf       nameservers of every WAN that is up, healthy first — read by dnsmasq

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// downMetric is added to the default-route metric of a WAN the health checker reports down, so
// the next WAN by metric takes over while the dead one stays reachable for the checker's pings.
const downMetric = 10000

// runtime state paths (variables so tests can use a temp dir)
var (
	wanRunDir           = RunDir + "/wan"
	wanStateFile        = RunDir + "/wan-state.json"
	resolvConf          = RunDir + "/resolv.conf"
	fwLoadForHook       = fwLoad
	fwLoadForCommit     = fwLoad
	refreshLan6ForHook  = refreshLan6
	gatewayConflictFile = RunDir + "/gateway-conflicts.json"
	requirePublicFile   = RunDir + "/require-public-ip.json"
	requirePublicNow    = time.Now
	requirePublicRedial = func(w *WAN) { startDetached("rc-service", netService(*w), "restart") }
	publicCheckAddrs    = ipv4Addrs
	publicCheckMetrics  = mainDefaultMetrics
	publicCheckRefresh  = func(c *Config) { _ = hookHealth(c) }
)

const (
	requirePublicGap  = 180 // seconds between redials unless wan[].require_public_ip_gap says otherwise
	requirePublicFast = 4   // redials at that plain gap; after them the wait doubles every time
	requirePublicCap  = 900 // the longest wait between redials (a configured gap above it is kept)
)

// requirePublicRecord is the guard's memory of one WAN (/run, so a reboot starts over). It never
// ends: a record only goes away with a public address.
type requirePublicRecord struct {
	Attempts   int   `json:"attempts"` // redials issued since boot / the last public address
	LastRedial int64 `json:"last_redial"`
}

func requirePublicGapOf(w *WAN) int {
	if w.RequirePublicIPGap == 0 {
		return requirePublicGap
	}
	return w.RequirePublicIPGap
}

// requirePublicWait: seconds between redial n and redial n+1. The ISP may be counting the old sessions
// (AIS: a session over the concurrent limit sits in a walled garden until the old ones time out), so
// the redials back off instead of stopping: gap for the first four, then 2x, 4x, ... up to 15 minutes.
func requirePublicWait(gap, n int) int {
	limit := max(gap, requirePublicCap)
	wait := gap
	for i := requirePublicFast; i <= n && wait < limit; i++ {
		wait *= 2
	}
	return min(wait, limit)
}

// publicWait is what the panel and doctor show of a WAN that holds a private address.
type publicWait struct {
	Class   string `json:"class"`             // cgnat | private
	Redials int    `json:"redials"`           // issued so far
	NextAt  int64  `json:"next_at,omitempty"` // unix time of the next redial (0: the next check)
}

// publicWaitOf: nil unless w has to hold a public address and ip is not one.
func publicWaitOf(w *WAN, ip string, rec requirePublicRecord) *publicWait {
	if w.Proto != "pppoe" || !w.RequirePublicIP || addrClass(ip) == "" {
		return nil
	}
	pw := &publicWait{Class: addrClass(ip), Redials: rec.Attempts}
	if rec.Attempts > 0 {
		pw.NextAt = rec.LastRedial + int64(requirePublicWait(requirePublicGapOf(w), rec.Attempts))
	}
	return pw
}

// publicIPHeld: the private / CGNAT address of a PPPoE WAN that has to hold a public one
// (wan[].require_public_ip), else "". The session is up and has an address but is not what the owner
// asked for (AIS puts the sessions over its concurrent limit in a walled garden: 100.64/10, no
// traffic), so routing treats the line as down: the WAN table loses its default route and the
// policy routes with fallback: main use the main table until a public address arrives.
func publicIPHeld(w *WAN) string {
	if w == nil || w.Proto != "pppoe" || !w.RequirePublicIP {
		return ""
	}
	if l, ok := readLease(w.Name); ok {
		return addrClass(l.IP)
	}
	return ""
}

func readRequirePublic() map[string]requirePublicRecord {
	m := map[string]requirePublicRecord{}
	b, err := os.ReadFile(requirePublicFile)
	if err == nil {
		_ = json.Unmarshal(b, &m)
	}
	return m
}

func writeRequirePublic(m map[string]requirePublicRecord) {
	if len(m) == 0 {
		_ = os.Remove(requirePublicFile)
		return
	}
	b, _ := json.Marshal(m)
	if err := writeAtomic(requirePublicFile, b, 0600); err != nil {
		logf("require_public_ip: %v", err)
	}
}

// requirePublicIP enforces the PPPoE public-address guard from the ppp-up hook and the cron check: a
// private address redials this one WAN (never another), waiting longer each time; a public address
// clears the record at once. It returns true while the address is private.
func requirePublicIP(c *Config, w *WAN, ip string) bool {
	if w == nil || w.Proto != "pppoe" || !w.RequirePublicIP {
		return false
	}
	cls := addrClass(ip)
	lk := flock(requirePublicFile+".lock", true)
	if lk == nil {
		return cls != ""
	}
	defer lk.Close()
	m := readRequirePublic()
	if cls == "" {
		if _, ok := m[w.Name]; ok {
			delete(m, w.Name)
			writeRequirePublic(m)
		}
		return false
	}
	r := m[w.Name]
	now := requirePublicNow().Unix()
	gap := requirePublicGapOf(w)
	if r.Attempts > 0 && now >= r.LastRedial && now-r.LastRedial < int64(requirePublicWait(gap, r.Attempts)) {
		return true
	}
	r.Attempts++
	r.LastRedial = now
	m[w.Name] = r
	writeRequirePublic(m)
	next := requirePublicWait(gap, r.Attempts)
	logf("wan %s: %s IPv4 address; redial %d, next in %d s", w.Name, cls, r.Attempts, next)
	if r.Attempts == requirePublicFast+1 {
		eventAdd(c, "doctor", "warn", "wan."+w.Name, fmt.Sprintf("%s still has a %s IPv4 address after %d redials; the ISP may be holding the session (concurrent-session limit), redialing continues with growing intervals up to %d min", w.Name, cls, requirePublicFast, max(gap, requirePublicCap)/60), false)
	}
	requirePublicRedial(w)
	return true
}

// pruneRequirePublic forgets the records of WANs that are gone or no longer need a public address
// (after an accepted apply), so switching the option on again starts a fresh sequence.
func pruneRequirePublic(c *Config) {
	if _, err := os.Stat(requirePublicFile); err != nil {
		return
	}
	lk := flock(requirePublicFile+".lock", true)
	if lk == nil {
		return
	}
	defer lk.Close()
	m := readRequirePublic()
	for name := range m {
		if w := c.WANByName(name); w == nil || w.Proto != "pppoe" || !w.RequirePublicIP {
			delete(m, name)
		}
	}
	writeRequirePublic(m)
}

func publicIPCheckEnabled(c *Config) bool {
	for _, w := range c.WAN {
		if w.Proto == "pppoe" && w.RequirePublicIP {
			return true
		}
	}
	return false
}

func publicIPCheckCronLine(c *Config) []string {
	if !publicIPCheckEnabled(c) {
		return nil
	}
	return []string{"# require_public_ip", "* * * * * " + mrBin + " wan public-check --cron"}
}

// publicIPCheck is the periodic review (cron, every minute) for sessions that came back during a wait.
// It reads the live interface address, so it also catches a PPPoE session that was already up when the
// option was enabled, and it re-routes a WAN whose routes do not match the guard (held out, or public
// again) within that minute. The cron invocation is the only periodic work; no resident process is added.
func publicIPCheck(c *Config) error {
	reroute := false
	for i := range c.WAN {
		w := &c.WAN[i]
		if w.Proto != "pppoe" || !w.RequirePublicIP {
			continue
		}
		addrs := publicCheckAddrs(w.Ifname())
		if len(addrs) == 0 {
			continue
		}
		ip := strings.SplitN(addrs[0], "/", 2)[0]
		requirePublicIP(c, w, ip)
		if ms := publicCheckMetrics(w.Ifname()); len(ms) > 0 && (ms[0] >= w.Metric+downMetric) != !wanHealthy(c, w.Name) {
			reroute = true
		}
	}
	if reroute {
		publicCheckRefresh(c)
	}
	return nil
}

func ipv6HealthRoutingEnabled(c *Config) bool { return c != nil && c.MultiWAN.Enabled() }

func gatewayConflictReported(key string) bool {
	lk := flock(gatewayConflictFile+".lock", true)
	if lk == nil {
		return false
	}
	defer lk.Close()
	m := map[string]bool{}
	if b, err := os.ReadFile(gatewayConflictFile); err == nil {
		_ = json.Unmarshal(b, &m)
	}
	if m[key] {
		return true
	}
	m[key] = true
	b, _ := json.Marshal(m)
	_ = writeAtomic(gatewayConflictFile, b, 0600)
	return false
}

func clearGatewayConflict(key string) {
	lk := flock(gatewayConflictFile+".lock", true)
	if lk == nil {
		return
	}
	defer lk.Close()
	m := map[string]bool{}
	if b, err := os.ReadFile(gatewayConflictFile); err == nil {
		_ = json.Unmarshal(b, &m)
	}
	if !m[key] {
		return
	}
	delete(m, key)
	if len(m) == 0 {
		_ = os.Remove(gatewayConflictFile)
		return
	}
	b, _ := json.Marshal(m)
	_ = writeAtomic(gatewayConflictFile, b, 0600)
}

// wanLease is what a WAN got when it came up.
type wanLease struct {
	IP      string   `json:"ip"`
	Prefix  int      `json:"prefix,omitempty"`
	Gateway string   `json:"gateway,omitempty"`
	DNS     []string `json:"dns,omitempty"`
	DNS6    []string `json:"dns6,omitempty"`
	Since   int64    `json:"since"`
	Dev     string   `json:"dev,omitempty"` // L3 interface, so leftovers can be removed once the WAN is gone
}

func readLease(name string) (wanLease, bool) {
	var l wanLease
	b, err := os.ReadFile(filepath.Join(wanRunDir, name+".json"))
	if err != nil || json.Unmarshal(b, &l) != nil {
		return l, false
	}
	return l, true
}

func writeLease(name string, l wanLease) {
	b, _ := json.Marshal(l)
	if err := writeAtomic(filepath.Join(wanRunDir, name+".json"), b, 0644); err != nil {
		logf("wan %s: %v", name, err)
	}
}

func removeLease(name string) { os.Remove(filepath.Join(wanRunDir, name+".json")) }

// wanHealth is one WAN in wan-state.json (written by net-wanmon).
type wanHealth struct {
	Name  string   `json:"name"`
	Dev   string   `json:"dev"`
	State string   `json:"state"` // up | down
	RTT   *float64 `json:"rtt_ms"`
	Since int64    `json:"since"`
	Fails int      `json:"fails"`
}

type wanHealthFile struct {
	Time     int64       `json:"time"`
	Interval int         `json:"interval"`
	WANs     []wanHealth `json:"wans"`
}

func readWanHealth() (wanHealthFile, bool) {
	var f wanHealthFile
	b, err := os.ReadFile(wanStateFile)
	if err != nil || json.Unmarshal(b, &f) != nil {
		return f, false
	}
	return f, true
}

// readWanState: WAN name -> "up" / "down" (empty when the checker is not running).
func readWanState() map[string]string {
	m := map[string]string{}
	f, _ := readWanHealth()
	for _, w := range f.WANs {
		m[w.Name] = w.State
	}
	return m
}

// wanHealthMap: the health checker's verdicts when it is configured, plus "down" for every WAN the
// public-address guard holds out (publicIPHeld), whatever the checker says about it.
func wanHealthMap(c *Config) map[string]string {
	m := map[string]string{}
	if c.MultiWAN.Enabled() {
		m = readWanState()
	}
	for i := range c.WAN {
		if publicIPHeld(&c.WAN[i]) != "" {
			m[c.WAN[i].Name] = "down"
		}
	}
	return m
}

func wanHealthy(c *Config, name string) bool { return wanHealthMap(c)[name] != "down" }

// hookPPP is called from /etc/ppp/ip-up and ip-down:
//
//	mr hook ppp-up|ppp-down IFNAME TTY SPEED LOCAL REMOTE IPPARAM
func hookPPP(c *Config, up bool, args []string) error {
	if len(args) < 6 {
		return fmt.Errorf("ppp hook: need 6 args, got %v", args)
	}
	ifname, ipparam := args[0], args[5]
	w := c.WANByName(ipparam)
	if w == nil {
		return fmt.Errorf("ppp hook: unknown wan %q", ipparam)
	}
	// pppd can report a delayed ip-up/ip-down after an apply changed this WAN to
	// another protocol (or moved it to another link).  Its lease and routes now
	// belong to the current protocol, so a stale PPP event must not tear them down.
	if w.Proto != "pppoe" || w.Ifname() != ifname {
		logf("wan %s: ignoring stale PPP event on %s (current %s on %s)", w.Name, ifname, w.Proto, w.Ifname())
		return nil
	}
	guarded := false
	if up {
		logf("wan %s up on %s (%s)", w.Name, ifname, args[3])
		l := wanLease{IP: args[3], Since: time.Now().Unix(), Dev: ifname}
		if net.ParseIP(args[4]) != nil {
			l.Gateway = args[4]
		}
		if w.PeerDNS { // pppd exports the peer's DNS servers to ip-up
			l.DNS, l.DNS6 = splitDNS(3, os.Getenv("DNS1"), os.Getenv("DNS2"))
		}
		writeLease(w.Name, l)
		guarded = requirePublicIP(c, w, args[3])
		wanUp(c, w, ifname, args[3], "")
		writeResolv(c)
	} else {
		logf("wan %s down on %s", w.Name, ifname)
		wanDown(c, w)
	}
	updateLEDs(c)
	err := fwLoadForHook(c)
	if relayErr := ipv6RelaySync(c); relayErr != nil {
		logf("IPv6 relay: %v", relayErr)
	}
	if up {
		if !guarded {
			runOnWAN(c, w.Name, "up")
			dialOnUp(c, w.Name)
		}
	} else {
		runOnWAN(c, w.Name, "down")
	}
	return err
}

// validIPs keeps up to max strings that parse as IP addresses (they come from the network).
func validIPs(max int, xs ...string) []string {
	var out []string
	for _, x := range xs {
		for _, f := range strings.Fields(x) {
			if ip := net.ParseIP(f); ip != nil && !ip.IsUnspecified() && len(out) < max {
				out = append(out, ip.String())
			}
		}
	}
	return out
}

func splitDNS(max int, xs ...string) (v4, v6 []string) {
	seen4, seen6 := map[string]bool{}, map[string]bool{}
	for _, x := range xs {
		for _, f := range strings.Fields(x) {
			ip := net.ParseIP(f)
			if ip == nil || ip.IsUnspecified() {
				continue
			}
			if ip4 := ip.To4(); ip4 != nil {
				if !seen4[ip4.String()] && len(v4) < max {
					seen4[ip4.String()] = true
					v4 = append(v4, ip4.String())
				}
			} else if !seen6[ip.String()] && len(v6) < max {
				seen6[ip.String()] = true
				v6 = append(v6, ip.String())
			}
		}
	}
	return v4, v6
}

// wanUp installs everything routing needs for one WAN that has an address. Idempotent.
// gw is the IPv4 gateway for ethernet WANs (DHCP / static); PPPoE routes point at the device.
func wanUp(c *Config, w *WAN, ifname, local, gw string) {
	t, _ := c.WANTable(w.Name)
	ts := fmt.Sprint(t)
	healthy := wanHealthy(c, w.Name)
	var via []string
	if w.Proto != "pppoe" {
		if gw == "" {
			logf("wan %s: no gateway on %s, default route not installed", w.Name, ifname)
		} else {
			via = []string{"via", gw}
			if !onLink(ifname, gw) {
				via = append(via, "onlink")
			}
		}
	}
	if w.Proto == "pppoe" || via != nil {
		metric := w.Metric
		if !healthy {
			metric += downMetric
		}
		setMainDefault(ifname, via, metric)
		if healthy {
			must("ip", append(append([]string{"route", "replace", "default"}, via...), "dev", ifname, "table", ts)...)
		} else {
			// policy / balanced / connmarked traffic falls through to main = the best healthy WAN
			run("ip", "route", "del", "default", "table", ts)
		}
	}
	if gw != "" && net.ParseIP(gw) != nil {
		for _, args := range gatewayRouteCommands(gw, ifname, local, t) {
			must(args[0], args[1:]...)
		}
		if ln := lanForIP(c, gw); ln != nil && !sameIP(gw, lanAddress(ln.IPv4)) {
			if lanHostUsesIP(c, gw) {
				key := w.Name + ":" + gw
				if !gatewayConflictReported(key) {
					eventAdd(c, "doctor", "risk", "wan."+w.Name, fmt.Sprintf("LAN host already uses upstream gateway %s; proxy ARP was not installed", gw), false)
				}
			} else {
				clearGatewayConflict(w.Name + ":" + gw)
				newProxy := !proxyNeighborExists(gw, ln.Bridge)
				must("ip", "neigh", "replace", "proxy", gw, "dev", ln.Bridge)
				if newProxy {
					eventAdd(c, "doctor", "risk", "wan."+w.Name, fmt.Sprintf("upstream gateway %s is in LAN subnet %s; upstream and LAN share a subnet, consider changing LAN to another range", gw, ln.IPv4), false)
				}
			}
		} else if gw != "" {
			deleteProxyNeighbors(c, gw)
		}
	}
	if w.Proto == "pppoe" {
		args := ipv6WANTableRouteArgs(w, healthy, "", t)
		if healthy {
			must("ip", args...)
		} else {
			run("ip", args...)
		}
	} else if gw6 := mainDefault6(ifname); gw6 != "" {
		args := ipv6WANTableRouteArgs(w, healthy, gw6, t)
		if healthy {
			must("ip", args...)
		} else {
			run("ip", args...)
		}
	}
	if ipv6HealthRoutingEnabled(c) {
		setMainDefault6(w, healthy)
	}
	// LAN route in the WAN table: strict rp_filter (src_valid_mark=1) checks marked LAN packets against it
	if _, lanNet, err := net.ParseCIDR(c.LAN.IPv4); err == nil {
		must("ip", "route", "replace", lanNet.String(), "dev", c.LAN.Bridge, "table", ts)
	}
	// replies the router itself sends from this WAN's address leave through this WAN
	for {
		if _, err := run("ip", "rule", "del", "lookup", ts, "pref", fmt.Sprint(prefFromLocal)); err != nil {
			break
		}
	}
	if local != "" {
		// also a rule for this address that points at another table: tables are numbered by WAN
		// position, so removing an earlier WAN renumbers this one (and the old table now belongs to
		// another WAN)
		for {
			if _, err := run("ip", "rule", "del", "from", local, "pref", fmt.Sprint(prefFromLocal)); err != nil {
				break
			}
		}
		must("ip", "rule", "add", "from", local, "lookup", ts, "pref", fmt.Sprint(prefFromLocal))
	}
	// multi-WAN: inbound on a non-default WAN must pass reverse-path checks (loose on WAN, strict stays on LAN)
	os.WriteFile("/proc/sys/net/ipv4/conf/"+ifname+"/rp_filter", []byte("2"), 0644)
	if w.IPv6 {
		os.WriteFile("/proc/sys/net/ipv6/conf/"+ifname+"/accept_ra", []byte("2"), 0644)
	}
}

// setMainDefault makes `default [via gw] dev ifname metric m` the only main-table default route
// through ifname. The new route is added before the old one is removed, so there is no gap.
func setMainDefault(ifname string, via []string, metric int) {
	args := append([]string{"route", "replace", "default"}, via...)
	must("ip", append(args, "dev", ifname, "metric", fmt.Sprint(metric))...)
	for _, m := range mainDefaultMetrics(ifname) {
		if m != metric {
			run("ip", "route", "del", "default", "dev", ifname, "metric", fmt.Sprint(m))
		}
	}
}

// ipRoutes decodes `ip -j <family> route show ...`.
func ipRoutes(args ...string) []map[string]any {
	var out []map[string]any
	if l, ok := ipJSON(append([]string{"route", "show"}, args...)...).([]any); ok {
		for _, x := range l {
			if m, ok := x.(map[string]any); ok {
				out = append(out, m)
			}
		}
	}
	return out
}

func mainDefaultMetrics(ifname string) []int {
	var ms []int
	for _, r := range ipRoutes("default", "dev", ifname) {
		m, _ := r["metric"].(float64)
		ms = append(ms, int(m))
	}
	return ms
}

func mainDefault6(ifname string) string {
	out, err := run("ip", "-6", "-j", "route", "show", "default", "dev", ifname)
	if err != nil {
		return ""
	}
	var rs []map[string]any
	json.Unmarshal([]byte(out), &rs)
	for _, r := range rs {
		if g, ok := r["gateway"].(string); ok && net.ParseIP(g) != nil {
			return g
		}
	}
	return ""
}

// setMainDefault6 mirrors the IPv4 health metric for RA-installed main-table routes. dhcpcd owns
// those routes, so the hook changes only their metric and leaves source-specific routes (proto 97)
// to srcDefaults6. A down WAN therefore remains probeable while the next healthy WAN wins IPv6 too.
func setMainDefault6(w *WAN, healthy bool) {
	if w == nil || !w.IPv6 {
		return
	}
	rs, _ := ipJSON("-6", "route", "show", "default", "dev", w.Ifname()).([]any)
	metric := 1024 + w.Metric
	if !healthy {
		metric += downMetric
	}
	for _, x := range rs {
		r, _ := x.(map[string]any)
		if proto, ok := r["protocol"].(string); !ok || proto != "ra" {
			continue
		}
		if ipv6SourceRoute(r) {
			continue
		}
		old, hasOld := r["metric"].(float64)
		if hasOld && int(old) == metric {
			continue
		}
		if w.Proto != "pppoe" && !ipv6RouteHasGateway(r) {
			continue
		}
		args := ipv6DefaultRouteReplaceArgs(r, w.Ifname(), metric)
		if len(args) == 0 {
			continue
		}
		if out, err := run("ip", args...); err != nil {
			logf("IPv6 default route update on %s failed: %v %s", w.Ifname(), err, strings.TrimSpace(out))
			continue
		}
		if hasOld {
			del := []string{"-6", "route", "del"}
			for i := 3; i < len(args); i++ {
				if args[i] == "expires" && i+1 < len(args) {
					i++
					continue
				}
				del = append(del, args[i])
			}
			// The route key includes its old metric; replace it first, then remove only the
			// previous RA route. Protocol and expiry are retained on the replacement.
			for i := range del {
				if del[i] == "metric" && i+1 < len(del) {
					del[i+1] = fmt.Sprint(int(old))
				}
			}
			run("ip", del...)
		}
	}
}

func ipv6SourceRoute(r map[string]any) bool {
	if proto, ok := r["protocol"].(string); ok && (proto == protoSrc6 || proto == "97") {
		return true
	}
	if proto, ok := r["protocol"].(float64); ok && int(proto) == atoi(protoSrc6) {
		return true
	}
	// iproute2 calls the `src` argument `prefsrc` in JSON. This also covers builds that
	// render protocol 97 as the generic "static" name.
	_, hasSrc := r["prefsrc"].(string)
	return hasSrc
}

func ipv6RouteHasGateway(r map[string]any) bool {
	if gw, ok := r["gateway"].(string); ok && net.ParseIP(gw) != nil {
		return true
	}
	nhs, ok := r["nexthops"].([]any)
	if !ok {
		return false
	}
	for _, x := range nhs {
		nh, _ := x.(map[string]any)
		if gw, ok := nh["gateway"].(string); ok && net.ParseIP(gw) != nil {
			return true
		}
	}
	return false
}

func ipv6DefaultRouteReplaceArgs(r map[string]any, dev string, metric int) []string {
	if dev == "" || r == nil {
		return nil
	}
	args := []string{"-6", "route", "replace", "default"}
	nhs, hasNexthops := r["nexthops"].([]any)
	if hasNexthops && len(nhs) > 0 {
		appendIPv6RouteAttrs := func(dst []string) []string {
			if proto, ok := r["protocol"].(string); ok && proto == "ra" {
				dst = append(dst, "proto", "ra")
			}
			if expires, ok := r["expires"].(float64); ok && expires > 0 {
				dst = append(dst, "expires", fmt.Sprint(int(expires)))
			}
			dst = append(dst, "metric", fmt.Sprint(metric))
			if pref, ok := r["pref"].(string); ok && (pref == "low" || pref == "medium" || pref == "high") {
				dst = append(dst, "pref", pref)
			}
			return dst
		}
		args = appendIPv6RouteAttrs(args)
		for _, x := range nhs {
			nh, _ := x.(map[string]any)
			args = append(args, "nexthop")
			if gw, ok := nh["gateway"].(string); ok && net.ParseIP(gw) != nil {
				args = append(args, "via", gw)
			}
			if nd, ok := nh["dev"].(string); ok && validDev(nd) {
				args = append(args, "dev", nd)
			}
			if weight, ok := nh["weight"].(float64); ok && weight > 0 {
				args = append(args, "weight", fmt.Sprint(int(weight)))
			}
		}
	} else {
		if gw, ok := r["gateway"].(string); ok && net.ParseIP(gw) != nil {
			args = append(args, "via", gw)
		}
		args = append(args, "dev", dev)
		if proto, ok := r["protocol"].(string); ok && proto == "ra" {
			args = append(args, "proto", "ra")
		}
		if expires, ok := r["expires"].(float64); ok && expires > 0 {
			args = append(args, "expires", fmt.Sprint(int(expires)))
		}
		args = append(args, "metric", fmt.Sprint(metric))
		if pref, ok := r["pref"].(string); ok && (pref == "low" || pref == "medium" || pref == "high") {
			args = append(args, "pref", pref)
		}
	}
	return args
}

func ipv6WANTableRouteArgs(w *WAN, healthy bool, gateway string, table int) []string {
	if w == nil {
		return nil
	}
	if !healthy {
		return []string{"-6", "route", "del", "default", "table", fmt.Sprint(table)}
	}
	args := []string{"-6", "route", "replace", "default"}
	if gateway != "" {
		args = append(args, "via", gateway)
	}
	return append(args, "dev", w.Ifname(), "table", fmt.Sprint(table))
}

// onLink reports whether gw is inside one of ifname's IPv4 subnets.
func onLink(ifname, gw string) bool {
	ip := net.ParseIP(gw)
	for _, a := range ipv4Addrs(ifname) {
		if _, n, err := net.ParseCIDR(a); err == nil && n.Contains(ip) {
			return true
		}
	}
	return false
}

// ipv4Addrs lists "addr/prefix" of ifname.
func ipv4Addrs(ifname string) []string {
	out, err := run("ip", "-4", "-o", "addr", "show", "dev", ifname)
	if err != nil {
		return nil
	}
	var as []string
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		for i := 0; i+1 < len(f); i++ {
			if f[i] == "inet" {
				as = append(as, f[i+1])
			}
		}
	}
	return as
}

func wanDown(c *Config, w *WAN) {
	lease, had := readLease(w.Name)
	t, _ := c.WANTable(w.Name)
	run("ip", "route", "flush", "table", fmt.Sprint(t))
	run("ip", "-6", "route", "flush", "table", fmt.Sprint(t))
	for {
		if _, err := run("ip", "rule", "del", "lookup", fmt.Sprint(t), "pref", fmt.Sprint(prefFromLocal)); err != nil {
			break
		}
	}
	if w.Proto != "pppoe" { // a PPPoE device takes its routes with it; ethernet WANs keep theirs
		for _, m := range mainDefaultMetrics(w.Ifname()) {
			run("ip", "route", "del", "default", "dev", w.Ifname(), "metric", fmt.Sprint(m))
		}
	}
	if had {
		removeGatewayArtifacts(c, lease)
	}
	removeLease(w.Name)
	writeResolv(c)
}

func removeGatewayArtifacts(c *Config, l wanLease) {
	if l.Gateway == "" || !validDev(l.Dev) {
		return
	}
	run("ip", "route", "del", l.Gateway+"/32", "dev", l.Dev)
	if l.Prefix > 0 { // PPPoE's peer route has no IPv4 prefix and never uses this gateway path.
		if out, err := run("ip", "-4", "route", "show", "table", "all"); err == nil {
			for _, table := range gatewayRouteTables(out, l.Gateway, l.Dev) {
				run("ip", "route", "del", l.Gateway+"/32", "dev", l.Dev, "table", table)
			}
		}
	}
	if ln := lanForIP(c, l.Gateway); ln != nil && !sameIP(l.Gateway, lanAddress(ln.IPv4)) {
		run("ip", "neigh", "del", "proxy", l.Gateway, "dev", ln.Bridge)
	}
}

func gatewayRouteTables(routes, gateway, dev string) []string {
	want, bare := gateway+"/32", gateway
	seen := map[string]bool{}
	var out []string
	for _, line := range strings.Split(routes, "\n") {
		f := strings.Fields(line)
		if len(f) < 3 || (f[0] != want && f[0] != bare) {
			continue
		}
		matchDev, table := false, ""
		for i := 1; i+1 < len(f); i++ {
			switch f[i] {
			case "dev":
				matchDev = f[i+1] == dev
			case "table":
				table = f[i+1]
			}
		}
		if matchDev && table != "" && !seen[table] {
			seen[table] = true
			out = append(out, table)
		}
	}
	return out
}

// gatewayRouteCommands installs a gateway host route in both the main and WAN policy tables.
func gatewayRouteCommands(gw, dev, local string, table int) [][]string {
	host := gw + "/32"
	base := []string{"ip", "route", "replace", host, "dev", dev}
	if local != "" {
		base = append(base, "src", local)
	}
	base = append(base, "metric", "0")
	main := append([]string(nil), base...)
	wan := append(append([]string(nil), base...), "table", fmt.Sprint(table))
	return [][]string{main, wan}
}

func sameIP(a, b string) bool { return net.ParseIP(a) != nil && net.ParseIP(a).Equal(net.ParseIP(b)) }

func lanAddress(cidr string) string {
	ip, _, _ := net.ParseCIDR(cidr)
	return ip.String()
}

func lanForIP(c *Config, ip string) *LANNet {
	a := net.ParseIP(ip)
	if a == nil {
		return nil
	}
	for _, ln := range c.LANNets() {
		if _, n, err := net.ParseCIDR(ln.IPv4); err == nil && n.Contains(a) {
			copy := ln
			return &copy
		}
	}
	return nil
}

func lanHostUsesIP(c *Config, ip string) bool {
	for _, h := range c.knownHosts() {
		if sameIP(h.IP, ip) {
			return true
		}
	}
	for _, ln := range c.LANNets() {
		if ln.Zone != "lan" {
			continue
		}
		out, _ := run("ip", "-4", "neigh", "show", "dev", ln.Bridge)
		for _, line := range strings.Split(out, "\n") {
			if f := strings.Fields(line); len(f) > 0 && sameIP(f[0], ip) && neighborOccupies(f) {
				return true
			}
		}
	}
	return false
}

func neighborOccupies(fields []string) bool {
	for _, f := range fields {
		switch f {
		case "REACHABLE", "STALE", "DELAY", "PROBE", "PERMANENT":
			return true
		case "INCOMPLETE", "FAILED":
			return false
		}
	}
	return false
}

func proxyNeighborExists(ip, dev string) bool {
	out, _ := run("ip", "neigh", "show", "proxy", ip, "dev", dev)
	return strings.TrimSpace(out) != ""
}

func deleteProxyNeighbors(c *Config, ip string) {
	for _, ln := range c.LANNets() {
		if ln.Zone == "lan" {
			run("ip", "neigh", "del", "proxy", ip, "dev", ln.Bridge)
		}
	}
}

// dropStaleWANs removes what a WAN that left router.yaml (or moved to another interface: renamed,
// VLAN / device changed) left behind. A PPPoE device takes its routes with it, but an ethernet WAN
// keeps its address and default route: when its client stops, the hook no longer finds it in the new
// router.yaml. A leftover default route with a lower metric than the remaining WANs would take all
// traffic. Leases record the interface, so the leftovers can be found here.
func dropStaleWANs(c *Config) {
	ents, _ := os.ReadDir(wanRunDir)
	live := map[string]bool{}
	for _, w := range c.WAN {
		live[w.Ifname()] = true
	}
	for _, e := range ents {
		name, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok {
			continue
		}
		l, _ := readLease(name)
		if w := c.WANByName(name); w != nil && (l.Dev == "" || l.Dev == w.Ifname()) {
			continue
		}
		if l.Dev != "" && validDev(l.Dev) && !live[l.Dev] {
			logf("wan %s: no longer on %s, removing its address and default route there", name, l.Dev)
			for _, m := range mainDefaultMetrics(l.Dev) {
				run("ip", "route", "del", "default", "dev", l.Dev, "metric", fmt.Sprint(m))
			}
			if ip := net.ParseIP(l.IP).To4(); ip != nil && l.Prefix > 0 && l.Prefix <= 32 {
				run("ip", "-4", "addr", "del", fmt.Sprintf("%s/%d", ip, l.Prefix), "dev", l.Dev)
			}
		}
		if l.Gateway != "" {
			removeGatewayArtifacts(c, l)
		}
		removeLease(name)
	}
}

// removeStalePD6 is committed only after an apply is accepted. Keeping deleted
// WAN PD records through verify lets a failed apply/rollback restore the old
// IPv6 policy state unchanged.
func removeStalePD6(c *Config) {
	ents, _ := os.ReadDir(wanRunDir)
	live := map[string]bool{}
	for _, w := range c.WAN {
		live[w.Name] = true
	}
	for _, e := range ents {
		name, ok := strings.CutSuffix(e.Name(), ".pd6")
		if ok && !live[name] {
			os.Remove(filepath.Join(wanRunDir, e.Name()))
		}
	}
}

// refreshRoutes re-applies wanUp for every WAN that currently has an IPv4 address.
// Used after apply/rollback, when mr-network starts and on health changes, so routing never
// depends on having seen the ppp / dhcp event.
func refreshRoutes(c *Config) {
	dropStaleWANs(c)
	for i := range c.WAN {
		w := &c.WAN[i]
		ifn := w.Ifname()
		addrs := ipv4Addrs(ifn)
		if len(addrs) == 0 {
			if w.Proto == "static" {
				removeLease(w.Name)
			}
			continue
		}
		local := strings.SplitN(addrs[0], "/", 2)[0]
		gw := ""
		switch w.Proto {
		case "static":
			gw = w.Gateway
			l, had := readLease(w.Name)
			if had && l.Gateway != "" && l.Gateway != w.Gateway {
				removeGatewayArtifacts(c, l)
			}
			if !had || l.IP != local {
				l = wanLease{IP: local, Since: time.Now().Unix()}
			}
			l.Gateway, l.DNS, l.Dev = w.Gateway, w.DNS, ifn
			if _, n, err := net.ParseCIDR(addrs[0]); err == nil {
				l.Prefix, _ = n.Mask.Size()
			}
			writeLease(w.Name, l)
		case "dhcp":
			l, ok := readLease(w.Name)
			if !ok {
				continue // address without a lease record: udhcpc will report it on renew
			}
			gw = l.Gateway
		}
		wanUp(c, w, ifn, local, gw)
	}
	// DHCPv6 hooks record renumber state.  Configuration changes retire old
	// prefixes only from netCommit, after apply verification/confirmation, so a
	// rollback never loses the previous prefix record.
	srcDefaults6(c) // health changes move it with the WAN metrics
	writeResolv(c)
}

// netCommit performs the irreversible runtime cleanup only after apply has
// passed verification (and, for a confirm window, after the owner confirms).
func netCommit(c *Config) error {
	removeStalePD6(c)
	pruneRequirePublic(c)
	lan6Renumber(c, true)
	srcDefaults6(c)
	writeResolv(c)
	if err := fwLoadForCommit(c); err != nil {
		return err
	}
	return ipv6RelaySync(c)
}

// writeResolv rewrites resolvConf from the WANs that are up (healthy first, then by metric).
func writeResolv(c *Config) {
	if c.DNS.Upstream != "isp" || !wanDNSFromPeers(c) {
		if c.DNS.Unblock != nil && c.DNS.Unblock.Enabled && c.DNS.Upstream == "manual" {
			servers := dnsUnblockInitialServers(c)
			dnsUnblockRefresh(c, servers)
		}
		if err := proxyNat46DNS64Sync(c); err != nil {
			logf("dns64: %v", err)
		}
		return
	}
	var b strings.Builder
	b.WriteString("# generated by mr: DNS servers of the WANs that are up (healthy first)\n")
	seen := map[string]bool{}
	var servers []string
	for _, w := range sortedWANs(c, wanHealthMap(c)) {
		l, ok := readLease(w.Name)
		if !ok {
			continue
		}
		for _, d := range append(append([]string{}, l.DNS...), l.DNS6...) {
			if !seen[d] && net.ParseIP(d) != nil {
				seen[d] = true
				servers = append(servers, d)
				fmt.Fprintf(&b, "nameserver %s\n", d)
			}
		}
	}
	if len(seen) == 0 {
		for _, d := range c.DNS.Fallback {
			server := strings.SplitN(d, "#", 2)[0]
			if net.ParseIP(server) != nil && !seen[server] {
				seen[server] = true
				servers = append(servers, server)
				fmt.Fprintf(&b, "nameserver %s\n", server)
			}
		}
		if len(seen) == 0 {
			// Never hand dnsmasq an empty (and therefore newest) resolv file: it would drop every
			// upstream. Without this file dnsmasq has no usable ISP source and doctor reports it.
			os.Remove(resolvConf)
			if err := proxyNat46DNS64Sync(c); err != nil {
				logf("dns64: %v", err)
			}
			dnsUnblockRefresh(c, nil)
			return
		}
	}
	if err := writeAtomic(resolvConf, []byte(b.String()), 0644); err != nil {
		logf("resolv: %v", err)
	}
	if len(servers) > 2 {
		servers = servers[:2]
	}
	dnsUnblockRefresh(c, servers)
	if err := proxyNat46DNS64Sync(c); err != nil {
		logf("dns64: %v", err)
	}
}

// hookDhcpcd is called from /etc/dhcpcd.exit-hook with dhcpcd's environment.
func hookDhcpcd(c *Config) error {
	// every event — a WAN's, or a LAN bridge's that gets the delegated prefix — records the RA bridges'
	// prefixes; after a reboot, the first one that finds a prefix there announces those that did not come back (RFC 9096,
	// mod_net_renumber.go)
	defer lan6Renumber(c)
	defer srcDefaults6(c) // every event: the LAN bridge's (address added) as well as the WAN's
	defer func() {
		if err := ipv6RelaySync(c); err != nil {
			logf("IPv6 relay: %v", err)
		}
	}()
	iface, reason := os.Getenv("interface"), os.Getenv("reason")
	w := c.wanByIfname(iface)
	if w == nil {
		return nil
	}
	if updateDHCP6DNS(w, reason, os.Getenv("new_dhcp6_name_servers"), os.Getenv("new_domain_name_servers")) {
		defer writeResolv(c)
	}
	switch reason {
	case "BOUND6", "REBIND6", "RENEW6", "REBOOT6", "INFORM6", "DELEGATED6", "ROUTERADVERT":
	case "EXPIRE6", "RELEASE6", "STOP6", "NOCARRIER", "STOPPED":
		os.Remove(pd6File(w.Name)) // the prefix is gone: policy routes stop sending its sources here
		return refreshLan6ForHook()
	default:
		return refreshLan6ForHook()
	}
	if pds := delegatedPrefixes(os.Environ()); len(pds) > 0 {
		// written only when it changes: its mtime is when this session got the prefix (dial order,
		// mod_net_dial.go); a renewal or router advertisement does not touch it
		if rec := strings.Join(pds, "\n") + "\n"; readFile(pd6File(w.Name)) != rec {
			writeAtomic(pd6File(w.Name), []byte(rec), 0644)
			defer dialOnUp(c, w.Name) // a late prefix can break the dial order too
		}
	}
	// ethernet WANs: routes need the upstream router's link-local gateway (learned from RA); without
	// one a default route means "on link" and every destination would be neighbour-solicited on the WAN.
	// PPPoE is point-to-point: the device is enough.
	var via []string
	if w.Proto != "pppoe" {
		gw6 := mainDefault6(iface)
		if gw6 == "" {
			return refreshLan6ForHook() // no RA yet; the ROUTERADVERT event comes back here
		}
		via = []string{"via", gw6}
		t, _ := c.WANTable(w.Name)
		run("ip", ipv6WANTableRouteArgs(w, wanHealthy(c, w.Name), gw6, t)...)
	}
	if ipv6HealthRoutingEnabled(c) {
		setMainDefault6(w, wanHealthy(c, w.Name))
	}
	for _, pfx := range append(delegatedPrefixes(os.Environ()), strings.Fields(os.Getenv("new_delegated_dhcp6_prefix"))...) {
		// "2405:...::/64" possibly with lifetime suffixes; keep the CIDR part
		pfx = strings.SplitN(pfx, ",", 2)[0]
		if _, _, err := net.ParseCIDR(pfx); err != nil {
			continue
		}
		if !w.SrcRoute { // switched off: drop a source route installed earlier
			run("ip", "-6", "route", "del", "default", "from", pfx, "dev", iface)
			continue
		}
		logf("wan %s: IPv6 source route for %s via %s", w.Name, pfx, iface)
		args := append(append([]string{"-6", "route", "replace", "default", "from", pfx}, via...), "dev", iface, "metric", "512")
		run("ip", args...)
	}
	runOnWAN(c, w.Name, "ipv6")
	return refreshLan6ForHook()
}

func updateDHCP6DNS(w *WAN, reason string, values ...string) bool {
	if !w.PeerDNS {
		return false
	}
	l, ok := readLease(w.Name)
	if !ok {
		return false
	}
	_, ds := splitDNS(3, values...)
	changed := len(ds) > 0
	if changed {
		l.DNS6 = ds
	} else if reason == "EXPIRE6" || reason == "RELEASE6" || reason == "STOP6" || reason == "NOCARRIER" || reason == "STOPPED" {
		changed = len(l.DNS6) > 0
		l.DNS6 = nil
	}
	if changed {
		writeLease(w.Name, l)
	}
	return changed
}

// protoSrc6 marks the main-table IPv6 default routes srcDefaults6 installs.
const protoSrc6 = "97"

// srcDefaults6: the router's own IPv6 traffic (no source chosen yet) follows the main table's default
// route, and without a src on it the kernel may pick an address from another WAN's prefix, which this
// WAN's upstream drops (Cd1s/mini-router#97). With more than one WAN, each WAN with a delegated prefix
// gets `default [via gw] dev WAN src <our address in its prefix> metric <WAN metric+1> proto 97`: in WAN
// metric order, below the RA routes (1024; metric 0 would mean 1024 too), a down WAN raised like IPv4.
// A WAN without prefix, address or gateway loses it (a PPPoE device takes it along when it goes).
func srcDefaults6(c *Config) {
	addrs := globalAddrs6()
	health := wanHealthMap(c)
	for i := range c.WAN {
		w := &c.WAN[i]
		dev := w.Ifname()
		metric := -1
		if src := wanSrc6(strings.Fields(readFile(pd6File(w.Name))), addrs); src != "" && len(c.WAN) > 1 {
			var via []string
			if w.Proto != "pppoe" {
				if gw6 := mainDefault6(dev); gw6 != "" {
					via = []string{"via", gw6}
				}
			}
			if w.Proto == "pppoe" || via != nil {
				metric = src6Metric(w, health[w.Name] != "down")
				run("ip", src6Args(dev, via, src, metric)...)
			}
		}
		rs, _ := ipJSON("-6", "route", "show", "default", "dev", dev, "proto", protoSrc6).([]any)
		for _, r := range rs {
			r, _ := r.(map[string]any)
			if m, _ := r["metric"].(float64); int(m) != metric {
				run("ip", "-6", "route", "del", "default", "dev", dev, "proto", protoSrc6, "metric", fmt.Sprint(int(m)))
			}
		}
	}
}

func src6Metric(w *WAN, healthy bool) int {
	if healthy {
		return w.Metric + 1
	}
	return w.Metric + 1 + downMetric
}

func src6Args(dev string, via []string, src string, metric int) []string {
	args := append([]string{"-6", "route", "replace", "default"}, via...)
	return append(args, "dev", dev, "src", src, "proto", protoSrc6, "metric", fmt.Sprint(metric))
}

// globalAddrs6: the router's global IPv6 addresses that are still preferred (not deprecated / stale).
func globalAddrs6() []string {
	var out []string
	l, _ := ipJSON("-6", "addr", "show", "scope", "global").([]any)
	for _, x := range l {
		m, _ := x.(map[string]any)
		ai, _ := m["addr_info"].([]any)
		for _, a := range ai {
			a, _ := a.(map[string]any)
			if s, _ := a["local"].(string); s != "" && a["preferred_life_time"] != float64(0) && a["tentative"] != true {
				out = append(out, s)
			}
		}
	}
	return out
}

// wanSrc6 returns the first of addrs inside one of the prefixes pfxs ("" if none).
func wanSrc6(pfxs, addrs []string) string {
	for _, a := range addrs {
		ip := net.ParseIP(a)
		for _, p := range pfxs {
			if _, n, err := net.ParseCIDR(p); err == nil && ip != nil && n.Contains(ip) {
				return ip.String()
			}
		}
	}
	return ""
}

var reIAPD = lazyRegexp(`^new_dhcp6_ia_pd([0-9]+)_prefix([0-9]+)=([0-9a-fA-F:]+)$`)

// delegatedPrefixes returns the prefixes dhcpcd reports for the WAN interface itself
// (new_dhcp6_ia_pd1_prefix1=2405:...:: plus new_dhcp6_ia_pd1_prefix1_length=64) as CIDRs.
// new_delegated_dhcp6_prefix only appears on the downstream (LAN) interface's events.
func delegatedPrefixes(env []string) []string {
	vars := map[string]string{}
	for _, kv := range env {
		if k, v, ok := strings.Cut(kv, "="); ok {
			vars[k] = v
		}
	}
	var out []string
	for _, kv := range env {
		m := reIAPD.FindStringSubmatch(kv)
		if m == nil {
			continue
		}
		l := vars["new_dhcp6_ia_pd"+m[1]+"_prefix"+m[2]+"_length"]
		if _, _, err := net.ParseCIDR(m[3] + "/" + l); err == nil {
			out = append(out, m[3]+"/"+l)
		}
	}
	sort.Strings(out)
	return out
}

// hookUdhcpc handles a busybox udhcpc event for a DHCP WAN (called by /usr/libexec/mr/net-udhcpc).
// The lease arrives in the environment and comes from the network: every value is parsed and
// only passed to `ip` as argv.
func hookUdhcpc(c *Config, event string) error {
	iface := os.Getenv("interface")
	w := c.wanByIfname(iface)
	if w == nil || w.Proto != "dhcp" {
		return fmt.Errorf("udhcpc: %q is not a DHCP WAN", iface)
	}
	fwDirty := false
	switch event {
	case "deconfig":
		if _, had := readLease(w.Name); had {
			logf("wan %s: DHCP lease dropped on %s", w.Name, iface)
		}
		wanDown(c, w)
		fwDirty = true
		run("ip", "-4", "addr", "flush", "dev", iface)
		run("ip", "link", "set", iface, "up")
		runOnWAN(c, w.Name, "down")
	case "bound", "renew":
		ip := net.ParseIP(os.Getenv("ip")).To4()
		if ip == nil || ip.IsUnspecified() {
			return fmt.Errorf("udhcpc: bad address %q", os.Getenv("ip"))
		}
		prefix := dhcpPrefix(os.Getenv("mask"), os.Getenv("subnet"))
		gw := ""
		for _, r := range validIPs(4, os.Getenv("router")) {
			if g := net.ParseIP(r).To4(); g != nil && !g.Equal(ip) {
				gw = g.String()
				break
			}
		}
		var dns []string
		if w.PeerDNS {
			dns = validIPs(3, os.Getenv("dns"))
		}
		cidr := fmt.Sprintf("%s/%d", ip, prefix)
		old, had := readLease(w.Name)
		fwDirty = !had || old.Gateway != gw || old.Dev != iface
		if had && old.Gateway != "" && old.Gateway != gw {
			removeGatewayArtifacts(c, old)
		}
		// a new address in the old one's subnet is added as a secondary; with the kernel default
		// promote_secondaries=0, deleting the old primary below would delete the new address too
		os.WriteFile("/proc/sys/net/ipv4/conf/"+iface+"/promote_secondaries", []byte("1"), 0644)
		must("ip", "addr", "replace", cidr, "dev", iface)
		for _, a := range ipv4Addrs(iface) {
			if a != cidr {
				run("ip", "addr", "del", a, "dev", iface)
			}
		}
		since := time.Now().Unix()
		if had && old.IP == ip.String() {
			since = old.Since
		} else {
			logf("wan %s: DHCP %s gateway %s on %s", w.Name, cidr, gw, iface)
		}
		writeLease(w.Name, wanLease{IP: ip.String(), Prefix: prefix, Gateway: gw, DNS: dns, DNS6: old.DNS6, Since: since, Dev: iface})
		wanUp(c, w, iface, ip.String(), gw)
		writeResolv(c)
		runOnWAN(c, w.Name, "up")
	case "leasefail", "nak":
		logf("wan %s: DHCP %s on %s", w.Name, event, iface)
	}
	updateLEDs(c)
	if fwDirty {
		return fwLoad(c)
	}
	return nil
}

// dhcpPrefix: udhcpc exports mask (prefix length) and subnet (dotted); default /24.
func dhcpPrefix(mask, subnet string) int {
	if n, err := strconv.Atoi(mask); err == nil && n >= 1 && n <= 32 {
		return n
	}
	if ip := net.ParseIP(subnet).To4(); ip != nil {
		if ones, bits := net.IPMask(ip).Size(); bits == 32 && ones > 0 {
			return ones
		}
	}
	return 24
}

// hookHealth re-applies routes and the firewall after the health checker changed a WAN's state
// (or started / stopped). Down WANs get the raised metric and lose their table's default route;
// the balance map is re-rendered without them.
func hookHealth(c *Config) error {
	refreshRoutes(c)
	if c.DNS.Unblock != nil && c.DNS.Unblock.Enabled {
		writeResolv(c)
	}
	err := fwLoad(c)
	runOnWAN(c, "", "health")
	return err
}

// wanCommand: DHCP/health hooks, the periodic public-IP review, and WAN status/control commands.
func wanCommand(c *Config, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: mr wan detect PORT [--timeout SECONDS] | dhcp EVENT | health | public-check --cron | status | dial-wait WAN | dial-restore | mac WAN")
	}
	switch args[0] {
	case "detect":
		return wanDetectCommand(c, args)
	case "dial-wait":
		if len(args) == 2 {
			dialWait(c, args[1])
		}
		return nil
	case "dial-restore":
		return dialRestore(c)
	case "mac": // a stable MAC for a PPPoE WAN on a shared port (Cd1s/mini-router#114)
		if len(args) != 2 || c.WANByName(args[1]) == nil {
			return fmt.Errorf("mr wan mac WAN (a configured WAN)")
		}
		w := *c.WANByName(args[1])
		fmt.Println(wanMACSuggest(wanPortMAC(c, w, readFile), w.Name))
		return nil
	case "dhcp":
		if len(args) < 2 {
			return fmt.Errorf("mr wan dhcp EVENT")
		}
		return hookUdhcpc(c, args[1])
	case "health":
		return hookHealth(c)
	case "public-check":
		if len(args) != 2 || args[1] != "--cron" {
			return fmt.Errorf("usage: mr wan public-check --cron")
		}
		return publicIPCheck(c)
	case "status":
		return json.NewEncoder(os.Stdout).Encode(wanRuntime(c))
	}
	return fmt.Errorf("unknown: mr wan %s", args[0])
}
