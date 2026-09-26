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
	wanRunDir    = RunDir + "/wan"
	wanStateFile = RunDir + "/wan-state.json"
	resolvConf   = RunDir + "/resolv.conf"
)

// wanLease is what a WAN got when it came up.
type wanLease struct {
	IP      string   `json:"ip"`
	Prefix  int      `json:"prefix,omitempty"`
	Gateway string   `json:"gateway,omitempty"`
	DNS     []string `json:"dns,omitempty"`
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

// wanHealthMap is readWanState when the health checker is configured, else empty (all healthy).
func wanHealthMap(c *Config) map[string]string {
	if !c.MultiWAN.Enabled() {
		return map[string]string{}
	}
	return readWanState()
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
	if up {
		logf("wan %s up on %s (%s)", w.Name, ifname, args[3])
		l := wanLease{IP: args[3], Since: time.Now().Unix(), Dev: ifname}
		if net.ParseIP(args[4]) != nil {
			l.Gateway = args[4]
		}
		if w.PeerDNS { // pppd exports the peer's DNS servers to ip-up
			l.DNS = validIPs(3, os.Getenv("DNS1"), os.Getenv("DNS2"))
		}
		writeLease(w.Name, l)
		wanUp(c, w, ifname, args[3], "")
		writeResolv(c)
	} else {
		logf("wan %s down on %s", w.Name, ifname)
		wanDown(c, w)
	}
	updateLEDs(c)
	err := fwLoad(c)
	if up {
		runOnWAN(c, w.Name, "up")
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
	if w.Proto == "pppoe" {
		must("ip", "-6", "route", "replace", "default", "dev", ifname, "table", ts)
	} else if gw6 := mainDefault6(ifname); gw6 != "" {
		must("ip", "-6", "route", "replace", "default", "via", gw6, "dev", ifname, "table", ts)
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
	removeLease(w.Name)
	writeResolv(c)
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
		removeLease(name)
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
			continue
		}
		local := strings.SplitN(addrs[0], "/", 2)[0]
		gw := ""
		switch w.Proto {
		case "static":
			gw = w.Gateway
			l, had := readLease(w.Name)
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
	writeResolv(c)
}

// writeResolv rewrites resolvConf from the WANs that are up (healthy first, then by metric).
func writeResolv(c *Config) {
	if !wanDNSFromPeers(c) {
		return
	}
	var b strings.Builder
	b.WriteString("# generated by mr: DNS servers of the WANs that are up (healthy first)\n")
	seen := map[string]bool{}
	for _, w := range sortedWANs(c, wanHealthMap(c)) {
		l, ok := readLease(w.Name)
		if !ok {
			continue
		}
		for _, d := range l.DNS {
			if !seen[d] && net.ParseIP(d) != nil {
				seen[d] = true
				fmt.Fprintf(&b, "nameserver %s\n", d)
			}
		}
	}
	if len(seen) == 0 {
		// Never hand dnsmasq an empty (and therefore newest) resolv file: it would drop every
		// upstream. Without this file dnsmasq keeps what it has / uses its other resolv files
		// (e.g. right after an upgrade, before the WANs have re-dialled and written lease records).
		os.Remove(resolvConf)
		return
	}
	if err := writeAtomic(resolvConf, []byte(b.String()), 0644); err != nil {
		logf("resolv: %v", err)
	}
}

// hookDhcpcd is called from /etc/dhcpcd.exit-hook with dhcpcd's environment.
func hookDhcpcd(c *Config) error {
	// every event — a WAN's, or a LAN bridge's that gets the delegated prefix — records the RA bridges'
	// prefixes; after a reboot, the first one that finds a prefix there announces those that did not come back (RFC 9096,
	// mod_net_renumber.go)
	defer lan6Renumber(c)
	iface, reason := os.Getenv("interface"), os.Getenv("reason")
	w := c.wanByIfname(iface)
	if w == nil {
		return nil
	}
	switch reason {
	case "BOUND6", "REBIND6", "RENEW6", "REBOOT6", "INFORM6", "DELEGATED6", "ROUTERADVERT":
	case "EXPIRE6", "RELEASE6", "STOP6", "NOCARRIER", "STOPPED":
		os.Remove(pd6File(w.Name)) // the prefix is gone: policy routes stop sending its sources here
		return refreshLan6()
	default:
		return refreshLan6()
	}
	if pds := delegatedPrefixes(os.Environ()); len(pds) > 0 {
		writeAtomic(pd6File(w.Name), []byte(strings.Join(pds, "\n")+"\n"), 0644)
	}
	// ethernet WANs: routes need the upstream router's link-local gateway (learned from RA); without
	// one a default route means "on link" and every destination would be neighbour-solicited on the WAN.
	// PPPoE is point-to-point: the device is enough.
	var via []string
	if w.Proto != "pppoe" {
		gw6 := mainDefault6(iface)
		if gw6 == "" {
			return refreshLan6() // no RA yet; the ROUTERADVERT event comes back here
		}
		via = []string{"via", gw6}
		t, _ := c.WANTable(w.Name)
		run("ip", "-6", "route", "replace", "default", "via", gw6, "dev", iface, "table", fmt.Sprint(t))
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
	return refreshLan6()
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
	switch event {
	case "deconfig":
		if _, had := readLease(w.Name); had {
			logf("wan %s: DHCP lease dropped on %s", w.Name, iface)
		}
		wanDown(c, w)
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
		writeLease(w.Name, wanLease{IP: ip.String(), Prefix: prefix, Gateway: gw, DNS: dns, Since: since, Dev: iface})
		wanUp(c, w, iface, ip.String(), gw)
		writeResolv(c)
		runOnWAN(c, w.Name, "up")
	case "leasefail", "nak":
		logf("wan %s: DHCP %s on %s", w.Name, event, iface)
	}
	updateLEDs(c)
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
	err := fwLoad(c)
	runOnWAN(c, "", "health")
	return err
}

// wanCommand: `mr wan dhcp EVENT` (udhcpc script), `mr wan health` (net-wanmon), `mr wan status`.
func wanCommand(c *Config, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: mr wan dhcp EVENT | health | status")
	}
	switch args[0] {
	case "dhcp":
		if len(args) < 2 {
			return fmt.Errorf("mr wan dhcp EVENT")
		}
		return hookUdhcpc(c, args[1])
	case "health":
		return hookHealth(c)
	case "status":
		return json.NewEncoder(os.Stdout).Encode(wanRuntime(c))
	}
	return fmt.Errorf("unknown: mr wan %s", args[0])
}
