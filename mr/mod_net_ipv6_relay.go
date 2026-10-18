package main

// IPv6 SLAAC relay: a WAN's on-link /64 is also placed on the main LAN bridge and
// LAN neighbours in that prefix are proxied on the WAN. The work is event-driven
// when dhcpcd reports a WAN change and repeated by crond so hosts that appear later
// get a proxy entry without adding an idle daemon.

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
)

var (
	ipv6RelayStateFile   = RunDir + "/ipv6-relay.json"
	ipv6RelayLockFile    = RunDir + "/ipv6-relay.lock"
	ipv6RelayRun         = func(name string, args ...string) (string, error) { return run(name, args...) }
	ipv6RelaySetProxyNDP = ipv6RelayProxyNDP
)

type ipv6RelayPrefix struct {
	WAN    string `json:"wan"`
	Dev    string `json:"dev"`
	Prefix string `json:"prefix"`
	Addr   string `json:"addr"`
}

type ipv6RelayProxy struct {
	Addr string `json:"addr"`
	Dev  string `json:"dev"`
}

type ipv6RelayRoute struct {
	Addr string `json:"addr"`
	Dev  string `json:"dev"`
}

type ipv6RelayState struct {
	Prefixes []ipv6RelayPrefix `json:"prefixes"`
	Proxies  []ipv6RelayProxy  `json:"proxies"`
	Routes   []ipv6RelayRoute  `json:"routes,omitempty"`
	Misses   map[string]int    `json:"misses,omitempty"`
	LANAddrs []string          `json:"lan_addrs"`
}

const ipv6RelayMaxProxies = 64
const ipv6RelayProxyGrace = 3
const ipv6RelayProbeMax = 64

func ipv6RelayEnabled(c *Config) bool {
	if c == nil || !c.LAN.IPv6RA {
		return false
	}
	for _, w := range c.WAN {
		if w.IPv6Relay && w.IPv6 {
			return true
		}
	}
	return false
}

func ipv6RelayCronLine(c *Config) []string {
	if !ipv6RelayEnabled(c) {
		return nil
	}
	return []string{"# ipv6 relay", "* * * * * " + mrBin + " net ipv6-relay --cron"}
}

func netCommand(c *Config, args []string) error {
	if len(args) != 2 || args[0] != "ipv6-relay" || args[1] != "--cron" {
		return fmt.Errorf("usage: mr net ipv6-relay --cron")
	}
	return ipv6RelaySync(c)
}

func readIPv6RelayState() ipv6RelayState {
	var s ipv6RelayState
	b, _ := os.ReadFile(ipv6RelayStateFile)
	_ = json.Unmarshal(b, &s)
	return s
}

func writeIPv6RelayState(s ipv6RelayState) error {
	if len(s.Prefixes) == 0 && len(s.Proxies) == 0 && len(s.Routes) == 0 && len(s.LANAddrs) == 0 {
		err := os.Remove(ipv6RelayStateFile)
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return writeAtomic(ipv6RelayStateFile, b, 0600)
}

// ipv6RelayWANAddrs returns stable global /64 SLAAC addresses on a WAN. A delegated
// prefix is deliberately checked separately: PD owns the LAN prefix whenever present.
func ipv6RelayWANAddrs(dev string) []netip.Prefix {
	out, err := ipv6RelayRun("ip", "-6", "-j", "addr", "show", "dev", dev, "scope", "global")
	if err != nil {
		return nil
	}
	var links []struct {
		AddrInfo []struct {
			Family    string `json:"family"`
			Local     string `json:"local"`
			Prefixlen int    `json:"prefixlen"`
			Tentative bool   `json:"tentative"`
			Temporary bool   `json:"temporary"`
		} `json:"addr_info"`
	}
	if json.Unmarshal([]byte(out), &links) != nil {
		return nil
	}
	seen := map[string]bool{}
	var prefixes []netip.Prefix
	for _, l := range links {
		for _, a := range l.AddrInfo {
			ip, err := netip.ParseAddr(a.Local)
			if err != nil || a.Family != "inet6" || a.Prefixlen != 64 || a.Tentative || a.Temporary || !ip.IsGlobalUnicast() {
				continue
			}
			p := netip.PrefixFrom(ip, 64).Masked()
			if !seen[p.String()] {
				seen[p.String()] = true
				prefixes = append(prefixes, p)
			}
		}
	}
	return prefixes
}

func ipv6RelayPrefixes(c *Config) []ipv6RelayPrefix {
	var out []ipv6RelayPrefix
	seen := map[string]bool{}
	for _, w := range c.WAN {
		if !w.IPv6Relay || !w.IPv6 || len(pd6Prefixes(w.Name)) > 0 {
			continue // delegated prefixes have priority over relay
		}
		for _, p := range ipv6RelayWANAddrs(w.Ifname()) {
			key := w.Name + "\x00" + p.String()
			if seen[key] {
				continue
			}
			seen[key] = true
			addr := netip.MustParseAddr(ipv6RelayLANAddr(p, c.LAN.Bridge))
			out = append(out, ipv6RelayPrefix{WAN: w.Name, Dev: w.Ifname(), Prefix: p.String(), Addr: addr.String()})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].WAN+out[i].Prefix < out[j].WAN+out[j].Prefix })
	return out
}

func ipv6RelayNeighbours(dev string) []netip.Addr {
	out, err := ipv6RelayRun("ip", "-6", "-j", "neigh", "show", "dev", dev)
	if err != nil {
		return nil
	}
	var ns []struct {
		Dst   string   `json:"dst"`
		State []string `json:"state"`
	}
	if json.Unmarshal([]byte(out), &ns) != nil {
		return nil
	}
	var addrs []netip.Addr
	for _, n := range ns {
		ip, err := netip.ParseAddr(n.Dst)
		if err != nil || !ip.IsGlobalUnicast() {
			continue
		}
		good := false
		for _, st := range n.State {
			if st == "REACHABLE" || st == "STALE" || st == "DELAY" || st == "PROBE" || st == "PERMANENT" {
				good = true
			}
		}
		if good {
			addrs = append(addrs, ip)
		}
	}
	return addrs
}

func ipv6RelayLocalAddrs(dev string) []netip.Addr {
	out, err := ipv6RelayRun("ip", "-6", "-j", "addr", "show", "dev", dev, "scope", "global")
	if err != nil {
		return nil
	}
	var links []struct {
		AddrInfo []struct {
			Family string `json:"family"`
			Local  string `json:"local"`
		} `json:"addr_info"`
	}
	if json.Unmarshal([]byte(out), &links) != nil {
		return nil
	}
	var outAddrs []netip.Addr
	for _, l := range links {
		for _, a := range l.AddrInfo {
			ip, err := netip.ParseAddr(a.Local)
			if err == nil && a.Family == "inet6" && ip.IsGlobalUnicast() {
				outAddrs = append(outAddrs, ip)
			}
		}
	}
	return outAddrs
}

func ipv6RelayLANAddr(prefix netip.Prefix, bridge string) string {
	out, err := ipv6RelayRun("ip", "-j", "link", "show", "dev", bridge)
	var links []struct {
		Address string `json:"address"`
	}
	if err == nil && json.Unmarshal([]byte(out), &links) == nil && len(links) > 0 {
		if mac, err := net.ParseMAC(links[0].Address); err == nil && len(mac) == 6 {
			b := prefix.Addr().As16()
			b[8] = mac[0] ^ 2
			copy(b[9:11], mac[1:3])
			b[11], b[12] = 0xff, 0xfe
			copy(b[13:], mac[3:])
			return netip.AddrFrom16(b).String()
		}
	}
	// A bridge without a readable MAC is unusual, but ::2 avoids the common upstream ::1.
	return prefix.Addr().Next().Next().String()
}

func ipv6RelayProxyNDP(dev string, enabled bool) error {
	value := "0\n"
	if enabled {
		value = "1\n"
	}
	path := "/proc/sys/net/ipv6/conf/" + dev + "/proxy_ndp"
	return os.WriteFile(path, []byte(value), 0644)
}

// ipv6RelayProbe asks the WAN whether an address is already occupied upstream.
// A reply means the address must never be proxied from LAN. The caller bounds
// the number of probes per scan so a hostile neighbour table cannot create
// unbounded work.
func ipv6RelayProbe(dev, addr string) bool {
	_, err := ipv6RelayRun("ping6", "-c", "1", "-W", "1", "-I", dev, addr)
	return err == nil
}

func ipv6RelaySync(c *Config) error {
	if !ipv6RelayEnabled(c) {
		if _, err := os.Stat(ipv6RelayStateFile); os.IsNotExist(err) {
			return nil
		}
	}
	wait := true
	if !ipv6RelayEnabled(c) {
		wait = false
	}
	lk := flock(ipv6RelayLockFile, wait)
	if lk == nil {
		if !ipv6RelayEnabled(c) {
			return nil
		}
		return fmt.Errorf("IPv6 relay: cannot lock state")
	}
	defer lk.Close()
	old := readIPv6RelayState()
	cur := ipv6RelayState{Prefixes: ipv6RelayPrefixes(c), Misses: map[string]int{}}
	prefixesChanged := len(old.Prefixes) != len(cur.Prefixes)
	if !prefixesChanged {
		for i := range old.Prefixes {
			if old.Prefixes[i] != cur.Prefixes[i] {
				prefixesChanged = true
				break
			}
		}
	}
	for _, p := range cur.Prefixes {
		if !containsString(old.LANAddrs, p.Addr+"/64") {
			if _, err := ipv6RelayRun("ip", "-6", "addr", "replace", p.Addr+"/64", "dev", c.LAN.Bridge); err != nil {
				return fmt.Errorf("IPv6 relay LAN address %s: %v", p.Addr, err)
			}
		}
		ipv6RelayRun("ip", "-6", "route", "replace", p.Addr+"/128", "dev", c.LAN.Bridge, "proto", "static", "metric", "50")
		cur.LANAddrs = append(cur.LANAddrs, p.Addr+"/64")
	}
	for _, a := range old.LANAddrs {
		keep := false
		for _, x := range cur.LANAddrs {
			if x == a {
				keep = true
			}
		}
		if !keep {
			if ip, err := netip.ParsePrefix(a); err == nil {
				ipv6RelayRun("ip", "-6", "route", "del", ip.Addr().String()+"/128", "dev", c.LAN.Bridge, "proto", "static", "metric", "50")
			}
			ipv6RelayRun("ip", "-6", "addr", "replace", a, "dev", c.LAN.Bridge, "preferred_lft", "0", "valid_lft", "2700")
		}
	}

	lanNeigh := ipv6RelayNeighbours(c.LAN.Bridge)
	local := ipv6RelayLocalAddrs(c.LAN.Bridge)
	localSet := map[string]bool{}
	for _, ip := range local {
		localSet[ip.String()] = true
	}
	probeCount := 0
	for _, p := range cur.Prefixes {
		// The same /64 is connected on br-lan and the WAN. Prefer the WAN for
		// destinations that are not known LAN neighbours; install /128 LAN host
		// routes below to keep local traffic on the bridge.
		ipv6RelayRun("ip", "-6", "route", "replace", p.Prefix, "dev", p.Dev, "proto", "static", "metric", "100")
		if err := ipv6RelaySetProxyNDP(p.Dev, true); err != nil {
			return fmt.Errorf("IPv6 relay proxy_ndp %s: %v", p.Dev, err)
		}
		wanNeigh := ipv6RelayNeighbours(p.Dev)
		wanSet := map[string]bool{}
		for _, ip := range append(wanNeigh, ipv6RelayLocalAddrs(p.Dev)...) {
			wanSet[ip.String()] = true
		}
		prefix := netip.MustParsePrefix(p.Prefix)
		for _, ip := range lanNeigh {
			addr := ip.String()
			if !prefix.Contains(ip) || addr == p.Addr || localSet[addr] || wanSet[addr] || len(cur.Proxies) >= ipv6RelayMaxProxies {
				continue
			}
			if probeCount >= ipv6RelayProbeMax {
				continue
			}
			probeCount++
			if ipv6RelayProbe(p.Dev, addr) {
				continue
			}
			proxy := ipv6RelayProxy{Addr: addr, Dev: p.Dev}
			cur.Proxies = append(cur.Proxies, proxy)
			cur.Routes = append(cur.Routes, ipv6RelayRoute{Addr: addr, Dev: c.LAN.Bridge})
		}
	}
	// The router's own relay address is a local LAN route; it is never a proxy.
	for _, p := range cur.Prefixes {
		cur.Routes = append(cur.Routes, ipv6RelayRoute{Addr: p.Addr, Dev: c.LAN.Bridge})
	}
	for _, p := range old.Prefixes {
		found := false
		for _, now := range cur.Prefixes {
			if p == now {
				found = true
			}
		}
		if !found {
			ipv6RelayRun("ip", "-6", "route", "del", p.Prefix, "dev", p.Dev, "proto", "static", "metric", "100")
		}
	}
	sort.Slice(cur.Proxies, func(i, j int) bool {
		return cur.Proxies[i].Dev+cur.Proxies[i].Addr < cur.Proxies[j].Dev+cur.Proxies[j].Addr
	})
	has := func(xs []ipv6RelayProxy, x ipv6RelayProxy) bool {
		for _, y := range xs {
			if x == y {
				return true
			}
		}
		return false
	}
	activePrefix := func(dev, addr string) bool {
		ip, err := netip.ParseAddr(addr)
		if err != nil {
			return false
		}
		for _, p := range cur.Prefixes {
			if p.Dev == dev && netip.MustParsePrefix(p.Prefix).Contains(ip) {
				return true
			}
		}
		return false
	}
	for _, p := range old.Proxies {
		if has(cur.Proxies, p) {
			continue
		}
		if activePrefix(p.Dev, p.Addr) && old.Misses[p.Dev+"\x00"+p.Addr] < ipv6RelayProxyGrace {
			cur.Proxies = append(cur.Proxies, p)
			cur.Routes = append(cur.Routes, ipv6RelayRoute{Addr: p.Addr, Dev: c.LAN.Bridge})
			cur.Misses[p.Dev+"\x00"+p.Addr] = old.Misses[p.Dev+"\x00"+p.Addr] + 1
			continue
		}
		ipv6RelayRun("ip", "-6", "neigh", "del", "proxy", p.Addr, "dev", p.Dev)
	}
	legacyRoutes := append([]ipv6RelayRoute{}, old.Routes...)
	if len(legacyRoutes) == 0 {
		for _, a := range old.LANAddrs {
			if ip, err := netip.ParsePrefix(a); err == nil {
				legacyRoutes = append(legacyRoutes, ipv6RelayRoute{Addr: ip.Addr().String(), Dev: c.LAN.Bridge})
			}
		}
		for _, p := range old.Proxies {
			legacyRoutes = append(legacyRoutes, ipv6RelayRoute{Addr: p.Addr, Dev: c.LAN.Bridge})
		}
	}
	routeKey := func(r ipv6RelayRoute) string { return r.Dev + "\x00" + r.Addr }
	routeHas := func(rs []ipv6RelayRoute, want ipv6RelayRoute) bool {
		for _, r := range rs {
			if routeKey(r) == routeKey(want) {
				return true
			}
		}
		return false
	}
	for _, r := range legacyRoutes {
		if !routeHas(cur.Routes, r) {
			ipv6RelayRun("ip", "-6", "route", "del", r.Addr+"/128", "dev", r.Dev, "proto", "static", "metric", "50")
		}
	}
	for _, r := range cur.Routes {
		if !routeHas(legacyRoutes, r) {
			ipv6RelayRun("ip", "-6", "route", "replace", r.Addr+"/128", "dev", r.Dev, "proto", "static", "metric", "50")
		}
	}
	activeDevs := map[string]bool{}
	for _, p := range cur.Prefixes {
		activeDevs[p.Dev] = true
	}
	for _, p := range old.Prefixes {
		if !activeDevs[p.Dev] {
			ipv6RelaySetProxyNDP(p.Dev, false)
		}
	}
	for _, p := range cur.Proxies {
		if !has(old.Proxies, p) {
			ipv6RelayRun("ip", "-6", "neigh", "replace", "proxy", p.Addr, "dev", p.Dev)
		}
	}
	if prefixesChanged {
		// dnsmasq's constructor: range notices the new address, but a reload makes the
		// first RA immediate and emits a zero-lifetime RA when a prefix is removed.
		ipv6RelayRun("rc-service", "dnsmasq", "reload")
	}
	return writeIPv6RelayState(cur)
}
