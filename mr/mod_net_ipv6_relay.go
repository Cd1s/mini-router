package main

// IPv6 SLAAC relay: a WAN's on-link /64 is also placed on the main LAN bridge and
// LAN neighbours in that prefix are proxied on the WAN. dhcpcd / ppp events and apply
// reconcile the state; crond's per-minute run also probes new LAN addresses on the WAN
// and records the verdicts in /run, which every reconcile reads: only an address with an
// unexpired "free" verdict is proxied. No idle daemon is added.

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"sync"
	"time"
)

var (
	ipv6RelayStateFile = RunDir + "/ipv6-relay.json"
	ipv6RelayLockFile  = RunDir + "/ipv6-relay.lock"
	// probe verdicts per WAN device and address (tmpfs; written by the cron run, read by every sync)
	ipv6RelayVerdictFile   = RunDir + "/ipv6-relay-probe.json"
	ipv6RelayProbeLockFile = RunDir + "/ipv6-relay-probe.lock"
	ipv6RelayRun           = func(name string, args ...string) (string, error) { return run(name, args...) }
	ipv6RelaySetProxyNDP   = ipv6RelayProxyNDP
	ipv6RelayProbeFn       = ipv6RelayProbe
	ipv6RelayNow           = time.Now
	ipv6RelaySleep         = time.Sleep
	// probes start only within the budget; one probe (ping6 -W 3 plus the INCOMPLETE re-reads)
	// takes at most about a slot, so a cron run spends at most budget + slot probing
	ipv6RelayProbeBudget = 8 * time.Second
	ipv6RelayProbeSlot   = 6 * time.Second
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

const (
	ipv6RelayMaxProxies    = 64
	ipv6RelayProxyGrace    = 3
	ipv6RelayProbeMax      = 64
	ipv6RelayProbeParallel = 8
	ipv6RelayVerdictTTL    = 10 * time.Minute
	ipv6RelayFree          = "free"
	ipv6RelayOccupied      = "occupied"
)

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
	ipv6RelayDiscover(c)
	return ipv6RelaySyncWait(c, false)
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

// ipv6RelayProbe asks the WAN whether an address is already in use upstream: an echo reply, or a
// usable WAN neighbour entry afterwards (an upstream host answers NS even when it ignores echo),
// means occupied; a FAILED entry (the kernel's NS retries got no answer) means free. Anything else
// — ping6 could not run, the entry is still INCOMPLETE — is unknown and never makes it eligible.
func ipv6RelayProbe(dev, addr string) string {
	if _, err := ipv6RelayRun("ping6", "-c", "1", "-W", "3", "-I", dev, addr); err == nil {
		return ipv6RelayOccupied
	}
	for i := 0; i < 6; i++ {
		switch st := ipv6RelayNeighState(dev, addr); {
		case ipv6RelayUsableState(st):
			return ipv6RelayOccupied
		case st == "FAILED":
			return ipv6RelayFree
		case st == "INCOMPLETE":
			ipv6RelaySleep(250 * time.Millisecond)
		default:
			return ""
		}
	}
	return ""
}

func ipv6RelayUsableState(st string) bool {
	return st == "REACHABLE" || st == "STALE" || st == "DELAY" || st == "PROBE" || st == "PERMANENT"
}

// ipv6RelayNeighState: the first state flag of the neighbour entry for addr on dev ("" = none).
func ipv6RelayNeighState(dev, addr string) string {
	out, err := ipv6RelayRun("ip", "-6", "-j", "neigh", "show", "to", addr, "dev", dev)
	if err != nil {
		return ""
	}
	var ns []struct {
		State []string `json:"state"`
	}
	if json.Unmarshal([]byte(out), &ns) != nil {
		return ""
	}
	for _, n := range ns {
		for _, st := range n.State {
			if ipv6RelayUsableState(st) || st == "FAILED" || st == "INCOMPLETE" {
				return st
			}
		}
	}
	return ""
}

// Probe verdicts are shared by every process (cron, dhcpcd / ppp hooks, apply) through a tmpfs file:
// only an unexpired "free" verdict makes a LAN neighbour eligible for a proxy entry.
type ipv6RelayVerdict struct {
	Result string `json:"result"`
	At     int64  `json:"at"`
	TTL    int64  `json:"ttl"`
}

func ipv6RelayVerdictKey(dev, addr string) string { return dev + " " + addr }

func (v ipv6RelayVerdict) valid(now int64) bool { return v.At <= now && now < v.At+v.TTL }

// readIPv6RelayVerdicts returns the unexpired verdicts.
func readIPv6RelayVerdicts(now int64) map[string]ipv6RelayVerdict {
	m := map[string]ipv6RelayVerdict{}
	b, _ := os.ReadFile(ipv6RelayVerdictFile)
	_ = json.Unmarshal(b, &m)
	for k, v := range m {
		if !v.valid(now) || (v.Result != ipv6RelayFree && v.Result != ipv6RelayOccupied) {
			delete(m, k)
		}
	}
	return m
}

func ipv6RelayEligible(verdicts map[string]ipv6RelayVerdict, dev, addr string) bool {
	return verdicts[ipv6RelayVerdictKey(dev, addr)].Result == ipv6RelayFree
}

// ipv6RelayDiscover probes candidate LAN addresses on the WAN and records the verdicts. Only the
// per-minute cron run calls it, outside the relay state lock, and a run that is still probing makes
// the next one skip. Candidates are filtered before the cap; addresses already proxied come first,
// then ones without a verdict, then verdicts past half their TTL. At most ipv6RelayProbeParallel
// probes run at once and no probe starts after the budget, so a run is bounded; the rest wait for
// the next minute (their verdicts are missing meanwhile, so they are not proxied).
func ipv6RelayDiscover(c *Config) {
	if !ipv6RelayEnabled(c) {
		return
	}
	lk := flock(ipv6RelayProbeLockFile, false)
	if lk == nil {
		return
	}
	defer lk.Close()
	now := ipv6RelayNow().Unix()
	verdicts := readIPv6RelayVerdicts(now)
	proxied := map[string]bool{}
	for _, p := range readIPv6RelayState().Proxies {
		proxied[ipv6RelayVerdictKey(p.Dev, p.Addr)] = true
	}
	lan := ipv6RelayNeighbours(c.LAN.Bridge)
	local := map[string]bool{}
	for _, ip := range ipv6RelayLocalAddrs(c.LAN.Bridge) {
		local[ip.String()] = true
	}
	type candidate struct {
		dev, addr string
		rank      int
	}
	var cands []candidate
	seen := map[string]bool{}
	for _, p := range ipv6RelayPrefixes(c) {
		prefix := netip.MustParsePrefix(p.Prefix)
		wan := map[string]bool{}
		for _, ip := range append(ipv6RelayNeighbours(p.Dev), ipv6RelayLocalAddrs(p.Dev)...) {
			wan[ip.String()] = true
		}
		for _, ip := range lan {
			addr, key := ip.String(), ipv6RelayVerdictKey(p.Dev, ip.String())
			if !prefix.Contains(ip) || addr == p.Addr || local[addr] || seen[key] {
				continue
			}
			seen[key] = true
			if wan[addr] { // the WAN already knows this address: occupied without a probe
				verdicts[key] = ipv6RelayVerdict{Result: ipv6RelayOccupied, At: now, TTL: int64(ipv6RelayVerdictTTL / time.Second)}
				continue
			}
			v, ok := verdicts[key]
			switch {
			case proxied[key] && (!ok || now-v.At >= v.TTL/2):
				cands = append(cands, candidate{p.Dev, addr, 0})
			case !ok:
				cands = append(cands, candidate{p.Dev, addr, 1})
			case now-v.At >= v.TTL/2:
				cands = append(cands, candidate{p.Dev, addr, 2})
			}
		}
	}
	sort.SliceStable(cands, func(i, j int) bool { return cands[i].rank < cands[j].rank })
	if len(cands) > ipv6RelayProbeMax {
		cands = cands[:ipv6RelayProbeMax]
	}
	var mu sync.Mutex
	results := map[string]string{}
	stop := time.Now().Add(ipv6RelayProbeBudget)
	jobs := make(chan candidate)
	var wg sync.WaitGroup
	for i := 0; i < ipv6RelayProbeParallel; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for x := range jobs {
				r := ipv6RelayProbeFn(x.dev, x.addr)
				mu.Lock()
				results[ipv6RelayVerdictKey(x.dev, x.addr)] = r
				mu.Unlock()
			}
		}()
	}
feed:
	for _, x := range cands {
		wait := time.Until(stop)
		if wait <= 0 {
			break
		}
		select {
		case jobs <- x:
		case <-time.After(wait): // every worker is still busy at the end of the budget
			break feed
		}
	}
	close(jobs)
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Until(stop) + ipv6RelayProbeSlot):
		// a probe that overran its slot is dropped; its address keeps no verdict
	}
	mu.Lock()
	at := ipv6RelayNow().Unix()
	for k, r := range results {
		switch r {
		case ipv6RelayFree, ipv6RelayOccupied:
			verdicts[k] = ipv6RelayVerdict{Result: r, At: at, TTL: int64(ipv6RelayVerdictTTL / time.Second)}
		default:
			delete(verdicts, k) // unknown: no verdict, so no proxy until a later run decides
		}
	}
	results = map[string]string{}
	mu.Unlock()
	if len(verdicts) == 0 {
		os.Remove(ipv6RelayVerdictFile)
		return
	}
	if b, err := json.Marshal(verdicts); err == nil {
		writeAtomic(ipv6RelayVerdictFile, b, 0600)
	}
}

// ipv6RelaySync reconciles the LAN relay addresses, prefix routes, proxy entries and /128 host routes
// with the current WAN prefixes, LAN neighbours and probe verdicts. It never probes; every caller
// (dhcpcd / ppp hooks, apply, cron) decides from the same verdict file. wait=false (cron) skips the
// run when another process holds the state lock.
func ipv6RelaySync(c *Config) error { return ipv6RelaySyncWait(c, true) }

func ipv6RelaySyncWait(c *Config, wait bool) error {
	if !ipv6RelayEnabled(c) {
		if _, err := os.Stat(ipv6RelayStateFile); os.IsNotExist(err) {
			return nil
		}
		wait = false
	}
	lk := flock(ipv6RelayLockFile, wait)
	if lk == nil {
		if !wait {
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
		if !containsString(cur.LANAddrs, a) {
			ipv6RelayRun("ip", "-6", "addr", "replace", a, "dev", c.LAN.Bridge, "preferred_lft", "0", "valid_lft", "2700")
		}
	}

	verdicts := readIPv6RelayVerdicts(ipv6RelayNow().Unix())
	lanNeigh := ipv6RelayNeighbours(c.LAN.Bridge)
	local := map[string]bool{}
	for _, ip := range ipv6RelayLocalAddrs(c.LAN.Bridge) {
		local[ip.String()] = true
	}
	wanSets := map[string]map[string]bool{}
	oldProxy := map[ipv6RelayProxy]bool{}
	for _, p := range old.Proxies {
		oldProxy[p] = true
	}
	var eligible []ipv6RelayProxy
	for _, p := range cur.Prefixes {
		// The same /64 is connected on br-lan and the WAN. Prefer the WAN for destinations
		// that are not proxied LAN hosts; the /128 LAN host routes below keep those on the bridge.
		ipv6RelayRun("ip", "-6", "route", "replace", p.Prefix, "dev", p.Dev, "proto", "static", "metric", "100")
		if err := ipv6RelaySetProxyNDP(p.Dev, true); err != nil {
			return fmt.Errorf("IPv6 relay proxy_ndp %s: %v", p.Dev, err)
		}
		if wanSets[p.Dev] == nil {
			wanSets[p.Dev] = map[string]bool{}
			for _, ip := range append(ipv6RelayNeighbours(p.Dev), ipv6RelayLocalAddrs(p.Dev)...) {
				wanSets[p.Dev][ip.String()] = true
			}
		}
		prefix := netip.MustParsePrefix(p.Prefix)
		for _, ip := range lanNeigh {
			addr := ip.String()
			if !prefix.Contains(ip) || addr == p.Addr || local[addr] || wanSets[p.Dev][addr] || !ipv6RelayEligible(verdicts, p.Dev, addr) {
				continue
			}
			eligible = append(eligible, ipv6RelayProxy{Addr: addr, Dev: p.Dev})
		}
	}
	// the cap keeps entries that are already proxied first, so new addresses cannot push them out
	sort.SliceStable(eligible, func(i, j int) bool { return oldProxy[eligible[i]] && !oldProxy[eligible[j]] })
	for _, x := range eligible {
		if len(cur.Proxies) < ipv6RelayMaxProxies && !ipv6RelayHasProxy(cur.Proxies, x) {
			cur.Proxies = append(cur.Proxies, x)
		}
	}
	// A proxied host that dropped out of the LAN neighbour table keeps its entry for a few scans
	// (hysteresis against reply gaps). Every other reason to stop — no unexpired free verdict, an
	// occupied verdict, the WAN or the router has the address, the prefix is gone — removes it now.
	inPrefix := func(x ipv6RelayProxy) bool {
		ip, err := netip.ParseAddr(x.Addr)
		if err != nil {
			return false
		}
		for _, p := range cur.Prefixes {
			if p.Dev == x.Dev && netip.MustParsePrefix(p.Prefix).Contains(ip) && p.Addr != x.Addr {
				return true
			}
		}
		return false
	}
	for _, p := range old.Proxies {
		if ipv6RelayHasProxy(cur.Proxies, p) {
			continue
		}
		key := p.Dev + "\x00" + p.Addr
		if inPrefix(p) && ipv6RelayEligible(verdicts, p.Dev, p.Addr) && !local[p.Addr] && !wanSets[p.Dev][p.Addr] &&
			len(cur.Proxies) < ipv6RelayMaxProxies && old.Misses[key] < ipv6RelayProxyGrace {
			cur.Proxies = append(cur.Proxies, p)
			cur.Misses[key] = old.Misses[key] + 1
			continue
		}
		ipv6RelayRun("ip", "-6", "neigh", "del", "proxy", p.Addr, "dev", p.Dev)
	}
	sort.Slice(cur.Proxies, func(i, j int) bool {
		return cur.Proxies[i].Dev+cur.Proxies[i].Addr < cur.Proxies[j].Dev+cur.Proxies[j].Addr
	})
	for _, p := range cur.Proxies {
		cur.Routes = append(cur.Routes, ipv6RelayRoute{Addr: p.Addr, Dev: c.LAN.Bridge})
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
	routeHas := func(rs []ipv6RelayRoute, want ipv6RelayRoute) bool {
		for _, r := range rs {
			if r == want {
				return true
			}
		}
		return false
	}
	for _, r := range old.Routes {
		if !routeHas(cur.Routes, r) {
			ipv6RelayRun("ip", "-6", "route", "del", r.Addr+"/128", "dev", r.Dev, "proto", "static", "metric", "50")
		}
	}
	for _, r := range cur.Routes {
		if !routeHas(old.Routes, r) {
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
		if !oldProxy[p] {
			ipv6RelayRun("ip", "-6", "neigh", "replace", "proxy", p.Addr, "dev", p.Dev)
		}
	}
	if prefixesChanged {
		// dnsmasq's constructor: range notices the new address, but a reload makes the
		// first RA immediate and emits a zero-lifetime RA when a prefix is removed.
		ipv6RelayRun("rc-service", "dnsmasq", "reload")
	}
	if !ipv6RelayEnabled(c) {
		os.Remove(ipv6RelayVerdictFile)
	}
	return writeIPv6RelayState(cur)
}

func ipv6RelayHasProxy(xs []ipv6RelayProxy, x ipv6RelayProxy) bool {
	for _, y := range xs {
		if x == y {
			return true
		}
	}
	return false
}
