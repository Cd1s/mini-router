package main

// IPv6 SLAAC relay: a WAN's on-link /64 is also placed on the main LAN bridge and
// LAN neighbours in that prefix are proxied on the WAN. The work is event-driven
// when dhcpcd reports a WAN change and repeated by crond so hosts that appear later
// get a proxy entry without adding an idle daemon.

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strings"
)

const ipv6RelaySet = "ipv6_relay6"

var (
	ipv6RelayStateFile = RunDir + "/ipv6-relay.json"
	ipv6RelayLockFile  = RunDir + "/ipv6-relay.lock"
	ipv6RelayRun       = func(name string, args ...string) (string, error) { return run(name, args...) }
	ipv6RelayRunStdin  = func(input string, name string, args ...string) (string, error) {
		return runStdin(input, name, args...)
	}
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

type ipv6RelayState struct {
	Prefixes []ipv6RelayPrefix `json:"prefixes"`
	Proxies  []ipv6RelayProxy  `json:"proxies"`
	LANAddrs []string          `json:"lan_addrs"`
}

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
	if len(s.Prefixes) == 0 && len(s.Proxies) == 0 && len(s.LANAddrs) == 0 {
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
			addr := p.Addr().Next()
			out = append(out, ipv6RelayPrefix{WAN: w.Name, Dev: w.Ifname(), Prefix: p.String(), Addr: addr.String()})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].WAN+out[i].Prefix < out[j].WAN+out[j].Prefix })
	return out
}

func ipv6RelayNeighbours(bridge string) []netip.Addr {
	out, err := ipv6RelayRun("ip", "-6", "-j", "neigh", "show", "dev", bridge)
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
		good := len(n.State) == 0
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

func ipv6RelaySetScript(prefixes []ipv6RelayPrefix) string {
	var elems []string
	for _, p := range prefixes {
		elems = append(elems, p.Prefix)
	}
	s := "flush set inet mr " + ipv6RelaySet + "\n"
	if len(elems) > 0 {
		s += "add element inet mr " + ipv6RelaySet + " { " + strings.Join(elems, ", ") + " }\n"
	}
	return s
}

func ipv6RelaySync(c *Config) error {
	lk := flock(ipv6RelayLockFile, true)
	if lk == nil {
		return fmt.Errorf("IPv6 relay: cannot lock state")
	}
	defer lk.Close()
	old := readIPv6RelayState()
	cur := ipv6RelayState{Prefixes: ipv6RelayPrefixes(c)}
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
			ipv6RelayRun("ip", "-6", "addr", "del", a, "dev", c.LAN.Bridge)
		}
	}

	for _, p := range cur.Prefixes {
		// Linux only answers proxy-NDP requests on an interface whose per-device
		// proxy_ndp switch is enabled. The interface can be created after network.sh.
		ipv6RelayRun("sysctl", "-q", "-w", "net.ipv6.conf."+p.Dev+".proxy_ndp=1")
		for _, ip := range ipv6RelayNeighbours(c.LAN.Bridge) {
			if !netip.MustParsePrefix(p.Prefix).Contains(ip) || ip.String() == p.Addr {
				continue
			}
			cur.Proxies = append(cur.Proxies, ipv6RelayProxy{Addr: ip.String(), Dev: p.Dev})
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
	for _, p := range old.Proxies {
		if !has(cur.Proxies, p) {
			ipv6RelayRun("ip", "-6", "neigh", "del", "proxy", p.Addr, "dev", p.Dev)
		}
	}
	activeDevs := map[string]bool{}
	for _, p := range cur.Prefixes {
		activeDevs[p.Dev] = true
	}
	for _, p := range old.Prefixes {
		if !activeDevs[p.Dev] {
			ipv6RelayRun("sysctl", "-q", "-w", "net.ipv6.conf."+p.Dev+".proxy_ndp=0")
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
	if ipv6RelayEnabled(c) {
		if _, err := ipv6RelayRunStdin(ipv6RelaySetScript(cur.Prefixes), "nft", "-f", "-"); err != nil {
			return err
		}
	}
	return writeIPv6RelayState(cur)
}
