package main

// net module: IPv6 renumbering on the LAN side (RFC 9096 §3.5, signalling stale prefixes).
//
// dnsmasq advertises whatever global address a LAN bridge has (dhcp-range=::,constructor:<bridge>).
// When dhcpcd removes a delegated prefix (PPPoE redial, lease lost), dnsmasq keeps advertising that
// prefix as an old one — preferred lifetime 0 — for the rest of its lifetime (at most 2 h), so the
// clients stop using it at once and take the new prefix. What dnsmasq cannot know is a prefix it
// advertised before a reboot, power cut or upgrade: ISPs that hand out a new prefix per PPPoE session
// leave the clients holding the dead one as preferred until the RA lifetime (dhcp.ipv6.lease) ends.
//
// So the addresses last advertised on the RA bridges are recorded on flash, per WAN that delegated them
// (the dhcpcd hook's pd6 record). A WAN without addresses for the moment (release, link down, shutdown:
// dhcpcd's RELEASE6 / STOP6 / STOPPED remove the pd6 record and the addresses) keeps its record; once it
// has addresses again, every recorded one that has not come back — after a reboot or a PPPoE redial in
// the same boot — is put on its bridge once more for lan6StalePreferred seconds of preferred lifetime:
// dnsmasq sees it, advertises it, sees the kernel deprecate it and then advertises it as an old prefix
// like any other. If the ISP hands out the same prefix again, nothing is stale. Flash is written only when
// a non-empty set changes. Runs from the dhcpcd hook; nothing resident. mr-dhcpcd starts after dnsmasq,
// so the first event after boot finds it running.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
)

var lan6StateFile = "/etc/mini-router/state/lan6-prefixes.json"

// lan6StalePreferred: preferred lifetime (seconds) of a stale address put back. Long
// enough for dnsmasq to notice it and advertise it once, short enough that clients stop using it at once.
const lan6StalePreferred = 10

// lan6State: the addresses last advertised per WAN x bridge. Keys are "<wan> <bridge>" (lan6Key).
type lan6State struct {
	Addrs map[string][]string `json:"addrs"` // "wan br-lan" -> ["2001:db8:1::1/64", ...]
}

func lan6Key(wan, br string) string { return wan + " " + br }

// lan6ByWAN files the bridges' addresses (cur, by bridge) under the WAN whose delegated prefix holds
// them (pds, by WAN). Every WAN x bridge pair gets a key, empty while that WAN has not delegated there.
func lan6ByWAN(cur map[string][]string, wans []string, pds map[string][]netip.Prefix) map[string][]string {
	out := map[string][]string{}
	for br, as := range cur {
		for _, w := range wans {
			k := lan6Key(w, br)
			out[k] = nil
			for _, a := range as {
				ap, err := netip.ParsePrefix(a)
				for _, p := range pds[w] {
					if err == nil && p.Contains(ap.Addr()) {
						out[k] = append(out[k], a)
						break
					}
				}
			}
		}
	}
	return out
}

// lan6Addrs parses `ip -j -6 addr show dev BRIDGE scope global` into the addresses dnsmasq advertises
// a prefix for: not deprecated or tentative, and not one of the stale addresses put back here
// (their preferred lifetime is at most lan6StalePreferred).
func lan6Addrs(j []byte) []string {
	var links []struct {
		Addrs []struct {
			Family     string `json:"family"`
			Local      string `json:"local"`
			Prefixlen  int    `json:"prefixlen"`
			Deprecated bool   `json:"deprecated"`
			Tentative  bool   `json:"tentative"`
			Temporary  bool   `json:"temporary"`
			Preferred  uint64 `json:"preferred_life_time"`
		} `json:"addr_info"`
	}
	json.Unmarshal(j, &links)
	var out []string
	for _, l := range links {
		for _, a := range l.Addrs {
			if a.Family != "inet6" || a.Deprecated || a.Tentative || a.Temporary || a.Preferred <= lan6StalePreferred {
				continue
			}
			if s, ok := lan6CIDR(fmt.Sprintf("%s/%d", a.Local, a.Prefixlen)); ok {
				out = append(out, s)
			}
		}
	}
	sort.Strings(out)
	return out
}

// lan6CIDR: a global unicast IPv6 address with its prefix length, canonical (it is read back from
// flash and passed to ip(8)).
func lan6CIDR(s string) (string, bool) {
	ip, n, err := net.ParseCIDR(s)
	if err != nil || ip.To4() != nil || !ip.IsGlobalUnicast() {
		return "", false
	}
	ones, _ := n.Mask.Size()
	return fmt.Sprintf("%s/%d", ip, ones), true
}

// lan6Plan compares what the bridges have now (cur, lan6ByWAN) with the record. A key without addresses
// now keeps its record (dhcpcd events come before the delegation, WANs delegate at different times, and
// the prefix the ISP may hand out again must not be deprecated in between); a key with addresses replaces
// it, and the recorded ones that are gone are stale. WANs and bridges that no longer do RA are left out
// (nothing advertises there).
func lan6Plan(prev lan6State, cur map[string][]string) (stale map[string][]string, next lan6State) {
	next = lan6State{Addrs: map[string][]string{}}
	stale = map[string][]string{}
	for k, now := range cur {
		if len(now) == 0 {
			if len(prev.Addrs[k]) > 0 {
				next.Addrs[k] = prev.Addrs[k]
			}
			continue
		}
		next.Addrs[k] = now
		for _, a := range prev.Addrs[k] {
			if s, valid := lan6CIDR(a); valid && !containsString(now, s) && !containsString(stale[k], s) {
				stale[k] = append(stale[k], s)
			}
		}
	}
	return stale, next
}

func containsString(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

// raMaxLease: RFC 9096 (ND_PREFERRED_LIMIT 2700 s, ND_VALID_LIMIT 5400 s) for the LAN prefixes. dnsmasq
// advertises a constructor: prefix with min(the bridge address's lifetime, the range's lease) as both
// preferred and valid lifetime — there is no separate preferred cap — so the lease is held at 2700 s.
const raMaxLease = 2700

// leaseSecs: a lease ("45m", "12h", "3600") in seconds; 0 = infinite or unreadable.
func leaseSecs(lease string) int {
	mult := map[byte]int{'s': 1, 'm': 60, 'h': 3600, 'd': 86400, 'w': 604800}
	num, m := lease, 1
	if l := len(lease); l > 1 && mult[lease[l-1]] > 0 {
		num, m = lease[:l-1], mult[lease[l-1]]
	}
	n, err := strconv.Atoi(num)
	if err != nil || n <= 0 {
		return 0
	}
	return min(n, 1<<20) * m
}

// raLease: the lease rendered into an RA dhcp-range, at most raMaxLease.
func raLease(lease string) string {
	if s := leaseSecs(lease); s <= 0 || s > raMaxLease {
		return "45m"
	}
	return lease
}

// raLeaseSecs: how long a stale prefix stays advertised as old: the valid lifetime the clients were
// given (raLease).
func raLeaseSecs(lease string) int { return leaseSecs(raLease(lease)) }

// lan6Renumber records the prefixes of the RA bridges per WAN and, once a WAN has delegated again,
// announces the ones that did not come back as stale (see the top of this file).
func lan6Renumber(c *Config) {
	lease := map[string]int{}
	for _, n := range dhcpNets(c) {
		if n.ra {
			lease[n.bridge] = raLeaseSecs(n.ipv6.Lease)
		}
	}
	cur := map[string][]string{}
	for br := range lease {
		out, err := exec.Command("ip", "-j", "-6", "addr", "show", "dev", br, "scope", "global").Output()
		if err != nil {
			return // bridge not there (yet): the next event tries again
		}
		cur[br] = lan6Addrs(out)
	}
	var prev lan6State
	old, err := os.ReadFile(lan6StateFile)
	if err == nil {
		json.Unmarshal(old, &prev)
	}
	var wans []string
	pds := map[string][]netip.Prefix{}
	for _, w := range c.WAN {
		wans = append(wans, w.Name)
		for _, l := range strings.Fields(readFile(pd6File(w.Name))) {
			if p, err := netip.ParsePrefix(l); err == nil {
				pds[w.Name] = append(pds[w.Name], p)
			}
		}
	}
	stale, next := lan6Plan(prev, lan6ByWAN(cur, wans, pds))
	var keys []string
	for k := range stale {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		_, br, _ := strings.Cut(k, " ")
		for _, a := range stale[k] {
			logf("lan6: %s on %s was advertised and is gone: announcing it as stale (RFC 9096)", a, br)
			run("ip", "-6", "addr", "add", a, "dev", br, "valid_lft", strconv.Itoa(lease[br]),
				"preferred_lft", strconv.Itoa(lan6StalePreferred), "noprefixroute", "nodad")
		}
	}
	// flash is written only when a non-empty set changes
	b, _ := json.Marshal(next)
	if (err != nil && len(next.Addrs) == 0) || bytes.Equal(old, b) {
		return
	}
	if err := writeAtomic(lan6StateFile, b, 0644); err != nil {
		logf("lan6: %v", err)
	}
}
