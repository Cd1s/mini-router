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
// So the prefixes on the RA bridges are recorded on flash (written only when they change), and after a
// reboot every recorded address that has not come back is put on its bridge once more for
// lan6StalePreferred seconds of preferred lifetime: dnsmasq sees it, advertises it, sees the kernel
// deprecate it and then advertises it as an old prefix like any other. If the ISP hands out the same
// prefix again, dhcpcd re-adds the address and dnsmasq advertises it as before. Runs from the dhcpcd
// hook; nothing resident. mr-dhcpcd starts after dnsmasq, so the first event after boot finds it running.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
)

var (
	lan6StateFile = "/etc/mini-router/state/lan6-prefixes.json"
	bootIDFile    = "/proc/sys/kernel/random/boot_id"
)

// lan6StalePreferred: preferred lifetime (seconds) of a stale address put back after a reboot. Long
// enough for dnsmasq to notice it and advertise it once, short enough that clients stop using it at once.
const lan6StalePreferred = 10

// lan6State is what the RA bridges advertised, per boot.
type lan6State struct {
	Boot  string              `json:"boot"`
	Addrs map[string][]string `json:"addrs"` // bridge -> ["2001:db8:1::1/64", ...]
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

// lan6Plan compares what the bridges have now (cur) with the record. Within one boot dnsmasq has seen
// every change itself; in a new boot, recorded addresses that are not back are stale. Bridges that no
// longer do RA are left out (nothing advertises there).
func lan6Plan(prev lan6State, boot string, cur map[string][]string) (stale map[string][]string, next lan6State) {
	next = lan6State{Boot: boot, Addrs: map[string][]string{}}
	for br, as := range cur {
		if len(as) > 0 {
			next.Addrs[br] = as
		}
	}
	stale = map[string][]string{}
	if prev.Boot == "" || prev.Boot == boot {
		return stale, next
	}
	for br, as := range prev.Addrs {
		now, ok := cur[br]
		if !ok {
			continue
		}
		for _, a := range as {
			if s, valid := lan6CIDR(a); valid && !containsString(now, s) {
				stale[br] = append(stale[br], s)
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

// raLeaseSecs: how long a stale prefix stays advertised as old: the RA lease (the valid lifetime the
// clients were given), at most 2 h like dnsmasq; "infinite" = 2 h.
func raLeaseSecs(lease string) int {
	mult := map[byte]int{'s': 1, 'm': 60, 'h': 3600, 'd': 86400, 'w': 604800}
	secs := 7200
	if l := len(lease); l > 1 && mult[lease[l-1]] > 0 {
		if n, err := strconv.Atoi(lease[:l-1]); err == nil && n > 0 && n <= 7200 {
			secs = n * mult[lease[l-1]]
		}
	}
	if secs > 7200 {
		secs = 7200
	}
	return secs
}

// lan6Renumber records the prefixes of the RA bridges and, in the first dhcpcd event after a reboot,
// announces the ones that did not come back as stale (see the top of this file).
func lan6Renumber(c *Config) {
	boot := strings.TrimSpace(readFile(bootIDFile))
	if boot == "" {
		return
	}
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
	stale, next := lan6Plan(prev, boot, cur)
	var brs []string
	for br := range stale {
		brs = append(brs, br)
	}
	sort.Strings(brs)
	for _, br := range brs {
		for _, a := range stale[br] {
			logf("lan6: %s on %s was advertised before the reboot and is gone: announcing it as stale (RFC 9096)", a, br)
			run("ip", "-6", "addr", "add", a, "dev", br, "valid_lft", strconv.Itoa(lease[br]),
				"preferred_lft", strconv.Itoa(lan6StalePreferred), "noprefixroute", "nodad")
		}
	}
	// flash is written only when the prefixes (or the boot) change
	b, _ := json.Marshal(next)
	if (err != nil && len(next.Addrs) == 0) || bytes.Equal(old, b) {
		return
	}
	if err := writeAtomic(lan6StateFile, b, 0644); err != nil {
		logf("lan6: %v", err)
	}
}
