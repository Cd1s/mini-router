package main

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIPv6RelayValidationAndRender(t *testing.T) {
	c := testConfig(t)
	c.LAN.IPv6RA = true
	c.WAN[0].IPv6 = true
	c.WAN[0].IPv6PD = false
	c.WAN[0].IPv6Relay = true
	c.Policy[1].NAT6 = false
	mustValid(t, c)

	if got := renderDhcpcd(c); strings.Contains(got, "ipv6_relay") {
		t.Fatalf("relay changed dhcpcd configuration:\n%s", got)
	}
	if got := renderDnsmasq(c); !strings.Contains(got, "IPv6 SLAAC relay") {
		t.Fatalf("dnsmasq does not mark the relay RA:\n%s", got)
	}
	gotNft := renderNft(c, allExist)
	if strings.Contains(gotNft, "ipv6-relay") || strings.Contains(gotNft, "ip6 daddr @ipv6_relay6") {
		t.Fatalf("relay added an unconditional inbound firewall accept:\n%s", gotNft)
	}
	if !strings.Contains(gotNft, "policy drop") {
		t.Fatalf("firewall lost the default drop policy:\n%s", gotNft)
	}
	if got := strings.Join(ipv6RelayCronLine(c), "\n"); !strings.Contains(got, "mr net ipv6-relay --cron") {
		t.Fatalf("IPv6 relay has no periodic hook: %q", got)
	}
}

func TestIPv6RelayDisabledLeavesBaselineRender(t *testing.T) {
	c := testConfig(t)
	mustValid(t, c)
	if s := renderDhcpcd(c); strings.Contains(s, "ipv6_relay") {
		t.Fatalf("disabled relay changed baseline dhcpcd.conf:\n%s", s)
	}
	if s := renderDnsmasq(c); strings.Contains(s, "SLAAC relay") {
		t.Fatalf("disabled relay changed baseline dnsmasq.conf:\n%s", s)
	}
	if s := renderNft(c, allExist); strings.Contains(s, "ipv6_relay") || strings.Contains(s, "ipv6-relay") {
		t.Fatalf("disabled relay changed baseline nftables:\n%s", s)
	}
	if s := strings.Join(renderCronLines(c), "\n"); strings.Contains(s, "ipv6-relay") {
		t.Fatalf("disabled relay changed baseline crontab:\n%s", s)
	}
}

func TestIPv6RelayDisabledMatchesMainBaselineFiles(t *testing.T) {
	c := testConfig(t)
	f := renderMap(t, c)
	f[GenDir+"/nftables.nft"] = renderNft(c, allExist)
	want := map[string]string{
		"/etc/dhcpcd.conf":       "ca2e991b988fdd8c82cc389013c705ba6a2fc125788865d7bafb8b79095d36ed",
		"/etc/dnsmasq.conf":      "286d28a6beefba0d494d500300fa1ff3d5b00cb186cd00dabd823a21f9175c46",
		GenDir + "/nftables.nft": "60965cd020469cc242e089d8fe0286ec86dbe6a24447d88c25079a4f1aeb6d3b",
		"/etc/crontabs/root":     "e16a0402de64658fe2c028a2520a3460bd87a8394977ff5c9333df4cd47a4895",
	}
	for path, hash := range want {
		got := sha256.Sum256([]byte(f[path]))
		if fmt.Sprintf("%x", got) != hash {
			t.Errorf("%s differs from origin/main baseline: %x", path, got)
		}
	}
}

func TestIPv6RelayRequiresIPv6AndLANRA(t *testing.T) {
	c := testConfig(t)
	c.WAN[0].IPv6Relay = true
	c.WAN[0].IPv6 = false
	if errs := c.Validate(); !strings.Contains(strings.Join(errs, "\n"), "ipv6_relay: requires ipv6") {
		t.Fatalf("missing ipv6_relay/ipv6 validation: %v", errs)
	}
	c.WAN[0].IPv6 = true
	c.LAN.IPv6RA = false
	if errs := c.Validate(); !strings.Contains(strings.Join(errs, "\n"), "ipv6_relay: requires lan.ipv6_ra") {
		t.Fatalf("missing ipv6_relay/LAN RA validation: %v", errs)
	}
}

func TestIPv6RelayNeighbourStatesRequireUsableEntry(t *testing.T) {
	old := ipv6RelayRun
	ipv6RelayRun = func(name string, args ...string) (string, error) {
		return `[{"dst":"2001:db8:1::10","state":["REACHABLE"]},{"dst":"2001:db8:1::11","state":["FAILED"]},{"dst":"2001:db8:1::12","state":["INCOMPLETE"]},{"dst":"2001:db8:1::13"}]`, nil
	}
	t.Cleanup(func() { ipv6RelayRun = old })
	got := ipv6RelayNeighbours("br-lan")
	if len(got) != 1 || got[0].String() != "2001:db8:1::10" {
		t.Fatalf("unusable neighbour states were accepted: %v", got)
	}
}

func TestIPv6RelaySyncTracksNeighboursAndCleansOnDisable(t *testing.T) {
	d := t.TempDir()
	oldState, oldLock, oldRun, oldSet, oldWan := ipv6RelayStateFile, ipv6RelayLockFile, ipv6RelayRun, ipv6RelaySetProxyNDP, wanRunDir
	ipv6RelayStateFile, ipv6RelayLockFile, wanRunDir = filepath.Join(d, "state.json"), filepath.Join(d, "lock"), filepath.Join(d, "wan")
	if err := os.MkdirAll(wanRunDir, 0755); err != nil {
		t.Fatal(err)
	}
	var neigh = "2001:db8:1::20"
	var calls []string
	ipv6RelayRun = func(name string, args ...string) (string, error) {
		line := name + " " + strings.Join(args, " ")
		calls = append(calls, line)
		if name == "ping6" {
			return "", errors.New("no reply")
		}
		if strings.Contains(line, "addr show dev wan") {
			return `[{"addr_info":[{"family":"inet6","local":"2001:db8:1::2","prefixlen":64}]}]`, nil
		}
		if strings.Contains(line, "neigh show dev br-lan") {
			return `[{"dst":"` + neigh + `","state":["STALE"]}]`, nil
		}
		return "", nil
	}
	ipv6RelaySetProxyNDP = func(string, bool) error { return nil }
	t.Cleanup(func() {
		ipv6RelayStateFile, ipv6RelayLockFile, ipv6RelayRun, ipv6RelaySetProxyNDP, wanRunDir = oldState, oldLock, oldRun, oldSet, oldWan
	})
	c := &Config{LAN: LAN{Bridge: "br-lan", IPv6RA: true}, WAN: []WAN{{Name: "wan", Device: "wan", Proto: "dhcp", IPv6: true, IPv6Relay: true}}}
	if err := ipv6RelaySync(c); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(calls, "\n")
	for _, want := range []string{"addr replace 2001:db8:1::2/64 dev br-lan", "route replace 2001:db8:1::/64 dev wan proto static metric 100", "neigh replace proxy 2001:db8:1::20 dev wan"} {
		if !strings.Contains(joined, want) {
			t.Errorf("first relay sync missing %q:\n%s", want, joined)
		}
	}
	neigh = "2001:db8:1::21"
	calls = nil
	if err := ipv6RelaySync(c); err != nil {
		t.Fatal(err)
	}
	joined = strings.Join(calls, "\n")
	if !strings.Contains(joined, "neigh replace proxy 2001:db8:1::21 dev wan") || strings.Contains(joined, "neigh del proxy 2001:db8:1::20 dev wan") {
		t.Errorf("neighbour change was not reconciled:\n%s", joined)
	}
	for i := 0; i < 3; i++ {
		calls = nil
		if err := ipv6RelaySync(c); err != nil {
			t.Fatal(err)
		}
	}
	if !strings.Contains(strings.Join(calls, "\n"), "neigh del proxy 2001:db8:1::20 dev wan") {
		t.Fatalf("missing neighbours were not eventually removed:\n%s", strings.Join(calls, "\n"))
	}
	c.WAN[0].IPv6Relay = false
	calls = nil
	if err := ipv6RelaySync(c); err != nil {
		t.Fatal(err)
	}
	joined = strings.Join(calls, "\n")
	if !strings.Contains(joined, "addr replace 2001:db8:1::2/64 dev br-lan preferred_lft 0 valid_lft 2700") || !strings.Contains(joined, "neigh del proxy 2001:db8:1::21 dev wan") {
		t.Errorf("disable did not clean relay state:\n%s", joined)
	}
	if err := os.WriteFile(filepath.Join(wanRunDir, "wan.pd6"), []byte("2001:db8:1::/56\n"), 0644); err != nil {
		t.Fatal(err)
	}
	c.WAN[0].IPv6Relay = true
	calls = nil
	if err := ipv6RelaySync(c); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(calls, "\n"), "addr replace") {
		t.Fatalf("PD did not take priority over relay:\n%s", strings.Join(calls, "\n"))
	}
}

func TestIPv6RelayPDTransitionCleansActiveRelay(t *testing.T) {
	d := t.TempDir()
	oldState, oldLock, oldRun, oldSet, oldWan := ipv6RelayStateFile, ipv6RelayLockFile, ipv6RelayRun, ipv6RelaySetProxyNDP, wanRunDir
	ipv6RelayStateFile, ipv6RelayLockFile, wanRunDir = filepath.Join(d, "state.json"), filepath.Join(d, "lock"), filepath.Join(d, "wan")
	os.MkdirAll(wanRunDir, 0755)
	os.WriteFile(filepath.Join(wanRunDir, "wan.pd6"), []byte("2001:db8:1::/56\n"), 0644)
	writeIPv6RelayState(ipv6RelayState{Prefixes: []ipv6RelayPrefix{{WAN: "wan", Dev: "wan", Prefix: "2001:db8:1::/64", Addr: "2001:db8:1::2"}}, Proxies: []ipv6RelayProxy{{Addr: "2001:db8:1::20", Dev: "wan"}}, LANAddrs: []string{"2001:db8:1::2/64"}})
	var calls []string
	ipv6RelayRun = func(name string, args ...string) (string, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return "", nil
	}
	ipv6RelaySetProxyNDP = func(dev string, enabled bool) error {
		calls = append(calls, "proxy_ndp "+dev+" "+fmt.Sprint(enabled))
		return nil
	}
	t.Cleanup(func() {
		ipv6RelayStateFile, ipv6RelayLockFile, ipv6RelayRun, ipv6RelaySetProxyNDP, wanRunDir = oldState, oldLock, oldRun, oldSet, oldWan
	})
	c := &Config{LAN: LAN{Bridge: "br-lan", IPv6RA: true}, WAN: []WAN{{Name: "wan", Device: "wan", Proto: "dhcp", IPv6: true, IPv6Relay: true}}}
	if err := ipv6RelaySync(c); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(calls, "\n")
	for _, want := range []string{"addr replace 2001:db8:1::2/64 dev br-lan preferred_lft 0 valid_lft 2700", "route del 2001:db8:1::/64 dev wan proto static metric 100", "neigh del proxy 2001:db8:1::20 dev wan", "proxy_ndp wan false", "rc-service dnsmasq reload"} {
		if !strings.Contains(joined, want) {
			t.Errorf("PD transition missing %q:\n%s", want, joined)
		}
	}
}

func TestIPv6RelayRoutesStayInsidePrefixAndAreCleaned(t *testing.T) {
	d := t.TempDir()
	oldState, oldLock, oldRun, oldSet, oldWan := ipv6RelayStateFile, ipv6RelayLockFile, ipv6RelayRun, ipv6RelaySetProxyNDP, wanRunDir
	ipv6RelayStateFile, ipv6RelayLockFile, wanRunDir = filepath.Join(d, "state.json"), filepath.Join(d, "lock"), filepath.Join(d, "wan")
	os.MkdirAll(wanRunDir, 0755)
	writeIPv6RelayState(ipv6RelayState{Prefixes: []ipv6RelayPrefix{{WAN: "wan", Dev: "wan", Prefix: "2001:db8:1::/64", Addr: "2001:db8:1::2"}}, Routes: []ipv6RelayRoute{{Addr: "2001:4860:4860::8888", Dev: "br-lan"}}})
	var calls []string
	ipv6RelayRun = func(name string, args ...string) (string, error) {
		line := name + " " + strings.Join(args, " ")
		calls = append(calls, line)
		switch {
		case name == "ping6":
			return "", errors.New("no reply")
		case strings.Contains(line, "addr show dev wan"):
			return `[{"addr_info":[{"family":"inet6","local":"2001:db8:1::2","prefixlen":64}]}]`, nil
		case strings.Contains(line, "neigh show dev br-lan"):
			return `[{"dst":"2001:db8:1::20","state":["STALE"]},{"dst":"2001:4860:4860::8888","state":["STALE"]}]`, nil
		default:
			return "", nil
		}
	}
	ipv6RelaySetProxyNDP = func(string, bool) error { return nil }
	t.Cleanup(func() {
		ipv6RelayStateFile, ipv6RelayLockFile, ipv6RelayRun, ipv6RelaySetProxyNDP, wanRunDir = oldState, oldLock, oldRun, oldSet, oldWan
	})
	c := &Config{LAN: LAN{Bridge: "br-lan", IPv6RA: true}, WAN: []WAN{{Name: "wan", Device: "wan", Proto: "dhcp", IPv6: true, IPv6Relay: true}}}
	if err := ipv6RelaySync(c); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(calls, "\n")
	if strings.Contains(joined, "route replace 2001:4860:4860::8888/128") {
		t.Fatalf("out-of-prefix neighbour received a host route:\n%s", joined)
	}
	if !strings.Contains(joined, "route replace 2001:db8:1::20/128") {
		t.Fatalf("in-prefix neighbour did not receive a host route:\n%s", joined)
	}
	c.WAN[0].IPv6Relay = false
	calls = nil
	if err := ipv6RelaySync(c); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(calls, "\n"), "route del 2001:db8:1::20/128") {
		t.Fatalf("relay host route was not cleaned:\n%s", strings.Join(calls, "\n"))
	}
}
