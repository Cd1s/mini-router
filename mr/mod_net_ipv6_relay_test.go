package main

import (
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

	if got := renderDhcpcd(c); !strings.Contains(got, "ipv6_relay=true") {
		t.Fatalf("dhcpcd does not carry the relay setting:\n%s", got)
	}
	if got := renderDnsmasq(c); !strings.Contains(got, "IPv6 SLAAC relay") {
		t.Fatalf("dnsmasq does not mark the relay RA:\n%s", got)
	}
	if got := renderNft(c, allExist); !strings.Contains(got, "set ipv6_relay6") || !strings.Contains(got, "comment \"ipv6-relay\"") {
		t.Fatalf("firewall does not render IPv6 relay forwarding:\n%s", got)
	}
	if got := strings.Join(ipv6RelayCronLine(c), "\n"); !strings.Contains(got, "mr net ipv6-relay --cron") {
		t.Fatalf("IPv6 relay has no periodic hook: %q", got)
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

func TestIPv6RelaySyncTracksNeighboursAndCleansOnDisable(t *testing.T) {
	d := t.TempDir()
	oldState, oldLock, oldRun, oldStdin, oldWan := ipv6RelayStateFile, ipv6RelayLockFile, ipv6RelayRun, ipv6RelayRunStdin, wanRunDir
	ipv6RelayStateFile, ipv6RelayLockFile, wanRunDir = filepath.Join(d, "state.json"), filepath.Join(d, "lock"), filepath.Join(d, "wan")
	if err := os.MkdirAll(wanRunDir, 0755); err != nil {
		t.Fatal(err)
	}
	var neigh = "2001:db8:1::20"
	var calls []string
	ipv6RelayRun = func(name string, args ...string) (string, error) {
		line := name + " " + strings.Join(args, " ")
		calls = append(calls, line)
		if strings.Contains(line, "addr show dev wan") {
			return `[{"addr_info":[{"family":"inet6","local":"2001:db8:1::2","prefixlen":64}]}]`, nil
		}
		if strings.Contains(line, "neigh show dev br-lan") {
			return `[{"dst":"` + neigh + `","state":["STALE"]}]`, nil
		}
		return "", nil
	}
	ipv6RelayRunStdin = func(input, name string, args ...string) (string, error) {
		calls = append(calls, name+" "+strings.Join(args, " ")+"\n"+input)
		return "", nil
	}
	t.Cleanup(func() {
		ipv6RelayStateFile, ipv6RelayLockFile, ipv6RelayRun, ipv6RelayRunStdin, wanRunDir = oldState, oldLock, oldRun, oldStdin, oldWan
	})
	c := &Config{LAN: LAN{Bridge: "br-lan", IPv6RA: true}, WAN: []WAN{{Name: "wan", Device: "wan", Proto: "dhcp", IPv6: true, IPv6Relay: true}}}
	if err := ipv6RelaySync(c); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(calls, "\n")
	for _, want := range []string{"addr replace 2001:db8:1::1/64 dev br-lan", "neigh replace proxy 2001:db8:1::20 dev wan", "add element inet mr ipv6_relay6 { 2001:db8:1::/64 }"} {
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
	if !strings.Contains(joined, "neigh del proxy 2001:db8:1::20 dev wan") || !strings.Contains(joined, "neigh replace proxy 2001:db8:1::21 dev wan") {
		t.Errorf("neighbour change was not reconciled:\n%s", joined)
	}
	c.WAN[0].IPv6Relay = false
	calls = nil
	if err := ipv6RelaySync(c); err != nil {
		t.Fatal(err)
	}
	joined = strings.Join(calls, "\n")
	if !strings.Contains(joined, "addr del 2001:db8:1::1/64 dev br-lan") || !strings.Contains(joined, "neigh del proxy 2001:db8:1::21 dev wan") {
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
