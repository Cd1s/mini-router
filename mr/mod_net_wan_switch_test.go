package main

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPPPDownAfterProtoSwitchKeepsCurrentDHCPState(t *testing.T) {
	tempState(t)
	fakeHookCommands(t)
	c := testConfig(t)
	c.WAN[0] = WAN{Name: "wan", Device: "wan", Proto: "dhcp", PeerDNS: true}
	writeLease("wan", wanLease{IP: "192.0.2.10", Gateway: "192.0.2.1", DNS: []string{"192.0.2.53"}, Dev: "wan"})
	if err := os.MkdirAll(filepath.Dir(resolvConf), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(resolvConf, []byte("nameserver 192.0.2.53\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := hookPPP(c, false, []string{"pppoe-wan", "", "", "", "", "wan"}); err != nil {
		t.Fatal(err)
	}
	if _, ok := readLease("wan"); !ok {
		t.Fatal("stale PPP down removed the current DHCP lease")
	}
	if _, err := os.Stat(resolvConf); err != nil {
		t.Fatalf("stale PPP down removed current resolv.conf: %v", err)
	}
}

func fakeHookCommands(t *testing.T) {
	t.Helper()
	bin := t.TempDir()
	for _, name := range []string{"ip", "nft"} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\ncase \"$*\" in *'-j route'*|*'-j -6 route'*) echo '[]';; esac\nexit 0\n"), 0755); err != nil {
			t.Fatal(err)
		}
	}
	old := os.Getenv("PATH")
	os.Setenv("PATH", bin+string(os.PathListSeparator)+old)
	t.Cleanup(func() { os.Setenv("PATH", old) })
}

func TestDHCPDeconfigAfterProtoSwitchDoesNotTouchPPPoE(t *testing.T) {
	tempState(t)
	c := testConfig(t)
	c.WAN[0] = WAN{Name: "wan", Device: "wan", Proto: "pppoe", PeerDNS: true}
	writeLease("wan", wanLease{IP: "203.0.113.10", Dev: "pppoe-wan"})
	old := os.Getenv("interface")
	os.Setenv("interface", "wan")
	t.Cleanup(func() { os.Setenv("interface", old) })
	if err := hookUdhcpc(c, "deconfig"); err == nil {
		t.Fatal("stale DHCP deconfig unexpectedly accepted for PPPoE WAN")
	}
	if _, ok := readLease("wan"); !ok {
		t.Fatal("stale DHCP deconfig removed PPPoE lease")
	}
}

func TestLan6PlanRetiresRemovedOrDisabledWAN(t *testing.T) {
	prev := lan6State{Addrs: map[string][]string{
		"wan br-lan":  {"2001:db8:1::1/64"},
		"wan2 br-lan": {"2001:db8:2::1/64"},
	}}
	cur := lan6ByWAN(map[string][]string{"br-lan": {"2001:db8:1::1/64"}}, []string{"wan"}, map[string][]netip.Prefix{
		"wan": {netip.MustParsePrefix("2001:db8:1::/56")},
	})
	stale, next := lan6Plan(prev, cur)
	if !strings.Contains(strings.Join(stale["wan2 br-lan"], " "), "2001:db8:2::1/64") {
		t.Fatalf("removed WAN prefix was not retired: stale=%v", stale)
	}
	if _, ok := next.Addrs["wan2 br-lan"]; ok {
		t.Fatalf("removed WAN remained in renumber state: %v", next.Addrs)
	}

	// The runtime removes a disabled WAN's key before planning, distinguishing
	// it from a transient dhcpcd release (which keeps an empty key).
	cur = lan6ByWAN(map[string][]string{"br-lan": {"2001:db8:1::1/64"}}, nil, map[string][]netip.Prefix{})
	stale, next = lan6Plan(prev, cur)
	if len(stale["wan br-lan"]) == 0 {
		t.Fatalf("disabled PD prefix was not retired: stale=%v", stale)
	}
	if len(next.Addrs) != 0 {
		t.Fatalf("disabled PD remained in renumber state: %v", next.Addrs)
	}
}

func TestNetworkScriptCleansStaleWANVLANAndRestoresMAC(t *testing.T) {
	c := testConfig(t)
	c.WAN[0].VLAN = 0
	c.WAN[0].MAC = ""
	sh := renderNetwork(c)
	if !strings.Contains(sh, "ip link del \"$n\"") || !strings.Contains(sh, "/sys/class/net/wan.*") {
		t.Fatalf("network.sh has no stale WAN VLAN cleanup:\n%s", sh)
	}
	if !strings.Contains(sh, "ethtool -P wan") || !strings.Contains(sh, "ip link set dev wan address") {
		t.Fatalf("network.sh has no permanent MAC restore:\n%s", sh)
	}
}
