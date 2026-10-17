package main

import (
	"encoding/json"
	"net/netip"
	"os"
	"os/exec"
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
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\ncase \"$*\" in *'rule del'*) exit 1;; *'-j route'*|*'-j -6 route'*) echo '[]';; esac\nexit 0\n"), 0755); err != nil {
			t.Fatal(err)
		}
	}
	old := os.Getenv("PATH")
	os.Setenv("PATH", bin+string(os.PathListSeparator)+old)
	t.Cleanup(func() { os.Setenv("PATH", old) })
}

func TestPPPDownCurrentPPPoEStillCleansState(t *testing.T) {
	tempState(t)
	fakeHookCommands(t)
	c := testConfig(t)
	c.WAN[0] = WAN{Name: "wan", Device: "wan", Proto: "pppoe", PeerDNS: true}
	writeLease("wan", wanLease{IP: "203.0.113.10", Dev: "pppoe-wan"})
	wanDown(c, &c.WAN[0])
	if _, ok := readLease("wan"); ok {
		t.Fatal("current PPPoE down did not remove its lease")
	}
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

func TestLan6RetireDetectsProtoSwitchButKeepsSameWAN(t *testing.T) {
	prev := lan6State{Addrs: map[string][]string{"wan br-lan": {"2001:db8:1::1/64"}}, Devices: map[string]string{"wan br-lan": "pppoe-wan"}}
	old := wanRunDir
	wanRunDir = t.TempDir()
	t.Cleanup(func() { wanRunDir = old })
	if !lan6RetireWAN(prev, WAN{Name: "wan", Device: "wan", Proto: "dhcp", IPv6: true, IPv6PD: true}, true) {
		t.Fatal("PPPoE to DHCP did not retire the old WAN owner")
	}
	if lan6RetireWAN(prev, WAN{Name: "wan", Device: "wan", Proto: "pppoe", IPv6: true, IPv6PD: true}, true) {
		t.Fatal("unchanged PPPoE WAN was retired")
	}
}

func TestLan6PlanDoesNotDeprecatePrefixStillOwnedByAnotherWANKey(t *testing.T) {
	prev := lan6State{Addrs: map[string][]string{"wan br-lan": {"2001:db8:1::1/64"}}}
	cur := map[string][]string{"wan0 br-lan": {"2001:db8:1::1/64"}}
	stale, _ := lan6Plan(prev, cur)
	if len(stale) != 0 {
		t.Fatalf("renamed WAN still owns the prefix but was deprecated: %v", stale)
	}
}

func TestLan6RenumberRetiresProtoSwitchAfterCommit(t *testing.T) {
	oldState, oldRun := lan6StateFile, wanRunDir
	d := t.TempDir()
	lan6StateFile, wanRunDir = filepath.Join(d, "lan6.json"), filepath.Join(d, "wan")
	t.Cleanup(func() { lan6StateFile, wanRunDir = oldState, oldRun })
	os.MkdirAll(wanRunDir, 0755)
	prev := lan6State{Addrs: map[string][]string{"wan br-lan": {"2001:db8:1::1/64"}}, Devices: map[string]string{"wan br-lan": "pppoe-wan"}}
	b, _ := json.Marshal(prev)
	if err := os.WriteFile(lan6StateFile, b, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pd6File("wan"), []byte("2001:db8:1::/48\n"), 0644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(d, "bin")
	os.Mkdir(bin, 0755)
	ip := "#!/bin/sh\ncase \"$*\" in *'-j -6 addr show dev br-lan'*) echo '[{\"addr_info\":[{\"family\":\"inet6\",\"local\":\"2001:db8:1::1\",\"prefixlen\":64,\"preferred_life_time\":3600}]}' ;; *) echo \"$*\" >> '" + filepath.Join(d, "ip.log") + "' ;; esac\n"
	if err := os.WriteFile(filepath.Join(bin, "ip"), []byte(ip), 0755); err != nil {
		t.Fatal(err)
	}
	oldPath := os.Getenv("PATH")
	os.Setenv("PATH", bin+string(os.PathListSeparator)+oldPath)
	t.Cleanup(func() { os.Setenv("PATH", oldPath) })
	c := testConfig(t)
	c.WAN[0] = WAN{Name: "wan", Device: "wan", Proto: "dhcp", IPv6: true, IPv6PD: true}
	lan6Renumber(c, true)
	if _, err := os.Stat(pd6File("wan")); !os.IsNotExist(err) {
		t.Fatalf("committed protocol switch kept old pd6: %v", err)
	}
	log, _ := os.ReadFile(filepath.Join(d, "ip.log"))
	if !strings.Contains(string(log), "addr replace 2001:db8:1::1/64") {
		t.Fatalf("stale prefix was not announced: %q", log)
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
	// veth devices in the netns report "Permanent address: not set".  That
	// must not be mistaken for a MAC and must not be taken down.
	var line string
	for _, l := range strings.Split(sh, "\n") {
		if strings.Contains(l, "ethtool -P wan ") {
			line = l
			break
		}
	}
	if line == "" {
		t.Fatal("missing WAN permanent MAC command")
	}
	d := t.TempDir()
	if err := os.MkdirAll(filepath.Join(d, "sys/net"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "sys/net/address"), []byte("02:00:00:00:00:01\n"), 0644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(d, "bin")
	if err := os.Mkdir(bin, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "ethtool"), []byte("#!/bin/sh\necho 'Permanent address: not set'\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "ip"), []byte("#!/bin/sh\ncase \"$*\" in *' link set '*) echo \"$*\" >> \""+filepath.Join(d, "ip.log")+"\";; esac\n"), 0755); err != nil {
		t.Fatal(err)
	}
	line = strings.ReplaceAll(line, "/sys/class/net/wan/address", filepath.Join(d, "sys/net/address"))
	cmd := exec.Command("sh", "-c", line)
	cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("MAC restore command: %v %s", err, out)
	}
	if b, _ := os.ReadFile(filepath.Join(d, "ip.log")); len(b) != 0 {
		t.Fatalf("invalid permanent MAC caused link mutation: %q", b)
	}
	// A valid permanent MAC changes an originally-up link and restores UP even
	// when the address operation fails.  A down link remains down.
	if err := os.WriteFile(filepath.Join(bin, "ethtool"), []byte("#!/bin/sh\necho 'Permanent address: 02:11:22:33:44:55'\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "ip"), []byte("#!/bin/sh\nif [ \"$1\" = -o ]; then echo '1: wan: <BROADCAST,UP,LOWER_UP>'; elif [ \"$1\" = link ] && [ \"$2\" = set ]; then echo \"$*\" >> \""+filepath.Join(d, "ip.log")+"\"; fi\n"), 0755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(d, "ip.log"), nil, 0644)
	cmd2 := exec.Command("sh", "-c", line)
	cmd2.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	if out, err := cmd2.CombinedOutput(); err != nil {
		t.Fatalf("valid MAC restore command: %v %s", err, out)
	}
	if b, _ := os.ReadFile(filepath.Join(d, "ip.log")); !strings.Contains(string(b), "link set wan up") {
		t.Fatalf("originally-up link was not restored: %q", b)
	}
	for _, bad := range []string{"00:00:00:00:00:00", "01:11:22:33:44:55"} {
		if err := os.WriteFile(filepath.Join(bin, "ethtool"), []byte("#!/bin/sh\necho 'Permanent address: "+bad+"'\n"), 0755); err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join(d, "ip.log"), nil, 0644)
		cmdBad := exec.Command("sh", "-c", line)
		cmdBad.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"))
		if out, err := cmdBad.CombinedOutput(); err != nil {
			t.Fatalf("invalid MAC %s: %v %s", bad, err, out)
		}
		if b, _ := os.ReadFile(filepath.Join(d, "ip.log")); len(b) != 0 {
			t.Fatalf("invalid permanent MAC %s caused link mutation: %q", bad, b)
		}
	}
}

func TestNetworkScriptDeletesOnlyMarkedVLANs(t *testing.T) {
	c := testConfig(t)
	c.WAN[0].VLAN = 0
	sh := renderNetwork(c)
	var cleanup string
	for _, l := range strings.Split(sh, "\n") {
		if strings.HasPrefix(l, "for d in /sys/class/net/wan.*") {
			cleanup = l
			break
		}
	}
	if !strings.Contains(cleanup, "alias mini-router") {
		t.Fatalf("VLAN cleanup is not alias-scoped: %q", cleanup)
	}
	d := t.TempDir()
	for _, n := range []string{"wan.100", "wan.500"} {
		if err := os.MkdirAll(filepath.Join(d, "sys/net", n), 0755); err != nil {
			t.Fatal(err)
		}
	}
	bin := filepath.Join(d, "bin")
	if err := os.Mkdir(bin, 0755); err != nil {
		t.Fatal(err)
	}
	ip := "#!/bin/sh\ncase \"$*\" in\n  *'link show dev wan.100'*) echo 'wan.100: alias mini-router' ;;\n  *'link show dev wan.500'*) echo 'wan.500: user vlan' ;;\n  *'link del'*) echo \"$*\" >> '" + filepath.Join(d, "ip.log") + "' ;;\nesac\n"
	if err := os.WriteFile(filepath.Join(bin, "ip"), []byte(ip), 0755); err != nil {
		t.Fatal(err)
	}
	cleanup = strings.Replace(cleanup, "/sys/class/net/wan.*", filepath.Join(d, "sys/net/wan.*"), 1)
	cmd := exec.Command("sh", "-c", cleanup)
	cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("VLAN cleanup: %v %s", err, out)
	}
	b, _ := os.ReadFile(filepath.Join(d, "ip.log"))
	if !strings.Contains(string(b), "link del wan.100") || strings.Contains(string(b), "wan.500") {
		t.Fatalf("cleanup deleted the wrong VLANs: %q", b)
	}
}
