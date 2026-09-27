package main

import (
	"slices"
	"strings"
	"testing"
)

func netFlowDevs(c *Config) []string {
	for _, m := range modules {
		if m.Name == "net" {
			return m.FlowDevs(c)
		}
	}
	return nil
}

func noRead(string) string { return "" }

// Multi-dial on one port (Cd1s/mini-router#114): the home config's wan2 has its own MAC, so it dials on
// the macvlan mv-wan2; wan keeps the port and its MAC.
func TestMacvlanHome(t *testing.T) {
	c := testConfig(t)
	mustValid(t, c)
	f := renderMap(t, c)
	sh := f[GenDir+"/network.sh"]
	add := `case "$(ip -d -o link show mv-wan2 2>/dev/null)" in *"mv-wan2@wan:"*"link/ether 02:55:b8:c9:87:3a "*" macvlan mode private "*) ;; *) ip link del mv-wan2 2>/dev/null; ip link add link wan name mv-wan2 address 02:55:b8:c9:87:3a type macvlan mode private;; esac` + "\n"
	stale := `for d in /sys/class/net/mv-*; do n=${d##*/}; case " mv-wan2 " in *" $n "*) continue;; esac;`
	wantSubs(t, "network.sh", sh, stale, "modprobe -q macvlan 2>/dev/null\n", add,
		"echo 1 2>/dev/null > /proc/sys/net/ipv6/conf/mv-wan2/disable_ipv6\n", "ip link set dev mv-wan2 mtu 1500\n", "ip link set mv-wan2 up\n")
	wantNone(t, "network.sh", sh, "ip link set wan address 02:55:b8:c9:87:3a")
	if up, s, a := strings.Index(sh, "ip link set wan up\n"), strings.Index(sh, stale), strings.Index(sh, add); up > s || s > a {
		t.Errorf("network.sh order: wan up %d, stale cleanup %d, macvlan %d", up, s, a)
	}
	wantSubs(t, "peers/wan2", f["/etc/ppp/peers/wan2"], "nic-mv-wan2\n", "# macvlan mv-wan2 on wan, MAC 02:55:b8:c9:87:3a\n")
	wantSubs(t, "peers/wan", f["/etc/ppp/peers/wan"], "nic-wan\n")
	wantNone(t, "peers/wan", f["/etc/ppp/peers/wan"], "macvlan", "nic-mv-")
	wantNone(t, "dhcpcd.conf", f["/etc/dhcpcd.conf"], "mv-")
	if d := netFlowDevs(c); !slices.Contains(d, "mv-wan2") || !slices.Contains(d, "wan") {
		t.Errorf("FlowDevs %v: want wan and mv-wan2", d)
	}
	if serviceFor("/etc/ppp/peers/wan2") != "mr-pppoe.wan2" {
		t.Error("a changed macvlan (peers file) does not restart mr-pppoe.wan2")
	}
	// mr wan mac wan2: the MAC the home config uses
	if got := wanMACSuggest(wanPortMAC(c, c.WAN[1], noRead), "wan2"); got != "02:55:b8:c9:87:3a" || got != c.WAN[1].MAC {
		t.Errorf("mr wan mac wan2 = %s, config has %s", got, c.WAN[1].MAC)
	}
	if got := wanMACSuggest("02:00:00:00:00:01", "wan2"); got != "02:94:9a:e3:fb:78" {
		t.Errorf("suggestion %s", got)
	}
	// without a mac on the first WAN: the port's own address
	c.WAN[0].MAC = ""
	if got := wanPortMAC(c, c.WAN[1], func(p string) string {
		if p != "/sys/class/net/wan/address" {
			t.Errorf("read %s", p)
		}
		return "02:00:00:00:00:01\n"
	}); got != "02:00:00:00:00:01" {
		t.Errorf("port MAC %q", got)
	}
	if docWANMACs(testConfig(t), &docEnv{read: noRead}) != nil {
		t.Error("doctor warns about the home config")
	}
	// RFC 4638: the macvlan gets the lower device's link MTU
	c = testConfig(t)
	c.WAN[1].MTU = 1500
	wantSubs(t, "network.sh mtu 1500", renderNetwork(c), "ip link set dev wan mtu 1508\n", "ip link set dev mv-wan2 mtu 1508\n")
}

// Configs from before #114 keep working: wan2 without a mac (or with the port's) shares the port's MAC,
// and mr doctor suggests one.
func TestMacvlanShared(t *testing.T) {
	for _, mac := range []string{"", "A4:A9:30:6E:2B:89"} {
		c := testConfig(t)
		c.WAN[1].MAC = mac
		mustValid(t, c)
		f := renderMap(t, c)
		sh := f[GenDir+"/network.sh"]
		wantSubs(t, "network.sh", sh, `case "  " in`) // stale macvlans still go
		wantNone(t, "network.sh", sh, "type macvlan", "modprobe -q macvlan")
		wantSubs(t, "peers/wan2", f["/etc/ppp/peers/wan2"], "nic-wan\n")
		if slices.Contains(netFlowDevs(c), "mv-wan2") {
			t.Error("FlowDevs has mv-wan2")
		}
		d := docWANMACs(c, &docEnv{read: noRead})
		if len(d) != 1 || d[0].ID != "wan.mac.wan2" || d[0].Sev != "warn" || !strings.Contains(d[0].Detail, "shares wan's MAC on device wan") ||
			!strings.Contains(d[0].Fix, "e.g. 02:55:b8:c9:87:3a (mr wan mac wan2)") {
			t.Errorf("doctor: %+v", d)
		}
	}
	// multi-port: one account on two ports with one MAC (DSA ports inherit the conduit's)
	c := testConfig(t)
	c.WAN[1].Device, c.WAN[1].MAC = "eth1", ""
	d := docWANMACs(c, &docEnv{read: func(p string) string { return "a4:a9:30:6e:2b:89\n" }})
	if len(d) != 1 || !strings.Contains(d[0].Detail, "same MAC a4:a9:30:6e:2b:89 on another port") {
		t.Errorf("doctor multi-port: %+v", d)
	}
}
