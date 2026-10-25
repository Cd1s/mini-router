package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fakeIPLog replaces `ip` and `nft` with scripts that log their arguments and answer "no routes"
// to JSON queries; the returned func gives the commands run so far, one per line.
func fakeIPLog(t *testing.T) func() string {
	t.Helper()
	bin, log := t.TempDir(), filepath.Join(t.TempDir(), "ip.log")
	script := "#!/bin/sh\ncase \"$*\" in *'rule del'*) exit 1;; *'-j route'*|*'-j -6 route'*) echo '[]';; *) echo \"$*\" >> '" + log + "';; esac\nexit 0\n"
	for _, name := range []string{"ip", "nft"} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(script), 0755); err != nil {
			t.Fatal(err)
		}
	}
	old := os.Getenv("PATH")
	os.Setenv("PATH", bin+string(os.PathListSeparator)+old)
	t.Cleanup(func() { os.Setenv("PATH", old) })
	return func() string { b, _ := os.ReadFile(log); return string(b) }
}

func TestPublicIPGuardHoldsPrivateWANOut(t *testing.T) {
	tempState(t)
	c := testConfig(t)
	c.WAN[0].RequirePublicIP = true
	for _, tc := range []struct {
		name, ip string
		opt      bool
		proto    string
		held     bool
	}{
		{"cgnat", "100.64.1.2", true, "pppoe", true},
		{"rfc1918", "10.1.2.3", true, "pppoe", true},
		{"link-local", "169.254.7.7", true, "pppoe", true},
		{"public", "203.0.113.2", true, "pppoe", false},
		{"option off", "100.64.1.2", false, "pppoe", false},
	} {
		c.WAN[0].RequirePublicIP, c.WAN[0].Proto = tc.opt, tc.proto
		writeLease("wan", wanLease{IP: tc.ip, Dev: "pppoe-wan"})
		got := wanHealthMap(c)["wan"] == "down"
		if got != tc.held || wanHealthy(c, "wan") == tc.held {
			t.Errorf("%s: held=%v, want %v (map %v)", tc.name, got, tc.held, wanHealthMap(c))
		}
	}
	// no lease (PPPoE down) or another WAN's private address: not this WAN's business
	c.WAN[0].RequirePublicIP, c.WAN[0].Proto = true, "pppoe"
	removeLease("wan")
	writeLease("wan2", wanLease{IP: "100.64.9.9", Dev: "pppoe-wan2"})
	if m := wanHealthMap(c); m["wan"] == "down" || m["wan2"] == "down" {
		t.Errorf("only a WAN with the option and its own private lease is held out: %v", m)
	}
}

func TestPublicIPGuardKeepsWanmonVerdict(t *testing.T) {
	tempState(t)
	c := testConfig(t)
	c.MultiWAN.Mode = "failover"
	c.WAN[0].RequirePublicIP = true
	writeLease("wan", wanLease{IP: "203.0.113.2", Dev: "pppoe-wan"})
	if err := os.WriteFile(wanStateFile, []byte(`{"time":1,"interval":5,"wans":[{"name":"wan","state":"down"},{"name":"wan2","state":"up"}]}`), 0644); err != nil {
		t.Fatal(err)
	}
	if m := wanHealthMap(c); m["wan"] != "down" || m["wan2"] != "up" {
		t.Fatalf("wanmon verdicts must survive the overlay: %v", m)
	}
}

// The incident: a PPPoE session in the ISP's walled garden is up and has an address, so the WAN's
// table kept its default route and the pinned devices lost the internet (nothing fell back).
func TestHookPPPPrivateAddressDropsWANTableDefault(t *testing.T) {
	tempState(t)
	eventEnv(t)
	cmds := fakeIPLog(t)
	oldFW, oldRedial := fwLoadForHook, requirePublicRedial
	fwLoadForHook = func(*Config) error { return nil }
	requirePublicRedial = func(*WAN) {}
	t.Cleanup(func() { fwLoadForHook, requirePublicRedial = oldFW, oldRedial })
	c := testConfig(t)
	c.WAN[0].RequirePublicIP = true
	table, _ := c.WANTable("wan")

	if err := hookPPP(c, true, []string{"pppoe-wan", "", "", "100.64.1.2", "", "wan"}); err != nil {
		t.Fatal(err)
	}
	got := cmds()
	if !strings.Contains(got, "route del default table "+strconv.Itoa(table)) {
		t.Errorf("CGNAT session kept the default route of its WAN table:\n%s", got)
	}
	if strings.Contains(got, "default dev pppoe-wan table "+strconv.Itoa(table)) {
		t.Errorf("CGNAT session installed the table default:\n%s", got)
	}
	if !strings.Contains(got, "route replace default dev pppoe-wan metric "+strconv.Itoa(c.WAN[0].Metric+downMetric)) {
		t.Errorf("CGNAT session kept a normal main-table metric:\n%s", got)
	}

	// the next session is public: the table gets its default route back at once
	before := len(got)
	if err := hookPPP(c, true, []string{"pppoe-wan", "", "", "203.0.113.2", "", "wan"}); err != nil {
		t.Fatal(err)
	}
	got = cmds()[before:]
	if !strings.Contains(got, "route replace default dev pppoe-wan table "+strconv.Itoa(table)) {
		t.Errorf("public session did not restore the table default:\n%s", got)
	}
	if !strings.Contains(got, "route replace default dev pppoe-wan metric "+strconv.Itoa(c.WAN[0].Metric)+"\n") {
		t.Errorf("public session did not restore the main-table metric:\n%s", got)
	}
}

func TestHookPPPPrivateAddressWithoutOptionStaysRouted(t *testing.T) {
	tempState(t)
	cmds := fakeIPLog(t)
	oldFW := fwLoadForHook
	fwLoadForHook = func(*Config) error { return nil }
	t.Cleanup(func() { fwLoadForHook = oldFW })
	c := testConfig(t)
	c.WAN[0].RequirePublicIP = false
	table, _ := c.WANTable("wan")
	if err := hookPPP(c, true, []string{"pppoe-wan", "", "", "100.64.1.2", "", "wan"}); err != nil {
		t.Fatal(err)
	}
	if got := cmds(); !strings.Contains(got, "route replace default dev pppoe-wan table "+strconv.Itoa(table)) {
		t.Errorf("a WAN without require_public_ip keeps its table default even on CGNAT:\n%s", got)
	}
}

// publicIPCheck (cron, once a minute) also re-routes a WAN whose routes do not match the guard:
// the option was switched on while a CGNAT session was already up.
func TestPublicIPCheckReroutesWhenGuardStateDiffersFromRoutes(t *testing.T) {
	tempState(t)
	eventEnv(t)
	c := testConfig(t)
	c.WAN[0].RequirePublicIP, c.WAN[0].RequirePublicIPGap = true, 180
	oldNow, oldAddrs, oldRedial, oldMetrics, oldRefresh := requirePublicNow, publicCheckAddrs, requirePublicRedial, publicCheckMetrics, publicCheckRefresh
	now := time.Unix(1_800_000_000, 0)
	requirePublicNow = func() time.Time { return now }
	addr := "100.64.1.2/32"
	publicCheckAddrs = func(string) []string { return []string{addr} }
	requirePublicRedial = func(*WAN) {}
	metric := c.WAN[0].Metric // a normal metric: routes still treat the line as healthy
	publicCheckMetrics = func(string) []int { return []int{metric} }
	refreshes := 0
	publicCheckRefresh = func(*Config) { refreshes++ }
	t.Cleanup(func() {
		requirePublicNow, publicCheckAddrs, requirePublicRedial, publicCheckMetrics, publicCheckRefresh = oldNow, oldAddrs, oldRedial, oldMetrics, oldRefresh
	})
	writeLease("wan", wanLease{IP: "100.64.1.2", Dev: "pppoe-wan"})

	publicIPCheck(c)
	if refreshes != 1 {
		t.Fatalf("held WAN with a normal route metric: %d refreshes, want 1", refreshes)
	}
	metric = c.WAN[0].Metric + downMetric // routes now match
	publicIPCheck(c)
	if refreshes != 1 {
		t.Fatalf("matching routes were refreshed again: %d", refreshes)
	}
	// the session turned public but the routes still say down
	addr = "203.0.113.2/32"
	writeLease("wan", wanLease{IP: "203.0.113.2", Dev: "pppoe-wan"})
	publicIPCheck(c)
	if refreshes != 2 {
		t.Fatalf("public WAN with a raised metric: %d refreshes, want 2", refreshes)
	}
}

// fallback: drop is the owner's choice: the table loses its default route like for fallback: main,
// and the drop rule (oifname {other WANs}) is what keeps the traffic from leaving elsewhere.
func TestFallbackDropRuleUnchangedByGuard(t *testing.T) {
	tempState(t)
	c := testConfig(t)
	c.WAN[0].RequirePublicIP = true
	c.Policy = []Policy{{Name: "pinned", Src: "192.168.1.55", Via: "wan", Fallback: "drop"}}
	rules := strings.Join(policyFallbackRules(c), "\n")
	if !strings.Contains(rules, `counter drop comment "fallback:pinned"`) {
		t.Fatalf("fallback: drop lost its rule:\n%s", rules)
	}
}
