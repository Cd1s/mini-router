package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRequirePublicIPValidation(t *testing.T) {
	c := testConfig(t)
	c.WAN[0].RequirePublicIP = true
	c.WAN[0].RequirePublicIPGap = 180
	c.defaults()
	mustValid(t, c)
	m, err := configToJSON(c)
	if err != nil {
		t.Fatal(err)
	}
	w, ok := m["wan"].([]any)
	if !ok || len(w) == 0 {
		t.Fatalf("WAN config missing from JSON: %v", m["wan"])
	}
	wm := w[0].(map[string]any)
	if wm["require_public_ip"] != true || wm["require_public_ip_gap"] != 180 {
		t.Fatalf("require_public_ip did not round-trip: %#v", wm)
	}
	c.WAN[0].Proto = "dhcp"
	if got := strings.Join(c.Validate(), "\n"); !strings.Contains(got, "require_public_ip: only supported on pppoe") {
		t.Fatalf("non-PPPoE require_public_ip accepted: %s", got)
	}
	c.WAN[0].Proto, c.WAN[0].RequirePublicIPGap = "pppoe", -1
	if got := strings.Join(c.Validate(), "\n"); !strings.Contains(got, "require_public_ip_gap: 1-86400") {
		t.Fatalf("negative require_public_ip_gap accepted: %s", got)
	}
	c.WAN[0].RequirePublicIPGap = 86401
	if got := strings.Join(c.Validate(), "\n"); !strings.Contains(got, "require_public_ip_gap: 1-86400") {
		t.Fatalf("large require_public_ip_gap accepted: %s", got)
	}
}

func TestRequirePublicIPRedialsOnlyOneWANAndStops(t *testing.T) {
	tempState(t)
	c := testConfig(t)
	c.WAN[0].RequirePublicIP = true
	c.WAN[0].RequirePublicIPGap = 1
	c.WAN[1].RequirePublicIP = true
	c.WAN[1].RequirePublicIPGap = 1
	now := time.Unix(1_800_000_000, 0)
	oldNow, oldRedial := requirePublicNow, requirePublicRedial
	var redials []string
	requirePublicNow = func() time.Time { return now }
	requirePublicRedial = func(w *WAN) { redials = append(redials, w.Name) }
	t.Cleanup(func() { requirePublicNow, requirePublicRedial = oldNow, oldRedial })

	for i := 0; i < requirePublicMax; i++ {
		requirePublicIP(c, &c.WAN[0], "100.64.1.2")
		now = now.Add(2 * time.Second)
	}
	if strings.Join(redials, ",") != "wan,wan,wan,wan" {
		t.Fatalf("redials=%v, want four attempts for wan only", redials)
	}
	var rec map[string]requirePublicRecord
	b, err := os.ReadFile(requirePublicFile)
	if err != nil || json.Unmarshal(b, &rec) != nil || !rec["wan"].Risk || rec["wan"].Attempts != requirePublicMax {
		t.Fatalf("state=%s err=%v", b, err)
	}
	// A public address clears the sequence; another private address may start fresh.
	requirePublicIP(c, &c.WAN[0], "203.0.113.2")
	if _, ok := readRequirePublic()["wan"]; ok {
		t.Fatal("public address did not clear require_public_ip state")
	}
}

func TestPublicIPCheckHonoursCooldownAndEventuallyStops(t *testing.T) {
	tempState(t)
	eventEnv(t)
	c := testConfig(t)
	c.WAN[0].RequirePublicIP, c.WAN[0].RequirePublicIPGap = true, 180
	c.WAN[1].RequirePublicIP, c.WAN[1].RequirePublicIPGap = true, 180
	now := time.Unix(1_800_000_000, 0)
	oldNow, oldAddrs, oldRedial := requirePublicNow, publicCheckAddrs, requirePublicRedial
	var redials []string
	requirePublicNow = func() time.Time { return now }
	publicCheckAddrs = func(dev string) []string {
		if dev == c.WAN[0].Ifname() {
			return []string{"100.64.1.2/32"}
		}
		return []string{"198.51.100.2/32"}
	}
	requirePublicRedial = func(w *WAN) { redials = append(redials, w.Name) }
	t.Cleanup(func() { requirePublicNow, publicCheckAddrs, requirePublicRedial = oldNow, oldAddrs, oldRedial })

	publicIPCheck(c) // first observation: redial immediately
	now = now.Add(10 * time.Second)
	publicIPCheck(c) // cooldown: no second redial yet
	if len(redials) != 1 {
		t.Fatalf("cooldown was ignored: %v", redials)
	}
	for i := 0; i < 4; i++ {
		now = now.Add(180 * time.Second)
		publicIPCheck(c)
	}
	if strings.Join(redials, ",") != "wan,wan,wan,wan" {
		t.Fatalf("redials after cooldown: %v", redials)
	}
	if !readRequirePublic()["wan"].Risk {
		t.Fatal("fifth private observation did not stop and mark risk")
	}
}

func TestRequirePublicIPHookSkipsDialRestore(t *testing.T) {
	tempState(t)
	eventEnv(t)
	fakeHookCommands(t)
	c := testConfig(t)
	c.WAN[0].RequirePublicIP = true
	c.MultiWAN.DialOrder = []string{"wan2", "wan"}
	c.MultiWAN.DialRestore = "now"
	oldFW, oldRedial, oldSpawn := fwLoadForHook, requirePublicRedial, dialSpawn
	var redials, spawned []string
	fwLoadForHook = func(*Config) error { return nil }
	requirePublicRedial = func(w *WAN) { redials = append(redials, w.Name) }
	dialSpawn = func(args ...string) error { spawned = append(spawned, strings.Join(args, " ")); return nil }
	t.Cleanup(func() { fwLoadForHook, requirePublicRedial, dialSpawn = oldFW, oldRedial, oldSpawn })
	if err := hookPPP(c, true, []string{"pppoe-wan", "", "", "100.64.1.2", "", "wan"}); err != nil {
		t.Fatal(err)
	}
	if strings.Join(redials, ",") != "wan" {
		t.Fatalf("guard redial target: %v", redials)
	}
	if len(spawned) != 0 {
		t.Fatalf("private guard triggered dial-order restore: %v", spawned)
	}
}

func TestPublicIPCheckCronLine(t *testing.T) {
	c := testConfig(t)
	if got := publicIPCheckCronLine(c); len(got) != 0 {
		t.Fatalf("disabled public check rendered cron: %v", got)
	}
	c.WAN[0].RequirePublicIP = true
	want := []string{"# require_public_ip", "* * * * * /usr/sbin/mr wan public-check --cron"}
	if got := publicIPCheckCronLine(c); strings.Join(got, "\n") != strings.Join(want, "\n") || !cronWanted(c) {
		t.Fatalf("public check cron: %v", got)
	}
	if got := strings.Join(renderCronLines(c), "\n"); !strings.Contains(got, strings.Join(want, "\n")) {
		t.Fatalf("rendered crontab missing public check: %s", got)
	}
}

func TestIPv6RAHealthChangePreservesRouteType(t *testing.T) {
	d := t.TempDir()
	bin := filepath.Join(d, "bin")
	if err := os.Mkdir(bin, 0755); err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(d, "ip.log")
	script := "#!/bin/sh\ncase \"$*\" in *'-j -6 route show default dev pppoe-wan'*) echo '[{\"protocol\":\"ra\",\"metric\":1024,\"gateway\":\"fe80::1\",\"expires\":123,\"nexthops\":[{\"gateway\":\"fe80::1\",\"dev\":\"pppoe-wan\"}]}]' ;; *) echo \"$*\" >> '" + log + "' ;; esac\n"
	if err := os.WriteFile(filepath.Join(bin, "ip"), []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	oldPath := os.Getenv("PATH")
	os.Setenv("PATH", bin+string(os.PathListSeparator)+oldPath)
	t.Cleanup(func() { os.Setenv("PATH", oldPath) })
	setMainDefault6(&WAN{Name: "wan", Proto: "pppoe", IPv6: true, Metric: 0}, false)
	got, _ := os.ReadFile(log)
	if strings.TrimSpace(string(got)) != "-6 route replace default proto ra expires 123 metric 11024 nexthop via fe80::1 dev pppoe-wan\n-6 route del default proto ra metric 1024 nexthop via fe80::1 dev pppoe-wan" {
		t.Fatalf("RA route was replaced/destructively rebuilt: %q", got)
	}
}

func TestGatewayConflictStatePersists(t *testing.T) {
	tempState(t)
	if gatewayConflictReported("wan:192.168.1.1") {
		t.Fatal("first gateway conflict was reported as duplicate")
	}
	if !gatewayConflictReported("wan:192.168.1.1") {
		t.Fatal("gateway conflict state did not persist")
	}
	clearGatewayConflict("wan:192.168.1.1")
	if gatewayConflictReported("wan:192.168.1.1") {
		t.Fatal("cleared gateway conflict still reported as duplicate")
	}
}

func TestIPv6DefaultRouteHealthArgs(t *testing.T) {
	r := map[string]any{"protocol": "ra", "gateway": "fe80::1", "metric": float64(1024), "expires": float64(123)}
	if got := strings.Join(ipv6DefaultRouteReplaceArgs(r, "pppoe-wan", downMetric+1024), " "); got != "-6 route replace default via fe80::1 dev pppoe-wan proto ra expires 123 metric 11024" {
		t.Fatalf("IPv6 route args: %s", got)
	}
	w := &WAN{Name: "wan", Proto: "pppoe", IPv6: true}
	if got := strings.Join(ipv6WANTableRouteArgs(w, false, "", 200), " "); got != "-6 route del default table 200" {
		t.Fatalf("down WAN IPv6 table route: %s", got)
	}
	if got := strings.Join(ipv6WANTableRouteArgs(w, true, "", 200), " "); got != "-6 route replace default dev pppoe-wan table 200" {
		t.Fatalf("healthy WAN IPv6 table route: %s", got)
	}
}

func TestIPv6HealthRoutingOnlyChangesWithMultiWANHealth(t *testing.T) {
	c := testConfig(t)
	if ipv6HealthRoutingEnabled(c) {
		t.Fatal("single-WAN/default config unexpectedly enables IPv6 health routing")
	}
	c.MultiWAN.Mode = "failover"
	if !ipv6HealthRoutingEnabled(c) {
		t.Fatal("multi-WAN health config did not enable IPv6 health routing")
	}
}

func TestDoctorCGNATHealthHint(t *testing.T) {
	c := testConfig(t)
	c.WAN[0].RequirePublicIP = true
	e := fakeDocEnv()
	e.addrs4 = func(dev string) []string {
		if dev == c.WAN[0].Ifname() {
			return []string{"100.64.3.4/32"}
		}
		return []string{"198.51.100.20/32"}
	}
	e.health = func(*Config) map[string]string { return map[string]string{"wan": "down"} }
	f := docFindingsByID(docWAN(c, e), "wan.wan")
	if !strings.Contains(f.Detail, "CGNAT") || !strings.Contains(f.Fix, "automatic public-IP redial") {
		t.Fatalf("doctor finding: %+v", f)
	}
}

func docFindingsByID(fs []docFinding, id string) docFinding {
	for _, f := range fs {
		if f.ID == id {
			return f
		}
	}
	return docFinding{}
}
