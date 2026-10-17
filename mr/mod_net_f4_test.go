package main

import (
	"encoding/json"
	"os"
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
	if got := strings.Join(ipv6DefaultRouteArgs(map[string]any{"gateway": "fe80::1", "metric": float64(1024)}, "pppoe-wan", downMetric+1024), " "); got != "-6 route replace default via fe80::1 dev pppoe-wan metric 11024" {
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
