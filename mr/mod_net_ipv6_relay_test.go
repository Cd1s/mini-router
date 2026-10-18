package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
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

// relayTestEnv points every relay file (state, verdicts, both locks, WAN run dir) into a temp dir
// and restores the hooks afterwards; run is the fake for ip / ping6 / rc-service.
func relayTestEnv(t *testing.T, run func(name string, args ...string) (string, error)) string {
	t.Helper()
	d := t.TempDir()
	saved := []any{ipv6RelayStateFile, ipv6RelayLockFile, ipv6RelayVerdictFile, ipv6RelayProbeLockFile, wanRunDir}
	oldRun, oldSet, oldProbe, oldNow, oldSleep, oldBudget, oldSlot := ipv6RelayRun, ipv6RelaySetProxyNDP, ipv6RelayProbeFn, ipv6RelayNow, ipv6RelaySleep, ipv6RelayProbeBudget, ipv6RelayProbeSlot
	ipv6RelayStateFile, ipv6RelayLockFile = filepath.Join(d, "state.json"), filepath.Join(d, "lock")
	ipv6RelayVerdictFile, ipv6RelayProbeLockFile = filepath.Join(d, "probe.json"), filepath.Join(d, "probe.lock")
	wanRunDir = filepath.Join(d, "wan")
	if err := os.MkdirAll(wanRunDir, 0755); err != nil {
		t.Fatal(err)
	}
	ipv6RelayRun = run
	ipv6RelaySetProxyNDP = func(string, bool) error { return nil }
	ipv6RelaySleep = func(time.Duration) {}
	t.Cleanup(func() {
		ipv6RelayStateFile, ipv6RelayLockFile, ipv6RelayVerdictFile, ipv6RelayProbeLockFile, wanRunDir =
			saved[0].(string), saved[1].(string), saved[2].(string), saved[3].(string), saved[4].(string)
		ipv6RelayRun, ipv6RelaySetProxyNDP, ipv6RelayProbeFn, ipv6RelayNow, ipv6RelaySleep, ipv6RelayProbeBudget, ipv6RelayProbeSlot = oldRun, oldSet, oldProbe, oldNow, oldSleep, oldBudget, oldSlot
	})
	return d
}

// seedVerdicts writes the verdict file as another process (the cron run) would have.
func seedVerdicts(t *testing.T, v map[string]ipv6RelayVerdict) {
	t.Helper()
	b, _ := json.Marshal(v)
	if err := os.WriteFile(ipv6RelayVerdictFile, b, 0600); err != nil {
		t.Fatal(err)
	}
}

func freeNow(addrs ...string) map[string]ipv6RelayVerdict {
	m := map[string]ipv6RelayVerdict{}
	for _, a := range addrs {
		m[ipv6RelayVerdictKey("wan", a)] = ipv6RelayVerdict{Result: ipv6RelayFree, At: time.Now().Unix(), TTL: 600}
	}
	return m
}

func relayConfig() *Config {
	return &Config{LAN: LAN{Bridge: "br-lan", IPv6RA: true}, WAN: []WAN{{Name: "wan", Device: "wan", Proto: "dhcp", IPv6: true, IPv6Relay: true}}}
}

const relayWANAddr = `[{"addr_info":[{"family":"inet6","local":"2001:db8:1::2","prefixlen":64}]}]`

func TestIPv6RelaySyncTracksNeighboursAndCleansOnDisable(t *testing.T) {
	var neigh = "2001:db8:1::20"
	var calls []string
	relayTestEnv(t, func(name string, args ...string) (string, error) {
		line := name + " " + strings.Join(args, " ")
		calls = append(calls, line)
		switch {
		case name == "ping6":
			t.Fatalf("sync probed: %s", line)
		case strings.Contains(line, "addr show dev wan"):
			return relayWANAddr, nil
		case strings.Contains(line, "neigh show dev br-lan"):
			return `[{"dst":"` + neigh + `","state":["STALE"]}]`, nil
		}
		return "", nil
	})
	seedVerdicts(t, freeNow("2001:db8:1::20", "2001:db8:1::21"))
	c := relayConfig()
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
		t.Errorf("neighbour change was not reconciled (the vanished one keeps its grace):\n%s", joined)
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
	if _, err := os.Stat(ipv6RelayVerdictFile); !os.IsNotExist(err) {
		t.Errorf("disable left the probe verdicts behind: %v", err)
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
	var calls []string
	relayTestEnv(t, func(name string, args ...string) (string, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return "", nil
	})
	ipv6RelaySetProxyNDP = func(dev string, enabled bool) error {
		calls = append(calls, "proxy_ndp "+dev+" "+fmt.Sprint(enabled))
		return nil
	}
	os.WriteFile(filepath.Join(wanRunDir, "wan.pd6"), []byte("2001:db8:1::/56\n"), 0644)
	writeIPv6RelayState(ipv6RelayState{Prefixes: []ipv6RelayPrefix{{WAN: "wan", Dev: "wan", Prefix: "2001:db8:1::/64", Addr: "2001:db8:1::2"}},
		Proxies: []ipv6RelayProxy{{Addr: "2001:db8:1::20", Dev: "wan"}}, LANAddrs: []string{"2001:db8:1::2/64"},
		Routes: []ipv6RelayRoute{{Addr: "2001:db8:1::20", Dev: "br-lan"}, {Addr: "2001:db8:1::2", Dev: "br-lan"}}})
	if err := ipv6RelaySync(relayConfig()); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(calls, "\n")
	for _, want := range []string{"addr replace 2001:db8:1::2/64 dev br-lan preferred_lft 0 valid_lft 2700", "route del 2001:db8:1::/64 dev wan proto static metric 100",
		"neigh del proxy 2001:db8:1::20 dev wan", "route del 2001:db8:1::20/128 dev br-lan", "route del 2001:db8:1::2/128 dev br-lan", "proxy_ndp wan false", "rc-service dnsmasq reload"} {
		if !strings.Contains(joined, want) {
			t.Errorf("PD transition missing %q:\n%s", want, joined)
		}
	}
}

func TestIPv6RelayRoutesStayInsidePrefixAndAreCleaned(t *testing.T) {
	var calls []string
	relayTestEnv(t, func(name string, args ...string) (string, error) {
		line := name + " " + strings.Join(args, " ")
		calls = append(calls, line)
		switch {
		case strings.Contains(line, "addr show dev wan"):
			return relayWANAddr, nil
		case strings.Contains(line, "neigh show dev br-lan"):
			return `[{"dst":"2001:db8:1::20","state":["STALE"]},{"dst":"2001:4860:4860::8888","state":["STALE"]}]`, nil
		}
		return "", nil
	})
	writeIPv6RelayState(ipv6RelayState{Prefixes: []ipv6RelayPrefix{{WAN: "wan", Dev: "wan", Prefix: "2001:db8:1::/64", Addr: "2001:db8:1::2"}}, Routes: []ipv6RelayRoute{{Addr: "2001:4860:4860::8888", Dev: "br-lan"}}})
	// even a (forged) free verdict cannot make an address outside the relay /64 eligible
	seedVerdicts(t, freeNow("2001:db8:1::20", "2001:4860:4860::8888"))
	c := relayConfig()
	if err := ipv6RelaySync(c); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(calls, "\n")
	if strings.Contains(joined, "route replace 2001:4860:4860::8888/128") || strings.Contains(joined, "proxy 2001:4860:4860::8888") {
		t.Fatalf("out-of-prefix neighbour received a host route or proxy:\n%s", joined)
	}
	if !strings.Contains(joined, "route del 2001:4860:4860::8888/128") {
		t.Fatalf("a recorded out-of-prefix route was not removed:\n%s", joined)
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

// The verdict decides: ping6 reply or a usable WAN entry = occupied, FAILED = free, anything else = no
// verdict (ping6 missing / failing, INCOMPLETE that never resolves).
func TestIPv6RelayProbeVerdicts(t *testing.T) {
	cases := []struct {
		name   string
		ping   error
		states []string // successive neighbour states for the address on the WAN
		want   string
	}{
		{"echo reply", nil, nil, ipv6RelayOccupied},
		{"answers NS, ignores echo", errors.New("1"), []string{"REACHABLE"}, ipv6RelayOccupied},
		{"stale upstream entry", errors.New("1"), []string{"STALE"}, ipv6RelayOccupied},
		{"nobody answers", errors.New("1"), []string{"FAILED"}, ipv6RelayFree},
		{"resolution still running, then failed", errors.New("1"), []string{"INCOMPLETE", "INCOMPLETE", "FAILED"}, ipv6RelayFree},
		{"never resolves", errors.New("1"), []string{"INCOMPLETE"}, ""},
		{"ping6 could not run (no entry)", errors.New("exec: not found"), []string{""}, ""},
	}
	for _, tc := range cases {
		i := 0
		relayTestEnv(t, func(name string, args ...string) (string, error) {
			if name == "ping6" {
				return "", tc.ping
			}
			line := strings.Join(args, " ")
			if !strings.Contains(line, "neigh show to 2001:db8:1::20 dev wan") {
				t.Fatalf("%s: unexpected command %s %s", tc.name, name, line)
			}
			st := tc.states[len(tc.states)-1]
			if i < len(tc.states) {
				st = tc.states[i]
			}
			i++
			if st == "" {
				return "[]", nil
			}
			return `[{"dst":"2001:db8:1::20","state":["` + st + `"]}]`, nil
		})
		if got := ipv6RelayProbe("wan", "2001:db8:1::20"); got != tc.want {
			t.Errorf("%s: verdict %q, want %q", tc.name, got, tc.want)
		}
	}
}

// Cross-process: the hook / apply sync reads the verdicts the cron run wrote. Only an unexpired free
// verdict is proxied; occupied, expired or missing verdicts are not, and an existing proxy that loses
// its free verdict or shows up in the WAN neighbour table is removed at once (no grace).
func TestIPv6RelaySyncFollowsSharedVerdicts(t *testing.T) {
	wanNeigh := "[]"
	var calls []string
	relayTestEnv(t, func(name string, args ...string) (string, error) {
		line := name + " " + strings.Join(args, " ")
		calls = append(calls, line)
		switch {
		case name == "ping6":
			t.Fatalf("sync probed: %s", line)
		case strings.Contains(line, "addr show dev wan"):
			return relayWANAddr, nil
		case strings.Contains(line, "neigh show dev br-lan"):
			return `[{"dst":"2001:db8:1::20","state":["STALE"]},{"dst":"2001:db8:1::21","state":["STALE"]},{"dst":"2001:db8:1::22","state":["REACHABLE"]},{"dst":"2001:db8:1::23","state":["STALE"]},{"dst":"2001:db8:1::24","state":["STALE"]}]`, nil
		case strings.Contains(line, "neigh show dev wan"):
			return wanNeigh, nil
		}
		return "", nil
	})
	now := time.Now().Unix()
	v := freeNow("2001:db8:1::20", "2001:db8:1::24")
	v[ipv6RelayVerdictKey("wan", "2001:db8:1::21")] = ipv6RelayVerdict{Result: ipv6RelayOccupied, At: now, TTL: 600}
	v[ipv6RelayVerdictKey("wan", "2001:db8:1::23")] = ipv6RelayVerdict{Result: ipv6RelayFree, At: now - 700, TTL: 600} // expired
	seedVerdicts(t, v)                                                                                                 // ::22 has no verdict at all
	c := relayConfig()
	if err := ipv6RelaySync(c); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(calls, "\n")
	for _, a := range []string{"::20", "::24"} {
		if !strings.Contains(joined, "neigh replace proxy 2001:db8:1"+a+" dev wan") {
			t.Errorf("free verdict 2001:db8:1%s was not proxied:\n%s", a, joined)
		}
	}
	for _, a := range []string{"::21", "::22", "::23"} {
		if strings.Contains(joined, "proxy 2001:db8:1"+a+" ") || strings.Contains(joined, "route replace 2001:db8:1"+a+"/128") {
			t.Errorf("2001:db8:1%s (occupied / no verdict / expired) was proxied:\n%s", a, joined)
		}
	}
	// the cron run now finds ::20 occupied upstream: removed in the same scan
	v[ipv6RelayVerdictKey("wan", "2001:db8:1::20")] = ipv6RelayVerdict{Result: ipv6RelayOccupied, At: now, TTL: 600}
	seedVerdicts(t, v)
	calls = nil
	if err := ipv6RelaySync(c); err != nil {
		t.Fatal(err)
	}
	joined = strings.Join(calls, "\n")
	if !strings.Contains(joined, "neigh del proxy 2001:db8:1::20 dev wan") || !strings.Contains(joined, "route del 2001:db8:1::20/128") {
		t.Fatalf("an address that became occupied kept its proxy:\n%s", joined)
	}
	// ::24 appears in the WAN neighbour table: removed at once despite its free verdict
	wanNeigh = `[{"dst":"2001:db8:1::24","state":["STALE"]}]`
	calls = nil
	if err := ipv6RelaySync(c); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(calls, "\n"), "neigh del proxy 2001:db8:1::24 dev wan") {
		t.Fatalf("an address the WAN knows kept its proxy:\n%s", strings.Join(calls, "\n"))
	}
	// with no verdict file at all (the cron run never decided), nothing is proxied
	os.Remove(ipv6RelayVerdictFile)
	wanNeigh = "[]"
	writeIPv6RelayState(ipv6RelayState{})
	calls = nil
	if err := ipv6RelaySync(c); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(calls, "\n"), "neigh replace proxy") {
		t.Fatalf("proxied without any verdict:\n%s", strings.Join(calls, "\n"))
	}
}

// Discover writes the verdicts other processes read; it probes at most ipv6RelayProbeParallel at once,
// starts nothing after the budget and returns within budget + slot; candidates are filtered before
// the cap; unknown results and unprobed addresses get no verdict; a fresh verdict is not probed again;
// a run that finds the probe lock taken does nothing.
func TestIPv6RelayDiscoverIsBoundedAndShared(t *testing.T) {
	var lanJSON strings.Builder
	lanJSON.WriteString(`[{"dst":"2001:db8:1::2","state":["REACHABLE"]},{"dst":"2001:4860::1","state":["STALE"]},{"dst":"2001:db8:1::99","state":["STALE"]}`)
	for i := 0; i < 60; i++ {
		fmt.Fprintf(&lanJSON, `,{"dst":"2001:db8:1::%x","state":["STALE"]}`, 0x100+i)
	}
	lanJSON.WriteString("]")
	relayTestEnv(t, func(name string, args ...string) (string, error) {
		line := name + " " + strings.Join(args, " ")
		switch {
		case strings.Contains(line, "addr show dev wan"):
			return relayWANAddr, nil
		case strings.Contains(line, "neigh show dev br-lan"):
			return lanJSON.String(), nil
		case strings.Contains(line, "neigh show dev wan"):
			return `[{"dst":"2001:db8:1::99","state":["REACHABLE"]}]`, nil
		}
		return "", nil
	})
	ipv6RelayProbeBudget, ipv6RelayProbeSlot = 600*time.Millisecond, 400*time.Millisecond
	var mu sync.Mutex
	inFlight, maxInFlight := 0, 0
	probed := map[string]int{}
	ipv6RelayProbeFn = func(dev, addr string) string {
		mu.Lock()
		inFlight++
		if inFlight > maxInFlight {
			maxInFlight = inFlight
		}
		probed[addr]++
		mu.Unlock()
		time.Sleep(150 * time.Millisecond)
		mu.Lock()
		inFlight--
		mu.Unlock()
		switch {
		case strings.HasSuffix(addr, "::100"):
			return "" // unknown
		case strings.HasSuffix(addr, "::101"):
			return ipv6RelayOccupied
		}
		return ipv6RelayFree
	}
	c := relayConfig()
	start := time.Now()
	ipv6RelayDiscover(c)
	if d := time.Since(start); d > ipv6RelayProbeBudget+ipv6RelayProbeSlot+200*time.Millisecond {
		t.Fatalf("discover took %v", d)
	}
	if maxInFlight > ipv6RelayProbeParallel || maxInFlight == 0 {
		t.Fatalf("parallel probes: %d", maxInFlight)
	}
	for _, a := range []string{"2001:db8:1::2", "2001:4860::1", "2001:db8:1::99"} {
		if probed[a] > 0 {
			t.Errorf("%s (router / outside the prefix / known on the WAN) was probed", a)
		}
	}
	first := len(probed)
	if first == 0 || first >= 60 {
		t.Fatalf("probed %d of 60 candidates within the budget, want some but not all", first)
	}
	v := readIPv6RelayVerdicts(time.Now().Unix())
	if v[ipv6RelayVerdictKey("wan", "2001:db8:1::99")].Result != ipv6RelayOccupied {
		t.Errorf("the WAN neighbour was not recorded occupied: %v", v)
	}
	if _, ok := v[ipv6RelayVerdictKey("wan", "2001:db8:1::100")]; ok {
		t.Errorf("an unknown probe result was stored as a verdict")
	}
	if v[ipv6RelayVerdictKey("wan", "2001:db8:1::101")].Result != ipv6RelayOccupied || v[ipv6RelayVerdictKey("wan", "2001:db8:1::102")].Result != ipv6RelayFree {
		t.Errorf("probe results not stored: %v", v)
	}
	// the hook / apply sync (another process: nothing in memory) proxies exactly the free verdicts
	if err := ipv6RelaySync(c); err != nil {
		t.Fatal(err)
	}
	st := readIPv6RelayState()
	free := 0
	for k, x := range v {
		if x.Result == ipv6RelayFree && strings.HasPrefix(k, "wan ") {
			free++
		}
	}
	if len(st.Proxies) != free {
		t.Fatalf("proxies %d, free verdicts %d: %v", len(st.Proxies), free, st.Proxies)
	}
	// the next run probes only what has no fresh verdict
	before := map[string]int{}
	for k, n := range probed {
		before[k] = n
	}
	ipv6RelayDiscover(c)
	for a, n := range probed {
		if before[a] > 0 && n > before[a] && !strings.HasSuffix(a, "::100") {
			t.Errorf("%s was probed again although its verdict is fresh", a)
		}
	}
	if len(probed) <= first {
		t.Errorf("the second run did not continue with the remaining candidates")
	}
	// a run that finds another one still probing does nothing
	lk := flock(ipv6RelayProbeLockFile, true)
	n := len(probed)
	ipv6RelayDiscover(c)
	lk.Close()
	if len(probed) != n {
		t.Errorf("discover probed while the probe lock was held")
	}
	// the cron command does not wait for a held state lock
	lk = flock(ipv6RelayLockFile, true)
	done := make(chan error, 1)
	go func() { done <- netCommand(c, []string{"ipv6-relay", "--cron"}) }()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("cron run with a busy lock: %v", err)
		}
	case <-time.After(ipv6RelayProbeBudget + ipv6RelayProbeSlot + time.Second):
		t.Errorf("cron run waited for the relay state lock")
	}
	lk.Close()
}

// The cap counts filtered candidates and keeps already proxied addresses first.
func TestIPv6RelayCapKeepsExistingProxies(t *testing.T) {
	var lanJSON strings.Builder
	lanJSON.WriteString("[")
	v := map[string]ipv6RelayVerdict{}
	for i := 0; i < 80; i++ {
		if i > 0 {
			lanJSON.WriteString(",")
		}
		a := fmt.Sprintf("2001:db8:1::%x", 0x100+i)
		fmt.Fprintf(&lanJSON, `{"dst":"%s","state":["STALE"]}`, a)
		v[ipv6RelayVerdictKey("wan", a)] = ipv6RelayVerdict{Result: ipv6RelayFree, At: time.Now().Unix(), TTL: 600}
	}
	lanJSON.WriteString("]")
	relayTestEnv(t, func(name string, args ...string) (string, error) {
		line := name + " " + strings.Join(args, " ")
		switch {
		case strings.Contains(line, "addr show dev wan"):
			return relayWANAddr, nil
		case strings.Contains(line, "neigh show dev br-lan"):
			return lanJSON.String(), nil
		}
		return "", nil
	})
	seedVerdicts(t, v)
	last := "2001:db8:1::14f" // sorts after the first 64
	writeIPv6RelayState(ipv6RelayState{Prefixes: []ipv6RelayPrefix{{WAN: "wan", Dev: "wan", Prefix: "2001:db8:1::/64", Addr: "2001:db8:1::2"}},
		Proxies: []ipv6RelayProxy{{Addr: last, Dev: "wan"}}, LANAddrs: []string{"2001:db8:1::2/64"}})
	if err := ipv6RelaySync(relayConfig()); err != nil {
		t.Fatal(err)
	}
	st := readIPv6RelayState()
	if len(st.Proxies) != ipv6RelayMaxProxies || !ipv6RelayHasProxy(st.Proxies, ipv6RelayProxy{Addr: last, Dev: "wan"}) {
		t.Fatalf("cap %d, existing proxy kept: %v (%d proxies)", ipv6RelayMaxProxies, ipv6RelayHasProxy(st.Proxies, ipv6RelayProxy{Addr: last, Dev: "wan"}), len(st.Proxies))
	}
}
