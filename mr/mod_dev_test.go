package main

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// devConfig: the home config plus a small inventory that every section refers to.
func devConfig(t *testing.T) *Config {
	t.Helper()
	c := testConfig(t)
	c.Devices = []Device{
		{Name: "office-pc", MACs: []string{"02:00:00:00:10:01"}, IP: "192.168.1.70", Type: "pc", Owner: "Alice"},
		{Name: "kid-tablet", MACs: []string{"AA:BB:CC:00:00:21", "aa:bb:cc:00:00:22"}, IP: "192.168.1.121"},
		{Name: "game-console", MACs: []string{"aa:bb:cc:00:00:23"}},
	}
	c.Groups = map[string][]string{"kids": {"kid-tablet", "game-console"}}
	return c
}

func TestDevValidate(t *testing.T) {
	c := devConfig(t)
	c.Firewall.Forwards = append(c.Firewall.Forwards, Forward{Name: "rdp", Proto: []string{"tcp"}, Port: "3390", To: "office-pc", ToPort: "3389"})
	c.Firewall.Access = []FwAccess{{Name: "kids", Devices: []string{"group:kids"}}}
	c.Policy = append(c.Policy, Policy{Name: "office", Device: "office-pc", Via: "wan2", Fallback: "drop"})
	c.Proxy.Bypass = []ProxyDevice{{Name: "kids", Device: "group:kids"}}
	c.Guard.AlwaysBypass = []string{"kid-tablet"}
	c.defaults()
	if errs := c.Validate(); len(errs) > 0 {
		t.Fatalf("valid inventory refused: %v", errs)
	}

	bad := devConfig(t)
	bad.Devices = append(bad.Devices,
		Device{Name: "Bad_Name", MACs: []string{"02:00:00:00:20:01"}},
		Device{Name: "office-pc", MACs: []string{"02:00:00:00:10:01"}, IP: "192.168.1.70"}, // duplicate everything
		Device{Name: "desktop", MACs: []string{"02:00:00:00:20:02"}},                       // a dhcp.hosts name
		Device{Name: "nomac", MACs: nil},
		Device{Name: "mcast", MACs: []string{"01:00:5e:00:00:01"}},
		Device{Name: "outside", MACs: []string{"02:00:00:00:20:03"}, IP: "10.9.9.9"},
		Device{Name: "router", MACs: []string{"02:00:00:00:20:04"}, IP: "192.168.1.6"},
		Device{Name: "evil", MACs: []string{"02:00:00:00:20:05"}, Type: "a b", Owner: "x\ny"},
	)
	bad.Devices = append(bad.Devices, Device{Name: "stolen", MACs: []string{bad.DHCP.Hosts[0].MAC}, IP: bad.DHCP.Hosts[0].IP})
	bad.Groups["kids"] = append(bad.Groups["kids"], "ghost", "game-console")
	bad.Groups["Bad"] = []string{"office-pc"}
	bad.Groups["empty"] = nil
	wantErrs(t, bad,
		`devices[3].name: lowercase letters`, `devices[4].name: duplicate "office-pc"`,
		`devices[4].macs: 02:00:00:00:10:01 is also in device office-pc`, `devices[4].ip: 192.168.1.70 is also the address of device office-pc`,
		`devices[5].name: "desktop" is also a dhcp.hosts name`, `devices[6].macs: 1-8 MACs`, `devices[7].macs: 01:00:5e:00:00:01 is not a unicast MAC`,
		`devices[8].ip: an IPv4 inside a LAN-side network, got "10.9.9.9"`, `devices[9].ip`, `that is the router itself`,
		`devices[10].type: a short label`, `devices[10].owner: max 40 characters`,
		`devices[11].macs: `+strings.ToLower(bad.DHCP.Hosts[0].MAC)+` is also in dhcp.hosts`, `devices[11].ip: `+bad.DHCP.Hosts[0].IP+` is also in dhcp.hosts`,
		`groups.kids: unknown device "ghost"`, `groups.kids: duplicate "game-console"`, `groups: name "Bad"`, `groups.empty: 1-256 devices`)

	// references to names that do not exist (a device deleted while still in use): every place is listed
	ref := devConfig(t)
	ref.Devices = ref.Devices[1:] // office-pc deleted
	ref.Firewall.Forwards = append(ref.Firewall.Forwards,
		Forward{Name: "rdp", Proto: []string{"tcp"}, Port: "3390", To: "office-pc"},
		Forward{Name: "cons", Proto: []string{"tcp"}, Port: "3391", To: "game-console"})
	ref.Firewall.Access = []FwAccess{{Name: "kids", Devices: []string{"group:kidz", "office-pc"}}}
	ref.Policy = append(ref.Policy, Policy{Name: "office", Device: "office-pc", Via: "wan2"},
		Policy{Name: "both", MAC: "02:00:00:00:30:01", Device: "group:kids", Via: "wan2", Fallback: "never"})
	ref.Proxy.Bypass = []ProxyDevice{{Name: "pc", Device: "office-pc"}, {Name: "x", MAC: "02:00:00:00:30:02", Device: "game-console"}}
	ref.Guard.AlwaysBypass = []string{"office-pc"}
	ref.Proxy.Enabled = true
	ref.defaults()
	wantErrs(t, ref,
		`firewall.forwards[3].to: unknown device "office-pc"`, `firewall.forwards[4].to: device game-console has no ip`,
		`firewall.access[0].devices: unknown group "group:kidz"`, `firewall.access[0].devices: unknown device "office-pc"`,
		`policy_routes[1].device: unknown device "office-pc"`, `policy_routes[2]: set mac or device, not both`,
		`policy_routes[2].fallback: main|drop, got "never"`,
		`proxy.bypass[0].device: unknown device "office-pc"`, `proxy.bypass[1]: set mac or device, not both`,
		`guard.always_bypass: device "office-pc" is not in proxy.bypass`)
	// an access entry needs at least one MAC, from macs or devices
	e := devConfig(t)
	e.Firewall.Access = []FwAccess{{Name: "none"}}
	e.defaults()
	wantErrs(t, e, `firewall.access[0].macs: 1-64 device MACs required (macs and / or devices)`)
}

func TestDevRender(t *testing.T) {
	c := devConfig(t)
	c.Firewall.Forwards = append(c.Firewall.Forwards, Forward{Name: "rdp", Proto: []string{"tcp"}, Port: "3390", To: "office-pc", ToPort: "3389"})
	c.Firewall.Access = []FwAccess{{Name: "kids", MACs: []string{"02:00:00:00:30:01"}, Devices: []string{"group:kids", "kid-tablet"}}}
	c.Policy = append(c.Policy, Policy{Name: "office", Device: "office-pc", Via: "wan2", Fallback: "drop"},
		Policy{Name: "kids", Device: "group:kids", Src: "192.168.1.0/24", Via: "wan", Fallback: "drop"})
	c.Proxy.Bypass = []ProxyDevice{{Name: "kids", Device: "group:kids"}, {Name: "x", MAC: "02:00:00:00:30:02"}}
	c.DHCP.HostLeases = map[string]string{"aa:bb:cc:00:00:22": "infinite"}
	c.defaults()
	if errs := c.Validate(); len(errs) > 0 {
		t.Fatal(errs)
	}
	files, err := Render(c)
	if err != nil {
		t.Fatal(err)
	}
	var dnsmasq string
	for _, f := range files {
		if f.Path == "/etc/dnsmasq.conf" {
			dnsmasq = f.Data
		}
	}
	mustContain(t, "dnsmasq.conf", dnsmasq,
		"dhcp-host=02:00:00:00:10:01,192.168.1.70,office-pc\n",
		"dhcp-host=aa:bb:cc:00:00:21,aa:bb:cc:00:00:22,192.168.1.121,kid-tablet,infinite\n",
		"dhcp-host=aa:bb:cc:00:00:23,game-console\n")
	nft := renderNft(c, allExist)
	kids := "{ aa:bb:cc:00:00:21, aa:bb:cc:00:00:22, aa:bb:cc:00:00:23 }"
	mustContain(t, "nft", nft,
		`tcp dport 3390 dnat ip to 192.168.1.70:3389 comment "rdp"`,
		`ether saddr { 02:00:00:00:30:01, aa:bb:cc:00:00:21, aa:bb:cc:00:00:22, aa:bb:cc:00:00:23 } update @ac_4`,
		`iifname "br-lan" ether saddr 02:00:00:00:10:01 ip daddr != 192.168.1.0/24 ct state new ct mark set 0x102`,
		`iifname "br-lan" ether saddr `+kids+` ip saddr 192.168.1.0/24 ip daddr != 192.168.1.0/24 ct state new`,
		// fallback: drop, at the top of forward (before the access rules and flow offload)
		`iifname "br-lan" ether saddr 02:00:00:00:10:01 meta nfproto ipv4 oifname "pppoe-wan" counter drop comment "fallback:office"`,
		// IPv6: only sources in wan2's prefix (what the policy routes); another prefix takes the default WAN
		`iifname "br-lan" ether saddr 02:00:00:00:10:01 ip6 saddr @pd6_1 oifname "pppoe-wan" counter drop comment "fallback:office"`,
		`iifname "br-lan" ether saddr `+kids+` ip saddr 192.168.1.0/24 oifname "pppoe-wan2" counter drop comment "fallback:kids"`)
	fwd := nft[strings.Index(nft, "chain forward {"):]
	if a, b := strings.Index(fwd, "fallback:office"), strings.Index(fwd, "update @ac_4"); a < 0 || b < 0 || a > b || b > strings.Index(fwd, "flow add") {
		t.Errorf("forward chain order: fallback, access, flow offload\n%s", fwd[:min(len(fwd), 1500)])
	}
	// the rendered file never holds runtime pauses
	mustNotContain(t, "nft", nft, "@paused")

	// the proxy's bypass set (rendered only with the proxy services present)
	var macs []string
	for _, d := range c.Proxy.Bypass {
		macs = append(macs, proxyBypassMACs(c, d)...)
	}
	if got := strings.Join(dedup(macs), ", "); got != "aa:bb:cc:00:00:21, aa:bb:cc:00:00:22, aa:bb:cc:00:00:23, 02:00:00:00:30:02" {
		t.Errorf("bypass MACs = %s", got)
	}
	// knownHosts: names for lists, events, WOL; static only with an ip
	if mac, host, _, err := wolTarget(c, "kid-tablet", ""); err != nil || host != "kid-tablet" || mac.String() != "aa:bb:cc:00:00:21" {
		t.Errorf("wol kid-tablet = %v %q %v", mac, host, err)
	}
}

// The real home config has no devices: its rendered files do not change (tools/ci.sh compares the
// whole render with the previous commit's too).
func TestDevHomeUnchanged(t *testing.T) {
	c := testConfig(t)
	if len(c.Devices) > 0 || len(c.Groups) > 0 {
		t.Skip("the home config has an inventory now")
	}
	nft := renderNft(c, allExist)
	mustNotContain(t, "home nft", nft, "fallback:", "@paused", "ac_4")
	for _, p := range c.Policy {
		if p.Fallback != "" || p.Device != "" {
			t.Errorf("home policy %s uses new keys", p.Name)
		}
	}
}

// pauseEnv: pause state in a temp dir, a fixed clock, a fake neighbour table, reloads recorded.
func pauseEnv(t *testing.T, now *int64) (reloads *int) {
	t.Helper()
	d := t.TempDir()
	oldF, oldL, oldU, oldR, oldLd, oldN, oldCL, oldLF := pauseFile, pauseLock, pauseUptime, pauseReload, pauseLoaded, monNeighbours, ChangeLog, pauseLeaseFile
	t.Cleanup(func() {
		pauseFile, pauseLock, pauseUptime, pauseReload, pauseLoaded, monNeighbours, ChangeLog, pauseLeaseFile = oldF, oldL, oldU, oldR, oldLd, oldN, oldCL, oldLF
	})
	pauseFile, pauseLock, ChangeLog, pauseLeaseFile = filepath.Join(d, "pause.json"), filepath.Join(d, "pause.lock"), filepath.Join(d, "changes.log"), filepath.Join(d, "leases")
	os.WriteFile(pauseLeaseFile, []byte("1900000000 aa:bb:cc:00:00:23 192.168.1.140 console *\n"), 0644)
	pauseUptime = func() int64 { return *now }
	n := 0
	pauseReload = func(*Config) error { n++; return nil }
	pauseLoaded = func([]string) error { return nil }
	monNeighbours = func() ([]monNeigh, error) {
		return []monNeigh{
			{Addr: netip.MustParseAddr("192.168.1.121"), MAC: "aa:bb:cc:00:00:21"},
			{Addr: netip.MustParseAddr("2001:db8:1::21"), MAC: "aa:bb:cc:00:00:21"},
			{Addr: netip.MustParseAddr("fe80::21"), MAC: "aa:bb:cc:00:00:21"},
			{Addr: netip.MustParseAddr("192.168.1.99"), MAC: "02:00:00:00:99:99"}, // took over an old address
		}, nil
	}
	return &n
}

func TestPause(t *testing.T) {
	now := int64(1000)
	reloads := pauseEnv(t, &now)
	c := devConfig(t)
	c.defaults()

	for _, d := range []string{"0s", "8d", "90", "1x", "-1h", ""} {
		if _, err := pauseDuration(d); err == nil {
			t.Errorf("duration %q accepted", d)
		}
	}
	for d, want := range map[string]int64{"30m": 1800, "1h": 3600, "2h30m": 9000, "1d": 86400, "7d": 604800, "45s": 45} {
		if got, err := pauseDuration(d); err != nil || got != want {
			t.Errorf("duration %q = %d, %v", d, got, err)
		}
	}
	for _, bad := range []string{"nobody", "group:none", "01:00:5e:00:00:01", strings.Repeat("x", 80), "a\nb"} {
		if _, err := pauseTarget(c, bad); err == nil {
			t.Errorf("target %q accepted", bad)
		}
	}
	if m, err := pauseTarget(c, strings.ToUpper(c.DHCP.Hosts[0].Name)); err != nil || len(m) != 1 {
		t.Errorf("a dhcp.hosts name: %v %v", m, err)
	}

	if s := pauseScript(c); s != "" {
		t.Fatalf("nothing paused but a script: %s", s)
	}
	macs, err := pauseSet(c, "group:kids", 3600, "cli")
	if err != nil || strings.Join(macs, " ") != "aa:bb:cc:00:00:21 aa:bb:cc:00:00:22 aa:bb:cc:00:00:23" || *reloads != 1 {
		t.Fatalf("pause group:kids = %v, %v (%d reloads)", macs, err, *reloads)
	}
	now += 600
	if _, err := pauseSet(c, "02:00:00:00:99:99", 60, "web"); err != nil {
		t.Fatal(err)
	}
	s := pauseScript(c)
	mustContain(t, "pause script", s,
		"add set inet mr paused { type ether_addr; size 256; flags timeout; }",
		`insert rule inet mr forward iifname { "br-lan" } ether saddr @paused oifname { "pppoe-wan", "pppoe-wan2" } counter drop comment "pause"`,
		`insert rule inet mr forward iifname { "pppoe-wan", "pppoe-wan2" } ip daddr @paused_4 counter drop comment "pause"`,
		`insert rule inet mr forward iifname { "pppoe-wan", "pppoe-wan2" } ip6 daddr @paused_6 counter drop comment "pause"`,
		`insert rule inet mr input iifname { "br-lan" } ether saddr @paused fib daddr type != { local, broadcast, multicast, anycast } counter drop comment "pause"`,
		"add element inet mr paused { aa:bb:cc:00:00:21 timeout 3000s, aa:bb:cc:00:00:22 timeout 3000s, aa:bb:cc:00:00:23 timeout 3000s, 02:00:00:00:99:99 timeout 60s }",
		"192.168.1.121 timeout 3000s", "192.168.1.140 timeout 3000s", "192.168.1.99 timeout 60s",
		"add element inet mr paused_6 { 2001:db8:1::21 timeout 3000s }")
	mustNotContain(t, "pause script", s, "fe80::21")

	// an address another (not paused) device holds now is left alone
	monNeighbours = func() ([]monNeigh, error) {
		return []monNeigh{{Addr: netip.MustParseAddr("192.168.1.140"), MAC: "02:00:00:00:77:77"}}, nil
	}
	mustNotContain(t, "pause script", pauseScript(c), "192.168.1.140")

	l := pauseList(c)
	if len(l) != 4 || l[0].MAC != "02:00:00:00:99:99" || l[0].Left != 60 || l[1].Name != "kid-tablet" || l[1].Ref != "group:kids" || l[1].By != "cli" {
		t.Errorf("list = %+v", l)
	}
	st := map[string]any{}
	pauseStatus(c, st)
	if _, ok := st["paused"]; !ok {
		t.Error("status lacks the pauses")
	}

	// expiry: the 60 s one is gone, the kernel does the same on its own
	now += 61
	if l := pauseList(c); len(l) != 3 {
		t.Errorf("after 61 s: %+v", l)
	}
	// unpause one device of the group, then everything
	gone, err := pauseClear(c, "kid-tablet", "cli")
	if err != nil || len(gone) != 2 {
		t.Errorf("unpause kid-tablet = %v %v", gone, err)
	}
	if gone, _ := pauseClear(c, "office-pc", "cli"); len(gone) != 0 {
		t.Errorf("unpausing a device that is not paused: %v", gone)
	}
	r := *reloads
	if gone, err := pauseClear(c, "all", "cli"); err != nil || len(gone) != 1 || *reloads != r+1 {
		t.Errorf("unpause all = %v %v", gone, err)
	}
	if _, err := os.Stat(pauseFile); !os.IsNotExist(err) {
		t.Error("state file left behind with nothing paused")
	}
	st = map[string]any{}
	pauseStatus(c, st)
	if _, ok := st["paused"]; ok {
		t.Error("status shows pauses with nothing paused")
	}

	// a tampered state file renders nothing it should not
	os.WriteFile(pauseFile, []byte(`{"paused":[{"mac":"aa:bb:cc:00:00:21 } ; flush ruleset","until":99999},{"mac":"02:00:00:00:00:05","until":1700,"ips":["1.2.3.4; drop","192.168.1.5"]},{"mac":"02:00:00:00:00:06","until":999999999}]}`), 0600)
	s = pauseScript(c)
	mustNotContain(t, "tampered state", s, "flush", "1.2.3.4", "02:00:00:00:00:06")
	mustContain(t, "tampered state", s, "02:00:00:00:00:05 timeout", "192.168.1.5 timeout")
}

func TestPauseAPI(t *testing.T) {
	now := int64(5000)
	pauseEnv(t, &now)
	d := t.TempDir()
	y, _ := os.ReadFile("../examples/router.yaml")
	y = append(y, []byte("\ndevices:\n  - {name: kid-tablet, macs: [\"aa:bb:cc:00:00:21\"]}\n")...)
	os.WriteFile(filepath.Join(d, "router.yaml"), y, 0644)
	oldC, oldS := devConfigPath, devSecretsPath
	t.Cleanup(func() { devConfigPath, devSecretsPath = oldC, oldS })
	devConfigPath, devSecretsPath = filepath.Join(d, "router.yaml"), "testdata/secrets.yaml"

	var m *Module
	for _, x := range modules {
		if x.Name == "dev" {
			m = x
		}
	}
	call := func(action, method, body string) apiResp {
		return m.API[action](apiReq{method: method, action: action, body: []byte(body)})
	}
	if r := call("dev.pause", "GET", ""); r.status != 405 {
		t.Errorf("GET dev.pause: %d", r.status)
	}
	if r := call("dev.unpause", "GET", ""); r.status != 405 {
		t.Errorf("GET dev.unpause: %d", r.status)
	}
	for _, b := range []string{`{"target":"kid-tablet","duration":"9d"}`, `{"target":"nobody","duration":"1h"}`, `not json`} {
		if r := call("dev.pause", "POST", b); r.status != 400 {
			t.Errorf("POST dev.pause %s: %d", b, r.status)
		}
	}
	r := call("dev.pause", "POST", `{"target":"kid-tablet","duration":"1h"}`)
	if r.status != 0 {
		t.Fatalf("POST dev.pause: %d %v", r.status, r.body)
	}
	b, _ := json.Marshal(call("dev.paused", "GET", "").body)
	if !strings.Contains(string(b), `"mac":"aa:bb:cc:00:00:21","name":"kid-tablet","ref":"kid-tablet","by":"web","left":3600`) {
		t.Errorf("dev.paused = %s", b)
	}
	if log, _ := os.ReadFile(ChangeLog); !strings.Contains(string(log), "web: pause kid-tablet (aa:bb:cc:00:00:21) for 1h") {
		t.Errorf("change log: %s", log)
	}
	if r := call("dev.unpause", "POST", `{"target":"kid-tablet"}`); r.status != 0 {
		t.Errorf("POST dev.unpause: %d %v", r.status, r.body)
	}
	b, _ = json.Marshal(call("dev.paused", "GET", "").body)
	if string(b) != `{"paused":[]}` {
		t.Errorf("after unpause: %s", b)
	}
	// tokens: listing is read, pausing is operate
	for a, scope := range map[string]string{"dev.paused": "read", "dev.pause": "operate", "dev.unpause": "operate"} {
		if tokenActions[a] != scope {
			t.Errorf("tokenActions[%s] = %q, want %s", a, tokenActions[a], scope)
		}
	}
}
