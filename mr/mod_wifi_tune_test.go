package main

// Tests of the WiFi tuning of Cd1s/mini-router#41: multicast-to-unicast, 802.11v band steering
// (mod_wifi_steer.go), radio health and self-heal (mod_wifi_health.go).

import (
	"encoding/hex"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---- config, rendering, cron ----

func TestWifiTuneValidate(t *testing.T) {
	cases := []struct {
		edit func(c *Config)
		want string
	}{
		{func(c *Config) { c.WiFi.Steering.MinSignal2G = -20 }, "min_signal_2g: -90 to -30"},
		{func(c *Config) { c.WiFi.Steering.Exclude = []string{"aa:bb:cc:00:00:0z"} }, "exclude: invalid MAC"},
		{func(c *Config) { c.WiFi.Steering.Exclude = []string{"aa:bb:cc:00:00:01", "AA:BB:CC:00:00:01"} }, "listed twice"},
		{func(c *Config) { c.WiFi.Radios[0].SSIDs[2].Encryption = "sae-mixed" }, `SSID "MiniRouter-WPA3" differs between 2.4 and 5 GHz`},
		{func(c *Config) { c.WiFi.Radios[0].SSIDs[2].Network = "guest" }, "differs between"},
		{func(c *Config) { c.WiFi.Radios[0].SSIDs[2].SSID = "MiniRouter-Other" }, "no SSID is on both 2.4 and 5 GHz"},
		{func(c *Config) { c.WiFi.Radios = c.WiFi.Radios[:1] }, "needs a 2.4 GHz and a 5 GHz radio"},
	}
	for _, tc := range cases {
		c := wifiLabConfig(t)
		tc.edit(c)
		if errs := strings.Join(c.Validate(), "\n"); !strings.Contains(errs, tc.want) {
			t.Errorf("want error containing %q, got:\n%s", tc.want, errs)
		}
	}
	// the home config has different SSID names per band: steering has nothing to work on
	c := testConfig(t)
	c.WiFi.Steering.Enabled = true
	c.defaults()
	if errs := strings.Join(c.Validate(), "\n"); !strings.Contains(errs, "no SSID is on both") {
		t.Errorf("home + steering: %s", errs)
	}
	// off: the same names do not matter, nothing is rendered
	c = wifiLabConfig(t)
	c.WiFi.Steering.Enabled = false
	c.WiFi.Radios[0].SSIDs[2].Encryption = "sae-mixed"
	if errs := c.Validate(); len(errs) > 0 {
		t.Errorf("steering off: %v", errs)
	}
	if strings.Contains(renderMap(t, c)["/etc/hostapd/hostapd-phy0.conf"], "bss_transition=") {
		t.Error("bss_transition rendered with steering off")
	}
}

func TestWifiTuneDefaults(t *testing.T) {
	c := testConfig(t)
	if c.WiFi.Steering.MinSignal2G != 0 || c.WiFi.SelfHeal || len(wifiCronLine(c)) != 0 || cronWanted(c) {
		t.Errorf("home config: steering %+v self_heal %v cron %v", c.WiFi.Steering, c.WiFi.SelfHeal, wifiCronLine(c))
	}
	c = wifiLabConfig(t)
	if c.WiFi.Steering.MinSignal2G != -65 || c.WiFi.Steering.Exclude[0] != "aa:bb:cc:00:00:09" {
		t.Errorf("lab steering: %+v", c.WiFi.Steering)
	}
	c.WiFi.Steering.MinSignal2G = 0
	c.defaults()
	if c.WiFi.Steering.MinSignal2G != steerMinSignal {
		t.Errorf("default min signal: %d", c.WiFi.Steering.MinSignal2G)
	}
	cr := strings.Join(renderCronLines(c), "\n")
	if !strings.Contains(cr, "\n* * * * * "+mrBin+" wifi tick") || !cronWanted(c) {
		t.Errorf("lab crontab:\n%s", cr)
	}
	c.WiFi.Steering.Enabled = false // self-heal alone needs the tick too
	if len(wifiCronLine(c)) != 2 {
		t.Error("self_heal without steering: no tick")
	}
	c.WiFi.SelfHeal = false
	if len(wifiCronLine(c)) != 0 {
		t.Error("tick without steering or self-heal")
	}
}

// bssSection: the lines of one BSS (interface= / bss= up to the next one).
func bssSection(conf, ifname string) string {
	var b strings.Builder
	in := false
	for _, l := range strings.Split(conf, "\n") {
		if strings.HasPrefix(l, "interface=") || strings.HasPrefix(l, "bss=") {
			in = strings.HasSuffix(l, "="+ifname)
		}
		if in {
			b.WriteString(l + "\n")
		}
	}
	return b.String()
}

func TestWifiTuneRender(t *testing.T) {
	c := wifiLabConfig(t)
	got := renderMap(t, c)
	p0, p1 := got["/etc/hostapd/hostapd-phy0.conf"], got["/etc/hostapd/hostapd-phy1.conf"]
	for _, tc := range []struct {
		conf, ifname string
		want, not    []string
	}{
		{p0, "phy0-ap0-2", []string{"ssid2=" + hex.EncodeToString([]byte("MiniRouter-WPA3")), "multicast_to_unicast=1\n", "bss_transition=1\nrrm_neighbor_report=1\n"}, nil},
		{p1, "phy1-ap0-1", []string{"bss_transition=1\nrrm_neighbor_report=1\n"}, []string{"multicast_to_unicast="}},
		{p1, "phy1-ap0", []string{"multicast_to_unicast=1\n"}, []string{"bss_transition="}},
		{p0, "phy0-ap0", nil, []string{"multicast_to_unicast=", "bss_transition=", "rrm_neighbor_report="}},
		{p1, "phy1-ap0-3", nil, []string{"multicast_to_unicast=", "bss_transition="}},
	} {
		sec := bssSection(tc.conf, tc.ifname)
		for _, w := range tc.want {
			if !strings.Contains(sec, w) {
				t.Errorf("%s: missing %q in\n%s", tc.ifname, w, sec)
			}
		}
		for _, n := range tc.not {
			if strings.Contains(sec, n) {
				t.Errorf("%s: unexpected %q", tc.ifname, n)
			}
		}
	}
	if p := steerPairs(c); len(p) != 1 || p[0] != (steerPair{SSID: "MiniRouter-WPA3", From: "phy0-ap0-2", To: "phy1-ap0-1", FromPhy: "phy0", ToPhy: "phy1"}) {
		t.Errorf("pairs: %+v", p)
	}
	if tokenActions["wifi.health"] != "read" {
		t.Error("wifi.health must be a read action for tokens")
	}
}

// ---- hostapd parsing ----

func TestHapdStaParse(t *testing.T) {
	s, ok := parseHapdSta("02:00:00:00:00:0A\nflags=[AUTH][ASSOC][AUTHORIZED][WMM][MFP][HT][VHT]\naid=1\nsignal=-61\n" +
		"connected_time=6781\nsupp_op_classes=81515354737475767778797a7b7c7d7e7f8082\next_capab=01000a0200400040\n")
	if !ok || s.MAC != "02:00:00:00:00:0a" || s.Signal != -61 || s.Connected != 6781 || !s.btm() || s.has5g() != 1 {
		t.Errorf("parsed %+v btm %v 5g %d", s, s.btm(), s.has5g())
	}
	for _, tc := range []struct {
		ext, ops string
		btm      bool
		five     int
	}{
		{"0100020200400040", "5151535454", false, 0}, // no BSS transition bit; 2.4 GHz classes only
		{"01", "", false, -1},                        // too short; no op classes announced
		{"0000080000", "5151827376", true, 0},        // 130 ends the list: what follows is not a class
		{"", "7373", false, 1},
	} {
		st := hapdSta{}
		st.ExtCapab, _ = hex.DecodeString(tc.ext)
		st.OpClasses, _ = hex.DecodeString(tc.ops)
		if st.btm() != tc.btm || st.has5g() != tc.five {
			t.Errorf("ext %s ops %s: btm %v 5g %d", tc.ext, tc.ops, st.btm(), st.has5g())
		}
	}
	for _, bad := range []string{"", "FAIL\n", "UNKNOWN COMMAND\n", "02:00:00:00:00;0a\n"} {
		if _, ok := parseHapdSta(bad); ok {
			t.Errorf("parsed %q as a station", bad)
		}
	}
}

// nr5 is the own neighbor report of a 5 GHz BSS as hostapd builds it: BSSID, BSSID information
// (0x198f LE), operating class 128, channel 36, PHY type 9, wide bandwidth channel subelement (80 MHz, 42).
const nr5 = "020000000101" + "8f190000" + "80" + "24" + "09" + "0603012a00"

func TestNeighborReport(t *testing.T) {
	cand, err := nrCandidate(nr5)
	if err != nil || cand != "02:00:00:00:01:01,0x0000198f,128,36,9,0603012a000301ff" {
		t.Errorf("candidate %q %v", cand, err)
	}
	for _, bad := range []string{"", "0200", "zz" + nr5[2:]} {
		if _, err := nrCandidate(bad); err == nil {
			t.Errorf("nrCandidate(%q) accepted", bad)
		}
	}
	m := parseNeighbors("02:00:00:00:01:01 ssid=43687669 nr=" + nr5 + " stat\n02:00:00:00:00:12 ssid=41 nr=0200;x\nFAIL\n")
	if m["02:00:00:00:01:01"] != (nrEntry{SSID: "43687669", NR: nr5}) || m["02:00:00:00:00:12"].NR != "" {
		t.Errorf("neighbors %+v", m)
	}
	code, target, ok := parseBTMResp("<3>BSS-TM-RESP 02:00:00:00:00:0A status_code=0 bss_termination_delay=0 target_bssid=02:00:00:00:01:01", "02:00:00:00:00:0a")
	if !ok || code != 0 || target != "02:00:00:00:01:01" {
		t.Errorf("resp %d %q %v", code, target, ok)
	}
	if _, _, ok := parseBTMResp("<3>BSS-TM-RESP 02:00:00:00:00:0b status_code=7", "02:00:00:00:00:0a"); ok {
		t.Error("answer of another station taken")
	}
	if code, _, ok := parseBTMResp("<3>BSS-TM-RESP 02:00:00:00:00:0a status_code=7 bss_termination_delay=0", "02:00:00:00:00:0a"); !ok || code != 7 {
		t.Error("decline without target")
	}
}

func TestSteerWhy(t *testing.T) {
	const now = 1_800_000_000
	good := hapdSta{MAC: "02:00:00:00:00:0a", Flags: "[AUTH][ASSOC][AUTHORIZED]", Signal: -50, Connected: 300, ExtCapab: []byte{0, 0, 8}, OpClasses: []byte{81, 81, 115}}
	conf := Steering{Enabled: true, MinSignal2G: -60, Exclude: []string{"02:00:00:00:00:99"}}
	mod := func(f func(s *hapdSta)) hapdSta { s := good; f(&s); return s }
	for _, tc := range []struct {
		s    hapdSta
		e    *steerSta
		want string
	}{
		{good, nil, ""},
		{mod(func(s *hapdSta) { s.MAC = "02:00:00:00:00:99" }), nil, "excluded"},
		{mod(func(s *hapdSta) { s.Flags = "[AUTH][ASSOC]" }), nil, "not authorized"},
		{mod(func(s *hapdSta) { s.ExtCapab = []byte{0, 0, 2} }), nil, "no 802.11v"},
		{mod(func(s *hapdSta) { s.OpClasses = []byte{81, 81, 83} }), nil, "no 5 GHz"},
		{mod(func(s *hapdSta) { s.OpClasses = nil }), nil, ""}, // unknown: ask (it may decline)
		{mod(func(s *hapdSta) { s.Signal = -61 }), nil, "below -60"},
		{mod(func(s *hapdSta) { s.Signal = 0 }), nil, "signal unknown"},
		{mod(func(s *hapdSta) { s.Connected = 30 }), nil, "less than a minute"},
		{good, &steerSta{First: now - 3600, N: 3, Last: now - 3500, Result: "accepted"}, "asked 3 times"},
		{good, &steerSta{First: now - 90000, N: 3, Last: now - 90000, Result: "accepted"}, ""}, // window over
		{good, &steerSta{First: now - 7200, N: 1, Last: now - 7200, Result: "rejected"}, "declined recently"},
		{good, &steerSta{First: now - 600, N: 1, Last: now - 600, Result: "noreply"}, "asked recently"},
		{good, &steerSta{First: now - 1900, N: 1, Last: now - 1900, Result: "noreply"}, ""},
	} {
		if got := steerWhy(tc.s, tc.e, conf, now); tc.want == "" && got != "" || tc.want != "" && !strings.Contains(got, tc.want) {
			t.Errorf("%+v %+v: %q, want %q", tc.s, tc.e, got, tc.want)
		}
	}
}

// ---- steering against fake hostapd BSSes ----

// fakeHapd answers like hostapd's control socket; one request may get several datagrams (replies and
// events, as an attached monitor sees them).
func fakeHapd(t *testing.T, dir, ifname string, reply func(cmd string) []string) {
	t.Helper()
	c, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: filepath.Join(dir, ifname), Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	go func() {
		buf := make([]byte, 4096)
		for {
			n, from, err := c.ReadFromUnix(buf)
			if err != nil {
				return
			}
			for _, r := range reply(string(buf[:n])) {
				c.WriteToUnix([]byte(r), from)
			}
		}
	}()
}

// steerEnv: temp state file, fake clock, fake 2.4 GHz BSS phy0-ap0-2 with stations and fake 5 GHz BSS
// phy1-ap0-1 of the lab's MiniRouter-WPA3. answer: the BSS-TM-RESP status the 2.4 GHz BSS sends (-1: none).
type steerEnv struct {
	mu     sync.Mutex
	cmds   []string // every command, "ifname: cmd"
	now    time.Time
	answer int
	on5    map[string]bool // stations the 5 GHz BSS reports
	nb2    string          // SHOW_NEIGHBOR of the 2.4 GHz BSS
}

func (e *steerEnv) get() int { e.mu.Lock(); defer e.mu.Unlock(); return e.answer }

func (e *steerEnv) set(answer int, on5 string, dt time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.answer, e.now = answer, e.now.Add(dt)
	if on5 != "" {
		e.on5[on5] = true
	}
}

func (e *steerEnv) log(ifn, cmd string) {
	e.mu.Lock()
	e.cmds = append(e.cmds, ifn+": "+cmd)
	e.mu.Unlock()
}

func (e *steerEnv) sent(prefix string) []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []string
	for _, c := range e.cmds {
		if strings.HasPrefix(c, prefix) {
			out = append(out, c)
		}
	}
	return out
}

const nr2 = "020000000012" + "8f090000" + "51" + "06" + "07"

var steerStas = []string{
	"02:00:00:00:00:0a\nflags=[AUTH][ASSOC][AUTHORIZED][WMM][MFP][HT][HE]\nsignal=-50\nconnected_time=300\next_capab=01000a0200400040\nsupp_op_classes=5151537374\n",
	"02:00:00:00:00:0b\nflags=[AUTH][ASSOC][AUTHORIZED]\nsignal=-80\nconnected_time=300\next_capab=01000a0200400040\n",                 // weak
	"02:00:00:00:00:0c\nflags=[AUTH][ASSOC][AUTHORIZED]\nsignal=-40\nconnected_time=300\next_capab=0100020200400040\n",                 // no 802.11v
	"aa:bb:cc:00:00:09\nflags=[AUTH][ASSOC][AUTHORIZED]\nsignal=-40\nconnected_time=300\next_capab=01000a0200400040\n",                 // excluded
	"02:00:00:00:00:0e\nflags=[AUTH][ASSOC][AUTHORIZED]\nsignal=-45\nconnected_time=900\next_capab=01000a02\nsupp_op_classes=515153\n", // 2.4 GHz only
}

func newSteerEnv(t *testing.T) (*steerEnv, map[string]radioOp) {
	t.Helper()
	dir := t.TempDir()
	e := &steerEnv{now: time.Unix(1_800_000_000, 0), answer: 0, on5: map[string]bool{}, nb2: "02:00:00:00:00:12 ssid=00 nr=" + nr2 + "\n"}
	oDir, oFile, oNow, oWait := hostapdCtrlDir, wifiSteerFile, wifiNow, steerWait
	t.Cleanup(func() { hostapdCtrlDir, wifiSteerFile, wifiNow, steerWait = oDir, oFile, oNow, oWait })
	hostapdCtrlDir, wifiSteerFile = dir, filepath.Join(t.TempDir(), "wifi-steer.json")
	wifiNow = func() time.Time { e.mu.Lock(); defer e.mu.Unlock(); return e.now }
	steerWait = 300 * time.Millisecond
	fakeHapd(t, dir, "phy0-ap0-2", func(cmd string) []string {
		e.log("phy0-ap0-2", cmd)
		switch {
		case cmd == "SHOW_NEIGHBOR":
			e.mu.Lock()
			defer e.mu.Unlock()
			return []string{e.nb2}
		case strings.HasPrefix(cmd, "SET_NEIGHBOR "):
			f := strings.Fields(cmd)
			e.mu.Lock()
			e.nb2 += f[1] + " " + f[2] + " " + f[3] + "\n"
			e.mu.Unlock()
			return []string{"OK\n"}
		case cmd == "STA-FIRST":
			return []string{steerStas[0]}
		case strings.HasPrefix(cmd, "STA-NEXT "):
			for i, s := range steerStas {
				if strings.HasPrefix(s, strings.TrimPrefix(cmd, "STA-NEXT ")) {
					if i+1 < len(steerStas) {
						return []string{steerStas[i+1]}
					}
					return []string{""}
				}
			}
			return []string{"FAIL\n"}
		case cmd == "ATTACH", cmd == "DETACH":
			return []string{"OK\n"}
		case strings.HasPrefix(cmd, "BSS_TM_REQ "):
			mac := strings.Fields(cmd)[1]
			out := []string{"OK\n"}
			if a := e.get(); a >= 0 {
				out = append(out, "<3>BSS-TM-RESP 02:00:00:00:00:0b status_code=0", // another station: ignored
					"<3>BSS-TM-RESP "+mac+" status_code="+strconv.Itoa(a)+" bss_termination_delay=0")
			}
			return out
		}
		return []string{"UNKNOWN COMMAND\n"}
	})
	fakeHapd(t, dir, "phy1-ap0-1", func(cmd string) []string {
		e.log("phy1-ap0-1", cmd)
		switch {
		case cmd == "SHOW_NEIGHBOR":
			return []string{"02:00:00:00:01:01 ssid=4d696e69526f757465722d57504133 nr=" + nr5 + " stat\n"}
		case strings.HasPrefix(cmd, "SET_NEIGHBOR "):
			return []string{"OK\n"}
		case strings.HasPrefix(cmd, "STA "):
			mac := strings.TrimPrefix(cmd, "STA ")
			e.mu.Lock()
			defer e.mu.Unlock()
			if e.on5[mac] {
				return []string{mac + "\nflags=[AUTH][ASSOC][AUTHORIZED]\n"}
			}
			return []string{"FAIL\n"}
		}
		return []string{"UNKNOWN COMMAND\n"}
	})
	ops := map[string]radioOp{
		"phy0": {State: "ENABLED", BSS: []opBSS{{Ifname: "phy0-ap0"}, {Ifname: "phy0-ap0-1"}, {Ifname: "phy0-ap0-2", BSSID: "02:00:00:00:00:12", Clients: 5}}},
		"phy1": {State: "ENABLED", BSS: []opBSS{{Ifname: "phy1-ap0"}, {Ifname: "phy1-ap0-1", BSSID: "02:00:00:00:01:01"}}},
	}
	return e, ops
}

func decisionsByMAC(ds []steerDecision) map[string]steerDecision {
	m := map[string]steerDecision{}
	for _, d := range ds {
		m[d.MAC] = d
	}
	return m
}

func TestSteerPass(t *testing.T) {
	e, ops := newSteerEnv(t)
	c := wifiLabConfig(t)

	// dry run: decisions, nothing sent, no state
	d := decisionsByMAC(steerPass(c, ops, true))
	if !d["02:00:00:00:00:0a"].Steer || d["02:00:00:00:00:0a"].Result != "" || len(e.sent("phy0-ap0-2: BSS_TM_REQ")) != 0 || len(e.sent("phy0-ap0-2: SET_NEIGHBOR")) != 0 {
		t.Fatalf("dry run: %+v %v", d, e.cmds)
	}
	if _, err := os.Stat(wifiSteerFile); err == nil {
		t.Error("dry run wrote state")
	}
	for mac, want := range map[string]string{"02:00:00:00:00:0b": "below -65", "02:00:00:00:00:0c": "no 802.11v", "aa:bb:cc:00:00:09": "excluded", "02:00:00:00:00:0e": "no 5 GHz"} {
		if x := d[mac]; x.Steer || !strings.Contains(x.Why, want) || x.To != "phy1-ap0-1" || x.SSID != "MiniRouter-WPA3" {
			t.Errorf("%s: %+v, want %q", mac, x, want)
		}
	}

	// real run: one request with the 5 GHz BSS as the only (preferred) candidate, the answer awaited
	d = decisionsByMAC(steerPass(c, ops, false))
	if r := d["02:00:00:00:00:0a"].Result; r != "accepted" {
		t.Errorf("result %q", r)
	}
	req := e.sent("phy0-ap0-2: BSS_TM_REQ")
	want := "phy0-ap0-2: BSS_TM_REQ 02:00:00:00:00:0a pref=1 abridged=1 valid_int=200 dialog_token=1 neighbor=02:00:00:00:01:01,0x0000198f,128,36,9,0603012a000301ff"
	if len(req) != 1 || req[0] != want {
		t.Errorf("requests %q\nwant %q", req, want)
	}
	if strings.Contains(strings.Join(req, ""), "disassoc_imminent") {
		t.Error("steering must never force a disassociation")
	}
	if at, de := e.sent("phy0-ap0-2: ATTACH"), e.sent("phy0-ap0-2: DETACH"); len(at) != 1 || len(de) != 1 {
		t.Errorf("attach %d detach %d", len(at), len(de))
	}
	// neighbor lists: 5 GHz's own report into the 2.4 GHz BSS and the other way round, once
	if s := e.sent("phy0-ap0-2: SET_NEIGHBOR"); len(s) != 1 || s[0] != "phy0-ap0-2: SET_NEIGHBOR 02:00:00:00:01:01 ssid=4d696e69526f757465722d57504133 nr="+nr5 {
		t.Errorf("SET_NEIGHBOR on 2.4 GHz: %q", s)
	}
	if s := e.sent("phy1-ap0-1: SET_NEIGHBOR"); len(s) != 1 || s[0] != "phy1-ap0-1: SET_NEIGHBOR 02:00:00:00:00:12 ssid=00 nr="+nr2 {
		t.Errorf("SET_NEIGHBOR on 5 GHz: %q", s)
	}

	// a minute later: the station is on 5 GHz now; it is not asked again; the neighbor entry stays
	e.set(0, "02:00:00:00:00:0a", time.Minute)
	d = decisionsByMAC(steerPass(c, ops, false))
	if x := d["02:00:00:00:00:0a"]; x.Steer || x.Why != "asked recently" {
		t.Errorf("second run: %+v", x)
	}
	if len(e.sent("phy0-ap0-2: BSS_TM_REQ")) != 1 || len(e.sent("phy0-ap0-2: SET_NEIGHBOR")) != 1 {
		t.Error("asked twice, or the neighbor entry was set again")
	}
	st := loadSteerState()
	if st.Count["sent"] != 1 || st.Count["accepted"] != 1 || st.Count["moved"] != 1 || len(st.Recent) != 1 || !st.Recent[0].Moved || st.Recent[0].Signal != -50 {
		t.Errorf("state %+v %+v", st.Count, st.Recent)
	}

	// a decline holds the station 4 h; no answer only the 30 min cooldown
	e.set(7, "", 31*time.Minute)
	d = decisionsByMAC(steerPass(c, ops, false))
	if r := d["02:00:00:00:00:0a"].Result; r != "declined (status 7)" {
		t.Errorf("decline: %q", r)
	}
	e.set(7, "", 31*time.Minute)
	if x := decisionsByMAC(steerPass(c, ops, false))["02:00:00:00:00:0a"]; x.Why != "declined recently" {
		t.Errorf("after a decline: %+v", x)
	}
	e.set(-1, "", 4*time.Hour)
	start := time.Now()
	if r := decisionsByMAC(steerPass(c, ops, false))["02:00:00:00:00:0a"].Result; r != "no answer" || time.Since(start) > 2*time.Second {
		t.Errorf("no answer: %q after %s", r, time.Since(start))
	}
	e.set(-1, "", 31*time.Minute)
	if x := decisionsByMAC(steerPass(c, ops, false))["02:00:00:00:00:0a"]; x.Why != "asked 3 times in 24 h" {
		t.Errorf("fourth time: %+v", x)
	}
	st = loadSteerState()
	if st.Count["sent"] != 3 || st.Count["rejected"] != 1 || st.Count["noreply"] != 1 || st.Token != 3 {
		t.Errorf("counts %+v token %d", st.Count, st.Token)
	}
	if x := st.Dev["02:00:00:00:00:0a"]; x == nil || x.Accepted != 1 || x.Rejected != 1 || x.NoReply != 1 || x.Moved != 1 {
		t.Errorf("per device: %+v", x)
	}

	// 5 GHz radio in its radar check, or hostapd not answering: nothing is asked
	ops["phy1"] = radioOp{State: "DFS", BSS: ops["phy1"].BSS}
	if ds := steerPass(c, ops, false); len(ds) != 1 || ds[0].MAC != "" || ds[0].Why != "5 GHz radio is DFS" {
		t.Errorf("DFS: %+v", ds)
	}
	delete(ops, "phy1")
	if ds := steerPass(c, ops, false); len(ds) != 1 || !strings.Contains(ds[0].Why, "not answering") {
		t.Errorf("down: %+v", ds)
	}
}

// ---- health ----

// healthFS: fake sysfs / debugfs / hwmon for the lab's two radios (kernel phy0 / phy1 on one chip).
func healthFS(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	o := []string{wifiDebugfs, wifiSysNet, wifiSysPhy, wifiHwmonDir, wifiHealthFile, wifiTickLock}
	t.Cleanup(func() {
		wifiDebugfs, wifiSysNet, wifiSysPhy, wifiHwmonDir, wifiHealthFile, wifiTickLock = o[0], o[1], o[2], o[3], o[4], o[5]
	})
	wifiDebugfs, wifiSysNet, wifiSysPhy, wifiHwmonDir = filepath.Join(d, "debug"), filepath.Join(d, "net"), filepath.Join(d, "ieee80211"), filepath.Join(d, "hwmon")
	wifiHealthFile, wifiTickLock = filepath.Join(d, "run", "wifi-health.json"), filepath.Join(d, "run", "wifi.tick")
	w := func(p, s string) {
		os.MkdirAll(filepath.Dir(p), 0755)
		if err := os.WriteFile(p, []byte(s), 0644); err != nil {
			t.Fatal(err)
		}
	}
	os.MkdirAll(filepath.Join(d, "chip"), 0755)
	for i, p := range []string{"phy0", "phy1"} {
		w(filepath.Join(wifiSysNet, p+"-ap0", "phy80211", "name"), p+"\n")
		os.MkdirAll(filepath.Join(wifiSysPhy, p), 0755)
		os.Symlink(filepath.Join(d, "chip"), filepath.Join(wifiSysPhy, p, "device"))
		mt := filepath.Join(wifiDebugfs, p, "mt76")
		w(filepath.Join(mt, "tx_stats"), txStatsSample(1000))
		w(filepath.Join(mt, "vow_atf"), "1\n")
		w(filepath.Join(mt, "sys_recovery"), "Please echo the correct value ...\n0: grab firmware transient SER state\n\nSYS_RESET_COUNT: WM 0, WA 0\n")
		w(filepath.Join(mt, "fw_util_wm"), "Program counter: 0x801e0c\n")
		hw := filepath.Join(wifiHwmonDir, "hwmon"+strconv.Itoa(i+1))
		w(filepath.Join(hw, "name"), "mt7915_"+p+"\n")
		w(filepath.Join(hw, "temp1_input"), "53000\n")
		w(filepath.Join(hw, "temp1_crit"), "110000\n")
		w(filepath.Join(hw, "throttle1"), "100\n")
	}
	w(filepath.Join(wifiHwmonDir, "hwmon0", "name"), "cpu_thermal\n")
	return d
}

// txStatsSample: an mt76 tx_stats as the router prints it, with su acknowledged MPDUs.
func txStatsSample(su int64) string {
	return "\nPhy 1, Phy band 1\nLength:        1 |   2 - 10 |\nCount:   3579410 |   472381 |\nBA miss count: 123485\n\n" +
		"Tx Beamformer applied PPDU counts: iBF: 0, eBF: 4063485\nTx multi-user MPDU counts: 9536\n" +
		"Tx multi-user successful MPDU counts: 1646\nTx single-user successful MPDU counts: " + strconv.FormatInt(su, 10) + "\n\n" +
		"Tx MSDU statistics:\nAMSDU pack count of 1 MSDU in TXD:  1775077 ( 60%)\n"
}

func TestHealthParse(t *testing.T) {
	if n, ok := parseTxAcked(txStatsSample(6027338)); !ok || n != 6027338+1646 {
		t.Errorf("tx acked %d %v", n, ok)
	}
	if n, ok := parseTxAcked(txStatsSample(-5)); !ok || n != uint32(1646-5) { // a u32 printed with %d past 2^31
		t.Errorf("wrapped: %d", n)
	}
	if _, ok := parseTxAcked("Program counter: 0x1\n"); ok {
		t.Error("counter from nothing")
	}
	if n := parseFwResets("x\nSYS_RESET_COUNT: WM 1, WA 2\n"); n != 3 {
		t.Errorf("resets %d", n)
	}
	for _, s := range []string{"", "SYS_RESET_COUNT: WM x, WA 2"} {
		if parseFwResets(s) != -1 {
			t.Errorf("resets of %q", s)
		}
	}
	if parseFwBusy("Program counter: 0x801e0c\n") != -1 || parseFwBusy("Program counter: 0x1\nBusy: 12%  Peak busy: 40%\n") != 12 {
		t.Error("fw busy")
	}
	if tx, rx := parseAirtime("RX: 499141 us\nTX: 279777 us\nWeight: 256\nDeficit: VO: 2018 us VI: 256 us\n"); tx != 279777 || rx != 499141 {
		t.Errorf("airtime %d %d", tx, rx)
	}
}

func TestReadRadioHealth(t *testing.T) {
	healthFS(t)
	c := wifiLabConfig(t)
	h := readRadioHealth(c.WiFi.Radios[1], radioOp{State: "ENABLED", BSS: []opBSS{{Clients: 2}, {Clients: 1}}}, true)
	if h.KPhy != "phy1" || h.Stations != 3 || h.TempC != 53 || h.CritC != 110 || h.TxDuty != 100 || !h.HasTx || h.TxAcked != 2646 ||
		h.ATF != "on" || !h.SER || h.FwResets != 0 || h.FwBusy != -1 || h.State != "ENABLED" {
		t.Errorf("health %+v", h)
	}
	if f := wifiHealthFindings(c, []radioHealth{h}); len(f) != 1 || f[0].Sev != "ok" || f[0].ID != "wifi.health.phy1" || !strings.Contains(f[0].Detail, "53 °C") {
		t.Errorf("findings %+v", f)
	}
	// throttled, ATF off, a firmware restart, TX stalled; given up = risk; no ATF anywhere = a skip
	h2 := h
	h2.TxDuty, h2.ATF, h2.FwResets, h2.StalledS = 60, "off", 1, 700
	f := wifiHealthFindings(c, []radioHealth{h2})
	if len(f) != 1 || f[0].Sev != "warn" || !strings.Contains(f[0].Detail, "TX duty 60 %") || !strings.Contains(f[0].Detail, "airtime fairness is off") ||
		!strings.Contains(f[0].Detail, "firmware restarted 1") || !strings.Contains(f[0].Detail, "no acknowledged TX for") {
		t.Errorf("warn findings %+v", f)
	}
	h2.Stage, h2.ATF = "failed", "absent"
	f = wifiHealthFindings(c, []radioHealth{h2, {Phy: "phy0"}})
	if len(f) != 2 || f[0].Sev != "risk" || f[1].ID != "wifi.atf" || f[1].Sev != "skip" {
		t.Errorf("risk findings %+v", f)
	}
	// the doctor's wifi check carries them
	e := fakeDocEnv()
	e.wifiRadio = func(*Config) []docFinding { return wifiHealthFindings(c, []radioHealth{h}) }
	if out := docWiFi(c, e); len(out) != 2 || out[1].ID != "wifi.health.phy1" {
		t.Errorf("doctor: %+v", out)
	}
	// no AP netdev: nothing but defaults, no finding
	os.RemoveAll(wifiSysNet)
	if h := readRadioHealth(c.WiFi.Radios[1], radioOp{}, false); h.KPhy != "" || h.HasTx || h.FwResets != -1 || h.ATF != "absent" {
		t.Errorf("no netdev: %+v", h)
	}
}

func TestHealStep(t *testing.T) {
	const t0 = 1_800_000_000
	var h healState
	step := func(dt int64, tx uint32, sta int, want string) {
		t.Helper()
		var act string
		h, act = healStep(h, t0+dt, "phy1", sta, tx, true, true)
		if act != want {
			t.Fatalf("t+%d tx %d sta %d: %q, want %q (state %+v)", dt, tx, sta, act, want, h)
		}
	}
	step(0, 100, 3, "")
	for dt := int64(60); dt < 600; dt += 60 {
		step(dt, 100, 3, "") // stalled, not yet 10 minutes
	}
	step(600, 100, 3, "ser")
	for dt := int64(660); dt < 1200; dt += 60 {
		step(dt, 100, 3, "")
	}
	step(1200, 100, 3, "restart")
	step(1800, 100, 3, "") // a gap of 10 min: new baseline, no action (and no loss of the stage)
	step(1860, 100, 3, "") // stalled again, but only a minute
	step(2400, 100, 3, "") // gap again
	for dt := int64(2460); dt < 3000; dt += 60 {
		step(dt, 100, 3, "")
	}
	step(3000, 100, 3, "failed")
	step(3060, 100, 3, "")
	step(3120, 101, 3, "recovered") // TX moves: back to normal
	if h.Stage != 0 || len(h.Acts) != 4 {
		t.Errorf("state %+v", h)
	}
	// no stations: never stalled; a moving counter: never stalled
	h = healState{}
	for dt := int64(0); dt < 3600; dt += 60 {
		step(dt, 5, 0, "")
	}
	for dt := int64(3600); dt < 7200; dt += 60 {
		step(dt, uint32(dt), 4, "")
	}
	// the counter wraps (u32): still moving
	h = healState{KPhy: "phy1", T: t0, TX: 4294967295, Sta: 3, Moved: t0}
	step(60, 3, 3, "")
	// another phy (driver reloaded) or no counter: new baseline
	h = healState{KPhy: "phy0", T: t0, TX: 1, Sta: 3, Moved: t0 - 3600}
	step(60, 1, 3, "")
	if h.KPhy != "phy1" || h.Moved != t0+60 {
		t.Errorf("baseline %+v", h)
	}
	// no firmware recovery available: straight to the hostapd restart
	h = healState{KPhy: "phy1", T: t0, TX: 1, Sta: 3, Moved: t0 - 540}
	h, act := healStep(h, t0+60, "phy1", 3, 1, true, false)
	if act != "restart" || h.Stage != 2 {
		t.Errorf("no SER: %q %+v", act, h)
	}
	// the 24 h budget
	h = healState{KPhy: "phy1", T: t0, TX: 1, Sta: 3, Moved: t0 - 540}
	for i := int64(0); i < healDayMax; i++ {
		h.Acts = append(h.Acts, healAction{T: t0 - 3600*(i+1), Action: "ser"})
	}
	if h, act = healStep(h, t0+60, "phy1", 3, 1, true, true); act != "failed" || !strings.Contains(h.Acts[len(h.Acts)-1].Detail, "limit") {
		t.Errorf("budget: %q %+v", act, h.Acts)
	}
}

func TestHealPass(t *testing.T) {
	d := healthFS(t)
	_, now, _, _ := eventEnv(t)
	oNow, oRestart, oPending, oDir := wifiNow, wifiRestartHostapd, wifiPending, hostapdCtrlDir
	t.Cleanup(func() { wifiNow, wifiRestartHostapd, wifiPending, hostapdCtrlDir = oNow, oRestart, oPending, oDir })
	wifiNow = func() time.Time { return *now }
	restarts := 0
	wifiRestartHostapd = func() error { restarts++; return nil }
	pending := errors.New("a change waits for confirmation")
	wifiPending = func() error { return nil }
	c := wifiLabConfig(t)
	ops := map[string]radioOp{
		"phy0": {State: "ENABLED", BSS: []opBSS{{Ifname: "phy0-ap0", Clients: 2}}},
		"phy1": {State: "ENABLED", BSS: []opBSS{{Ifname: "phy1-ap0", Clients: 3}}},
	}
	var moving int64 // > 0: phy1's counter advances every minute
	tick := func(n int) {
		for i := 0; i < n; i++ {
			*now = now.Add(time.Minute)
			if moving > 0 {
				moving += 10
				os.WriteFile(filepath.Join(d, "debug", "phy1", "mt76", "tx_stats"), []byte(txStatsSample(moving)), 0644)
			}
			healPass(c, ops)
		}
	}
	tick(1) // baseline
	wifiPending = func() error { return pending }
	tick(10) // stalled 10 min, but a change waits: nothing done
	sr := filepath.Join(d, "debug", "phy0", "mt76", "sys_recovery")
	if b, _ := os.ReadFile(sr); strings.HasPrefix(string(b), serFull+"\n") || len(eventsRead(0, 100)) != 0 {
		t.Fatal("acted while a change waits for confirmation")
	}
	wifiPending = func() error { return nil }
	tick(1)
	// both radios stalled: one firmware recovery for the chip (both bands share it)
	b0, _ := os.ReadFile(sr)
	b1, _ := os.ReadFile(filepath.Join(d, "debug", "phy1", "mt76", "sys_recovery"))
	if !strings.HasPrefix(string(b0), serFull+"\n") || strings.HasPrefix(string(b1), serFull+"\n") {
		t.Errorf("sys_recovery: phy0 %q phy1 %q", b0[:12], b1[:12])
	}
	ev := eventsRead(0, 100)
	if len(ev) != 2 || ev[0].Type != "wifi" || ev[0].Sev != "warn" || ev[0].Key != "phy0" || !strings.Contains(ev[0].Msg, "firmware recovery (SER) triggered") ||
		!strings.Contains(ev[1].Msg, "already triggered for this chip") {
		t.Errorf("events %+v", ev)
	}
	h := wifiHealthAll(c, ops)
	if h[0].Stage != "ser" || h[0].StalledS < 600 || len(h[0].Actions) != 1 {
		t.Errorf("health after SER: %+v", h[0])
	}
	// still stalled 10 min later: one hostapd restart for both
	tick(10)
	if restarts != 1 {
		t.Errorf("restarts %d", restarts)
	}
	// phy1 moves again; phy0 does not: gives up after 10 more minutes
	moving = 2000
	tick(10)
	ev = eventsRead(0, 100)
	var got []string
	for _, e := range ev {
		got = append(got, e.Key+":"+e.Sev)
	}
	if strings.Join(got, " ") != "phy0:warn phy1:warn phy0:warn phy1:warn phy1:info phy0:risk" {
		t.Errorf("events: %s\n%+v", got, ev)
	}
	if last := ev[len(ev)-1].Msg; !strings.Contains(last, "self-heal gave up") || !strings.Contains(last, "no automatic reboot") {
		t.Errorf("give-up message %q", last)
	}
	if h := wifiHealthAll(c, ops); h[0].Stage != "failed" || h[1].Stage != "" {
		t.Errorf("stages %q %q", h[0].Stage, h[1].Stage)
	}
	if f := wifiHealthFindings(c, wifiHealthAll(c, ops)); f[0].Sev != "risk" || f[1].Sev != "ok" {
		t.Errorf("findings %+v", f)
	}
	// the tick (self-heal only; no hostapd answers: a new baseline); a tick while another holds the lock
	// returns at once without a sample
	c.WiFi.Steering.Enabled = false
	hostapdCtrlDir = t.TempDir()
	*now = now.Add(time.Minute)
	lk := flock(wifiTickLock, false)
	if err := wifiTick(c); err != nil || loadHealState()["phy0"].T == now.Unix() {
		t.Fatalf("tick under the lock: %v", err)
	}
	lk.Close()
	if err := wifiTick(c); err != nil || loadHealState()["phy0"].T != now.Unix() || loadHealState()["phy0"].Stage != 3 {
		t.Fatalf("tick: %v %+v", err, loadHealState()["phy0"])
	}
}
