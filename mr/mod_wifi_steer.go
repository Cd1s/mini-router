package main

// wifi module: 802.11v band steering without a daemon (Cd1s/mini-router#41). usteer / DAWN need
// OpenWrt's hostapd ubus patches; here the per-minute `mr wifi tick` (crond, while wifi.steering is on)
// talks to hostapd's control socket directly:
//
//   - pairs: an SSID on 2.4 GHz and the 5 GHz SSID of the same name, encryption, key_secret and network
//     (steerPairs). Only those BSSes get bss_transition=1 + rrm_neighbor_report=1 in their config.
//   - target: the 5 GHz BSS's own neighbor report as hostapd built it (SHOW_NEIGHBOR: BSSID, BSSID
//     information, operating class, channel, PHY type, wide-bandwidth subelement). Each band's own report
//     is also put into the other band's neighbor list (SET_NEIGHBOR) for clients that ask.
//   - candidates: stations of the 2.4 GHz BSS (STA-FIRST / STA-NEXT) that are authorized, announce BSS
//     Transition (extended capabilities bit 19), support a 5 GHz operating class (when they list them),
//     have a signal of at least min_signal_2g, have been connected a minute, are not excluded, and were
//     not asked recently (30 min; 4 h after a decline; at most 3 times in 24 h). At most 4 per run.
//   - request: BSS_TM_REQ with a preferred-candidate list of that one BSS (preference 255), abridged,
//     no disassociation imminent — the station may decline and stays connected either way. The answer
//     (BSS-TM-RESP event) is awaited for 2 s by attaching to hostapd for that time only.
//   - result: /run/mini-router/wifi-steer.json (RAM): per-station holds, counters, the last 20 requests,
//     and whether a steered station showed up on the 5 GHz BSS (checked in the next runs). One syslog line
//     per request; nothing on flash.

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	steerMinSignal  = -60   // dBm: default wifi.steering.min_signal_2g
	steerMinConn    = 60    // s connected before a station is asked
	steerCooldown   = 1800  // s between two requests to one station
	steerRejectHold = 14400 // s after a station declined
	steerWindow     = 86400 // s: the window of steerDayMax
	steerDayMax     = 3     // requests per station and window
	steerTickMax    = 4     // requests per run
	steerValidInt   = 200   // TBTTs the candidate list is valid (~20 s at 100 TU)
	steerRecentMax  = 20
)

var (
	wifiSteerFile = RunDir + "/wifi-steer.json"
	steerWait     = 2 * time.Second // for the station's BSS-TM-RESP
)

// steerPair is one SSID on both bands: From (2.4 GHz BSS netdev) -> To (5 GHz BSS netdev).
type steerPair struct {
	SSID           string
	From, To       string
	FromPhy, ToPhy string
}

func bandRadio(c *Config, band string) *Radio {
	for i := range c.WiFi.Radios {
		if c.WiFi.Radios[i].Band == band {
			return &c.WiFi.Radios[i]
		}
	}
	return nil
}

// steerCompatible: a client can move between the two without new credentials or another network.
func steerCompatible(a, b SSID) bool {
	return a.Encryption == b.Encryption && a.Key == b.Key && networkName(a.Network) == networkName(b.Network)
}

// steerPairs: the SSIDs steering works on (none while wifi.steering is off).
func steerPairs(c *Config) []steerPair {
	if !c.WiFi.Steering.Enabled {
		return nil
	}
	two, five := bandRadio(c, "2g"), bandRadio(c, "5g")
	if two == nil || five == nil {
		return nil
	}
	i2, i5 := apIfnames(*two), apIfnames(*five)
	var out []steerPair
	for i, a := range two.SSIDs {
		for j, b := range five.SSIDs {
			if a.SSID == b.SSID && steerCompatible(a, b) {
				out = append(out, steerPair{SSID: a.SSID, From: i2[i], To: i5[j], FromPhy: two.Phy, ToPhy: five.Phy})
			}
		}
	}
	return out
}

// steerIfnames: the BSS netdevs that take part in steering (rendered with bss_transition=1).
func steerIfnames(c *Config) map[string]bool {
	m := map[string]bool{}
	for _, p := range steerPairs(c) {
		m[p.From], m[p.To] = true, true
	}
	return m
}

// ---- hostapd: stations, neighbor reports, BSS Transition Management ----

// hapdSta is one station as hostapd's STA / STA-FIRST / STA-NEXT describe it.
type hapdSta struct {
	MAC       string
	Flags     string
	Signal    int // dBm, 0 = unknown
	Connected int // s
	ExtCapab  []byte
	OpClasses []byte // supp_op_classes: the current operating class, then the supported ones
}

func parseHapdSta(s string) (hapdSta, bool) {
	lines := strings.Split(s, "\n")
	first := strings.TrimSpace(lines[0])
	if !reMAC.MatchString(first) {
		return hapdSta{}, false
	}
	st := hapdSta{MAC: strings.ToLower(first)}
	for _, l := range lines[1:] {
		k, v, ok := strings.Cut(strings.TrimSpace(l), "=")
		if !ok {
			continue
		}
		switch k {
		case "flags":
			st.Flags = v
		case "signal":
			st.Signal = atoi(v)
		case "connected_time":
			st.Connected = atoi(v)
		case "ext_capab":
			st.ExtCapab, _ = hex.DecodeString(v)
		case "supp_op_classes":
			st.OpClasses, _ = hex.DecodeString(v)
		}
	}
	return st, true
}

// btm: the station announces BSS Transition Management (extended capabilities bit 19).
func (s hapdSta) btm() bool { return len(s.ExtCapab) > 2 && s.ExtCapab[2]&0x08 != 0 }

// has5g: 1 = lists a 5 GHz operating class (115-129), 0 = lists its classes and none is 5 GHz,
// -1 = did not say. The list ends at the delimiters of the extension sequences (130, 0).
func (s hapdSta) has5g() int {
	if len(s.OpClasses) < 2 {
		return -1
	}
	for _, c := range s.OpClasses[1:] {
		if c == 0 || c == 130 {
			break
		}
		if c >= 115 && c <= 129 {
			return 1
		}
	}
	return 0
}

// hostapdStations lists the stations of one BSS (at most 256).
func hostapdStations(ifname string) []hapdSta {
	var out []hapdSta
	r, err := hostapdCmd(ifname, "STA-FIRST", time.Second)
	for i := 0; err == nil && i < 256; i++ {
		s, ok := parseHapdSta(r)
		if !ok {
			break
		}
		out = append(out, s)
		r, err = hostapdCmd(ifname, "STA-NEXT "+s.MAC, time.Second)
	}
	return out
}

// nrEntry is one line of SHOW_NEIGHBOR: the SSID and the neighbor report element body, both hex.
type nrEntry struct{ SSID, NR string }

var reHexStr = lazyRegexp(`^([0-9a-f]{2}){1,255}$`)

func parseNeighbors(s string) map[string]nrEntry {
	m := map[string]nrEntry{}
	for _, l := range strings.Split(s, "\n") {
		f := strings.Fields(l)
		if len(f) < 2 || !reMAC.MatchString(f[0]) {
			continue
		}
		var e nrEntry
		for _, x := range f[1:] {
			if v, ok := strings.CutPrefix(x, "ssid="); ok && reHexStr.MatchString(v) {
				e.SSID = v
			}
			if v, ok := strings.CutPrefix(x, "nr="); ok && reHexStr.MatchString(v) {
				e.NR = v
			}
		}
		m[strings.ToLower(f[0])] = e
	}
	return m
}

// nrCandidate turns a neighbor report element body (BSSID, BSSID information, operating class,
// channel, PHY type, subelements) into BSS_TM_REQ's neighbor= syntax, with a candidate preference
// subelement (3) of 255 appended.
func nrCandidate(nrHex string) (string, error) {
	b, err := hex.DecodeString(nrHex)
	if err != nil || len(b) < 13 {
		return "", fmt.Errorf("bad neighbor report %q", nrHex)
	}
	return fmt.Sprintf("%s,0x%08x,%d,%d,%d,%s0301ff", net.HardwareAddr(b[:6]), binary.LittleEndian.Uint32(b[6:10]),
		b[10], b[11], b[12], hex.EncodeToString(b[13:])), nil
}

// parseBTMResp reads a "<3>BSS-TM-RESP <mac> status_code=N ... [target_bssid=X]" event for mac.
func parseBTMResp(ev, mac string) (int, string, bool) {
	if i := strings.IndexByte(ev, '>'); strings.HasPrefix(ev, "<") && i > 0 {
		ev = ev[i+1:]
	}
	f := strings.Fields(ev)
	if len(f) < 3 || f[0] != "BSS-TM-RESP" || !strings.EqualFold(f[1], mac) {
		return 0, "", false
	}
	kv := parseKV(strings.Join(f[2:], "\n"))
	code, err := strconv.Atoi(kv["status_code"])
	if err != nil {
		return 0, "", false
	}
	return code, strings.ToLower(kv["target_bssid"]), true
}

// hostapdBTM sends BSS_TM_REQ <mac> <args> on ifname and waits up to wait for the station's answer.
// hostapd reports it only as an event to attached monitors, so this client attaches for the exchange
// and detaches after it. Status -1: no answer in time.
func hostapdBTM(ifname, mac, args string, wait time.Duration) (int, string, error) {
	if !reDev.MatchString(ifname) || strings.Contains(ifname, "..") || !reMAC.MatchString(mac) {
		return -1, "", fmt.Errorf("bad request %q %q", ifname, mac)
	}
	c, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: "", Net: "unixgram"})
	if err != nil {
		return -1, "", err
	}
	defer c.Close()
	dst := &net.UnixAddr{Name: filepath.Join(hostapdCtrlDir, ifname), Net: "unixgram"}
	buf := make([]byte, 4096)
	var events []string
	ask := func(cmd string, d time.Duration) (string, error) { // the reply; events that come first are kept
		c.SetDeadline(time.Now().Add(d))
		if _, err := c.WriteToUnix([]byte(cmd), dst); err != nil {
			return "", err
		}
		for {
			n, _, err := c.ReadFromUnix(buf)
			if err != nil {
				return "", err
			}
			if n > 0 && buf[0] == '<' {
				events = append(events, string(buf[:n]))
				continue
			}
			return strings.TrimSpace(string(buf[:n])), nil
		}
	}
	if r, err := ask("ATTACH", time.Second); err != nil || r != "OK" {
		return -1, "", fmt.Errorf("hostapd %s: ATTACH: %v%s", ifname, err, r)
	}
	defer ask("DETACH", 300*time.Millisecond)
	if r, err := ask("BSS_TM_REQ "+mac+" "+args, 2*time.Second); err != nil || r != "OK" {
		return -1, "", fmt.Errorf("hostapd %s: BSS_TM_REQ: %v%s", ifname, err, r)
	}
	deadline := time.Now().Add(wait)
	for {
		for _, e := range events {
			if code, target, ok := parseBTMResp(e, mac); ok {
				return code, target, nil
			}
		}
		events = events[:0]
		c.SetDeadline(deadline)
		n, _, err := c.ReadFromUnix(buf)
		if err != nil {
			return -1, "", nil
		}
		if n > 0 && buf[0] == '<' {
			events = append(events, string(buf[:n]))
		}
	}
}

// ---- state and decisions ----

type steerSta struct {
	First  int64  `json:"first"` // start of the window
	N      int    `json:"n"`     // requests in the window
	Last   int64  `json:"last"`  // last request
	Result string `json:"result"`
	To     string `json:"to"`
	Moved  bool   `json:"moved,omitempty"`
}

type steerRec struct {
	T      int64  `json:"t"`
	MAC    string `json:"mac"`
	SSID   string `json:"ssid"`
	From   string `json:"from"`
	To     string `json:"to"`
	Signal int    `json:"signal"`
	Result string `json:"result"`
	Moved  bool   `json:"moved,omitempty"`
}

type steerState struct {
	Since  int64                `json:"since"`
	Token  int                  `json:"token"`
	Sta    map[string]*steerSta `json:"sta"`
	Count  map[string]int       `json:"count"` // sent accepted rejected noreply error moved
	Recent []steerRec           `json:"recent"`
}

func loadSteerState() *steerState {
	st := &steerState{}
	json.Unmarshal([]byte(readFile(wifiSteerFile)), st)
	if st.Sta == nil {
		st.Sta = map[string]*steerSta{}
	}
	if st.Count == nil {
		st.Count = map[string]int{}
	}
	if st.Recent == nil {
		st.Recent = []steerRec{}
	}
	return st
}

func (st *steerState) save(now int64) {
	for mac, e := range st.Sta {
		if now-e.Last > steerWindow {
			delete(st.Sta, mac)
		}
	}
	if st.Since == 0 {
		st.Since = now
	}
	b, _ := json.Marshal(st)
	writeAtomic(wifiSteerFile, b, 0600)
}

// steerWhy: "" = ask this station now, else why not.
func steerWhy(s hapdSta, e *steerSta, conf Steering, now int64) string {
	min := conf.MinSignal2G
	if min == 0 {
		min = steerMinSignal
	}
	switch {
	case slicesHas(conf.Exclude, s.MAC):
		return "excluded"
	case !strings.Contains(s.Flags, "[AUTHORIZED]"):
		return "not authorized"
	case !s.btm():
		return "no 802.11v BSS transition support"
	case s.has5g() == 0:
		return "no 5 GHz support"
	case s.Signal == 0:
		return "signal unknown"
	case s.Signal < min:
		return fmt.Sprintf("signal %d dBm below %d", s.Signal, min)
	case s.Connected < steerMinConn:
		return "connected less than a minute"
	case e != nil && now-e.First < steerWindow && e.N >= steerDayMax:
		return fmt.Sprintf("asked %d times in 24 h", e.N)
	case e != nil && e.Result == "rejected" && now-e.Last < steerRejectHold:
		return "declined recently"
	case e != nil && now-e.Last < steerCooldown:
		return "asked recently"
	}
	return ""
}

// steerDecision is what one run did (or, with --dry-run, would do) about one station.
type steerDecision struct {
	MAC    string `json:"mac,omitempty"`
	SSID   string `json:"ssid"`
	From   string `json:"from"`
	To     string `json:"to"`
	Signal int    `json:"signal,omitempty"`
	Steer  bool   `json:"steer"`
	Why    string `json:"why,omitempty"`
	Result string `json:"result,omitempty"`
}

// bssOf: the live BSS of ifname in a radio's STATUS.
func bssOf(op radioOp, ifname string) *opBSS {
	for i := range op.BSS {
		if op.BSS[i].Ifname == ifname {
			return &op.BSS[i]
		}
	}
	return nil
}

// steerPass: one steering run over every pair (ops: live radio state by our phy name).
func steerPass(c *Config, ops map[string]radioOp, dry bool) []steerDecision {
	now := wifiNow().Unix()
	st := loadSteerState()
	out := []steerDecision{}
	sent := 0
	for _, p := range steerPairs(c) {
		pd := steerDecision{SSID: p.SSID, From: p.From, To: p.To}
		op2, ok2 := ops[p.FromPhy]
		op5, ok5 := ops[p.ToPhy]
		b2, b5 := bssOf(op2, p.From), bssOf(op5, p.To)
		if !ok2 || !ok5 || b2 == nil || b5 == nil {
			pd.Why = "hostapd not answering or BSS not up"
			out = append(out, pd)
			continue
		}
		if op5.State != "ENABLED" {
			pd.Why = "5 GHz radio is " + op5.State
			out = append(out, pd)
			continue
		}
		bss2, bss5 := strings.ToLower(b2.BSSID), strings.ToLower(b5.BSSID)
		if !reMAC.MatchString(bss2) || !reMAC.MatchString(bss5) { // they go into SET_NEIGHBOR commands
			pd.Why = "no BSSID in hostapd's STATUS"
			out = append(out, pd)
			continue
		}
		r2, err2 := hostapdCmd(p.From, "SHOW_NEIGHBOR", time.Second)
		r5, err5 := hostapdCmd(p.To, "SHOW_NEIGHBOR", time.Second)
		n2, n5 := parseNeighbors(r2), parseNeighbors(r5)
		own5 := n5[bss5]
		cand, err := nrCandidate(own5.NR)
		if err2 != nil || err5 != nil || own5.NR == "" || err != nil {
			pd.Why = p.To + " has no neighbor report of its own (rrm_neighbor_report: apply the config)"
			out = append(out, pd)
			continue
		}
		if !dry { // each band's own report in the other band's list, for clients that ask
			if n2[bss5].NR != own5.NR && own5.SSID != "" {
				hostapdCmd(p.From, fmt.Sprintf("SET_NEIGHBOR %s ssid=%s nr=%s", bss5, own5.SSID, own5.NR), time.Second)
			}
			if own2 := n2[bss2]; own2.NR != "" && own2.SSID != "" && n5[bss2].NR != own2.NR {
				hostapdCmd(p.To, fmt.Sprintf("SET_NEIGHBOR %s ssid=%s nr=%s", bss2, own2.SSID, own2.NR), time.Second)
			}
			steerMarkMoved(st, p.To, now)
		}
		for _, s := range hostapdStations(p.From) {
			d := steerDecision{MAC: s.MAC, SSID: p.SSID, From: p.From, To: p.To, Signal: s.Signal}
			d.Why = steerWhy(s, st.Sta[s.MAC], c.WiFi.Steering, now)
			if d.Why == "" && sent >= steerTickMax {
				d.Why = fmt.Sprintf("at most %d requests per run", steerTickMax)
			}
			d.Steer = d.Why == ""
			if d.Steer {
				sent++
				if !dry {
					d.Result = steerSend(st, p, s, cand, now)
				}
			}
			out = append(out, d)
		}
	}
	if !dry {
		st.save(now)
	}
	return out
}

// steerMarkMoved: stations asked in the last 15 minutes that are now on the 5 GHz BSS to.
func steerMarkMoved(st *steerState, to string, now int64) {
	for mac, e := range st.Sta {
		if e.Moved || e.To != to || now-e.Last > 900 {
			continue
		}
		if r, err := hostapdCmd(to, "STA "+mac, time.Second); err == nil && strings.HasPrefix(strings.ToLower(r), mac) {
			e.Moved = true
			st.Count["moved"]++
			for i := len(st.Recent) - 1; i >= 0; i-- {
				if st.Recent[i].MAC == mac {
					st.Recent[i].Moved = true
					break
				}
			}
		}
	}
}

// steerSend asks one station to move and records the answer.
func steerSend(st *steerState, p steerPair, s hapdSta, cand string, now int64) string {
	st.Token = st.Token%255 + 1
	args := fmt.Sprintf("pref=1 abridged=1 valid_int=%d dialog_token=%d neighbor=%s", steerValidInt, st.Token, cand)
	code, _, err := hostapdBTM(p.From, s.MAC, args, steerWait)
	key, res := "accepted", "accepted"
	switch {
	case err != nil:
		key, res = "error", "error: "+err.Error()
	case code < 0:
		key, res = "noreply", "no answer"
	case code != 0:
		key, res = "rejected", fmt.Sprintf("declined (status %d)", code)
	}
	e := st.Sta[s.MAC]
	if e == nil || now-e.First >= steerWindow {
		e = &steerSta{First: now}
		st.Sta[s.MAC] = e
	}
	e.N++
	e.Last, e.Result, e.To, e.Moved = now, key, p.To, false
	st.Count["sent"]++
	st.Count[key]++
	st.Recent = append(st.Recent, steerRec{T: now, MAC: s.MAC, SSID: p.SSID, From: p.From, To: p.To, Signal: s.Signal, Result: res})
	if len(st.Recent) > steerRecentMax {
		st.Recent = st.Recent[len(st.Recent)-steerRecentMax:]
	}
	logf("wifi steer: %s %s -> %s (%d dBm): %s", s.MAC, p.From, p.To, s.Signal, res)
	return res
}

// steerSummary: the steering part of wifi.health.
func steerSummary(c *Config) map[string]any {
	st := loadSteerState()
	pairs := []map[string]string{}
	for _, p := range steerPairs(c) {
		pairs = append(pairs, map[string]string{"ssid": p.SSID, "from": p.From, "to": p.To})
	}
	min := c.WiFi.Steering.MinSignal2G
	if min == 0 {
		min = steerMinSignal
	}
	return map[string]any{"enabled": c.WiFi.Steering.Enabled, "min_signal_2g": min, "excluded": len(c.WiFi.Steering.Exclude),
		"pairs": pairs, "counts": st.Count, "since": st.Since, "recent": st.Recent}
}
