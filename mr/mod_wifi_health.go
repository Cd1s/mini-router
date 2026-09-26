package main

// wifi module: radio health and self-heal (Cd1s/mini-router#41), and `mr wifi tick`.
//
// Health (read only; `mr wifi health`, API wifi.health, `mr doctor`): per radio, from the kernel phy
// behind <phy>-ap0 —
//   - temperature, throttle temperature and TX duty cycle (hwmon mt79xx_<phy>: temp1_input, temp1_crit,
//     throttle1; 100 % = not throttled);
//   - acknowledged MPDUs, single- plus multi-user (mt76 debugfs tx_stats: the hardware MIB counters, so
//     WED-offloaded traffic counts too);
//   - hardware airtime fairness (mt76 debugfs vow_atf: the firmware's VoW scheduler, which also covers
//     WED-offloaded traffic; mt76 turns it on by default where it exists), firmware restarts since the
//     driver loaded (sys_recovery: SYS_RESET_COUNT), the WM MCU load (fw_util_wm; only reported while
//     firmware debugging is on, so usually absent);
//   - per station (wifi.stations): airtime used, from mac80211's station debugfs.
//
// Self-heal (wifi.self_heal, run by the per-minute `mr wifi tick` from crond; state in /run): a radio
// with stations associated whose acknowledged-MPDU counter has not moved for 10 minutes is stalled
// (hostapd polls idle stations every 5 minutes, so a healthy radio never stays still that long). Then,
// one step per 10 minutes while it stays stalled: the driver's full firmware recovery (debugfs
// sys_recovery 7: SER, the path mt76 takes itself on a firmware watchdog; resets the whole chip, both
// bands, stations stay associated), a restart of mr-hostapd, and finally an event that it could not be
// fixed — never a reboot. At most 4 actions per radio in 24 h; none while a change waits for
// confirmation. Every step is an event (type wifi, mod_sys_event.go).

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// paths and actions (variables so tests use a temp dir and fakes)
var (
	wifiDebugfs        = "/sys/kernel/debug/ieee80211"
	wifiSysNet         = "/sys/class/net"
	wifiSysPhy         = "/sys/class/ieee80211"
	wifiHwmonDir       = "/sys/class/hwmon"
	wifiHealthFile     = RunDir + "/wifi-health.json"
	wifiTickLock       = RunDir + "/wifi.tick"
	wifiNow            = time.Now
	wifiRestartHostapd = func() error {
		if out, err := run("rc-service", "mr-hostapd", "restart"); err != nil {
			return fmt.Errorf("%v: %s", err, firstLine(strings.TrimSpace(out)))
		}
		return nil
	}
	wifiPending = pendingBlocks
)

const (
	healStall  = 600 // s: stations associated and no acknowledged TX for this long = stalled
	healGap    = 300 // s: samples further apart start a new baseline (crond stopped, clock jump)
	healDayMax = 4   // actions per radio in 24 h
	healActs   = 16  // actions kept per radio
	serFull    = "7" // sys_recovery: trigger & enable system error full recovery
)

var reKPhy = lazyRegexp(`^phy[0-9]{1,3}$`)

func bandLabel(b string) string {
	return map[string]string{"2g": "2.4 GHz", "5g": "5 GHz", "6g": "6 GHz"}[b]
}

// kernelPhy: the kernel's name of the phy behind a radio's first AP netdev ("" when it does not exist).
func kernelPhy(r Radio) string {
	p := strings.TrimSpace(readFile(filepath.Join(wifiSysNet, r.Phy+"-ap0", "phy80211", "name")))
	if !reKPhy.MatchString(p) {
		return ""
	}
	return p
}

// liveRadios: hostapd STATUS of every radio, by our phy name (a radio whose hostapd does not answer is
// missing).
func liveRadios(c *Config) map[string]radioOp {
	m := map[string]radioOp{}
	for _, r := range c.WiFi.Radios {
		if op, err := radioStatus(r, time.Second); err == nil {
			m[r.Phy] = op
		}
	}
	return m
}

// ---- metrics ----

type healAction struct {
	T      int64  `json:"t"`
	Action string `json:"action"` // ser | restart | failed | recovered
	Detail string `json:"detail,omitempty"`
}

type radioHealth struct {
	Phy      string       `json:"phy"`
	Band     string       `json:"band"`
	KPhy     string       `json:"kphy,omitempty"`
	State    string       `json:"state,omitempty"` // hostapd radio state ("" = not answering)
	Stations int          `json:"stations"`
	TempC    float64      `json:"temp_c,omitempty"`
	CritC    float64      `json:"crit_c,omitempty"`  // the firmware starts throttling here
	TxDuty   int          `json:"tx_duty,omitempty"` // %: 100 = not throttled, 0 = unknown
	FwBusy   int          `json:"fw_busy"`           // WM MCU load %, -1 = not reported
	TxAcked  uint32       `json:"tx_acked"`          // acknowledged MPDUs (SU + MU), wraps at 2^32
	HasTx    bool         `json:"has_tx"`
	ATF      string       `json:"atf"`       // on | off | absent (vow_atf)
	FwResets int          `json:"fw_resets"` // firmware restarts since the driver loaded, -1 = unknown
	SER      bool         `json:"ser"`       // sys_recovery available
	StalledS int64        `json:"stalled_s,omitempty"`
	Stage    string       `json:"heal_stage,omitempty"` // ser | restart | failed (self-heal steps taken)
	Actions  []healAction `json:"heal_actions,omitempty"`
}

// parseTxAcked: acknowledged MPDUs (single-user + multi-user) from mt76's tx_stats. The driver keeps
// u32 accumulators of the hardware MIB counters and prints them with %d.
func parseTxAcked(s string) (uint32, bool) {
	var sum uint32
	found := false
	for _, l := range strings.Split(s, "\n") {
		k, v, ok := strings.Cut(l, ":")
		if !ok || (k != "Tx single-user successful MPDU counts" && k != "Tx multi-user successful MPDU counts") {
			continue
		}
		if n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
			sum += uint32(n)
			found = true
		}
	}
	return sum, found
}

// parseFwResets: "SYS_RESET_COUNT: WM 0, WA 0" of sys_recovery (-1: not there).
func parseFwResets(s string) int {
	_, v, ok := strings.Cut(s, "SYS_RESET_COUNT:")
	if !ok {
		return -1
	}
	v = firstLine(v)
	n := 0
	for _, part := range strings.Split(v, ",") {
		f := strings.Fields(part)
		if len(f) != 2 {
			return -1
		}
		k, err := strconv.Atoi(f[1])
		if err != nil {
			return -1
		}
		n += k
	}
	return n
}

// parseFwBusy: "Busy: 12%  Peak busy: 40%" of fw_util_wm (-1: not reported, i.e. fw_debug_wm off).
func parseFwBusy(s string) int {
	_, v, ok := strings.Cut(s, "Busy:")
	if !ok {
		return -1
	}
	n, err := strconv.Atoi(strings.TrimSpace(strings.SplitN(v, "%", 2)[0]))
	if err != nil {
		return -1
	}
	return n
}

// parseAirtime: "RX: 499141 us\nTX: 279777 us\n..." of a station's airtime file.
func parseAirtime(s string) (tx, rx uint64) {
	for _, l := range strings.Split(s, "\n") {
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		switch k {
		case "TX":
			tx = atou(firstField(strings.TrimSpace(v)))
		case "RX":
			rx = atou(firstField(strings.TrimSpace(v)))
		}
	}
	return tx, rx
}

// hwmonFor: the hwmon directory of an mt76 phy (mt7915_phy0, mt7996_phy1, ...).
func hwmonFor(kphy string) string {
	ents, _ := os.ReadDir(wifiHwmonDir)
	for _, e := range ents {
		d := filepath.Join(wifiHwmonDir, e.Name())
		n := strings.TrimSpace(readFile(filepath.Join(d, "name")))
		if strings.HasPrefix(n, "mt7") && strings.HasSuffix(n, "_"+kphy) {
			return d
		}
	}
	return ""
}

// readRadioHealth: the metrics of one radio (op: its hostapd STATUS, up: hostapd answered).
func readRadioHealth(r Radio, op radioOp, up bool) radioHealth {
	h := radioHealth{Phy: r.Phy, Band: r.Band, FwBusy: -1, FwResets: -1, ATF: "absent"}
	if up {
		h.State = op.State
		for _, b := range op.BSS {
			h.Stations += b.Clients
		}
	}
	h.KPhy = kernelPhy(r)
	if h.KPhy == "" {
		return h
	}
	mt := filepath.Join(wifiDebugfs, h.KPhy, "mt76")
	h.TxAcked, h.HasTx = parseTxAcked(readFile(filepath.Join(mt, "tx_stats")))
	switch strings.TrimSpace(readFile(filepath.Join(mt, "vow_atf"))) {
	case "0":
		h.ATF = "off"
	case "":
	default:
		h.ATF = "on"
	}
	if s := readFile(filepath.Join(mt, "sys_recovery")); s != "" {
		h.SER = true
		h.FwResets = parseFwResets(s)
	}
	h.FwBusy = parseFwBusy(readFile(filepath.Join(mt, "fw_util_wm")))
	if d := hwmonFor(h.KPhy); d != "" {
		h.TempC = float64(atoi(strings.TrimSpace(readFile(filepath.Join(d, "temp1_input"))))) / 1000
		h.CritC = float64(atoi(strings.TrimSpace(readFile(filepath.Join(d, "temp1_crit"))))) / 1000
		h.TxDuty = atoi(strings.TrimSpace(readFile(filepath.Join(d, "throttle1"))))
	}
	return h
}

// wifiHealthAll: every radio's metrics plus what self-heal saw (ops: liveRadios).
func wifiHealthAll(c *Config, ops map[string]radioOp) []radioHealth {
	st := loadHealState()
	now := wifiNow().Unix()
	out := []radioHealth{}
	for _, r := range c.WiFi.Radios {
		op, up := ops[r.Phy]
		h := readRadioHealth(r, op, up)
		if s, ok := st[r.Phy]; ok {
			h.Actions = s.Acts
			if c.WiFi.SelfHeal && s.KPhy == h.KPhy && now-s.T <= healGap {
				if s.Sta > 0 {
					h.StalledS = s.T - s.Moved
				}
				h.Stage = map[int]string{1: "ser", 2: "restart", 3: "failed"}[s.Stage]
			}
		}
		out = append(out, h)
	}
	return out
}

// wifiHealthReport: API wifi.health and `mr wifi health`.
func wifiHealthReport(c *Config) map[string]any {
	return map[string]any{"time": wifiNow().Unix(), "self_heal": c.WiFi.SelfHeal,
		"radios": wifiHealthAll(c, liveRadios(c)), "steering": steerSummary(c)}
}

func apiWifiHealth() apiResp {
	c, err := loadConfig(ConfigPath, SecretsPath)
	if err != nil {
		return errResp(500, "%v", err)
	}
	return apiResp{body: wifiHealthReport(c)}
}

// ---- doctor ----

// wifiDoctor: `mr doctor`'s radio findings (check wifi).
func wifiDoctor(c *Config) []docFinding {
	return wifiHealthFindings(c, wifiHealthAll(c, liveRadios(c)))
}

// wifiHealthFindings: one finding per radio that has a kernel phy, and a skip when no radio has
// hardware airtime fairness.
func wifiHealthFindings(c *Config, hs []radioHealth) []docFinding {
	var out []docFinding
	atf := false
	for _, h := range hs {
		if h.KPhy == "" {
			continue // not up: the check above reports it
		}
		atf = atf || h.ATF != "absent"
		f := docFinding{ID: "wifi.health." + h.Phy, Sev: "ok", Title: "WiFi radio"}
		parts := []string{fmt.Sprintf("%s %s", bandLabel(h.Band), h.Phy)}
		if h.TempC > 0 {
			parts = append(parts, fmt.Sprintf("%.0f °C", h.TempC))
		}
		parts = append(parts, fmt.Sprintf("%d station(s)", h.Stations), "ATF "+h.ATF)
		var bad, fix []string
		warn := func(msg, how string) {
			if f.Sev == "ok" {
				f.Sev = "warn"
			}
			bad = append(bad, msg)
			fix = append(fix, how)
		}
		if h.TxDuty > 0 && h.TxDuty < 100 {
			warn(fmt.Sprintf("thermal throttling: TX duty %d %%", h.TxDuty), "airflow (vents free, not stacked): the radio sends less to cool down")
		} else if h.CritC > 0 && h.TempC >= h.CritC-10 {
			warn(fmt.Sprintf("near the throttle temperature (%.0f °C)", h.CritC), "airflow (vents free, not stacked)")
		}
		if h.ATF == "off" {
			warn("hardware airtime fairness is off", "echo 1 > "+filepath.Join(wifiDebugfs, h.KPhy, "mt76/vow_atf")+" (the driver's default)")
		}
		if h.FwResets > 0 {
			warn(fmt.Sprintf("firmware restarted %d time(s) since the driver loaded", h.FwResets), "grep -i -e mt79 -e 'wifi' /var/log/messages; dmesg | grep -i mt79")
		}
		switch {
		case h.Stage == "failed":
			f.Sev = "risk"
			bad = append(bad, "TX stalled with stations associated; self-heal could not fix it")
			fix = append(fix, "reboot the router; keep dmesg first (mr mon dmesg)")
		case h.StalledS >= 120:
			how := "wifi.self_heal recovers it (firmware recovery, then a hostapd restart)"
			if !c.WiFi.SelfHeal {
				how = "enable wifi.self_heal, or: echo " + serFull + " > " + filepath.Join(wifiDebugfs, h.KPhy, "mt76/sys_recovery") + "; rc-service mr-hostapd restart"
			}
			warn(fmt.Sprintf("no acknowledged TX for %s with %d station(s)", fmtSecs(h.StalledS), h.Stations), how)
		}
		f.Detail = eventClean(strings.Join(append(parts, bad...), "; "), 300)
		f.Fix = strings.Join(fix, "; ")
		out = append(out, f)
	}
	if len(out) > 0 && !atf {
		out = append(out, docFinding{ID: "wifi.atf", Sev: "skip", Title: "WiFi airtime fairness",
			Detail: "no vow_atf in this kernel's mt76: WED-offloaded traffic bypasses airtime fairness (needs an mt76 with openwrt/mt76 6b7b98627bcc, HW ATF for mt7986+)"})
	}
	return out
}

// ---- self-heal ----

type healState struct {
	KPhy  string       `json:"kphy"`
	T     int64        `json:"t"`     // last sample
	TX    uint32       `json:"tx"`    // acknowledged MPDUs at T
	Sta   int          `json:"sta"`   // stations at T
	Moved int64        `json:"moved"` // last sample with TX moving or no station
	Stage int          `json:"stage"` // 0 ok, 1 firmware recovery done, 2 hostapd restarted, 3 given up
	ActT  int64        `json:"act_t"`
	Acts  []healAction `json:"acts,omitempty"`
}

func loadHealState() map[string]healState {
	m := map[string]healState{}
	json.Unmarshal([]byte(readFile(wifiHealthFile)), &m)
	return m
}

// healStep: one sample of one radio (ok: the counter was read and the radio is ENABLED; ser: firmware
// recovery available). Returns the new state and the action due: "" | ser | restart | failed | recovered.
func healStep(h healState, now int64, kphy string, sta int, tx uint32, ok, ser bool) (healState, string) {
	if !ok || kphy == "" || kphy != h.KPhy || h.T == 0 || now < h.T || now-h.T > healGap {
		// no counter, radio not up, another phy (driver reloaded), first sample, a gap: new baseline
		h.KPhy, h.T, h.TX, h.Sta, h.Moved = kphy, now, tx, sta, now
		return h, ""
	}
	moved := tx != h.TX
	h.T, h.TX, h.Sta = now, tx, sta
	if moved || sta == 0 {
		h.Moved = now
		if moved && h.Stage > 0 {
			h.Stage = 0
			return h.act(now, "recovered", ""), "recovered"
		}
		return h, ""
	}
	if now-h.Moved < healStall || h.Stage >= 3 || (h.Stage > 0 && now-h.ActT < healStall) {
		return h, ""
	}
	n := 0
	for _, a := range h.Acts {
		if (a.Action == "ser" || a.Action == "restart") && now-a.T < 86400 {
			n++
		}
	}
	next, detail := "ser", ""
	switch {
	case h.Stage == 2:
		next, detail = "failed", "still stalled after firmware recovery and a hostapd restart"
	case n >= healDayMax:
		next, detail = "failed", fmt.Sprintf("limit of %d actions in 24 h reached", healDayMax)
	case h.Stage == 1 || !ser:
		next = "restart"
	}
	h.Stage = map[string]int{"ser": 1, "restart": 2, "failed": 3}[next]
	h.ActT = now
	return h.act(now, next, detail), next
}

func (h healState) act(now int64, action, detail string) healState {
	h.Acts = append(append([]healAction(nil), h.Acts...), healAction{T: now, Action: action, Detail: detail})
	if len(h.Acts) > healActs {
		h.Acts = h.Acts[len(h.Acts)-healActs:]
	}
	return h
}

// healPass: one self-heal sample of every radio, and the actions it calls for.
func healPass(c *Config, ops map[string]radioOp) {
	st := loadHealState()
	now := wifiNow().Unix()
	serDone := map[string]bool{} // chip (device path) -> recovery written this run (it resets both bands)
	restarted := false
	blocked := wifiPending() != nil
	for _, r := range c.WiFi.Radios {
		op, up := ops[r.Phy]
		h := readRadioHealth(r, op, up)
		prev := st[r.Phy]
		next, act := healStep(prev, now, h.KPhy, h.Stations, h.TxAcked, h.HasTx && up && op.State == "ENABLED", h.SER)
		name := fmt.Sprintf("%s (%s)", r.Phy, bandLabel(r.Band))
		stalled := fmtSecs(now - prev.Moved)
		if blocked && (act == "ser" || act == "restart") {
			logf("wifi self-heal: %s stalled %s, %s deferred: a change waits for confirmation", name, stalled, act)
			next.Stage, next.ActT, next.Acts = prev.Stage, prev.ActT, prev.Acts
			act = ""
		}
		switch act {
		case "ser":
			dev, _ := filepath.EvalSymlinks(filepath.Join(wifiSysPhy, h.KPhy, "device"))
			res := "firmware recovery (SER) triggered"
			if dev != "" && serDone[dev] {
				res = "firmware recovery already triggered for this chip"
			} else if err := writeDebugfs(filepath.Join(wifiDebugfs, h.KPhy, "mt76", "sys_recovery"), serFull); err != nil {
				res = "firmware recovery failed: " + err.Error()
			}
			serDone[dev] = true
			eventAdd(c, "wifi", "warn", r.Phy, fmt.Sprintf("%s: no acknowledged TX for %s with %d station(s): %s", name, stalled, h.Stations, res), true)
		case "restart":
			res := "hostapd restarted (both bands reconnect)"
			if restarted {
				res = "hostapd already restarted"
			} else if err := wifiRestartHostapd(); err != nil {
				res = "hostapd restart failed: " + err.Error()
			}
			restarted = true
			eventAdd(c, "wifi", "warn", r.Phy, fmt.Sprintf("%s: TX still stalled after %s with %d station(s): %s", name, stalled, h.Stations, res), true)
		case "failed":
			eventAdd(c, "wifi", "risk", r.Phy, fmt.Sprintf("%s: TX stalled with %d station(s), self-heal gave up (%s); no automatic reboot",
				name, h.Stations, next.Acts[len(next.Acts)-1].Detail), true)
		case "recovered":
			eventAdd(c, "wifi", "info", r.Phy, fmt.Sprintf("%s: TX moving again after the self-heal step", name), true)
		}
		if act != "" {
			logf("wifi self-heal: %s %s", name, act)
		}
		st[r.Phy] = next
	}
	b, _ := json.Marshal(st)
	writeAtomic(wifiHealthFile, b, 0600)
}

// writeDebugfs writes one value into an existing debugfs file (no create, no truncate).
func writeDebugfs(path, val string) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	_, err = f.WriteString(val + "\n")
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// ---- tick ----

// wifiCronLine: the per-minute tick while steering or self-heal is on.
func wifiCronLine(c *Config) []string {
	if len(c.WiFi.Radios) == 0 || (!c.WiFi.Steering.Enabled && !c.WiFi.SelfHeal) {
		return nil
	}
	return []string{"# wifi band steering / radio self-heal (wifi.steering, wifi.self_heal)", "* * * * * " + mrBin + " wifi tick"}
}

// wifiTick is `mr wifi tick` (crond, every minute): one steering run and one self-heal sample. A tick
// that is still running makes the next one return at once.
func wifiTick(c *Config) error {
	if len(c.WiFi.Radios) == 0 || (!c.WiFi.Steering.Enabled && !c.WiFi.SelfHeal) {
		return nil
	}
	lk := flock(wifiTickLock, false)
	if lk == nil {
		return nil
	}
	defer lk.Close()
	ops := liveRadios(c)
	if c.WiFi.Steering.Enabled {
		steerPass(c, ops, false)
	}
	if c.WiFi.SelfHeal {
		healPass(c, ops)
	}
	return nil
}
