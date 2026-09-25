package main

// sys module: the event log and `mr event` (Cd1s/mini-router#16). What is worth knowing afterwards —
// a WAN that dropped or came back, a multi-WAN failover, a change applied or rolled back, a locked
// web UI login, a new DHCP client, a reboot and why, a firmware change, a health check that turned
// bad — is appended by the code that sees it to one small log on flash; notifications
// (mod_sys_notify.go) are sent from that log. Nothing is resident:
//
//   - the net hooks call OnWAN inside pppd / udhcpc / the health checker: a line is appended and, when a
//     notification channel wants the type, a detached `mr notify flush --hook` is started;
//   - apply / rollback results (history.go setResult) and the login throttle (api_login.go) add theirs;
//   - mr-mon's per-minute sampler (rootfs/usr/libexec/mr/mon-collect) runs `mr event tick` only when
//     dnsmasq's lease file changed (new devices) or the uptime in /run/mini-router/event.due has come
//     (a notification retry, held events, the next background `mr doctor`); any other minute costs a
//     few shell builtins;
//   - mr-bootlog runs `mr event boot` at boot (why the router restarted: clean reboot, kernel crash in
//     pstore, power cut / hang, new firmware) and `mr event shutdown` when OpenRC takes the system down.
//
// Log: /etc/mini-router/state/events.log — JSON lines {seq, t, type, sev, key, msg}, the newest 200
// kept (rewritten when it passes 250 lines or 96 KiB). On flash, because the events that matter most (a
// crash, a power cut, a rollback at boot) are the ones a RAM log loses; a few lines a day. Text that
// comes from the network (DHCP host names, addresses) is cleaned of control characters and capped.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

// event is one line of the log.
type event struct {
	Seq  int64  `json:"seq"`
	Time int64  `json:"t"`
	Type string `json:"type"`
	Sev  string `json:"sev"`           // info | warn | risk
	Key  string `json:"key,omitempty"` // subject: WAN name, MAC, check id, source address, change #
	Msg  string `json:"msg"`
}

// eventTypes: every type, in the order the web UI lists them.
var eventTypes = []string{"wan_down", "wan_up", "failover", "apply", "rollback", "login_lock", "new_device", "boot", "upgrade", "doctor"}

// eventLabels: short names for notification lines.
var eventLabels = map[string]string{
	"wan_down": "WAN down", "wan_up": "WAN up", "failover": "Failover", "apply": "Change", "rollback": "Rollback",
	"login_lock": "Login locked", "new_device": "New device", "boot": "Boot", "upgrade": "Firmware", "doctor": "Health check",
}

const (
	eventKeep      = 200
	eventTrimLines = 250
	eventTrimBytes = 96 << 10
	eventMsgMax    = 300
	eventSeenMax   = 2048
	eventBootQuiet = 300 // s after boot before the first background health check (WANs dial, radios start)
)

// paths and clocks (variables so tests can use a temp dir and fake time)
var (
	eventLog          = "/etc/mini-router/state/events.log"
	eventLockFile     = "/etc/mini-router/state/events.lock"
	eventDevices      = "/etc/mini-router/state/devices.seen"
	eventBootFile     = "/etc/mini-router/state/boot.json"
	eventShutdownFile = "/etc/mini-router/state/shutdown.json"
	eventRunFile      = RunDir + "/events.json" // what the hooks saw: WANs up / down, health, when the next calls are due
	eventDueFile      = RunDir + "/event.due"   // uptime (s) at which mon-collect runs `mr event tick`
	eventSeenFile     = RunDir + "/leases.seen" // mtime = the lease file last scanned
	eventTickLock     = RunDir + "/event.tick"
	eventLeaseFile    = LeaseFile
	pstoreDir         = "/sys/fs/pstore"
	eventNow          = time.Now
	eventUptime       = func() float64 { return atof(firstField(readFile("/proc/uptime"))) }
	eventBootID       = func() string { return strings.TrimSpace(readFile("/proc/sys/kernel/random/boot_id")) }
)

// eventClean makes text from anywhere safe for the log, a notification and a terminal: one line of
// printable characters, at most max bytes (cut at a rune boundary).
func eventClean(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == 0xfffd {
			return ' '
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > max {
		cut := max
		for cut > 0 && (s[cut]&0xc0) == 0x80 {
			cut--
		}
		s = s[:cut] + "…"
	}
	return s
}

// flock opens path and takes an exclusive lock (wait false: nil when someone else holds it).
func flock(path string, wait bool) *os.File {
	os.MkdirAll(filepath.Dir(path), 0755)
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil
	}
	how := syscall.LOCK_EX
	if !wait {
		how |= syscall.LOCK_NB
	}
	if syscall.Flock(int(f.Fd()), how) != nil {
		f.Close()
		return nil
	}
	return f
}

// eventAdd appends one event. kick: start a background flush when a notification channel wants
// this type (false at boot before OpenRC, where nothing may be started: the boot event sends it).
// c may be nil (the config is loaded only when a flush could be needed).
func eventAdd(c *Config, typ, sev, key, msg string, kick bool) {
	e := event{Time: eventNow().Unix(), Type: typ, Sev: sev, Key: eventClean(key, 64), Msg: eventClean(msg, eventMsgMax)}
	if err := eventAppend(&e); err != nil {
		logf("event %s: %v", typ, err)
		return
	}
	if !kick {
		return
	}
	if c == nil {
		lc, err := loadConfig(ConfigPath, SecretsPath)
		if err != nil {
			return
		}
		c = lc
	}
	if notifyWants(c, typ) {
		notifyKick()
	}
}

// eventAppend gives e the next sequence number and appends it, trimming the log when it is long.
func eventAppend(e *event) error {
	lk := flock(eventLockFile, true)
	if lk == nil {
		return errors.New("cannot lock " + eventLockFile)
	}
	defer lk.Close()
	data, err := os.ReadFile(eventLog)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	lines := eventLines(data)
	if len(lines) > 0 {
		var last event
		if json.Unmarshal(lines[len(lines)-1], &last) == nil {
			e.Seq = last.Seq
		}
	}
	e.Seq++
	b, _ := json.Marshal(e)
	b = append(b, '\n')
	if len(lines)+1 > eventTrimLines || len(data)+len(b) > eventTrimBytes {
		keep := lines
		if len(keep) > eventKeep-1 {
			keep = keep[len(keep)-(eventKeep-1):]
		}
		var out []byte
		for _, l := range keep {
			out = append(append(out, l...), '\n')
		}
		return writeAtomic(eventLog, append(out, b...), 0600)
	}
	f, err := os.OpenFile(eventLog, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	if len(data) > 0 && data[len(data)-1] != '\n' { // a torn last line (power cut) must not swallow this one
		b = append([]byte{'\n'}, b...)
	}
	_, err = f.Write(b)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// eventLines: the non-empty lines of the log.
func eventLines(data []byte) [][]byte {
	var out [][]byte
	for _, l := range bytes.Split(data, []byte{'\n'}) {
		if len(bytes.TrimSpace(l)) > 0 {
			out = append(out, l)
		}
	}
	return out
}

// eventsRead returns the events with seq > after, oldest first (at most max, the newest; 0 = all).
func eventsRead(after int64, max int) []event {
	data, _ := os.ReadFile(eventLog)
	out := []event{}
	for _, l := range eventLines(data) {
		var e event
		if json.Unmarshal(l, &e) == nil && e.Seq > after && e.Type != "" {
			out = append(out, e)
		}
	}
	if max > 0 && len(out) > max {
		out = out[len(out)-max:]
	}
	return out
}

// eventLastSeq: the sequence number of the newest event (0: none).
func eventLastSeq() int64 {
	ev := eventsRead(0, 1)
	if len(ev) == 0 {
		return 0
	}
	return ev[0].Seq
}

// ---- runtime state (/run: what the hooks saw) ----

type eventRun struct {
	Up         map[string]int64  `json:"up,omitempty"`     // WAN -> since (unix): up as the hooks last saw it
	Down       map[string]int64  `json:"down,omitempty"`   // WAN -> since: went down after being up
	Health     map[string]string `json:"health,omitempty"` // WAN -> up | down (multi-WAN health checker)
	Doctor     map[string]string `json:"doctor,omitempty"` // finding id -> warn | risk of the last background run
	DoctorNext float64           `json:"doctor_next,omitempty"`
	NotifyDue  float64           `json:"notify_due,omitempty"`
}

// eventRunUpdate changes the runtime state under its lock and rewrites event.due.
func eventRunUpdate(f func(s *eventRun)) {
	lk := flock(eventRunFile+".lock", true)
	if lk != nil {
		defer lk.Close()
	}
	var s eventRun
	if b, err := os.ReadFile(eventRunFile); err == nil {
		json.Unmarshal(b, &s)
	}
	if s.Up == nil {
		s.Up = map[string]int64{}
	}
	if s.Down == nil {
		s.Down = map[string]int64{}
	}
	f(&s)
	b, _ := json.Marshal(s)
	if err := writeAtomic(eventRunFile, b, 0600); err != nil {
		logf("event: %v", err)
	}
	due := 0.0
	for _, t := range []float64{s.DoctorNext, s.NotifyDue} {
		if t > 0 && (due == 0 || t < due) {
			due = t
		}
	}
	if due == 0 {
		os.Remove(eventDueFile)
	} else {
		writeAtomic(eventDueFile, []byte(fmt.Sprintf("%d\n", int64(due))), 0644)
	}
}

func eventRunRead() eventRun {
	var s eventRun
	if b, err := os.ReadFile(eventRunFile); err == nil {
		json.Unmarshal(b, &s)
	}
	return s
}

// ---- WAN events (OnWAN) ----

func eventOnWAN(c *Config, wan, ev string) {
	now := eventNow().Unix()
	switch ev {
	case "up":
		var down int64
		eventRunUpdate(func(s *eventRun) {
			if _, ok := s.Up[wan]; !ok {
				s.Up[wan] = now
			}
			down = s.Down[wan]
			delete(s.Down, wan)
		})
		if down > 0 { // only a recovery: the first "up" after boot and DHCP renewals are not events
			eventAdd(c, "wan_up", "info", wan, fmt.Sprintf("%s is connected again after %s down", wan, fmtSecs(now-down)), true)
		}
	case "down":
		was := false
		eventRunUpdate(func(s *eventRun) {
			if _, ok := s.Up[wan]; ok {
				was = true
				delete(s.Up, wan)
				s.Down[wan] = now
			}
		})
		if was { // udhcpc starts with "deconfig": not a loss
			how := "lost its connection"
			if w := c.WANByName(wan); w != nil {
				how += " (" + w.Proto + " on " + w.Ifname() + ")"
			}
			eventAdd(c, "wan_down", "warn", wan, wan+" "+how, true)
		}
	case "health":
		eventHealth(c)
	}
}

// eventHealth compares the multi-WAN health checker's view with the last one seen: a WAN that turned
// down or up again is a failover event. The first view (checker start) only records.
func eventHealth(c *Config) {
	now := map[string]string{}
	if c.MultiWAN.Enabled() {
		if f, ok := readWanHealth(); ok {
			for _, w := range f.WANs {
				now[w.Name] = w.State
			}
		}
	}
	var prev map[string]string
	eventRunUpdate(func(s *eventRun) { prev, s.Health = s.Health, now })
	if len(now) == 0 {
		return
	}
	names := make([]string, 0, len(now))
	for n := range now {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		old, ok := prev[n]
		if !ok || old == now[n] {
			continue
		}
		if now[n] == "down" {
			to := "no other WAN is healthy"
			for _, w := range sortedWANs(c, now) {
				if now[w.Name] != "down" {
					to = "traffic moves to " + w.Name
					break
				}
			}
			eventAdd(c, "failover", "warn", n, fmt.Sprintf("%s fails its health check; %s", n, to), true)
		} else {
			eventAdd(c, "failover", "info", n, n+" passes its health check again", true)
		}
	}
}

// ---- apply / rollback (history.go setResult) ----

// eventChange records how a change ended. A rollback at boot runs before OpenRC: logged only, the
// boot event's flush sends it.
func eventChange(r revision) {
	what := fmt.Sprintf("change #%d (%s", r.Rev, r.Via)
	if r.Comment != "" {
		what += ": " + r.Comment
	}
	what += ")"
	key := fmt.Sprint(r.Rev)
	switch {
	case r.Result == "applied" || r.Result == "confirmed":
		eventAdd(nil, "apply", "info", key, what+" "+r.Result, true)
	case strings.HasPrefix(r.Result, "rolled back"):
		eventAdd(nil, "rollback", "warn", key, what+" "+r.Result, !strings.Contains(r.Result, "at boot"))
	}
}

// eventLoginLock: the login throttle locked a source (web UI passwords or API tokens, api_login.go).
func eventLoginLock(remote, what string, locked time.Duration) {
	eventAdd(nil, "login_lock", "warn", loginKey(remote), fmt.Sprintf("%d failed %s from %s: locked for %s", loginMax, what, remote, locked), true)
}

// ---- new devices (mr event tick) ----

// eventLearn: after the list of seen MACs is created, new clients are only recorded for this long —
// dnsmasq's lease file is in RAM, so the devices of the house come back one by one as they renew.
const eventLearn = 24 * 3600

// eventScanLeases reports DHCP clients whose MAC was never seen (dhcp.hosts count as known). The
// list of seen MACs is on flash (a reboot reports nothing); for a day after it is created it only
// learns.
func eventScanLeases(c *Config) {
	now := eventNow()
	os.MkdirAll(filepath.Dir(eventSeenFile), 0755)
	if f, err := os.OpenFile(eventSeenFile, os.O_CREATE|os.O_WRONLY, 0644); err == nil {
		f.Close()
	}
	os.Chtimes(eventSeenFile, now, now) // before reading: a change from here on triggers the next scan
	v4, _ := parseLeases(readFile(eventLeaseFile))
	seenData, err := os.ReadFile(eventDevices)
	learnUntil := int64(0)
	if os.IsNotExist(err) {
		learnUntil = now.Unix() + eventLearn
	}
	var order []string
	known := map[string]bool{}
	for _, l := range strings.Split(string(seenData), "\n") {
		if t, ok := strings.CutPrefix(l, "# learning until "); ok {
			learnUntil = int64(atoi(strings.TrimSpace(t)))
		}
		if m := strings.ToLower(strings.TrimSpace(l)); reMAC.MatchString(m) && !known[m] {
			known[m] = true
			order = append(order, m)
		}
	}
	learning := now.Unix() < learnUntil
	for _, h := range c.DHCP.Hosts {
		known[strings.ToLower(h.MAC)] = true
	}
	added := false
	for _, l := range v4 {
		mac := strings.ToLower(l.MAC)
		if !reMAC.MatchString(mac) || known[mac] {
			continue
		}
		known[mac] = true
		order = append(order, mac)
		added = true
		if learning {
			continue
		}
		name := l.Name
		if name == "*" || name == "" {
			name = "(no name)"
		}
		where := ""
		if n := lanNetFor(c, net.ParseIP(l.IP)); n != nil {
			where = " on " + n.Name
		}
		priv := ""
		if b := mac[1]; b == '2' || b == '6' || b == 'a' || b == 'e' {
			priv = ", private MAC"
		}
		eventAdd(c, "new_device", "info", mac, fmt.Sprintf("%s (%s%s) got %s%s", eventClean(name, 64), mac, priv, l.IP, where), true)
	}
	if seenData == nil || added {
		if len(order) > eventSeenMax {
			order = order[len(order)-eventSeenMax:]
		}
		head := ""
		if learning {
			head = fmt.Sprintf("# learning until %d\n", learnUntil)
		}
		if err := writeAtomic(eventDevices, []byte(head+strings.Join(order, "\n")+"\n"), 0600); err != nil {
			logf("event: %v", err)
		}
	}
}

// ---- boot / shutdown ----

type bootState struct {
	BootID  string   `json:"boot_id"`
	Version string   `json:"version"`
	Time    int64    `json:"time"`
	Pstore  []string `json:"pstore,omitempty"` // crash records already reported (name@mtime)
}

type shutdownMark struct {
	Time     int64  `json:"time"`
	Runlevel string `json:"runlevel,omitempty"`
	Why      string `json:"why,omitempty"`
}

// pstoreRecords: crash records the kernel kept over the reboot (ramoops), with the first line that
// says what happened.
func pstoreRecords() (ids []string, first string) {
	ents, _ := os.ReadDir(pstoreDir)
	for _, e := range ents {
		if !strings.HasPrefix(e.Name(), "dmesg-") {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		ids = append(ids, fmt.Sprintf("%s@%d", e.Name(), fi.ModTime().Unix()))
		if first == "" {
			first = crashLine(readFile(filepath.Join(pstoreDir, e.Name())))
			if first == "" {
				first = e.Name()
			}
		}
	}
	return ids, first
}

// crashMarks: kernel log text that means something went badly wrong.
var crashMarks = []string{"Kernel panic", "Internal error:", "Unable to handle kernel", "BUG:", "Oops", "Out of memory:",
	"soft lockup", "hard LOCKUP", "rcu_sched self-detected stall", "hung_task", "blocked for more than", "watchdog: "}

// crashLine: the first kernel log line with a crash mark (timestamp and level stripped).
func crashLine(s string) string {
	sc := bufio.NewScanner(strings.NewReader(s))
	sc.Buffer(make([]byte, 0, 4096), 1<<20)
	for sc.Scan() {
		l := sc.Text()
		for _, m := range crashMarks {
			if i := strings.Index(l, m); i >= 0 {
				if j := strings.Index(l, "] "); j >= 0 && j < i {
					l = l[j+2:]
				}
				return eventClean(l, 160)
			}
		}
	}
	return ""
}

// eventBoot records why the router (re)started, once per boot.
func eventBoot(c *Config) error {
	id := eventBootID()
	var prev bootState
	if b, err := os.ReadFile(eventBootFile); err == nil {
		json.Unmarshal(b, &prev)
	}
	if id != "" && prev.BootID == id {
		return nil
	}
	var mark *shutdownMark
	if b, err := os.ReadFile(eventShutdownFile); err == nil {
		var m shutdownMark
		if json.Unmarshal(b, &m) == nil {
			mark = &m
		}
		os.Remove(eventShutdownFile)
	}
	ids, first := pstoreRecords()
	reported := map[string]bool{}
	for _, x := range prev.Pstore {
		reported[x] = true
	}
	crash := false
	for _, x := range ids {
		crash = crash || !reported[x]
	}
	upgraded := prev.Version != "" && prev.Version != version
	sev, msg := "info", "booted"
	switch {
	case crash:
		sev, msg = "warn", "booted after a kernel crash: "+first
	case mark != nil:
		msg = "booted after a clean " + map[bool]string{true: "shutdown", false: "reboot"}[mark.Runlevel == "shutdown"]
		if mark.Why != "" {
			msg += " (" + mark.Why + ")"
		}
		if mark.Time > 0 {
			msg += ", down " + fmtSecs(eventNow().Unix()-mark.Time)
		}
	case upgraded:
		msg = "booted the new firmware"
	case prev.BootID != "":
		sev, msg = "warn", "booted after an unexpected restart (power cut, hang or hardware watchdog)"
	}
	eventAdd(c, "boot", sev, "", msg, true)
	if upgraded {
		eventAdd(c, "upgrade", "info", "", "mr "+prev.Version+" → "+version, true)
	}
	st := bootState{BootID: id, Version: version, Time: eventNow().Unix(), Pstore: ids}
	b, _ := json.Marshal(st)
	if err := writeAtomic(eventBootFile, b, 0600); err != nil {
		return err
	}
	eventSchedule(c)
	return nil
}

// eventShutdown marks a clean stop (mr-bootlog's stop while OpenRC goes down), with the reason the
// change log gives for a reboot of the last 15 minutes (schedule, web UI).
func eventShutdown() error {
	m := shutdownMark{Time: eventNow().Unix(), Runlevel: os.Getenv("RC_RUNLEVEL")}
	lines := strings.Split(strings.TrimSpace(readFile(ChangeLog)), "\n")
	if l := lines[len(lines)-1]; strings.Contains(l, "reboot") && len(l) > 20 {
		if t, err := time.ParseInLocation("2006-01-02 15:04:05", l[:19], time.Local); err == nil && eventNow().Sub(t) < 15*time.Minute {
			m.Why = eventClean(l[20:], 80)
		}
	}
	b, _ := json.Marshal(m)
	return writeAtomic(eventShutdownFile, b, 0600)
}

// ---- tick (mon-collect) ----

// eventSchedule sets when the next background health check is due (none without an interval).
func eventSchedule(c *Config) {
	iv := notifyDoctorInterval(c)
	up := eventUptime()
	eventRunUpdate(func(s *eventRun) {
		switch {
		case iv == 0:
			s.DoctorNext = 0
		case s.DoctorNext == 0 || s.DoctorNext > up+float64(iv*60):
			s.DoctorNext = max(up, eventBootQuiet)
		}
	})
}

// eventTick: called by mr-mon's sampler when the lease file changed or event.due has come.
func eventTick(c *Config) error {
	lk := flock(eventTickLock, false)
	if lk == nil {
		return nil // the previous tick still runs
	}
	defer lk.Close()
	if fi, err := os.Stat(eventLeaseFile); err == nil {
		if st, err := os.Stat(eventSeenFile); err != nil || fi.ModTime().After(st.ModTime()) || fi.ModTime().Equal(st.ModTime()) {
			eventScanLeases(c)
		}
	}
	up := eventUptime()
	if iv := notifyDoctorInterval(c); iv > 0 {
		if s := eventRunRead(); s.DoctorNext > 0 && up >= s.DoctorNext {
			eventRunUpdate(func(s *eventRun) { s.DoctorNext = up + float64(iv*60) })
			doctorEvents(c, runDoctor(c, newDocEnv()))
		}
	}
	eventSchedule(c)
	_, err := notifyFlush(c, notifyRun{})
	return err
}

// ---- mr event, API ----

// eventCommand: `mr event list [--json] [N] | tick | boot | shutdown`.
func eventCommand(c *Config, args []string) error {
	usage := errors.New("usage: mr event list [--json] [N] | tick | boot | shutdown")
	if len(args) == 0 {
		return usage
	}
	switch args[0] {
	case "list":
		asJSON, n := false, 50
		for _, a := range args[1:] {
			if a == "--json" {
				asJSON = true
			} else if v := atoi(a); v > 0 && v <= eventKeep {
				n = v
			} else {
				return usage
			}
		}
		ev := eventsRead(0, n)
		if asJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", " ")
			return enc.Encode(ev)
		}
		loc := sysLocation(c)
		for _, e := range ev {
			fmt.Printf("%s  %-4s %-12s %s\n", time.Unix(e.Time, 0).In(loc).Format("2006-01-02 15:04:05"), e.Sev, e.Type, e.Msg)
		}
		return nil
	case "tick":
		return eventTick(c)
	case "boot":
		return eventBoot(c)
	case "shutdown":
		return eventShutdown()
	}
	return usage
}

// apiSysEvents: GET → {events (newest first), notify: channel states, types}.
func apiSysEvents(r apiReq) apiResp {
	ev := eventsRead(0, eventKeep)
	for i, j := 0, len(ev)-1; i < j; i, j = i+1, j-1 {
		ev[i], ev[j] = ev[j], ev[i]
	}
	body := map[string]any{"events": ev, "types": eventTypes, "notify": []notifyStatus{}}
	if c, err := loadConfig(ConfigPath, SecretsPath); err == nil {
		body["notify"] = notifyStatuses(c)
	}
	return apiResp{body: body}
}

// eventRecent for `mr status` (overview): the newest n events, newest first.
func eventRecent(n int) []event {
	ev := eventsRead(0, n)
	for i, j := 0, len(ev)-1; i < j; i, j = i+1, j-1 {
		ev[i], ev[j] = ev[j], ev[i]
	}
	return ev
}

// fmtSecs: 45s, 3m12s, 2h05m, 3d4h.
func fmtSecs(s int64) string {
	switch {
	case s < 0:
		s = 0
		fallthrough
	case s < 60:
		return fmt.Sprintf("%ds", s)
	case s < 3600:
		return fmt.Sprintf("%dm%02ds", s/60, s%60)
	case s < 86400:
		return fmt.Sprintf("%dh%02dm", s/3600, s%3600/60)
	}
	return fmt.Sprintf("%dd%dh", s/86400, s%86400/3600)
}
