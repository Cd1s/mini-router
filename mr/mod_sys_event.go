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
//   - mr-mon's per-minute sampler (rootfs/usr/libexec/mr/mon-collect) starts `mr event tick` only when
//     dnsmasq's lease file is newer than /run/mini-router/leases.seen (new devices) or the uptime in
//     /run/mini-router/event.due has come (a notification retry, held events, the next background
//     `mr doctor`); any other minute costs a few shell builtins;
//   - mr-bootlog runs `mr event boot` at boot (why the router restarted: clean restart, kernel crash in
//     pstore, power cut / hang, new firmware) and `mr event shutdown` when OpenRC takes the system down.
//
// Log: /etc/mini-router/state/events.log — JSON lines {seq, t, type, sev, key, msg}, the newest 200
// kept (rewritten when it passes 250 lines or 96 KiB). On flash, because the events that matter most (a
// crash, a power cut, a rollback at boot) are the ones a RAM log loses. Flash writes are bounded: at
// most eventTypeHour lines of one type per hour are kept (a flapping WAN, a DHCP flood with random MACs
// or a password-guessing botnet only reach syslog after that), so the worst case is ~100 short appends
// and two rewrites an hour; a normal day writes a few lines. Text that comes from the network (DHCP host
// names, addresses) is cleaned of control characters and capped.

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
var eventTypes = []string{"wan_down", "wan_up", "failover", "apply", "rollback", "login_lock", "new_device", "boot", "upgrade", "doctor", "cert", "wifi", "ddns", "update", "archive", "watchcat", "device"}

// eventLabels: short names for notification lines.
var eventLabels = map[string]string{
	"wan_down": "WAN down", "wan_up": "WAN up", "failover": "Failover", "apply": "Change", "rollback": "Rollback",
	"login_lock": "Login locked", "new_device": "New device", "boot": "Boot", "upgrade": "Firmware", "doctor": "Health check",
	"cert": "Certificate", "wifi": "WiFi self-heal", "ddns": "DDNS", "update": "Update", "archive": "Archive", "watchcat": "Watchcat", "device": "Device",
}

const (
	eventKeep      = 200
	eventTrimLines = 250
	eventTrimBytes = 96 << 10
	eventMsgMax    = 300
	eventTypeHour  = 10   // lines of one type kept per hour (flash wear, floods); the rest goes to syslog only
	eventSeenMax   = 2048 // MACs remembered for new-device detection
	eventSeenSlack = 256  // appended before the list is rewritten to its newest eventSeenMax
	eventScanMax   = 5    // new devices reported one by one per scan; the rest as one line
	eventBootQuiet = 300  // s after boot before the first background health check (WANs dial, radios start)
)

// errEventCapped: the type already has eventTypeHour lines in the last hour.
var errEventCapped = errors.New("rate cap")

// paths and clocks (variables so tests can use a temp dir and fake time)
var (
	eventLog          = "/etc/mini-router/state/events.log"
	eventLockFile     = "/etc/mini-router/state/events.lock"
	eventDevices      = "/etc/mini-router/state/devices.seen"
	eventBootFile     = "/etc/mini-router/state/boot.json"
	eventShutdownFile = "/etc/mini-router/state/shutdown.json"
	eventRunFile      = RunDir + "/events.json" // what the hooks saw: WANs up / down, health, when the next calls are due
	eventDueFile      = RunDir + "/event.due"   // uptime (s) at which mon-collect starts `mr event tick`
	eventSeenFile     = RunDir + "/leases.seen" // mtime: just before the lease file was last scanned
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

// eventAdd appends one event and reports whether it was kept. kick: start a background flush when a
// notification channel wants this type (false at boot before OpenRC, where nothing may be started —
// the boot event sends it — and for batches, which call eventKick once). c may be nil (the config is
// loaded only when a flush could be needed).
func eventAdd(c *Config, typ, sev, key, msg string, kick bool) bool {
	e := event{Time: eventNow().Unix(), Type: typ, Sev: sev, Key: eventClean(key, 64), Msg: eventClean(msg, eventMsgMax)}
	if err := eventAppend(&e); err != nil {
		if err == errEventCapped {
			logf("event %s (not kept, %d in the last hour): %s", typ, eventTypeHour, e.Msg)
		} else {
			logf("event %s: %v", typ, err)
		}
		return false
	}
	if kick {
		eventKick(c, typ)
	}
	return true
}

// eventKick starts a background flush when some channel wants events of type typ.
func eventKick(c *Config, typ string) {
	if c == nil {
		lc, err := loadConfig(sysConfigPath, sysSecretsPath)
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
	seq, n := int64(0), 0
	for _, l := range lines { // the highest seq, not the last line's: a power cut can tear the last line
		var x event
		if json.Unmarshal(l, &x) != nil {
			continue
		}
		seq = max(seq, x.Seq)
		if x.Type == e.Type && x.Time > e.Time-3600 && x.Time <= e.Time {
			n++
		}
	}
	if n >= eventTypeHour {
		return errEventCapped
	}
	e.Seq = seq + 1
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
	lines := eventLines(data)
	out := []event{}
	for i := len(lines) - 1; i >= 0 && (max <= 0 || len(out) < max); i-- { // newest first: `mr status` wants 8
		var e event
		if json.Unmarshal(lines[i], &e) == nil && e.Seq > after && e.Type != "" {
			out = append(out, e)
		}
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
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
	WatchNext  float64           `json:"watch_next,omitempty"` // devices[].watch: the next presence sample (dev module)
	NotifyDue  float64           `json:"notify_due,omitempty"`
}

// eventRunUpdate changes the runtime state under its lock and rewrites event.due.
func eventRunUpdate(f func(s *eventRun)) {
	lk := flock(eventRunFile+".lock", true)
	if lk != nil {
		defer lk.Close()
	}
	var s eventRun
	readJSONFile(eventRunFile, &s)
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
	for _, t := range []float64{s.DoctorNext, s.NotifyDue, s.WatchNext} {
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
	readJSONFile(eventRunFile, &s)
	return s
}

// ---- WAN events (OnWAN) ----

// changeLogTail: the last lines of the change log (its last 4 KiB).
func changeLogTail() []string {
	f, err := os.Open(ChangeLog)
	if err != nil {
		return nil
	}
	defer f.Close()
	if fi, err := f.Stat(); err == nil && fi.Size() > 4096 {
		f.Seek(-4096, 2)
	}
	b := make([]byte, 4096)
	n, _ := f.Read(b)
	return strings.Split(strings.TrimSpace(string(b[:n])), "\n")
}

// changeLogRecent: the text of change-log lines of the last d, newest first ("2006-01-02 15:04:05 text").
func changeLogRecent(d time.Duration) []string {
	var out []string
	lines := changeLogTail()
	for i := len(lines) - 1; i >= 0; i-- {
		l := lines[i]
		if len(l) < 21 {
			continue
		}
		t, err := time.ParseInLocation("2006-01-02 15:04:05", l[:19], time.Local)
		if err != nil {
			continue
		}
		if eventNow().Sub(t) > d {
			break
		}
		out = append(out, l[20:])
	}
	return out
}

// eventWANExpected: why a WAN going down or up now is no surprise. quiet: the system is going down
// (a clean stop marked by `mr event shutdown`): not an event at all. why: an apply or a rollback is
// running, or the change log of the last two minutes names a redial / reconnect / restart of this
// WAN or its service (web UI, schedule, agent) — then the events are info, with the reason.
func eventWANExpected(wan string) (why string, quiet bool) {
	var m shutdownMark
	if readJSONFile(eventShutdownFile, &m); m.Time > 0 && m.BootID == eventBootID() && eventNow().Unix()-m.Time < 600 {
		return "", true
	}
	if p, err := readPending(); err == nil && (p.State == stateApplying || p.State == stateReverting) {
		return "a change was being applied", false
	}
	for _, l := range changeLogRecent(2 * time.Minute) {
		f := strings.Fields(l)
		if len(f) < 2 {
			continue
		}
		target := f[len(f)-1] // "webui: redial wan NAME", "schedule: reconnect NAME", "…: restart mr-pppoe.NAME"
		if i := strings.LastIndexByte(target, '.'); i >= 0 {
			target = target[i+1:]
		}
		if target == wan {
			return eventClean(l, 60), false
		}
	}
	return "", false
}

func eventOnWAN(c *Config, wan, ev string) {
	now := eventNow().Unix()
	sev, note, quiet := "warn", "", false
	if ev == "up" || ev == "down" {
		var why string
		if why, quiet = eventWANExpected(wan); why != "" {
			sev, note = "info", " ("+why+")"
		}
	}
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
		if down > 0 && !quiet { // only a recovery: the first "up" after boot and DHCP renewals are not events
			eventAdd(c, "wan_up", "info", wan, fmt.Sprintf("%s is connected again after %s down%s", wan, fmtSecs(now-down), note), true)
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
		if was && !quiet { // udhcpc starts with "deconfig": not a loss
			how := "lost its connection"
			if w := c.WANByName(wan); w != nil {
				how += " (" + w.Proto + " on " + w.Ifname() + ")"
			}
			eventAdd(c, "wan_down", sev, wan, wan+" "+how+note, true)
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
	names := make([]string, 0, len(now))
	for n := range now {
		names = append(names, n)
	}
	sort.Strings(names)
	added := false
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
			added = eventAdd(c, "failover", "warn", n, fmt.Sprintf("%s fails its health check; %s", n, to), false) || added
		} else {
			added = eventAdd(c, "failover", "info", n, n+" passes its health check again", false) || added
		}
	}
	if added {
		eventKick(c, "failover")
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
		archiveAfterChange()
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

// eventScanLeases reports DHCP clients whose MAC was never seen (dhcp.hosts count as known). The list
// of seen MACs is on flash (a reboot reports nothing); for a day after it is created it only learns.
// New MACs are appended (18 bytes each); the list is rewritten to its newest eventSeenMax only when it
// has grown eventSeenSlack past that. At most eventScanMax devices are reported one by one per scan.
func eventScanLeases(c *Config) {
	now := eventNow()
	os.MkdirAll(filepath.Dir(eventSeenFile), 0755)
	if f, err := os.OpenFile(eventSeenFile, os.O_CREATE|os.O_WRONLY, 0644); err == nil {
		f.Close()
	}
	// before reading, and a second early: a lease written later (even within this second) is newer,
	// so mon-collect's `[ leases -nt seen ]` never misses one (at worst one scan too many)
	os.Chtimes(eventSeenFile, now.Add(-time.Second), now.Add(-time.Second))
	v4, _ := parseLeases(readFile(eventLeaseFile))
	seenData, err := os.ReadFile(eventDevices)
	fresh := os.IsNotExist(err)
	learnUntil := int64(0)
	if fresh {
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
	for _, h := range c.knownHosts() { // dhcp.hosts and the device inventory are never "new"
		known[strings.ToLower(h.MAC)] = true
	}
	var added []string
	var report []lease
	for _, l := range v4 {
		mac := strings.ToLower(l.MAC)
		if !reMAC.MatchString(mac) || known[mac] {
			continue
		}
		known[mac] = true
		added = append(added, mac)
		if !learning {
			report = append(report, l)
		}
	}
	kept := false
	for i, l := range report {
		if i == eventScanMax {
			kept = eventAdd(c, "new_device", "info", "", fmt.Sprintf("%d more new devices (mr dns leases)", len(report)-i), false) || kept
			break
		}
		name := l.Name
		if name == "*" || name == "" {
			name = "(no name)"
		}
		where := ""
		if n := lanNetFor(c, net.ParseIP(l.IP)); n != nil {
			where = " on " + n.Name
		}
		mac := strings.ToLower(l.MAC)
		priv := ""
		if b := mac[1]; b == '2' || b == '6' || b == 'a' || b == 'e' { // locally administered: randomized
			priv = ", private MAC"
		}
		kept = eventAdd(c, "new_device", "info", mac, fmt.Sprintf("%s (%s%s) got %s%s", eventClean(name, 64), mac, priv, l.IP, where), false) || kept
	}
	if kept {
		eventKick(c, "new_device")
	}
	all := append(order, added...)
	switch {
	case fresh || len(all) > eventSeenMax+eventSeenSlack:
		if len(all) > eventSeenMax {
			all = all[len(all)-eventSeenMax:]
		}
		head := ""
		if learning {
			head = fmt.Sprintf("# learning until %d\n", learnUntil)
		}
		body := strings.Join(all, "\n")
		if body != "" {
			body += "\n"
		}
		if err := writeAtomic(eventDevices, []byte(head+body), 0600); err != nil {
			logf("event: %v", err)
		}
	case len(added) > 0:
		f, err := os.OpenFile(eventDevices, os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			logf("event: %v", err)
			return
		}
		b := strings.Join(added, "\n") + "\n"
		if len(seenData) > 0 && seenData[len(seenData)-1] != '\n' {
			b = "\n" + b
		}
		f.WriteString(b)
		f.Close()
	}
}

// ---- boot / shutdown ----

type bootState struct {
	BootID  string   `json:"boot_id"`
	Version string   `json:"version"`
	Time    int64    `json:"time"`
	Pstore  []string `json:"pstore,omitempty"` // crash records already reported (name@mtime)
}

// shutdownMark: written by `mr event shutdown` while OpenRC stops the system (reboot and power-off
// both run the "shutdown" runlevel: Alpine's inittab), read by the next `mr event boot`.
type shutdownMark struct {
	Time   int64  `json:"time"`
	BootID string `json:"boot_id,omitempty"` // the boot that ended cleanly (a mark left by an older boot is stale)
	Why    string `json:"why,omitempty"`
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

// crashMarks: kernel log text that means something went badly wrong. Not "watchdog: " — the watchdog
// driver announces itself with it at every boot ("1001c000.watchdog: Watchdog enabled"); the lockup
// detectors' lines are matched by "soft lockup" / "hard LOCKUP".
var crashMarks = []string{"Kernel panic", "Internal error:", "Unable to handle kernel", "BUG:", "Oops:", "Out of memory:",
	"soft lockup", "hard LOCKUP", "self-detected stall", "detected stalls on CPU", "blocked for more than"}

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

// eventBoot records why the router (re)started, once per boot. mr-bootlog runs it as the last boot
// service, before NTP may have synced: the clock is then mr-clock's last saved time, so the downtime
// is only given when NTP already agrees. c is nil when router.yaml does not load (recorded, nothing
// scheduled). The first boot of a new version saves what `mr plan` would change (mod_sys_update.go).
func eventBoot(c *Config) error {
	id := eventBootID()
	var prev bootState
	readJSONFile(eventBootFile, &prev)
	var mark *shutdownMark
	if b, err := os.ReadFile(eventShutdownFile); err == nil {
		var m shutdownMark
		if json.Unmarshal(b, &m) == nil && m.BootID != id && (prev.BootID == "" || m.BootID == "" || m.BootID == prev.BootID) {
			mark = &m
		}
		// consumed; a mark of this very boot came from a restart of mr-bootlog, not a shutdown
		os.Remove(eventShutdownFile)
	}
	if id != "" && prev.BootID == id {
		return nil
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
		msg = "booted after a clean restart"
		if mark.Why != "" {
			msg += " (" + mark.Why + ")"
		}
		if synced, _, _ := ntpMarker(); synced && mark.Time > 0 && eventNow().Unix() > mark.Time {
			msg += ", down " + fmtSecs(eventNow().Unix()-mark.Time)
		}
	case upgraded:
		msg = "booted the new firmware"
	case prev.BootID != "":
		sev, msg = "warn", "booted after an unexpected restart (power cut, hang or hardware watchdog)"
	}
	eventAdd(c, "boot", sev, "", msg, false)
	if c == nil {
		eventAdd(nil, "boot", "risk", "config", "router.yaml / secrets.yaml do not load: mr validate", false)
	}
	if upgraded {
		eventAdd(c, "upgrade", "info", "", "mr "+prev.Version+" → "+version, false)
		if c != nil {
			upgradePlanKick()
		}
	}
	st := bootState{BootID: id, Version: version, Time: eventNow().Unix(), Pstore: ids}
	b, _ := json.Marshal(st)
	if err := writeAtomic(eventBootFile, b, 0600); err != nil {
		return err
	}
	if c == nil {
		return nil
	}
	eventSchedule(c)
	if len(c.Notify.Channels) > 0 { // the boot event and what was logged before OpenRC (a rollback at boot)
		notifyKick()
	}
	return nil
}

// eventShutdown marks a clean stop (mr-bootlog's stop while OpenRC goes down, and sysupgrade before its
// kexec), with the reason the change log gives for a reboot or sysupgrade of the last 15 minutes.
func eventShutdown() error {
	m := shutdownMark{Time: eventNow().Unix(), BootID: eventBootID()}
	if r := changeLogRecent(15 * time.Minute); len(r) > 0 {
		switch {
		case strings.Contains(r[0], "sysupgrade"): // the kexec skips OpenRC: sysupgrade marks its stop itself
			m.Why = "sysupgrade"
		case strings.Contains(r[0], "reboot"):
			m.Why = eventClean(r[0], 80)
		}
	}
	b, _ := json.Marshal(m)
	return writeAtomic(eventShutdownFile, b, 0600)
}

// ---- tick (mon-collect) ----

// eventSchedule sets when the next background health check is due (none without an interval) and
// drops a notification retry when no channel is left.
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
		if len(c.Notify.Channels) == 0 {
			s.NotifyDue = 0
		}
		switch {
		case len(devWatched(c)) == 0:
			s.WatchNext = 0
		case s.WatchNext == 0 || s.WatchNext > up+60:
			s.WatchNext = up
		}
	})
}

// eventTick: started by mr-mon's sampler when the lease file changed or event.due has come.
func eventTick(c *Config) error {
	lk := flock(eventTickLock, false)
	if lk == nil {
		return nil // the previous tick still runs
	}
	defer lk.Close()
	if fi, err := os.Stat(eventLeaseFile); err == nil {
		if st, err := os.Stat(eventSeenFile); err != nil || fi.ModTime().After(st.ModTime()) {
			eventScanLeases(c)
		}
	}
	up := eventUptime()
	if iv := notifyDoctorInterval(c); iv > 0 {
		if s := eventRunRead(); s.DoctorNext > 0 && up >= s.DoctorNext {
			eventRunUpdate(func(s *eventRun) { s.DoctorNext = up + float64(iv*60) })
			e := newDocEnv()
			if c.Notify.AutoHeal {
				doctorHeal(c, e)
			}
			doctorEvents(c, runDoctor(c, e))
		}
	}
	if s := eventRunRead(); s.WatchNext > 0 && up >= s.WatchNext || len(devWatched(c)) == 0 && fileExists(devWatchFile) {
		eventRunUpdate(func(s *eventRun) { s.WatchNext = up + 55 }) // mon-collect samples once a minute
		devWatchPass(c)
	}
	eventSchedule(c)
	if len(c.Notify.Channels) == 0 {
		return nil
	}
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
			fmt.Printf("%s  %-4s %-10s %s\n", time.Unix(e.Time, 0).In(loc).Format("2006-01-02 15:04:05"), e.Sev, e.Type, e.Msg)
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
	body := map[string]any{"events": eventRecent(eventKeep), "types": eventTypes, "notify": []notifyStatus{}}
	if c, err := loadConfig(sysConfigPath, sysSecretsPath); err == nil {
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
