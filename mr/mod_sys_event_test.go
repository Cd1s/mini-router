package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestMain keeps every test of the package off the host's /etc/mini-router/state and /run: the
// event log, the notification state and the doctor result go to a temp dir, and nothing starts a
// background `mr notify flush` (it would run the test binary). Hooks, applies and the login throttle
// all append events, so this covers tests that never think about them.
func TestMain(m *testing.M) {
	d, err := os.MkdirTemp("", "mr-events-")
	if err != nil {
		panic(err)
	}
	eventPaths(d)
	sysConfigPath, sysSecretsPath = filepath.Join(d, "none", "router.yaml"), filepath.Join(d, "none", "secrets.yaml")
	notifyKick = func() {}
	upgradePlanKick, archiveKick = func() {}, func() {}
	code := m.Run()
	os.RemoveAll(d)
	os.Exit(code)
}

// eventPaths points every event / notify / doctor file under d.
func eventPaths(d string) {
	eventLog, eventLockFile, eventDevices = filepath.Join(d, "events.log"), filepath.Join(d, "events.lock"), filepath.Join(d, "devices.seen")
	eventBootFile, eventShutdownFile = filepath.Join(d, "boot.json"), filepath.Join(d, "shutdown.json")
	eventRunFile, eventDueFile, eventSeenFile = filepath.Join(d, "run", "events.json"), filepath.Join(d, "run", "event.due"), filepath.Join(d, "run", "leases.seen")
	eventTickLock, eventLeaseFile, pstoreDir = filepath.Join(d, "run", "event.tick"), filepath.Join(d, "dhcp.leases"), filepath.Join(d, "pstore")
	notifyCursorFile, notifyStateFile = filepath.Join(d, "notify.json"), filepath.Join(d, "run", "notify.json")
	notifyLockFile, notifyWaitFile = filepath.Join(d, "run", "notify.lock"), filepath.Join(d, "run", "notify.wait")
	doctorFile, ntpSyncDir = filepath.Join(d, "run", "doctor.json"), filepath.Join(d, "mr-clock")
	upgradePlanFile, healFile, updateStateFile = filepath.Join(d, "run", "upgrade-plan.txt"), filepath.Join(d, "run", "heal.json"), filepath.Join(d, "update.json")
}

// eventEnv: a fresh state dir, a fake clock (now) and uptime (*up), kicks counted in *kicks.
func eventEnv(t *testing.T) (d string, now *time.Time, up *float64, kicks *int) {
	t.Helper()
	d = t.TempDir()
	saved := []any{eventLog, eventLockFile, eventDevices, eventBootFile, eventShutdownFile, eventRunFile, eventDueFile, eventSeenFile,
		eventTickLock, eventLeaseFile, pstoreDir, notifyCursorFile, notifyStateFile, notifyLockFile, notifyWaitFile, doctorFile, ntpSyncDir}
	oNow, oUp, oID, oKick, oConfirm, oChange, oVersion := eventNow, eventUptime, eventBootID, notifyKick, ConfirmFile, ChangeLog, version
	t.Cleanup(func() {
		p := []*string{&eventLog, &eventLockFile, &eventDevices, &eventBootFile, &eventShutdownFile, &eventRunFile, &eventDueFile, &eventSeenFile,
			&eventTickLock, &eventLeaseFile, &pstoreDir, &notifyCursorFile, &notifyStateFile, &notifyLockFile, &notifyWaitFile, &doctorFile, &ntpSyncDir}
		for i := range p {
			*p[i] = saved[i].(string)
		}
		eventNow, eventUptime, eventBootID, notifyKick, ConfirmFile, ChangeLog, version = oNow, oUp, oID, oKick, oConfirm, oChange, oVersion
	})
	eventPaths(d)
	ConfirmFile, ChangeLog = filepath.Join(d, "confirm-pending"), filepath.Join(d, "changes.log")
	t0 := time.Unix(1_800_000_000, 0)
	now, up, kicks = &t0, new(float64), new(int)
	*up = 1000
	eventNow = func() time.Time { return *now }
	eventUptime = func() float64 { return *up }
	eventBootID = func() string { return "boot-1" }
	notifyKick = func() { *kicks++ }
	return d, now, up, kicks
}

func eventTypesOf(ev []event) string {
	var s []string
	for _, e := range ev {
		s = append(s, e.Type)
	}
	return strings.Join(s, ",")
}

func TestEventClean(t *testing.T) {
	for in, want := range map[string]string{
		"a\nb\tc\x00d\x1b[31me": "a b c d [31me",
		"  lots   of\r\nspace ": "lots of space",
		"bidi\u0085x\u00a0ok":   "bidi x ok",
		"bad \xff utf8":         "bad utf8",
	} {
		if got := eventClean(in, 100); got != want {
			t.Errorf("eventClean(%q) = %q, want %q", in, got, want)
		}
	}
	if got := eventClean("设备设备设备", 7); got != "设备…" { // cut at a rune boundary
		t.Errorf("rune cut: %q", got)
	}
}

// Sequence numbers keep growing across trims and a torn last line; the log keeps the newest 200;
// one type is kept at most eventTypeHour times an hour, other types are not affected.
func TestEventAppend(t *testing.T) {
	_, now, _, _ := eventEnv(t)
	for i := 0; i < 260; i++ {
		*now = now.Add(time.Hour) // one an hour: never capped
		if !eventAdd(nil, "boot", "info", "", fmt.Sprint("booted ", i), false) {
			t.Fatal("event not kept")
		}
	}
	ev := eventsRead(0, 0)
	if len(ev) < eventKeep || len(ev) > eventTrimLines || ev[len(ev)-1].Seq != 260 || ev[len(ev)-1].Msg != "booted 259" {
		t.Fatalf("after 260 events: %d kept, last %+v", len(ev), ev[len(ev)-1])
	}
	for i := 1; i < len(ev); i++ {
		if ev[i].Seq != ev[i-1].Seq+1 {
			t.Fatalf("seq gap at %d: %d after %d", i, ev[i].Seq, ev[i-1].Seq)
		}
	}
	// a power cut tore the last line: the next event starts a new line and continues the sequence
	f, _ := os.OpenFile(eventLog, os.O_APPEND|os.O_WRONLY, 0600)
	f.WriteString(`{"seq":261,"t":1,"ty`)
	f.Close()
	eventAdd(nil, "apply", "info", "7", "change #7 applied", false)
	if last := eventsRead(0, 1); len(last) != 1 || last[0].Seq != 261 || last[0].Type != "apply" {
		t.Errorf("after a torn line: %+v", last)
	}
	if got := eventLastSeq(); got != 261 {
		t.Errorf("eventLastSeq %d", got)
	}
	if ev := eventsRead(259, 0); eventTypesOf(ev) != "boot,apply" {
		t.Errorf("eventsRead after 259: %s", eventTypesOf(ev))
	}
	if ev := eventRecent(2); len(ev) != 2 || ev[0].Type != "apply" {
		t.Errorf("eventRecent: %+v", ev)
	}

	// the hourly cap per type
	kept := 0
	for i := 0; i < 25; i++ {
		*now = now.Add(time.Minute)
		if eventAdd(nil, "new_device", "info", "", "x", false) {
			kept++
		}
	}
	if kept != eventTypeHour {
		t.Errorf("new_device kept %d times in 25 minutes, want %d", kept, eventTypeHour)
	}
	if !eventAdd(nil, "wan_down", "warn", "wan", "wan lost its connection", false) {
		t.Error("another type was capped too")
	}
	*now = now.Add(time.Hour)
	if !eventAdd(nil, "new_device", "info", "", "x", false) {
		t.Error("still capped an hour later")
	}
	if fi, _ := os.Stat(eventLog); fi.Size() > eventTrimBytes {
		t.Errorf("log is %d bytes", fi.Size())
	}
}

// WAN events: the first up and DHCP renewals are not events, a loss is (warn), the recovery says how
// long; udhcpc's initial deconfig is not a loss; during an apply both are expected (info).
func TestEventWAN(t *testing.T) {
	_, now, _, kicks := eventEnv(t)
	c := testConfig(t)
	c.Notify.Channels = []NotifyChannel{{Name: "hook", Type: "webhook", URL: "x", Format: "json"}}
	c.Notify.Events = notifyDefaultEvents()
	eventOnWAN(c, "wan2", "down") // deconfig at start
	eventOnWAN(c, "wan", "up")
	eventOnWAN(c, "wan", "up") // renewal
	if ev := eventsRead(0, 0); len(ev) != 0 {
		t.Fatalf("events for a first up / renewal / initial deconfig: %+v", ev)
	}
	*now = now.Add(time.Minute)
	eventOnWAN(c, "wan", "down")
	*now = now.Add(95 * time.Second)
	eventOnWAN(c, "wan", "up")
	ev := eventsRead(0, 0)
	if eventTypesOf(ev) != "wan_down,wan_up" || ev[0].Sev != "warn" || ev[0].Key != "wan" ||
		ev[0].Msg != "wan lost its connection (pppoe on pppoe-wan)" || ev[1].Msg != "wan is connected again after 1m35s down" {
		t.Errorf("down / up: %+v", ev)
	}
	if *kicks != 2 {
		t.Errorf("kicks %d, want 2", *kicks)
	}
	// an apply restarts the WAN: expected
	writeAtomic(ConfirmFile, []byte(`{"snapshot":"s.tar.gz","state":"applying","via":"web UI"}`), 0600)
	eventOnWAN(c, "wan", "down")
	eventOnWAN(c, "wan", "up")
	ev = eventsRead(2, 0)
	if len(ev) != 2 || ev[0].Sev != "info" || !strings.HasSuffix(ev[0].Msg, "(a change was being applied)") {
		t.Errorf("during an apply: %+v", ev)
	}
	// nobody wants the type: no kick
	c.Notify.Events = []string{"boot"}
	os.Remove(ConfirmFile)
	eventOnWAN(c, "wan", "down")
	if *kicks != 4 {
		t.Errorf("kicked for an unwanted type (%d)", *kicks)
	}
	// a redial / restart of this WAN in the change log of the last two minutes is expected; another
	// WAN's is not
	eventOnWAN(c, "wan", "up")
	before := eventLastSeq()
	appendChangeLogAt(*now, "schedule: reconnect wan2")
	eventOnWAN(c, "wan", "down")
	appendChangeLogAt(*now, "webui: restart mr-pppoe.wan")
	eventOnWAN(c, "wan", "up")
	ev = eventsRead(before, 0)
	if len(ev) != 2 || ev[0].Sev != "warn" || ev[1].Msg != "wan is connected again after 0s down (webui: restart mr-pppoe.wan)" {
		t.Errorf("redial: %+v", ev)
	}
	*now = now.Add(3 * time.Minute)
	eventOnWAN(c, "wan", "down")
	if ev := eventsRead(before+2, 0); len(ev) != 1 || ev[0].Sev != "warn" {
		t.Errorf("an old change-log line still excuses a loss: %+v", ev)
	}
	// the system is going down (mr-bootlog's stop marked it): WAN losses are no events
	eventOnWAN(c, "wan", "up")
	before = eventLastSeq()
	eventShutdown()
	eventOnWAN(c, "wan", "down")
	eventOnWAN(c, "wan", "up")
	if ev := eventsRead(before, 0); len(ev) != 0 {
		t.Errorf("events while shutting down: %+v", ev)
	}
}

// Multi-WAN health: the first view only records; a WAN that fails says where traffic goes.
func TestEventFailover(t *testing.T) {
	d, _, _, _ := eventEnv(t)
	tempState(t)
	c := testConfig(t)
	c.MultiWAN.Mode = "failover"
	health := func(a, b string) {
		f := wanHealthFile{WANs: []wanHealth{{Name: "wan", State: a}, {Name: "wan2", State: b}}}
		bs, _ := json.Marshal(f)
		os.WriteFile(wanStateFile, bs, 0644)
	}
	health("up", "up")
	eventOnWAN(c, "", "health")
	health("down", "up")
	eventOnWAN(c, "", "health")
	health("down", "down")
	eventOnWAN(c, "", "health")
	health("up", "down")
	eventOnWAN(c, "", "health")
	var msgs []string
	for _, e := range eventsRead(0, 0) {
		msgs = append(msgs, e.Sev+" "+e.Msg)
	}
	want := "warn wan fails its health check; traffic moves to wan2|warn wan2 fails its health check; no other WAN is healthy|" +
		"info wan passes its health check again"
	if got := strings.Join(msgs, "|"); got != want {
		t.Errorf("failover events:\n%s\nwant\n%s", got, want)
	}
	_ = d
}

// Changes and login locks: the apply and rollback results history.go records, a lock of a source.
func TestEventChangeAndLogin(t *testing.T) {
	eventEnv(t)
	eventChange(revision{Rev: 7, Via: "web UI", Comment: "open\nport", Result: "confirmed"})
	eventChange(revision{Rev: 8, Via: "mr apply", Result: "pending"}) // not an end state
	eventChange(revision{Rev: 8, Via: "mr apply", Result: "rolled back at boot: the router restarted before it was confirmed"})
	eventLoginLock("2001:db8:1:2:3:4:5:6", "web UI logins", 30*time.Second)
	ev := eventsRead(0, 0)
	if eventTypesOf(ev) != "apply,rollback,login_lock" {
		t.Fatalf("types: %s", eventTypesOf(ev))
	}
	if ev[0].Msg != "change #7 (web UI: open port) confirmed" || ev[1].Sev != "warn" || ev[2].Key != "2001:db8:1:2::/64" ||
		ev[2].Msg != "5 failed web UI logins from 2001:db8:1:2:3:4:5:6: locked for 30s" {
		t.Errorf("events: %+v", ev)
	}
}

// New devices: a day of learning, then every unknown MAC once (static hosts are known), untrusted
// names cleaned, randomized MACs marked, at most eventScanMax lines per scan; the list is appended.
func TestEventNewDevices(t *testing.T) {
	d, now, _, kicks := eventEnv(t)
	c := testConfig(t)
	c.DHCP.Hosts = append(c.DHCP.Hosts, Host{Name: "printer", MAC: "02:00:00:00:00:99", IP: "192.168.1.99"})
	c.Notify.Channels = []NotifyChannel{{Name: "tg", Type: "telegram", Token: "x", ChatID: "1"}}
	c.Notify.Events = notifyDefaultEvents()
	lease := func(lines ...string) {
		os.WriteFile(eventLeaseFile, []byte(strings.Join(lines, "\n")+"\n"), 0644)
	}
	lease("1800000100 02:00:00:00:00:01 192.168.1.101 laptop 01:02:00:00:00:00:01")
	eventScanLeases(c) // creates the list: learning
	lease("1800000100 02:00:00:00:00:01 192.168.1.101 laptop *", "1800000100 02:00:00:00:00:02 192.168.1.102 tv *")
	*now = now.Add(time.Hour)
	eventScanLeases(c)
	if ev := eventsRead(0, 0); len(ev) != 0 {
		t.Fatalf("events while learning: %+v", ev)
	}
	seen, _ := os.ReadFile(eventDevices)
	if !strings.HasPrefix(string(seen), "# learning until 1800086400\n") || !strings.Contains(string(seen), "02:00:00:00:00:02\n") {
		t.Fatalf("devices.seen while learning:\n%s", seen)
	}
	*now = now.Add(24 * time.Hour)
	lease("1800000100 02:00:00:00:00:01 192.168.1.101 laptop *", "1800000100 02:00:00:00:00:02 192.168.1.102 tv *",
		"1800000100 02:00:00:00:00:99 192.168.1.99 printer *",
		"1800000100 00:11:22:33:44:55 192.168.1.103 evil\x1b[2Jname *",
		"1800000100 aa:00:00:00:00:04 192.168.1.104 * *")
	eventScanLeases(c)
	ev := eventsRead(0, 0)
	if len(ev) != 2 || ev[0].Msg != "evil [2Jname (00:11:22:33:44:55) got 192.168.1.103 on lan" ||
		ev[1].Msg != "(no name) (aa:00:00:00:00:04, private MAC) got 192.168.1.104 on lan" || ev[1].Key != "aa:00:00:00:00:04" {
		t.Fatalf("new devices: %+v", ev)
	}
	if *kicks != 1 {
		t.Errorf("one scan, %d kicks", *kicks)
	}
	eventScanLeases(c)
	if n := len(eventsRead(0, 0)); n != 2 {
		t.Errorf("reported again: %d events", n)
	}
	// a burst: five one by one, the rest as one line
	var ls []string
	for i := 10; i < 18; i++ {
		ls = append(ls, fmt.Sprintf("1800000100 00:00:00:00:00:%02d 192.168.1.%d dev%d *", i, 100+i, i))
	}
	lease(ls...)
	*now = now.Add(time.Hour)
	eventScanLeases(c)
	ev = eventsRead(2, 0)
	if len(ev) != 6 || ev[5].Msg != "3 more new devices (mr dns leases)" {
		t.Errorf("burst: %+v", ev)
	}
	seen, _ = os.ReadFile(eventDevices)
	if n := strings.Count(string(seen), "00:00:00:00:00:1"); n != 8 || strings.Count(string(seen), "\n") != 13 { // + the old header
		t.Errorf("devices.seen after the burst:\n%s", seen)
	}
	// the seen marker is a second early: a lease written in the same second is still newer
	st, _ := os.Stat(eventSeenFile)
	if !st.ModTime().Before(*now) {
		t.Errorf("leases.seen mtime %v not before the scan (%v)", st.ModTime(), *now)
	}
	// the list is trimmed to its newest eventSeenMax once it has grown eventSeenSlack past it
	var big []string
	for i := 0; i < eventSeenMax+eventSeenSlack; i++ {
		big = append(big, fmt.Sprintf("00:00:00:%02x:%02x:%02x", i>>16&0xff, i>>8&0xff, i&0xff))
	}
	os.WriteFile(eventDevices, []byte(strings.Join(big, "\n")+"\n"), 0600)
	lease("1800000100 02:a2:1b:dc:51:9f 192.168.1.200 new *")
	eventScanLeases(c)
	seen, _ = os.ReadFile(eventDevices)
	if n := strings.Count(string(seen), "\n"); n != eventSeenMax || !strings.HasSuffix(string(seen), "02:a2:1b:dc:51:9f\n") {
		t.Errorf("trim: %d lines", n)
	}
	_ = d
}

func TestEventCrashLine(t *testing.T) {
	for in, want := range map[string]string{
		"<4>[    1.226037] mtk-wdt 1001c000.watchdog: Watchdog enabled (timeout=31 sec, nowayout=0)": "",
		"<6>[    0.013282] pstore: Registered ramoops as persistent store backend":                   "",
		"[  812.1] Internal error: Oops: 0000000096000004 [#1] SMP":                                  "Internal error: Oops: 0000000096000004 [#1] SMP",
		"<3>[ 99.0] watchdog: BUG: soft lockup - CPU#2 stuck for 23s! [kworker/2:1:77]":              "watchdog: BUG: soft lockup - CPU#2 stuck for 23s! [kworker/2:1:77]",
		"[5.0] Out of memory: Killed process 812 (sing-box)":                                         "Out of memory: Killed process 812 (sing-box)",
		"[9.9] INFO: task kworker:12 blocked for more than 120 seconds.":                             "INFO: task kworker:12 blocked for more than 120 seconds.",
	} {
		if got := crashLine(in); got != want {
			t.Errorf("crashLine(%q) = %q, want %q", in, got, want)
		}
	}
}

// Boot records: once per boot; a clean restart (with the reason from the change log), a kernel
// crash in pstore (reported once), new firmware, and anything else as an unexpected restart.
func TestEventBoot(t *testing.T) {
	d, now, _, kicks := eventEnv(t)
	c := testConfig(t)
	boot := func(id string) event {
		t.Helper()
		eventBootID = func() string { return id }
		if err := eventBoot(c); err != nil {
			t.Fatal(err)
		}
		ev := eventsRead(0, 0)
		return ev[len(ev)-1]
	}
	version = "v1"
	if e := boot("b1"); e.Type != "boot" || e.Msg != "booted" || e.Sev != "info" {
		t.Errorf("first boot: %+v", e)
	}
	boot("b1")
	if n := len(eventsRead(0, 0)); n != 1 {
		t.Errorf("a second run in the same boot added an event (%d)", n)
	}
	// clean restart from a schedule; NTP synced: the downtime is known
	appendChangeLogAt(*now, "schedule: reboot")
	eventBootID = func() string { return "b1" }
	eventShutdown()
	*now = now.Add(3 * time.Minute)
	os.MkdirAll(ntpSyncDir, 0755)
	os.WriteFile(filepath.Join(ntpSyncDir, "synced"), nil, 0644)
	if e := boot("b2"); e.Msg != "booted after a clean restart (schedule: reboot), down 3m00s" || e.Sev != "info" {
		t.Errorf("clean restart: %+v", e)
	}
	if _, err := os.Stat(eventShutdownFile); err == nil {
		t.Error("shutdown mark not consumed")
	}
	// power cut
	if e := boot("b3"); e.Msg != "booted after an unexpected restart (power cut, hang or hardware watchdog)" || e.Sev != "warn" {
		t.Errorf("power cut: %+v", e)
	}
	// a stale mark (written by an older boot than the last one recorded) does not count
	os.WriteFile(eventShutdownFile, []byte(`{"time":1,"boot_id":"b1"}`), 0600)
	if e := boot("b4"); e.Sev != "warn" {
		t.Errorf("stale mark accepted: %+v", e)
	}
	// kernel crash kept by ramoops: reported once
	os.MkdirAll(pstoreDir, 0755)
	os.WriteFile(filepath.Join(pstoreDir, "dmesg-ramoops-0"), []byte("Panic#1 Part1\n<0>[ 7.1] Kernel panic - not syncing: Fatal exception\n"), 0444)
	if e := boot("b5"); e.Msg != "booted after a kernel crash: Kernel panic - not syncing: Fatal exception" || e.Sev != "warn" {
		t.Errorf("crash: %+v", e)
	}
	if e := boot("b6"); strings.Contains(e.Msg, "crash") {
		t.Errorf("the same crash record reported again: %+v", e)
	}
	// new firmware (sysupgrade kexecs: no clean-stop mark)
	version = "v2"
	boot("b7")
	ev := eventsRead(0, 0)
	if a, b := ev[len(ev)-2], ev[len(ev)-1]; a.Msg != "booted the new firmware" || b.Type != "upgrade" || b.Msg != "mr v1 → v2" {
		t.Errorf("upgrade: %+v %+v", a, b)
	}
	// channels: the boot sends what is pending (also a rollback logged before OpenRC)
	c.Notify.Channels = []NotifyChannel{{Name: "tg", Type: "telegram", Token: "x", ChatID: "1"}}
	k := *kicks
	boot("b8")
	if *kicks != k+1 {
		t.Error("no flush at boot with channels")
	}
	// `rc-service mr-bootlog restart` (a stop that was not a shutdown, then a start in the same boot):
	// the mark is dropped, the next power cut is still unexpected
	eventShutdown()
	boot("b8")
	if e := boot("b9"); e.Sev != "warn" || !strings.Contains(e.Msg, "unexpected") {
		t.Errorf("a service restart counted as a clean shutdown: %+v", e)
	}
	_ = d
}

// The tick scans leases only when they changed, runs the background doctor when due, and keeps
// event.due at the earliest of the next doctor run and a notification retry.
func TestEventTick(t *testing.T) {
	_, _, up, _ := eventEnv(t)
	c := testConfig(t)
	due := func() string { b, _ := os.ReadFile(eventDueFile); return strings.TrimSpace(string(b)) }
	eventSchedule(c)
	if due() != "" {
		t.Errorf("event.due without doctor / channels: %q", due())
	}
	iv := 30
	c.Notify.Doctor = &iv
	*up = 100
	eventSchedule(c)
	if due() != "300" {
		t.Errorf("first doctor run after boot: %q, want 300", due())
	}
	*up = 5000
	eventSchedule(c)
	if due() != "300" {
		t.Errorf("rescheduled a due run: %q", due())
	}
	ran := 0
	oldD := newDocEnv
	newDocEnv = func() *docEnv { ran++; return fakeDocEnv() }
	t.Cleanup(func() { newDocEnv = oldD })
	if err := eventTick(c); err != nil {
		t.Fatal(err)
	}
	if ran != 1 || due() != "6800" {
		t.Errorf("tick: doctor ran %d times, event.due %q (want 1, 6800)", ran, due())
	}
	eventTick(c)
	if ran != 1 {
		t.Error("doctor ran again before it was due")
	}
	// lease scan: only when the lease file is newer than the marker
	os.WriteFile(eventLeaseFile, []byte("1800000100 02:00:00:00:00:01 192.168.1.101 laptop *\n"), 0644)
	eventTick(c)
	if _, err := os.Stat(eventDevices); err != nil {
		t.Fatal("no scan after a lease change")
	}
	os.Remove(eventDevices)
	eventTick(c)
	if _, err := os.Stat(eventDevices); err == nil {
		t.Error("scanned an unchanged lease file")
	}
	// doctor off: no due
	c.Notify.Doctor = nil
	eventTick(c)
	if due() != "" {
		t.Errorf("event.due with doctor off: %q", due())
	}
	if err := eventCommand(c, []string{"tick"}); err != nil {
		t.Error(err)
	}
	for _, bad := range [][]string{nil, {"list", "0"}, {"list", "999"}, {"nope"}} {
		if eventCommand(c, bad) == nil {
			t.Errorf("mr event %v accepted", bad)
		}
	}
}

func TestEventAPI(t *testing.T) {
	eventEnv(t)
	eventAdd(nil, "boot", "info", "", "booted", false)
	eventAdd(nil, "wan_down", "warn", "wan", "wan lost its connection", false)
	b, _ := json.Marshal(apiSysEvents(apiReq{method: "GET"}).body)
	var r struct {
		Events []event         `json:"events"`
		Types  []string        `json:"types"`
		Notify []notifyStatus  `json:"notify"`
		Other  json.RawMessage `json:"other"`
	}
	json.Unmarshal(b, &r)
	if len(r.Events) != 2 || r.Events[0].Type != "wan_down" || len(r.Types) != len(eventTypes) || r.Notify == nil {
		t.Errorf("sys.events: %s", b)
	}
	if tokenActions["sys.events"] != "read" || tokenActions["sys.doctor"] != "read" || tokenActions["sys.notifytest"] != "" {
		t.Error("token scopes of the new actions")
	}
}

func TestFmtSecs(t *testing.T) {
	for s, want := range map[int64]string{-5: "0s", 45: "45s", 192: "3m12s", 7500: "2h05m", 273600: "3d4h"} {
		if got := fmtSecs(s); got != want {
			t.Errorf("fmtSecs(%d) = %q, want %q", s, got, want)
		}
	}
}
