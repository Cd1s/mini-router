package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// dialEnv: the home config (dial_order [wan2, wan], dial_restore 04:30), leases and dial state in a temp
// dir, the event clock at *now; dialSleep advances it and calls onSleep (if set) with the sleep count.
func dialEnv(t *testing.T) (c *Config, now *time.Time, sleeps *int, onSleep *func(int)) {
	t.Helper()
	c = testConfig(t)
	d, now, _, _ := eventEnv(t)
	oRun, oState, oLock, oSleep, oRestart, oSpawn := wanRunDir, dialStateFile, dialLockFile, dialSleep, dialRestart, dialSpawn
	t.Cleanup(func() {
		wanRunDir, dialStateFile, dialLockFile, dialSleep, dialRestart, dialSpawn = oRun, oState, oLock, oSleep, oRestart, oSpawn
	})
	wanRunDir, dialStateFile, dialLockFile = filepath.Join(d, "wan"), filepath.Join(d, "run", "dial.json"), filepath.Join(d, "run", "dial.lock")
	os.MkdirAll(wanRunDir, 0755)
	sleeps, onSleep = new(int), new(func(int))
	dialSleep = func(x time.Duration) {
		*now = now.Add(x)
		*sleeps++
		if *onSleep != nil {
			(*onSleep)(*sleeps)
		}
	}
	return c, now, sleeps, onSleep
}

func TestDialValidate(t *testing.T) {
	c := testConfig(t)
	if m := c.MultiWAN; strings.Join(m.DialOrder, ",") != "wan2,wan" || m.DialWait != 0 || m.dialWait() != 30*time.Second || m.DialRestore != "04:30" || m.Enabled() {
		t.Fatalf("home config: %+v", m)
	}
	for _, tc := range []struct {
		f    func(m *MultiWAN)
		want string
	}{
		{func(m *MultiWAN) { m.DialOrder = []string{"wan"} }, "at least two"},
		{func(m *MultiWAN) { m.DialOrder = []string{"wan", "nope"} }, `"nope" is not a PPPoE WAN`},
		{func(m *MultiWAN) { m.DialOrder = []string{"wan", "wan2", "wan"} }, `"wan" listed twice`},
		{func(m *MultiWAN) { m.DialWait = 121 }, "dial_wait: 1-120"},
		{func(m *MultiWAN) { m.DialRestore = "4:30" }, "dial_restore: off | now | HH:MM"},
		{func(m *MultiWAN) { m.DialRestore = "24:00" }, "dial_restore: off | now | HH:MM"},
		{func(m *MultiWAN) { m.DialRestore = "later" }, "dial_restore: off | now | HH:MM"},
		{func(m *MultiWAN) { m.DialOrder, m.DialWait = nil, 0 }, "need multiwan.dial_order"},
	} {
		c := testConfig(t)
		tc.f(&c.MultiWAN)
		if errs := strings.Join(c.Validate(), "\n"); !strings.Contains(errs, tc.want) {
			t.Errorf("want %q in:\n%s", tc.want, errs)
		}
	}
	for _, r := range []string{"off", "now", "", "00:00", "23:59"} {
		c := testConfig(t)
		c.MultiWAN.DialRestore = r
		if errs := c.Validate(); len(errs) > 0 {
			t.Errorf("dial_restore %q: %v", r, errs)
		}
	}
}

// pd6Record: the dhcpcd hook's record of the prefix wan delegated, written at unix time at.
func pd6Record(t *testing.T, wan string, at int64) {
	t.Helper()
	if err := os.WriteFile(pd6File(wan), []byte("2001:db8:2::/64\n"), 0644); err != nil {
		t.Fatal(err)
	}
	os.Chtimes(pd6File(wan), time.Unix(at, 0), time.Unix(at, 0))
}

func TestDialWait(t *testing.T) {
	c, now, sleeps, onSleep := dialEnv(t)
	t0 := *now
	dialWait(c, "wan2") // first in the order
	dialWait(c, "iptv") // not listed
	if *sleeps != 0 {
		t.Errorf("the first / an unlisted WAN waited %d s", *sleeps)
	}
	dialWait(c, "wan") // wan2 never comes up: gives up after dial_wait
	if got := now.Sub(t0); got != 30*time.Second {
		t.Errorf("timeout after %v", got)
	}
	writeLease("wan2", wanLease{IP: "192.0.2.2", Since: now.Unix()})
	pd6Record(t, "wan2", now.Unix())
	*sleeps = 0
	dialWait(c, "wan") // wan2 is up with its prefix: only the settle
	if *sleeps != 1 {
		t.Errorf("waited %d times with wan2 up", *sleeps)
	}
	// a session without its prefix yet is not enough (the ISP acts on the delegation too); a record
	// older than the session is the previous session's
	if pd6Record(t, "wan2", now.Unix()-60); dialReady(c, "wan2", 0) {
		t.Error("ready with the previous session's prefix record")
	}
	c.WAN[1].IPv6PD = false
	if !dialReady(c, "wan2", 0) {
		t.Error("a WAN without ipv6_pd needs no prefix")
	}
	c.WAN[1].IPv6PD = true
	removeLease("wan2")
	os.Remove(pd6File("wan2"))
	*sleeps = 0
	*onSleep = func(n int) {
		switch n {
		case 3: // the session
			writeLease("wan2", wanLease{IP: "192.0.2.2", Since: now.Unix()})
		case 6: // the prefix, seconds later
			pd6Record(t, "wan2", now.Unix())
		}
	}
	dialWait(c, "wan")
	if *sleeps != 6 {
		t.Errorf("wan2 ready after its prefix: slept %d times", *sleeps)
	}
}

func TestDialLate(t *testing.T) {
	c, _, _, _ := dialEnv(t)
	m := c.MultiWAN
	writeLease("wan", wanLease{IP: "192.0.2.1", Since: 100})
	if l := dialLate(m); len(l) != 0 {
		t.Errorf("only wan up: %v", l)
	}
	writeLease("wan2", wanLease{IP: "192.0.2.2", Since: 50})
	if l := dialLate(m); len(l) != 0 {
		t.Errorf("wan2 then wan: %v", l)
	}
	writeLease("wan2", wanLease{IP: "192.0.2.2", Since: 200}) // wan2 redialled on its own
	if l := dialLate(m); strings.Join(l, ",") != "wan" {
		t.Errorf("wan2 redialled: late %v", l)
	}
	m.DialOrder = []string{"a", "b", "c"}
	writeLease("a", wanLease{Since: 300})
	writeLease("b", wanLease{Since: 200})
	writeLease("c", wanLease{Since: 250})
	if l := dialLate(m); strings.Join(l, ",") != "b,c" {
		t.Errorf("a redialled: late %v", l)
	}
}

func TestDialRestore(t *testing.T) {
	c, now, _, _ := dialEnv(t)
	var spawned, restarted []string
	dialSpawn = func(args ...string) error {
		spawned = append(spawned, strings.Join(args, " "))
		return nil
	}
	dialRestart = func(svc string) error {
		restarted = append(restarted, svc)
		writeLease(strings.TrimPrefix(svc, "mr-pppoe."), wanLease{IP: "192.0.2.1", Since: now.Unix() + 3})
		pd6Record(t, strings.TrimPrefix(svc, "mr-pppoe."), now.Unix()+5)
		return nil
	}
	writeLease("wan", wanLease{IP: "192.0.2.1", Since: now.Unix() - 100})
	writeLease("wan2", wanLease{IP: "192.0.2.2", Since: now.Unix()}) // wan2 just redialled: broken

	// HH:MM: nothing now; crond at 04:30 router time (+03, not the example's: sync-public rewrites that;
	// now is 11:00 there)
	c.System.Timezone = "<+03>-3"
	dialOnUp(c, "wan2")
	if len(spawned) != 0 {
		t.Errorf("HH:MM spawned %v", spawned)
	}
	if at := dialRestoreAt(c); at != 1_800_063_000 {
		t.Errorf("restore at %d (%s)", at, time.Unix(at, 0).UTC())
	}
	if l := strings.Join(dialCronLine(c), "\n"); l != "# multiwan.dial_restore\n30 4 * * * /usr/sbin/mr wan dial-restore" || !cronWanted(c) {
		t.Errorf("cron: %q", l)
	}
	// off: nothing at all
	c.MultiWAN.DialRestore = "off"
	dialOnUp(c, "wan2")
	if dialRestore(c); len(spawned)+len(restarted) != 0 || dialRestoreAt(c) != 0 || len(dialCronLine(c)) != 0 {
		t.Errorf("off: spawned %v restarted %v", spawned, restarted)
	}
	// now: the hook starts a detached restore, which redials wan
	c.MultiWAN.DialRestore = "now"
	dialOnUp(c, "wan2")
	if strings.Join(spawned, ";") != "wan dial-restore" || len(dialCronLine(c)) != 0 {
		t.Errorf("now: spawned %v", spawned)
	}
	if err := dialRestore(c); err != nil || strings.Join(restarted, ",") != "mr-pppoe.wan" || len(dialLate(c.MultiWAN)) != 0 {
		t.Errorf("restore: %v restarted %v late %v", err, restarted, dialLate(c.MultiWAN))
	}
	if ev := eventsRead(0, 0); len(ev) != 1 || ev[0].Type != "dial" || ev[0].Key != "wan" {
		t.Errorf("events: %+v", ev)
	}
	if !strings.Contains(readFile(ChangeLog), "dial order: restart mr-pppoe.wan") {
		t.Errorf("change log: %q", readFile(ChangeLog))
	}
	// broken again within 10 minutes: not again; after that: again
	*now = now.Add(5 * time.Minute)
	writeLease("wan2", wanLease{IP: "192.0.2.2", Since: now.Unix()})
	spawned = nil
	dialOnUp(c, "wan") // a later WAN coming up spawns too (the restore itself checks)
	dialRestore(c)
	if len(restarted) != 1 {
		t.Errorf("rate limit: restarted %v", restarted)
	}
	*now = now.Add(6 * time.Minute)
	dialRestore(c)
	if len(restarted) != 2 {
		t.Errorf("after 11 minutes: restarted %v", restarted)
	}
}
