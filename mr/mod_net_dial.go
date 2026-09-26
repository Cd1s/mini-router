package main

// net module: PPPoE dial order (router.yaml multiwan.dial_order / dial_wait / dial_restore,
// Cd1s/mini-router#109). Several PPPoE sessions on one ISP account: some things at the ISP (its DDNS)
// follow the session that connected last, so the WANs dial in a fixed order.
//
//   - mr-pppoe.<wan> runs /usr/libexec/mr/pppoe-dial, which calls `mr wan dial-wait <wan>` (waits until
//     every WAN before it in dial_order has a session, at most dial_wait seconds) and then execs pppd.
//     OpenRC never waits for it; a WAN never waits for itself or a later one.
//   - The order is broken when an up WAN has an older session (lease `since`, written by the ppp-up hook)
//     than an up WAN before it. dial_restore now: the ppp-up hook starts a detached `mr wan dial-restore`;
//     HH:MM: crond runs it at that time. It redials the late WANs in order (rc-service mr-pppoe.<wan>
//     restart, each waiting for its new session), at most once per 10 minutes per WAN, with an event.

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"slices"
	"strings"
	"syscall"
	"time"
)

const dialRestoreGap = 600 // s between two restore redials of one WAN

var (
	dialStateFile = RunDir + "/dial-restore.json" // WAN -> unix time of its last restore redial
	dialLockFile  = RunDir + "/dial-restore.lock"
	dialSleep     = time.Sleep
	dialRestart   = func(svc string) error {
		out, err := run("rc-service", svc, "restart")
		if err != nil {
			logf("dial order: %s restart: %v %s", svc, err, strings.TrimSpace(out))
		}
		return err
	}
	// dialSpawn starts `mr ARGS` in its own session and does not wait (the pppd hook must not block)
	dialSpawn = func(args ...string) error {
		cmd := exec.Command(mrBin, args...)
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		if err := cmd.Start(); err != nil {
			return err
		}
		return cmd.Process.Release()
	}
)

func netValidateDial(c *Config, v *Validator) {
	m := c.MultiWAN
	if len(m.DialOrder) == 0 {
		if m.DialWait != 0 || (m.DialRestore != "" && m.DialRestore != "off") {
			v.Add("multiwan.dial_wait / dial_restore: need multiwan.dial_order")
		}
		return
	}
	if len(m.DialOrder) < 2 {
		v.Add("multiwan.dial_order: at least two PPPoE WANs")
	}
	seen := map[string]bool{}
	for _, n := range m.DialOrder {
		if w := c.WANByName(n); w == nil || w.Proto != "pppoe" {
			v.Add("multiwan.dial_order: %q is not a PPPoE WAN", n)
		} else if seen[n] {
			v.Add("multiwan.dial_order: %q listed twice", n)
		}
		seen[n] = true
	}
	if m.DialWait < 0 || m.DialWait > 120 {
		v.Add("multiwan.dial_wait: 1-120 seconds")
	}
	if _, _, ok := dialRestoreTime(m.DialRestore); !ok && m.DialRestore != "" && m.DialRestore != "off" && m.DialRestore != "now" {
		v.Add("multiwan.dial_restore: off | now | HH:MM, got %q", m.DialRestore)
	}
}

// dialRestoreTime parses dial_restore "HH:MM".
func dialRestoreTime(s string) (hour, minute int, ok bool) {
	if len(s) != 5 || s[2] != ':' {
		return 0, 0, false
	}
	for i, ch := range s {
		if i != 2 && (ch < '0' || ch > '9') {
			return 0, 0, false
		}
	}
	hour, minute = atoi(s[:2]), atoi(s[3:])
	return hour, minute, hour < 24 && minute < 60
}

func dialRestoreOn(m MultiWAN) bool {
	return len(m.DialOrder) > 0 && m.DialRestore != "" && m.DialRestore != "off"
}

// dialEarlier: the WANs before name in dial_order (none when name is not listed).
func dialEarlier(m MultiWAN, name string) []string {
	if i := slices.Index(m.DialOrder, name); i > 0 {
		return m.DialOrder[:i]
	}
	return nil
}

// dialWaitUp waits until every WAN in names has a session that started at or after since, or until
// deadline; reports whether they all have one.
func dialWaitUp(names []string, since int64, deadline time.Time) bool {
	for {
		ok := true
		for _, n := range names {
			if l, up := readLease(n); !up || l.Since < since {
				ok = false
			}
		}
		if ok {
			return true
		}
		if !eventNow().Before(deadline) {
			return false
		}
		dialSleep(time.Second)
	}
}

// dialWait is `mr wan dial-wait WAN` (pppoe-dial, before pppd starts).
func dialWait(c *Config, name string) {
	earlier := dialEarlier(c.MultiWAN, name)
	if len(earlier) == 0 {
		return
	}
	if !dialWaitUp(earlier, 0, eventNow().Add(c.MultiWAN.dialWait())) {
		logf("wan %s: dialling after %s without %s (multiwan.dial_order)", name, c.MultiWAN.dialWait(), strings.Join(earlier, ", "))
	}
}

// dialLate: the up WANs of dial_order whose session is older than that of an up WAN before them.
func dialLate(m MultiWAN) []string {
	var late []string
	var newest int64
	for _, n := range m.DialOrder {
		l, up := readLease(n)
		if !up {
			continue
		}
		if l.Since < newest {
			late = append(late, n)
		}
		newest = max(newest, l.Since)
	}
	return late
}

// dialRestoreAt: with dial_restore HH:MM and a broken order, when crond redials next (unix; 0 = nothing pending).
func dialRestoreAt(c *Config) int64 {
	h, mi, ok := dialRestoreTime(c.MultiWAN.DialRestore)
	if !ok || len(dialLate(c.MultiWAN)) == 0 {
		return 0
	}
	now := eventNow()
	off := time.Duration(tzOffset(sysTZ(c), now)) * time.Second
	wall := now.UTC().Add(off)
	at := time.Date(wall.Year(), wall.Month(), wall.Day(), h, mi, 0, 0, time.UTC)
	if !at.After(wall) {
		at = at.Add(24 * time.Hour)
	}
	return at.Add(-off).Unix()
}

// dialCronLine: crond runs the HH:MM restore (it only redials when the order is still broken).
func dialCronLine(c *Config) []string {
	h, mi, ok := dialRestoreTime(c.MultiWAN.DialRestore)
	if !ok || len(c.MultiWAN.DialOrder) == 0 {
		return nil
	}
	return []string{"# multiwan.dial_restore", fmt.Sprintf("%d %d * * * %s wan dial-restore", mi, h, mrBin)}
}

// dialOnUp runs in the ppp-up hook: with dial_restore now, a broken order starts a detached restore.
func dialOnUp(c *Config, name string) {
	m := c.MultiWAN
	if !dialRestoreOn(m) || !slices.Contains(m.DialOrder, name) {
		return
	}
	late := dialLate(m)
	if len(late) == 0 {
		return
	}
	if m.DialRestore != "now" {
		logf("wan %s: dial order broken (%s dialled earlier), restore at %s", name, strings.Join(late, ", "), m.DialRestore)
		return
	}
	if err := dialSpawn("wan", "dial-restore"); err != nil {
		logf("dial order: %v", err)
	}
}

// dialDue: the late WANs that were not restored in the last dialRestoreGap seconds; records them in st.
func dialDue(late []string, st map[string]int64, now int64) []string {
	var due []string
	for _, n := range late {
		if now-st[n] >= dialRestoreGap {
			due = append(due, n)
			st[n] = now
		}
	}
	return due
}

// dialRestore is `mr wan dial-restore` (detached from the ppp-up hook, or crond): redials the late WANs
// in dial order, each after the previous one has its new session (or dial_wait passed).
func dialRestore(c *Config) error {
	m := c.MultiWAN
	if !dialRestoreOn(m) {
		return nil
	}
	lk := flock(dialLockFile, false)
	if lk == nil {
		return nil // a restore is running
	}
	defer lk.Close()
	late := dialLate(m)
	if len(late) == 0 {
		return nil
	}
	st := map[string]int64{}
	readJSONFile(dialStateFile, &st)
	due := dialDue(late, st, eventNow().Unix())
	if len(due) < len(late) {
		logf("dial order: broken (%s), redialling only %d of them (at most once per %d minutes each)", strings.Join(late, ", "), len(due), dialRestoreGap/60)
	}
	if len(due) == 0 {
		return nil
	}
	b, _ := json.Marshal(st)
	writeAtomic(dialStateFile, b, 0644)
	for _, n := range due {
		svc := "mr-pppoe." + n
		appendChangeLog("dial order: restart " + svc) // the down / up events of this redial are expected
		eventAdd(c, "dial", "info", n, fmt.Sprintf("%s redialled to restore the dial order %s", n, strings.Join(m.DialOrder, " → ")), true)
		t0 := eventNow().Unix()
		if dialRestart(svc) == nil {
			dialWaitUp([]string{n}, t0, eventNow().Add(m.dialWait()))
		}
	}
	return nil
}
