package main

import (
	"strings"
	"testing"
)

func TestWatchcatStep(t *testing.T) {
	in := wcIn{Uptime: 3600, After: 600, Gap: 6 * 3600, Now: 10000}
	var s wcState
	var acts []string
	// down from t=10000, one tick per minute for 2 hours
	for i := 0; i < 120; i++ {
		in.Now = 10000 + int64(i)*60
		var a string
		s, a = wcStep(s, in)
		if a != "" {
			acts = append(acts, a)
		}
		if a == "reboot" {
			in.LastReboot = in.Now
		}
	}
	// after 10 min: redial; +10: restart; +20: reboot; +40: restart (one reboot per gap)
	if got := strings.Join(acts, ","); got != "redial,restart,reboot,restart" {
		t.Fatalf("escalation: %s", got)
	}
	// a reboot 1 h ago: the reboot step becomes a restart
	in.LastReboot = in.Now - 3600
	s2, a := wcStep(wcState{DownSince: 1, Step: 2}, in)
	if a != "restart" || s2.Step != 3 {
		t.Errorf("reboot gap: %s %+v", a, s2)
	}
	// pending change / right after boot: nothing, but the down time is kept
	for _, x := range []wcIn{{Now: 99999, Pending: true, Uptime: 3600, After: 600}, {Now: 99999, Uptime: 60, After: 600}} {
		if s3, a := wcStep(wcState{DownSince: 1}, x); a != "" || s3.DownSince != 1 {
			t.Errorf("%+v: %s %+v", x, a, s3)
		}
	}
	// back online: recovered once, state cleared
	in.Online = true
	if s4, a := wcStep(s, in); a != "recovered" || s4 != (wcState{}) {
		t.Errorf("online: %s %+v", a, s4)
	}
	if _, a := wcStep(wcState{}, in); a != "" {
		t.Errorf("online again: %s", a)
	}
}

func TestWatchcatValidateCron(t *testing.T) {
	c := testConfig(t)
	c.System.Watchcat = Watchcat{Enabled: true, Targets: []string{"x;reboot"}}
	wcDefaults(c)
	v := &Validator{}
	wcValidate(c, v)
	if len(v.errs) != 1 || !strings.Contains(v.errs[0], "targets") {
		t.Errorf("errs: %v", v.errs)
	}
	if l := wcCronLine(c); len(l) != 2 || l[1] != "* * * * * /usr/sbin/mr watchcat tick" {
		t.Errorf("cron: %v", l)
	}
}
