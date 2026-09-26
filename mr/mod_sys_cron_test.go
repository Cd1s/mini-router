package main

import (
	"strings"
	"testing"
	"time"
)

func TestCronMatch(t *testing.T) {
	at := func(s string) time.Time { x, _ := time.Parse("2006-01-02 15:04", s); return x } // 2026-09-28 is a Monday
	for _, tc := range []struct {
		spec, t string
		want    bool
	}{
		{"0 23 * * *", "2026-09-28 23:00", true}, {"0 23 * * *", "2026-09-28 23:01", false},
		{"30 */6 * * *", "2026-09-28 18:30", true}, {"30 */6 * * *", "2026-09-28 19:30", false},
		{"0 7 * * 1-5", "2026-09-28 07:00", true}, {"0 7 * * 1-5", "2026-09-27 07:00", false},
		{"0 7 1 * 0", "2026-09-27 07:00", true}, {"0 7 1 * 0", "2026-10-01 07:00", true}, {"0 7 1 * 0", "2026-10-02 07:00", false},
		{"0 7 * 1,3 *", "2026-09-28 07:00", false}, {"5 0-2/2 * * *", "2026-09-28 02:05", true},
	} {
		if got := cronMatch(tc.spec, at(tc.t)); got != tc.want {
			t.Errorf("cronMatch(%q, %s) = %v", tc.spec, tc.t, got)
		}
	}
}

// localAt makes schedNow return the given wall-clock time in <+03>-3 (the zone the tests set).
func localAt(t *testing.T, s string) {
	x, err := time.Parse("2006-01-02 15:04", s)
	if err != nil {
		t.Fatal(err)
	}
	schedNow = func() time.Time { return x.Add(-3 * time.Hour) }
}

func TestScheduleWindows(t *testing.T) {
	c := testConfig(t)
	c.System.Timezone = "<+03>-3"
	c.Schedules = []Schedule{
		{Name: "wifi-night", Cron: "0 23 * * *", Action: "wifi-off", Target: "phy0"},
		{Name: "wifi-day", Cron: "0 7 * * *", Action: "wifi-on"},
		{Name: "dark", Cron: "30 22 * * *", Action: "leds-off"},
		{Name: "light", Cron: "0 8 * * 1-5", Action: "leds-on"},
	}
	if errs := c.Validate(); len(errs) > 0 {
		t.Fatal(errs)
	}
	old := schedNow
	t.Cleanup(func() { schedNow = old })
	localAt(t, "2026-09-29 02:00") // Tuesday night
	if !schedOff(c, "wifi-off", "wifi-on", "phy0") || schedOff(c, "wifi-off", "wifi-on", "phy1") || !schedOff(c, "leds-off", "leds-on", "") {
		t.Error("02:00: phy0 and the LEDs should be off, phy1 on")
	}
	localAt(t, "2026-09-29 07:00")
	if schedOff(c, "wifi-off", "wifi-on", "phy0") || !schedOff(c, "leds-off", "leds-on", "") {
		t.Error("07:00: wifi on, LEDs still off")
	}
	localAt(t, "2026-09-27 12:00") // Sunday: no leds-on since Friday 22:30
	if !schedOff(c, "leds-off", "leds-on", "") {
		t.Error("Sunday noon: LEDs off")
	}
	c.Schedules[0].Enabled = new(bool)
	localAt(t, "2026-09-29 02:00")
	if schedOff(c, "wifi-off", "wifi-on", "phy0") {
		t.Error("a disabled schedule counts")
	}
	if l := renderCronLines(c); len(l) < 2 || l[1] != "0 7 * * * /usr/sbin/mr sys run wifi-on" {
		t.Errorf("cron lines: %q", l)
	}

	c.Schedules = []Schedule{
		{Name: "a", Cron: "0 23 * * *", Action: "wifi-off", Target: "phy9"},
		{Name: "b", Cron: "0 23 * * *", Action: "leds-off", Target: "x"},
		{Name: "c", Cron: "0 23 * * *", Action: "wifi-on", Target: "phy0; reboot"},
	}
	errs := strings.Join(c.Validate(), "\n")
	for _, s := range []string{`schedules[0]: wifi-off: no wifi radio "phy9"`, "schedules[1]: leds-off takes no target", "schedules[2]: wifi-on: no wifi radio"} {
		if !strings.Contains(errs, s) {
			t.Errorf("want error %q in:\n%s", s, errs)
		}
	}
}

func TestWifiWindow(t *testing.T) {
	dir := t.TempDir()
	oDir, oWin, oNow := hostapdCtrlDir, wifiWindowDir, schedNow
	t.Cleanup(func() { hostapdCtrlDir, wifiWindowDir, schedNow = oDir, oWin, oNow })
	hostapdCtrlDir, wifiWindowDir = dir, t.TempDir()
	state, sent := map[string]string{"phy0-ap0": "ENABLED", "phy1-ap0": "ENABLED"}, []string{}
	for _, ifn := range []string{"phy0-ap0", "phy1-ap0"} {
		ifn := ifn
		fakeHostapd(t, dir, ifn, func(cmd string) string {
			switch cmd {
			case "STATUS":
				return "state=" + state[ifn] + "\nbss[0]=" + ifn + "\n"
			case "DISABLE":
				state[ifn] = "DISABLED"
			case "ENABLE":
				state[ifn] = "ENABLED"
			}
			sent = append(sent, ifn+" "+cmd)
			return "OK\n"
		})
	}
	c := testConfig(t)
	c.System.Timezone = "<+03>-3"
	c.Schedules = []Schedule{{Name: "off", Cron: "0 23 * * *", Action: "wifi-off"}, {Name: "on", Cron: "0 7 * * *", Action: "wifi-on"}}
	localAt(t, "2026-09-29 02:00")
	if err := wifiWindow(c); err != nil || strings.Join(sent, ",") != "phy0-ap0 DISABLE,phy1-ap0 DISABLE" {
		t.Fatalf("night: %v %q", err, sent)
	}
	sent = nil
	if wifiWindow(c); len(sent) > 0 {
		t.Errorf("again: %q", sent)
	}
	localAt(t, "2026-09-29 08:00")
	state["phy1-ap0"] = "ENABLED" // hostapd restarted meanwhile
	if err := wifiWindow(c); err != nil || strings.Join(sent, ",") != "phy0-ap0 ENABLE" {
		t.Fatalf("morning: %v %q", err, sent)
	}
	// a radio disabled by someone else is left alone
	state["phy0-ap0"], sent = "DISABLED", nil
	if wifiWindow(c); len(sent) > 0 {
		t.Errorf("foreign DISABLED: %q", sent)
	}
}
