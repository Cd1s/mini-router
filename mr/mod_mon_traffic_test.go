package main

import (
	"path/filepath"
	"testing"
	"time"
)

func TestMonTraffic(t *testing.T) {
	files := monCTFiles(monCTFixture, "1000.0 0\n")
	files["/sys/class/net/wan/statistics/rx_bytes"] = "1000\n"
	files["/sys/class/net/wan/statistics/tx_bytes"] = "500\n"
	root := monFake(t, files)
	d := t.TempDir()
	oRun, oFlows, oFlash, oNow := monTrafficRun, monTrafficFlows, monTrafficFlash, monTrafficNow
	t.Cleanup(func() { monTrafficRun, monTrafficFlows, monTrafficFlash, monTrafficNow = oRun, oFlows, oFlash, oNow })
	monTrafficRun, monTrafficFlows, monTrafficFlash = filepath.Join(d, "run.json"), filepath.Join(d, "flows"), filepath.Join(d, "flash.json")
	now := time.Date(2026, 9, 30, 20, 30, 0, 0, time.UTC) // 23:30 in <+03>-3
	monTrafficNow = func() time.Time { return now }
	c := testConfig(t)
	c.System.Timezone = "<+03>-3" // not the example's: sync-public rewrites that
	if monAccount(c); fileExists(monTrafficRun) {
		t.Fatal("counted while system.traffic_stats is off")
	}
	c.System.TrafficStats = true
	if err := monAccount(c); err != nil {
		t.Fatal(err)
	}
	st := monTrafficLoad()
	mac := st.Cur.Dev["02:e3:50:10:6a:63"]
	if st.Cur.Month != "2026-09" || mac == nil || mac.Up != 11570 || mac.Down != 1256200 || mac.Name != "laptop" || len(st.Cur.WAN) != 0 || !fileExists(monTrafficFlash) {
		t.Fatalf("first run: %+v %+v", st.Cur, mac)
	}
	// a minute later, past midnight: a new month; the WAN counters moved, the flows did not
	now = now.Add(31 * time.Minute)
	monWrite(t, root, map[string]string{"/proc/uptime": "1060.0 0\n", "/sys/class/net/wan/statistics/rx_bytes": "4000\n", "/sys/class/net/wan/statistics/tx_bytes": "700\n"})
	if err := monAccount(c); err != nil {
		t.Fatal(err)
	}
	st = monTrafficLoad()
	if st.Cur.Month != "2026-10" || st.Prev == nil || st.Prev.Month != "2026-09" || len(st.Cur.Dev) != 0 {
		t.Fatalf("month change: %+v prev %+v", st.Cur, st.Prev)
	}
	if w := st.Cur.WAN["wan"]; w == nil || w.Down != 3000 || w.Up != 200 {
		t.Errorf("wan: %+v", w)
	}
	saved := st.Saved
	now = now.Add(10 * time.Minute)
	monAccount(c)
	if monTrafficLoad().Saved != saved {
		t.Error("flash written again within the hour")
	}
}
