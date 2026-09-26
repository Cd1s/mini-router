package main

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDevWatch(t *testing.T) {
	d, now, up, _ := eventEnv(t)
	oFile, oPresent := devWatchFile, devPresent
	t.Cleanup(func() { devWatchFile, devPresent = oFile, oPresent })
	devWatchFile = filepath.Join(d, "run", "dev-watch.json")
	here := map[string]bool{}
	devPresent = func(*Config) map[string]bool { return here }
	c := devConfig(t)
	c.Devices[0].Watch = true
	name, mac := c.Devices[0].Name, strings.ToLower(c.Devices[0].MACs[0])
	msgs := func() string {
		var s []string
		for _, e := range eventsRead(0, 50) {
			if e.Type == "device" {
				s = append(s, e.Msg)
			}
		}
		return strings.Join(s, "|")
	}
	step := func(secs int, seen bool) {
		*now = now.Add(time.Duration(secs) * time.Second)
		*up += float64(secs)
		here = map[string]bool{mac: seen}
		if err := eventTick(c); err != nil {
			t.Fatal(err)
		}
	}
	eventSchedule(c) // due now
	step(0, false)   // learning: no events for 10 minutes
	step(60, true)
	if m := msgs(); m != "" {
		t.Fatalf("events while learning: %s", m)
	}
	step(600, true)
	step(60, false)
	step(300, true) // back within 10 min: no flap
	step(60, false)
	step(480, false)
	if m := msgs(); m != "" {
		t.Fatalf("offline too early: %s", m)
	}
	step(60, false)
	step(60, true)
	if m := msgs(); m != name+" is offline (not seen for 10m00s)|"+name+" is online" {
		t.Errorf("events: %s", m)
	}
	// nothing watched any more: no more ticks for it, the state goes
	c.Devices[0].Watch = false
	step(60, true)
	if eventRunRead().WatchNext != 0 || fileExists(devWatchFile) {
		t.Error("watch state kept without watched devices")
	}
}
