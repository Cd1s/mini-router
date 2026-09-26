package main

// dev module: online / offline events for devices[].watch (#90), in the event log (type device) and so in
// the notifications. No daemon: `mr event tick` (sys, started by mon's per-minute sampler; eventSchedule
// makes it due every minute while a device is watched) calls devWatchPass.
//
// A device is seen while one of its MACs is associated with one of the router's BSSes (hostapd) or is in
// the neighbour table as REACHABLE / DELAY / PROBE (a wired device that talked through the router in the
// last minute or so; STALE entries can stay for hours and do not count). Online as soon as it is seen,
// offline after devWatchAway without being seen — so a phone that sleeps its WiFi for a few minutes does
// not flap. The first devWatchAway after the state is created (boot, first watched device) only learns.
// State: /run/mini-router/dev-watch.json (RAM).

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

const devWatchAway = 600 // s

var (
	devWatchFile = RunDir + "/dev-watch.json"
	// MACs seen right now (lowercase); a variable for tests
	devPresent = devPresentMACs
)

type devWatchState struct {
	Since int64                     `json:"since"`
	Dev   map[string]*devWatchEntry `json:"dev"`
}

type devWatchEntry struct {
	Seen   int64 `json:"seen"`
	Online bool  `json:"online"`
}

func devWatched(c *Config) []Device {
	var out []Device
	for _, d := range c.Devices {
		if d.Watch {
			out = append(out, d)
		}
	}
	return out
}

func devPresentMACs(c *Config) map[string]bool {
	m := map[string]bool{}
	for _, r := range c.WiFi.Radios {
		for _, ifn := range apIfnames(r) {
			for _, s := range hostapdStations(ifn) {
				m[strings.ToLower(s.MAC)] = true
			}
		}
	}
	if nb, err := monNeighbours(); err == nil {
		for _, n := range nb {
			if n.State&0x1a != 0 { // NUD_REACHABLE | NUD_DELAY | NUD_PROBE
				m[strings.ToLower(n.MAC)] = true
			}
		}
	}
	return m
}

// devWatchPass: one sample of every watched device, and its events.
func devWatchPass(c *Config) {
	ws := devWatched(c)
	if len(ws) == 0 {
		os.Remove(devWatchFile)
		return
	}
	now := eventNow().Unix()
	var st devWatchState
	readJSONFile(devWatchFile, &st)
	if st.Since == 0 || st.Since > now {
		st.Since = now
	}
	quiet := now-st.Since < devWatchAway
	seen := devPresent(c)
	next := map[string]*devWatchEntry{}
	kept := false
	for _, d := range ws {
		e := st.Dev[d.Name]
		if e == nil {
			e = &devWatchEntry{Seen: now}
		}
		here := false
		for _, m := range d.MACs {
			here = here || seen[strings.ToLower(m)]
		}
		if here {
			e.Seen = now
		}
		switch {
		case here && !e.Online:
			e.Online = true
			if !quiet {
				kept = eventAdd(c, "device", "info", d.Name, d.Name+" is online", false) || kept
			}
		case !here && e.Online && now-e.Seen >= devWatchAway:
			e.Online = false
			if !quiet {
				kept = eventAdd(c, "device", "info", d.Name, fmt.Sprintf("%s is offline (not seen for %s)", d.Name, fmtSecs(now-e.Seen)), false) || kept
			}
		}
		next[d.Name] = e
	}
	st.Dev = next
	b, _ := json.Marshal(st)
	writeAtomic(devWatchFile, b, 0600)
	if kept {
		eventKick(c, "device")
	}
}
