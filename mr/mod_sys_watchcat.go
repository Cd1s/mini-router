package main

// sys module: watchcat (system.watchcat, Cd1s/mini-router#29) — when every WAN has been down for
// `after` minutes, escalate with backoff: redial the WANs → restart mr-network → reboot (at most once
// per `reboot_hours`, never during a pending change or right after boot). `mr watchcat tick` runs from
// crond every minute; "down" comes from the multi-WAN checker (wan-state.json) when it runs, else from
// one ping round to the targets. Every step is an event (type watchcat). No daemon.

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// Watchcat is system.watchcat.
type Watchcat struct {
	Enabled     bool     `yaml:"enabled"`
	After       int      `yaml:"after,omitempty"`        // minutes all WANs down before the first step (default 10)
	RebootHours int      `yaml:"reboot_hours,omitempty"` // at most one watchcat reboot per this many hours (default 6)
	Targets     []string `yaml:"targets,omitempty"`      // IPv4 pinged without multiwan (default: multiwan.targets or 1.1.1.1, 223.5.5.5)
}

const wcBootQuiet = 600 // s after boot without any step

var (
	wcStateFile  = RunDir + "/watchcat.json"
	wcRebootFile = "/etc/mini-router/state/watchcat-reboot" // unix time of the last watchcat reboot (flash)
)

type wcState struct {
	DownSince int64 `json:"down_since,omitempty"`
	NextAt    int64 `json:"next_at,omitempty"`
	Step      int   `json:"step,omitempty"`
}

type wcIn struct {
	Now, LastReboot int64
	Uptime          float64
	Online, Pending bool
	After, Gap      int64 // seconds
}

// wcStep is the state machine: the next state and the action ("" | recovered | redial | restart | reboot).
func wcStep(s wcState, in wcIn) (wcState, string) {
	if in.Online {
		if s.Step > 0 {
			return wcState{}, "recovered"
		}
		return wcState{}, ""
	}
	if s.DownSince == 0 {
		s.DownSince = in.Now
	}
	if in.Pending || in.Uptime < wcBootQuiet || in.Now-s.DownSince < in.After || in.Now < s.NextAt {
		return s, ""
	}
	act := [...]string{"redial", "restart", "reboot"}[min(s.Step, 2)]
	if act == "reboot" && in.LastReboot > 0 && in.Now-in.LastReboot < in.Gap {
		act = "restart"
	}
	s.NextAt = in.Now + in.After<<min(s.Step, 3)
	s.Step++
	return s, act
}

func wcDefaults(c *Config) {
	w := &c.System.Watchcat
	if !w.Enabled {
		return
	}
	if w.After == 0 {
		w.After = 10
	}
	if w.RebootHours == 0 {
		w.RebootHours = 6
	}
}

func wcValidate(c *Config, v *Validator) {
	w := c.System.Watchcat
	if !w.Enabled {
		return
	}
	if !c.routerMode() || len(c.WAN) == 0 {
		v.Add("system.watchcat: needs mode router with a WAN")
	}
	if w.After < 3 || w.After > 240 {
		v.Add("system.watchcat.after: 3-240 minutes, got %d", w.After)
	}
	if w.RebootHours < 1 || w.RebootHours > 168 {
		v.Add("system.watchcat.reboot_hours: 1-168, got %d", w.RebootHours)
	}
	if len(w.Targets) > 4 {
		v.Add("system.watchcat.targets: at most 4")
	}
	for _, t := range w.Targets {
		if a, err := netip.ParseAddr(t); err != nil || !a.Is4() {
			v.Add("system.watchcat.targets: IPv4 address, got %q", t)
		}
	}
}

func wcCronLine(c *Config) []string {
	if !c.System.Watchcat.Enabled {
		return nil
	}
	return []string{"# watchcat (system.watchcat)", "* * * * * " + mrBin + " watchcat tick"}
}

// wcOnline: any WAN up per the multi-WAN checker (when its state is fresh), else one ping round.
var wcOnline = func(c *Config) bool {
	if f, ok := readWanHealth(); ok && len(f.WANs) > 0 && eventNow().Unix()-f.Time < int64(3*max(f.Interval, 5)+60) {
		for _, w := range f.WANs {
			if w.State == "up" {
				return true
			}
		}
		return false
	}
	targets := c.System.Watchcat.Targets
	if len(targets) == 0 {
		targets = c.MultiWAN.Targets
	}
	if len(targets) == 0 {
		targets = []string{"1.1.1.1", "223.5.5.5"}
	}
	for _, t := range targets {
		if _, err := run("ping", "-c", "1", "-W", "3", t); err == nil {
			return true
		}
	}
	return false
}

// wcRun performs an action (a variable so tests can record it).
var wcRun = func(c *Config, act string) {
	switch act {
	case "redial":
		for _, w := range c.WAN {
			if svc := netService(w); svc != "" {
				run("rc-service", svc, "restart")
			}
		}
	case "restart":
		run("rc-service", "mr-network", "restart")
	case "reboot":
		os.WriteFile(wcRebootFile, []byte(strconv.FormatInt(eventNow().Unix(), 10)+"\n"), 0644)
		run("sync")
		run("reboot")
	}
}

var wcMsg = map[string]string{
	"recovered": "internet back after watchcat steps",
	"redial":    "all WANs down for %d min: redialing",
	"restart":   "all WANs still down: restarting the network",
	"reboot":    "all WANs still down: rebooting",
}

// wcTick is `mr watchcat tick` (crond, every minute).
func wcTick(c *Config) error {
	w := c.System.Watchcat
	if !w.Enabled {
		return nil
	}
	lk := flock(wcStateFile+".lock", false)
	if lk == nil {
		return nil
	}
	defer lk.Close()
	var s wcState
	readJSONFile(wcStateFile, &s)
	p, _ := readPending()
	last, _ := strconv.ParseInt(strings.TrimSpace(readFile(wcRebootFile)), 10, 64)
	in := wcIn{Now: eventNow().Unix(), LastReboot: last, Uptime: eventUptime(), Online: wcOnline(c), Pending: p != nil,
		After: int64(w.After) * 60, Gap: int64(w.RebootHours) * 3600}
	ns, act := wcStep(s, in)
	if b, err := json.Marshal(ns); err == nil {
		writeAtomic(wcStateFile, b, 0644)
	}
	if act == "" {
		return nil
	}
	sev := "warn"
	if act == "recovered" {
		sev = "info"
	}
	msg := wcMsg[act]
	if strings.Contains(msg, "%d") {
		msg = fmt.Sprintf(msg, w.After)
	}
	logf("watchcat: %s", msg)
	eventAdd(c, "watchcat", sev, act, msg, act != "reboot")
	wcRun(c, act)
	return nil
}

func wcCommand(c *Config, args []string) error {
	if len(args) != 1 || args[0] != "tick" {
		return fmt.Errorf("usage: mr watchcat tick")
	}
	return wcTick(c)
}
