package main

// fw module: presence rules (firewall.rules[].when, Cd1s/mini-router#47) — a traffic rule that is active
// only while devices are at home (present) or away (absent).
//
// A device is present while one of its MACs was seen (a WiFi station or a REACHABLE neighbour) in the
// last presenceHold seconds, so it turns absent ~10 minutes after it left (phones sleep and drop off
// WiFi briefly). `mr presence tick` (crond, every minute) records what it sees in
// /run/mini-router/presence.json and reloads the firewall only when a rule's state changes.
// The rendered ruleset has `jump when_<hash>` and an empty chain per rule, so it never depends on
// who is home; fwLoad fills the chains of the active rules in the same transaction (presenceScript).

import (
	"encoding/json"
	"fmt"
	"hash/fnv"
	"slices"
	"strings"
	"time"
)

// FwWhen: devices (inventory names, group:NAME) or MACs.
type FwWhen struct {
	Present []string `yaml:"present,omitempty" json:"present,omitempty"`
	Absent  []string `yaml:"absent,omitempty" json:"absent,omitempty"`
}

const presenceHold = 600

var (
	presenceFile = RunDir + "/presence.json"
	presenceNow  = time.Now
	// presenceSeen: the MACs on the network right now (WiFi stations + reachable neighbours), lowercase
	presenceSeen = func(c *Config) []string {
		var out []string
		for _, s := range stationsFor(c) {
			out = append(out, strings.ToLower(s.MAC))
		}
		for _, nud := range []string{"reachable", "delay", "probe"} {
			o, _ := run("ip", "neigh", "show", "nud", nud)
			for _, l := range strings.Split(o, "\n") {
				f := strings.Fields(l)
				if i := slices.Index(f, "lladdr"); i >= 0 && i+1 < len(f) {
					out = append(out, strings.ToLower(f[i+1]))
				}
			}
		}
		return out
	}
)

type presenceState struct {
	Seen   map[string]int64 `json:"seen"`   // MAC → last seen (unix)
	Active []string         `json:"active"` // rules active at the last reload
}

func presenceRules(c *Config) []FwRule {
	var out []FwRule
	for _, r := range c.Firewall.Rules {
		if on(r.Enabled) && r.When != nil {
			out = append(out, r)
		}
	}
	return out
}

func presenceChain(name string) string {
	h := fnv.New32a()
	h.Write([]byte(name))
	return fmt.Sprintf("when_%08x", h.Sum32())
}

func presenceMACs(c *Config, refs []string) []string {
	var out []string
	for _, r := range refs {
		if reMAC.MatchString(r) {
			out = append(out, strings.ToLower(r))
		} else if m, ok := devRefMACs(c, r); ok {
			out = append(out, m...)
		}
	}
	return out
}

// presenceActive: the names of the rules whose condition holds.
func presenceActive(c *Config, seen map[string]int64, now int64) []string {
	here := func(ref string) bool {
		for _, m := range presenceMACs(c, []string{ref}) {
			if now-seen[m] < presenceHold {
				return true
			}
		}
		return false
	}
	var out []string
	for _, r := range presenceRules(c) {
		ok := true
		for _, d := range r.When.Present {
			ok = ok && here(d)
		}
		for _, d := range r.When.Absent {
			ok = ok && !here(d)
		}
		if ok {
			out = append(out, r.Name)
		}
	}
	return out
}

func presenceLoad() presenceState {
	st := presenceState{Seen: map[string]int64{}}
	readJSONFile(presenceFile, &st)
	if st.Seen == nil {
		st.Seen = map[string]int64{}
	}
	return st
}

// presenceScript: the active rules' lines, for fwLoad's transaction.
func presenceScript(c *Config) string {
	if len(presenceRules(c)) == 0 {
		return ""
	}
	active := presenceActive(c, presenceLoad().Seen, presenceNow().Unix())
	var b strings.Builder
	for _, r := range presenceRules(c) {
		if !slices.Contains(active, r.Name) {
			continue
		}
		x := r
		x.When = nil
		for _, l := range fwRuleLines(c, x, fwClockFor(c)) {
			fmt.Fprintf(&b, "add rule inet mr %s %s\n", presenceChain(r.Name), l)
		}
	}
	return b.String()
}

func presenceCronLine(c *Config) []string {
	if len(presenceRules(c)) == 0 {
		return nil
	}
	return []string{"# presence rules (firewall.rules[].when)", "* * * * * " + mrBin + " presence tick"}
}

// presenceTick is `mr presence tick`.
func presenceTick(c *Config) error {
	if len(presenceRules(c)) == 0 {
		return nil
	}
	st := presenceLoad()
	now := presenceNow().Unix()
	for _, m := range presenceSeen(c) {
		st.Seen[m] = now
	}
	for m, t := range st.Seen {
		if now-t > 86400 {
			delete(st.Seen, m)
		}
	}
	active := presenceActive(c, st.Seen, now)
	changed := !slices.Equal(active, st.Active)
	st.Active = active
	if b, err := json.Marshal(st); err == nil {
		writeAtomic(presenceFile, b, 0644)
	}
	if !changed {
		return nil
	}
	logf("presence: active rules now %v", active)
	return fwLoad(c)
}

func presenceValidate(c *Config, v *Validator, p string, w *FwWhen) {
	if w == nil {
		return
	}
	refs := append(append([]string{}, w.Present...), w.Absent...)
	if len(refs) == 0 || len(refs) > 16 {
		v.Add("%s.when: present and / or absent, 1-16 devices", p)
	}
	for _, r := range refs {
		if !reMAC.MatchString(r) {
			devCheckRefs(c, v, p+".when", []string{r})
		}
	}
}

func presenceCommand(c *Config, args []string) error {
	if len(args) != 1 || args[0] != "tick" {
		return fmt.Errorf("usage: mr presence tick")
	}
	return presenceTick(c)
}
