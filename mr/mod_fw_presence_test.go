package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPresenceRules(t *testing.T) {
	c := testConfig(t)
	c.Devices = append(c.Devices, Device{Name: "phone", MACs: []string{"02:00:00:00:00:51", "02:00:00:00:00:52"}})
	c.Firewall.Rules = append(c.Firewall.Rules,
		FwRule{Name: "cam-home", Action: "drop", Src: "lan", Dest: "wan", SrcMAC: []string{"aa:bb:cc:00:00:61"}, When: &FwWhen{Present: []string{"phone"}}},
		FwRule{Name: "away", Action: "reject", Dest: "router", Proto: []string{"tcp"}, DestPort: "22", When: &FwWhen{Absent: []string{"aa:bb:cc:00:00:62"}}})
	if errs := c.Validate(); len(errs) > 0 {
		t.Fatal(errs)
	}
	nft := renderNft(c, func(string) bool { return true })
	for _, n := range []string{"cam-home", "away"} {
		ch := presenceChain(n)
		if !strings.Contains(nft, "chain "+ch+" {") || !strings.Contains(nft, "jump "+ch+"\n") {
			t.Errorf("%s: chain / jump missing", n)
		}
	}
	now := int64(100000)
	seen := map[string]int64{"02:00:00:00:00:52": now - 300, "aa:bb:cc:00:00:62": now - 700}
	if a := presenceActive(c, seen, now); strings.Join(a, ",") != "cam-home,away" {
		t.Errorf("active: %v", a)
	}
	seen["02:00:00:00:00:52"], seen["aa:bb:cc:00:00:62"] = now-601, now-10 // phone left 10 min ago; the other came home
	if a := presenceActive(c, seen, now); len(a) != 0 {
		t.Errorf("active after: %v", a)
	}
	// fwLoad's part: the lines of the active rules go into their chains
	old, oldNow := presenceFile, presenceNow
	defer func() { presenceFile, presenceNow = old, oldNow }()
	presenceFile = filepath.Join(t.TempDir(), "presence.json")
	presenceNow = func() time.Time { return time.Unix(now, 0) }
	b, _ := json.Marshal(presenceState{Seen: map[string]int64{"02:00:00:00:00:51": now}})
	os.WriteFile(presenceFile, b, 0644)
	sc := presenceScript(c)
	if !strings.Contains(sc, "add rule inet mr "+presenceChain("cam-home")+" iifname") || !strings.Contains(sc, `drop comment "rule:cam-home"`) ||
		!strings.Contains(sc, `comment "rule:away"`) {
		t.Errorf("script:\n%s", sc)
	}
	c.Firewall.Rules[len(c.Firewall.Rules)-1].When = &FwWhen{Present: []string{"nobody"}}
	if errs := strings.Join(c.Validate(), "\n"); !strings.Contains(errs, `.when: unknown device "nobody"`) {
		t.Errorf("errs: %s", errs)
	}
}
