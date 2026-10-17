package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNetVerifyPPPoEUnavailableWithOtherWAN(t *testing.T) {
	c := testConfig(t)
	c.WAN = []WAN{
		{Name: "wan", Device: "wan", Proto: "pppoe"},
		{Name: "backup", Device: "backup", Proto: "dhcp"},
	}
	d := t.TempDir()
	oldNet, oldDeadline, oldAddrs := sysNet, verifyDeadline, ipv4AddrsForVerify
	sysNet = d
	verifyDeadline = func(...*Config) time.Time { return time.Now().Add(-time.Second) }
	ipv4AddrsForVerify = func(dev string) []string {
		if dev == "backup" {
			return []string{"198.51.100.2/24"}
		}
		return nil
	}
	t.Cleanup(func() { sysNet, verifyDeadline, ipv4AddrsForVerify = oldNet, oldDeadline, oldAddrs })
	for _, dev := range []string{"wan", "backup"} {
		if err := os.MkdirAll(filepath.Join(d, dev), 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(d, "wan", "carrier"), []byte("1"), 0644); err != nil {
		t.Fatal(err)
	}
	if errs := netVerify(c, []string{"mr-pppoe.wan"}); len(errs) != 0 {
		t.Fatalf("PPPoE outage with another WAN online caused verification failure: %v", errs)
	}
}
