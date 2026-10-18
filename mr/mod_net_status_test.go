package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNetVerifyPPPoEUnavailableWithOtherWAN(t *testing.T) {
	c := testConfig(t)
	c.MultiWAN.DialOrder = nil
	c.WAN = []WAN{
		{Name: "wan", Device: "wan", Proto: "pppoe"},
		{Name: "backup", Device: "backup", Proto: "dhcp"},
	}
	d := t.TempDir()
	oldNet, oldDeadline, oldAddrs, oldAccepted := sysNet, verifyDeadline, ipv4AddrsForVerify, acceptedWANConfigForVerify
	sysNet = d
	verifyDeadline = func(...*Config) time.Time { return time.Now().Add(-time.Second) }
	ipv4AddrsForVerify = func(dev string) []string {
		if dev == "backup" {
			return []string{"198.51.100.2/24"}
		}
		return nil
	}
	acceptedWANConfigForVerify = func() (*Config, bool) { return c, true }
	t.Cleanup(func() {
		sysNet, verifyDeadline, ipv4AddrsForVerify, acceptedWANConfigForVerify = oldNet, oldDeadline, oldAddrs, oldAccepted
	})
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

func TestNetVerifyChangedPPPoEWithOtherWANStillFails(t *testing.T) {
	c := testConfig(t)
	c.MultiWAN.DialOrder = nil
	old := *c
	old.WAN = append([]WAN(nil), c.WAN...)
	old.secrets = map[string]string{"pppoe_password": "old-password"}
	c.secrets = map[string]string{"pppoe_password": "new-password"}
	c.WAN[0].Password = "pppoe_password"
	d := t.TempDir()
	oldNet, oldDeadline, oldAddrs, oldAccepted := sysNet, verifyDeadline, ipv4AddrsForVerify, acceptedWANConfigForVerify
	sysNet = d
	verifyDeadline = func(...*Config) time.Time { return time.Now().Add(-time.Second) }
	ipv4AddrsForVerify = func(dev string) []string {
		if dev == c.WAN[1].Ifname() {
			return []string{"198.51.100.2/24"}
		}
		return nil
	}
	acceptedWANConfigForVerify = func() (*Config, bool) { return &old, true }
	t.Cleanup(func() {
		sysNet, verifyDeadline, ipv4AddrsForVerify, acceptedWANConfigForVerify = oldNet, oldDeadline, oldAddrs, oldAccepted
	})
	os.MkdirAll(filepath.Join(d, c.WAN[0].LinkDev()), 0755)
	os.WriteFile(filepath.Join(d, c.WAN[0].LinkDev(), "carrier"), []byte("1"), 0644)
	if errs := netVerify(c, []string{"mr-pppoe." + c.WAN[0].Name}); len(errs) == 0 {
		t.Fatal("changed PPPoE was exempted while another WAN was online")
	}
}

func TestNetVerifyUnchangedPPPoENoCarrierIsExempt(t *testing.T) {
	c := testConfig(t)
	c.MultiWAN.DialOrder = nil
	d := t.TempDir()
	oldNet, oldDeadline, oldAddrs, oldAccepted := sysNet, verifyDeadline, ipv4AddrsForVerify, acceptedWANConfigForVerify
	sysNet = d
	verifyDeadline = func(...*Config) time.Time { return time.Now().Add(-time.Second) }
	ipv4AddrsForVerify = func(string) []string { return nil }
	acceptedWANConfigForVerify = func() (*Config, bool) { return c, true }
	t.Cleanup(func() {
		sysNet, verifyDeadline, ipv4AddrsForVerify, acceptedWANConfigForVerify = oldNet, oldDeadline, oldAddrs, oldAccepted
	})
	if err := os.MkdirAll(filepath.Join(d, c.WAN[0].LinkDev()), 0755); err != nil {
		t.Fatal(err)
	}
	if errs := netVerify(c, []string{"mr-pppoe." + c.WAN[0].Name}); len(errs) != 0 {
		t.Fatalf("unchanged PPPoE without carrier was not exempted: %v", errs)
	}
}

func TestNetVerifyAllDialOrderWANsShareCappedDeadline(t *testing.T) {
	c := testConfig(t)
	c.WAN = []WAN{
		{Name: "wan1", Device: "wan1", Proto: "pppoe"},
		{Name: "wan2", Device: "wan2", Proto: "pppoe"},
		{Name: "wan3", Device: "wan3", Proto: "pppoe"},
		{Name: "wan4", Device: "wan4", Proto: "pppoe"},
	}
	c.MultiWAN.DialOrder = []string{"wan1", "wan2", "wan3", "wan4"}
	c.MultiWAN.DialWait = 120
	d := t.TempDir()
	oldNet, oldAddrs, oldAccepted, oldNow, oldSleep := sysNet, ipv4AddrsForVerify, acceptedWANConfigForVerify, verifyNow, verifySleep
	sysNet = d
	ipv4AddrsForVerify = func(string) []string { return nil }
	acceptedWANConfigForVerify = func() (*Config, bool) { return c, true }
	now := time.Unix(1_800_000_000, 0)
	verifyNow = func() time.Time { return now }
	verifySleep = func(d time.Duration) { now = now.Add(d) }
	t.Cleanup(func() {
		sysNet, ipv4AddrsForVerify, acceptedWANConfigForVerify, verifyNow, verifySleep = oldNet, oldAddrs, oldAccepted, oldNow, oldSleep
	})
	for _, w := range c.WAN {
		if err := os.MkdirAll(filepath.Join(d, w.LinkDev()), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, w.LinkDev(), "carrier"), []byte("1"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	restarted := []string{"mr-pppoe.wan1", "mr-pppoe.wan2", "mr-pppoe.wan3", "mr-pppoe.wan4"}
	if errs := netVerify(c, restarted); len(errs) != len(restarted) {
		t.Fatalf("verification errors = %v, want one per failed WAN", errs)
	}
	if elapsed := now.Sub(time.Unix(1_800_000_000, 0)); elapsed > 300*time.Second {
		t.Fatalf("shared verification budget exceeded: %v", elapsed)
	}
}
