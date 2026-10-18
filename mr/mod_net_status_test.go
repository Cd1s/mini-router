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
