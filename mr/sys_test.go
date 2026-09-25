package main

import "testing"

// effOper: ethernet keeps its operstate; ppp / tun ("unknown") are up when IFF_UP and carrier = 1.
// The values are what a router reports (sysfs flags never include IFF_RUNNING).
func TestEffOper(t *testing.T) {
	for _, c := range []struct{ oper, flags, carrier, want string }{
		{"up", "0x1003", "1", "up"},
		{"down", "0x1003", "0", "down"},
		{"lowerlayerdown", "0x1303", "0", "lowerlayerdown"},
		{"unknown", "0x1091\n", "1\n", "up"},
		{"unknown", "0x1091", "0", "down"},
		{"unknown", "0x1090", "", "down"},
		{"unknown", "", "", "unknown"},
		{"dormant", "0x1091", "1", "dormant"},
	} {
		if got := effOper(c.oper, c.flags, c.carrier); got != c.want {
			t.Errorf("effOper(%q, %q, %q) = %q, want %q", c.oper, c.flags, c.carrier, got, c.want)
		}
	}
}
