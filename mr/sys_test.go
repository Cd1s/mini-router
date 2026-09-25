package main

import "testing"

// effOper: ethernet keeps its operstate; ppp / tun ("unknown") follow IFF_UP|IFF_RUNNING.
func TestEffOper(t *testing.T) {
	for _, c := range []struct{ oper, flags, want string }{
		{"up", "0x1003", "up"},
		{"down", "0x1003", "down"},
		{"unknown", "0x10d1", "up"},
		{"unknown", "0x1d1\n", "up"},
		{"unknown", "0x1090", "down"},
		{"unknown", "0x1001", "down"},
		{"unknown", "", "unknown"},
		{"dormant", "0x10d1", "dormant"},
	} {
		if got := effOper(c.oper, c.flags); got != c.want {
			t.Errorf("effOper(%q, %q) = %q, want %q", c.oper, c.flags, got, c.want)
		}
	}
}
