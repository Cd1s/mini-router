package main

import (
	"fmt"
	"strings"
	"testing"
)

func TestRefreshLan6IncludesExtraLANBridges(t *testing.T) {
	c := testConfig(t)
	c.Networks = []Network{{Name: "iot", IPv4: "192.168.30.1/24", IPv6RA: true}}
	oldRun, oldStdin := runLan6, runLan6Stdin
	t.Cleanup(func() { runLan6, runLan6Stdin = oldRun, oldStdin })
	var script string
	runLan6 = func(name string, args ...string) (string, error) {
		if name != "ip" {
			return "", fmt.Errorf("unexpected command %s", name)
		}
		bridge := args[5]
		return map[string]string{
			"br-lan": "2: br-lan    inet6 2001:db8:1::1/64 scope global\n",
			"br-iot": "3: br-iot    inet6 2001:db8:2::1/64 scope global\n",
		}[bridge], nil
	}
	runLan6Stdin = func(in, name string, args ...string) (string, error) {
		script = in
		return "", nil
	}
	if err := refreshLan6For(c); err != nil {
		t.Fatal(err)
	}
	for _, prefix := range []string{"2001:db8:1::/64", "2001:db8:2::/64"} {
		if !strings.Contains(script, prefix) {
			t.Errorf("@lan6 script missing %s: %s", prefix, script)
		}
	}
}
