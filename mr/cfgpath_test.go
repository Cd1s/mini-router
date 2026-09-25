package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestParsePath(t *testing.T) {
	for p, want := range map[string][]pathStep{
		"firewall.forwards[nas-ssh].enabled":   {{key: "firewall"}, {key: "forwards"}, {sel: true, val: "nas-ssh"}, {key: "enabled"}},
		"dhcp.hosts[mac=aa:bb:cc:dd:ee:ff].ip": {{key: "dhcp"}, {key: "hosts"}, {sel: true, selK: "mac", val: "aa:bb:cc:dd:ee:ff"}, {key: "ip"}},
		`system.sysctl."net.core.rmem_max"`:    {{key: "system"}, {key: "sysctl"}, {key: "net.core.rmem_max"}},
		`wifi.radios[phy1].ssids["a]b c"]`:     {{key: "wifi"}, {key: "radios"}, {sel: true, val: "phy1"}, {key: "ssids"}, {sel: true, val: "a]b c"}},
		"system.ntp[0]":                        {{key: "system"}, {key: "ntp"}, {sel: true, val: "0"}},
		"lan":                                  {{key: "lan"}},
	} {
		got, err := parsePath(p)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("%s: %+v %v", p, got, err)
			continue
		}
		if back := fmtPath(got); back != p {
			t.Errorf("fmtPath(parsePath(%q)) = %q", p, back)
		}
	}
	for _, p := range []string{"", "a..b", "a[", "a[]", ".a", "a.", `a."open`, "a]b", "a[x]b", "a b"} {
		if st, err := parsePath(p); err == nil {
			t.Errorf("%q accepted: %+v", p, st)
		}
	}
}

const editSrc = `# the router
system:
  hostname: r1   # its name
  history: 30

lan: {bridge: br-lan, ports: [lan1], ipv4: 10.0.0.1/24}

firewall:
  forwards:
    - {name: web, proto: [tcp], port: "8443", to: 10.0.0.2}  # web
    # ssh from outside
    - name: ssh
      proto: [tcp]
      port: "2222"
      to: 10.0.0.3
`

func edit(t *testing.T, src string, ops ...patchOp) string {
	t.Helper()
	out, _, kept, err := editYAML([]byte(src), ops)
	if err != nil {
		t.Fatal(err)
	}
	if !kept {
		t.Fatalf("layout not kept:\n%s", out)
	}
	return string(out)
}

func opSet(p, v string) patchOp {
	n, err := parseValue(v)
	if err != nil {
		panic(err)
	}
	return patchOp{Op: "set", Path: p, node: n}
}

func opAdd(p, v string) patchOp { o := opSet(p, v); o.Op = "add"; return o }
func opDel(p string) patchOp    { return patchOp{Op: "del", Path: p} }

// Edits change only their own lines: comments, order and layout stay; del removes the line.
func TestEditKeepsLayout(t *testing.T) {
	for _, c := range []struct {
		ops         []patchOp
		gone, added []string
	}{
		{[]patchOp{opSet("system.hostname", "r2")}, []string{"  hostname: r1   # its name\n"}, []string{"  hostname: r2   # its name\n"}},
		{[]patchOp{opSet("firewall.forwards[ssh].port", "2223")}, []string{"      port: \"2222\"\n"}, []string{"      port: \"2223\"\n"}},
		{[]patchOp{opDel("system.history")}, []string{"  history: 30\n"}, nil},
		{[]patchOp{opDel("firewall.forwards[web]")}, []string{"    - {name: web, proto: [tcp], port: \"8443\", to: 10.0.0.2}  # web\n"}, nil},
		{[]patchOp{opSet("firewall.forwards[web].enabled", "false")}, []string{"    - {name: web, proto: [tcp], port: \"8443\", to: 10.0.0.2}  # web\n"},
			[]string{"    - {name: web, proto: [tcp], port: \"8443\", to: 10.0.0.2, enabled: false}  # web\n"}},
		{[]patchOp{opAdd("firewall.forwards", `{name: dns, proto: [udp], port: "53", to: 10.0.0.4}`)}, nil,
			[]string{"    - {name: dns, proto: [udp], port: \"53\", to: 10.0.0.4}\n"}},
		{[]patchOp{opAdd("lan.ports", "lan2")}, []string{"lan: {bridge: br-lan, ports: [lan1], ipv4: 10.0.0.1/24}\n"},
			[]string{"lan: {bridge: br-lan, ports: [lan1, lan2], ipv4: 10.0.0.1/24}\n"}},
		{[]patchOp{opDel("lan.ports[lan1]")}, []string{"lan: {bridge: br-lan, ports: [lan1], ipv4: 10.0.0.1/24}\n"},
			[]string{"lan: {bridge: br-lan, ports: [], ipv4: 10.0.0.1/24}\n"}},
	} {
		out := edit(t, editSrc, c.ops...)
		gone, added := lineDiff(editSrc, out)
		if !reflect.DeepEqual(gone, c.gone) || !reflect.DeepEqual(added, c.added) {
			t.Errorf("%+v:\n-%q\n+%q\n%s", c.ops[0], gone, added, out)
		}
	}
	// new keys and sections: added, the rest untouched
	out := edit(t, editSrc, opSet(`system.sysctl."net.core.rmem_max"`, "8000000"), opSet("proxy.enabled", "true"))
	c, err := decodeConfig([]byte(out))
	if err != nil {
		t.Fatal(err)
	}
	if c.System.Sysctl["net.core.rmem_max"] != "8000000" || !c.Proxy.Enabled || c.System.Hostname != "r1" {
		t.Errorf("new keys: %+v %+v\n%s", c.System, c.Proxy, out)
	}
	if gone, _ := lineDiff(editSrc, out); len(gone) > 0 {
		t.Errorf("lines lost: %q", gone)
	}
}

func TestEditErrors(t *testing.T) {
	for _, ops := range [][]patchOp{
		{opSet("nosuch.key", "1")},
		{opSet("lan.ipv6_ra", "maybe")},
		{opSet("lan", "5")},
		{opSet("firewall.forwards[nosuch].port", `"1"`)},
		{opAdd("firewall.forwards", `{name: web, port: "1"}`)},
		{opAdd("firewall.forwards", `{port: "1"}`)},
		{opAdd("lan.ports", "lan1")},
		{opAdd("system.hostname", "x")},
		{opDel("system.nosuch")},
		{opDel("firewall.forwards[nosuch]")},
		{{Op: "move", Path: "lan"}},
		{{Op: "set", Path: "lan.ipv4"}},
	} {
		if out, _, _, err := editYAML([]byte(editSrc), ops); err == nil {
			t.Errorf("%+v accepted:\n%s", ops[0], out)
		}
	}
	// API values are JSON
	out, c, _, err := editYAML([]byte(editSrc), []patchOp{{Op: "set", Path: "firewall.forwards[ssh].proto", Value: []byte(`["tcp","udp"]`)}})
	if err != nil || strings.Join(c.Firewall.Forwards[1].Proto, ",") != "tcp,udp" || !strings.Contains(string(out), "proto: [tcp, udp]") {
		t.Errorf("JSON value: %v\n%s", err, out)
	}
}

// Every value of the home and lab configs as `mr export --flat` writes it: the path finds it again and
// the value reads back the same.
func TestFlatPaths(t *testing.T) {
	src, sf := labYAML(t)
	lab := filepath.Join(t.TempDir(), "lab.yaml")
	os.WriteFile(lab, []byte(src), 0644)
	for _, cfg := range [][2]string{{"../examples/router.yaml", "testdata/secrets.yaml"}, {lab, sf}} {
		c, err := loadConfig(cfg[0], cfg[1])
		if err != nil {
			t.Fatal(err)
		}
		root, _ := canonNode(c)
		lines := flatLines(root, "")
		if len(lines) < 100 {
			t.Fatalf("%s: only %d values", cfg[0], len(lines))
		}
		for _, l := range lines {
			p, v, ok := splitAssign(l)
			if !ok {
				t.Fatalf("no = in %q", l)
			}
			steps, err := parsePath(p)
			if err != nil {
				t.Errorf("%q: %v", l, err)
				continue
			}
			n, err := nodeAt(root, steps, false)
			if err != nil {
				t.Errorf("%q: %v", l, err)
				continue
			}
			if got := renderFlow(n); got != v {
				t.Errorf("%q reads back %q", l, got)
			}
			if pv, err := parseValue(v); err != nil || (n.Kind == yaml.ScalarNode && pv.Value != n.Value) {
				t.Errorf("%q: value does not parse back (%v)", l, err)
			}
		}
	}
}

// mr set / del on a copy of the home config: validated, the changes listed, layout kept; an invalid
// result is refused and the file left alone.
func TestSetCommand(t *testing.T) {
	d := t.TempDir()
	cfg, secf := filepath.Join(d, "router.yaml"), filepath.Join(d, "secrets.yaml")
	src := homeYAML(t)
	os.WriteFile(cfg, []byte(src), 0644)
	b, _ := os.ReadFile("testdata/secrets.yaml")
	os.WriteFile(secf, b, 0600)
	c := testConfig(t)
	fwd := c.Firewall.Forwards[0].Name
	other := "software"
	if c.Firewall.Offload == "software" {
		other = "off"
	}
	changes, _, _, err := editFile(cfg, secf, []patchOp{opSet("firewall.offload", other)})
	if err != nil || len(changes) != 1 || !strings.HasPrefix(changes[0], "~ firewall.offload: ") {
		t.Fatalf("changes %q %v", changes, err)
	}
	if err := cfgCommand("set", []string{"firewall.offload=bogus"}, cfg, secf); err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Errorf("invalid value accepted: %v", err)
	}
	if mustRead(t, cfg) != src {
		t.Fatal("refused edit changed the file")
	}
	if err := cfgCommand("set", []string{"-n", "firewall.forwards[" + fwd + "].enabled=false"}, cfg, secf); err != nil || mustRead(t, cfg) != src {
		t.Fatalf("dry run: %v", err)
	}
	if err := cfgCommand("set", []string{"firewall.forwards[" + fwd + "].enabled=false"}, cfg, secf); err != nil {
		t.Fatal(err)
	}
	gone, added := lineDiff(src, mustRead(t, cfg))
	if len(gone) != 1 || len(added) != 1 || !strings.Contains(added[0], "enabled: false") {
		t.Errorf("set changed -%q +%q", gone, added)
	}
	if err := cfgCommand("del", []string{"firewall.forwards[" + fwd + "].enabled"}, cfg, secf); err != nil {
		t.Fatal(err)
	}
	if got := mustRead(t, cfg); got != src {
		gone, added := lineDiff(src, got)
		t.Errorf("set + del is not the original: -%q +%q", gone, added)
	}
}
