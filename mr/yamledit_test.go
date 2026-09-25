package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// uiSave does what the web UI does with router.yaml src: load it as the page's JSON, let edit change
// that JSON, submit it — and returns the router.yaml that would be installed.
func uiSave(t *testing.T, src, secrets string, edit func(m map[string]any)) string {
	t.Helper()
	out, err := uiSaveErr(t, src, secrets, edit)
	if err != nil {
		t.Fatalf("layout not kept: %v", err)
	}
	return out
}

func uiSaveErr(t *testing.T, src, secrets string, edit func(m map[string]any)) (string, error) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "router.yaml")
	os.WriteFile(p, []byte(src), 0644)
	c, err := loadConfig(p, secrets)
	if err != nil {
		t.Fatal(err)
	}
	m, err := configToJSON(c)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(m)
	var page map[string]any
	json.Unmarshal(raw, &page)
	edit(page)
	raw, _ = json.Marshal(page)
	nc, y, err := configFromJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	nc.secrets = c.secrets
	nc.defaults()
	out, err := keepLayout([]byte(src), y, nc)
	if err != nil {
		// show the edited text around the failure
		if base, e1 := decodeConfig([]byte(src)); e1 == nil {
			base.secrets = nc.secrets
			base.defaults()
			want, _ := decodeConfig(y)
			bn, _ := canonNode(base)
			wn, _ := canonNode(want)
			if m, e2 := mergeYAML([]byte(src), bn, wn); e2 == nil {
				gone, added := changed(src, string(m))
				err = fmt.Errorf("%v\n-%q\n+%q", err, gone, added)
			}
		}
	}
	return string(out), err
}

// changed returns the lines only in a and only in b, after the common head and tail.
func changed(a, b string) (gone, added []string) {
	x, y := strings.SplitAfter(a, "\n"), strings.SplitAfter(b, "\n")
	i := 0
	for i < len(x) && i < len(y) && x[i] == y[i] {
		i++
	}
	j := 0
	for j < len(x)-i && j < len(y)-i && x[len(x)-1-j] == y[len(y)-1-j] {
		j++
	}
	return x[i : len(x)-j], y[i : len(y)-j]
}

// lineDiff: the lines only in a and only in b, counted as multisets (order ignored).
func lineDiff(a, b string) (gone, added []string) {
	n := map[string]int{}
	for _, l := range strings.SplitAfter(a, "\n") {
		n[l]++
	}
	for _, l := range strings.SplitAfter(b, "\n") {
		if n[l] > 0 {
			n[l]--
		} else {
			added = append(added, l)
		}
	}
	for l, c := range n {
		for ; c > 0; c-- {
			gone = append(gone, l)
		}
	}
	return gone, added
}

func homeYAML(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("../examples/router.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func sec(m map[string]any, path ...any) any {
	var v any = m
	for _, p := range path {
		switch k := p.(type) {
		case string:
			v = v.(map[string]any)[k]
		case int:
			v = v.([]any)[k]
		}
	}
	return v
}

// A save without changes leaves every byte; each edit touches exactly its own line(s) — comments,
// order, quoting, alignment and blank lines elsewhere stay (Cd1s/mini-router#11).
func TestUISaveKeepsLayout(t *testing.T) {
	src := homeYAML(t)
	const secrets = "testdata/secrets.yaml"
	fwd1 := sec(mustJSON(t, src), "firewall", "forwards", 1, "name").(string)
	if out := uiSave(t, src, secrets, func(map[string]any) {}); out != src {
		gone, added := changed(src, out)
		t.Fatalf("save without changes altered the file:\n-%q\n+%q", gone, added)
	}
	line := func(sub string) string { // the whole line of src containing sub
		i := strings.Index(src, sub)
		if i < 0 {
			t.Fatalf("%q not in the example", sub)
		}
		s := strings.LastIndex(src[:i], "\n") + 1
		return src[s : i+strings.Index(src[i:], "\n")+1]
	}
	cases := []struct {
		name        string
		edit        func(m map[string]any)
		gone, added func() []string
	}{
		{"scalar", func(m map[string]any) { sec(m, "system").(map[string]any)["hostname"] = "office" },
			func() []string { return []string{line("hostname: ")} },
			func() []string { return []string{"  hostname: office\n"} }},
		{"scalar in a list item, trailing comment kept", func(m map[string]any) { sec(m, "wan", 0).(map[string]any)["metric"] = 5 },
			func() []string { return []string{"    metric: 0\n"} },
			func() []string { return []string{"    metric: 5\n"} }},
		{"quoted string keeps its quotes", func(m map[string]any) { sec(m, "wan", 1).(map[string]any)["username"] = "0123" },
			func() []string {
				return []string{strings.Split(src[strings.Index(src, "  - name: wan2"):], "\n")[3] + "\n"}
			},
			func() []string { return []string{"    username: \"0123\"\n"} }},
		{"map value (sysctl)", func(m map[string]any) {
			sec(m, "system", "sysctl").(map[string]any)["net.ipv4.tcp_fin_timeout"] = "20"
		},
			func() []string { return []string{line("tcp_fin_timeout")} },
			func() []string { return []string{"    net.ipv4.tcp_fin_timeout: \"20\"\n"} }},
		{"inline list", func(m map[string]any) { sec(m, "lan").(map[string]any)["ports"] = []any{"lan2", "lan3"} },
			func() []string { return []string{line("ports: [")} },
			func() []string { return []string{"  ports: [lan2, lan3]\n"} }},
		{"bool switched off", func(m map[string]any) { sec(m, "wan", 1).(map[string]any)["ipv6_srcroute"] = false },
			func() []string { return []string{line("ipv6_srcroute")} },
			func() []string { return []string{"    ipv6_srcroute: false\n"} }},
		{"value inside a flow item: alignment kept", func(m map[string]any) {
			f := sec(m, "firewall", "forwards", 1).(map[string]any)
			f["to_port"] = "9000"
		},
			func() []string { return []string{line("name: " + fwd1 + ",")} },
			func() []string {
				l := line("name: " + fwd1 + ",")
				i := strings.Index(l, "to_port: ")
				return []string{l[:i] + `to_port: "9000"}` + "\n"}
			}},
		{"flow item appended after its siblings", func(m map[string]any) {
			fw := sec(m, "firewall").(map[string]any)
			fw["forwards"] = append(fw["forwards"].([]any), map[string]any{"name": "web", "proto": []any{"tcp"}, "port": "8080", "to": "192.168.1.50", "to_port": "80"})
		},
			func() []string { return nil },
			func() []string {
				return []string{`    - {name: web, proto: [tcp], port: "8080", to: 192.168.1.50, to_port: "80"}` + "\n"}
			}},
		{"named item removed", func(m map[string]any) {
			d := sec(m, "dhcp").(map[string]any)
			hosts := d["hosts"].([]any)
			d["hosts"] = append(append([]any{}, hosts[:1]...), hosts[2:]...)
		},
			func() []string {
				return []string{line("name: " + sec(mustJSON(t, src), "dhcp", "hosts", 1, "name").(string))}
			},
			func() []string { return nil }},
		{"new top-level section at the end", func(m map[string]any) {
			m["static_routes"] = []any{map[string]any{"name": "lab", "target": "10.9.0.0/16", "via": "192.168.1.2"}}
		},
			func() []string { return nil },
			func() []string {
				return []string{"\n", "static_routes:\n", "  - name: lab\n", "    target: 10.9.0.0/16\n", "    via: 192.168.1.2\n"}
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := uiSave(t, src, secrets, tc.edit)
			gone, added := changed(src, out)
			if strings.Join(gone, "") != strings.Join(tc.gone(), "") || strings.Join(added, "") != strings.Join(tc.added(), "") {
				t.Errorf("diff:\n-%q\n+%q\nwant:\n-%q\n+%q", gone, added, tc.gone(), tc.added())
			}
		})
	}
}

// An optional key switched off (omitempty) loses its line, comment included; adding it again puts it
// after the section's last key.
func TestUISaveOptionalKey(t *testing.T) {
	src := strings.Replace(homeYAML(t), "  synflood_protect: true\n", "  synflood_protect: true\n  log_drops: true             # noisy\n", 1)
	out := uiSave(t, src, "testdata/secrets.yaml", func(m map[string]any) { delete(sec(m, "firewall").(map[string]any), "log_drops") })
	if out != homeYAML(t) {
		gone, added := changed(src, out)
		t.Errorf("-%q\n+%q", gone, added)
	}
	out = uiSave(t, homeYAML(t), "testdata/secrets.yaml", func(m map[string]any) { sec(m, "firewall").(map[string]any)["log_drops"] = true })
	gone, added := changed(homeYAML(t), out)
	if len(gone) != 0 || strings.Join(added, "") != "  log_drops: true\n" {
		t.Errorf("-%q\n+%q", gone, added)
	}
}

// mustJSON: the page's JSON for src.
func mustJSON(t *testing.T, src string) map[string]any {
	return mustJSONWith(t, src, "testdata/secrets.yaml")
}

func mustJSONWith(t *testing.T, src, secrets string) map[string]any {
	t.Helper()
	p := filepath.Join(t.TempDir(), "router.yaml")
	os.WriteFile(p, []byte(src), 0644)
	c, err := loadConfig(p, secrets)
	if err != nil {
		t.Fatal(err)
	}
	m, _ := configToJSON(c)
	raw, _ := json.Marshal(m)
	var out map[string]any
	json.Unmarshal(raw, &out)
	return out
}

// Reordering a named list moves the items' lines (comments and all); nothing else changes.
func TestUISaveReorder(t *testing.T) {
	src := homeYAML(t)
	out := uiSave(t, src, "testdata/secrets.yaml", func(m map[string]any) {
		f := sec(m, "firewall").(map[string]any)["forwards"].([]any)
		f[0], f[1] = f[1], f[0]
	})
	lines := func(s string) map[string]int {
		n := map[string]int{}
		for _, l := range strings.SplitAfter(s, "\n") {
			n[l]++
		}
		return n
	}
	a, b := lines(src), lines(out)
	for l, n := range a {
		if b[l] != n {
			t.Fatalf("reorder changed the line set: %q %d -> %d", l, n, b[l])
		}
	}
	m := mustJSON(t, src)
	n0, n1 := sec(m, "firewall", "forwards", 0, "name").(string), sec(m, "firewall", "forwards", 1, "name").(string)
	i0, i1 := strings.Index(out, "name: "+n0+","), strings.Index(out, "name: "+n1+",")
	if i0 < 0 || i1 < 0 || i1 > i0 {
		t.Errorf("forwards not swapped:\n%s", out)
	}
}

// Every lab fragment (all features on): a save without changes is byte-identical.
func TestUISaveLabUnchanged(t *testing.T) {
	src, sf := labYAML(t)
	if out := uiSave(t, src, sf, func(map[string]any) {}); out != src {
		gone, added := changed(src, out)
		t.Fatalf("lab save without changes altered the file:\n-%q\n+%q", gone, added)
	}
}

// Every scalar the page can edit in the lab config (all features on), changed one at a time, is
// edited in place: no fallback to the canonical form, and only a line or two change (more only where
// defaults derive values from the changed one and the file now spells them out).
func TestUISaveEveryLeaf(t *testing.T) {
	src, sf := labYAML(t)
	page := mustJSONWith(t, src, sf)
	var paths [][]any
	var walk func(v any, path []any)
	walk = func(v any, path []any) {
		switch x := v.(type) {
		case map[string]any:
			for k, c := range x {
				if k != "name" { // renaming a named item is a delete + add
					walk(c, append(append([]any{}, path...), k))
				}
			}
		case []any:
			for i, c := range x {
				walk(c, append(append([]any{}, path...), i))
			}
		default:
			paths = append(paths, path)
		}
	}
	walk(page, nil)
	wide := 0
	if len(paths) < 200 {
		t.Fatalf("only %d leaves in the lab config", len(paths))
	}
	for _, path := range paths {
		out, err := uiSaveErr(t, src, sf, func(m map[string]any) {
			parent := sec(m, path[:len(path)-1]...)
			set := func(v any) any {
				switch x := v.(type) {
				case string:
					return x + "x"
				case float64:
					return x + 1
				case bool:
					return !x
				}
				return v
			}
			switch k := path[len(path)-1].(type) {
			case string:
				parent.(map[string]any)[k] = set(parent.(map[string]any)[k])
			case int:
				parent.([]any)[k] = set(parent.([]any)[k])
			}
		})
		if err != nil {
			t.Errorf("%v: %v", path, err)
			continue
		}
		gone, added := lineDiff(src, out)
		if len(gone)+len(added) == 0 || len(gone) > 1 || len(added) > 1 {
			if len(gone) > 4 || len(added) > 4 || len(gone)+len(added) == 0 {
				t.Errorf("%v: -%q +%q", path, gone, added)
			}
			wide++
		}
	}
	if wide > 3 {
		t.Errorf("%d of %d edits changed more than one line", wide, len(paths))
	}
	t.Logf("%d leaves edited in place, %d with derived values spelled out", len(paths), wide)
}

func labYAML(t *testing.T) (src, secrets string) {
	t.Helper()
	root, _ := filepath.Abs("..")
	frags, _ := filepath.Glob("../examples/lab.d/*.yaml")
	var b strings.Builder
	for _, f := range frags {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		b.WriteString(strings.ReplaceAll(string(data), "@REPO@", root))
	}
	sf := filepath.Join(t.TempDir(), "secrets.yaml")
	var secs []byte
	for _, f := range append([]string{"testdata/secrets.yaml"}, globs("testdata/secrets.d/*.yaml")...) {
		b, _ := os.ReadFile(f)
		secs = append(secs, b...)
	}
	os.WriteFile(sf, secs, 0600)
	return b.String(), sf
}

func globs(p string) []string { m, _ := filepath.Glob(p); return m }

// Things the text editor does not handle fall back to the canonical encoding (keepLayout errors;
// uiConfigYAML then writes the canonical form) instead of writing something wrong.
func TestMergeYAMLRefuses(t *testing.T) {
	c := testConfig(t)
	bn, _ := canonNode(c)
	for _, src := range []string{"base: &a {x: 1}\nother: *a\n", "- a\n- b\n", "a: 1\n---\nb: 2\n"} {
		if _, err := mergeYAML([]byte(src), bn, bn); err == nil {
			t.Errorf("accepted %q", src)
		}
	}
}
