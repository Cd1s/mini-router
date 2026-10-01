package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const extraSecret = "ExtraSecretPassw0rd"

// extraFragment: a Shadowsocks server inbound with a direct outbound of its own.
const extraFragment = `{
  "inbounds": [{"type": "shadowsocks", "tag": "ss-in", "listen": "192.168.50.1", "listen_port": 8388, "method": "aes-256-gcm", "password": "` + extraSecret + `"}],
  "outbounds": [{"type": "direct", "tag": "ss-out"}],
  "route": {"final": "block", "default_domain_resolver": "nope", "rules": [{"inbound": ["ss-in"], "action": "route", "outbound": "ss-out"}]},
  "dns": {"servers": [{"type": "udp", "tag": "dns-x", "server": "9.9.9.9"}], "rules": [{"inbound": ["ss-in"], "action": "route", "server": "dns-x"}]}
}`

func extraConfig(t *testing.T, body string) *Config {
	t.Helper()
	c := proxyTestConfig(t)
	f := filepath.Join(t.TempDir(), "proxy-extra.json")
	if err := os.WriteFile(f, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	c.Proxy.ExtraConfig = f
	return c
}

func TestProxyExtraMerge(t *testing.T) {
	c := extraConfig(t, extraFragment)
	if errs := c.Validate(); len(errs) > 0 {
		t.Fatal(errs)
	}
	js := renderMap(t, c)[proxyGenJSON]
	if !strings.Contains(js, `"listen_port": 8388`) {
		t.Error("numbers of the fragment changed")
	}
	var sb struct {
		Inbounds  []map[string]any `json:"inbounds"`
		Outbounds []map[string]any `json:"outbounds"`
		Route     struct {
			Rules    []map[string]any `json:"rules"`
			Final    string           `json:"final"`
			Resolver string           `json:"default_domain_resolver"`
		} `json:"route"`
		DNS struct {
			Servers []map[string]any `json:"servers"`
			Rules   []map[string]any `json:"rules"`
		} `json:"dns"`
	}
	if err := json.Unmarshal([]byte(js), &sb); err != nil {
		t.Fatal(err)
	}
	// appended
	if n := len(sb.Inbounds); sb.Inbounds[n-1]["tag"] != "ss-in" || sb.Inbounds[0]["tag"] != "dns-in" {
		t.Errorf("inbounds: %v", sb.Inbounds)
	}
	if n := len(sb.Outbounds); sb.Outbounds[n-1]["tag"] != "ss-out" || sb.Outbounds[0]["tag"] != "direct" {
		t.Errorf("outbounds: %v", sb.Outbounds)
	}
	if n := len(sb.DNS.Servers); sb.DNS.Servers[n-1]["tag"] != "dns-x" || sb.DNS.Servers[0]["tag"] != "local" {
		t.Errorf("dns.servers: %v", sb.DNS.Servers)
	}
	// prepended: before mr's hijack-dns and every transparent-proxy rule
	if sb.Route.Rules[0]["outbound"] != "ss-out" || sb.Route.Rules[1]["action"] != "hijack-dns" {
		t.Errorf("route.rules: %v", sb.Route.Rules[:2])
	}
	if sb.DNS.Rules[0]["server"] != "dns-x" || sb.DNS.Rules[1]["server"] != "fakeip" {
		t.Errorf("dns.rules: %v", sb.DNS.Rules[:2])
	}
	// mr set final and default_domain_resolver: the fragment's are ignored
	if sb.Route.Final != "direct" || sb.Route.Resolver != "local" {
		t.Errorf("final %q resolver %q", sb.Route.Final, sb.Route.Resolver)
	}
	// without a fragment the output is unchanged
	c.Proxy.ExtraConfig = ""
	if strings.Contains(renderMap(t, c)[proxyGenJSON], "ss-in") {
		t.Error("fragment merged although proxy.extra_config is not set")
	}
}

func TestProxyExtraFinalAndResolverUsedWhenUnset(t *testing.T) {
	cfg := proxyObj{"route": proxyObj{"rules": []any{}}, "dns": proxyObj{}}
	proxyMergeExtra(cfg, map[string]any{"route": map[string]any{"final": "x", "default_domain_resolver": "y"}})
	r := cfg["route"].(proxyObj)
	if r["final"] != "x" || r["default_domain_resolver"] != "y" {
		t.Errorf("route: %v", r)
	}
}

func TestProxyExtraValidation(t *testing.T) {
	for _, tc := range []struct{ name, body, want string }{
		{"tag of an mr outbound", `{"outbounds":[{"type":"direct","tag":"sg1"}]}`, `outbounds[0].tag: "sg1" is already used`},
		{"tag of an mr inbound", `{"inbounds":[{"type":"direct","tag":"tproxy4"}]}`, `inbounds[0].tag: "tproxy4"`},
		{"tag of an mr dns server", `{"dns":{"servers":[{"type":"udp","tag":"local","server":"1.1.1.1"}]}}`, `dns.servers[0].tag: "local"`},
		{"tag twice", `{"outbounds":[{"type":"direct","tag":"a"},{"type":"direct","tag":"a"}]}`, `outbounds[1].tag: "a"`},
		{"endpoint vs outbound", `{"outbounds":[{"type":"direct","tag":"a"}],"endpoints":[{"type":"wireguard","tag":"a"}]}`, `endpoints[0].tag: "a"`},
		{"no tag", `{"inbounds":[{"type":"direct"}]}`, `inbounds[0].tag: required`},
		{"key owned by mr", `{"experimental":{"clash_api":{}}}`, `experimental: not allowed`},
		{"route key not allowed", `{"route":{"rule_set":[]}}`, `route.rule_set: not allowed`},
		{"not a list", `{"inbounds":{}}`, `inbounds: must be a list`},
		{"element not an object", `{"route":{"rules":["x"]}}`, `route.rules[0]: must be an object`},
		{"syntax error", `{"inbounds": x}`, `syntax error at byte`},
		{"cut off", `{"inbounds": [`, `not a JSON object`},
		{"not an object", `[1]`, `not a JSON object`},
		{"trailing data", `{} {}`, `trailing data`},
	} {
		c := extraConfig(t, tc.body)
		errs := strings.Join(c.Validate(), "\n")
		if !strings.Contains(errs, "proxy.extra_config") || !strings.Contains(errs, tc.want) {
			t.Errorf("%s: want %q in:\n%s", tc.name, tc.want, errs)
		}
		if _, err := Render(c); err == nil { // render refuses too: apply never gets that far
			t.Errorf("%s: render accepted the fragment", tc.name)
		}
	}
	// missing file, relative path
	c := proxyTestConfig(t)
	c.Proxy.ExtraConfig = filepath.Join(t.TempDir(), "missing.json")
	if errs := strings.Join(c.Validate(), "\n"); !strings.Contains(errs, "proxy.extra_config: cannot read the file") {
		t.Errorf("missing file: %s", errs)
	}
	c.Proxy.ExtraConfig = "relative.json"
	if errs := strings.Join(c.Validate(), "\n"); !strings.Contains(errs, "absolute path required") {
		t.Errorf("relative path: %s", errs)
	}
	// proxy off: the file is not read
	c.Proxy.ExtraConfig = filepath.Join(t.TempDir(), "missing.json")
	c.Proxy.Enabled = false
	if errs := c.Validate(); len(errs) > 0 {
		t.Errorf("disabled proxy validated the fragment: %v", errs)
	}
}

// the fragment's content (credentials) never reaches an error, the plan diff or the status
func TestProxyExtraNeverLeaks(t *testing.T) {
	// errors
	for _, body := range []string{
		`{"inbounds": [{"password": "` + extraSecret + `"`,
		`{"experimental":{"password":"` + extraSecret + `"}}`,
		`{"inbounds":[{"tag":"tproxy4","password":"` + extraSecret + `"}]}`,
		`{"inbounds":[{"password":"` + extraSecret + `"}]}`,
		`{"route":{"rules":["` + extraSecret + `"]}}`,
	} {
		c := extraConfig(t, body)
		errs := strings.Join(c.Validate(), "\n")
		if _, err := Render(c); err != nil {
			errs += err.Error()
		}
		if errs == "" || strings.Contains(errs, extraSecret) {
			t.Errorf("errors empty or leak for %s: %s", body, errs)
		}
	}
	c := extraConfig(t, extraFragment)
	js := renderMap(t, c)[proxyGenJSON]
	if !strings.Contains(js, extraSecret) {
		t.Fatal("test setup: the password is in sing-box.json (0600)")
	}
	// plan -v diff
	if d := fileDiff(proxyGenJSON, "", js, c.planMasks()); !strings.Contains(d, "******") || strings.Contains(d, extraSecret) {
		t.Errorf("diff leaks or does not mask:\n%s", d)
	}
	// status / API
	b, _ := json.Marshal(proxyStatus(c))
	if strings.Contains(string(b), extraSecret) || !strings.Contains(string(b), `"extra_config":{"set":true,"sha256":"`) {
		t.Errorf("status: %s", b)
	}
	if h := proxyExtraHash(c.Proxy.ExtraConfig); len(h) != 12 {
		t.Errorf("hash %q", h)
	}
}

// `sing-box check` of the merged config gates the render; its output never carries the fragment's secrets
func TestProxyExtraSingBoxCheck(t *testing.T) {
	c := extraConfig(t, extraFragment)
	old := singBoxBin
	defer func() { singBoxBin = old }()
	dir := t.TempDir()
	script := func(body string) string {
		p := filepath.Join(dir, "sing-box")
		os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0755)
		return p
	}
	singBoxBin = script(`[ "$1" = check ] && exit 0; exit 2`)
	if _, err := Render(c); err != nil {
		t.Fatalf("passing check: %v", err)
	}
	singBoxBin = script(`echo "FATAL decode config: bad ` + extraSecret + `"; exit 1`)
	c = extraConfig(t, strings.Replace(extraFragment, "ss-out", "ss-out2", 2)) // another hash: no cached pass
	_, err := Render(c)
	if err == nil || !strings.Contains(err.Error(), "sing-box check failed") {
		t.Fatalf("failing check not reported: %v", err)
	}
	if strings.Contains(err.Error(), extraSecret) {
		t.Errorf("check output leaks: %v", err)
	}
	// not installed (a PC): no check
	singBoxBin = filepath.Join(dir, "nowhere")
	if _, err := Render(c); err != nil {
		t.Errorf("without sing-box: %v", err)
	}
	// no fragment: never runs it
	singBoxBin = script(`exit 1`)
	c.Proxy.ExtraConfig = ""
	if _, err := Render(c); err != nil {
		t.Errorf("no fragment: %v", err)
	}
}
