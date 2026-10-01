package main

// proxy module: proxy.extra_config — a user-supplied raw sing-box fragment merged into the config mr renders for
// mr-proxy (the single sing-box instance). Docs: docs/modules/proxy.md.
//
// The fragment may hold credentials: mr never echoes it (errors give byte offsets and tags, never content), the
// merged result lives only in the 0600 gen/sing-box.json, and `mr plan -v` masks its secret-looking values.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// proxyExtraKeys: what a fragment may contain (everything else — log, experimental, ntp … — stays mr's).
var (
	proxyExtraTop   = map[string]bool{"inbounds": true, "outbounds": true, "endpoints": true, "route": true, "dns": true}
	proxyExtraRoute = map[string]bool{"rules": true, "final": true, "default_domain_resolver": true}
	proxyExtraDNS   = map[string]bool{"servers": true, "rules": true}
)

// singBoxBin: the sing-box that checks the merged result (a variable for tests); absent off the router.
var singBoxBin = "/usr/bin/sing-box"

// proxyExtraRead parses the fragment. Errors never quote its content.
func proxyExtraRead(path string) (map[string]any, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read the file (%v)", errors.Unwrap(err))
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 1<<20+1))
	if err != nil || len(b) > 1<<20 {
		return nil, fmt.Errorf("unreadable or larger than 1 MiB")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber() // ports and other numbers come out as they went in
	var m map[string]any
	if err := dec.Decode(&m); err != nil || m == nil {
		var se *json.SyntaxError
		if errors.As(err, &se) {
			return nil, fmt.Errorf("not a JSON object (syntax error at byte %d)", se.Offset)
		}
		return nil, fmt.Errorf("not a JSON object")
	}
	if dec.More() {
		return nil, fmt.Errorf("not a JSON object (trailing data)")
	}
	return m, nil
}

// proxyExtraList: m[key] as a list of objects.
func proxyExtraList(m map[string]any, key string) ([]any, error) {
	v, ok := m[key]
	if !ok {
		return nil, nil
	}
	l, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("%s: must be a list", key)
	}
	for i, x := range l {
		if _, ok := x.(map[string]any); !ok {
			return nil, fmt.Errorf("%s[%d]: must be an object", key, i)
		}
	}
	return l, nil
}

func proxyExtraObj(m map[string]any, key string, allowed map[string]bool) (map[string]any, error) {
	v, ok := m[key]
	if !ok {
		return nil, nil
	}
	o, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s: must be an object", key)
	}
	for k := range o {
		if !allowed[k] {
			return nil, fmt.Errorf("%s.%s: not allowed (mr owns it)", key, k)
		}
	}
	return o, nil
}

// proxyOwnTags: the tags mr itself generates, by namespace (outbounds and endpoints share one).
func proxyOwnTags(c *Config) (in, out, dns map[string]bool) {
	p := &c.Proxy
	in = map[string]bool{"dns-in": true, "tproxy4": true, "tproxy6": true, "notify-in": true}
	out = map[string]bool{"direct": true}
	dns = map[string]bool{"local": true, "fakeip": true}
	for i := range p.Global {
		in[fmt.Sprintf("tproxy4-g%d", i)], in[fmt.Sprintf("tproxy6-g%d", i)] = true, true
	}
	for _, n := range p.Nodes {
		out[n.Name] = true
	}
	for _, g := range p.Groups {
		out[g.Name] = true
	}
	return
}

// proxyExtraProblems validates a parsed fragment: shape, allowed keys, every tag present and unique, no collision
// with mr's own tags.
func proxyExtraProblems(c *Config, m map[string]any) []string {
	var errs []string
	for k := range m {
		if !proxyExtraTop[k] {
			errs = append(errs, fmt.Sprintf("%s: not allowed (allowed: inbounds, outbounds, endpoints, route.rules / final / default_domain_resolver, dns.servers / rules)", k))
		}
	}
	in, out, dns := proxyOwnTags(c)
	tags := func(key string, own map[string]bool, l []any) {
		for i, x := range l {
			t, _ := x.(map[string]any)["tag"].(string)
			switch {
			case t == "" || len(t) > 64 || !safeText(t):
				errs = append(errs, fmt.Sprintf("%s[%d].tag: required (printable, up to 64 bytes)", key, i))
			case own[t]:
				errs = append(errs, fmt.Sprintf("%s[%d].tag: %q is already used (by mr or earlier in the file)", key, i, t))
			default:
				own[t] = true
			}
		}
	}
	for _, x := range []struct {
		key string
		own map[string]bool
	}{{"inbounds", in}, {"outbounds", out}, {"endpoints", out}} {
		l, err := proxyExtraList(m, x.key)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		tags(x.key, x.own, l)
	}
	if _, err := proxyExtraObj(m, "route", proxyExtraRoute); err != nil {
		errs = append(errs, err.Error())
	} else if r, _ := m["route"].(map[string]any); r != nil {
		if _, err := proxyExtraList(r, "rules"); err != nil {
			errs = append(errs, "route."+err.Error())
		}
	}
	if _, err := proxyExtraObj(m, "dns", proxyExtraDNS); err != nil {
		errs = append(errs, err.Error())
	} else if d, _ := m["dns"].(map[string]any); d != nil {
		for _, key := range []string{"servers", "rules"} {
			l, err := proxyExtraList(d, key)
			if err != nil {
				errs = append(errs, "dns."+err.Error())
			} else if key == "servers" {
				tags("dns.servers", dns, l)
			}
		}
	}
	return errs
}

// proxyMergeExtra merges the (validated) fragment into mr's config: inbounds / outbounds / endpoints / dns.servers
// appended; route.rules and dns.rules PREPENDED, so rules that match an inbound of the fragment win over mr's
// transparent-proxy rules; route.final and route.default_domain_resolver only when mr set none.
func proxyMergeExtra(cfg, m map[string]any) {
	appendTo := func(dst map[string]any, key string, src map[string]any) {
		if l, _ := src[key].([]any); len(l) > 0 {
			old, _ := dst[key].([]any)
			dst[key] = append(old, l...)
		}
	}
	prependTo := func(dst map[string]any, key string, src map[string]any) {
		if l, _ := src[key].([]any); len(l) > 0 {
			old, _ := dst[key].([]any)
			dst[key] = append(append([]any{}, l...), old...)
		}
	}
	for _, k := range []string{"inbounds", "outbounds", "endpoints"} {
		appendTo(cfg, k, m)
	}
	if r, _ := m["route"].(map[string]any); r != nil {
		route := cfg["route"].(proxyObj)
		prependTo(route, "rules", r)
		for _, k := range []string{"final", "default_domain_resolver"} {
			if _, set := route[k]; !set && r[k] != nil {
				route[k] = r[k]
			}
		}
	}
	if d, _ := m["dns"].(map[string]any); d != nil {
		dns := cfg["dns"].(proxyObj)
		appendTo(dns, "servers", d)
		prependTo(dns, "rules", d)
	}
}

// proxyApplyExtra reads, validates and merges proxy.extra_config into cfg (render time).
func proxyApplyExtra(c *Config, cfg map[string]any) error {
	m, err := proxyExtraRead(c.Proxy.ExtraConfig)
	if err != nil {
		return fmt.Errorf("proxy.extra_config: %v", err)
	}
	if errs := proxyExtraProblems(c, m); len(errs) > 0 {
		return fmt.Errorf("proxy.extra_config: %s", strings.Join(errs, "; "))
	}
	proxyMergeExtra(cfg, m)
	return nil
}

// proxyExtraSecrets: the secret-looking string values of the fragment, to mask them in `mr plan -v` diffs of the
// merged sing-box.json (keys named like password, uuid, key, secret, token, psk, auth, obfs, user).
func proxyExtraSecrets(c *Config) map[string]string {
	out := map[string]string{}
	if !c.Proxy.Enabled || c.Proxy.ExtraConfig == "" {
		return out
	}
	m, err := proxyExtraRead(c.Proxy.ExtraConfig)
	if err != nil {
		return out
	}
	var walk func(key string, v any)
	walk = func(key string, v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, e := range x {
				walk(k, e)
			}
		case []any:
			for _, e := range x {
				walk(key, e)
			}
		case string:
			k := strings.ToLower(key)
			for _, w := range []string{"pass", "uuid", "key", "secret", "token", "psk", "auth", "obfs", "user"} {
				if strings.Contains(k, w) && len(x) >= 4 {
					out["extra:"+x] = x
				}
			}
		}
	}
	walk("", m)
	return out
}

// planMasks: secrets.yaml values plus the fragment's secret-looking values (for `mr plan -v` diffs).
func (c *Config) planMasks() map[string]string {
	out := map[string]string{}
	for k, v := range c.secrets {
		out[k] = v
	}
	for k, v := range proxyExtraSecrets(c) {
		out[k] = v
	}
	return out
}

// proxyExtraHash: a short digest of the fragment (status / plan: "changed" without content).
func proxyExtraHash(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:6])
}

// proxyCheckMerged runs `sing-box check` on the merged config when a fragment is in use and sing-box is installed
// (not on a PC / in unit tests). A passing check is remembered by hash in /run, so repeated renders stay cheap.
// The output is cleaned of secret values and cut short.
func proxyCheckMerged(c *Config, js string) error {
	if c.Proxy.ExtraConfig == "" {
		return nil
	}
	if _, err := os.Stat(singBoxBin); err != nil {
		return nil
	}
	sum := sha256.Sum256([]byte(js))
	ok := filepath.Join(RunDir, "proxy-check-"+hex.EncodeToString(sum[:8]))
	if _, err := os.Stat(ok); err == nil {
		return nil
	}
	dir, err := os.MkdirTemp("", "mr-sbcheck")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	cfg := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfg, []byte(js), 0600); err != nil {
		return err
	}
	out, err := exec.Command(singBoxBin, "check", "-c", cfg, "-D", dir).CombinedOutput()
	if err != nil {
		msg := string(out)
		masks := c.planMasks()
		for _, k := range sortedKeys(masks) {
			if v := masks[k]; len(v) >= 4 {
				msg = strings.ReplaceAll(msg, v, "******")
			}
		}
		msg = strings.TrimSpace(strings.ReplaceAll(msg, dir, ""))
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return fmt.Errorf("proxy.extra_config: sing-box check failed on the merged config: %s", msg)
	}
	os.WriteFile(ok, nil, 0600)
	return nil
}
