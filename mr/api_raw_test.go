package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// The router.yaml editor (#19): the text is taken as typed (comments, layout), decoded strictly, and an
// API token cannot use it to change what it may not change.
func TestRawYAMLSubmit(t *testing.T) {
	y, err := os.ReadFile("../examples/router.yaml")
	if err != nil {
		t.Fatal(err)
	}
	text := "# my notes stay\n" + strings.Replace(string(y), "cache_size: 8000", "cache_size: 9000   # bigger", 1)
	body, _ := json.Marshal(map[string]any{"yaml": text, "base_rev": "x"})
	c, got, _, _, err := candidate(apiReq{body: body})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != text || c.DNS.CacheSize != 9000 {
		t.Errorf("raw text not kept as typed (cache %d)", c.DNS.CacheSize)
	}
	for bad, want := range map[string]string{
		"lan: [\n":                   "router.yaml:",
		"nosuchkey: 1\n":             "field nosuchkey not found",
		strings.Repeat("#", 1<<20+1): "larger than 1 MiB",
	} {
		b, _ := json.Marshal(map[string]any{"yaml": bad})
		if _, _, _, _, err := candidate(apiReq{body: b}); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%.20q: %v, want %q", bad, err, want)
		}
	}
	// a token: the raw text goes through the same lock as a whole config
	live, _, _ := tokenEnv(t)
	evil := strings.Replace(string(y), "system:", "guard: {offload: \"off\"}\nsystem:", 1)
	b, _ := json.Marshal(map[string]any{"yaml": evil, "base_rev": "x"})
	if e := tokenGuard(apiReq{action: "plan", body: b}, live); e == nil || !strings.Contains(e.body.(map[string]any)["error"].(string), "guard") {
		t.Errorf("a token changed the guard through raw text: %+v", e)
	}
	b, _ = json.Marshal(map[string]any{"yaml": string(y)})
	if e := tokenGuard(apiReq{action: "apply", body: b}, live); e == nil || e.status != 400 {
		t.Errorf("raw text without base_rev accepted from a token: %+v", e)
	}
}
