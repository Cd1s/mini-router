package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProxyCheckAPIContract(t *testing.T) {
	if st := apiProxyCheck(apiReq{method: "GET"}).status; st != 405 {
		t.Fatalf("GET proxy.check: %d", st)
	}
	if got := tokenActions["proxy.check"]; got != "operate" {
		t.Fatalf("proxy.check token scope = %q, want operate", got)
	}
	d := t.TempDir()
	oldC, oldS := proxyConfigPath, proxySecretsPath
	t.Cleanup(func() { proxyConfigPath, proxySecretsPath = oldC, oldS })
	proxyConfigPath, proxySecretsPath = filepath.Join(d, "router.yaml"), filepath.Join(d, "secrets.yaml")
	if err := os.WriteFile(proxyConfigPath, []byte("proxy:\n  enabled: true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	resp := apiProxyCheck(apiReq{method: "POST", body: []byte(`{}`)})
	body, _ := resp.body.(map[string]any)
	if resp.status != 409 || body["errors"] == nil {
		t.Fatalf("failed proxy.check response: status=%d body=%v", resp.status, resp.body)
	}
}
