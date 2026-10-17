package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestSysTSLoginStateGates(t *testing.T) {
	d := t.TempDir()
	oldC, oldS, oldCmd := sysConfigPath, sysSecretsPath, tsCommand
	t.Cleanup(func() { sysConfigPath, sysSecretsPath, tsCommand = oldC, oldS, oldCmd })
	sysConfigPath, sysSecretsPath = filepath.Join(d, "router.yaml"), filepath.Join(d, "secrets.yaml")
	if err := os.WriteFile(sysConfigPath, []byte("services:\n  tailscale:\n    enabled: true\n    port: 41641\n"), 0600); err != nil {
		t.Fatal(err)
	}

	var calls []string
	tsCommand = func(_ context.Context, args ...string) ([]byte, error) {
		calls = append(calls, args[0])
		return []byte(`{"BackendState":"Running"}`), nil
	}
	if r := apiSysTSLogin(apiReq{method: "POST", body: []byte(`{}`)}); r.status != 409 || len(calls) != 1 || calls[0] != "status" {
		t.Fatalf("running state: status=%d calls=%v body=%v", r.status, calls, r.body)
	}

	calls = nil
	statusCalls := 0
	tsCommand = func(_ context.Context, args ...string) ([]byte, error) {
		calls = append(calls, args[0])
		if args[0] == "login" {
			return nil, nil
		}
		statusCalls++
		if statusCalls == 1 {
			return []byte(`{"BackendState":"NeedsLogin"}`), nil
		}
		return []byte(`{"BackendState":"NeedsLogin","AuthURL":"https://login.tailscale.com/a/test"}`), nil
	}
	r := apiSysTSLogin(apiReq{method: "POST", body: []byte(`{}`)})
	body, _ := r.body.(map[string]any)
	if r.status != 0 || body["auth_url"] != "https://login.tailscale.com/a/test" || len(calls) != 3 || calls[1] != "login" {
		t.Fatalf("needs login: status=%d calls=%v body=%v", r.status, calls, r.body)
	}
}
