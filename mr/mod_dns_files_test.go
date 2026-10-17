package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func dnsFileRequest(t *testing.T, method string, body any) apiResp {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return apiDNSFiles(apiReq{method: method, body: b})
}

func TestDNSFilesValidationAndDirectory(t *testing.T) {
	d := t.TempDir()
	oldDir, oldLog, oldRun, oldRef := dnsListDir, ChangeLog, dnsListRun, dnsListIsReferenced
	dnsListDir, ChangeLog, dnsListRun, dnsListIsReferenced = d, filepath.Join(d, "changes.log"), func(string, ...string) (string, error) { return "", nil }, func(string) bool { return false }
	t.Cleanup(func() { dnsListDir, ChangeLog, dnsListRun, dnsListIsReferenced = oldDir, oldLog, oldRun, oldRef })

	if r := apiDNSFiles(apiReq{}); r.status != 0 {
		t.Fatalf("empty GET: status %d", r.status)
	}
	for _, name := range []string{"../x.domains", "/etc/passwd", ".x.domains", "x.domains\n", "x.txt"} {
		if r := dnsFileRequest(t, "POST", map[string]any{"file": name, "content": "example.com", "save": true}); r.status == 0 {
			t.Errorf("accepted bad filename %q", name)
		}
	}
	if r := dnsFileRequest(t, "POST", map[string]any{"file": strings.Repeat("x", 65) + ".domains", "content": "example.com", "save": true}); r.status == 0 {
		t.Error("accepted overlong filename")
	}
	if r := dnsFileRequest(t, "GET", map[string]any{"file": "x.domains", "content": "example.com", "save": true}); r.status != 405 {
		t.Errorf("GET save status = %d, want 405", r.status)
	}
	if r := dnsFileRequest(t, "POST", map[string]any{"file": "x.domains", "content": "bad domain!", "save": true}); r.status == 0 {
		t.Error("accepted invalid domain")
	}
	if r := dnsFileRequest(t, "POST", map[string]any{"file": "x.ips", "content": "not-an-ip", "save": true}); r.status == 0 {
		t.Error("accepted invalid IP")
	}
	if r := dnsFileRequest(t, "POST", map[string]any{"file": "x.hosts", "content": "192.0.2.1 host.example", "save": true}); r.status != 0 {
		t.Fatalf("valid hosts: status %d", r.status)
	}
	if r := dnsFileRequest(t, "POST", map[string]any{"file": "x.servers", "content": "server=/example.com/1.1.1.1\nrev-server=192.0.2.0/24,1.1.1.1", "save": true}); r.status != 0 {
		t.Fatalf("valid servers: status %d", r.status)
	}
	if r := apiDNSList(apiReq{method: "POST", body: []byte(`{"name":"fallback.domains","content":"example.com","save":true}`)}); r.status != 0 {
		t.Fatalf("dnslist filename fallback: status %d", r.status)
	}
	if b, err := os.ReadFile(filepath.Join(d, "x.servers")); err != nil || !strings.Contains(string(b), "server=/example.com/1.1.1.1") {
		t.Fatalf("saved servers: %v %q", err, b)
	}
	for _, tc := range []struct{ name, content string }{
		{"x.hosts", "host.example 192.0.2.1"},
		{"x.servers", "conf-file=/tmp/evil"},
		{"x.servers", "server=/example.com/not-an-ip"},
	} {
		if r := dnsFileRequest(t, "POST", map[string]any{"file": tc.name, "content": tc.content, "save": true}); r.status == 0 {
			t.Errorf("accepted invalid %s %q", tc.name, tc.content)
		}
	}
	if err := os.Symlink(filepath.Join(d, "x.domains"), filepath.Join(d, "link.domains")); err != nil {
		t.Fatal(err)
	}
	if r := dnsFileRequest(t, "GET", map[string]any{"file": "link.domains"}); r.status == 0 {
		t.Error("followed symlink")
	}
}

func TestDNSFilesSizeAndSpecialContent(t *testing.T) {
	oldDir, oldLog, oldRun, oldRef := dnsListDir, ChangeLog, dnsListRun, dnsListIsReferenced
	dnsListDir, ChangeLog, dnsListRun, dnsListIsReferenced = t.TempDir(), filepath.Join(t.TempDir(), "changes.log"), func(string, ...string) (string, error) { return "", nil }, func(string) bool { return false }
	t.Cleanup(func() { dnsListDir, ChangeLog, dnsListRun, dnsListIsReferenced = oldDir, oldLog, oldRun, oldRef })
	if r := dnsFileRequest(t, "POST", map[string]any{"file": "x.domains", "content": strings.Repeat("a", dnsListMax+1), "save": true}); r.status != 413 {
		t.Errorf("large content status = %d, want 413", r.status)
	}
	if r := dnsFileRequest(t, "POST", map[string]any{"file": "x.domains", "content": "example.com\x00", "save": true}); r.status == 0 {
		t.Error("accepted NUL")
	}
}

func TestDNSFilesReloadValidationAndRollback(t *testing.T) {
	d := t.TempDir()
	oldDir, oldLog, oldRun, oldRef := dnsListDir, ChangeLog, dnsListRun, dnsListIsReferenced
	dnsListDir, ChangeLog = d, filepath.Join(d, "changes.log")
	dnsListIsReferenced = func(string) bool { return true }
	var calls []string
	dnsListRun = func(name string, args ...string) (string, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return "", nil
	}
	t.Cleanup(func() { dnsListDir, ChangeLog, dnsListRun, dnsListIsReferenced = oldDir, oldLog, oldRun, oldRef })
	path := filepath.Join(d, "extra.hosts")
	if err := os.WriteFile(path, []byte("192.0.2.1 old.example\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if r := dnsFileRequest(t, "POST", map[string]any{"file": "extra.hosts", "content": "192.0.2.2 new.example", "save": true}); r.status != 0 {
		t.Fatalf("valid reload: %d", r.status)
	}
	if got := strings.Join(calls, "|"); !strings.Contains(got, "dnsmasq --test --conf-file=/etc/dnsmasq.conf") || !strings.Contains(got, "rc-service dnsmasq restart") || !strings.Contains(got, "rc-service dnsmasq status") {
		t.Fatalf("reload calls: %s", got)
	}
	calls = nil
	dnsListRun = func(name string, args ...string) (string, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		if name == "dnsmasq" {
			return "bad config", os.ErrInvalid
		}
		return "", nil
	}
	if r := dnsFileRequest(t, "POST", map[string]any{"file": "extra.hosts", "content": "192.0.2.3 rejected.example", "save": true}); r.status == 0 {
		t.Fatal("accepted failed dnsmasq test")
	}
	b, _ := os.ReadFile(path)
	if string(b) != "192.0.2.2 new.example\n" {
		t.Fatalf("test failure should keep last accepted file, got %q", b)
	}
}
