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
	oldDir, oldLog, oldReload := dnsListDir, ChangeLog, dnsListReload
	dnsListDir, ChangeLog, dnsListReload = d, filepath.Join(d, "changes.log"), func() error { return nil }
	t.Cleanup(func() { dnsListDir, ChangeLog, dnsListReload = oldDir, oldLog, oldReload })

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
	oldDir, oldLog, oldReload := dnsListDir, ChangeLog, dnsListReload
	dnsListDir, ChangeLog, dnsListReload = t.TempDir(), filepath.Join(t.TempDir(), "changes.log"), func() error { return nil }
	t.Cleanup(func() { dnsListDir, ChangeLog, dnsListReload = oldDir, oldLog, oldReload })
	if r := dnsFileRequest(t, "POST", map[string]any{"file": "x.domains", "content": strings.Repeat("a", dnsListMax+1), "save": true}); r.status != 413 {
		t.Errorf("large content status = %d, want 413", r.status)
	}
	if r := dnsFileRequest(t, "POST", map[string]any{"file": "x.domains", "content": "example.com\x00", "save": true}); r.status == 0 {
		t.Error("accepted NUL")
	}
}
