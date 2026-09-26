package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestReleaseNewer(t *testing.T) {
	for _, x := range []struct {
		cur, tag, pub string
		want          bool
	}{
		{"v0.2.0", "v0.3.0", "", true}, {"v0.2.0", "v0.2.0", "", false}, {"v0.10.0", "v0.9.9", "", false}, {"v1.0.0", "v1.0.1", "", true},
		{"m3-20260925-92b2ecc", "v0.2.0", "2026-09-25T12:41:58Z", false}, {"m3-20260925-92b2ecc", "v0.3.0", "2026-09-27T08:00:00Z", true},
		{"dev", "v9.9.9", "2030-01-01T00:00:00Z", false}, {"v0.2.0", "v0.3.0-rc1", "", false},
	} {
		if got := releaseNewer(x.cur, x.tag, x.pub); got != x.want {
			t.Errorf("releaseNewer(%q, %q, %q) = %v", x.cur, x.tag, x.pub, got)
		}
	}
}

func TestUpdateCheck(t *testing.T) {
	eventEnv(t)
	tag := "v0.3.0"
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"tag_name":"` + tag + `","published_at":"2026-09-27T08:00:00Z","body":"x"}`))
	}))
	defer srv.Close()
	oURL, oVer := updateURL, version
	t.Cleanup(func() { updateURL, version = oURL, oVer })
	updateURL, version = srv.URL, "v0.2.0"
	c := testConfig(t)
	for i := 0; i < 2; i++ { // the same release is reported once
		if err := updateCheck(c, srv.Client()); err != nil {
			t.Fatal(err)
		}
	}
	if ev := eventsRead(0, 0); len(ev) != 1 || ev[0].Type != "update" || !strings.Contains(ev[0].Msg, "v0.3.0") {
		t.Fatalf("events: %+v", ev)
	}
	tag = "v0.3.0\nx"
	if err := updateCheck(c, srv.Client()); err == nil {
		t.Error("a bad tag was accepted")
	}
	c.Notify.UpdateCheck = true
	if l := renderCronLines(c); !strings.HasSuffix(l[len(l)-1], " * * * "+mrBin+" notify update-check") || !cronWanted(c) {
		t.Errorf("cron: %q", l)
	}
}

func TestArchive(t *testing.T) {
	eventEnv(t)
	var got struct{ method, auth, body string }
	code := 200
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got.method, got.auth, got.body = r.Method, r.Header.Get("Authorization"), string(b)
		w.WriteHeader(code)
	}))
	defer srv.Close()
	d := t.TempDir()
	oc := sysConfigPath
	t.Cleanup(func() { sysConfigPath = oc })
	sysConfigPath = filepath.Join(d, "router.yaml")
	os.WriteFile(sysConfigPath, []byte("system:\n  hostname: r1\n"), 0600)
	c := testConfig(t)
	c.secrets["arch_url"] = srv.URL + "/cfg?k=s3cr3t-arch"
	c.secrets["arch_tok"] = "tok-s3cr3t"
	c.Notify.Archive = &NotifyArchive{URL: "arch_url", Token: "arch_tok", Method: "put"}
	mustValid(t, c)
	if err := archiveSend(c, srv.Client()); err != nil || got.method != "PUT" || got.auth != "Bearer tok-s3cr3t" || got.body != "system:\n  hostname: r1\n" {
		t.Fatalf("%v %+v", err, got)
	}
	code = 500
	if err := archiveSend(c, srv.Client()); err == nil || strings.Contains(err.Error(), "s3cr3t") {
		t.Errorf("failure: %v", err)
	}
	c.secrets["arch_url"] = "http://192.0.2.1/cfg"
	c.Notify.Archive.Method = "get"
	if errs := strings.Join(c.Validate(), "\n"); !strings.Contains(errs, "archive.url_secret") || !strings.Contains(errs, "archive.method") {
		t.Errorf("validation: %s", errs)
	}
}

func TestDoctorUpgradeHealGuard(t *testing.T) {
	eventEnv(t)
	c := testConfig(t)
	e := fakeDocEnv()
	plan := "plan:\n  write   /etc/dnsmasq.conf\n  write   /etc/hostapd.conf\n  reload  firewall\n"
	read := e.read
	e.read = func(p string) string {
		if p == upgradePlanFile {
			return plan
		}
		return read(p)
	}
	if f := docUpgrade(c, e); len(f) != 1 || f[0].Sev != "warn" || !strings.Contains(f[0].Detail, "2 generated file(s) and the firewall") {
		t.Errorf("upgrade: %+v", f)
	}
	plan = "nothing to do\n"
	if f := docUpgrade(c, e); len(f) != 1 || f[0].Sev != "ok" {
		t.Errorf("upgrade, same files: %+v", f)
	}
	// #99: a stale saved plan (boot before the WANs existed) is re-checked; a real change still warns
	plan = "plan:\n  reload  firewall\n"
	os.MkdirAll(filepath.Dir(upgradePlanFile), 0755)
	os.WriteFile(upgradePlanFile, []byte(plan), 0600)
	e.plan = func(*Config) (*Plan, error) { return &Plan{Firewall: true}, nil }
	if f := docUpgrade(c, e); len(f) != 1 || f[0].Sev != "warn" || !fileExists(upgradePlanFile) {
		t.Errorf("upgrade, pending: %+v", f)
	}
	e.plan = func(*Config) (*Plan, error) { return &Plan{}, nil }
	if f := docUpgrade(c, e); len(f) != 1 || f[0].Sev != "ok" || fileExists(upgradePlanFile) {
		t.Errorf("upgrade, stale: %+v", f)
	}
	e.plan = nil
	e.nftChain = func(string) string {
		return "tcp dport 853 counter packets 3 bytes 180 reject\nudp dport 853 counter packets 2 bytes 90 reject\n"
	}
	if f := docDNSGuard(c, e); len(f) != 1 || !strings.Contains(f[0].Detail, "refused 5 ") {
		t.Errorf("dns guard: %+v", f)
	}
	e.v6default = func() bool { return false }
	c.WAN[0].IPv6 = true
	if f := docIPv6(c, e); f[0].ID != "ipv6.route" || f[0].Sev != "warn" {
		t.Errorf("ipv6: %+v", f)
	}
	// heal: a service that is not running is restarted once per healEvery
	var restarted []string
	e.running = func(names []string) map[string]bool {
		m := map[string]bool{}
		for _, n := range names {
			m[n] = n != "ntpd" && n != "mr-network"
		}
		return m
	}
	e.restart = func(s string) error { restarted = append(restarted, s); return errors.New("x") }
	doctorHeal(c, e)
	doctorHeal(c, e)
	if strings.Join(restarted, ",") != "ntpd" {
		t.Errorf("heal restarted %v", restarted)
	}
	if ev := eventsRead(0, 0); len(ev) != 1 || ev[0].Key != "heal.ntpd" || ev[0].Sev != "warn" {
		t.Errorf("heal events: %+v", ev)
	}
	// the web UI's heal during the background one: still one restart
	os.Remove(healFile)
	var mu sync.Mutex
	restarted = nil
	e.restart = func(s string) error {
		time.Sleep(50 * time.Millisecond)
		mu.Lock()
		restarted = append(restarted, s)
		mu.Unlock()
		return nil
	}
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); doctorHeal(c, e) }()
	}
	wg.Wait()
	if len(restarted) != 1 {
		t.Errorf("concurrent heal restarted %v", restarted)
	}
}

func TestDoctorTokenCache(t *testing.T) {
	eventEnv(t)
	b, _ := json.Marshal(docResult{Time: time.Now().Unix(), Risk: 7})
	os.MkdirAll(filepath.Dir(doctorFile), 0755)
	os.WriteFile(doctorFile, b, 0600)
	if r := apiSysDoctor(apiReq{method: "GET", via: "api:agent"}); r.body.(docResult).Risk != 7 {
		t.Errorf("token request not served from the cache: %+v", r.body)
	}
}

func TestEventBootNoConfig(t *testing.T) {
	eventEnv(t)
	if err := eventBoot(nil); err != nil {
		t.Fatal(err)
	}
	if ev := eventsRead(0, 0); len(ev) != 2 || ev[1].Key != "config" {
		t.Errorf("events: %+v", ev)
	}
}

func TestNotifyViaProxy(t *testing.T) {
	c := proxyTestConfig(t)
	c.secrets["tg"] = tgTestToken
	c.Notify = Notify{Channels: []NotifyChannel{{Name: "tg", Type: "telegram", Token: "tg", ChatID: "12345", ViaProxy: true}}}
	c.defaults()
	mustValid(t, c)
	js, err := proxySingBox(c, nil)
	if err != nil || !strings.Contains(js, `"tag": "notify-in"`) || !strings.Contains(js, `"listen_port": 7894`) || !strings.Contains(js, `"outbound": "auto"`) {
		t.Fatalf("%v\n%s", err, js)
	}
	o := proxyNotifyUp
	t.Cleanup(func() { proxyNotifyUp = o })
	for _, up := range []bool{false, true} {
		proxyNotifyUp = func() bool { return up }
		tr := notifyHTTP(c, c.Notify.Channels[0]).Transport.(*http.Transport)
		if (tr.Proxy != nil) != up {
			t.Errorf("proxy up %v: transport proxy set %v", up, tr.Proxy != nil)
		}
	}
	c.Notify.Channels[0].ViaProxy = false
	if js, _ := proxySingBox(c, nil); strings.Contains(js, "notify-in") {
		t.Error("notify inbound without a via_proxy channel")
	}
}
