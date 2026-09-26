package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Every list format; comments, element-hiding rules, exceptions and IPs are not names.
func TestAdblockParse(t *testing.T) {
	list := `# comment
! adblock comment
[Adblock Plus 2.0]
Ads.Example.
*.wild.example
.dot.example
||abp.example^
||imp.example^$important
||third.example^$third-party
@@||exception.example^
0.0.0.0 hosts.example other.example # two names
127.0.0.1 localhost
::1 ip6-localhost
local=/dm1.example/
address=/dm2.example/0.0.0.0
address=/dm3.example/#
server=/dm4.example/
server=/fwd.example/1.1.1.1
server=/exc.example/#
example.com##.banner
1.2.3.4
com
bad_label-.example
`
	set := map[string]bool{}
	good, total, err := adblockParse(strings.NewReader(list), set)
	var got []string
	for d := range set {
		got = append(got, d)
	}
	sort.Strings(got)
	want := []string{"abp.example", "ads.example", "dm1.example", "dm2.example", "dm3.example", "dm4.example", "dot.example",
		"hosts.example", "imp.example", "other.example", "wild.example"}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("names %v, want %v (%v)", got, want, err)
	}
	if good != 10 || total != 20 {
		t.Errorf("good %d of %d", good, total)
	}
}

func TestAdblockBuild(t *testing.T) {
	set := map[string]bool{"example.com": true, "ads.example.com": true, "x.y.example.com": true, "tracker.net": true,
		"sub.tracker.net": true, "cdn.site.org": true, "img.cdn.site.org": true, "site.org": false}
	block, fwd := adblockBuild(set, []string{"good.example.com", "site.org", "nothing.example"})
	// site.org is allowed: cdn.site.org and below are dropped; example.com covers its subdomains;
	// good.example.com sits under a blocked name: forwarded as usual
	if want := []string{"example.com", "tracker.net"}; !reflect.DeepEqual(block, want) {
		t.Errorf("block %v, want %v", block, want)
	}
	if want := []string{"good.example.com"}; !reflect.DeepEqual(fwd, want) {
		t.Errorf("fwd %v, want %v", fwd, want)
	}
}

func TestAdblockValidateRender(t *testing.T) {
	c := testConfig(t)
	c.DNS.Adblock = Adblock{Enabled: true}
	errs := strings.Join(c.Validate(), "\n")
	if !strings.Contains(errs, "dns.adblock.lists: at least one list while enabled") {
		t.Errorf("no lists accepted:\n%s", errs)
	}
	c.DNS.Adblock = Adblock{Enabled: true, MaxDomains: 5, Allow: []string{"ok.example", "bad name", "com"},
		Lists: []string{"http://lists.example/a.txt", "https://user:pw@lists.example/a", "https://lists.example/a b", "https://lists.example/ok.txt"}}
	errs = strings.Join(c.Validate(), "\n")
	for _, want := range []string{"lists[0]: an https:// URL", "lists[1]: an https:// URL", "lists[2]: an https:// URL",
		`allow[1]: a domain name`, `allow[2]: a domain name`, "max_domains: 1000-1000000"} {
		if !strings.Contains(errs, want) {
			t.Errorf("want %q in:\n%s", want, errs)
		}
	}
	if strings.Contains(errs, "lists[3]") || strings.Contains(errs, "allow[0]") {
		t.Errorf("a good entry refused:\n%s", errs)
	}

	d := t.TempDir()
	old := adblockConf
	adblockConf = filepath.Join(d, "adblock.conf")
	t.Cleanup(func() { adblockConf = old })
	c = testConfig(t)
	if strings.Contains(renderDnsmasq(c), "conf-file") || len(adblockCronLine(c)) != 0 {
		t.Error("ad blocking off: no conf-file line, no cron line")
	}
	c.DNS.Adblock = Adblock{Enabled: true, Lists: []string{"https://lists.example/a.txt"}}
	mustValid(t, c)
	line := "conf-file=" + adblockConf + "\n"
	if !strings.Contains(renderDnsmasq(c), line) {
		t.Error("dnsmasq.conf lacks the adblock conf-file")
	}
	if px, err := proxyDnsmasq(c, nil); err != nil || !strings.Contains(px, line) {
		t.Errorf("proxy dnsmasq lacks the adblock conf-file (%v)", err)
	}
	files := func() map[string]string {
		fs, err := Render(c)
		if err != nil {
			t.Fatal(err)
		}
		m := map[string]string{}
		for _, f := range fs {
			m[f.Path] = f.Data
		}
		return m
	}
	// missing: rendered empty (dnsmasq refuses a missing conf-file); present: left to the updater
	if got, ok := files()[adblockConf]; !ok || got != adblockEmpty {
		t.Errorf("missing file not rendered: %q", got)
	}
	os.WriteFile(adblockConf, []byte("local=/x.example/\n"), 0644)
	if _, ok := files()[adblockConf]; ok {
		t.Error("an existing list is part of the render (plans, snapshots)")
	}
	if serviceFor(adblockConf) != "dnsmasq" {
		t.Error("restart mapping")
	}
	if l := adblockCronLine(c); len(l) != 2 || !strings.HasSuffix(l[1], " * * * * "+mrBin+" dns adblock update --cron") {
		t.Errorf("cron line %v", l)
	}
	if cr := strings.Join(renderCronLines(c), "\n"); !strings.Contains(cr, "dns adblock update --cron") || !cronWanted(c) {
		t.Errorf("crontab: %s", cr)
	}
}

type adblockEnv struct {
	c       *Config
	hits    *atomic.Int64
	reloads *int
	lists   map[string]string
	fail    *error
}

func newAdblockEnv(t *testing.T) *adblockEnv {
	t.Helper()
	e := &adblockEnv{hits: &atomic.Int64{}, reloads: new(int), fail: new(error), lists: map[string]string{
		"/a.txt": "# list a\nads.example\nsub.ads.example\ntracker.example\n",
		"/b.txt": "0.0.0.0 hosts.example\n0.0.0.0 cdn.site.example site.example\n",
	}}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.hits.Add(1)
		body, ok := e.lists[r.URL.Path]
		if !ok {
			http.Error(w, "nope", 500)
			return
		}
		w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	d := t.TempDir()
	o1, o2, o3, o4, o5, o6 := adblockConf, adblockStatus, adblockLock, adblockHTTP, adblockReload, adblockNow
	t.Cleanup(func() {
		adblockConf, adblockStatus, adblockLock, adblockHTTP, adblockReload, adblockNow = o1, o2, o3, o4, o5, o6
	})
	adblockConf, adblockStatus, adblockLock = filepath.Join(d, "state", "adblock.conf"), filepath.Join(d, "run", "adblock.json"), filepath.Join(d, "run", "adblock.lock")
	adblockHTTP = srv.Client
	adblockReload = func() error { *e.reloads++; return *e.fail }
	now := time.Unix(1800000000, 0)
	adblockNow = func() time.Time { return now }
	e.c = testConfig(t)
	e.c.DNS.Adblock = Adblock{Enabled: true, Lists: []string{srv.URL + "/a.txt", srv.URL + "/b.txt"}, Allow: []string{"cdn.site.example"}}
	mustValid(t, e.c)
	return e
}

func TestAdblockUpdate(t *testing.T) {
	e := newAdblockEnv(t)
	res, err := adblockUpdate(e.c, false, true)
	if err != nil || !res.OK || res.Domains != 4 || !res.Changed || *e.reloads != 1 {
		t.Fatalf("first update: %+v %v, %d reloads", res, err, *e.reloads)
	}
	data, _ := os.ReadFile(adblockConf)
	want := "server=/cdn.site.example/#\nlocal=/ads.example/\nlocal=/hosts.example/\nlocal=/site.example/\nlocal=/tracker.example/\n"
	if !strings.HasPrefix(string(data), "# mr dns adblock: domains=4 time=1800000000 config="+adblockConfigHash(e.c)+"\n") || !strings.HasSuffix(string(data), want) {
		t.Errorf("file:\n%s", data)
	}
	st := adblockState(e.c)
	if st["domains"] != 4 || st["current"] != true || st["last"].(adblockResult).Lists[1].Domains != 2 {
		t.Errorf("state %+v", st)
	}
	// same lists: rewritten (header time), no restart
	if res, err := adblockUpdate(e.c, false, true); err != nil || res.Changed || *e.reloads != 1 {
		t.Errorf("unchanged update: %+v %v, %d reloads", res, err, *e.reloads)
	}
	// cron: fresh and same settings: nothing fetched
	h := e.hits.Load()
	if res, err := adblockUpdate(e.c, true, true); res != nil || err != nil || e.hits.Load() != h {
		t.Errorf("cron on a fresh file fetched (%v %v)", res, err)
	}
	// cron: other settings (allow) rebuild at once
	e.c.DNS.Adblock.Allow = append(e.c.DNS.Adblock.Allow, "tracker.example")
	if res, err := adblockUpdate(e.c, true, true); err != nil || res == nil || res.Domains != 3 || *e.reloads != 2 {
		t.Errorf("cron after a settings change: %+v %v", res, err)
	}
	// cron: a day later
	adblockNow = func() time.Time { return time.Unix(1800000000+21*3600, 0) }
	if res, _ := adblockUpdate(e.c, true, true); res == nil {
		t.Error("cron did not update a day-old file")
	}
	good, _ := os.ReadFile(adblockConf)

	// a list that fails or is not a domain list keeps the previous file
	e.lists["/b.txt"] = "<html>\n<body>rate limited</body>\n</html>\n"
	if _, err := adblockUpdate(e.c, false, true); err == nil || !strings.Contains(err.Error(), "not a domain list (0 of 3 lines usable)") {
		t.Errorf("HTML page: %v", err)
	}
	delete(e.lists, "/b.txt")
	if _, err := adblockUpdate(e.c, false, true); err == nil || !strings.Contains(err.Error(), "HTTP 500") {
		t.Errorf("HTTP 500: %v", err)
	}
	if now, _ := os.ReadFile(adblockConf); string(now) != string(good) {
		t.Error("a failed update changed the file")
	}
	if st := adblockState(e.c); st["last"].(adblockResult).OK || st["last"].(adblockResult).Error == "" {
		t.Errorf("failure not in the status: %+v", st["last"])
	}
	// above max_domains
	e.lists["/b.txt"] = "x.example\n"
	e.c.DNS.Adblock.MaxDomains = 1000
	big := ""
	for i := 0; i < 1001; i++ {
		big += "n" + strings.Repeat("x", i%7) + time.Duration(i).String() + ".big.example\n"
	}
	e.lists["/a.txt"] = big
	if _, err := adblockUpdate(e.c, false, true); err == nil || !strings.Contains(err.Error(), "above max_domains 1000") {
		t.Errorf("max_domains: %v", err)
	}
	// dnsmasq does not come back: the previous file is put back and dnsmasq restarted again
	e.lists["/a.txt"] = "new.example\n"
	*e.fail = errors.New("dnsmasq does not answer")
	r0 := *e.reloads
	if _, err := adblockUpdate(e.c, false, true); err == nil || !strings.Contains(err.Error(), "the previous ones are back") {
		t.Errorf("reload failure: %v", err)
	}
	if now, _ := os.ReadFile(adblockConf); string(now) != string(good) || *e.reloads != r0+2 {
		t.Errorf("reload failure: file restored %v, %d reloads", string(now) == string(good), *e.reloads-r0)
	}
	// off: refused
	e.c.DNS.Adblock.Enabled = false
	if _, err := adblockUpdate(e.c, false, true); err == nil {
		t.Error("update while off")
	}
}

// The list hosts, the NTP servers and the local domain are never blocked: the router needs them.
func TestAdblockImplicitAllow(t *testing.T) {
	c := testConfig(t)
	c.System.NTP = []string{"pool.ntp.org", "192.0.2.123"}
	c.DNS.Adblock.Lists = []string{"https://cdn.jsdelivr.net/gh/x/y.txt"}
	got := adblockImplicitAllow(c)
	for _, want := range []string{"cdn.jsdelivr.net", "pool.ntp.org"} {
		if !contains(got, want) {
			t.Errorf("%s missing from %v", want, got)
		}
	}
	block, _ := adblockBuild(map[string]bool{"jsdelivr.net": true, "ntp.org": true}, got)
	if len(block) != 2 {
		t.Errorf("parents of needed names stay blocked, the names are forwarded: %v", block)
	}
	_, fwd := adblockBuild(map[string]bool{"jsdelivr.net": true, "ntp.org": true}, got)
	if !contains(fwd, "cdn.jsdelivr.net") || !contains(fwd, "pool.ntp.org") {
		t.Errorf("fwd %v", fwd)
	}
}
