package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// no test ever starts a background `mr ddns sync` (it would run the test binary)
func init() { ddnsKick = func() {} }

const (
	cfTestToken = "test-token-0123456789-abcdefghij"
	cfTestZone  = "0123456789abcdef0123456789abcdef"
)

// fakeCF is a small Cloudflare API v4: zones by name, dns_records list / create / patch / delete.
type fakeCF struct {
	mu      sync.Mutex
	recs    []map[string]any // id, name, type, content, ttl, proxied
	calls   []string         // "GET /zones", "PATCH /zones/<zone>/dns_records/<id>", ...
	bodies  []map[string]any // POST / PATCH bodies
	status  int              // answer every call with this HTTP status (0 = normal)
	code    int              // ... and this Cloudflare error code
	garbage bool             // answer with something that is not JSON
	seq     int
}

func (f *fakeCF) handler(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	path := strings.TrimPrefix(r.URL.Path, "/client/v4")
	f.calls = append(f.calls, r.Method+" "+path)
	answer := func(status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(v)
	}
	fail := func(status, code int, msg string) {
		answer(status, map[string]any{"success": false, "errors": []any{map[string]any{"code": code, "message": msg}}, "result": nil})
	}
	if r.Header.Get("Authorization") != "Bearer "+cfTestToken {
		fail(403, 9109, "Invalid access token")
		return
	}
	if f.garbage {
		w.WriteHeader(502)
		io.WriteString(w, "<html>bad gateway</html>")
		return
	}
	if f.status != 0 {
		fail(f.status, f.code, "simulated failure")
		return
	}
	ok := func(v any) { answer(200, map[string]any{"success": true, "errors": []any{}, "result": v}) }
	switch {
	case r.Method == "GET" && path == "/zones":
		if r.URL.Query().Get("name") == "example.com" {
			ok([]any{map[string]any{"id": cfTestZone, "name": "example.com"}})
		} else {
			ok([]any{})
		}
	case path == "/zones/"+cfTestZone+"/dns_records" && r.Method == "GET":
		q := r.URL.Query()
		out := []any{}
		for _, x := range f.recs {
			if x["name"] == q.Get("name") && x["type"] == q.Get("type") {
				out = append(out, x)
			}
		}
		ok(out)
	case path == "/zones/"+cfTestZone+"/dns_records" && r.Method == "POST":
		var b map[string]any
		json.NewDecoder(r.Body).Decode(&b)
		f.bodies = append(f.bodies, b)
		f.seq++
		x := map[string]any{"id": fmt.Sprintf("%032x", 0xa00+f.seq), "name": b["name"], "type": b["type"], "content": b["content"], "ttl": b["ttl"], "proxied": b["proxied"]}
		f.recs = append(f.recs, x)
		ok(x)
	case strings.HasPrefix(path, "/zones/"+cfTestZone+"/dns_records/") && r.Method == "PATCH":
		var b map[string]any
		json.NewDecoder(r.Body).Decode(&b)
		f.bodies = append(f.bodies, b)
		id := strings.TrimPrefix(path, "/zones/"+cfTestZone+"/dns_records/")
		for _, x := range f.recs {
			if x["id"] == id {
				for k, v := range b {
					x[k] = v
				}
				ok(x)
				return
			}
		}
		fail(404, 81044, "Record does not exist.")
	case strings.HasPrefix(path, "/zones/"+cfTestZone+"/dns_records/") && r.Method == "DELETE": // ACME TXT records (edge)
		id := strings.TrimPrefix(path, "/zones/"+cfTestZone+"/dns_records/")
		for i, x := range f.recs {
			if x["id"] == id {
				f.recs = append(f.recs[:i], f.recs[i+1:]...)
				ok(map[string]any{"id": id})
				return
			}
		}
		fail(404, 81044, "Record does not exist.")
	default:
		fail(404, 7003, "Could not route")
	}
}

func (f *fakeCF) take() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := f.calls
	f.calls = nil
	return c
}

// ddnsEnv: the home config with DDNS on, a fake Cloudflare, runtime files in a temp dir, a fake
// clock and fake IPv6 addresses. The WAN "wan" has 192.0.2.10.
func ddnsEnv(t *testing.T) (*Config, *fakeCF, *time.Time, map[string][]net.IP) {
	t.Helper()
	d := tempState(t)
	f := &fakeCF{}
	srv := httptest.NewServer(http.HandlerFunc(f.handler))
	t.Cleanup(srv.Close)
	now := time.Unix(1_800_000_000, 0)
	addrs := map[string][]net.IP{}
	a, b, cc, e, g, h := ddnsStateFile, ddnsLockFile, ddnsWaitFile, cfAPIBase, ddnsNow, ddnsAddrs6
	ddnsStateFile, ddnsLockFile, ddnsWaitFile = filepath.Join(d, "ddns.json"), filepath.Join(d, "ddns.lock"), filepath.Join(d, "ddns.wait")
	cfAPIBase = srv.URL + "/client/v4"
	ddnsNow = func() time.Time { return now }
	ddnsAddrs6 = func(dev string) []net.IP { return addrs[dev] }
	t.Cleanup(func() { ddnsStateFile, ddnsLockFile, ddnsWaitFile, cfAPIBase, ddnsNow, ddnsAddrs6 = a, b, cc, e, g, h })

	c := testConfig(t)
	c.secrets["cf_test_token"] = cfTestToken
	c.Services.DDNS = DDNS{Enabled: true, Records: []DDNSRecord{
		{Name: "home.example.com", Zone: "example.com", Token: "cf_test_token", IPv6: "router"},
	}}
	c.defaults()
	if errs := c.Validate(); len(errs) > 0 {
		t.Fatal(errs)
	}
	writeLease("wan", wanLease{IP: "192.0.2.10", Dev: "pppoe-wan"})
	return c, f, &now, addrs
}

func TestDDNSValidate(t *testing.T) {
	c := testConfig(t)
	c.secrets["cf_ok"] = cfTestToken
	c.secrets["cf_bad"] = "has spaces in it, not a token"
	iv := 3
	c.Services.DDNS = DDNS{Enabled: true, Interval: &iv, Records: []DDNSRecord{
		{Name: "home.example.com", Zone: "example.com", Token: "cf_ok", IPv4: "wan2", IPv6: "::10", TTL: 120}, // valid
		{Name: "*.example.com", Zone: "example.com", Token: "cf_ok"},                                          // valid (wildcard)
		{Name: "home.example.com", Zone: "example.com", Token: "cf_ok"},                                       // duplicate
		{Name: "home.example.org", Zone: "example.com", Token: "cf_ok"},                                       // outside the zone
		{Name: "a b.example.com", Zone: "example.com", Token: "cf_ok"},
		{Name: "x.example.com", Zone: "example.com", Token: "cf_ok", Provider: "ddns-go"},
		{Name: "y.example.com", Zone: "example.com", Token: "CF_OK"},
		{Name: "z.example.com", Zone: "example.com", Token: "cf_missing"},
		{Name: "w.example.com", Zone: "example.com", Token: "cf_bad"},
		{Name: "v.example.com", Zone: "example.com", Token: "cf_ok", IPv4: "wan9"},
		{Name: "u.example.com", Zone: "example.com", Token: "cf_ok", IPv6: "fe80::10"},
		{Name: "s.example.com", Zone: "example.com", Token: "cf_ok", IPv4: "off", IPv6: "off"},
		{Name: "r.example.com", Zone: "example.com", Token: "cf_ok", TTL: 30},
		{Name: "q.example.com", Zone: "example.com\nx", Token: "cf_ok"},
		{Name: "p.example.com", Zone: "example.com", Token: "cf_ok", IPv6: "::"},
	}}
	c.defaults()
	errs := strings.Join(c.Validate(), "\n")
	for _, s := range []string{
		"services.ddns.interval: 5-60", "records[2].name: duplicate", `records[3].name: "home.example.org" is not inside zone`,
		"records[4].name: a host name", "records[5].provider", "records[6].token_secret: secret name", `records[7].token_secret: secret "cf_missing" missing`,
		"records[8].token_secret: the secret is not an API token", `records[9].ipv4: active | off | a WAN name`, `got "wan9" (no such WAN)`,
		`records[10].ipv6: off | router | ::IID`, "records[11]: ipv4 and ipv6 are both off", "records[12].ttl", "records[13].zone",
		`records[14].ipv6`,
	} {
		if !strings.Contains(errs, s) {
			t.Errorf("want error %q in:\n%s", s, errs)
		}
	}
	for _, s := range []string{"records[0]", "records[1]"} {
		if strings.Contains(errs, s) {
			t.Errorf("valid record rejected (%s):\n%s", s, errs)
		}
	}
	if strings.Contains(errs, cfTestToken) {
		t.Error("a validation message shows the token")
	}
	// enabled without records; the secret names reach the web UI's "已设置" list, never the values
	c.Services.DDNS = DDNS{Enabled: true}
	if !strings.Contains(strings.Join(c.Validate(), "\n"), "services.ddns: enabled without records") {
		t.Error("enabled without records accepted")
	}
	c.Services.DDNS.Records = []DDNSRecord{{Name: "home.example.com", Zone: "example.com", Token: "cf_ok"}}
	if k := strings.Join(secretKeys(c), " "); !strings.Contains(k, "cf_ok") {
		t.Errorf("secretKeys lacks the DDNS token name: %s", k)
	}
}

// The home config (no ddns) marshals and renders exactly as before; on / off / interval 0 switch the
// crontab line and crond.
func TestDDNSCron(t *testing.T) {
	sysTemp(t)
	c := testConfig(t)
	if y, _ := yaml.Marshal(c); strings.Contains(string(y), "ddns:") {
		t.Error("an absent services.ddns appears in the canonical config (plan / history would show a change)")
	}
	c.secrets["cf_test_token"] = cfTestToken
	c.Services.DDNS = DDNS{Enabled: true, Records: []DDNSRecord{{Name: "home.example.com", Zone: "example.com", Token: "cf_test_token"}}}
	c.defaults()
	if errs := c.Validate(); len(errs) > 0 {
		t.Fatal(errs)
	}
	if *c.Services.DDNS.Interval != 10 || c.Services.DDNS.Records[0].Provider != "cloudflare" || c.Services.DDNS.Records[0].IPv4 != "active" || c.Services.DDNS.Records[0].IPv6 != "off" {
		t.Errorf("defaults: %+v", c.Services.DDNS)
	}
	f := renderMap(t, c)
	if f[cronFile] != cronBegin+"\n# ddns (services.ddns)\n*/10 * * * * /usr/sbin/mr ddns sync --cron\n"+cronEnd+"\n" {
		t.Errorf("crontab:\n%s", f[cronFile])
	}
	if !strings.Contains(strings.Join(enabledServices(c), " "), "crond") {
		t.Error("crond not enabled for the DDNS check")
	}
	zero := 0
	c.Services.DDNS.Interval = &zero
	if _, ok := renderMap(t, c)[cronFile]; ok || strings.Contains(strings.Join(enabledServices(c), " "), "crond") {
		t.Error("interval 0: crontab / crond without anything to run")
	}
	iv := 30
	c.Services.DDNS.Interval, c.Services.DDNS.Enabled = &iv, false
	if _, ok := renderMap(t, c)[cronFile]; ok {
		t.Error("disabled DDNS still in the crontab")
	}
}

func TestDDNSLocalAddresses(t *testing.T) {
	c, _, _, addrs := ddnsEnv(t)
	for src, want := range map[string]string{"active": "192.0.2.10", "wan": "192.0.2.10", "wan2": ""} {
		if ip, _ := ddnsIPv4(c, src); ip != want {
			t.Errorf("ipv4 %s = %q, want %q", src, ip, want)
		}
	}
	// active: a WAN behind CGNAT is skipped for the next one with a public address
	writeLease("wan", wanLease{IP: "100.64.3.4"})
	writeLease("wan2", wanLease{IP: "198.51.100.7"})
	if ip, note := ddnsIPv4(c, "active"); ip != "198.51.100.7" || note != "" {
		t.Errorf("active with a CGNAT primary: %q %q", ip, note)
	}
	if ip, note := ddnsIPv4(c, "wan"); ip != "" || !strings.Contains(note, "cgnat address 100.64.3.4") {
		t.Errorf("CGNAT published: %q %q", ip, note)
	}
	writeLease("wan2", wanLease{IP: "192.168.8.2"})
	if ip, note := ddnsIPv4(c, "active"); ip != "" || !strings.Contains(note, "private") {
		t.Errorf("private address published: %q %q", ip, note)
	}

	if ip, note := ddnsIPv6(c, "router"); ip != "" || note == "" {
		t.Errorf("no IPv6 yet: %q %q", ip, note)
	}
	addrs["pppoe-wan"] = []net.IP{net.ParseIP("2001:db8:ffff::5")}
	if ip, _ := ddnsIPv6(c, "router"); ip != "2001:db8:ffff::5" {
		t.Errorf("router without a LAN prefix: %q (want the WAN address)", ip)
	}
	addrs["br-lan"] = []net.IP{net.ParseIP("2001:db8:1:2::1")}
	for src, want := range map[string]string{"router": "2001:db8:1:2::1", "::10": "2001:db8:1:2::10", "::1234:5678:9abc:def0": "2001:db8:1:2:1234:5678:9abc:def0"} {
		if ip, _ := ddnsIPv6(c, src); ip != want {
			t.Errorf("ipv6 %s = %q, want %q", src, ip, want)
		}
	}
	for s, ok := range map[string]bool{"::10": true, "::1:0:0:0": true, "::": false, "2001:db8::1": false, "::ffff:1.2.3.4": false, "10": false, "::1:2:3:4:5": false} {
		if (ddnsIID(s) != nil) != ok {
			t.Errorf("ddnsIID(%q) ok=%v", s, !ok)
		}
	}
	// `ip -j -6 addr` output: deprecated, tentative, temporary, ULA and link-local addresses are not used
	var v any
	json.Unmarshal([]byte(`[{"ifname":"br-lan","addr_info":[
		{"family":"inet6","local":"2001:db8:9::aaaa","prefixlen":64,"scope":"global","temporary":true,"dynamic":true},
		{"family":"inet6","local":"2001:db8:9::1","prefixlen":64,"scope":"global","deprecated":true,"preferred_life_time":0},
		{"family":"inet6","local":"fd00::1","prefixlen":64,"scope":"global"},
		{"family":"inet6","local":"2001:db8:9::2","prefixlen":64,"scope":"global","tentative":true},
		{"family":"inet6","local":"fe80::1","prefixlen":64,"scope":"link"},
		{"family":"inet6","local":"2001:db8:8::1","prefixlen":64,"scope":"global","dynamic":true,"mngtmpaddr":true,"valid_life_time":7200,"preferred_life_time":3600}]}]`), &v)
	if got := parseGlobal6(v); len(got) != 1 || got[0].String() != "2001:db8:8::1" {
		t.Errorf("parseGlobal6: %v", got)
	}
}

func TestDDNSCloudflare(t *testing.T) {
	c, f, now, addrs := ddnsEnv(t)
	addrs["br-lan"] = []net.IP{net.ParseIP("2001:db8:1:2::1")}
	// an A record with an old address, proxied, hand-set TTL; no AAAA yet
	f.recs = []map[string]any{{"id": fmt.Sprintf("%032x", 1), "name": "home.example.com", "type": "A", "content": "203.0.113.99", "ttl": 300, "proxied": true}}
	sync := func(o ddnsRun) []ddnsState {
		t.Helper()
		rows, err := ddnsSync(c, o)
		if err != nil {
			t.Fatal(err)
		}
		return rows
	}

	rows := sync(ddnsRun{})
	calls := strings.Join(f.take(), "\n")
	for _, s := range []string{"GET /zones", "GET /zones/" + cfTestZone + "/dns_records", "PATCH /zones/" + cfTestZone + "/dns_records/" + fmt.Sprintf("%032x", 1), "POST /zones/" + cfTestZone + "/dns_records"} {
		if !strings.Contains(calls, s) {
			t.Errorf("first sync: no %q in\n%s", s, calls)
		}
	}
	if len(rows) != 2 || rows[0].Type != "A" || rows[0].Published != "192.0.2.10" || rows[1].Type != "AAAA" || rows[1].Published != "2001:db8:1:2::1" || rows[0].Changed == 0 {
		t.Fatalf("rows: %+v", rows)
	}
	// only the content changes: proxied and the TTL set by hand stay; a new record is not proxied
	if b := f.bodies[0]; len(b) != 1 || b["content"] != "192.0.2.10" {
		t.Errorf("PATCH body %v (want content only)", b)
	}
	if b := f.bodies[1]; b["proxied"] != false || b["ttl"] != float64(1) || b["type"] != "AAAA" || b["name"] != "home.example.com" {
		t.Errorf("POST body %v", b)
	}
	if f.recs[0]["proxied"] != true || fmt.Sprint(f.recs[0]["ttl"]) != "300" {
		t.Errorf("record changed beyond its content: %v", f.recs[0])
	}

	// unchanged addresses: no request at all (hooks, cron within the day)
	*now = now.Add(10 * time.Minute)
	sync(ddnsRun{})
	sync(ddnsRun{daily: true})
	if c := f.take(); len(c) != 0 {
		t.Errorf("unchanged address caused requests: %v", c)
	}

	// a new WAN address: the zone id is remembered, one lookup + one PATCH
	writeLease("wan", wanLease{IP: "192.0.2.11"})
	rows = sync(ddnsRun{})
	if c := f.take(); len(c) != 2 || !strings.HasPrefix(c[0], "GET /zones/") || !strings.HasPrefix(c[1], "PATCH ") {
		t.Errorf("address change: %v", c)
	}
	if rows[0].Published != "192.0.2.11" || f.recs[0]["content"] != "192.0.2.11" {
		t.Errorf("not updated: %+v %v", rows[0], f.recs[0])
	}

	// a day later the cron run asks the provider once (someone changed the record by hand)
	f.recs[0]["content"] = "203.0.113.1"
	*now = now.Add(25 * time.Hour)
	sync(ddnsRun{daily: true})
	if c := f.take(); len(c) != 3 || !strings.HasPrefix(c[1], "PATCH ") { // A: GET + PATCH, AAAA: GET
		t.Errorf("daily check: %v", c)
	}
	if f.recs[0]["content"] != "192.0.2.11" {
		t.Error("record edited by hand not fixed by the daily check")
	}

	// a CGNAT address is never published and costs nothing
	writeLease("wan", wanLease{IP: "100.64.0.9"})
	rows = sync(ddnsRun{})
	if c := f.take(); len(c) != 0 || rows[0].Local != "" || !strings.Contains(rows[0].Note, "cgnat") {
		t.Errorf("CGNAT: calls %v, row %+v", c, rows[0])
	}
	writeLease("wan", wanLease{IP: "192.0.2.12"})

	// server errors back off: 1, 2, 4 … minutes; nothing is tried before that
	f.status, f.code = 500, 1000
	rows = sync(ddnsRun{})
	if rows[0].Error == "" || rows[0].Retry != now.Unix()+60 || rows[0].Stopped {
		t.Errorf("first failure: %+v", rows[0])
	}
	f.take()
	*now = now.Add(30 * time.Second)
	sync(ddnsRun{})
	if c := f.take(); len(c) != 0 {
		t.Errorf("retried during backoff: %v", c)
	}
	*now = now.Add(31 * time.Second)
	rows = sync(ddnsRun{})
	if c := f.take(); len(c) == 0 || rows[0].Retry != now.Unix()+120 {
		t.Errorf("second attempt: calls %v, retry %d", c, rows[0].Retry-now.Unix())
	}
	if ddnsBackoff(3) != 4 || ddnsBackoff(7) != 60 || ddnsBackoff(50) != 60 {
		t.Error("backoff steps")
	}
	// an answer that is not the API's
	f.status, f.garbage = 0, true
	rows = sync(ddnsRun{retry: true})
	if !strings.Contains(rows[0].Error, "not an API answer") {
		t.Errorf("garbage answer: %+v", rows[0])
	}
	f.garbage = false
	rows = sync(ddnsRun{retry: true})
	if rows[0].Error != "" || rows[0].Published != "192.0.2.12" || rows[0].Retry != 0 {
		t.Errorf("recovery: %+v", rows[0])
	}
	f.take()

	// a refused token stops the record until the config (or the token) changes
	c.secrets["cf_test_token"] = cfTestToken[:len(cfTestToken)-1] + "X"
	writeLease("wan", wanLease{IP: "192.0.2.13"})
	rows = sync(ddnsRun{})
	if !rows[0].Stopped || !strings.Contains(rows[0].Error, "refused the token") {
		t.Errorf("403: %+v", rows[0])
	}
	f.take()
	*now = now.Add(3 * time.Hour)
	sync(ddnsRun{daily: true})
	if c := f.take(); len(c) != 0 {
		t.Errorf("stopped record retried automatically: %v", c)
	}
	sync(ddnsRun{retry: true}) // 立即更新 still tries
	if c := f.take(); len(c) == 0 {
		t.Error("manual update did not try a stopped record")
	}
	c.secrets["cf_test_token"] = cfTestToken // new token = new state: tried at once
	rows = sync(ddnsRun{})
	if rows[0].Stopped || rows[0].Published != "192.0.2.13" {
		t.Errorf("after the token changed: %+v", rows[0])
	}

	// the token never leaves the router: not in the state file, the status, the API answer
	b, _ := os.ReadFile(ddnsStateFile)
	st, _ := json.Marshal(ddnsStatus(c))
	sum, _ := json.Marshal(ddnsSummary(c))
	for what, data := range map[string]string{"state": string(b), "status": string(st), "summary": string(sum)} {
		if strings.Contains(data, cfTestToken) || strings.Contains(data, "test-token") {
			t.Errorf("%s contains the token", what)
		}
	}
	if strings.Contains(string(st), cfTestZone) || strings.Contains(string(st), `"config"`) {
		t.Errorf("status shows internal state: %s", st)
	}
	fi, _ := os.Stat(ddnsStateFile)
	if fi.Mode().Perm() != 0600 {
		t.Errorf("state file mode %v", fi.Mode())
	}

	// a record removed from the config is forgotten (never deleted at the provider)
	c.Services.DDNS.Records[0].IPv6 = "off"
	sync(ddnsRun{})
	if m := ddnsLoad(); len(m) != 1 || m["home.example.com/A"] == nil {
		t.Errorf("state after removing AAAA: %v", m)
	}
	for _, x := range f.take() {
		if strings.HasPrefix(x, "DELETE") {
			t.Error("a record was deleted at the provider")
		}
	}
}

func TestDDNSCloudflareEdges(t *testing.T) {
	c, f, _, _ := ddnsEnv(t)
	c.Services.DDNS.Records[0].IPv6 = "off"
	// ids that are not Cloudflare ids never reach a URL path; other names / types are left alone
	f.recs = []map[string]any{
		{"id": "../../zones", "name": "home.example.com", "type": "A", "content": "203.0.113.1"},
		{"id": fmt.Sprintf("%032x", 7), "name": "other.example.com", "type": "A", "content": "203.0.113.1"},
	}
	rows, _ := ddnsSync(c, ddnsRun{})
	calls := strings.Join(f.take(), "\n")
	if strings.Contains(calls, "..") || strings.Contains(calls, fmt.Sprintf("%032x", 7)) || !strings.Contains(calls, "POST ") {
		t.Errorf("calls:\n%s", calls)
	}
	if rows[0].Published != "192.0.2.10" {
		t.Errorf("row %+v", rows[0])
	}
	// a zone the token does not cover
	c.Services.DDNS.Records = []DDNSRecord{{Name: "home.example.net", Zone: "example.net", Token: "cf_test_token", Provider: "cloudflare", IPv4: "active", IPv6: "off"}}
	rows, _ = ddnsSync(c, ddnsRun{})
	if !strings.Contains(rows[0].Error, "zone example.net not found") || rows[0].Stopped {
		t.Errorf("unknown zone: %+v", rows[0])
	}
	// a configured TTL is kept on the record
	c.Services.DDNS.Records = []DDNSRecord{{Name: "home.example.com", Zone: "example.com", Token: "cf_test_token", Provider: "cloudflare", IPv4: "active", IPv6: "off", TTL: 120}}
	f.take()
	f.bodies = nil
	ddnsSync(c, ddnsRun{})
	if len(f.bodies) != 1 || f.bodies[0]["ttl"] != float64(120) {
		t.Errorf("TTL: %v", f.bodies)
	}
	// `update NAME` only touches that record; unknown names are refused
	if err := ddnsCommand(c, []string{"update", "nope.example.com"}); err == nil {
		t.Error("update of an unknown record accepted")
	}
	if err := ddnsCommand(c, []string{"sync", "--bogus"}); err == nil {
		t.Error("sync --bogus accepted")
	}
}

// WAN events start one background sync (not for "down"), only while DDNS is on; a sync --hook
// finds another waiter and leaves at once.
func TestDDNSHooks(t *testing.T) {
	c, f, _, _ := ddnsEnv(t)
	n := 0
	old := ddnsKick
	ddnsKick = func() { n++ }
	t.Cleanup(func() { ddnsKick = old })
	for _, ev := range []string{"up", "ipv6", "health", "down"} {
		runOnWAN(c, "wan", ev)
	}
	if n != 3 {
		t.Errorf("kicks for up/ipv6/health/down: %d, want 3", n)
	}
	for _, m := range modules {
		if m.Name == "sys" {
			m.Verify(c, nil) // the post-apply hook (other modules' Verify would wait for real services)
		}
	}
	if n != 4 {
		t.Errorf("apply did not start a sync (%d)", n)
	}
	c.Services.DDNS.Records[0].IPv6 = "off" // RA / prefix events cannot change an A record
	runOnWAN(c, "wan", "ipv6")
	if n != 4 {
		t.Error("kicked on an IPv6 event without AAAA records")
	}
	c.Services.DDNS.Enabled = false
	runOnWAN(c, "wan", "up")
	if n != 4 {
		t.Error("kicked while DDNS is off")
	}
	c.Services.DDNS.Enabled = true

	w := ddnsTryLock(ddnsWaitFile)
	if w == nil {
		t.Fatal("wait lock")
	}
	t0 := time.Now()
	if err := ddnsCommand(c, []string{"sync", "--hook"}); err != nil || time.Since(t0) > time.Second || len(f.take()) != 0 {
		t.Errorf("sync --hook with a waiter present: err %v, %v", err, time.Since(t0))
	}
	if ddnsTryLock(ddnsWaitFile) != nil {
		t.Error("wait lock not exclusive")
	}
	w.Close()
}

func TestDDNSAPI(t *testing.T) {
	if st := apiSysDDNSUpdate(apiReq{method: "GET"}).status; st != 405 {
		t.Errorf("sys.ddnsupdate via GET: %d", st)
	}
}
