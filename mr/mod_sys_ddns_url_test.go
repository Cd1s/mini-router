package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	duckTestToken = "0123abcd-duck-test-token-4567-89ef"
	dynTestPass   = "dyn-test-pass-word"
	hookTestToken = "hook-test-token-0123"
)

// fakeHTTP records the requests to a small server and answers with reply.
type fakeHTTP struct {
	mu    sync.Mutex
	reqs  []*http.Request
	body  []string
	reply func(r *http.Request, body string) (int, string)
}

func (f *fakeHTTP) start(t *testing.T) string {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.reqs, f.body = append(f.reqs, r), append(f.body, string(b))
		reply := f.reply
		f.mu.Unlock()
		st, out := reply(r, string(b))
		w.WriteHeader(st)
		io.WriteString(w, out)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func (f *fakeHTTP) take() ([]*http.Request, []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, b := f.reqs, f.body
	f.reqs, f.body = nil, nil
	return r, b
}

func TestDDNSDuckDNS(t *testing.T) {
	c, _, now, addrs := ddnsEnv(t)
	addrs["br-lan"] = []net.IP{net.ParseIP("2001:db8:1:2::1")}
	a, aaaa := "", ""
	f := &fakeHTTP{reply: func(r *http.Request, _ string) (int, string) {
		q := r.URL.Query()
		if q.Get("token") != duckTestToken || q.Get("domains") != "labhome" || q.Get("verbose") != "true" {
			return 200, "KO"
		}
		old := a + aaaa
		for _, v := range []string{q.Get("ip"), q.Get("ipv6")} {
			if ip := net.ParseIP(v); ip != nil && ip.To4() != nil {
				a = v
			} else if ip != nil {
				aaaa = v
			}
		}
		st := "UPDATED"
		if a+aaaa == old {
			st = "NOCHANGE"
		}
		return 200, "OK\n" + a + "\n" + aaaa + "\n" + st
	}}
	base := f.start(t)
	old := duckAPIBase
	duckAPIBase = base + "/update"
	t.Cleanup(func() { duckAPIBase = old })
	c.secrets["duck"] = duckTestToken
	setRecords(t, c, DDNSRecord{Name: "labhome.duckdns.org", Provider: "duckdns", Token: "duck", IPv6: "router"})

	// both types in one request; the other state is published by it
	rows, _ := ddnsSync(c, ddnsRun{})
	reqs, _ := f.take()
	if len(reqs) != 1 || reqs[0].URL.Query().Get("ip") != "192.0.2.10" || reqs[0].URL.Query().Get("ipv6") != "2001:db8:1:2::1" {
		t.Fatalf("first sync: %v", reqs)
	}
	if rows[0].Published != "192.0.2.10" || rows[1].Published != "2001:db8:1:2::1" || rows[1].Changed == 0 {
		t.Errorf("rows: %+v", rows)
	}
	// unchanged: nothing; a day later the check resends once (NOCHANGE: no change recorded)
	*now = now.Add(time.Hour)
	ddnsSync(c, ddnsRun{daily: true})
	if reqs, _ := f.take(); len(reqs) != 0 {
		t.Errorf("unchanged: %d requests", len(reqs))
	}
	ch := rows[0].Changed
	*now = now.Add(25 * time.Hour)
	rows, _ = ddnsSync(c, ddnsRun{daily: true})
	if reqs, _ := f.take(); len(reqs) != 1 || rows[0].Changed != ch {
		t.Errorf("daily check: %d requests, %+v", len(reqs), rows[0])
	}
	// a new prefix: the AAAA request carries the (unchanged) IPv4 address too
	addrs["br-lan"] = []net.IP{net.ParseIP("2001:db8:1:3::1")}
	rows, _ = ddnsSync(c, ddnsRun{})
	if reqs, _ := f.take(); len(reqs) != 1 || reqs[0].URL.Query().Get("ip") != "192.0.2.10" || reqs[0].URL.Query().Get("ipv6") != "2001:db8:1:3::1" || aaaa != "2001:db8:1:3::1" {
		t.Errorf("new prefix: %v", reqs)
	}
	// AAAA only: the IPv6 address goes into ip= (an empty ip= would make DuckDNS take IPv4 from the connection)
	setRecords(t, c, DDNSRecord{Name: "labhome.duckdns.org", Provider: "duckdns", Token: "duck", IPv4: "off", IPv6: "::10"})
	ddnsSync(c, ddnsRun{})
	if reqs, _ := f.take(); len(reqs) != 1 || reqs[0].URL.Query().Get("ip") != "2001:db8:1:3::10" || reqs[0].URL.Query().Has("ipv6") {
		t.Errorf("AAAA only: %v", reqs)
	}
	// a wrong token: KO stops the record; the token is in no error, state or status
	c.secrets["duck"] = "0123abcd-duck-wrong-token-4567-89ef"
	rows, _ = ddnsSync(c, ddnsRun{})
	if !rows[0].Stopped || !strings.Contains(rows[0].Error, "KO") {
		t.Errorf("KO: %+v", rows[0])
	}
	// the request URL (with the token) never reaches an error text
	duckAPIBase = "http://127.0.0.1:1/update"
	rows, _ = ddnsSync(c, ddnsRun{retry: true})
	if rows[0].Error == "" || strings.Contains(rows[0].Error, "token") || strings.Contains(rows[0].Error, "127.0.0.1:1/update") {
		t.Errorf("connection error: %q", rows[0].Error)
	}
	ddnsNoSecret(t, c, rows, duckTestToken, "0123abcd-duck-wrong-token-4567-89ef")
}

func TestDDNSDyndns2(t *testing.T) {
	c, _, now, addrs := ddnsEnv(t)
	addrs["br-lan"] = []net.IP{net.ParseIP("2001:db8:1:2::1")}
	cur, mode := "", ""
	f := &fakeHTTP{reply: func(r *http.Request, _ string) (int, string) {
		u, p, ok := r.BasicAuth()
		if !ok || u != "lab-user" || p != dynTestPass {
			return 401, "badauth"
		}
		if mode != "" {
			return 200, mode
		}
		q := r.URL.Query()
		v := q.Get("myip") + "," + q.Get("myipv6")
		if v == cur {
			return 200, "nochg " + v
		}
		cur = v
		return 200, "good " + v
	}}
	base := f.start(t)
	c.secrets["dyn"] = dynTestPass
	rec := DDNSRecord{Name: "home.example.org", Provider: "dyndns2", URL: "https://dyn.example.org/nic/update?system=dyndns", Username: "lab-user", Password: "dyn", IPv6: "router"}
	setRecords(t, c, rec)
	c.Services.DDNS.Records[0].URL = base + "/nic/update?system=dyndns" // the fake is plain HTTP (validation wants https)

	rows, _ := ddnsSync(c, ddnsRun{})
	reqs, _ := f.take()
	if len(reqs) != 1 {
		t.Fatalf("first sync: %d requests", len(reqs))
	}
	q := reqs[0].URL.Query()
	if q.Get("hostname") != "home.example.org" || q.Get("myip") != "192.0.2.10" || q.Get("myipv6") != "2001:db8:1:2::1" || q.Get("system") != "dyndns" ||
		reqs[0].URL.Path != "/nic/update" || !strings.HasPrefix(reqs[0].Header.Get("User-Agent"), "mini-router-ddns/") {
		t.Errorf("request: %v %v", reqs[0].URL, reqs[0].Header)
	}
	if rows[0].Published != "192.0.2.10" || rows[1].Published != "2001:db8:1:2::1" {
		t.Errorf("rows: %+v", rows)
	}
	// the daily check: nochg is a success without a change
	ch := rows[0].Changed
	*now = now.Add(25 * time.Hour)
	rows, _ = ddnsSync(c, ddnsRun{daily: true})
	if reqs, _ := f.take(); len(reqs) != 1 || rows[0].Error != "" || rows[0].Changed != ch {
		t.Errorf("nochg: %d %+v", len(reqs), rows[0])
	}
	// 911: retried later; abuse / a wrong password: stopped
	mode = "911"
	rows, _ = ddnsSync(c, ddnsRun{retry: true, check: true})
	if rows[0].Stopped || !strings.Contains(rows[0].Error, "dyndns2: HTTP 200 911") {
		t.Errorf("911: %+v", rows[0])
	}
	mode = "abuse"
	rows, _ = ddnsSync(c, ddnsRun{retry: true, check: true})
	if !rows[0].Stopped || !strings.Contains(rows[0].Error, "blocked for abuse") {
		t.Errorf("abuse: %+v", rows[0])
	}
	mode = ""
	c.secrets["dyn"] = "dyn-wrong-pass-word"
	rows, _ = ddnsSync(c, ddnsRun{})
	if !rows[0].Stopped || !strings.Contains(rows[0].Error, "HTTP 401 badauth (wrong user name or password)") {
		t.Errorf("badauth: %+v", rows[0])
	}
	ddnsNoSecret(t, c, rows, dynTestPass, "dyn-wrong-pass-word")
}

func TestDDNSWebhook(t *testing.T) {
	c, _, now, _ := ddnsEnv(t)
	status := 200
	f := &fakeHTTP{reply: func(r *http.Request, _ string) (int, string) { return status, "ok " + hookTestToken }}
	base := f.start(t)
	c.secrets["hook"] = hookTestToken
	setRecords(t, c, DDNSRecord{Name: "Home.Example.com", Provider: "webhook", URL: "https://hooks.example.org/ddns?h={name}&t={type}&ip={ip}", Token: "hook"})
	if c.Services.DDNS.Records[0].Method != "GET" {
		t.Errorf("default method %q", c.Services.DDNS.Records[0].Method)
	}
	c.Services.DDNS.Records[0].URL = base + "/ddns?h={name}&t={type}&ip={ip}"
	rows, _ := ddnsSync(c, ddnsRun{})
	reqs, _ := f.take()
	if len(reqs) != 1 || reqs[0].Method != "GET" || reqs[0].URL.RawQuery != "h=home.example.com&t=A&ip=192.0.2.10" ||
		reqs[0].Header.Get("Authorization") != "Bearer "+hookTestToken || rows[0].Published != "192.0.2.10" {
		t.Fatalf("GET: %v %v %+v", reqs, reqs[0].Header, rows[0])
	}
	// no daily resend (it would repeat whatever the hook does); 立即更新 (force) resends
	*now = now.Add(25 * time.Hour)
	ddnsSync(c, ddnsRun{daily: true})
	if reqs, _ := f.take(); len(reqs) != 0 {
		t.Errorf("daily resend: %d", len(reqs))
	}
	ddnsSync(c, ddnsRun{retry: true, check: true})
	if reqs, _ := f.take(); len(reqs) != 1 {
		t.Errorf("forced: %d", len(reqs))
	}
	// POST: JSON body; {token} in the URL instead of the header (escaped)
	c.secrets["hook"] = "a b/c&d=e"
	c.Services.DDNS.Records[0].Method = "POST"
	c.Services.DDNS.Records[0].URL = base + "/p/{token}?ip={ip}"
	ddnsSync(c, ddnsRun{})
	reqs, bodies := f.take()
	var jb map[string]string
	json.Unmarshal([]byte(bodies[0]), &jb)
	if len(reqs) != 1 || reqs[0].Method != "POST" || reqs[0].Header.Get("Authorization") != "" || reqs[0].URL.EscapedPath() != "/p/a+b%2Fc%26d%3De" || reqs[0].URL.RawQuery != "ip=192.0.2.10" ||
		reqs[0].Header.Get("Content-Type") != "application/json" || jb["name"] != "home.example.com" || jb["type"] != "A" || jb["ip"] != "192.0.2.10" {
		t.Errorf("POST: %v %q %v", reqs[0].URL, bodies, reqs[0].Header)
	}
	// 401 stops, 500 backs off; the answer (which echoes the token) never reaches the state
	c.secrets["hook"] = hookTestToken
	status = 500
	rows, _ = ddnsSync(c, ddnsRun{})
	if rows[0].Stopped || rows[0].Error != "webhook: HTTP 500" {
		t.Errorf("500: %+v", rows[0])
	}
	status = 401
	rows, _ = ddnsSync(c, ddnsRun{retry: true})
	if !rows[0].Stopped || !strings.Contains(rows[0].Error, "HTTP 401") {
		t.Errorf("401: %+v", rows[0])
	}
	// a request error names the URL with the token: it is dropped
	c.Services.DDNS.Records[0].URL = "http://127.0.0.1:1/p/{token}"
	rows, _ = ddnsSync(c, ddnsRun{retry: true})
	if rows[0].Error == "" || strings.Contains(rows[0].Error, "/p/") {
		t.Errorf("connection error: %q", rows[0].Error)
	}
	ddnsNoSecret(t, c, rows, hookTestToken)
}

func TestDDNSValidateProviders(t *testing.T) {
	c := testConfig(t)
	c.secrets["k"], c.secrets["t"], c.secrets["short"], c.secrets["spacy"] = aliTestSecret, cfTestToken, "abc", "has a space in it 0123"
	iv := 10
	c.Services.DDNS = DDNS{Enabled: true, Interval: &iv, Records: []DDNSRecord{
		{Name: "a.example.com", Provider: "alidns", Zone: "example.com", KeyID: aliTestID, Key: "k"},                                                                                  // 0 valid
		{Name: "b.example.com", Provider: "dnspod", Zone: "example.com", KeyID: tcTestID, Key: "k", TTL: 600, IPv4: "mac:02:00:00:00:00:10", IPv6: "url:https://ip6.example.org/"},    // 1 valid
		{Name: "myhome.duckdns.org", Provider: "duckdns", Token: "t", IPv4: "url:https://ip4.example.org/?format=text", IPv6: "router"},                                               // 2 valid
		{Name: "c.example.org", Provider: "dyndns2", URL: "https://dynupdate.no-ip.com/nic/update", Username: "me@example.org", Password: "k", IPv4: "198.51.100.7"},                  // 3 valid
		{Name: "d.example.org", Provider: "webhook", URL: "https://h.example.org/x?n={name}&t={type}&i={ip}&k={token}", Token: "k", Method: "POST", IPv6: "2001:db8::7", IPv4: "off"}, // 4 valid
		{Name: "e.example.org", Provider: "webhook", URL: "https://h.example.org/{ip}"},                                                                                               // 5 valid (no token)
		{Name: "f.example.com", Provider: "alidns", Zone: "example.com", KeyID: "LTAI short!", Key: "short"},                                                                          // 6 key_id, key_secret value
		{Name: "g.example.com", Provider: "cloudflare", Zone: "example.com", Token: "t", KeyID: aliTestID, URL: "https://x.example.org/"},                                             // 7 keys of another provider
		{Name: "h.example.net", Provider: "duckdns", Token: "t"},                                                                                                                      // 8 not a DuckDNS name
		{Name: "x.y.duckdns.org", Provider: "duckdns", Token: "t", Zone: "duckdns.org"},                                                                                               // 9 two labels, zone
		{Name: "i.example.org", Provider: "dyndns2", URL: "http://dyn.example.org/", Username: "a:b", Password: "spacy"},                                                              // 10 url, username, password
		{Name: "*.example.org", Provider: "dyndns2", URL: "https://user:pw@dyn.example.org/", Username: "u", Password: "k"},                                                           // 11 wildcard, userinfo
		{Name: "j.example.org", Provider: "webhook", URL: "https://h.example.org/{ip}{secret}", Method: "PUT"},                                                                        // 12 placeholder, method
		{Name: "k.example.org", Provider: "webhook", URL: "https://h.example.org/?k={token}"},                                                                                         // 13 {token} without token_secret
		{Name: "l.example.org", Provider: "webhook", URL: "https://h.example.org/ a\"b", TTL: 60},                                                                                     // 14 quotes / spaces, ttl
		{Name: "m.example.com", Zone: "example.com", Provider: "cloudflare", Token: "t", IPv4: "192.168.1.5", IPv6: "fd00::5"},                                                        // 15 private fixed values
		{Name: "n.example.com", Zone: "example.com", Provider: "cloudflare", Token: "t", IPv4: "100.64.1.1", IPv6: "mac:01:00:5e:00:00:01"},                                           // 16 CGNAT, multicast MAC
		{Name: "o.example.com", Zone: "example.com", Provider: "cloudflare", Token: "t", IPv4: "url:http://ip.example.org/", IPv6: "url:https://ip.example.org/#x"},                   // 17 lookup URLs
	}}
	c.defaults()
	errs := strings.Join(c.Validate(), "\n")
	for _, s := range []string{
		"records[6].key_id: the AccessKey ID", "records[6].key_secret: the secret is not an API key secret",
		"records[7].key_id: not used by provider cloudflare (it takes zone, token_secret, ttl)", "records[7].url: not used by provider cloudflare",
		`records[8].name: a DuckDNS name like myhome.duckdns.org, got "h.example.net"`, `records[9].name: a DuckDNS name`, "records[9].zone: not used by provider duckdns",
		"records[10].url: the provider's update URL", "not an https:// URL", "records[10].username: 1-128 printable characters", "records[10].password_secret: the secret is not a password",
		`records[11].name: dyndns2 updates one host name, not "*.example.org"`, "records[11].url: the provider's update URL, e.g. https://dynupdate.no-ip.com/nic/update: no user:password@ in the URL",
		"records[12].url: an https:// URL with {name} {type} {ip} (and {token}) placeholders: unknown placeholder", `records[12].method: GET | POST, got "PUT"`,
		"records[13].url: {token} needs token_secret", "records[14].url: an https:// URL", "spaces, quotes", "records[14].ttl: not used by provider webhook",
		`records[15].ipv4: active | off | a WAN name | url:https://… | mac:MAC | a public IPv4 address, got "192.168.1.5" (private, CGNAT and reserved`, `records[15].ipv6: off | router | ::IID`, `got "fd00::5" (not a global address)`,
		`records[16].ipv4:`, `got "100.64.1.1"`, `got "mac:01:00:5e:00:00:01" (not a unicast MAC)`,
		`got "url:http://ip.example.org/" (not an https:// URL)`, `got "url:https://ip.example.org/#x" (no #fragment)`,
	} {
		if !strings.Contains(errs, s) {
			t.Errorf("want error %q in:\n%s", s, errs)
		}
	}
	for i := 0; i <= 5; i++ {
		if p := fmt.Sprintf("records[%d]", i); strings.Contains(errs, p+".") || strings.Contains(errs, p+":") {
			t.Errorf("valid record %d rejected:\n%s", i, errs)
		}
	}
	for _, s := range []string{aliTestSecret, cfTestToken, "has a space"} {
		if strings.Contains(errs, s) {
			t.Errorf("a validation message shows a secret: %s", s)
		}
	}
	if k := strings.Join(ddnsSecrets(c), " "); !strings.Contains(k, "k") || !strings.Contains(k, "t") || !strings.Contains(k, "spacy") {
		t.Errorf("secret names: %s", k)
	}
	// the edge takes the same AliDNS / DNSPod keys
	e := &c.Services.Edge
	*e = Edge{Enabled: true, Routes: []EdgeRoute{{Name: "nas", Host: "nas.example.com", To: "http://192.168.1.10:5000"}},
		ACME: EdgeACME{Provider: "alidns", KeyID: aliTestID, Key: "k"}}
	c.Services.DDNS = DDNS{}
	c.defaults()
	for _, x := range c.Validate() {
		if strings.Contains(x, "services.edge.acme") {
			t.Errorf("edge alidns rejected: %s", x)
		}
	}
	e.ACME = EdgeACME{Provider: "dnspod", KeyID: "no", Key: "short", Token: "t"}
	errs = strings.Join(c.Validate(), "\n")
	for _, s := range []string{"acme.token_secret: not used by provider dnspod", "acme.key_id: the AccessKey ID / SecretId", "acme.key_secret: the secret is not an API key secret"} {
		if !strings.Contains(errs, s) {
			t.Errorf("edge: want %q in:\n%s", s, errs)
		}
	}
	e.ACME = EdgeACME{Provider: "cloudflare", Token: "t", KeyID: aliTestID}
	if errs := strings.Join(c.Validate(), "\n"); !strings.Contains(errs, "acme: key_id / key_secret are for provider alidns or dnspod") {
		t.Errorf("edge cloudflare with key_id:\n%s", errs)
	}
}

// url: sources — the lookup, its answer formats, private answers, one lookup per URL and sync, the
// status without a request; the dialer's family and source address.
func TestDDNSSourceURL(t *testing.T) {
	c, cf, _, _ := ddnsEnv(t)
	writeLease("wan", wanLease{IP: "127.0.0.1"}) // a loopback lease binds nothing (the test host has no 192.0.2.10)
	answer, status := "Current IP Address: 198.51.100.23</body>", 200
	f := &fakeHTTP{reply: func(*http.Request, string) (int, string) { return status, answer }}
	base := f.start(t)
	r := DDNSRecord{Name: "home.example.com", Provider: "cloudflare", Zone: "example.com", Token: "cf_test_token", IPv4: "url:" + base + "/ip"}
	r2 := r
	r2.Name = "nas.example.com"
	c.Services.DDNS.Records = []DDNSRecord{r, r2}
	c.defaults()
	rows, _ := ddnsSync(c, ddnsRun{})
	if reqs, _ := f.take(); len(reqs) != 1 {
		t.Errorf("lookups: %d (want one per URL and sync)", len(reqs))
	}
	if rows[0].Local != "198.51.100.23" || rows[0].Published != "198.51.100.23" || rows[1].Published != "198.51.100.23" {
		t.Fatalf("rows: %+v", rows)
	}
	cf.take()
	// the status never looks anything up: it shows the last result
	st := ddnsStatus(c)
	if reqs, _ := f.take(); len(reqs) != 0 || st[0].Local != "198.51.100.23" {
		t.Errorf("status: %d lookups, %+v", len(reqs), st[0])
	}
	// a private answer, no address, an error status, a redirect: nothing is published, the note says why
	for ans, want := range map[string]string{"10.1.2.3": "answered a private address 10.1.2.3", "100.64.0.1": "cgnat address", "nothing here": "no IPv4 address in the answer", "": "HTTP 500"} {
		answer, status = ans, 200
		if ans == "" {
			status = 500
		}
		rows, _ = ddnsSync(c, ddnsRun{})
		if rows[0].Local != "" || !strings.Contains(rows[0].Note, want) || rows[0].Published != "198.51.100.23" {
			t.Errorf("answer %q: %+v", ans, rows[0])
		}
	}
	answer, status = "", 302
	if rows, _ = ddnsSync(c, ddnsRun{}); !strings.Contains(rows[0].Note, "HTTP 302") {
		t.Errorf("redirect followed? %+v", rows[0])
	}
	if c := cf.take(); len(c) != 0 {
		t.Errorf("provider asked without an address: %v", c)
	}
	// answer formats
	ctx := context.Background()
	for body, want := range map[string]string{"198.51.100.24\n": "198.51.100.24", `{"ip":"198.51.100.25"}`: "198.51.100.25", "addr=2001:db8::5;": "2001:db8::5",
		"IPv6: 2001:db8:0:1::abcd (v4 203.0.113.9)": "2001:db8:0:1::abcd"} {
		answer, status = body, 200
		v6 := strings.Contains(want, ":")
		ip, err := ddnsFetchIP(ctx, ddnsHTTP(), base+"/ip", v6)
		if err != nil || ip.String() != want {
			t.Errorf("fetch %q: %v %v", body, ip, err)
		}
	}
	// the lookup client dials only its family and from the given address (the WAN's, for its policy rule)
	var from string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { from = r.RemoteAddr; io.WriteString(w, "198.51.100.26") }))
	defer srv.Close()
	if ip, err := ddnsFetchIP(ctx, ddnsLookupHTTP("tcp4", net.ParseIP("127.0.0.2")), srv.URL, false); err != nil || ip.String() != "198.51.100.26" || !strings.HasPrefix(from, "127.0.0.2:") {
		t.Errorf("bound lookup: %v %v from %s", ip, err, from)
	}
	if _, err := ddnsFetchIP(ctx, ddnsLookupHTTP("tcp6", nil), srv.URL, false); err == nil {
		t.Error("a tcp6 lookup reached an IPv4-only server")
	}
	// the source address is the WAN `active` would use, whatever its class
	writeLease("wan", wanLease{IP: "100.64.3.4"})
	if a := ddnsWANAddr4(c); a.String() != "100.64.3.4" {
		t.Errorf("WAN source address %v", a)
	}
}

// mac: sources — IPv4 from the DHCP lease (else the neighbour table), private addresses not published;
// IPv6 from the neighbour table inside the LAN prefix: EUI-64 first, then the published one, then the lowest.
func TestDDNSSourceMAC(t *testing.T) {
	c, _, _, addrs := ddnsEnv(t)
	d := t.TempDir()
	var nb []monNeigh
	o1, o2 := ddnsNeigh, ddnsLeaseFile
	ddnsNeigh, ddnsLeaseFile = func() []monNeigh { return nb }, filepath.Join(d, "dhcp.leases")
	t.Cleanup(func() { ddnsNeigh, ddnsLeaseFile = o1, o2 })
	mac := "02:00:00:00:00:10"
	n := func(a string, m string) monNeigh { return monNeigh{Addr: netip.MustParseAddr(a), MAC: m, Ifindex: 5} }
	src := &ddnsSrc{c: c}
	rec := DDNSRecord{IPv4: "mac:" + mac, IPv6: "mac:" + mac}

	os.WriteFile(ddnsLeaseFile, []byte("1800000100 02:00:00:00:00:10 198.51.100.50 nas *\n1800000050 02:00:00:00:00:10 198.51.100.49 nas *\n1800000200 aa:bb:cc:dd:ee:ff 198.51.100.60 pc *\n"), 0644)
	if ip, note := src.local(rec, "A", nil); ip != "198.51.100.50" || note != "" {
		t.Errorf("lease: %q %q", ip, note)
	}
	os.WriteFile(ddnsLeaseFile, []byte("1800000100 02:00:00:00:00:10 192.168.1.10 nas *\n"), 0644)
	if ip, note := src.local(rec, "A", nil); ip != "" || !strings.Contains(note, "private address 192.168.1.10") {
		t.Errorf("private lease: %q %q", ip, note)
	}
	os.Remove(ddnsLeaseFile)
	nb = []monNeigh{n("198.51.100.51", mac)}
	if ip, _ := (&ddnsSrc{c: c}).local(rec, "A", nil); ip != "198.51.100.51" {
		t.Errorf("neighbour: %q", ip)
	}
	nb = nil
	if ip, note := (&ddnsSrc{c: c}).local(rec, "A", nil); ip != "" || !strings.Contains(note, "no DHCP lease or neighbour entry") {
		t.Errorf("absent: %q %q", ip, note)
	}

	// IPv6
	if _, note := (&ddnsSrc{c: c}).local(rec, "AAAA", nil); !strings.Contains(note, "no global IPv6 prefix") {
		t.Errorf("no prefix: %q", note)
	}
	addrs["br-lan"] = []net.IP{net.ParseIP("2001:db8:1:2::1")}
	nb = []monNeigh{n("2001:db8:1:2:aaaa::9", mac), n("2001:db8:9:9::5", mac), n("fe80::10", mac), n("fd00::10", mac), n("2001:db8:1:2:0:ff:fe00:10", mac),
		n("2001:db8:1:2::77", "aa:bb:cc:dd:ee:ff"), n("2001:db8:1:2:1111::9", mac)}
	if ip, _ := (&ddnsSrc{c: c}).local(rec, "AAAA", nil); ip != "2001:db8:1:2:0:ff:fe00:10" {
		t.Errorf("EUI-64 first: %q", ip)
	}
	nb = append(nb[:4], nb[5:]...) // no EUI-64 address
	if ip, _ := (&ddnsSrc{c: c}).local(rec, "AAAA", nil); ip != "2001:db8:1:2:1111::9" {
		t.Errorf("lowest: %q", ip)
	}
	if ip, _ := (&ddnsSrc{c: c}).local(rec, "AAAA", &ddnsState{Published: "2001:db8:1:2:aaaa::9"}); ip != "2001:db8:1:2:aaaa::9" {
		t.Errorf("published one kept: %q", ip)
	}
	nb = []monNeigh{n("2001:db8:9:9::5", mac)}
	if ip, note := (&ddnsSrc{c: c}).local(rec, "AAAA", nil); ip != "" || !strings.Contains(note, "no global IPv6 address in the neighbour table") {
		t.Errorf("old prefix only: %q %q", ip, note)
	}
	// fixed values
	if ip, _ := src.local(DDNSRecord{IPv4: "203.0.113.5", IPv6: "2001:db8::5"}, "AAAA", nil); ip != "2001:db8::5" {
		t.Errorf("fixed: %q", ip)
	}
}

// WAN events for the new sources; the ddns events: a change (info), a record that keeps failing
// (warn, once), and its recovery (info) — never with a secret.
func TestDDNSEventsAndHooks(t *testing.T) {
	c, f, now, addrs := ddnsEnv(t)
	eventEnv(t)
	for _, x := range []struct {
		v4, v6, event string
		want          bool
	}{
		{"off", "mac:02:00:00:00:00:10", "ipv6", true}, {"off", "mac:02:00:00:00:00:10", "up", false},
		{"url:https://ip.example.org/", "off", "up", true}, {"url:https://ip.example.org/", "off", "ipv6", false},
		{"off", "url:https://ip.example.org/", "up", true}, {"203.0.113.5", "off", "up", false}, {"mac:02:00:00:00:00:10", "off", "health", false},
	} {
		c.Services.DDNS.Records[0].IPv4, c.Services.DDNS.Records[0].IPv6 = x.v4, x.v6
		if got := ddnsUses(c, x.event); got != x.want {
			t.Errorf("ddnsUses(%s/%s, %s) = %v", x.v4, x.v6, x.event, got)
		}
	}
	c.Services.DDNS.Records[0].IPv4, c.Services.DDNS.Records[0].IPv6 = "active", "router"
	addrs["br-lan"] = []net.IP{net.ParseIP("2001:db8:1:2::1")}
	f.recs = []map[string]any{{"id": fmt.Sprintf("%032x", 1), "name": "home.example.com", "type": "A", "content": "203.0.113.99", "ttl": 1, "proxied": false}}

	ddnsSync(c, ddnsRun{})
	ev := eventsRead(0, 10) // oldest first
	if len(ev) != 1 || ev[0].Type != "ddns" || ev[0].Sev != "info" || ev[0].Key != "home.example.com" ||
		ev[0].Msg != "updated home.example.com A 192.0.2.10; home.example.com AAAA 2001:db8:1:2::1" {
		t.Fatalf("change event: %+v", ev)
	}
	// unchanged: no event
	ddnsSync(c, ddnsRun{})
	if len(eventsRead(0, 10)) != 1 {
		t.Error("an event without a change")
	}
	// failures: a warning after the third in a row, once; then "updated again"
	writeLease("wan", wanLease{IP: "192.0.2.11"})
	f.status, f.code = 500, 1000
	for i := 0; i < 5; i++ {
		ddnsSync(c, ddnsRun{})
		*now = now.Add(time.Duration(ddnsBackoff(i+1))*time.Minute + time.Second)
	}
	ev = eventsRead(0, 10)
	if len(ev) != 2 || ev[1].Sev != "warn" || !strings.HasPrefix(ev[1].Msg, "update failing: home.example.com A: Cloudflare: HTTP 500") {
		t.Fatalf("failure event: %+v", ev)
	}
	f.status = 0
	ddnsSync(c, ddnsRun{})
	ev = eventsRead(0, 10)
	if len(ev) != 4 || ev[2].Msg != "updated home.example.com A 192.0.2.11 (was 192.0.2.10)" || ev[3].Msg != "updated again: home.example.com A" {
		t.Fatalf("recovery events: %+v", ev)
	}
	// a refused token warns at once
	c.secrets["cf_test_token"] = cfTestToken[:len(cfTestToken)-1] + "X"
	writeLease("wan", wanLease{IP: "192.0.2.12"})
	ddnsSync(c, ddnsRun{})
	ev = eventsRead(0, 10)
	if len(ev) != 5 || ev[4].Sev != "warn" || !strings.Contains(ev[4].Msg, "refused the token") {
		t.Fatalf("refused token event: %+v", ev)
	}
	b, _ := json.Marshal(ev)
	if strings.Contains(string(b), cfTestToken[:12]) {
		t.Error("an event shows the token")
	}
	if !slicesHas(notifyDefaultEvents(), "ddns") || eventLabels["ddns"] == "" {
		t.Error("ddns events are not notified by default")
	}
}
