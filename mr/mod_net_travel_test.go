package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// tempCheckDir points the check / conflict records at a temp dir for one test.
func tempCheckDir(t *testing.T) string {
	t.Helper()
	tempState(t)
	d := filepath.Join(t.TempDir(), "wan-check")
	old := checkDir
	checkDir = d
	t.Cleanup(func() { checkDir = old })
	return d
}

func TestTravelClassify(t *testing.T) {
	cases := []struct {
		code, body int
		want       string
	}{
		{204, 0, "online"}, {200, 0, "online"}, {200, 1200, "portal"}, {302, 0, "portal"}, {301, 10, "portal"},
		{307, 0, "portal"}, {511, 300, "portal"}, {403, 0, ""}, {404, 10, ""}, {500, 0, ""}, {502, 0, ""},
	}
	for _, tc := range cases {
		if got := classify(tc.code, tc.body); got != tc.want {
			t.Errorf("classify(%d, %d) = %q, want %q", tc.code, tc.body, got, tc.want)
		}
	}
}

func TestTravelCleanURL(t *testing.T) {
	base, _ := url.Parse("http://connectivitycheck.example.com/generate_204")
	cases := []struct {
		raw   string
		https bool
		want  string
	}{
		{"http://192.0.2.1:8080/login?mac=aa&x=1", false, "http://192.0.2.1:8080/login?mac=aa&x=1"},
		{"/portal/login.html", false, "http://connectivitycheck.example.com/portal/login.html"},
		{"https://portal.example.net/", true, "https://portal.example.net/"},
		{"http://portal.example.net/", true, ""}, // RFC 8908: https only
		{"javascript:alert(1)", false, ""},
		{"data:text/html,<b>x</b>", false, ""},
		{"ftp://192.0.2.1/", false, ""},
		{"http://user:pw@192.0.2.1/", false, ""},
		{"http://192.0.2.1/\"><script>", false, ""},
		{"http://192.0.2.1/a\nb", false, ""},
		{"http:///nohost", false, ""},
		{"http://192.0.2.1/" + strings.Repeat("a", 600), false, ""},
	}
	for _, tc := range cases {
		b := base
		if tc.https {
			b = nil
		}
		if got := cleanURL(tc.raw, b, tc.https); got != tc.want {
			t.Errorf("cleanURL(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

func TestTravelPortalFromBody(t *testing.T) {
	cases := map[string]string{
		`<html><head><META HTTP-EQUIV="Refresh" CONTENT="0; URL=http://192.0.2.1/login?id=7"></head></html>`: "http://192.0.2.1/login?id=7",
		`<meta http-equiv='refresh' content='2;url=/auth'>`:                                                  "/auth",
		`<script>window.location.href = "https://portal.example.net/start";</script>`:                        "https://portal.example.net/start",
		`<script>location.replace('http://198.51.100.7/');</script>`:                                         "http://198.51.100.7/",
		`<html><body>Welcome</body></html>`:                                                                  "",
	}
	for body, want := range cases {
		if got := portalFromBody([]byte(body)); got != want {
			t.Errorf("portalFromBody(%q) = %q, want %q", body, got, want)
		}
	}
}

func TestTravelValidCheckURL(t *testing.T) {
	for _, s := range []string{"http://connectivitycheck.gstatic.com/generate_204", "http://cp.cloudflare.com/generate_204",
		"http://192.0.2.10/cgi-bin/204", "http://check.example.com:8080/x?y=1", "http://check.example.com"} {
		if !validCheckURL(s) {
			t.Errorf("rejected %q", s)
		}
	}
	for _, s := range []string{"", "https://check.example.com/", "http://[2001:db8::1]/", "http://127.0.0.1/", "http://0.0.0.0/",
		"http://user@check.example.com/", "http://check.example.com/a b", "http://check.example.com/#x", "http://check.example.com:99999/",
		"http://check..example.com/", "http://check.example.com/\"x", "file:///etc/passwd", "http://check.example.com/\n", "check.example.com"} {
		if validCheckURL(s) {
			t.Errorf("accepted %q", s)
		}
	}
}

// probe against a local HTTP server: the classification, the login URL (Location, relative
// Location, meta refresh), the Date header, and answers that say nothing about the network.
func TestTravelProbe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/204":
			w.WriteHeader(204)
		case "/empty":
			w.WriteHeader(200)
		case "/302":
			w.Header().Set("Location", "http://192.0.2.1/login?ap=hotel")
			w.WriteHeader(302)
		case "/rel":
			w.Header().Set("Location", "/login")
			w.WriteHeader(302)
		case "/evil":
			w.Header().Set("Location", "javascript:alert(document.cookie)")
			w.WriteHeader(302)
		case "/page":
			fmt.Fprint(w, `<html><meta http-equiv="refresh" content="0;url=http://192.0.2.1/p"></html>`)
		case "/511":
			w.WriteHeader(511)
		default:
			w.WriteHeader(503)
		}
	}))
	defer srv.Close()
	client := checkClient("", nil, 3*time.Second)
	cases := []struct {
		path, state, portal string
		code                int
	}{
		{"/204", "online", "", 204},
		{"/empty", "online", "", 200},
		{"/302", "portal", "http://192.0.2.1/login?ap=hotel", 302},
		{"/rel", "portal", srv.URL + "/login", 302},
		{"/evil", "portal", "", 302},
		{"/page", "portal", "http://192.0.2.1/p", 200},
		{"/511", "portal", "", 511},
	}
	for _, tc := range cases {
		r, date, sent, err := probe(client, srv.URL+tc.path)
		if err != nil {
			t.Errorf("%s: %v", tc.path, err)
			continue
		}
		if r.State != tc.state || r.PortalURL != tc.portal || r.Code != tc.code || r.URL != srv.URL+tc.path {
			t.Errorf("%s: got %+v", tc.path, r)
		}
		if date.IsZero() || sent.IsZero() || date.Sub(sent) > 5*time.Second || sent.Sub(date) > 5*time.Second {
			t.Errorf("%s: Date %v sent %v", tc.path, date, sent)
		}
	}
	if _, _, _, err := probe(client, srv.URL+"/down"); err == nil || !strings.Contains(err.Error(), "HTTP 503") {
		t.Errorf("503 must be an error (next URL), got %v", err)
	}
	srv.Close()
	if _, _, _, err := probe(client, srv.URL+"/204"); err == nil {
		t.Error("closed server must be an error")
	}
}

func TestTravelPortalAPI(t *testing.T) {
	c, u := portalAPI([]byte(`{"captive": true, "user-portal-url": "https://portal.example.net/login", "seconds-remaining": 30}`))
	if c == nil || !*c || u != "https://portal.example.net/login" {
		t.Errorf("captive API: %v %q", c, u)
	}
	c, u = portalAPI([]byte(`{"captive": false}`))
	if c == nil || *c || u != "" {
		t.Errorf("not captive: %v %q", c, u)
	}
	if c, u = portalAPI([]byte(`{"captive": true, "user-portal-url": "http://portal.example.net/"}`)); u != "" {
		t.Errorf("plain-HTTP user-portal-url accepted: %q", u)
	}
	if c, _ = portalAPI([]byte(`<html>`)); c != nil {
		t.Error("garbage parsed")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") != "application/captive+json" {
			w.WriteHeader(406)
			return
		}
		fmt.Fprint(w, `{"captive": true, "user-portal-url": "https://portal.example.net/x"}`)
	}))
	defer srv.Close()
	if c, u := fetchPortalAPI(checkClient("", nil, 3*time.Second), srv.URL); c == nil || !*c || u != "https://portal.example.net/x" {
		t.Errorf("fetchPortalAPI: %v %q", c, u)
	}
}

func TestTravelPortalAPIFromEnv(t *testing.T) {
	for raw, want := range map[string]string{
		"https://portal.example.net/api?x=1": "https://portal.example.net/api?x=1",
		"http://portal.example.net/api":      "",
		"https://portal.example.net/\x00x":   "",
	} {
		t.Setenv("opt114", hex.EncodeToString([]byte(raw)))
		if got := portalAPIFromEnv(); got != want {
			t.Errorf("opt114 %q -> %q, want %q", raw, got, want)
		}
	}
	t.Setenv("opt114", "zz")
	if got := portalAPIFromEnv(); got != "" {
		t.Errorf("bad hex -> %q", got)
	}
}

// travelConfig: the home config with a synthetic LAN (tests never depend on the home addresses)
// and a guest network.
func travelConfig(t *testing.T) *Config {
	c := testConfig(t)
	c.LAN.IPv4 = "192.168.50.1/24"
	c.DHCP.Hosts = nil
	c.Firewall.Forwards = nil
	c.Networks = []Network{{Name: "guest", IPv4: "192.168.60.1/24", Zone: "guest"}}
	c.defaults()
	return c
}

func TestTravelLANConflict(t *testing.T) {
	c := travelConfig(t)
	cases := []struct {
		ip     string
		prefix int
		gw     string
		net    string
	}{
		{"192.168.50.23", 24, "192.168.50.254", "lan"}, // the classic: upstream uses the LAN's own subnet
		{"192.168.60.9", 24, "192.168.60.1", "guest"},
		{"192.168.0.10", 16, "192.168.0.1", "lan"},   // a /16 upstream that contains the LAN
		{"198.51.100.20", 32, "192.168.50.1", "lan"}, // gateway inside the LAN
		{"10.0.0.23", 24, "10.0.0.1", ""},
		{"192.168.51.23", 24, "192.168.51.1", ""},
	}
	for _, tc := range cases {
		n, nn, bad := lanConflict(c, net.ParseIP(tc.ip), tc.prefix, net.ParseIP(tc.gw))
		if bad != (tc.net != "") || n.Name != tc.net {
			t.Errorf("%s/%d gw %s: got %q %v %v, want %q", tc.ip, tc.prefix, tc.gw, n.Name, nn, bad, tc.net)
		}
	}
	// the suggestion clears the upstream subnet and every other LAN-side network
	_, up, _ := net.ParseCIDR("10.77.0.0/16")
	if s := suggestLAN(c, up, "lan"); s != "172.22.77.1/24" {
		t.Errorf("suggestLAN = %q", s)
	}
	c.Networks = append(c.Networks, Network{Name: "iot", IPv4: "172.22.77.1/24"})
	if s := suggestLAN(c, up, "lan"); s != "192.168.77.1/24" {
		t.Errorf("suggestLAN with iot on the 2nd candidate = %q", s)
	}
	if s := suggestLAN(c, up, "iot"); s != "172.22.77.1/24" {
		t.Errorf("the moving network's own subnet is free: %q", s)
	}

	// a static WAN on top of a LAN-side network, and wan[].portal values
	c = travelConfig(t)
	c.WAN = append(c.WAN, WAN{Name: "hotel", Device: "lan4", Proto: "static", IPv4: "192.168.60.20/24", Gateway: "192.168.60.254", Metric: 90})
	c.LAN.Ports = []string{"lan2", "lan3"}
	c.WAN[0].Portal = "maybe"
	errs := strings.Join(c.Validate(), "\n")
	wantSubs(t, "validation", errs, "wan[2].ipv4: 192.168.60.20/24 overlaps LAN-side network guest (192.168.60.0/24)",
		`wan[0].portal: auto|off`)
	c.WAN[2].IPv4, c.WAN[2].Gateway, c.WAN[0].Portal = "198.51.100.20/24", "198.51.100.1", "auto"
	mustValid(t, c)
}

func TestTravelPortalDefault(t *testing.T) {
	for _, tc := range []struct {
		proto, portal string
		want          bool
	}{{"dhcp", "", true}, {"dhcp", "off", false}, {"pppoe", "", false}, {"pppoe", "auto", true}, {"static", "", false}, {"static", "auto", true}} {
		if got := (WAN{Proto: tc.proto, Portal: tc.portal}).PortalCheck(); got != tc.want {
			t.Errorf("%s/%q: %v", tc.proto, tc.portal, got)
		}
	}
	// the home config's JSON (what the web UI edits and saves back) gains no travel keys
	c := testConfig(t)
	m, err := configToJSON(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range m["wan"].([]any) {
		if _, ok := w.(map[string]any)["portal"]; ok {
			t.Error("wan JSON has an empty portal key")
		}
	}
	if _, ok := m["system"].(map[string]any)["connectivity_check"]; ok {
		t.Error("system JSON has an empty connectivity_check key")
	}
	if got := connCheckURLs(c); len(got) != 2 || !validCheckURL(got[0]) || !validCheckURL(got[1]) {
		t.Errorf("default check URLs: %v", got)
	}
}

func TestTravelConnCheckValidation(t *testing.T) {
	c := testConfig(t)
	c.System.ConnCheck = []string{"http://192.0.2.10/generate_204", "https://check.example.com/", "a", "b", "c"}
	errs := strings.Join(c.Validate(), "\n")
	wantSubs(t, "validation", errs, "system.connectivity_check: at most 4 URLs", `"https://check.example.com/": http://host`)
	wantNone(t, "validation", errs, "192.0.2.10")
	c.System.ConnCheck = []string{"http://192.0.2.10/generate_204"}
	mustValid(t, c)
	if got := connCheckURLs(c); len(got) != 1 || got[0] != "http://192.0.2.10/generate_204" {
		t.Errorf("configured URLs: %v", got)
	}
}

// Records: a refused lease is kept while it still collides, dropped when the WAN leaves DHCP or the
// config no longer collides; status shows a check only for the address it ran from.
func TestTravelRecords(t *testing.T) {
	d := tempCheckDir(t)
	c := travelConfig(t)
	c.WAN = append(c.WAN, WAN{Name: "hotel", Device: "lan4", Proto: "dhcp", Metric: 90})
	c.LAN.Ports = []string{"lan2", "lan3"}
	writeJSONFile(filepath.Join(d, "hotel.conflict.json"), wanConflict{Lease: "192.168.50.23/24", Gateway: "192.168.50.1", Network: "lan", Net: "192.168.50.0/24"})
	writeJSONFile(filepath.Join(d, "wan.conflict.json"), wanConflict{Lease: "192.168.50.9/24", Network: "lan", Net: "192.168.50.0/24"})
	retryConflicts(c) // hotel still collides; wan is PPPoE: nothing to ask for
	if readConflict("hotel") == nil {
		t.Error("conflict dropped while the LAN still overlaps")
	}
	if readConflict("wan") != nil {
		t.Error("conflict of a non-DHCP WAN kept")
	}
	c.LAN.IPv4 = "10.77.0.1/24" // the user moved the LAN
	retryConflicts(c)           // (no /etc/init.d/mr-udhcpc.hotel here: nothing restarted)
	if readConflict("hotel") != nil {
		t.Error("conflict kept after the LAN moved")
	}

	writeJSONFile(filepath.Join(d, "hotel.json"), wanCheck{WAN: "hotel", State: "portal", IP: "10.0.0.23", PortalURL: "http://192.0.2.1/"})
	writeJSONFile(filepath.Join(d, "gone.json"), wanCheck{WAN: "gone", State: "online"})
	if k, _, class := travelStatus("hotel", "10.0.0.23"); k == nil || k.State != "portal" || class != "private" {
		t.Errorf("status for the address the check ran from: %+v %q", k, class)
	}
	if k, _, _ := travelStatus("hotel", "10.0.0.24"); k != nil {
		t.Error("a check from another address is stale")
	}
	if k, _, class := travelStatus("hotel", ""); k != nil || class != "" {
		t.Error("a WAN without an address shows no check")
	}
	dropStaleChecks(c)
	if _, err := os.Stat(filepath.Join(d, "gone.json")); err == nil {
		t.Error("record of a removed WAN kept")
	}
	if readCheck("hotel") == nil {
		t.Error("record of a configured WAN removed")
	}
}

func TestTravelAddrClass(t *testing.T) {
	for ip, want := range map[string]string{"10.1.2.3": "private", "172.16.0.9": "private", "192.168.8.100": "private",
		"100.64.0.1": "cgnat", "100.127.255.254": "cgnat", "100.128.0.1": "", "169.254.10.1": "private",
		"198.51.100.7": "", "203.0.113.11": "", "": "", "2001:db8::1": ""} {
		if got := addrClass(ip); got != want {
			t.Errorf("addrClass(%q) = %q, want %q", ip, got, want)
		}
	}
}

func TestTravelHTTPClock(t *testing.T) {
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	floor := time.Date(2026, 9, 25, 19, 44, 0, 0, time.UTC)
	cases := []struct {
		name   string
		synced bool
		date   time.Time
		want   bool
	}{
		{"days behind, unsynced", false, now.Add(72 * time.Hour), true},
		{"ahead, unsynced", false, now.Add(-10 * time.Minute), true},
		{"within a minute", false, now.Add(59 * time.Second), false},
		{"NTP synced", true, now.Add(72 * time.Hour), false},
		{"before the image build", false, floor.Add(-time.Hour), false},
		{"next century", false, time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC), false},
		{"no Date", false, time.Time{}, false},
	}
	for _, tc := range cases {
		if got := httpClockStep(tc.synced, now, tc.date, floor); got != tc.want {
			t.Errorf("%s: %v", tc.name, got)
		}
	}
}
