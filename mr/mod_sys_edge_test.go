package main

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// no test ever starts a background `mr edge renew` (it would run the test binary)
func init() {
	edgeKick = func() {}
	edgeStart = func(string, ...string) {}
}

// edgeTestConfig: the home config with the reverse proxy on — lucky and its firewall.open 443 gone
// (the migration the docs describe), three routes: two under the wildcard certificate, one of its own.
func edgeTestConfig(t *testing.T) *Config {
	t.Helper()
	c := testConfig(t)
	c.secrets["cf_edge"] = cfTestToken
	c.Firewall.Open = nil
	c.Services.Lucky.Enabled = false
	c.Services.Edge = Edge{Enabled: true, Open: true,
		ACME: EdgeACME{Email: "admin@example.com", Token: "cf_edge", Wildcard: []string{"example.com"}},
		Routes: []EdgeRoute{
			{Name: "nas", Host: "nas.example.com", To: "http://192.168.1.10:5000"},
			{Name: "ha", Host: "ha.example.com", To: "http://192.168.1.20:8123", Allow: []string{"lan", "198.51.100.0/24", "2001:db8::7"}},
			{Name: "cam", Host: "cam.home.example.org", To: "https://192.168.1.30", Allow: []string{"lan"}},
			{Name: "old", Enabled: boolp(false), Host: "old.example.net", To: "http://192.168.1.40:80"},
		}}
	c.defaults()
	mustValid(t, c)
	return c
}

// The home config (no services.edge) marshals and renders exactly as before.
func TestEdgeHomeUnchanged(t *testing.T) {
	sysTemp(t)
	c := testConfig(t)
	if y, _ := yaml.Marshal(c); strings.Contains(string(y), "edge") {
		t.Error("an absent services.edge appears in the canonical config (plan / history would show a change)")
	}
	f := renderMap(t, c)
	if _, ok := f[edgeConfFile]; ok {
		t.Error("edge.json rendered without services.edge")
	}
	wantNone(t, "dnsmasq.conf", f["/etc/dnsmasq.conf"], "host-record=")
	wantNone(t, "nft", renderNft(c, allExist), "edge", "44300")
	if strings.Contains(strings.Join(enabledServices(c), " "), "mr-edge") {
		t.Error("mr-edge enabled without services.edge")
	}
	if _, ok := f[cronFile]; ok {
		t.Error("crontab rendered")
	}
	if _, ok := collectStatusKeys(c)["edge"]; ok {
		t.Error("status has an edge key")
	}
}

func collectStatusKeys(c *Config) map[string]any {
	st := map[string]any{}
	for _, m := range modules {
		if m.Name == "sys" {
			m.Status(c, st)
		}
	}
	return st
}

func TestEdgeRender(t *testing.T) {
	sysTemp(t)
	c := edgeTestConfig(t)
	f := renderMap(t, c)
	var ec edgeConf
	if err := json.Unmarshal([]byte(f[edgeConfFile]), &ec); err != nil {
		t.Fatalf("edge.json: %v\n%s", err, f[edgeConfFile])
	}
	want := edgeConf{Port: 443, WANPort: edgeWANPort, Certs: edgeCertDir, Routes: []edgeConfRoute{
		{Name: "nas", Host: "nas.example.com", To: "http://192.168.1.10:5000", Cert: "_.example.com"},
		{Name: "ha", Host: "ha.example.com", To: "http://192.168.1.20:8123", Cert: "_.example.com", Allow: []string{"lan", "198.51.100.0/24", "2001:db8::7/128"}},
		{Name: "cam", Host: "cam.home.example.org", To: "https://192.168.1.30", Cert: "cam.home.example.org", Allow: []string{"lan"}},
	}}
	if got, _ := json.Marshal(ec); string(got) != edgeJSON(want) {
		t.Errorf("edge.json:\n got %s\nwant %s", got, edgeJSON(want))
	}
	if strings.Contains(f[edgeConfFile], cfTestToken) || strings.Contains(f[edgeConfFile], "cf_edge") {
		t.Error("edge.json names the token")
	}
	if sysRestart(edgeConfFile) != "mr-edge" {
		t.Error("a changed edge.json does not restart mr-edge")
	}
	svcs := strings.Join(enabledServices(c), " ")
	if !strings.Contains(svcs, "mr-edge") || !strings.Contains(svcs, "crond") {
		t.Errorf("services: %s", svcs)
	}
	// the daily renewal check: a fixed minute and hour between 02:00 and 05:59
	lines := strings.Split(strings.TrimSpace(f[cronFile]), "\n")
	var job string
	for _, l := range lines {
		if strings.HasSuffix(l, " /usr/sbin/mr edge renew --cron") {
			job = l
		}
	}
	if fs := strings.Fields(job); len(fs) != 9 || fs[2] != "*" || fs[3] != "*" || fs[4] != "*" || atoi(fs[1]) < 2 || atoi(fs[1]) > 5 || atoi(fs[0]) > 59 {
		t.Errorf("crontab:\n%s", f[cronFile])
	}
	if _, err := checkCron(strings.Join(strings.Fields(job)[:5], " "), "restart"); err != nil {
		t.Errorf("cron spec %q: %v", job, err)
	}
	// firewall: the WANs' port 443 on the router's own addresses → the WAN listener, accepted there only
	nft := renderNft(c, allExist)
	wantSubs(t, "nft", nft,
		`iifname { "pppoe-wan", "pppoe-wan2" } tcp dport 44300 ct status dnat accept comment "edge"`,
		`iifname { "pppoe-wan", "pppoe-wan2" } fib daddr type local tcp dport 443 redirect to :44300 comment "edge"`)
	// dnsmasq: route hosts → the main LAN address (enabled routes only)
	dm := f["/etc/dnsmasq.conf"]
	wantSubs(t, "dnsmasq.conf", dm, "host-record=nas.example.com,192.168.1.6\n", "host-record=ha.example.com,192.168.1.6\n", "host-record=cam.home.example.org,192.168.1.6\n")
	wantNone(t, "dnsmasq.conf", dm, "old.example.net")

	// not open: nothing in the firewall; lan_dns off: nothing in dnsmasq
	c.Services.Edge.Open = false
	c.Services.Edge.LANDNS = boolp(false)
	wantNone(t, "nft (not open)", renderNft(c, allExist), "edge", "44300")
	wantNone(t, "dnsmasq (lan_dns off)", renderMap(t, c)["/etc/dnsmasq.conf"], "host-record=")
	if strings.Contains(renderMap(t, c)[edgeConfFile], "wan_port") {
		t.Error("edge.json has a WAN port while not open")
	}
	// off: no file, no service, no cron line
	c.Services.Edge.Enabled = false
	f = renderMap(t, c)
	if _, ok := f[edgeConfFile]; ok || strings.Contains(strings.Join(enabledServices(c), " "), "mr-edge") || strings.Contains(f[cronFile], "edge") {
		t.Error("disabled edge still rendered / enabled / scheduled")
	}
}

func edgeJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func TestEdgeCertFor(t *testing.T) {
	a := EdgeACME{Wildcard: []string{"example.com", "lab.example.org"}}
	for host, want := range map[string]string{
		"example.com":         "_.example.com",
		"nas.example.com":     "_.example.com",
		"a.nas.example.com":   "a.nas.example.com", // two labels below: not covered by *.example.com
		"nas.lab.example.org": "_.lab.example.org",
		"example.org":         "example.org",
		"nas.example.net":     "nas.example.net",
		"notexample.com":      "notexample.com",
	} {
		if got := edgeCertFor(a, host).Name; got != want {
			t.Errorf("%s: %s, want %s", host, got, want)
		}
	}
	if d := edgeCertFor(a, "nas.example.com").Domains; strings.Join(d, ",") != "example.com,*.example.com" {
		t.Errorf("wildcard domains: %v", d)
	}
	c := edgeTestConfig(t)
	var names []string
	for _, ct := range edgeCerts(c) {
		names = append(names, ct.Name)
	}
	if strings.Join(names, " ") != "_.example.com cam.home.example.org" {
		t.Errorf("certificates: %v", names)
	}
}

func TestEdgeValidate(t *testing.T) {
	c := edgeTestConfig(t)
	c.secrets["cf_bad"] = "has spaces in it, not a token"
	e := &c.Services.Edge
	e.Port = 22
	e.ACME = EdgeACME{Provider: "route53", Token: "cf_bad", Email: "not an address", Wildcard: []string{"*.example.com", "Example.com"}}
	e.Routes = []EdgeRoute{
		{Name: "ok", Host: "ok.example.com", To: "http://192.168.1.10:5000", Allow: []string{"lan", "203.0.113.0/24"}},
		{Name: "ok", Host: "dup-name.example.com", To: "http://192.168.1.10:5000"},
		{Name: "a", Host: "ok.example.com", To: "http://192.168.1.10:5000"},
		{Name: "b", Host: "*.example.com", To: "http://192.168.1.10:5000"},
		{Name: "c", Host: "Upper.example.com", To: "http://192.168.1.10:5000"},
		{Name: "d", Host: "single", To: "http://192.168.1.10:5000"},
		{Name: "e", Host: "nl.example.com\nx", To: "http://192.168.1.10:5000"},
		{Name: "f", Host: "f.example.com", To: "ftp://192.168.1.10"},
		{Name: "g", Host: "g.example.com", To: "http://nas.lan:5000"},
		{Name: "h", Host: "h.example.com", To: "http://203.0.113.9:80"},
		{Name: "i", Host: "i.example.com", To: "http://192.168.1.10:5000/admin"},
		{Name: "j", Host: "j.example.com", To: "http://user:pw@192.168.1.10:5000"},
		{Name: "k", Host: "k.example.com", To: "http://192.168.1.10:99999"},
		{Name: "l", Host: "l.example.com", To: "http://[2001:db8::10]:80"},
		{Name: "m", Host: "m.example.com", To: "http://127.0.0.1:8080", Allow: []string{"everyone"}},
		{Name: "n", Host: "n.example.com", To: "http://192.168.1.6:44300"},
		{Name: "o", Host: "o.example.com", To: "http://[fd00::10]:8080", Allow: []string{"10.0.0.0/33"}},
		{Name: "p", Host: "p.example.com", To: "http://100.101.102.103:8080", Desc: "tailnet\npeer"},
	}
	errs := strings.Join(c.Validate(), "\n")
	for _, s := range []string{
		"services.edge.port: 22 is used by SSH",
		`services.edge.acme.provider: cloudflare, got "route53"`,
		"services.edge.acme.email",
		"services.edge.acme.token_secret: the secret is not an API token",
		`services.edge.acme.wildcard: a lower-case domain like example.com, got "*.example.com"`,
		`services.edge.acme.wildcard: a lower-case domain like example.com, got "Example.com"`,
		`routes[ok].name: duplicate "ok"`,
		`routes[a].host: duplicate "ok.example.com"`,
		`routes[b].host: a lower-case host name`, `routes[c].host`, `routes[d].host`, `routes[e].host`,
		"routes[f].to: http://IP:port", "routes[g].to: http://IP:port or https://IP:port (the host must be an IP address)",
		"routes[h].to: 203.0.113.9 is not the router", "routes[i].to", "routes[j].to", "routes[k].to",
		"routes[l].to: 2001:db8::10 is not the router", `routes[m].allow: lan or an address / CIDR, got "everyone"`,
		"routes[n].to: the proxy itself", `routes[o].allow: lan or an address / CIDR, got "10.0.0.0/33"`, "routes[p].desc",
	} {
		if !strings.Contains(errs, s) {
			t.Errorf("want error %q in:\n%s", s, errs)
		}
	}
	for _, s := range []string{"routes[0]", "routes[o].to", "routes[p].to", "routes[m].to"} {
		if strings.Contains(errs, s) {
			t.Errorf("valid part rejected (%s):\n%s", s, errs)
		}
	}
	if strings.Contains(errs, cfTestToken) {
		t.Error("a validation message shows the token")
	}

	// enabled without routes, without a token
	c = edgeTestConfig(t)
	c.Services.Edge.Routes = []EdgeRoute{{Name: "x", Enabled: boolp(false), Host: "x.example.com", To: "http://192.168.1.10"}}
	c.Services.Edge.ACME.Token = ""
	wantErrs(t, c, "services.edge: enabled without routes", "services.edge.acme.token_secret: secret name")
	c.Services.Edge.ACME.Token = "cf_missing"
	wantErrs(t, c, `services.edge.acme.token_secret: secret "cf_missing" missing`)

	// firewall.open of the same port: WAN connections would reach the LAN listener
	c = edgeTestConfig(t)
	c.Firewall.Open = []Open{{Name: "lucky-https", Enabled: boolp(true), Proto: []string{"tcp"}, Port: "443"}}
	wantErrs(t, c, "services.edge: firewall.open[lucky-https] opens tcp 443 to the WAN")
	c.Firewall.Open = []Open{{Name: "range", Enabled: boolp(true), Proto: []string{"tcp"}, Port: "400-500"}}
	wantErrs(t, c, "firewall.open[range] opens tcp 443")
	c.Firewall.Open = []Open{{Name: "quic", Enabled: boolp(true), Proto: []string{"udp"}, Port: "443"}}
	mustValid(t, c)
	c.Services.Edge.Port = 8443 // the home config's lucky-https (tcp 443) can stay while the proxy uses another port
	c.Firewall.Open = []Open{{Name: "lucky-https", Enabled: boolp(true), Proto: []string{"tcp"}, Port: "443"}}
	mustValid(t, c)
	c.Services.Edge.Port = 443
	c.Firewall.Open = nil
	c.Firewall.Forwards = append(c.Firewall.Forwards, Forward{Name: "nas-https", Enabled: boolp(true), Proto: []string{"tcp"}, Port: "443", To: "192.168.1.10"})
	wantErrs(t, c, "services.edge.open: firewall.forwards[nas-https] already forwards tcp 443")
	c.Services.Edge.Open = false
	mustValid(t, c)

	// lucky's web UI port while lucky runs
	c = edgeTestConfig(t)
	c.Services.Lucky.Enabled = true
	c.Services.Edge.Port = c.Services.Lucky.Port
	wantErrs(t, c, "services.edge.port: 16601 is used by lucky's web UI")
}

// guard.never_expose: a route the WAN can use may not lead to the router's own SSH / web UI / DNS.
func TestEdgeGuard(t *testing.T) {
	c := edgeTestConfig(t)
	c.Guard.NeverExpose = []string{"ssh", "panel", "dns"}
	c.Services.Edge.Routes = append(c.Services.Edge.Routes, EdgeRoute{Name: "panel", Host: "router.example.com", To: "http://192.168.1.6:80"})
	wantErrs(t, c, "guard.never_expose: services.edge.routes[panel] makes the router's port 80 (panel) reachable from the WAN")
	c.Services.Edge.Routes[len(c.Services.Edge.Routes)-1].To = "http://127.0.0.1:22"
	wantErrs(t, c, "routes[panel] makes the router's port 22 (ssh)")
	c.Services.Edge.Routes[len(c.Services.Edge.Routes)-1].Allow = []string{"lan", "203.0.113.0/24"}
	wantErrs(t, c, "routes[panel] makes the router's port 22 (ssh)")
	c.Services.Edge.Routes[len(c.Services.Edge.Routes)-1].Allow = []string{"lan"} // LAN only: fine
	mustValid(t, c)
	c.Services.Edge.Routes[len(c.Services.Edge.Routes)-1].Allow = nil
	c.Services.Edge.Open = false // not reachable from the WAN at all
	mustValid(t, c)
	c.Services.Edge.Open = true
	c.Services.Edge.Routes[len(c.Services.Edge.Routes)-1].To = "http://192.168.1.6:16601" // lucky's UI: not guarded
	mustValid(t, c)
}

// A token may change routes, but not the ACME section (it references the API token); a change of
// services.edge is a high-risk change; the web UI learns the token's name, never its value.
func TestEdgeTokenAndRisk(t *testing.T) {
	base := edgeTestConfig(t)
	c := edgeTestConfig(t)
	c.Services.Edge.ACME.Email = "attacker@example.net"
	if got := strings.Join(lockedChanges(base, c), ","); !strings.Contains(got, "services.edge.acme") || !strings.Contains(got, "references a secret") {
		t.Errorf("ACME section not locked for tokens: %q", got)
	}
	c = edgeTestConfig(t)
	c.Services.Edge.Routes[0].To = "http://192.168.1.11:5000"
	if got := lockedChanges(base, c); len(got) > 0 {
		t.Errorf("route change locked: %v", got)
	}
	if r := classifyRisk(&Plan{}, []string{"~ services.edge.routes[nas].to: http://192.168.1.10:5000 → http://192.168.1.11:5000"}, adminPath{}); r.Level != "high" {
		t.Errorf("risk of an edge change: %+v", r)
	}
	if k := strings.Join(secretKeys(base), " "); !strings.Contains(k, "cf_edge") {
		t.Errorf("secretKeys lacks the ACME token name: %s", k)
	}
	if tokenActions["sys.edge"] != "read" || tokenActions["sys.edgerenew"] != "" {
		t.Error("token scopes: sys.edge must be read-only, sys.edgerenew session-only")
	}
}

func TestEdgeTarget(t *testing.T) {
	for in, want := range map[string]string{
		"http://192.168.1.10":        "http 192.168.1.10 80",
		"https://192.168.1.10":       "https 192.168.1.10 443",
		"http://192.168.1.10:5000/":  "http 192.168.1.10 5000",
		"https://[fd00::1]:8443":     "https fd00::1 8443",
		"http://192.168.1.10:05000":  "error",
		"http://192.168.1.10:0":      "error",
		"http://192.168.1.10?x=1":    "error",
		"http://192.168.1.10#f":      "error",
		"http://[fe80::1%25br-lan]/": "error",
		"http://[::ffff:1.2.3.4]/":   "error",
		"//192.168.1.10":             "error",
		"http:192.168.1.10":          "error",
	} {
		s, ip, port, err := edgeTarget(in)
		got := "error"
		if err == nil {
			got = s + " " + ip.String() + " " + strconv.Itoa(port)
		}
		if got != want {
			t.Errorf("%s: %s, want %s", in, got, want)
		}
	}
}
