package main

import (
	"net/http"
	"strings"
	"testing"
)

// Basic auth: 401 + challenge without / with wrong credentials, 200 with the right ones (then cached);
// the hash in edge.json matches the secret, the password itself is never in it.
func TestEdgeServeAuth(t *testing.T) {
	r := EdgeRoute{Name: "nas", Host: "nas.example.com", Auth: EdgeAuth{User: "alice", Password: "edge_nas"}}
	au := edgeAuthHash(r, "correct horse")
	e := newEdgeServeEnv(t, func(to string) []edgeConfRoute {
		return []edgeConfRoute{{Name: "nas", Host: "nas.example.com", To: to, Cert: "_.example.com", Auth: au}}
	})
	req := func(user, pw string) (int, string) {
		q, _ := http.NewRequest("GET", "https://nas.example.com/", nil)
		if user != "" {
			q.SetBasicAuth(user, pw)
		}
		resp, err := e.client(e.lan, true).Do(q)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode, resp.Header.Get("WWW-Authenticate")
	}
	if st, ch := req("", ""); st != 401 || !strings.HasPrefix(ch, `Basic realm="nas.example.com"`) {
		t.Errorf("no credentials: %d %q", st, ch)
	}
	for _, x := range [][2]string{{"alice", "wrong"}, {"bob", "correct horse"}} {
		if st, _ := req(x[0], x[1]); st != 401 {
			t.Errorf("%v: %d", x, st)
		}
	}
	for i := 0; i < 2; i++ {
		if st, _ := req("alice", "correct horse"); st != 200 {
			t.Errorf("right credentials: %d", st)
		}
	}
	if n := len(e.s.routes["nas.example.com"].authOK); n != 1 {
		t.Errorf("cache: %d entries", n)
	}
}

func TestEdgeAuthConfigAndWANPort(t *testing.T) {
	c := edgeTestConfig(t)
	c.secrets["edge_nas"] = "correct horse"
	c.Services.Edge.Routes[0].Auth = EdgeAuth{User: "alice", Password: "edge_nas"}
	c.Services.Edge.WANPort = 8443
	mustValid(t, c)
	js := renderMap(t, c)[edgeConfFile]
	if !strings.Contains(js, `"hash": "`+edgeAuthHash(c.Services.Edge.Routes[0], "correct horse").Hash) || strings.Contains(js, "correct horse") {
		t.Errorf("edge.json: %s", js)
	}
	if !slicesHas(secretKeys(c), "edge_nas") {
		t.Error("secret not listed")
	}
	nft := renderNft(c, func(string) bool { return true })
	if !strings.Contains(nft, "tcp dport { 443, 8443 } redirect to :44300") {
		t.Error("wan_port redirect missing")
	}
	c.secrets["edge_short"] = "short"
	c.Services.Edge.Routes[1].Auth = EdgeAuth{User: "a:b", Password: "edge_short"}
	c.Services.Edge.WANPort = 22
	errs := strings.Join(c.Validate(), "\n")
	for _, s := range []string{"auth.user: letters", "the password must be 8-128", "wan_port: 22 is used by SSH"} {
		if !strings.Contains(errs, s) {
			t.Errorf("missing %q in\n%s", s, errs)
		}
	}
}
