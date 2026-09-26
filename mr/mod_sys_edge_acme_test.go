package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// ---- a test CA ----

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newTestCA(t *testing.T, cn string) *testCA {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn}, IsCA: true, BasicConstraintsValid: true,
		NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: time.Now().Add(3650 * 24 * time.Hour), KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &testCA{cert: c, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// sign issues a leaf for pub; with key != nil it returns chain + key PEM (a .pem file as renew writes it).
func (ca *testCA) sign(t *testing.T, pub *ecdsa.PublicKey, key *ecdsa.PrivateKey, names []string, nb, na time.Time) []byte {
	t.Helper()
	if pub == nil {
		key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		pub = &key.PublicKey
	}
	sn, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tpl := &x509.Certificate{SerialNumber: sn, Subject: pkix.Name{CommonName: names[0]}, DNSNames: names, NotBefore: nb, NotAfter: na,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.cert, pub, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	out := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), ca.pem...)
	if key != nil {
		kd, _ := x509.MarshalECPrivateKey(key)
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd})...)
	}
	return out
}

// ---- an in-process ACME server ----

// acmeStub is a small RFC 8555 server: directory, nonces, accounts, orders, authorizations with dns-01
// challenges checked against a TXT lookup, finalize (the CSR's names and signature checked), the order
// "processing" for one poll, the chain signed by a test CA. Every JWS is verified: ES256 over
// protected.payload, a nonce it issued and never saw before, url = the request URL, jwk only for
// newAccount and a known kid for everything else.
type acmeStub struct {
	t        *testing.T
	srv      *httptest.Server
	mu       sync.Mutex
	seq      int
	nonces   map[string]bool
	accounts map[string]*ecdsa.PublicKey
	orders   []*stubOrder
	authzs   []*stubAuthz
	ca       *testCA
	txt      func(name string) []string
	life     time.Duration
	calls    []string
	badNonce int  // refuse this many requests with badNonce first
	refuse   bool // every challenge fails
}

type stubOrder struct {
	ids    []string
	authz  []int
	status string // pending | processing | valid | invalid
	cert   []byte
}

type stubAuthz struct {
	id, token, status, acct string
	wildcard                bool
}

func newACMEStub(t *testing.T, txt func(string) []string) *acmeStub {
	s := &acmeStub{t: t, nonces: map[string]bool{}, accounts: map[string]*ecdsa.PublicKey{}, ca: newTestCA(t, "mini-router test CA"),
		txt: txt, life: 90 * 24 * time.Hour}
	s.srv = httptest.NewServer(s)
	t.Cleanup(s.srv.Close)
	return s
}

func (s *acmeStub) take() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.calls
	s.calls = nil
	return c
}

func (s *acmeStub) problem(w http.ResponseWriter, status int, typ, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{"type": "urn:ietf:params:acme:error:" + typ, "detail": detail, "status": status})
}

func stubKey(j map[string]string) *ecdsa.PublicKey {
	x, e1 := base64.RawURLEncoding.DecodeString(j["x"])
	y, e2 := base64.RawURLEncoding.DecodeString(j["y"])
	if e1 != nil || e2 != nil || j["kty"] != "EC" || j["crv"] != "P-256" || len(x) != 32 || len(y) != 32 {
		return nil
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
}

func stubThumb(k *ecdsa.PublicKey) string {
	x, y := make([]byte, 32), make([]byte, 32)
	k.X.FillBytes(x)
	k.Y.FillBytes(y)
	h := sha256.Sum256([]byte(`{"crv":"P-256","kty":"EC","x":"` + b64u(x) + `","y":"` + b64u(y) + `"}`))
	return b64u(h[:])
}

// verify checks a JWS request; it returns the payload (nil for POST-as-GET) and the account (kid).
func (s *acmeStub) verify(r *http.Request) (payload []byte, kid string, key *ecdsa.PublicKey, typ, err string) {
	var j struct{ Protected, Payload, Signature string }
	if r.Header.Get("Content-Type") != "application/jose+json" || json.NewDecoder(r.Body).Decode(&j) != nil {
		return nil, "", nil, "malformed", "not a JWS"
	}
	pb, e := base64.RawURLEncoding.DecodeString(j.Protected)
	var h struct {
		Alg, Nonce, URL, Kid string
		JWK                  map[string]string
	}
	if e != nil || json.Unmarshal(pb, &h) != nil || h.Alg != "ES256" {
		return nil, "", nil, "malformed", "bad protected header"
	}
	if h.URL != s.srv.URL+r.URL.Path {
		return nil, "", nil, "unauthorized", "url " + h.URL + " is not " + r.URL.Path
	}
	if !s.nonces[h.Nonce] {
		return nil, "", nil, "badNonce", "unknown or reused nonce"
	}
	delete(s.nonces, h.Nonce)
	if s.badNonce > 0 {
		s.badNonce--
		return nil, "", nil, "badNonce", "try again"
	}
	if (h.JWK == nil) == (h.Kid == "") {
		return nil, "", nil, "malformed", "exactly one of jwk and kid"
	}
	if h.JWK != nil {
		if r.URL.Path != "/new-acct" {
			return nil, "", nil, "malformed", "jwk only for newAccount"
		}
		key = stubKey(h.JWK)
	} else {
		key, kid = s.accounts[h.Kid], h.Kid
	}
	if key == nil {
		return nil, "", nil, "accountDoesNotExist", "no such account"
	}
	sig, e := base64.RawURLEncoding.DecodeString(j.Signature)
	sum := sha256.Sum256([]byte(j.Protected + "." + j.Payload))
	if e != nil || len(sig) != 64 || !ecdsa.Verify(key, sum[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		return nil, "", nil, "malformed", "bad signature"
	}
	if j.Payload != "" {
		payload, _ = base64.RawURLEncoding.DecodeString(j.Payload)
	}
	return payload, kid, key, "", ""
}

func (s *acmeStub) orderJSON(i int) map[string]any {
	o := s.orders[i]
	var az []string
	ready := true
	for _, a := range o.authz {
		az = append(az, fmt.Sprintf("%s/authz/%d", s.srv.URL, a))
		ready = ready && s.authzs[a].status == "valid"
	}
	status := o.status
	if status == "pending" && ready {
		status = "ready"
	}
	var ids []map[string]string
	for _, d := range o.ids {
		ids = append(ids, map[string]string{"type": "dns", "value": d})
	}
	m := map[string]any{"status": status, "identifiers": ids, "authorizations": az, "finalize": fmt.Sprintf("%s/finalize/%d", s.srv.URL, i)}
	if status == "valid" {
		m["certificate"] = fmt.Sprintf("%s/cert/%d", s.srv.URL, i)
	}
	return m
}

func (s *acmeStub) authzJSON(i int) map[string]any {
	a := s.authzs[i]
	ch := map[string]any{"type": "dns-01", "url": fmt.Sprintf("%s/chal/%d", s.srv.URL, i), "token": a.token, "status": a.status}
	if a.status == "invalid" {
		ch["error"] = map[string]any{"type": "urn:ietf:params:acme:error:unauthorized", "detail": "no TXT record with the key authorization"}
	}
	return map[string]any{"status": a.status, "identifier": map[string]string{"type": "dns", "value": a.id}, "wildcard": a.wildcard,
		"challenges": []any{map[string]any{"type": "http-01", "url": s.srv.URL + "/chal/http", "token": "x"}, ch}}
}

func (s *acmeStub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, r.Method+" "+r.URL.Path)
	s.seq++
	n := fmt.Sprintf("nonce-%d-%d", s.seq, time.Now().UnixNano())
	s.nonces[n] = true
	w.Header().Set("Replay-Nonce", n)
	u := s.srv.URL
	answer := func(status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(v)
	}
	switch {
	case r.URL.Path == "/dir" && r.Method == "GET":
		answer(200, map[string]any{"newNonce": u + "/new-nonce", "newAccount": u + "/new-acct", "newOrder": u + "/new-order", "meta": map[string]any{"termsOfService": u + "/tos"}})
		return
	case r.URL.Path == "/new-nonce":
		w.WriteHeader(200)
		return
	case r.Method != "POST":
		s.problem(w, 405, "malformed", "POST only")
		return
	}
	payload, kid, key, typ, why := s.verify(r)
	if typ != "" {
		s.problem(w, 400, typ, why)
		return
	}
	var idx int
	switch {
	case r.URL.Path == "/new-acct":
		var p struct {
			TOS     bool     `json:"termsOfServiceAgreed"`
			Contact []string `json:"contact"`
		}
		if json.Unmarshal(payload, &p) != nil || !p.TOS {
			s.problem(w, 400, "malformed", "terms not agreed")
			return
		}
		kid := u + "/acct/" + stubThumb(key)[:12]
		status := 200
		if s.accounts[kid] == nil {
			status = 201
		}
		s.accounts[kid] = key
		w.Header().Set("Location", kid)
		answer(status, map[string]any{"status": "valid", "contact": p.Contact})
	case r.URL.Path == "/new-order":
		var p struct {
			Identifiers []struct{ Type, Value string }
		}
		if json.Unmarshal(payload, &p) != nil || len(p.Identifiers) == 0 {
			s.problem(w, 400, "malformed", "no identifiers")
			return
		}
		o := &stubOrder{status: "pending"}
		for _, id := range p.Identifiers {
			if id.Type != "dns" {
				s.problem(w, 400, "rejectedIdentifier", id.Type)
				return
			}
			o.ids = append(o.ids, id.Value)
			tok := make([]byte, 24)
			rand.Read(tok)
			s.authzs = append(s.authzs, &stubAuthz{id: strings.TrimPrefix(id.Value, "*."), wildcard: strings.HasPrefix(id.Value, "*."),
				token: b64u(tok), status: "pending", acct: kid})
			o.authz = append(o.authz, len(s.authzs)-1)
		}
		s.orders = append(s.orders, o)
		w.Header().Set("Location", fmt.Sprintf("%s/order/%d", u, len(s.orders)-1))
		answer(201, s.orderJSON(len(s.orders)-1))
	case sscan(r.URL.Path, "/authz/%d", &idx) && idx < len(s.authzs):
		if payload != nil {
			s.problem(w, 400, "malformed", "POST-as-GET expected")
			return
		}
		answer(200, s.authzJSON(idx))
	case sscan(r.URL.Path, "/chal/%d", &idx) && idx < len(s.authzs):
		if string(payload) != "{}" {
			s.problem(w, 400, "malformed", "challenge response must be {}")
			return
		}
		a := s.authzs[idx]
		sum := sha256.Sum256([]byte(a.token + "." + stubThumb(s.accounts[a.acct])))
		if !s.refuse && slicesHas(s.txt("_acme-challenge."+a.id), b64u(sum[:])) {
			a.status = "valid"
		} else {
			a.status = "invalid"
		}
		answer(200, map[string]any{"type": "dns-01", "status": "processing", "token": a.token})
	case sscan(r.URL.Path, "/finalize/%d", &idx) && idx < len(s.orders):
		if s.orderJSON(idx)["status"] != "ready" {
			s.problem(w, 403, "orderNotReady", "authorizations not valid")
			return
		}
		var p struct{ CSR string }
		json.Unmarshal(payload, &p)
		der, _ := base64.RawURLEncoding.DecodeString(p.CSR)
		csr, err := x509.ParseCertificateRequest(der)
		if err != nil || csr.CheckSignature() != nil || !sameSet(csr.DNSNames, s.orders[idx].ids) {
			s.problem(w, 400, "badCSR", "CSR names or signature")
			return
		}
		pub, _ := csr.PublicKey.(*ecdsa.PublicKey)
		s.orders[idx].cert = s.ca.sign(s.t, pub, nil, csr.DNSNames, time.Now().Add(-time.Hour), time.Now().Add(s.life))
		s.orders[idx].status = "processing"
		answer(200, s.orderJSON(idx))
	case sscan(r.URL.Path, "/order/%d", &idx) && idx < len(s.orders):
		o := s.orders[idx]
		m := s.orderJSON(idx)
		if o.status == "processing" {
			o.status = "valid" // one poll sees processing
		}
		answer(200, m)
	case sscan(r.URL.Path, "/cert/%d", &idx) && idx < len(s.orders) && s.orders[idx].status == "valid":
		if r.Header.Get("Accept") != "application/pem-certificate-chain" {
			s.problem(w, 406, "malformed", "accept")
			return
		}
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		w.Write(s.orders[idx].cert)
	default:
		s.problem(w, 404, "malformed", "no such resource "+r.URL.Path)
	}
}

func sscan(s, format string, n *int) bool {
	_, err := fmt.Sscanf(s, format, n)
	return err == nil && fmt.Sprintf(format, *n) == s
}

// ---- the environment ----

type edgeTestEnv struct {
	c       *Config
	acme    *acmeStub
	cf      *fakeCF
	events  *[]string
	signals *int
	dir     string
}

// edgeEnv: the edge test config, a fake Cloudflare (zone example.com only), the ACME stub validating
// against the fake's TXT records, every path in a temp dir, no processes, no events on disk.
func edgeEnv(t *testing.T) *edgeTestEnv {
	t.Helper()
	d := t.TempDir()
	f := &fakeCF{}
	cf := httptest.NewServer(http.HandlerFunc(f.handler))
	t.Cleanup(cf.Close)
	txt := func(name string) []string {
		f.mu.Lock()
		defer f.mu.Unlock()
		var out []string
		for _, x := range f.recs {
			if x["type"] == "TXT" && x["name"] == name {
				out = append(out, fmt.Sprint(x["content"]))
			}
		}
		return out
	}
	stub := newACMEStub(t, txt)
	events, signals := []string{}, 0
	o1, o2, o3, o4, o5, o6 := edgeCertDir, edgeAcctDir, edgeStateFile, edgeLockFile, edgeRunDir, edgeDirectory
	o7, o8, o9, o10, o11, o12, o13 := cfAPIBase, edgeTXTVisible, edgeEvent, edgeSignal, edgeServiceUser, acmePoll, edgeTXTWait
	t.Cleanup(func() {
		edgeCertDir, edgeAcctDir, edgeStateFile, edgeLockFile, edgeRunDir, edgeDirectory = o1, o2, o3, o4, o5, o6
		cfAPIBase, edgeTXTVisible, edgeEvent, edgeSignal, edgeServiceUser, acmePoll, edgeTXTWait = o7, o8, o9, o10, o11, o12, o13
	})
	edgeCertDir, edgeAcctDir = filepath.Join(d, "state", "edge"), filepath.Join(d, "state", "acme")
	edgeStateFile, edgeLockFile, edgeRunDir = filepath.Join(d, "run", "edge-renew.json"), filepath.Join(d, "run", "edge-renew.lock"), filepath.Join(d, "run", "mr-edge")
	edgeDirectory = func(bool) string { return stub.srv.URL + "/dir" }
	cfAPIBase = cf.URL + "/client/v4"
	edgeTXTVisible = func(_ context.Context, name, value string) (bool, error) { return slicesHas(txt(name), value), nil }
	edgeEvent = func(_ *Config, sev, key, msg string) { events = append(events, sev+" "+key+": "+msg) }
	edgeSignal = func() { signals++ }
	edgeServiceUser = func() (int, int) { return -1, -1 }
	acmePoll, edgeTXTWait = time.Millisecond, 50*time.Millisecond
	c := edgeTestConfig(t)
	return &edgeTestEnv{c: c, acme: stub, cf: f, events: &events, signals: &signals, dir: d}
}

func TestEdgeACMEIssue(t *testing.T) {
	e := edgeEnv(t)
	certs, err := edgeRenew(e.c, edgeRenewOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 2 || certs[0].Name != "_.example.com" || certs[0].State != "ok" || certs[0].Error != "" || certs[0].LastOK == 0 {
		t.Fatalf("wildcard certificate: %+v", certs)
	}
	if left := time.Until(time.Unix(certs[0].NotAfter, 0)); left < 89*24*time.Hour || left > 91*24*time.Hour {
		t.Errorf("not_after %v from now", left)
	}
	// the zone of cam.home.example.org is not in this Cloudflare account: that one fails, visibly
	if certs[1].Name != "cam.home.example.org" || certs[1].State != "missing" || !strings.Contains(certs[1].Error, "Cloudflare: no zone for cam.home.example.org") || certs[1].Retry == 0 {
		t.Errorf("certificate without a zone: %+v", certs[1])
	}
	// the file: chain + key, 0600, loads as a TLS pair, the wildcard names
	p := edgeCertPath("_.example.com")
	fi, err := os.Stat(p)
	if err != nil || fi.Mode().Perm() != 0600 {
		t.Fatalf("%s: %v %v", p, err, fi.Mode())
	}
	data, _ := os.ReadFile(p)
	pair, err := tls.X509KeyPair(data, data)
	if err != nil || !sameSet(pair.Leaf.DNSNames, []string{"example.com", "*.example.com"}) {
		t.Fatalf("pem: %v %v", err, pair.Leaf)
	}
	if n := strings.Count(string(data), "BEGIN CERTIFICATE"); n != 2 {
		t.Errorf("chain has %d certificates, want leaf + CA", n)
	}
	if fi, _ := os.Stat(edgeCertDir); fi.Mode().Perm() != 0700 {
		t.Errorf("cert dir mode %v", fi.Mode())
	}
	ents, _ := os.ReadDir(edgeAcctDir)
	if len(ents) != 1 {
		t.Fatalf("account keys: %v", ents)
	}
	if fi, _ := os.Stat(filepath.Join(edgeAcctDir, ents[0].Name())); fi.Mode().Perm() != 0600 {
		t.Errorf("account key mode %v", fi.Mode())
	}
	if fi, _ := os.Stat(edgeAcctDir); fi.Mode().Perm() != 0700 {
		t.Errorf("account dir mode %v", fi.Mode())
	}
	// DNS-01 through Cloudflare: two TXT records (example.com, *.example.com), both deleted again
	calls := strings.Join(e.cf.take(), "\n")
	if strings.Count(calls, "POST /zones/"+cfTestZone+"/dns_records") != 2 || strings.Count(calls, "DELETE /zones/"+cfTestZone+"/dns_records/") != 2 {
		t.Errorf("Cloudflare calls:\n%s", calls)
	}
	if len(e.cf.recs) != 0 {
		t.Errorf("TXT records left behind: %v", e.cf.recs)
	}
	if len(e.cf.bodies) < 1 || e.cf.bodies[0]["type"] != "TXT" || e.cf.bodies[0]["name"] != "_acme-challenge.example.com" {
		t.Errorf("TXT record body: %v", e.cf.bodies)
	}
	if *e.signals != 1 {
		t.Errorf("serve signalled %d times", *e.signals)
	}
	ev := strings.Join(*e.events, "\n")
	if !strings.Contains(ev, "info _.example.com: certificate example.com, *.example.com issued, valid until ") || !strings.Contains(ev, "warn cam.home.example.org: certificate cam.home.example.org not issued: Cloudflare: no zone") {
		t.Errorf("events:\n%s", ev)
	}
	// nothing secret in the state, the status, the API answer or the events
	st, _ := json.Marshal(edgeStatus(e.c))
	for what, s := range map[string]string{"state": readFile(edgeStateFile), "status": string(st), "events": ev} {
		for _, bad := range []string{cfTestToken, "PRIVATE KEY", "BEGIN", "cf_edge"} {
			if strings.Contains(s, bad) {
				t.Errorf("%s contains %q", what, bad)
			}
		}
	}
	if r := apiSysEdgeRenew(apiReq{method: "GET"}); r.status != 405 {
		t.Errorf("sys.edgerenew via GET: %d", r.status)
	}

	// a second automatic run: nothing is due, the failed one waits for its backoff — no request at all
	e.acme.take()
	if _, err := edgeRenew(e.c, edgeRenewOpts{auto: true}); err != nil {
		t.Fatal(err)
	}
	if c := e.acme.take(); len(c) > 0 {
		t.Errorf("ACME requests although nothing is due: %v", c)
	}
	if c := e.cf.take(); len(c) > 0 {
		t.Errorf("Cloudflare requests although nothing is due: %v", c)
	}
	// manual: the failed one is tried again at once (and fails again: no new event for the same error)
	n := len(*e.events)
	certs, _ = edgeRenew(e.c, edgeRenewOpts{names: []string{"cam.home.example.org"}})
	if len(e.cf.take()) == 0 || certs[1].Error == "" || len(*e.events) != n {
		t.Errorf("manual retry: %+v, events %v", certs[1], *e.events)
	}
	// forced: a certificate that is not due is issued again, with a new key
	old := data
	if _, err := edgeRenew(e.c, edgeRenewOpts{force: true, names: []string{"_.example.com"}}); err != nil {
		t.Fatal(err)
	}
	if now, _ := os.ReadFile(p); string(now) == string(old) {
		t.Error("forced renewal did not replace the certificate")
	}
	// the account is reused: one newAccount answer "200 existing" per run, never a second key
	if ents, _ := os.ReadDir(edgeAcctDir); len(ents) != 1 {
		t.Errorf("account keys after 3 runs: %v", ents)
	}
	// a route removed: its certificate goes too
	e.c.Services.Edge.Routes = e.c.Services.Edge.Routes[2:3] // cam only
	edgeRenew(e.c, edgeRenewOpts{auto: true})
	if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("certificate of removed routes kept: %v", err)
	}
}

// A refused validation: the error names the domain, the TXT records are deleted anyway, the
// automatic retries back off 1 h, 2 h, …; a bad nonce is retried transparently.
func TestEdgeACMEFailures(t *testing.T) {
	e := edgeEnv(t)
	e.c.Services.Edge.Routes = e.c.Services.Edge.Routes[:1] // nas → *.example.com
	e.acme.refuse = true
	certs, _ := edgeRenew(e.c, edgeRenewOpts{})
	if !strings.Contains(certs[0].Error, "ACME: validation of example.com failed: no TXT record with the key authorization") {
		t.Fatalf("refused validation: %+v", certs[0])
	}
	if len(e.cf.recs) != 0 {
		t.Errorf("TXT records left after a failure: %v", e.cf.recs)
	}
	st := edgeLoadState()["_.example.com"]
	if st == nil || st.Fails != 1 || st.Retry-st.ErrorAt != 3600 {
		t.Fatalf("backoff after one failure: %+v", st)
	}
	e.acme.take()
	edgeRenew(e.c, edgeRenewOpts{auto: true})
	if c := e.acme.take(); len(c) > 0 {
		t.Errorf("automatic run inside the backoff made requests: %v", c)
	}
	edgeRenew(e.c, edgeRenewOpts{}) // manual: at once
	if st := edgeLoadState()["_.example.com"]; st.Fails != 2 || st.Retry-st.ErrorAt != 7200 {
		t.Errorf("backoff after two failures: %+v", st)
	}
	if *e.signals != 0 {
		t.Error("serve signalled without a new certificate")
	}
	// a stale nonce once, then success; the state starts clean again
	e.acme.refuse, e.acme.badNonce = false, 1
	certs, _ = edgeRenew(e.c, edgeRenewOpts{})
	if certs[0].State != "ok" || certs[0].Error != "" || certs[0].Retry != 0 {
		t.Errorf("after badNonce: %+v", certs[0])
	}
	// a changed token starts the state afresh
	e.c.secrets["cf_edge"] = cfTestToken + "x"
	if s := edgeStatusCerts(e.c, edgeLoadState()); s[0].LastOK != 0 {
		t.Errorf("state kept across a token change: %+v", s[0])
	}
}

// Renewal timing: a third of the lifetime left (30 of 90 days), expiry, other names, other CA.
func TestEdgeDue(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	ct := edgeCert{Name: "nas.example.com", Domains: []string{"nas.example.com"}}
	info := func(from, to time.Duration, names ...string) *edgeCertInfo {
		if len(names) == 0 {
			names = ct.Domains
		}
		return &edgeCertInfo{Domains: names, NotBefore: now.Add(from), NotAfter: now.Add(to)}
	}
	day := 24 * time.Hour
	for _, x := range []struct {
		i    *edgeCertInfo
		stg  bool
		want string
	}{
		{nil, false, "missing"},
		{info(-10*day, 80*day), false, "ok"},
		{info(-59*day, 31*day), false, "ok"},
		{info(-61*day, 29*day), false, "due"},
		{info(-90*day, 0), false, "expired"},
		{info(-4*day, 2*day), false, "ok"}, // a 6-day certificate: due below 2 days
		{info(-5*day, 1*day), false, "due"},
		{info(-10*day, 80*day, "nas.example.com", "old.example.com"), false, "names changed"},
		{info(-10*day, 80*day), true, "other CA"},
	} {
		due, why := edgeDue(ct, x.i, x.stg, now)
		if why != x.want || due != (x.want != "ok") {
			t.Errorf("%+v staging=%v: %v %s, want %s", x.i, x.stg, due, why, x.want)
		}
	}
	// staging certificates are recognised by their issuer
	d := t.TempDir()
	old := edgeCertDir
	edgeCertDir = d
	t.Cleanup(func() { edgeCertDir = old })
	ca := newTestCA(t, "(STAGING) Pretend Pear X1")
	os.WriteFile(filepath.Join(d, "nas.example.com.pem"), ca.sign(t, nil, nil, ct.Domains, now, now.Add(90*day)), 0600)
	if i, err := edgeReadCert("nas.example.com"); err != nil || !i.Staging || i.Issuer != "(STAGING) Pretend Pear X1" {
		t.Errorf("staging issuer: %+v %v", i, err)
	}
	// a symlink is never followed
	os.Symlink(filepath.Join(d, "nas.example.com.pem"), filepath.Join(d, "link.example.com.pem"))
	if _, err := edgeReadCert("link.example.com"); err == nil {
		t.Error("edgeReadCert followed a symlink")
	}
	// ... and never blocks on a FIFO the service user could leave there (status runs in the web UI's CGI)
	if err := syscall.Mkfifo(filepath.Join(d, "fifo.example.com.pem"), 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := edgeReadCert("fifo.example.com"); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Error("edgeReadCert read a FIFO")
		}
	case <-time.After(2 * time.Second):
		t.Error("edgeReadCert blocked on a FIFO")
	}
}

// DNS-01 through the Cloudflare API: the zone is the longest suffix the token sees; the record is
// deleted by its id; a refused token is reported without the token.
func TestEdgeCloudflareDNS01(t *testing.T) {
	f := &fakeCF{}
	srv := httptest.NewServer(http.HandlerFunc(f.handler))
	defer srv.Close()
	old := cfAPIBase
	cfAPIBase = srv.URL + "/client/v4"
	defer func() { cfAPIBase = old }()
	p := &cfDNS01{hc: ddnsHTTP(), token: cfTestToken, zones: map[string]string{}}
	del, err := p.present(context.Background(), "_acme-challenge.a.b.example.com", "v4lue")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(f.take(), ","); got != "GET /zones,GET /zones,GET /zones,POST /zones/"+cfTestZone+"/dns_records" {
		t.Errorf("calls: %s", got)
	}
	if len(f.recs) != 1 || f.recs[0]["content"] != "v4lue" || f.recs[0]["type"] != "TXT" || f.recs[0]["name"] != "_acme-challenge.a.b.example.com" {
		t.Errorf("record: %v", f.recs)
	}
	del(context.Background())
	if len(f.recs) != 0 {
		t.Errorf("not deleted: %v", f.recs)
	}
	p2 := &cfDNS01{hc: ddnsHTTP(), token: "wrong-token-0123456789-abcdefghij", zones: map[string]string{}}
	if _, err := p2.present(context.Background(), "_acme-challenge.nas.example.com", "x"); err == nil || !strings.Contains(err.Error(), "refused the token") || strings.Contains(err.Error(), "wrong-token") {
		t.Errorf("refused token: %v", err)
	}
}

// The init script's `mr edge prepare`: a real directory 0700, .pem files 0600; symlinks untouched.
func TestEdgePrepare(t *testing.T) {
	d := t.TempDir()
	old, ou := edgeCertDir, edgeServiceUser
	edgeCertDir = filepath.Join(d, "state", "edge")
	edgeServiceUser = func() (int, int) { return os.Getuid(), os.Getgid() }
	defer func() { edgeCertDir, edgeServiceUser = old, ou }()
	if err := edgePrepare(); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(edgeCertDir, "a.example.com.pem"), []byte("x"), 0644)
	os.WriteFile(filepath.Join(d, "outside"), []byte("x"), 0644)
	os.Symlink(filepath.Join(d, "outside"), filepath.Join(edgeCertDir, "b.example.com.pem"))
	os.Chmod(edgeCertDir, 0755)
	if err := edgePrepare(); err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]os.FileMode{edgeCertDir: 0700, filepath.Join(edgeCertDir, "a.example.com.pem"): 0600, filepath.Join(d, "outside"): 0644} {
		if fi, _ := os.Stat(p); fi.Mode().Perm() != want {
			t.Errorf("%s: %v, want %v", p, fi.Mode().Perm(), want)
		}
	}
	// the directory replaced by a symlink: refused
	os.RemoveAll(edgeCertDir)
	os.Symlink(d, edgeCertDir)
	if err := edgePrepare(); err == nil {
		t.Error("prepare accepted a symlinked certificate directory")
	}
}
