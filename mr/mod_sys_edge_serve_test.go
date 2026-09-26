package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// edgeServeEnv: a running edge server on two loopback listeners (main + WAN) with certificates from a
// test CA, and a backend that echoes what it received.
type edgeServeEnv struct {
	s        *edgeServer
	lan, wan string // listener addresses
	pool     *x509.CertPool
	ca       *testCA
	certs    string
	backend  *httptest.Server
}

func newEdgeServeEnv(t *testing.T, routes func(backend string) []edgeConfRoute) *edgeServeEnv {
	t.Helper()
	e := &edgeServeEnv{ca: newTestCA(t, "edge test CA"), certs: t.TempDir()}
	e.pool = x509.NewCertPool()
	e.pool.AddCert(e.ca.cert)
	e.backend = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") == "websocket" {
			// a WebSocket-style upgrade: 101, then echo raw bytes
			hj, _ := w.(http.Hijacker)
			conn, rw, _ := hj.Hijack()
			defer conn.Close()
			rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
			rw.Flush()
			buf := make([]byte, 64)
			for {
				n, err := rw.Read(buf)
				if err != nil {
					return
				}
				conn.Write(append([]byte("echo:"), buf[:n]...))
			}
		}
		json.NewEncoder(w).Encode(map[string]string{"host": r.Host, "path": r.URL.RequestURI(), "xff": r.Header.Get("X-Forwarded-For"),
			"proto": r.Header.Get("X-Forwarded-Proto"), "xfhost": r.Header.Get("X-Forwarded-Host"), "via": r.Proto})
	}))
	t.Cleanup(e.backend.Close)
	lnLAN, _ := net.Listen("tcp", "127.0.0.1:0")
	lnWAN, _ := net.Listen("tcp", "127.0.0.1:0")
	ec := edgeConf{Port: lnLAN.Addr().(*net.TCPAddr).Port, WANPort: lnWAN.Addr().(*net.TCPAddr).Port, Certs: e.certs,
		Routes: routes(e.backend.URL)}
	for _, r := range ec.Routes {
		if _, err := os.Stat(filepath.Join(e.certs, r.Cert+".pem")); err != nil && r.Cert != "missing.example.com" {
			names := []string{r.Host}
			if strings.HasPrefix(r.Cert, "_.") {
				names = []string{strings.TrimPrefix(r.Cert, "_."), "*." + strings.TrimPrefix(r.Cert, "_.")}
			}
			os.WriteFile(filepath.Join(e.certs, r.Cert+".pem"), e.ca.sign(t, nil, nil, names, time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour)), 0600)
		}
	}
	s, err := newEdgeServer(ec, "test")
	if err != nil {
		t.Fatal(err)
	}
	e.s = s
	srv := s.httpServer()
	sem := make(chan struct{}, 8)
	for _, ln := range []net.Listener{lnLAN, lnWAN} {
		go srv.ServeTLS(&edgeLimit{Listener: ln, sem: sem}, "", "")
	}
	t.Cleanup(func() { srv.Close() })
	e.lan, e.wan = lnLAN.Addr().String(), lnWAN.Addr().String()
	return e
}

// client: HTTPS to host, always connecting to addr; h2 when allowed.
func (e *edgeServeEnv) client(addr string, h2 bool) *http.Client {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
		},
		TLSClientConfig:   &tls.Config{RootCAs: e.pool},
		ForceAttemptHTTP2: h2,
	}
	if !h2 {
		tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	}
	return &http.Client{Transport: tr, Timeout: 5 * time.Second}
}

func (e *edgeServeEnv) get(t *testing.T, addr, url string, h2 bool, hdr ...string) (int, map[string]string, error) {
	t.Helper()
	req, _ := http.NewRequest("GET", url, nil)
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := e.client(addr, h2).Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	var m map[string]string
	json.NewDecoder(resp.Body).Decode(&m)
	if m == nil {
		m = map[string]string{}
	}
	m["_proto"] = resp.Proto
	return resp.StatusCode, m, nil
}

func stdRoutes(to string) []edgeConfRoute {
	return []edgeConfRoute{
		{Name: "nas", Host: "nas.example.com", To: to, Cert: "_.example.com"},
		{Name: "ha", Host: "ha.example.com", To: to, Cert: "_.example.com", Allow: []string{"lan"}},
		{Name: "cam", Host: "cam.example.org", To: to, Cert: "cam.example.org", Allow: []string{"127.0.0.0/8"}},
		{Name: "tv", Host: "tv.example.org", To: to, Cert: "tv.example.org", Allow: []string{"lan", "203.0.113.0/24"}},
		{Name: "down", Host: "down.example.com", To: "http://127.0.0.1:1", Cert: "_.example.com"},
		{Name: "nocert", Host: "nocert.example.net", To: to, Cert: "missing.example.com"},
	}
}

// Routing by SNI, HTTP/2 and HTTP/1.1, headers to the upstream, Host ≠ SNI, unknown names.
func TestEdgeServeProxy(t *testing.T) {
	e := newEdgeServeEnv(t, stdRoutes)
	for _, h2 := range []bool{true, false} {
		st, m, err := e.get(t, e.lan, "https://nas.example.com/a/b?c=d", h2, "X-Forwarded-For", "192.0.2.66", "X-Forwarded-Host", "evil.example")
		if err != nil || st != 200 {
			t.Fatalf("h2=%v: %d %v", h2, st, err)
		}
		wantProto := map[bool]string{true: "HTTP/2.0", false: "HTTP/1.1"}[h2]
		if m["_proto"] != wantProto || m["host"] != "nas.example.com" || m["path"] != "/a/b?c=d" || m["xff"] != "127.0.0.1" ||
			m["proto"] != "https" || m["xfhost"] != "nas.example.com" || m["via"] != "HTTP/1.1" {
			t.Errorf("h2=%v: upstream saw %v", h2, m)
		}
	}
	// the wildcard certificate serves every host under it; the upstream down → 502, counted
	if st, _, err := e.get(t, e.lan, "https://down.example.com/", true); err != nil || st != 502 {
		t.Errorf("upstream down: %d %v", st, err)
	}
	// unknown SNI, no SNI, a route without its certificate: the handshake fails
	for _, name := range []string{"other.example.com", "", "nocert.example.net"} {
		conn, err := tls.Dial("tcp", e.lan, &tls.Config{ServerName: name, InsecureSkipVerify: true})
		if err == nil {
			conn.Close()
			t.Errorf("handshake for %q succeeded", name)
		}
	}
	// Host ≠ SNI (another host under the same certificate): 421
	conn, err := tls.Dial("tcp", e.lan, &tls.Config{ServerName: "nas.example.com", RootCAs: e.pool, NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: ha.example.com\r\nConnection: close\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil || resp.StatusCode != 421 {
		t.Errorf("Host ≠ SNI: %v %v", resp, err)
	}
	conn.Close()
	st := e.s.runStatus()
	if st.Routes["nas"].Requests != 2 || st.Routes["down"].Errors != 1 || st.Routes["nas"].Denied != 1 || st.Conf != "test" {
		t.Errorf("status: %+v", st)
	}
}

// Allow lists: lan = the main listener only; CIDRs on both; the WAN listener refuses lan-only routes
// already in the handshake.
func TestEdgeServeAllow(t *testing.T) {
	e := newEdgeServeEnv(t, stdRoutes)
	for _, x := range []struct {
		addr, host string
		ok         bool
	}{
		{e.lan, "ha.example.com", true},  // lan
		{e.wan, "ha.example.com", false}, // lan only, from the WAN
		{e.wan, "nas.example.com", true}, // everyone
		{e.wan, "cam.example.org", true}, // 127.0.0.0/8 matches the client
		{e.lan, "cam.example.org", true},
		{e.wan, "tv.example.org", false}, // lan + a CIDR the client is not in
		{e.lan, "tv.example.org", true},
	} {
		st, _, err := e.get(t, x.addr, "https://"+x.host+"/", false)
		if ok := err == nil && st == 200; ok != x.ok {
			t.Errorf("%s via %s: %d %v, want ok=%v", x.host, map[bool]string{true: "LAN", false: "WAN"}[x.addr == e.lan], st, err, x.ok)
		}
	}
	if d := e.s.runStatus().Routes["ha"].Denied; d < 1 {
		t.Errorf("denied handshakes counted: %d", d)
	}
	// the request-level check agrees with the handshake (a connection reused for another host)
	rt := e.s.routes["ha.example.com"]
	lanAddr, _ := net.ResolveTCPAddr("tcp", e.lan)
	wanAddr, _ := net.ResolveTCPAddr("tcp", e.wan)
	cli := &net.TCPAddr{IP: net.ParseIP("192.0.2.5"), Port: 5555}
	if ra, wan := e.s.peer(lanAddr, cli); !rt.allowed(ra, wan) {
		t.Error("lan route refused on the main listener")
	}
	if ra, wan := e.s.peer(wanAddr, cli); rt.allowed(ra, wan) {
		t.Error("lan route allowed on the WAN listener")
	}
}

// WebSocket (and any other HTTP/1.1 upgrade) passes through in both directions.
func TestEdgeServeWebSocket(t *testing.T) {
	e := newEdgeServeEnv(t, stdRoutes)
	conn, err := tls.Dial("tcp", e.lan, &tls.Config{ServerName: "nas.example.com", RootCAs: e.pool, NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(conn, "GET /ws HTTP/1.1\r\nHost: nas.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != 101 || resp.Header.Get("Upgrade") != "websocket" {
		t.Fatalf("upgrade: %v %v", resp, err)
	}
	for _, msg := range []string{"hello", "second frame"} {
		conn.Write([]byte(msg))
		buf := make([]byte, 64)
		n, err := br.Read(buf)
		if err != nil || string(buf[:n]) != "echo:"+msg {
			t.Fatalf("echo: %q %v", buf[:n], err)
		}
	}
}

// Certificates: a new file is picked up on SIGHUP (reload) and by itself (changed mtime, checked at
// most once a minute); a broken file keeps the old certificate.
func TestEdgeServeReload(t *testing.T) {
	e := newEdgeServeEnv(t, stdRoutes)
	serial := func() string {
		conn, err := tls.Dial("tcp", e.lan, &tls.Config{ServerName: "cam.example.org", RootCAs: e.pool})
		if err != nil {
			return "error: " + err.Error()
		}
		defer conn.Close()
		return conn.ConnectionState().PeerCertificates[0].SerialNumber.String()
	}
	first := serial()
	p := filepath.Join(e.certs, "cam.example.org.pem")
	os.WriteFile(p, e.ca.sign(t, nil, nil, []string{"cam.example.org"}, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour)), 0600)
	if serial() != first {
		t.Fatal("certificate changed before the next check")
	}
	e.s.reload(true) // SIGHUP
	second := serial()
	if second == first || strings.HasPrefix(second, "error") {
		t.Fatalf("reload: %s → %s", first, second)
	}
	// by itself: a changed file after the minute has passed
	os.WriteFile(p, e.ca.sign(t, nil, nil, []string{"cam.example.org"}, time.Now().Add(-time.Hour), time.Now().Add(48*time.Hour)), 0600)
	future := time.Now().Add(2 * time.Second)
	os.Chtimes(p, future, future)
	e.s.checked.Store(0)
	third := serial()
	if third == second {
		t.Error("changed file not picked up")
	}
	// broken file: the old certificate stays
	os.WriteFile(p, []byte("-----BEGIN CERTIFICATE-----\nbroken\n"), 0600)
	e.s.reload(true)
	if serial() != third {
		t.Error("a broken file replaced the certificate")
	}
	// a certificate that appears later (first issuance) makes its host work without a restart
	os.WriteFile(filepath.Join(e.certs, "missing.example.com.pem"), e.ca.sign(t, nil, nil, []string{"nocert.example.net"}, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour)), 0600)
	e.s.reload(true)
	if st, _, err := e.get(t, e.lan, "https://nocert.example.net/", false); err != nil || st != 200 {
		t.Errorf("new certificate: %d %v", st, err)
	}
}

// The serving process accepts only what the renderer writes: bad routes and ports are refused.
func TestEdgeServeConf(t *testing.T) {
	ok := edgeConfRoute{Name: "nas", Host: "nas.example.com", To: "http://192.168.1.10:5000", Cert: "_.example.com"}
	for name, ec := range map[string]edgeConf{
		"port":      {Port: 0, Routes: []edgeConfRoute{ok}},
		"same port": {Port: 443, WANPort: 443, Routes: []edgeConfRoute{ok}},
		"target":    {Port: 443, Routes: []edgeConfRoute{{Name: "x", Host: "x.example.com", To: "http://nas.lan", Cert: "x"}}},
		"cert path": {Port: 443, Routes: []edgeConfRoute{{Name: "x", Host: "x.example.com", To: "http://192.168.1.10", Cert: "../../secrets"}}},
		"duplicate": {Port: 443, Routes: []edgeConfRoute{ok, ok}},
		"allow":     {Port: 443, Routes: []edgeConfRoute{{Name: "x", Host: "x.example.com", To: "http://192.168.1.10", Cert: "x", Allow: []string{"everyone"}}}},
	} {
		if _, err := newEdgeServer(ec, ""); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// the rendered config of the test config loads
	c := edgeTestConfig(t)
	b, _ := json.Marshal(edgeConfOf(c))
	f := filepath.Join(t.TempDir(), "edge.json")
	os.WriteFile(f, b, 0644)
	ec, hash, err := edgeLoadConf(f)
	if err != nil || hash != edgeConfHash(string(b)) {
		t.Fatal(err)
	}
	if _, err := newEdgeServer(ec, hash); err != nil {
		t.Errorf("rendered config refused: %v", err)
	}
}
