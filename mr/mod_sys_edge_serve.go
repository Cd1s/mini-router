package main

// sys module: `mr edge serve` — the HTTPS reverse proxy process of services.edge (OpenRC service
// mr-edge). It reads only gen/edge.json and its certificate files: no router.yaml, no secrets.yaml, so
// it runs as the unprivileged user mr-edge with CAP_NET_BIND_SERVICE.
//
//   - TLS 1.2+ with HTTP/2 and HTTP/1.1 (Go's net/http). The certificate is chosen by SNI; an unknown
//     name, or a client the route's allow list refuses, fails the handshake (a scan of the address
//     learns no host names). The request's Host must be the SNI name (else 421: HTTP/2 connection
//     reuse across a wildcard certificate makes the browser retry on a connection of its own).
//   - Two listeners: the main port (reached through the LAN zone: allow `lan`) and, with open, the WAN
//     listener nftables redirects the WANs' port to. CIDRs in allow match the client address on both.
//   - Each route proxies to one upstream (httputil.ReverseProxy): the original Host, X-Forwarded-For /
//     -Proto / -Host set from the connection (a client's own X-Forwarded-* headers are dropped), WebSocket
//     and other upgrades passed through, streaming responses flushed at once. HTTPS upstreams are LAN
//     addresses with self-signed certificates: encrypted, not verified. No caching, no rewriting.
//   - Limits: 512 connections, 10 s for the TLS handshake and the request headers, 32 KiB of headers,
//     2 minutes idle; no body or response timeouts (uploads, long polls, WebSockets).
//   - Certificates are reloaded on SIGHUP (`mr edge renew` sends it) and when a file changed (checked at
//     most once a minute, on a handshake). A missing certificate only fails its hosts.
//   - /run/mr-edge/status.json: pid, the config hash (apply's Verify), requests per route; written at
//     start and at most once a minute while requests come in. Nothing is logged per request.

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	edgeMaxConns    = 512
	edgeHeaderBytes = 32 << 10
)

type edgeRoute struct {
	edgeConfRoute
	lan    bool
	any    bool
	nets   []netip.Prefix
	proxy  *httputil.ReverseProxy
	reqs   atomic.Int64
	errs   atomic.Int64
	denied atomic.Int64
	logged atomic.Int64 // last upstream error logged (unix): at most one per minute
}

type edgeCertEntry struct {
	mod  time.Time
	size int64
	cert *tls.Certificate
}

type edgeServer struct {
	conf    edgeConf
	hash    string
	routes  map[string]*edgeRoute // by host
	order   []*edgeRoute
	mu      sync.RWMutex
	certs   map[string]*edgeCertEntry
	checked atomic.Int64 // last look at the certificate files (unix)
	started time.Time
}

func edgeLoadConf(path string) (edgeConf, string, error) {
	var ec edgeConf
	b, err := os.ReadFile(path)
	if err != nil {
		return ec, "", err
	}
	if err := json.Unmarshal(b, &ec); err != nil {
		return ec, "", fmt.Errorf("%s: %v", path, err)
	}
	return ec, edgeConfHash(string(b)), nil
}

// newEdgeServer checks the config again (it is the process's only input) and builds the routes.
func newEdgeServer(ec edgeConf, hash string) (*edgeServer, error) {
	s := &edgeServer{conf: ec, hash: hash, routes: map[string]*edgeRoute{}, certs: map[string]*edgeCertEntry{}, started: time.Now()}
	if ec.Port < 1 || ec.Port > 65535 || ec.WANPort < 0 || ec.WANPort > 65535 || ec.WANPort == ec.Port {
		return nil, errors.New("edge.json: bad port")
	}
	tr := &http.Transport{
		Proxy:                  nil,
		DialContext:            (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		MaxIdleConns:           64,
		MaxIdleConnsPerHost:    16,
		IdleConnTimeout:        90 * time.Second,
		TLSHandshakeTimeout:    10 * time.Second,
		ExpectContinueTimeout:  time.Second,
		MaxResponseHeaderBytes: 64 << 10,
		// LAN services by IP address: self-signed certificates, nothing to verify them against
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	for _, r := range ec.Routes {
		scheme, ip, port, err := edgeTarget(r.To)
		if err != nil || !edgeHostOK(r.Host) || s.routes[r.Host] != nil || strings.ContainsAny(r.Cert, "/\\") || r.Cert == "" {
			return nil, fmt.Errorf("edge.json: bad route %q", r.Name)
		}
		lan, nets, err := edgeAllow(r.Allow)
		if err != nil {
			return nil, fmt.Errorf("edge.json: route %q: %v", r.Name, err)
		}
		rt := &edgeRoute{edgeConfRoute: r, lan: lan, any: len(r.Allow) == 0, nets: nets}
		target := &url.URL{Scheme: scheme, Host: net.JoinHostPort(ip.String(), strconv.Itoa(port))}
		rt.proxy = &httputil.ReverseProxy{
			Rewrite: func(pr *httputil.ProxyRequest) {
				pr.SetURL(target)
				pr.Out.Host = pr.In.Host
				pr.SetXForwarded()
			},
			Transport: tr,
			ErrorLog:  log.New(io.Discard, "", 0),
			ErrorHandler: func(w http.ResponseWriter, req *http.Request, err error) {
				if errors.Is(err, context.Canceled) {
					return // the client went away
				}
				rt.errs.Add(1)
				if now := time.Now().Unix(); now-rt.logged.Load() >= 60 {
					rt.logged.Store(now)
					logf("edge: %s: upstream %s: %s", rt.Name, rt.To, ddnsErrText(err))
				}
				http.Error(w, "upstream unavailable", http.StatusBadGateway)
			},
		}
		s.routes[r.Host] = rt
		s.order = append(s.order, rt)
	}
	s.reload(true)
	return s, nil
}

// allowed: whether a client at remote (wan: it came through the WAN listener) may use rt.
func (rt *edgeRoute) allowed(remote netip.Addr, wan bool) bool {
	if rt.any || (rt.lan && !wan) {
		return true
	}
	remote = remote.Unmap()
	for _, n := range rt.nets {
		if n.Contains(remote) {
			return true
		}
	}
	return false
}

// peer: the client address and whether the connection came in on the WAN listener.
func (s *edgeServer) peer(local, remote net.Addr) (netip.Addr, bool) {
	var ra netip.Addr
	if t, ok := remote.(*net.TCPAddr); ok {
		ra = t.AddrPort().Addr().Unmap()
	} else if ap, err := netip.ParseAddrPort(remote.String()); err == nil {
		ra = ap.Addr().Unmap()
	}
	wan := false
	if t, ok := local.(*net.TCPAddr); ok {
		wan = s.conf.WANPort > 0 && t.Port == s.conf.WANPort
	}
	return ra, wan
}

var (
	errEdgeUnknown = errors.New("unknown server name")
	errEdgeDenied  = errors.New("not allowed")
	errEdgeNoCert  = errors.New("no certificate yet")
)

func (s *edgeServer) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	rt := s.routes[strings.ToLower(strings.TrimSuffix(hello.ServerName, "."))]
	if rt == nil {
		return nil, errEdgeUnknown
	}
	if hello.Conn != nil {
		if ra, wan := s.peer(hello.Conn.LocalAddr(), hello.Conn.RemoteAddr()); !rt.allowed(ra, wan) {
			rt.denied.Add(1)
			return nil, errEdgeDenied
		}
	}
	if cert := s.cert(rt.Cert); cert != nil {
		return cert, nil
	}
	return nil, errEdgeNoCert
}

func (s *edgeServer) cert(name string) *tls.Certificate {
	if now := time.Now().Unix(); now-s.checked.Load() >= 60 {
		s.reload(false)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if e := s.certs[name]; e != nil {
		return e.cert
	}
	return nil
}

// reload (re)reads every certificate file that changed (all with force). A file that does not load
// keeps the certificate that was there.
func (s *edgeServer) reload(force bool) {
	s.checked.Store(time.Now().Unix())
	names := map[string]bool{}
	for _, rt := range s.order {
		names[rt.Cert] = true
	}
	for name := range names {
		p := filepath.Join(s.conf.Certs, name+".pem")
		fi, err := os.Stat(p)
		s.mu.RLock()
		old := s.certs[name]
		s.mu.RUnlock()
		if err != nil || (!force && old != nil && fi.ModTime().Equal(old.mod) && fi.Size() == old.size) {
			continue
		}
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		c, err := tls.X509KeyPair(data, data)
		if err != nil {
			logf("edge: %s.pem: %v", name, err)
			continue
		}
		s.mu.Lock()
		s.certs[name] = &edgeCertEntry{mod: fi.ModTime(), size: fi.Size(), cert: &c}
		s.mu.Unlock()
	}
}

func (s *edgeServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sni := ""
	if r.TLS != nil {
		sni = strings.ToLower(strings.TrimSuffix(r.TLS.ServerName, "."))
	}
	host := strings.ToLower(r.Host)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(host, ".")
	rt := s.routes[sni]
	if rt == nil || host != sni {
		if rt != nil {
			rt.denied.Add(1)
		}
		http.Error(w, "misdirected request", http.StatusMisdirectedRequest)
		return
	}
	local, _ := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	remote, err := netip.ParseAddrPort(r.RemoteAddr)
	if local == nil || err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if _, wan := s.peer(local, net.TCPAddrFromAddrPort(remote)); !rt.allowed(remote.Addr(), wan) {
		rt.denied.Add(1)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	rt.reqs.Add(1)
	rt.proxy.ServeHTTP(w, r)
}

// edgeLimit: at most n connections at once (Accept waits while full).
type edgeLimit struct {
	net.Listener
	sem chan struct{}
}

type edgeLimitConn struct {
	net.Conn
	release func()
}

func (c *edgeLimitConn) Close() error {
	err := c.Conn.Close()
	c.release()
	return err
}

func (l *edgeLimit) Accept() (net.Conn, error) {
	l.sem <- struct{}{}
	c, err := l.Listener.Accept()
	if err != nil {
		<-l.sem
		return nil, err
	}
	return &edgeLimitConn{Conn: c, release: sync.OnceFunc(func() { <-l.sem })}, nil
}

func (s *edgeServer) httpServer() *http.Server {
	return &http.Server{
		Handler:           s,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: s.getCertificate},
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    edgeHeaderBytes,
		ErrorLog:          log.New(io.Discard, "", 0), // scanners' failed handshakes are not news
	}
}

func (s *edgeServer) runStatus() edgeRun {
	st := edgeRun{PID: os.Getpid(), Started: s.started.Unix(), Updated: time.Now().Unix(), Conf: s.hash,
		Port: s.conf.Port, WANPort: s.conf.WANPort, Routes: map[string]edgeRouteStat{}}
	for _, rt := range s.order {
		st.Routes[rt.Name] = edgeRouteStat{Requests: rt.reqs.Load(), Errors: rt.errs.Load(), Denied: rt.denied.Load()}
	}
	return st
}

func (s *edgeServer) writeStatus() {
	b, _ := json.Marshal(s.runStatus())
	if err := writeAtomic(filepath.Join(edgeRunDir, "status.json"), b, 0644); err != nil {
		logf("edge: status: %v", err)
	}
}

// edgeServe is `mr edge serve [-c FILE]`.
func edgeServe(args []string) error {
	fs := flag.NewFlagSet("edge serve", flag.ContinueOnError)
	conf := fs.String("c", edgeConfFile, "edge.json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ec, hash, err := edgeLoadConf(*conf)
	if err != nil {
		return err
	}
	s, err := newEdgeServer(ec, hash)
	if err != nil {
		return err
	}
	os.Remove(filepath.Join(edgeRunDir, "status.json"))
	var lns []net.Listener
	for _, port := range []int{ec.Port, ec.WANPort} {
		if port == 0 {
			continue
		}
		ln, err := net.Listen("tcp", ":"+strconv.Itoa(port))
		if err != nil {
			for _, l := range lns {
				l.Close()
			}
			logf("edge: %v", err)
			return err
		}
		lns = append(lns, ln)
	}
	sem := make(chan struct{}, edgeMaxConns)
	srv := s.httpServer()
	errc := make(chan error, len(lns))
	for _, ln := range lns {
		go func(ln net.Listener) { errc <- srv.ServeTLS(&edgeLimit{Listener: ln, sem: sem}, "", "") }(ln)
	}
	s.writeStatus()
	logf("edge: serving %d routes on port %d%s", len(s.order), ec.Port, map[bool]string{true: " (and the WANs)"}[ec.WANPort > 0])
	sig := make(chan os.Signal, 2)
	signal.Notify(sig, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGINT)
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	var last int64
	for {
		select {
		case x := <-sig:
			if x == syscall.SIGHUP {
				s.reload(true)
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			srv.Shutdown(ctx)
			cancel()
			return nil
		case err := <-errc:
			return err
		case <-tick.C:
			n := int64(0)
			for _, rt := range s.order {
				n += rt.reqs.Load() + rt.errs.Load() + rt.denied.Load()
			}
			if n != last {
				last = n
				s.writeStatus()
			}
		}
	}
}
