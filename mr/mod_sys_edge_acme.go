package main

// sys module: certificates for the HTTPS reverse proxy (services.edge) — `mr edge renew`, a short run
// (crond once a day, after an apply that needs a certificate, the web UI's 立即申请). Nothing resident.
//
// ACME (RFC 8555) with the Go standard library only: ES256 JWS, account (one key per CA, created on
// first use), order, DNS-01 (TXT _acme-challenge.<host> through the Cloudflare API with the DDNS client's
// cfCall), a check that the record is visible at the zone's authoritative name servers, challenge,
// finalize with a fresh ECDSA P-256 key, download, checks (the chain's leaf matches the key and names
// every domain), then an atomic write of <cert>.pem (chain + key, 0600, owned by the service user), the
// TXT records deleted again, and SIGHUP to `mr edge serve` (it also notices the new file by itself).
//
// When: a certificate that is missing, names other domains, comes from the other CA (staging ↔
// production) or has less than a third of its lifetime left (30 of Let's Encrypt's 90 days) is renewed;
// anything else costs no request. Failures back off (1, 2, 4 … 24 h) for automatic runs; a manual run
// (`mr edge renew`, 立即申请) tries at once. Results: /run/mini-router/edge-renew.json (tmpfs), events
// (type cert) for issued and failed certificates.
//
// Secrets: the API token only goes into the Authorization header of Cloudflare requests; the account
// key stays in /etc/mini-router/state/acme (0700 root), certificate keys in the .pem files; none of them
// is ever logged, shown in the state file, `mr edge status` or the API (tested).

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// edgeDirectory: the ACME directory (Let's Encrypt; a variable so tests use an in-process stub).
var edgeDirectory = func(staging bool) string {
	if staging {
		return "https://acme-staging-v02.api.letsencrypt.org/directory"
	}
	return "https://acme-v02.api.letsencrypt.org/directory"
}

// test hooks
var (
	acmePoll = 2 * time.Second // between polls of an authorization / order
	acmeWait = 3 * time.Minute // for an authorization / order to settle
	// edgeTXTWait: how long to wait for the TXT records at the authoritative servers before asking the CA anyway
	edgeTXTWait = 2 * time.Minute
	// edgeTXTVisible reports whether name has a TXT record value at every authoritative server of its zone
	edgeTXTVisible = txtAtAuthority
	// edgeEvent records an event (type cert); edgeSignal tells `mr edge serve` to reload its certificates
	edgeEvent  = func(c *Config, sev, key, msg string) { eventAdd(c, "cert", sev, key, msg, true) }
	edgeSignal = edgeSignalServe
	// edgeDNS01For: the DNS-01 provider for the config (cloudflare)
	edgeDNS01For = func(c *Config) (dns01, error) {
		tok, err := c.Secret(c.Services.Edge.ACME.Token)
		if err != nil {
			return nil, err
		}
		return &cfDNS01{hc: ddnsHTTP(), token: tok, zones: map[string]string{}}, nil
	}
)

const acmeMaxBody = 1 << 20

// ---- ACME client ----

type acmeDir struct {
	NewNonce   string `json:"newNonce"`
	NewAccount string `json:"newAccount"`
	NewOrder   string `json:"newOrder"`
}

// acmeProblem is an ACME error document (RFC 7807).
type acmeProblem struct {
	Type   string `json:"type"`
	Detail string `json:"detail"`
	Status int    `json:"status"`
	retry  time.Duration
}

func (p *acmeProblem) Error() string {
	t := strings.TrimPrefix(p.Type, "urn:ietf:params:acme:error:")
	return ddnsErrText(fmt.Errorf("ACME: %s (HTTP %d): %s", t, p.Status, p.Detail))
}

type acmeClient struct {
	hc     *http.Client
	dirURL string
	dir    acmeDir
	key    *ecdsa.PrivateKey
	kid    string
	nonce  string
}

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (a *acmeClient) jwk() map[string]string {
	pub := a.key.PublicKey
	x, y := make([]byte, 32), make([]byte, 32)
	pub.X.FillBytes(x)
	pub.Y.FillBytes(y)
	return map[string]string{"crv": "P-256", "kty": "EC", "x": b64u(x), "y": b64u(y)}
}

// thumbprint: RFC 7638 (members in lexical order, no spaces).
func (a *acmeClient) thumbprint() string {
	j := a.jwk()
	h := sha256.Sum256([]byte(`{"crv":"P-256","kty":"EC","x":"` + j["x"] + `","y":"` + j["y"] + `"}`))
	return b64u(h[:])
}

// sameOrigin: every URL the client posts to must be on the directory's scheme and host.
func (a *acmeClient) sameOrigin(u string) bool {
	d, err1 := url.Parse(a.dirURL)
	x, err2 := url.Parse(u)
	return err1 == nil && err2 == nil && x.Scheme == d.Scheme && x.Host == d.Host && x.User == nil
}

func (a *acmeClient) get(ctx context.Context, u string, out any) (http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return nil, errors.New("ACME: bad URL")
	}
	req.Header.Set("User-Agent", "mini-router-edge/"+version)
	resp, err := a.hc.Do(req)
	if err != nil {
		return nil, errors.New("ACME: " + ddnsErrText(err))
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, acmeMaxBody))
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("ACME: HTTP %d from the directory", resp.StatusCode)
	}
	if out != nil && json.Unmarshal(raw, out) != nil {
		return nil, errors.New("ACME: unexpected answer from the directory")
	}
	return resp.Header, nil
}

func (a *acmeClient) newNonce(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "HEAD", a.dir.NewNonce, nil)
	if err != nil {
		return errors.New("ACME: bad newNonce URL")
	}
	resp, err := a.hc.Do(req)
	if err != nil {
		return errors.New("ACME: " + ddnsErrText(err))
	}
	resp.Body.Close()
	if a.nonce = resp.Header.Get("Replay-Nonce"); a.nonce == "" {
		return errors.New("ACME: no nonce")
	}
	return nil
}

// jws signs payload (nil = POST-as-GET: empty payload) for u with the account key: kid once the
// account exists, else the public key itself.
func (a *acmeClient) jws(u string, payload []byte) ([]byte, error) {
	prot := map[string]any{"alg": "ES256", "nonce": a.nonce, "url": u}
	if a.kid != "" {
		prot["kid"] = a.kid
	} else {
		prot["jwk"] = a.jwk()
	}
	pb, _ := json.Marshal(prot)
	signed := b64u(pb) + "." + b64u(payload)
	h := sha256.Sum256([]byte(signed))
	r, s, err := ecdsa.Sign(rand.Reader, a.key, h[:])
	if err != nil {
		return nil, err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	a.nonce = ""
	return json.Marshal(map[string]string{"protected": b64u(pb), "payload": b64u(payload), "signature": b64u(sig)})
}

// post sends a signed request; payload nil is a POST-as-GET. It retries a bad nonce twice.
func (a *acmeClient) post(ctx context.Context, u string, payload any, accept string) (http.Header, []byte, error) {
	if !a.sameOrigin(u) {
		return nil, nil, errors.New("ACME: the server named a URL on another host")
	}
	var pl []byte
	if payload != nil {
		pl, _ = json.Marshal(payload)
	}
	for attempt := 0; ; attempt++ {
		if a.nonce == "" {
			if err := a.newNonce(ctx); err != nil {
				return nil, nil, err
			}
		}
		body, err := a.jws(u, pl)
		if err != nil {
			return nil, nil, err
		}
		req, err := http.NewRequestWithContext(ctx, "POST", u, bytes.NewReader(body))
		if err != nil {
			return nil, nil, errors.New("ACME: bad URL")
		}
		req.Header.Set("Content-Type", "application/jose+json")
		req.Header.Set("User-Agent", "mini-router-edge/"+version)
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		resp, err := a.hc.Do(req)
		if err != nil {
			return nil, nil, errors.New("ACME: " + ddnsErrText(err))
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, acmeMaxBody))
		resp.Body.Close()
		a.nonce = resp.Header.Get("Replay-Nonce")
		if resp.StatusCode >= 400 {
			p := &acmeProblem{Status: resp.StatusCode}
			json.Unmarshal(raw, p)
			if p.Type == "urn:ietf:params:acme:error:badNonce" && attempt < 2 {
				continue
			}
			if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s > 0 {
				p.retry = time.Duration(s) * time.Second
			}
			return nil, nil, p
		}
		return resp.Header, raw, nil
	}
}

func (a *acmeClient) postJSON(ctx context.Context, u string, payload, out any) (http.Header, error) {
	h, raw, err := a.post(ctx, u, payload, "")
	if err != nil {
		return nil, err
	}
	if out != nil && json.Unmarshal(raw, out) != nil {
		return nil, errors.New("ACME: unexpected answer")
	}
	return h, nil
}

// acmeOpen fetches the directory and registers (or finds) the account of key.
func acmeOpen(ctx context.Context, hc *http.Client, dirURL string, key *ecdsa.PrivateKey, email string) (*acmeClient, error) {
	a := &acmeClient{hc: hc, dirURL: dirURL, key: key}
	if _, err := a.get(ctx, dirURL, &a.dir); err != nil {
		return nil, err
	}
	for _, u := range []string{a.dir.NewNonce, a.dir.NewAccount, a.dir.NewOrder} {
		if !a.sameOrigin(u) {
			return nil, errors.New("ACME: the directory names another host")
		}
	}
	req := map[string]any{"termsOfServiceAgreed": true}
	if email != "" {
		req["contact"] = []string{"mailto:" + email}
	}
	h, err := a.postJSON(ctx, a.dir.NewAccount, req, nil)
	if err != nil {
		return nil, err
	}
	if a.kid = h.Get("Location"); !a.sameOrigin(a.kid) {
		return nil, errors.New("ACME: no account URL")
	}
	return a, nil
}

type acmeOrder struct {
	Status         string       `json:"status"`
	Authorizations []string     `json:"authorizations"`
	Finalize       string       `json:"finalize"`
	Certificate    string       `json:"certificate"`
	Error          *acmeProblem `json:"error"`
}

type acmeAuthz struct {
	Status     string `json:"status"`
	Identifier struct {
		Value string `json:"value"`
	} `json:"identifier"`
	Challenges []struct {
		Type   string       `json:"type"`
		URL    string       `json:"url"`
		Token  string       `json:"token"`
		Status string       `json:"status"`
		Error  *acmeProblem `json:"error"`
	} `json:"challenges"`
}

var reACMEToken = lazyRegexp(`^[A-Za-z0-9_-]{16,128}$`)

// dns01 publishes a TXT record for a challenge; the returned func removes it again.
type dns01 interface {
	present(ctx context.Context, name, value string) (func(context.Context), error)
}

// acmeWaitStatus polls u (an authorization or order) until its status is not one of busy.
func (a *acmeClient) waitStatus(ctx context.Context, u string, out any, status func() string, busy ...string) error {
	deadline := time.Now().Add(acmeWait)
	for {
		if _, err := a.postJSON(ctx, u, nil, out); err != nil {
			return err
		}
		if !slicesHas(busy, status()) {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("ACME: still %s after %s", status(), acmeWait)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(acmePoll):
		}
	}
}

type txtRec struct{ name, value string }

// acmeIssue runs one order for domains: returns the PEM chain followed by the new private key.
func acmeIssue(ctx context.Context, a *acmeClient, dns dns01, domains []string) ([]byte, error) {
	var ids []map[string]string
	for _, d := range domains {
		ids = append(ids, map[string]string{"type": "dns", "value": d})
	}
	var order acmeOrder
	h, err := a.postJSON(ctx, a.dir.NewOrder, map[string]any{"identifiers": ids}, &order)
	if err != nil {
		return nil, err
	}
	orderURL := h.Get("Location")
	if !a.sameOrigin(orderURL) || !a.sameOrigin(order.Finalize) {
		return nil, errors.New("ACME: bad order")
	}
	type todo struct{ authz, chal string }
	var work []todo
	var recs []txtRec
	for _, u := range order.Authorizations {
		var z acmeAuthz
		if _, err := a.postJSON(ctx, u, nil, &z); err != nil {
			return nil, err
		}
		if z.Status == "valid" {
			continue
		}
		if z.Status != "pending" {
			return nil, fmt.Errorf("ACME: authorization for %s is %s", ddnsErrText(errors.New(z.Identifier.Value)), z.Status)
		}
		found := false
		for _, ch := range z.Challenges {
			if ch.Type != "dns-01" || !reACMEToken.MatchString(ch.Token) || !a.sameOrigin(ch.URL) {
				continue
			}
			sum := sha256.Sum256([]byte(ch.Token + "." + a.thumbprint()))
			name := "_acme-challenge." + strings.TrimPrefix(strings.ToLower(z.Identifier.Value), "*.")
			if !edgeHostOK(strings.TrimPrefix(name, "_acme-challenge.")) {
				return nil, errors.New("ACME: unexpected identifier")
			}
			recs = append(recs, txtRec{name, b64u(sum[:])})
			work = append(work, todo{u, ch.URL})
			found = true
			break
		}
		if !found {
			return nil, errors.New("ACME: no dns-01 challenge offered")
		}
	}
	// TXT records: always removed again, also when something below fails
	var cleanups []func(context.Context)
	cleanup := func() {
		cctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		for _, f := range cleanups {
			f(cctx)
		}
		cleanups = nil
	}
	defer cleanup()
	for _, r := range recs {
		f, err := dns.present(ctx, r.name, r.value)
		if err != nil {
			return nil, err
		}
		cleanups = append(cleanups, f)
	}
	if len(recs) > 0 {
		edgeWaitTXT(ctx, recs)
	}
	for _, w := range work {
		if _, err := a.postJSON(ctx, w.chal, struct{}{}, nil); err != nil {
			return nil, err
		}
	}
	for _, w := range work {
		var z acmeAuthz
		if err := a.waitStatus(ctx, w.authz, &z, func() string { return z.Status }, "pending", "processing"); err != nil {
			return nil, err
		}
		if z.Status != "valid" {
			why := ""
			for _, ch := range z.Challenges {
				if ch.Type == "dns-01" && ch.Error != nil {
					why = ": " + ch.Error.Detail
				}
			}
			return nil, fmt.Errorf("ACME: validation of %s failed%s", z.Identifier.Value, ddnsErrText(errors.New(why)))
		}
	}
	cleanup()
	// finalize with a fresh key
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: domains[0]}, DNSNames: domains}, key)
	if err != nil {
		return nil, err
	}
	if _, err := a.postJSON(ctx, order.Finalize, map[string]string{"csr": b64u(csr)}, &order); err != nil {
		return nil, err
	}
	if err := a.waitStatus(ctx, orderURL, &order, func() string { return order.Status }, "pending", "ready", "processing"); err != nil {
		return nil, err
	}
	if order.Status != "valid" || !a.sameOrigin(order.Certificate) {
		msg := "ACME: order " + order.Status
		if order.Error != nil {
			msg += ": " + order.Error.Detail
		}
		return nil, errors.New(ddnsErrText(errors.New(msg)))
	}
	_, chain, err := a.post(ctx, order.Certificate, nil, "application/pem-certificate-chain")
	if err != nil {
		return nil, err
	}
	if _, err := edgeCheckChain(chain, &key.PublicKey, domains, edgeNow()); err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	for rest := chain; ; {
		var b *pem.Block
		if b, rest = pem.Decode(rest); b == nil {
			break
		}
		if b.Type == "CERTIFICATE" {
			pem.Encode(&out, &pem.Block{Type: "CERTIFICATE", Bytes: b.Bytes})
		}
	}
	pem.Encode(&out, &pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	return out.Bytes(), nil
}

// edgeCheckChain: the chain's first certificate is for pub, names every domain and is valid now.
func edgeCheckChain(chain []byte, pub *ecdsa.PublicKey, domains []string, now time.Time) (*x509.Certificate, error) {
	b, _ := pem.Decode(chain)
	if b == nil || b.Type != "CERTIFICATE" {
		return nil, errors.New("ACME: the certificate is not PEM")
	}
	leaf, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return nil, errors.New("ACME: " + err.Error())
	}
	if k, ok := leaf.PublicKey.(*ecdsa.PublicKey); !ok || !k.Equal(pub) {
		return nil, errors.New("ACME: the certificate is not for our key")
	}
	for _, d := range domains {
		if !slicesHas(leaf.DNSNames, d) {
			return nil, fmt.Errorf("ACME: the certificate does not name %s", d)
		}
	}
	if now.After(leaf.NotAfter) || now.Before(leaf.NotBefore.Add(-time.Hour)) {
		return nil, errors.New("ACME: the certificate is not valid now (clock?)")
	}
	return leaf, nil
}

// edgeWaitTXT waits until every record is visible at its zone's authoritative servers. When they
// cannot be asked (port 53 blocked, …) or do not show it in time, the CA is asked anyway: Cloudflare
// publishes within seconds, and a wrong guess costs one failed validation, not a stuck renewal.
func edgeWaitTXT(ctx context.Context, recs []txtRec) {
	deadline := time.Now().Add(edgeTXTWait)
	var last error
	for {
		all := true
		for _, r := range recs {
			ok, err := edgeTXTVisible(ctx, r.name, r.value)
			if err != nil {
				last = err
			}
			all = all && ok
		}
		if all {
			return
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			logf("edge: TXT records not confirmed at the authoritative servers (%v); asking the CA anyway", ddnsErrText(errors.Join(last, errors.New("timeout"))))
			return
		}
		time.Sleep(min(5*time.Second, edgeTXTWait/4+time.Millisecond))
	}
}

// txtAtAuthority asks each authoritative server of name's zone directly (no cache on the way).
func txtAtAuthority(ctx context.Context, name, value string) (bool, error) {
	qctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var nss []*net.NS
	for zone := name; strings.Count(zone, ".") >= 1; {
		_, parent, _ := strings.Cut(zone, ".")
		zone = parent
		if ns, err := net.DefaultResolver.LookupNS(qctx, zone+"."); err == nil && len(ns) > 0 {
			nss = ns
			break
		}
	}
	if len(nss) == 0 {
		return false, errors.New("no NS records found for " + name)
	}
	asked := 0
	for _, ns := range nss {
		addrs, err := net.DefaultResolver.LookupHost(qctx, ns.Host)
		if err != nil || len(addrs) == 0 {
			continue
		}
		server := net.JoinHostPort(addrs[0], "53")
		r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, server)
		}}
		txts, err := r.LookupTXT(qctx, name+".")
		var de *net.DNSError
		if err != nil && !(errors.As(err, &de) && de.IsNotFound) {
			return false, err
		}
		if !slicesHas(txts, value) {
			return false, nil
		}
		asked++
	}
	if asked == 0 {
		return false, errors.New("the name servers of " + name + " have no address")
	}
	return true, nil
}

// ---- DNS-01 through Cloudflare (the DDNS client's cfCall, same token kind) ----

type cfDNS01 struct {
	hc    *http.Client
	token string
	zones map[string]string // zone name -> id
}

// zoneFor finds the zone of host: the longest suffix (at least two labels) the token can see.
func (p *cfDNS01) zoneFor(ctx context.Context, host string) (string, error) {
	labels := strings.Split(host, ".")
	for i := 0; i+2 <= len(labels); i++ {
		z := strings.Join(labels[i:], ".")
		if id, ok := p.zones[z]; ok {
			return id, nil
		}
		var zs []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}
		if err := cfCall(ctx, p.hc, p.token, "GET", "/zones", url.Values{"name": {z}}, nil, &zs); err != nil {
			return "", err
		}
		for _, x := range zs {
			if strings.EqualFold(x.Name, z) && reCFID.MatchString(x.ID) {
				p.zones[z] = x.ID
				return x.ID, nil
			}
		}
	}
	return "", &ddnsError{msg: "Cloudflare: no zone for " + host + " (does the token cover it?)"}
}

func (p *cfDNS01) present(ctx context.Context, name, value string) (func(context.Context), error) {
	zone, err := p.zoneFor(ctx, strings.TrimPrefix(name, "_acme-challenge."))
	if err != nil {
		return nil, err
	}
	var rec cfRecord
	body := map[string]any{"type": "TXT", "name": name, "content": value, "ttl": 120}
	if err := cfCall(ctx, p.hc, p.token, "POST", "/zones/"+zone+"/dns_records", nil, body, &rec); err != nil {
		return nil, err
	}
	if !reCFID.MatchString(rec.ID) {
		return nil, &ddnsError{msg: "Cloudflare: unexpected answer"}
	}
	return func(ctx context.Context) {
		if err := cfCall(ctx, p.hc, p.token, "DELETE", "/zones/"+zone+"/dns_records/"+rec.ID, nil, nil, nil); err != nil {
			logf("edge: could not delete the TXT record %s: %s", name, ddnsErrText(err))
		}
	}, nil
}

// ---- storage ----

// edgeCertInfo: what a stored certificate says (read as root by renew / status: never the key).
type edgeCertInfo struct {
	Domains   []string
	NotBefore time.Time
	NotAfter  time.Time
	Issuer    string
	Staging   bool
}

func edgeCertPath(name string) string { return filepath.Join(edgeCertDir, name+".pem") }

// edgeOpenOwn opens a file in the service user's certificate directory for root: never through a
// symlink, never blocking on a FIFO, regular files only.
func edgeOpenOwn(p string, flag int) (*os.File, error) {
	f, err := os.OpenFile(p, flag|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("%s is not a regular file", p)
	}
	return f, nil
}

// edgeReadCert parses the leaf of <name>.pem.
func edgeReadCert(name string) (*edgeCertInfo, error) {
	f, err := edgeOpenOwn(edgeCertPath(name), os.O_RDONLY)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 1<<20))
	if err != nil {
		return nil, err
	}
	for rest := data; ; {
		var b *pem.Block
		if b, rest = pem.Decode(rest); b == nil {
			return nil, errors.New("no certificate in " + name + ".pem")
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		leaf, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, err
		}
		return &edgeCertInfo{Domains: leaf.DNSNames, NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter,
			Issuer: leaf.Issuer.CommonName, Staging: strings.HasPrefix(leaf.Issuer.CommonName, "(STAGING)")}, nil
	}
}

// edgeDue: whether ct must be (re)issued now, and why.
func edgeDue(ct edgeCert, info *edgeCertInfo, staging bool, now time.Time) (bool, string) {
	switch {
	case info == nil:
		return true, "missing"
	case !sameSet(info.Domains, ct.Domains):
		return true, "names changed"
	case info.Staging != staging:
		return true, "other CA"
	case !now.Before(info.NotAfter):
		return true, "expired"
	case info.NotAfter.Sub(now) < info.NotAfter.Sub(info.NotBefore)/3:
		return true, "due"
	}
	return false, "ok"
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x, y := append([]string{}, a...), append([]string{}, b...)
	sort.Strings(x)
	sort.Strings(y)
	for i := range x {
		if !strings.EqualFold(x[i], y[i]) {
			return false
		}
	}
	return true
}

// edgeAnyDue: a cheap local check (no network) whether a renewal run would do something.
func edgeAnyDue(c *Config) bool {
	for _, ct := range edgeCerts(c) {
		info, _ := edgeReadCert(ct.Name)
		if due, _ := edgeDue(ct, info, c.Services.Edge.ACME.Staging, edgeNow()); due {
			return true
		}
	}
	return false
}

// edgeServiceUser: uid / gid of the service user (-1 without one: the service runs as root).
var edgeServiceUser = func() (int, int) {
	u, err := user.Lookup(edgeUser)
	if err != nil {
		return -1, -1
	}
	uid, e1 := strconv.Atoi(u.Uid)
	gid, e2 := strconv.Atoi(u.Gid)
	if e1 != nil || e2 != nil {
		return -1, -1
	}
	return uid, gid
}

// edgePrepare: the certificate directory exists, is a real directory (0700) and it and every .pem in
// it belong to the service user, who can reach it. Run as root by the init script before the
// unprivileged start (and by renew before it writes).
func edgePrepare() error {
	uid, gid := edgeServiceUser()
	if err := os.MkdirAll(filepath.Dir(edgeCertDir), 0755); err != nil {
		return err
	}
	if uid > 0 {
		for d := filepath.Dir(edgeCertDir); d != "/" && d != "."; d = filepath.Dir(d) {
			if fi, err := os.Stat(d); err == nil && fi.Mode().Perm()&0o001 == 0 {
				return fmt.Errorf("%s: the service user %s cannot reach %s (chmod o+x %s)", d, edgeUser, edgeCertDir, d)
			}
		}
	}
	if err := os.Mkdir(edgeCertDir, 0700); err != nil && !os.IsExist(err) {
		return err
	}
	fi, err := os.Lstat(edgeCertDir)
	if err != nil || !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", edgeCertDir)
	}
	if err := os.Chmod(edgeCertDir, 0700); err != nil {
		return err
	}
	if uid < 0 {
		uid, gid = 0, 0
	}
	if err := os.Lchown(edgeCertDir, uid, gid); err != nil {
		return err
	}
	ents, _ := os.ReadDir(edgeCertDir)
	for _, e := range ents {
		if !e.Type().IsRegular() || !strings.HasSuffix(e.Name(), ".pem") {
			continue
		}
		if f, err := edgeOpenOwn(filepath.Join(edgeCertDir, e.Name()), os.O_RDONLY); err == nil {
			f.Chown(uid, gid)
			f.Chmod(0600)
			f.Close()
		}
	}
	return nil
}

// edgeSave writes <name>.pem atomically: 0600, owned by the service user, never through a symlink.
func edgeSave(name string, data []byte) error {
	if err := edgePrepare(); err != nil {
		return err
	}
	uid, gid := edgeServiceUser()
	tmp := filepath.Join(edgeCertDir, "."+name+".tmp")
	os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil && uid >= 0 {
		err = f.Chown(uid, gid)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, edgeCertPath(name))
}

// edgeAccountKey loads (or creates) the account key for a CA directory: root only.
func edgeAccountKey(dirURL string) (*ecdsa.PrivateKey, error) {
	h := sha256.Sum256([]byte(dirURL))
	p := filepath.Join(edgeAcctDir, "account-"+hex.EncodeToString(h[:6])+".key")
	if err := os.MkdirAll(edgeAcctDir, 0700); err != nil {
		return nil, err
	}
	os.Chmod(edgeAcctDir, 0700)
	if f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW, 0); err == nil {
		data, _ := io.ReadAll(io.LimitReader(f, 64<<10))
		f.Close()
		if b, _ := pem.Decode(data); b != nil && b.Type == "EC PRIVATE KEY" {
			if k, err := x509.ParseECPrivateKey(b.Bytes); err == nil {
				return k, nil
			}
		}
		return nil, fmt.Errorf("%s: not an EC private key (move it away to start a new account)", p)
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, _ := x509.MarshalECPrivateKey(k)
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	err = pem.Encode(f, &pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return k, err
}

// edgeSignalServe sends SIGHUP to the running `mr edge serve` (pid from its status file, checked
// against /proc so a reused pid is never signalled).
func edgeSignalServe() {
	st, err := edgeReadRun()
	if err != nil || !pidAlive(st.PID) {
		return
	}
	cmd, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", st.PID))
	if bytes.Contains(cmd, []byte("edge\x00serve")) {
		syscall.Kill(st.PID, syscall.SIGHUP)
	}
}

// ---- renewal ----

// edgeCertState: one certificate's renewal results (tmpfs).
type edgeCertState struct {
	Name    string `json:"name"`
	Config  string `json:"config,omitempty"` // fingerprint of domains + CA + token: a change starts afresh
	LastTry int64  `json:"last_try,omitempty"`
	LastOK  int64  `json:"last_ok,omitempty"` // last issued
	Error   string `json:"error,omitempty"`
	ErrorAt int64  `json:"error_at,omitempty"`
	Fails   int    `json:"fails,omitempty"`
	Retry   int64  `json:"retry,omitempty"` // no automatic attempt before
}

func edgeFingerprint(ct edgeCert, staging bool, token string) string {
	h := sha256.Sum256([]byte(strings.Join(append([]string{strconv.FormatBool(staging), token}, ct.Domains...), "\x00")))
	return hex.EncodeToString(h[:8])
}

func edgeLoadState() map[string]*edgeCertState {
	m := map[string]*edgeCertState{}
	if b, err := os.ReadFile(edgeStateFile); err == nil {
		json.Unmarshal(b, &m)
	}
	for k, v := range m {
		if v == nil {
			delete(m, k)
		}
	}
	return m
}

// edgeBackoff: hours until the next automatic attempt after the n-th failure in a row (1, 2, 4 … 24).
func edgeBackoff(n int) int64 {
	if n < 1 {
		n = 1
	}
	if n > 5 {
		return 24
	}
	return min(int64(1)<<(n-1), 24)
}

type edgeRenewOpts struct {
	force bool     // reissue even certificates that are not due
	auto  bool     // cron / hook: respect the backoff
	names []string // only these certificates (default: all)
}

// edgeRenew brings every certificate the routes need up to date. It returns the certificates' status.
func edgeRenew(c *Config, o edgeRenewOpts) ([]edgeCertStatus, error) {
	lk := flock(edgeLockFile, true)
	if lk == nil {
		return nil, errors.New("cannot lock " + edgeLockFile)
	}
	defer lk.Close()
	a := c.Services.Edge.ACME
	tok, _ := c.Secret(a.Token)
	st := edgeLoadState()
	only := map[string]bool{}
	for _, n := range o.names {
		only[n] = true
	}
	keep := map[string]bool{}
	var cl *acmeClient
	var dns dns01
	var setupErr error
	issued := false
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	for _, ct := range edgeCerts(c) {
		keep[ct.Name] = true
		fp := edgeFingerprint(ct, a.Staging, tok)
		s := st[ct.Name]
		if s == nil || s.Config != fp {
			s = &edgeCertState{Name: ct.Name, Config: fp}
			st[ct.Name] = s
		}
		if len(only) > 0 && !only[ct.Name] {
			continue
		}
		now := edgeNow()
		info, _ := edgeReadCert(ct.Name)
		due, why := edgeDue(ct, info, a.Staging, now)
		if !due && !o.force {
			continue
		}
		if !due {
			why = "forced"
		}
		if o.auto && now.Unix() < s.Retry {
			continue
		}
		if cl == nil && setupErr == nil {
			cl, dns, setupErr = edgeSetup(ctx, c)
		}
		s.LastTry = now.Unix()
		var pemData []byte
		err := setupErr
		if err == nil {
			logf("edge: requesting a certificate for %s (%s)", strings.Join(ct.Domains, ", "), why)
			pemData, err = acmeIssue(ctx, cl, dns, ct.Domains)
		}
		if err == nil {
			err = edgeSave(ct.Name, pemData)
		}
		if err != nil {
			msg := ddnsErrText(err)
			if msg != s.Error {
				logf("edge: certificate %s: %s", ct.Name, msg)
				edgeEvent(c, "warn", ct.Name, "certificate "+strings.Join(ct.Domains, ", ")+" not issued: "+msg)
			}
			s.Error, s.ErrorAt = msg, now.Unix()
			s.Fails++
			retry := 3600 * edgeBackoff(s.Fails)
			var p *acmeProblem
			if errors.As(err, &p) && p.retry > 0 && int64(p.retry/time.Second) > retry {
				retry = int64(p.retry / time.Second)
			}
			s.Retry = now.Unix() + retry
			continue
		}
		info, _ = edgeReadCert(ct.Name)
		until := ""
		if info != nil {
			until = info.NotAfter.Format("2006-01-02")
		}
		logf("edge: certificate %s issued (valid until %s)", ct.Name, until)
		edgeEvent(c, "info", ct.Name, "certificate "+strings.Join(ct.Domains, ", ")+" issued, valid until "+until)
		s.LastOK = now.Unix()
		s.Error, s.ErrorAt, s.Fails, s.Retry = "", 0, 0, 0
		issued = true
	}
	for k := range st {
		if !keep[k] {
			delete(st, k)
		}
	}
	b, _ := json.MarshalIndent(st, "", " ")
	if err := writeAtomic(edgeStateFile, b, 0600); err != nil {
		logf("edge: %v", err)
	}
	edgePrune(keep)
	if issued {
		edgeSignal()
	}
	return edgeStatusCerts(c, st), nil
}

// edgeSetup: the account key, the ACME account and the DNS provider.
func edgeSetup(ctx context.Context, c *Config) (*acmeClient, dns01, error) {
	a := c.Services.Edge.ACME
	dirURL := edgeDirectory(a.Staging)
	key, err := edgeAccountKey(dirURL)
	if err != nil {
		return nil, nil, err
	}
	dns, err := edgeDNS01For(c)
	if err != nil {
		return nil, nil, err
	}
	cl, err := acmeOpen(ctx, ddnsHTTP(), dirURL, key, a.Email)
	return cl, dns, err
}

// edgePrune removes certificates no route needs any more (only <name>.pem files mr wrote).
func edgePrune(keep map[string]bool) {
	ents, _ := os.ReadDir(edgeCertDir)
	for _, e := range ents {
		name, ok := strings.CutSuffix(e.Name(), ".pem")
		if ok && e.Type().IsRegular() && !keep[name] && (edgeHostOK(name) || edgeHostOK(strings.TrimPrefix(name, "_."))) {
			os.Remove(filepath.Join(edgeCertDir, e.Name()))
		}
	}
}

// ---- status, API, CLI ----

// edgeCertStatus: one certificate as status / the API show it (never a key).
type edgeCertStatus struct {
	Name      string   `json:"name"`
	Domains   []string `json:"domains"`
	State     string   `json:"state"` // ok | due | missing | expired | names changed | other CA
	NotBefore int64    `json:"not_before,omitempty"`
	NotAfter  int64    `json:"not_after,omitempty"`
	Issuer    string   `json:"issuer,omitempty"`
	LastTry   int64    `json:"last_try,omitempty"`
	LastOK    int64    `json:"last_ok,omitempty"`
	Error     string   `json:"error,omitempty"`
	ErrorAt   int64    `json:"error_at,omitempty"`
	Retry     int64    `json:"retry,omitempty"`
}

func edgeStatusCerts(c *Config, st map[string]*edgeCertState) []edgeCertStatus {
	out := []edgeCertStatus{}
	a := c.Services.Edge.ACME
	tok, _ := c.Secret(a.Token)
	for _, ct := range edgeCerts(c) {
		r := edgeCertStatus{Name: ct.Name, Domains: ct.Domains}
		info, _ := edgeReadCert(ct.Name)
		_, r.State = edgeDue(ct, info, a.Staging, edgeNow())
		if info != nil {
			r.NotBefore, r.NotAfter, r.Issuer = info.NotBefore.Unix(), info.NotAfter.Unix(), info.Issuer
		}
		if s := st[ct.Name]; s != nil && s.Config == edgeFingerprint(ct, a.Staging, tok) {
			r.LastTry, r.LastOK, r.Error, r.ErrorAt, r.Retry = s.LastTry, s.LastOK, s.Error, s.ErrorAt, s.Retry
		}
		out = append(out, r)
	}
	return out
}

// edgeStatus: everything the web UI's card and `mr edge status` show.
func edgeStatus(c *Config) map[string]any {
	e := c.Services.Edge
	run, rerr := edgeReadRun()
	serving := rerr == nil && pidAlive(run.PID)
	routes := []map[string]any{}
	for _, r := range edgeRoutes(c) {
		x := map[string]any{"name": r.Name, "host": r.Host, "to": r.To, "allow": r.Allow,
			"cert": edgeCertFor(e.ACME, r.Host).Name, "wan": edgeWANReachable(c, r)}
		if serving {
			s := run.Routes[r.Name]
			x["requests"], x["errors"], x["denied"] = s.Requests, s.Errors, s.Denied
		}
		routes = append(routes, x)
	}
	renewing := false
	if f := ddnsTryLock(edgeLockFile); f != nil {
		f.Close()
	} else {
		renewing = true
	}
	out := map[string]any{"enabled": edgeOn(c), "port": e.Port, "open": e.Open, "staging": e.ACME.Staging,
		"serving": serving, "routes": routes, "certs": edgeStatusCerts(c, edgeLoadState()), "renewing": renewing}
	if serving {
		out["started"] = run.Started
	}
	return out
}

// edgeSummary for `mr status`: counts and the certificates that need attention.
func edgeSummary(c *Config) map[string]any {
	type bad struct {
		Name  string `json:"name"`
		State string `json:"state"`
		Error string `json:"error,omitempty"`
	}
	certs := edgeStatusCerts(c, edgeLoadState())
	ok := 0
	errs := []bad{}
	for _, x := range certs {
		if x.State == "ok" && x.Error == "" {
			ok++
		} else if x.State != "due" || x.Error != "" {
			errs = append(errs, bad{x.Name, x.State, x.Error})
		}
	}
	return map[string]any{"routes": len(edgeRoutes(c)), "certs": len(certs), "ok": ok, "errors": errs}
}

// edgeCommand: `mr edge status | renew [--force] [--cron|--hook] [CERT...] | prepare`
// (`mr edge serve` runs without the config: main.go).
func edgeCommand(c *Config, args []string) error {
	usage := errors.New("usage: mr edge status | renew [--force] [--cron|--hook] [CERT...] | serve [-c FILE]")
	if len(args) == 0 {
		return usage
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", " ")
	switch args[0] {
	case "status":
		return enc.Encode(edgeStatus(c))
	case "prepare":
		return edgePrepare()
	case "renew":
		if !edgeOn(c) {
			if len(args) > 1 && (args[1] == "--cron" || args[1] == "--hook") {
				return nil
			}
			return errors.New("services.edge is off")
		}
		o := edgeRenewOpts{}
		known := map[string]bool{}
		for _, ct := range edgeCerts(c) {
			known[ct.Name] = true
		}
		for _, x := range args[1:] {
			switch {
			case x == "--force" || x == "-f":
				o.force = true
			case x == "--cron":
				o.auto = true
			case x == "--hook":
				o.auto = true
				// after an apply: one at a time, and never behind a running one
				f := ddnsTryLock(edgeLockFile)
				if f == nil {
					return nil
				}
				f.Close()
			case known[x]:
				o.names = append(o.names, x)
			default:
				return fmt.Errorf("no certificate %q (mr edge status lists them)", x)
			}
		}
		certs, err := edgeRenew(c, o)
		if err != nil {
			return err
		}
		if o.auto {
			return nil
		}
		return enc.Encode(certs)
	}
	return usage
}

// apiSysEdge: GET → edgeStatus (routes with request counts, certificates, renewal results).
func apiSysEdge(r apiReq) apiResp {
	c, err := loadConfig(ConfigPath, SecretsPath)
	if err != nil {
		return errResp(500, "%v", err)
	}
	return apiResp{body: edgeStatus(c)}
}

// apiSysEdgeRenew: POST {} starts a renewal of what is due or missing now (ignoring the backoff) in the
// background; the card polls sys.edge (renewing) for the result.
func apiSysEdgeRenew(r apiReq) apiResp {
	if r.method != "POST" {
		return errResp(405, "POST required")
	}
	c, err := loadConfig(ConfigPath, SecretsPath)
	if err != nil {
		return errResp(500, "%v", err)
	}
	if !edgeOn(c) {
		return errResp(409, "the reverse proxy is off (apply a config with services.edge first)")
	}
	if f := ddnsTryLock(edgeLockFile); f == nil {
		return errResp(409, "a renewal is running")
	} else {
		f.Close()
	}
	self, args := selfCmd("edge", "renew")
	edgeStart(self, args...)
	return apiResp{body: map[string]any{"started": true}}
}

// edgeStart runs a detached command (a variable: tests never start processes).
var edgeStart = startDetached
