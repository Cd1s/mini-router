package main

// sys module: dynamic DNS (services.ddns), built into mr — nothing resident.
//
// When a sync runs:
//   - WAN events: the net hooks call Module.OnWAN (PPP up, DHCP bound / renew, dhcpcd RA / prefix,
//     multi-WAN failover); sys starts `mr ddns sync --hook` in the background. It waits 5 s (a PPP
//     reconnect brings IPv4, then RA, then the delegated prefix) with at most one waiter at a time,
//     and every sync holds a lock, so a burst of events costs one sync.
//   - crond runs `mr ddns sync --cron` every services.ddns.interval minutes (0 = WAN events only) as
//     the safety net for missed events and failed updates; it also asks the provider once a day
//     whether the record still holds the address (edited by hand?).
//   - an apply that leaves DDNS on starts one sync (new / changed records);
//   - `mr ddns update [--force]` and the web UI's 立即更新 run one at once.
//
// A sync compares the local address with the one last published (state below) and only calls the
// provider when they differ: an unchanged address costs no network request. Failures back off
// (1, 2, 4 … 60 minutes); refused credentials (401 / 403) stop the record until its config or token
// changes (立即更新 still tries). A DDNS failure never fails or rolls back an apply.
//
// Values: A = the WAN's IPv4 address (`active`: the healthy WAN with the lowest metric that has a
// public address; or a named WAN); AAAA = `router` (the router's own global address: the main LAN's
// address from the delegated prefix, else a WAN's) or `::IID` (that interface ID on the main LAN's
// delegated /64: a LAN device with a stable address; its inbound traffic still needs firewall.ipv6_allow).
// Private and CGNAT IPv4 addresses are never published.
//
// Provider: Cloudflare API v4 with an API token (permission Zone › DNS › Edit on the zone), token in
// secrets.yaml. Only the content (and the TTL when configured) of existing records is changed —
// proxied, comments and tags stay; a missing record is created (not proxied). Records are never
// deleted. HTTPS verifies the certificate against the system CA bundle; the token is sent only in the
// Authorization header and never logged or returned; answers are capped at 1 MiB.
//
// State (tmpfs, never flash): /run/mini-router/ddns.json — per record and type the local and the
// published address, times, last error, backoff. Lost on reboot: the first sync after boot asks
// the provider once per record.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// DDNS is services.ddns.
type DDNS struct {
	Enabled bool `yaml:"enabled"`
	// Interval: minutes between safety checks by crond (5-60); 0 = only WAN events. Default 10.
	Interval *int         `yaml:"interval,omitempty"`
	Records  []DDNSRecord `yaml:"records,omitempty"`
}

// DDNSRecord is one host name kept pointing at the router (A and / or AAAA).
type DDNSRecord struct {
	Name     string `yaml:"name"`               // host name, e.g. home.example.com (or *.example.com)
	Provider string `yaml:"provider,omitempty"` // cloudflare (default)
	Zone     string `yaml:"zone"`               // the zone at the provider, e.g. example.com
	Token    string `yaml:"token_secret"`       // secrets.yaml key of the API token
	IPv4     string `yaml:"ipv4,omitempty"`     // active (default) | <wan name> | off
	IPv6     string `yaml:"ipv6,omitempty"`     // off (default) | router | ::IID
	TTL      int    `yaml:"ttl,omitempty"`      // 60-86400 s; 0 = the provider's default (Cloudflare: automatic)
}

const (
	ddnsDefaultInterval = 10
	ddnsMaxBody         = 1 << 20
	ddnsDebounce        = 5 * time.Second
)

// runtime paths and hooks (variables so tests can use a temp dir / a fake API / no processes)
var (
	ddnsStateFile = RunDir + "/ddns.json"
	ddnsLockFile  = RunDir + "/ddns.lock"
	ddnsWaitFile  = RunDir + "/ddns.wait"
	cfAPIBase     = "https://api.cloudflare.com/client/v4"
	ddnsNow       = time.Now
	// ddnsKick starts a background `mr ddns sync --hook` unless one is already waiting.
	ddnsKick = func() {
		if f := ddnsTryLock(ddnsWaitFile); f != nil {
			f.Close() // the child takes it; two kicks at once: the second child finds it taken and exits
			self, args := selfCmd("ddns", "sync", "--hook")
			startDetached(self, args...)
		}
	}
	// ddnsAddrs6 lists dev's global IPv6 addresses usable as a DDNS value, preferred first.
	ddnsAddrs6 = ipGlobal6
)

// ddnsProviders: provider name -> upsert (make every record of that name and type hold ip; report
// whether something changed). A second provider is one more function here.
var ddnsProviders = map[string]func(ctx context.Context, hc *http.Client, token string, r DDNSRecord, typ, ip string, s *ddnsState) (bool, error){
	"cloudflare": cfUpsert,
}

func ddnsOn(c *Config) bool { return c.Services.DDNS.Enabled && len(c.Services.DDNS.Records) > 0 }

// ddnsInterval: minutes between crond runs (0 = none).
func ddnsInterval(c *Config) int {
	d := c.Services.DDNS
	if !ddnsOn(c) || d.Interval == nil {
		return 0
	}
	return *d.Interval
}

func ddnsDefaults(c *Config) {
	d := &c.Services.DDNS
	if d.Interval == nil && (d.Enabled || len(d.Records) > 0) { // absent section stays absent (plan / history)
		n := ddnsDefaultInterval
		d.Interval = &n
	}
	for i := range d.Records {
		r := &d.Records[i]
		if r.Provider == "" {
			r.Provider = "cloudflare"
		}
		if r.IPv4 == "" {
			r.IPv4 = "active"
		}
		if r.IPv6 == "" {
			r.IPv6 = "off"
		}
	}
}

var (
	reDDNSSecret = lazyRegexp(`^[a-z0-9_-]{1,40}$`)
	reDDNSToken  = lazyRegexp(`^[A-Za-z0-9._~+/=-]{20,256}$`)
	reCFID       = lazyRegexp(`^[0-9a-f]{32}$`)
)

// ddnsName: the record's name in lower case without a trailing dot; a leading "*." is allowed.
func ddnsName(s string) string { return strings.ToLower(strings.TrimSuffix(s, ".")) }

// ddnsIID parses "::IID": an IPv6 address with the upper 64 bits zero and a non-zero lower half.
func ddnsIID(s string) net.IP {
	if !strings.HasPrefix(s, "::") {
		return nil
	}
	ip := net.ParseIP(s)
	if ip == nil || ip.To4() != nil || strings.Contains(s, ".") {
		return nil
	}
	ip = ip.To16()
	for _, b := range ip[:8] {
		if b != 0 {
			return nil
		}
	}
	for _, b := range ip[8:] {
		if b != 0 {
			return ip
		}
	}
	return nil
}

// ddnsUses: whether a WAN event can change a value some record publishes: "ipv6" (RA, prefix) the
// AAAA records, "up" / "health" the A records; "down" none (there is nothing to publish then).
func ddnsUses(c *Config, event string) bool {
	for _, r := range c.Services.DDNS.Records {
		if (event == "ipv6" && r.IPv6 != "off") || ((event == "up" || event == "health") && r.IPv4 != "off") {
			return true
		}
	}
	return false
}

// ddnsTypes: the record types an entry keeps (A, AAAA).
func ddnsTypes(r DDNSRecord) []string {
	var t []string
	if r.IPv4 != "off" {
		t = append(t, "A")
	}
	if r.IPv6 != "off" {
		t = append(t, "AAAA")
	}
	return t
}

func validateDDNS(c *Config, v *Validator) {
	d := c.Services.DDNS
	if d.Interval != nil && *d.Interval != 0 && (*d.Interval < 5 || *d.Interval > 60) {
		v.Add("services.ddns.interval: 5-60 minutes, or 0 (only on WAN events), got %d", *d.Interval)
	}
	if len(d.Records) > 16 {
		v.Add("services.ddns.records: at most 16")
	}
	if d.Enabled && len(d.Records) == 0 {
		v.Add("services.ddns: enabled without records")
	}
	seen := map[string]bool{}
	for i, r := range d.Records {
		p := fmt.Sprintf("services.ddns.records[%d]", i)
		name, zone := ddnsName(r.Name), ddnsName(r.Zone)
		host := strings.TrimPrefix(name, "*.")
		if !validDNSName(host) || !strings.Contains(host, ".") {
			v.Add("%s.name: a host name like home.example.com (or *.example.com), got %q", p, r.Name)
		} else if seen[name] {
			v.Add("%s.name: duplicate %q", p, r.Name)
		}
		seen[name] = true
		if !validDNSName(zone) || strings.Contains(zone, "_") || !strings.Contains(zone, ".") {
			v.Add("%s.zone: the domain at the provider, e.g. example.com, got %q", p, r.Zone)
		} else if name != zone && !strings.HasSuffix(name, "."+zone) {
			v.Add("%s.name: %q is not inside zone %q", p, r.Name, r.Zone)
		}
		if ddnsProviders[r.Provider] == nil {
			v.Add("%s.provider: cloudflare, got %q", p, r.Provider)
		}
		if !reDDNSSecret.MatchString(r.Token) {
			v.Add("%s.token_secret: secret name [a-z0-9_-]{1,40} required, got %q", p, r.Token)
		} else if tok, err := c.Secret(r.Token); err != nil {
			v.Add("%s.token_secret: %v", p, err)
		} else if !reDDNSToken.MatchString(tok) {
			v.Add("%s.token_secret: the secret is not an API token (20-256 letters, digits, - _ . ~ + / =)", p)
		}
		switch r.IPv4 {
		case "active", "off":
		default:
			if !reName.MatchString(r.IPv4) || c.WANByName(r.IPv4) == nil {
				v.Add("%s.ipv4: active | off | a WAN name, got %q", p, r.IPv4)
			}
		}
		if r.IPv6 != "off" && r.IPv6 != "router" && ddnsIID(r.IPv6) == nil {
			v.Add("%s.ipv6: off | router | ::IID (a LAN device's interface ID, e.g. ::10), got %q", p, r.IPv6)
		}
		if r.IPv4 == "off" && r.IPv6 == "off" {
			v.Add("%s: ipv4 and ipv6 are both off", p)
		}
		if r.TTL != 0 && (r.TTL < 60 || r.TTL > 86400) {
			v.Add("%s.ttl: 60-86400 seconds or 0 (automatic), got %d", p, r.TTL)
		}
	}
}

func ddnsSecrets(c *Config) []string {
	var out []string
	for _, r := range c.Services.DDNS.Records {
		out = append(out, r.Token)
	}
	return out
}

// ---- local addresses ----

// ddnsIPv4 is the address for ipv4 = active | <wan>: from the lease record the net hooks write when a
// WAN comes up. note says why nothing is published (no address, private / CGNAT).
func ddnsIPv4(c *Config, src string) (ip, note string) {
	var ws []*WAN
	if src == "active" {
		ws = sortedWANs(c, wanHealthMap(c))
	} else if w := c.WANByName(src); w != nil {
		ws = []*WAN{w}
	}
	var notes []string
	for _, w := range ws {
		l, ok := readLease(w.Name)
		a := net.ParseIP(l.IP).To4()
		if !ok || a == nil || a.IsUnspecified() || a.IsLoopback() {
			continue
		}
		if cls := addrClass(a.String()); cls != "" {
			notes = append(notes, fmt.Sprintf("%s: %s address %s (behind another NAT), not published", w.Name, cls, a))
			continue
		}
		return a.String(), ""
	}
	if len(notes) == 0 {
		return "", "no WAN has an IPv4 address"
	}
	return "", strings.Join(notes, "; ")
}

// ddnsIPv6 is the address for ipv6 = router | ::IID.
func ddnsIPv6(c *Config, src string) (ip, note string) {
	lan := ddnsAddrs6(c.LAN.Bridge)
	if iid := ddnsIID(src); iid != nil {
		if len(lan) == 0 {
			return "", "no global IPv6 prefix on " + c.LAN.Bridge
		}
		a := make(net.IP, 16)
		copy(a, lan[0].To16()[:8])
		copy(a[8:], iid[8:])
		return a.String(), ""
	}
	if len(lan) > 0 {
		return lan[0].String(), ""
	}
	for _, w := range c.WAN {
		if w.IPv6 {
			if as := ddnsAddrs6(w.Ifname()); len(as) > 0 {
				return as[0].String(), ""
			}
		}
	}
	return "", "the router has no global IPv6 address"
}

func ddnsLocal(c *Config, r DDNSRecord, typ string) (string, string) {
	if typ == "A" {
		return ddnsIPv4(c, r.IPv4)
	}
	return ddnsIPv6(c, r.IPv6)
}

var ulaNet = &net.IPNet{IP: net.ParseIP("fc00::"), Mask: net.CIDRMask(7, 128)}

// ipGlobal6: `ip -j -6 addr show dev DEV scope global` without deprecated, tentative, failed,
// temporary (privacy) and ULA addresses.
func ipGlobal6(dev string) []net.IP {
	if !validDev(dev) {
		return nil
	}
	return parseGlobal6(ipJSON("-6", "addr", "show", "dev", dev, "scope", "global"))
}

func parseGlobal6(v any) []net.IP {
	var out []net.IP
	links, _ := v.([]any)
	for _, l := range links {
		m, _ := l.(map[string]any)
		infos, _ := m["addr_info"].([]any)
		for _, x := range infos {
			a, _ := x.(map[string]any)
			ip := net.ParseIP(fmt.Sprint(a["local"]))
			if ip == nil || ip.To4() != nil || !ip.IsGlobalUnicast() || ulaNet.Contains(ip) {
				continue
			}
			bad := false
			for _, f := range []string{"deprecated", "tentative", "dadfailed", "temporary"} {
				if b, _ := a[f].(bool); b {
					bad = true
				}
			}
			if pl, ok := a["preferred_life_time"].(float64); ok && pl == 0 {
				bad = true
			}
			if !bad {
				out = append(out, ip)
			}
		}
	}
	return out
}

// ---- state ----

// ddnsState is one record and type: what is on the router, what the provider has, and how the last
// attempts went.
type ddnsState struct {
	Name      string `json:"name"`
	Type      string `json:"type"`   // A | AAAA
	Source    string `json:"source"` // active | <wan> | router | ::IID
	Local     string `json:"local,omitempty"`
	Published string `json:"published,omitempty"` // what the provider held after the last successful update / check
	Note      string `json:"note,omitempty"`      // why there is no local address
	LastOK    int64  `json:"last_ok,omitempty"`   // last successful update or check
	Changed   int64  `json:"changed,omitempty"`   // last time a record was written
	Checked   int64  `json:"checked,omitempty"`   // last time the provider was asked
	Error     string `json:"error,omitempty"`
	ErrorAt   int64  `json:"error_at,omitempty"`
	Retry     int64  `json:"retry,omitempty"`   // no automatic attempt before
	Stopped   bool   `json:"stopped,omitempty"` // credentials refused: no automatic attempts until the config changes
	Fails     int    `json:"fails,omitempty"`
	// internal (never shown): which config + token this state belongs to (a change starts afresh), zone id
	Config string `json:"config,omitempty"`
	ZoneID string `json:"zone_id,omitempty"`
}

// view: what status / the API show of a state (no fingerprint, no zone id).
func (s ddnsState) view() ddnsState {
	s.Config, s.ZoneID = "", ""
	return s
}

func ddnsKey(name, typ string) string { return ddnsName(name) + "/" + typ }

// ddnsFingerprint identifies the config a state was made for; the token enters as a hash, and only
// the state file (root, tmpfs) keeps it.
func ddnsFingerprint(r DDNSRecord, typ, token string) string {
	h := sha256.Sum256([]byte(strings.Join([]string{r.Provider, ddnsName(r.Zone), ddnsName(r.Name), typ, fmt.Sprint(r.TTL), token}, "\x00")))
	return hex.EncodeToString(h[:8])
}

func ddnsLoad() map[string]*ddnsState {
	m := map[string]*ddnsState{}
	b, err := os.ReadFile(ddnsStateFile)
	if err == nil {
		json.Unmarshal(b, &m)
	}
	for k, s := range m {
		if s == nil {
			delete(m, k)
		}
	}
	return m
}

func ddnsSave(m map[string]*ddnsState) {
	b, _ := json.MarshalIndent(m, "", " ")
	if err := writeAtomic(ddnsStateFile, b, 0600); err != nil {
		logf("ddns: %v", err)
	}
}

// ddnsTryLock takes an exclusive flock on path without waiting (nil = someone else holds it).
func ddnsTryLock(path string) *os.File {
	os.MkdirAll(filepath.Dir(path), 0755)
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil
	}
	if syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		f.Close()
		return nil
	}
	return f
}

func ddnsLock() (*os.File, error) {
	os.MkdirAll(filepath.Dir(ddnsLockFile), 0755)
	f, err := os.OpenFile(ddnsLockFile, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// ddnsBackoff: minutes until the next automatic attempt after the n-th failure in a row.
func ddnsBackoff(n int) int64 {
	if n < 1 {
		n = 1
	}
	if n > 7 {
		return 60
	}
	return min(int64(1)<<(n-1), 60)
}

// ---- sync ----

// ddnsRun says what a sync may do.
type ddnsRun struct {
	retry bool     // ignore backoff and a refused-credentials stop (manual update)
	check bool     // ask the provider even when the state says the address is published (--force)
	daily bool     // ask the provider when the last check is a day old (cron)
	names []string // only these records (default: all)
}

// ddnsSync brings every record up to date and returns their states in config order.
func ddnsSync(c *Config, o ddnsRun) ([]ddnsState, error) {
	lk, err := ddnsLock()
	if err != nil {
		return nil, err
	}
	defer lk.Close()
	st := ddnsLoad()
	now := ddnsNow().Unix()
	keep := map[string]bool{}
	var out []ddnsState
	var hc *http.Client
	only := map[string]bool{}
	for _, n := range o.names {
		only[ddnsName(n)] = true
	}
	for _, r := range c.Services.DDNS.Records {
		if !ddnsOn(c) {
			break
		}
		for _, typ := range ddnsTypes(r) {
			key := ddnsKey(r.Name, typ)
			keep[key] = true
			tok, terr := c.Secret(r.Token)
			fp := ddnsFingerprint(r, typ, tok)
			s := st[key]
			if s == nil || s.Config != fp {
				s = &ddnsState{Config: fp}
				st[key] = s
			}
			s.Name, s.Type = ddnsName(r.Name), typ
			s.Source = r.IPv4
			if typ == "AAAA" {
				s.Source = r.IPv6
			}
			s.Local, s.Note = ddnsLocal(c, r, typ)
			out = append(out, *s)
			if (len(only) > 0 && !only[s.Name]) || s.Local == "" {
				continue
			}
			due := o.check || (o.daily && now-s.Checked >= 86400)
			if s.Published == s.Local && !due {
				continue
			}
			if !o.retry && (s.Stopped || now < s.Retry) {
				continue
			}
			upsert := ddnsProviders[r.Provider]
			var changed bool
			var uerr error
			switch {
			case terr != nil:
				uerr = &ddnsError{msg: terr.Error(), auth: true}
			case upsert == nil:
				uerr = &ddnsError{msg: "unknown provider " + r.Provider, auth: true}
			default:
				if hc == nil {
					hc = ddnsHTTP()
				}
				ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
				changed, uerr = upsert(ctx, hc, tok, r, typ, s.Local, s)
				cancel()
			}
			s.Checked = now
			if uerr != nil {
				ddnsFailed(s, uerr, now)
			} else {
				if changed {
					s.Changed = now
					logf("ddns: %s %s -> %s", s.Name, typ, s.Local)
				} else if s.Published != s.Local {
					logf("ddns: %s %s already %s", s.Name, typ, s.Local)
				}
				if s.Error != "" {
					logf("ddns: %s %s works again", s.Name, typ)
				}
				s.Published, s.LastOK = s.Local, now
				s.Error, s.ErrorAt, s.Retry, s.Stopped, s.Fails = "", 0, 0, false, 0
			}
			out[len(out)-1] = *s
		}
	}
	for k := range st {
		if !keep[k] {
			delete(st, k)
		}
	}
	ddnsSave(st)
	for i := range out {
		out[i] = out[i].view()
	}
	return out, nil
}

func ddnsFailed(s *ddnsState, err error, now int64) {
	msg := ddnsErrText(err)
	if msg != s.Error {
		logf("ddns: %s %s: %s", s.Name, s.Type, msg)
	}
	var de *ddnsError
	s.Stopped = errors.As(err, &de) && de.auth
	s.Error, s.ErrorAt = msg, now
	s.Fails++
	s.Retry = now + 60*ddnsBackoff(s.Fails)
}

// ddnsStatus: the states without contacting anyone (local addresses as of now).
func ddnsStatus(c *Config) []ddnsState {
	st := ddnsLoad()
	out := []ddnsState{}
	if !ddnsOn(c) {
		return out
	}
	for _, r := range c.Services.DDNS.Records {
		for _, typ := range ddnsTypes(r) {
			tok, _ := c.Secret(r.Token)
			s := ddnsState{}
			if x := st[ddnsKey(r.Name, typ)]; x != nil && x.Config == ddnsFingerprint(r, typ, tok) {
				s = *x
			}
			s.Name, s.Type = ddnsName(r.Name), typ
			s.Source = r.IPv4
			if typ == "AAAA" {
				s.Source = r.IPv6
			}
			s.Local, s.Note = ddnsLocal(c, r, typ)
			out = append(out, s.view())
		}
	}
	return out
}

// ddnsSummary for `mr status` (overview notice): counts and the records that fail.
func ddnsSummary(c *Config) map[string]any {
	type bad struct {
		Name    string `json:"name"`
		Type    string `json:"type"`
		Error   string `json:"error"`
		Stopped bool   `json:"stopped,omitempty"`
	}
	st := ddnsLoad()
	n, ok := 0, 0
	errs := []bad{}
	for _, r := range c.Services.DDNS.Records {
		for _, typ := range ddnsTypes(r) {
			n++
			if s := st[ddnsKey(r.Name, typ)]; s != nil {
				if s.Error != "" {
					errs = append(errs, bad{s.Name, typ, s.Error, s.Stopped})
				} else if s.Published != "" {
					ok++
				}
			}
		}
	}
	return map[string]any{"records": n, "ok": ok, "errors": errs}
}

// ---- provider: Cloudflare ----

// ddnsError is a failed update; auth = the credentials were refused (retrying cannot help).
type ddnsError struct {
	msg  string
	auth bool
}

func (e *ddnsError) Error() string { return e.msg }

// ddnsErrText: one printable line without URLs (a request error names the URL).
func ddnsErrText(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	s := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, err.Error())
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// ddnsHTTP: HTTPS with the system CA bundle, no proxy from the environment, no redirects.
var ddnsHTTP = func() *http.Client {
	return &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			Proxy:                  nil,
			TLSHandshakeTimeout:    10 * time.Second,
			ResponseHeaderTimeout:  15 * time.Second,
			MaxResponseHeaderBytes: 64 << 10,
			IdleConnTimeout:        30 * time.Second,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

type cfEnvelope struct {
	Success bool `json:"success"`
	Errors  []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
	Result json.RawMessage `json:"result"`
}

// cfAuthCodes: Cloudflare error codes that mean the token itself was refused.
var cfAuthCodes = map[int]bool{6003: true, 6111: true, 9103: true, 9106: true, 9109: true, 10000: true, 10001: true}

func (e cfEnvelope) text() string {
	if len(e.Errors) == 0 {
		return ""
	}
	return fmt.Sprintf(" (%d %s)", e.Errors[0].Code, e.Errors[0].Message)
}

// cfCall makes one API request; out receives "result".
func cfCall(ctx context.Context, hc *http.Client, token, method, path string, q url.Values, body, out any) error {
	u := cfAPIBase + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return &ddnsError{msg: "Cloudflare: bad request"}
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "mini-router-ddns/"+version)
	resp, err := hc.Do(req)
	if err != nil {
		return &ddnsError{msg: "Cloudflare: " + ddnsErrText(err)}
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, ddnsMaxBody))
	var e cfEnvelope
	jerr := json.Unmarshal(raw, &e)
	auth := resp.StatusCode == 401 || resp.StatusCode == 403
	for _, x := range e.Errors {
		auth = auth || cfAuthCodes[x.Code]
	}
	switch {
	case auth:
		return &ddnsError{msg: fmt.Sprintf("Cloudflare refused the token: HTTP %d%s", resp.StatusCode, ddnsErrText(errors.New(e.text()))), auth: true}
	case jerr != nil:
		return &ddnsError{msg: fmt.Sprintf("Cloudflare: HTTP %d, not an API answer", resp.StatusCode)}
	case resp.StatusCode/100 != 2 || !e.Success:
		return &ddnsError{msg: fmt.Sprintf("Cloudflare: HTTP %d%s", resp.StatusCode, ddnsErrText(errors.New(e.text())))}
	}
	if out != nil && json.Unmarshal(e.Result, out) != nil {
		return &ddnsError{msg: "Cloudflare: unexpected answer"}
	}
	return nil
}

type cfRecord struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
}

// cfUpsert makes every typ record named r.Name hold ip, creating one if there is none. The zone id
// is kept in the state; ids from the answers are checked before they go into a URL path.
func cfUpsert(ctx context.Context, hc *http.Client, token string, r DDNSRecord, typ, ip string, s *ddnsState) (bool, error) {
	name, zone := ddnsName(r.Name), ddnsName(r.Zone)
	if !reCFID.MatchString(s.ZoneID) {
		var zs []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}
		if err := cfCall(ctx, hc, token, "GET", "/zones", url.Values{"name": {zone}}, nil, &zs); err != nil {
			return false, err
		}
		s.ZoneID = ""
		for _, z := range zs {
			if strings.EqualFold(z.Name, zone) && reCFID.MatchString(z.ID) {
				s.ZoneID = z.ID
			}
		}
		if s.ZoneID == "" {
			return false, &ddnsError{msg: "Cloudflare: zone " + zone + " not found (does the token cover it?)"}
		}
	}
	base := "/zones/" + s.ZoneID + "/dns_records"
	var recs []cfRecord
	if err := cfCall(ctx, hc, token, "GET", base, url.Values{"type": {typ}, "name": {name}, "per_page": {"100"}}, nil, &recs); err != nil {
		s.ZoneID = "" // looked up again next time (zone moved / deleted)
		return false, err
	}
	var mine []cfRecord
	for _, x := range recs {
		if strings.EqualFold(strings.TrimSuffix(x.Name, "."), name) && x.Type == typ && reCFID.MatchString(x.ID) {
			mine = append(mine, x)
		}
	}
	ttl := r.TTL
	if len(mine) == 0 {
		if ttl == 0 {
			ttl = 1 // automatic
		}
		body := map[string]any{"type": typ, "name": name, "content": ip, "ttl": ttl, "proxied": false}
		return true, cfCall(ctx, hc, token, "POST", base, nil, body, nil)
	}
	want := net.ParseIP(ip)
	changed := false
	for _, x := range mine {
		if want.Equal(net.ParseIP(x.Content)) && (ttl == 0 || x.TTL == ttl) {
			continue
		}
		body := map[string]any{"content": ip}
		if ttl != 0 {
			body["ttl"] = ttl
		}
		if err := cfCall(ctx, hc, token, "PATCH", base+"/"+x.ID, nil, body, nil); err != nil {
			return changed, err
		}
		changed = true
	}
	return changed, nil
}

// ---- mr ddns, API ----

// ddnsCommand: `mr ddns status | update [--force] [NAME...] | sync [--hook|--cron]`.
func ddnsCommand(c *Config, args []string) error {
	usage := errors.New("usage: mr ddns status | update [--force] [NAME...] | sync [--hook|--cron]")
	if len(args) == 0 {
		return usage
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", " ")
	switch args[0] {
	case "status":
		return enc.Encode(ddnsStatus(c))
	case "update":
		o := ddnsRun{retry: true}
		for _, a := range args[1:] {
			switch {
			case a == "--force" || a == "-f":
				o.check = true
			case ddnsHas(c, a):
				o.names = append(o.names, a)
			default:
				return fmt.Errorf("no ddns record %q", a)
			}
		}
		if !ddnsOn(c) {
			return fmt.Errorf("services.ddns is off or has no records")
		}
		rows, err := ddnsSync(c, o)
		if err != nil {
			return err
		}
		return enc.Encode(rows)
	case "sync":
		if !ddnsOn(c) {
			return nil
		}
		o := ddnsRun{}
		if len(args) > 1 {
			switch args[1] {
			case "--hook":
				// debounce: one waiter at a time; the lock is released before the addresses are read,
				// so an event after this point starts the next waiter
				w := ddnsTryLock(ddnsWaitFile)
				if w == nil {
					return nil
				}
				time.Sleep(ddnsDebounce)
				w.Close()
			case "--cron":
				o.daily = true
			default:
				return usage
			}
		}
		_, err := ddnsSync(c, o)
		return err
	}
	return usage
}

func ddnsHas(c *Config, name string) bool {
	for _, r := range c.Services.DDNS.Records {
		if ddnsName(r.Name) == ddnsName(name) {
			return true
		}
	}
	return false
}

// apiSysDDNS: GET → {enabled, interval, records: states (local addresses as of now)}.
func apiSysDDNS(r apiReq) apiResp {
	c, err := loadConfig(ConfigPath, SecretsPath)
	if err != nil {
		return errResp(500, "%v", err)
	}
	return apiResp{body: map[string]any{"enabled": ddnsOn(c), "interval": ddnsInterval(c), "records": ddnsStatus(c)}}
}

// apiSysDDNSUpdate: POST {name (optional), force} updates now (ignoring backoff; force also asks the
// provider for records the state calls published) and returns the states.
func apiSysDDNSUpdate(r apiReq) apiResp {
	if r.method != "POST" {
		return errResp(405, "POST required")
	}
	var in struct {
		Name  string `json:"name"`
		Force bool   `json:"force"`
	}
	json.Unmarshal(r.body, &in)
	c, err := loadConfig(ConfigPath, SecretsPath)
	if err != nil {
		return errResp(500, "%v", err)
	}
	if !ddnsOn(c) {
		return errResp(409, "DDNS is off (apply a config with services.ddns first)")
	}
	o := ddnsRun{retry: true, check: in.Force}
	if in.Name != "" {
		if !ddnsHas(c, in.Name) {
			return errResp(400, "no ddns record %q", in.Name)
		}
		o.names = []string{in.Name}
	}
	rows, err := ddnsSync(c, o)
	if err != nil {
		return errResp(500, "%v", err)
	}
	return apiResp{body: map[string]any{"enabled": true, "interval": ddnsInterval(c), "records": rows}}
}

var cgnatNet = &net.IPNet{IP: net.IPv4(100, 64, 0, 0).To4(), Mask: net.CIDRMask(10, 32)}

// addrClass: "cgnat" (100.64/10) or "private" (RFC 1918, link-local) for an IPv4 address that is not
// reachable from the internet, "" for a public one (or not IPv4).
func addrClass(ip string) string {
	a := net.ParseIP(ip).To4()
	switch {
	case a == nil:
		return ""
	case cgnatNet.Contains(a):
		return "cgnat"
	case a.IsPrivate(), a.IsLinkLocalUnicast():
		return "private"
	}
	return ""
}
