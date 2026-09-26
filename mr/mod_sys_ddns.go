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
// provider when they differ: an unchanged address costs no network request (a url: source costs its
// lookup). Failures back off (1, 2, 4 … 60 minutes); refused credentials (401 / 403) stop the record
// until its config or secret changes (立即更新 still tries). A DDNS failure never fails or rolls back an
// apply. A published change, a record that keeps failing and its recovery become `ddns` events (the
// notify channels deliver them).
//
// Values (mod_sys_ddns_src.go): A = the WAN's IPv4 address (`active`: the healthy WAN with the lowest
// metric that has a public address; or a named WAN), an external lookup (url:), a LAN device (mac:) or
// a fixed address; AAAA = `router` (the router's own global address: the main LAN's address from the
// delegated prefix, else a WAN's), `::IID` (that interface ID on the main LAN's delegated /64), url:,
// mac: or fixed. Private and CGNAT IPv4 addresses are never published.
//
// Providers: one function each in ddnsProviders. Cloudflare API v4 (here; API token, permission Zone ›
// DNS › Edit): only the content (and the TTL when configured) of existing records is changed —
// proxied, comments and tags stay; a missing record is created (not proxied). AliDNS and DNSPod
// (signed APIs, mod_sys_ddns_sign.go) likewise keep line, status and TTL. DuckDNS, dyndns2 and a
// webhook (mod_sys_ddns_url.go) only send the address. Records are never deleted. HTTPS verifies the
// certificate against the system CA bundle, never follows a redirect; secrets are sent only where the
// provider wants them (a header, a signature, DuckDNS' query) and never logged or returned; answers
// are capped at 1 MiB.
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

// DDNSRecord is one host name kept pointing at the router (A and / or AAAA). Which of the provider
// keys a record needs depends on its provider (ddnsKeys); secrets are always names of secrets.yaml
// entries (*_secret).
type DDNSRecord struct {
	Name     string `yaml:"name"`                      // host name, e.g. home.example.com (or *.example.com)
	Provider string `yaml:"provider,omitempty"`        // cloudflare (default) | alidns | dnspod | duckdns | dyndns2 | webhook
	Zone     string `yaml:"zone,omitempty"`            // cloudflare, alidns, dnspod: the zone at the provider, e.g. example.com
	Token    string `yaml:"token_secret,omitempty"`    // Cloudflare API token, DuckDNS token, webhook token (optional)
	KeyID    string `yaml:"key_id,omitempty"`          // alidns: AccessKey ID; dnspod: SecretId (identifiers, not secret)
	Key      string `yaml:"key_secret,omitempty"`      // alidns: AccessKey secret; dnspod: SecretKey
	URL      string `yaml:"url,omitempty"`             // dyndns2: update URL; webhook: URL with {name} {type} {ip} {token}
	Username string `yaml:"username,omitempty"`        // dyndns2
	Password string `yaml:"password_secret,omitempty"` // dyndns2: password / update key
	Method   string `yaml:"method,omitempty"`          // webhook: GET (default) | POST
	IPv4     string `yaml:"ipv4,omitempty"`            // active (default) | <wan name> | off | url:https://… | mac:MAC | fixed address
	IPv6     string `yaml:"ipv6,omitempty"`            // off (default) | router | ::IID | url:https://… | mac:MAC | fixed address
	TTL      int    `yaml:"ttl,omitempty"`             // cloudflare, alidns, dnspod: 60-86400 s; 0 = the provider's default / the record's
}

// ddnsKeys: the keys (besides name, ipv4, ipv6) each provider takes; validation refuses the others, so
// a record never silently carries a key its provider ignores.
var ddnsKeys = map[string][]string{
	"cloudflare": {"zone", "token_secret", "ttl"},
	"alidns":     {"zone", "key_id", "key_secret", "ttl"},
	"dnspod":     {"zone", "key_id", "key_secret", "ttl"},
	"duckdns":    {"token_secret"},
	"dyndns2":    {"url", "username", "password_secret"},
	"webhook":    {"url", "method", "token_secret"},
}

const ddnsProviderList = "cloudflare | alidns | dnspod | duckdns | dyndns2 | webhook"

// ddnsSecretKey: the secrets.yaml entry a record authenticates with ("" = none: a webhook without token).
func ddnsSecretKey(r DDNSRecord) string {
	switch r.Provider {
	case "alidns", "dnspod":
		return r.Key
	case "dyndns2":
		return r.Password
	}
	return r.Token
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
// whether something changed). secret is the value of the record's secret (ddnsSecretKey); s.peer is
// the record's current address of the other type, for providers that set both in one request. A new
// provider is one more function here, its keys in ddnsKeys and its checks in validateDDNS.
var ddnsProviders = map[string]func(ctx context.Context, hc *http.Client, secret string, r DDNSRecord, typ, ip string, s *ddnsState) (bool, error){
	"cloudflare": cfUpsert,
	"alidns":     aliUpsert,
	"dnspod":     tcUpsert,
	"duckdns":    duckUpsert,
	"dyndns2":    dyn2Upsert,
	"webhook":    hookUpsert,
}

// ddnsBoth: providers whose update sets A and AAAA of a name in one request (both are sent when the
// record has both, so the provider never guesses the other one from the connection).
var ddnsBoth = map[string]bool{"duckdns": true, "dyndns2": true}

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
		if r.Provider == "webhook" && r.Method == "" {
			r.Method = "GET"
		}
	}
}

var (
	reDDNSSecret = lazyRegexp(`^[a-z0-9_-]{1,40}$`)
	reDDNSToken  = lazyRegexp(`^[A-Za-z0-9._~+/=-]{20,256}$`)
	reDDNSKeyID  = lazyRegexp(`^[A-Za-z0-9]{8,128}$`)
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
// AAAA records from the prefix (router, ::IID, mac:) or a lookup, "up" / "health" the A records from a
// WAN or a lookup (and an IPv6 lookup: a new PPP session can bring a new address); "down" none (there
// is nothing to publish then). Fixed values and IPv4 mac: never change with a WAN.
func ddnsUses(c *Config, event string) bool {
	for _, r := range c.Services.DDNS.Records {
		k4, k6 := ddnsKind(r.IPv4, false), ddnsKind(r.IPv6, true)
		switch event {
		case "ipv6":
			if k6 == "router" || k6 == "iid" || k6 == "mac" || k6 == "url" {
				return true
			}
		case "up", "health":
			if k4 == "active" || k4 == "wan" || k4 == "url" || (event == "up" && k6 == "url") {
				return true
			}
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

// ddnsSecretOK: a secret (or user name) that fits a header or a signature: min-max printable ASCII
// characters, no spaces.
func ddnsSecretOK(v string, min, max int) bool {
	if len(v) < min || len(v) > max {
		return false
	}
	for i := 0; i < len(v); i++ {
		if v[i] <= ' ' || v[i] > '~' {
			return false
		}
	}
	return true
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
		keys, known := ddnsKeys[r.Provider]
		if !known {
			v.Add("%s.provider: %s, got %q", p, ddnsProviderList, r.Provider)
		}
		uses := func(k string) bool { return slicesHas(keys, k) }
		if !validDNSName(host) || !strings.Contains(host, ".") {
			v.Add("%s.name: a host name like home.example.com (or *.example.com), got %q", p, r.Name)
		} else if seen[name] {
			v.Add("%s.name: duplicate %q", p, r.Name)
		} else if host != name && (r.Provider == "duckdns" || r.Provider == "dyndns2") {
			v.Add("%s.name: %s updates one host name, not %q", p, r.Provider, r.Name)
		} else if sub, ok := strings.CutSuffix(name, ".duckdns.org"); r.Provider == "duckdns" && (!ok || strings.Contains(sub, ".")) {
			v.Add("%s.name: a DuckDNS name like myhome.duckdns.org, got %q", p, r.Name)
		}
		seen[name] = true
		// every key the provider does not take stays empty
		set := map[string]bool{"zone": r.Zone != "", "token_secret": r.Token != "", "key_id": r.KeyID != "", "key_secret": r.Key != "",
			"url": r.URL != "", "username": r.Username != "", "password_secret": r.Password != "", "method": r.Method != "", "ttl": r.TTL != 0}
		for _, k := range []string{"zone", "token_secret", "key_id", "key_secret", "url", "username", "password_secret", "method", "ttl"} {
			if set[k] && known && !uses(k) {
				v.Add("%s.%s: not used by provider %s (it takes %s)", p, k, r.Provider, strings.Join(keys, ", "))
			}
		}
		if uses("zone") {
			if !validDNSName(zone) || strings.Contains(zone, "_") || !strings.Contains(zone, ".") {
				v.Add("%s.zone: the domain at the provider, e.g. example.com, got %q", p, r.Zone)
			} else if name != zone && !strings.HasSuffix(name, "."+zone) {
				v.Add("%s.name: %q is not inside zone %q", p, r.Name, r.Zone)
			}
		}
		// secret: field names a secrets.yaml entry whose value passes ok
		secret := func(field, key, what string, need bool, ok func(string) bool) {
			switch {
			case key == "" && !need:
			case !reDDNSSecret.MatchString(key):
				v.Add("%s.%s: secret name [a-z0-9_-]{1,40} required, got %q", p, field, key)
			default:
				if val, err := c.Secret(key); err != nil {
					v.Add("%s.%s: %v", p, field, err)
				} else if !ok(val) {
					v.Add("%s.%s: the secret is not %s", p, field, what)
				}
			}
		}
		token := func(s string) bool { return reDDNSToken.MatchString(s) }
		switch r.Provider {
		case "cloudflare":
			secret("token_secret", r.Token, "an API token (20-256 letters, digits, - _ . ~ + / =)", true, token)
		case "duckdns":
			secret("token_secret", r.Token, "a DuckDNS token (20-256 letters, digits, - _ . ~ + / =)", true, token)
		case "alidns", "dnspod":
			if !reDDNSKeyID.MatchString(r.KeyID) {
				v.Add("%s.key_id: the %s (8-128 letters and digits), got %q", p, map[string]string{"alidns": "AccessKey ID", "dnspod": "SecretId"}[r.Provider], r.KeyID)
			}
			secret("key_secret", r.Key, "an API key secret (16-128 printable characters, no spaces)", true, func(s string) bool { return ddnsSecretOK(s, 16, 128) })
		case "dyndns2":
			if pr := ddnsURLProblem(r.URL, false); pr != "" {
				v.Add("%s.url: the provider's update URL, e.g. https://dynupdate.no-ip.com/nic/update: %s", p, pr)
			}
			if !ddnsSecretOK(r.Username, 1, 128) || strings.Contains(r.Username, ":") {
				v.Add("%s.username: 1-128 printable characters without spaces or ':', got %q", p, r.Username)
			}
			secret("password_secret", r.Password, "a password (1-256 printable characters, no spaces)", true, func(s string) bool { return ddnsSecretOK(s, 1, 256) })
		case "webhook":
			if pr := ddnsURLProblem(r.URL, true); pr != "" {
				v.Add("%s.url: an https:// URL with {name} {type} {ip} (and {token}) placeholders: %s", p, pr)
			} else if strings.Contains(r.URL, "{token}") && r.Token == "" {
				v.Add("%s.url: {token} needs token_secret", p)
			}
			if r.Method != "GET" && r.Method != "POST" {
				v.Add("%s.method: GET | POST, got %q", p, r.Method)
			}
			secret("token_secret", r.Token, "a token (1-256 printable characters, no spaces)", false, func(s string) bool { return ddnsSecretOK(s, 1, 256) })
		}
		if ok, why := ddnsSrcOK(c, r.IPv4, false); !ok {
			v.Add("%s.ipv4: active | off | a WAN name | url:https://… | mac:MAC | a public IPv4 address, got %q%s", p, r.IPv4, why)
		}
		if ok, why := ddnsSrcOK(c, r.IPv6, true); !ok {
			v.Add("%s.ipv6: off | router | ::IID (a LAN device's interface ID, e.g. ::10) | url:https://… | mac:MAC | a global IPv6 address, got %q%s", p, r.IPv6, why)
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
		for _, k := range []string{r.Token, r.Key, r.Password} {
			if k != "" {
				out = append(out, k)
			}
		}
	}
	return out
}

// ddnsURLProblem: why raw is not a usable https URL ("" = fine). hook: the webhook's placeholders
// {name} {type} {ip} {token} are allowed. Credentials never go into a URL written in router.yaml.
func ddnsURLProblem(raw string, hook bool) string {
	if raw == "" {
		return "missing"
	}
	if len(raw) > 1024 {
		return "longer than 1024 characters"
	}
	for i := 0; i < len(raw); i++ {
		if b := raw[i]; b <= ' ' || b > '~' || strings.IndexByte("\"'\\<>`", b) >= 0 {
			return "spaces, quotes, non-ASCII or control characters"
		}
	}
	test := raw
	if hook {
		for _, ph := range []string{"{name}", "{type}", "{ip}", "{token}"} {
			test = strings.ReplaceAll(test, ph, "x")
		}
	}
	if strings.ContainsAny(test, "{}") {
		return "unknown placeholder"
	}
	u, err := url.Parse(test)
	switch {
	case err != nil || u.Scheme != "https" || u.Hostname() == "" || u.Opaque != "":
		return "not an https:// URL"
	case u.User != nil:
		return "no user:password@ in the URL"
	case strings.Contains(test, "#"):
		return "no #fragment"
	}
	return ""
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
	Type      string `json:"type"`               // A | AAAA
	Provider  string `json:"provider,omitempty"` // cloudflare | alidns | …
	Source    string `json:"source"`             // the ipv4 / ipv6 value: active | <wan> | router | ::IID | url:… | mac:… | address
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
	// internal (never shown): which config + secret this state belongs to (a change starts afresh), zone
	// id, whether the failure was reported as an event
	Config string `json:"config,omitempty"`
	ZoneID string `json:"zone_id,omitempty"`
	Warned bool   `json:"warned,omitempty"`
	// this run only: the record's current address of the other type (ddnsBoth providers send both);
	// done: already set by the other type's request
	peer string
	done bool
}

// view: what status / the API show of a state (no fingerprint, no zone id).
func (s ddnsState) view() ddnsState {
	s.Config, s.ZoneID, s.Warned = "", "", false
	return s
}

func ddnsKey(name, typ string) string { return ddnsName(name) + "/" + typ }

// ddnsFingerprint identifies the config a state was made for; the secret enters as a hash, and only
// the state file (root, tmpfs) keeps it.
func ddnsFingerprint(r DDNSRecord, typ, secret string) string {
	h := sha256.Sum256([]byte(strings.Join([]string{r.Provider, ddnsName(r.Zone), ddnsName(r.Name), typ, fmt.Sprint(r.TTL), secret,
		r.KeyID, r.URL, r.Username, r.Method}, "\x00")))
	return hex.EncodeToString(h[:8])
}

// ddnsSecret: the value of the record's secret ("" for a webhook without token).
func ddnsSecret(c *Config, r DDNSRecord) (string, error) { return c.Secret(ddnsSecretKey(r)) }

// ddnsSource: the configured value a state's address comes from.
func ddnsSource(r DDNSRecord, typ string) string {
	if typ == "AAAA" {
		return r.IPv6
	}
	return r.IPv4
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
	var ev ddnsEvents
	only := map[string]bool{}
	for _, n := range o.names {
		only[ddnsName(n)] = true
	}
	online, offline := &ddnsSrc{c: c, online: true}, &ddnsSrc{c: c}
	for _, r := range c.Services.DDNS.Records {
		if !ddnsOn(c) {
			break
		}
		sel := len(only) == 0 || only[ddnsName(r.Name)]
		tok, terr := ddnsSecret(c, r)
		types := ddnsTypes(r)
		ss := make([]*ddnsState, len(types))
		for i, typ := range types { // both addresses first: a provider may send them together
			key := ddnsKey(r.Name, typ)
			keep[key] = true
			fp := ddnsFingerprint(r, typ, tok)
			s := st[key]
			if s == nil || s.Config != fp {
				s = &ddnsState{Config: fp}
				st[key] = s
			}
			s.Name, s.Type, s.Provider, s.Source = ddnsName(r.Name), typ, r.Provider, ddnsSource(r, typ)
			src := offline // a record this run does not update looks nothing up
			if sel {
				src = online
			}
			s.Local, s.Note = src.local(r, typ, s)
			ss[i] = s
		}
		for i, typ := range types {
			s := ss[i]
			s.peer = ""
			if len(ss) == 2 {
				s.peer = ss[1-i].Local
			}
			if !sel || s.Local == "" {
				continue
			}
			// the daily check asks the provider whether the record still holds the address; a webhook has
			// nothing to ask (sending it again would repeat whatever it triggers)
			due := o.check || (o.daily && now-s.Checked >= 86400 && r.Provider != "webhook")
			if s.done || (s.Published == s.Local && !due) {
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
				ddnsFailed(s, uerr, now, tok)
				if !s.Warned && (s.Stopped || s.Fails >= ddnsWarnFails) {
					s.Warned = true
					ev.failing = append(ev.failing, s.Name+" "+typ+": "+s.Error)
				}
			} else {
				ddnsDone(s, changed, now, &ev)
				if p := ss[len(ss)-1-i]; ddnsBoth[r.Provider] && s.peer != "" && p != s { // the same request set the other type
					ddnsDone(p, changed && p.Published != p.Local, now, &ev)
					p.done = true
				}
			}
		}
		for _, s := range ss {
			out = append(out, *s)
		}
	}
	for k := range st {
		if !keep[k] {
			delete(st, k)
		}
	}
	ddnsSave(st)
	ev.send(c)
	for i := range out {
		out[i] = out[i].view()
	}
	return out, nil
}

// ddnsWarnFails: failures in a row (1 + 2 minutes of backoff) before a record becomes a warn event.
const ddnsWarnFails = 3

// ddnsDone records a successful update or check of s (changed: a record was written).
func ddnsDone(s *ddnsState, changed bool, now int64, ev *ddnsEvents) {
	if changed {
		s.Changed = now
		logf("ddns: %s %s -> %s", s.Name, s.Type, s.Local)
		msg := s.Name + " " + s.Type + " " + s.Local
		if s.Published != "" && s.Published != s.Local {
			msg += " (was " + s.Published + ")"
		}
		ev.changed = append(ev.changed, msg)
	} else if s.Published != s.Local {
		logf("ddns: %s %s already %s", s.Name, s.Type, s.Local)
	}
	if s.Error != "" {
		logf("ddns: %s %s works again", s.Name, s.Type)
	}
	if s.Warned {
		ev.again = append(ev.again, s.Name+" "+s.Type)
	}
	s.Published, s.LastOK, s.Checked = s.Local, now, now
	s.Error, s.ErrorAt, s.Retry, s.Stopped, s.Fails, s.Warned = "", 0, 0, false, 0, false
}

// ddnsEvents: what one sync reports to the event log (mod_sys_event.go, type ddns): at most one line
// each for the published changes (info), the records that started failing (warn: ddnsWarnFails in a
// row, or refused credentials) and the ones that work again (info).
type ddnsEvents struct{ changed, failing, again []string }

func (e ddnsEvents) send(c *Config) {
	key := func(l []string) string { n, _, _ := strings.Cut(l[0], " "); return n }
	if len(e.changed) > 0 {
		eventAdd(c, "ddns", "info", key(e.changed), "updated "+strings.Join(e.changed, "; "), true)
	}
	if len(e.failing) > 0 {
		eventAdd(c, "ddns", "warn", key(e.failing), "update failing: "+strings.Join(e.failing, "; "), true)
	}
	if len(e.again) > 0 {
		eventAdd(c, "ddns", "info", key(e.again), "updated again: "+strings.Join(e.again, "; "), true)
	}
}

func ddnsFailed(s *ddnsState, err error, now int64, secrets ...string) {
	msg := ddnsErrText(err, secrets...)
	if msg != s.Error {
		logf("ddns: %s %s: %s", s.Name, s.Type, msg)
	}
	var de *ddnsError
	s.Stopped = errors.As(err, &de) && de.auth
	s.Error, s.ErrorAt = msg, now
	s.Fails++
	s.Retry = now + 60*ddnsBackoff(s.Fails)
}

// ddnsStatus: the states without contacting anyone (local addresses as of now; a url: source shows
// the result of the last sync).
func ddnsStatus(c *Config) []ddnsState {
	st := ddnsLoad()
	out := []ddnsState{}
	if !ddnsOn(c) {
		return out
	}
	src := &ddnsSrc{c: c}
	for _, r := range c.Services.DDNS.Records {
		tok, _ := ddnsSecret(c, r)
		for _, typ := range ddnsTypes(r) {
			s := ddnsState{}
			if x := st[ddnsKey(r.Name, typ)]; x != nil && x.Config == ddnsFingerprint(r, typ, tok) {
				s = *x
			}
			s.Name, s.Type, s.Provider, s.Source = ddnsName(r.Name), typ, r.Provider, ddnsSource(r, typ)
			s.Local, s.Note = src.local(r, typ, &s)
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

// ---- providers: errors, HTTP; Cloudflare ----

// ddnsError is a failed update; auth = the credentials were refused (retrying cannot help).
type ddnsError struct {
	msg  string
	auth bool
	code string // the provider's error code (AliDNS, DNSPod), for callers that expect one
}

func (e *ddnsError) Error() string { return e.msg }

// ddnsCode: whether err is a provider error with this code.
func ddnsCode(err error, code string) bool {
	var de *ddnsError
	return errors.As(err, &de) && de.code == code
}

// ddnsErrText: one printable line without URLs (a request error names the URL, with its query) and
// without any form of the given secrets — replaced before the line is shortened, so no part of one
// is left.
func ddnsErrText(err error, secrets ...string) string {
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
	for _, x := range secrets {
		if x != "" {
			for _, v := range []string{x, url.QueryEscape(x), url.PathEscape(x)} {
				s = strings.ReplaceAll(s, v, "***")
			}
		}
	}
	if len(s) > 200 {
		cut := 200
		for cut > 0 && s[cut]&0xc0 == 0x80 {
			cut--
		}
		s = s[:cut]
	}
	return s
}

// ddnsTransport: no proxy from the environment, bounded waits and headers; TLS verified against the
// system CA bundle.
func ddnsTransport() *http.Transport {
	return &http.Transport{
		Proxy:                  nil,
		TLSHandshakeTimeout:    10 * time.Second,
		ResponseHeaderTimeout:  15 * time.Second,
		MaxResponseHeaderBytes: 64 << 10,
		IdleConnTimeout:        30 * time.Second,
	}
}

func ddnsNoRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// ddnsHTTP: HTTPS with the system CA bundle, no proxy from the environment, no redirects.
var ddnsHTTP = func() *http.Client {
	return &http.Client{Timeout: 20 * time.Second, Transport: ddnsTransport(), CheckRedirect: ddnsNoRedirect}
}

// ddnsRead: at most ddnsMaxBody bytes of an answer.
func ddnsRead(resp *http.Response) []byte {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, ddnsMaxBody))
	return b
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
