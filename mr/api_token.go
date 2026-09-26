package main

// API tokens (Cd1s/mini-router#17): scripts, Home Assistant and AI agents call the web UI's API
// (`mr api`, CGI) with `Authorization: Bearer mrt_…` instead of a login.
//
//   - router.yaml `api.tokens` names each token and what it may do; secrets.yaml holds only its
//     SHA-256 (`api_token_<name>: sha256:<hex>`). The token itself (mrt_ + 32 random bytes) is shown
//     once — by `mr token create` or the web UI (generated in the browser, only the hash is sent) —
//     and never stored.
//   - Scopes, each including the ones before: read (status, config, monitoring, history), operate
//     (redial, kick a client, restart a service, proxy node choice), apply (plan, apply, confirm,
//     revert, rollback). `allow` narrows a token to some actions, `from` to source addresses,
//     `expires` ends it. Only the actions listed in tokenActions exist for tokens: never the password,
//     login, sessions, backup / restore, firmware, factory reset, reboot, logs or token management.
//   - A token's config changes cannot touch the token list, SSH access, sysctl or local file paths
//     (lockedChanges), settle a change it did not make, or set token hashes. Its applies are recorded
//     as via=api:<name>.
//   - Only the Authorization header counts (no cookie: no CSRF, no X-MR header needed). A bad token
//     counts against its source in the login throttle (api_login.go); a locked source is refused
//     without a check, valid token or not. Last use: /run (every request) and flash (hourly).

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
)

type APIConf struct {
	Tokens []APIToken `yaml:"tokens,omitempty"`
}

type APIToken struct {
	Name    string   `yaml:"name"`
	Scope   string   `yaml:"scope"`             // read | operate | apply (each includes the ones before)
	Allow   []string `yaml:"allow,omitempty"`   // only these actions ("mon.*": all mon.); empty = the whole scope
	From    []string `yaml:"from,omitempty"`    // source addresses / CIDRs; empty = any
	Expires string   `yaml:"expires,omitempty"` // YYYY-MM-DD (router time): valid until that day begins
}

const (
	tokenPrefix       = "mrt_"
	tokenSecretPrefix = "api_token_"
	maxTokens         = 32
)

var scopeLevel = map[string]int{"read": 1, "operate": 2, "apply": 3}

// tokenActions: every action a token can reach and the scope it needs: the core actions of apiAction
// below, plus what each module declares in Module.TokenScope (merged by register). Anything else is
// refused to tokens.
//
//	read     no side effects, no secrets
//	operate  runtime actions that do not change the config
//	apply    config changes, through plan → apply → confirm with automatic rollback
var tokenActions = map[string]string{
	"status": "read", "config": "read", "config.raw": "read", "history": "read", "history.diff": "read", "job": "read",
	"validate": "apply", "apply": "apply", "confirm": "apply", "revert": "apply", "rollback": "apply",
}

// tokenLocked: config a token can never change. The token list (a token could extend itself), SSH
// (keys and password logins are a root shell: the password, secrets, firmware), sysctl
// (kernel.core_pattern and kernel.modprobe run programs as root), the guard (the owner's baselines),
// notify (an agent must not silence or redirect the owner's alerts).
// Local file paths and items that reference secrets: see lockedChanges.
var tokenLocked = []string{"api", "services.ssh", "system.sysctl", "guard", "notify"}

// variables so tests can point them elsewhere
var (
	tokenUsedRun  = RunDir + "/api-used.json"
	tokenUsedDisk = "/etc/mini-router/state/api-used.json"
)

func init() {
	register(&Module{
		Name:     "api",
		Prio:     80,
		Validate: tokensValidate,
		Secrets: func(c *Config) []string {
			var out []string
			for _, t := range c.API.Tokens {
				out = append(out, tokenSecretPrefix+t.Name)
			}
			return out
		},
		TokenScope: map[string]string{"plan": "apply", "schema": "read"}, // "tokens" (last use): sessions only
		API: map[string]func(r apiReq) apiResp{
			"plan":   apiPlan,
			"schema": func(apiReq) apiResp { return apiResp{body: configSchema()} },
			"tokens": func(apiReq) apiResp { return apiResp{body: map[string]any{"used": tokenUses()}} },
		},
	})
}

var (
	reTokenHash  = lazyRegexp(`^sha256:[0-9a-f]{64}$`)
	reAllowEntry = lazyRegexp(`^(\*|[a-z][a-z0-9_]*(\.[a-z0-9_]+)*(\.\*)?)$`)
)

func tokensValidate(c *Config, v *Validator) {
	if len(c.API.Tokens) > maxTokens {
		v.Add("api.tokens: at most %d", maxTokens)
	}
	seen := map[string]bool{}
	for i, t := range c.API.Tokens {
		p := fmt.Sprintf("api.tokens[%d]", i)
		if !reName.MatchString(t.Name) {
			v.Add("%s.name: [a-z][a-z0-9_-]{0,14}, got %q", p, t.Name)
		} else {
			p = "api.tokens[" + t.Name + "]"
		}
		if seen[t.Name] {
			v.Add("%s: duplicate name", p)
		}
		seen[t.Name] = true
		if scopeLevel[t.Scope] == 0 {
			v.Add("%s.scope: read|operate|apply, got %q", p, t.Scope)
		}
		for _, a := range t.Allow {
			if !reAllowEntry.MatchString(a) {
				v.Add("%s.allow: action name or group.* expected, got %q", p, a)
				continue
			}
			ok := false
			for act := range tokenActions {
				ok = ok || (actionMatch(a, act) && scopeLevel[tokenActions[act]] <= scopeLevel[t.Scope])
			}
			if !ok && scopeLevel[t.Scope] > 0 {
				v.Add("%s.allow: %q matches no action of scope %s", p, a, t.Scope)
			}
		}
		if len(t.From) > 16 {
			v.Add("%s.from: at most 16 entries", p)
		}
		for _, f := range t.From {
			if parseNet(f) == nil {
				v.Add("%s.from: address or CIDR expected, got %q", p, f)
			}
		}
		if _, err := t.expiry(time.UTC); err != nil {
			v.Add("%s.expires: YYYY-MM-DD expected, got %q", p, t.Expires)
		}
		if !reTokenHash.MatchString(c.secrets[tokenSecretPrefix+t.Name]) {
			v.Add("%s: no token hash %s%s in secrets.yaml (create tokens with `mr token create` or the web UI)", p, tokenSecretPrefix, t.Name)
		}
	}
}

func actionMatch(pat, action string) bool {
	return pat == "*" || pat == action || (strings.HasSuffix(pat, ".*") && strings.HasPrefix(action, strings.TrimSuffix(pat, "*")))
}

// parseNet: a CIDR, or one address as a host network.
func parseNet(s string) *net.IPNet {
	if _, n, err := net.ParseCIDR(s); err == nil {
		return n
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return nil
	}
	if v4 := ip.To4(); v4 != nil {
		return &net.IPNet{IP: v4, Mask: net.CIDRMask(32, 32)}
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
}

// expiry: when the token stops working (zero: never).
func (t *APIToken) expiry(loc *time.Location) (time.Time, error) {
	if t.Expires == "" {
		return time.Time{}, nil
	}
	if d, err := time.ParseInLocation("2006-01-02", t.Expires, loc); err == nil {
		return d, nil
	}
	return time.Parse(time.RFC3339, t.Expires)
}

func (t *APIToken) fromOK(remote string) bool {
	if len(t.From) == 0 {
		return true
	}
	ip := net.ParseIP(remote)
	for _, f := range t.From {
		if n := parseNet(f); n != nil && ip != nil && n.Contains(ip) {
			return true
		}
	}
	return false
}

// permits: the token's scope and allow list cover action.
func (t *APIToken) permits(action string) bool {
	need, ok := tokenActions[action]
	if !ok || scopeLevel[t.Scope] < scopeLevel[need] {
		return false
	}
	if len(t.Allow) == 0 {
		return true
	}
	for _, a := range t.Allow {
		if actionMatch(a, action) {
			return true
		}
	}
	return false
}

func newToken() (tok, hash string) {
	b := make([]byte, 32)
	rand.Read(b)
	tok = tokenPrefix + base64.RawURLEncoding.EncodeToString(b)
	return tok, tokenHash(tok)
}

func tokenHash(tok string) string {
	s := sha256.Sum256([]byte(tok))
	return "sha256:" + hex.EncodeToString(s[:])
}

// findToken: the token whose hash matches presented (every entry compared in constant time).
func findToken(c *Config, presented string) *APIToken {
	if !strings.HasPrefix(presented, tokenPrefix) || len(presented) > 256 {
		return nil
	}
	h := []byte(tokenHash(presented))
	var found *APIToken
	for i := range c.API.Tokens {
		t := &c.API.Tokens[i]
		if subtle.ConstantTimeCompare(h, []byte(c.secrets[tokenSecretPrefix+t.Name])) == 1 {
			found = t
		}
	}
	return found
}

// tokenAuth checks the bearer token of r against config c: the token, or the answer to send.
func tokenAuth(r apiReq, c *Config, now time.Time) (*APIToken, *apiResp) {
	fail := func(code int, f string, a ...any) (*APIToken, *apiResp) { e := errResp(code, f, a...); return nil, &e }
	if wait := loginWait(r.remote); wait > 0 {
		return fail(429, "too many failed attempts from this address: try again in %d s", wait)
	}
	presented, ok := strings.CutPrefix(r.auth, "Bearer ")
	var t *APIToken
	if ok {
		t = findToken(c, strings.TrimSpace(presented))
	}
	if t == nil {
		ok, wait, fails, locked := loginBegin(r.remote) // counted only when bad: a valid token never clears a source
		if !ok {
			return fail(429, "too many failed attempts from this address: try again in %d s", wait)
		}
		switch {
		case locked > 0:
			logf("api: %d bad tokens / passwords from %s: locked for %s", loginMax, r.remote, locked)
			eventLoginLock(r.remote, "API tokens / passwords", locked)
		case fails == 1:
			logf("api: bad token from %s", r.remote)
		}
		return fail(401, "invalid API token (Authorization: Bearer mrt_…)")
	}
	if exp, _ := t.expiry(sysLocation(c)); !exp.IsZero() && !now.Before(exp) {
		return fail(401, "API token %s expired on %s", t.Name, t.Expires)
	}
	if !t.fromOK(r.remote) {
		logf("api: token %s used from %s (not in its from list)", t.Name, r.remote)
		return fail(403, "API token %s is not allowed from %s", t.Name, r.remote)
	}
	if !t.permits(r.action) {
		if _, known := tokenActions[r.action]; !known {
			return fail(403, "%q is not available to API tokens (web UI or SSH only)", r.action)
		}
		return fail(403, "API token %s (scope %s) may not use %q", t.Name, t.Scope, r.action)
	}
	return t, nil
}

// handleToken serves a request that carries an Authorization header.
func handleToken(r apiReq) apiResp {
	c, err := loadConfig(ConfigPath, SecretsPath)
	if err != nil {
		return errResp(500, "%v", err)
	}
	t, e := tokenAuth(r, c, time.Now())
	if e != nil {
		return *e
	}
	noteTokenUse(t.Name, r.remote)
	r.via = "api:" + t.Name
	if e := tokenGuard(r, c); e != nil {
		return *e
	}
	resp := apiAction(r, readSecrets())
	resp.authed = true
	return resp
}

// tokenGuard refuses what a token may not do even within its scope.
func tokenGuard(r apiReq, live *Config) *apiResp {
	refuse := func(code int, f string, a ...any) *apiResp { e := errResp(code, f, a...); return &e }
	switch r.action {
	case "plan", "validate", "apply":
		var in configSubmit
		if json.Unmarshal(r.body, &in) != nil {
			return nil // the action reports it
		}
		for k := range in.Secrets {
			if strings.HasPrefix(k, tokenSecretPrefix) {
				return refuse(403, "API tokens cannot set token hashes")
			}
		}
		if r.action == "apply" && len(in.Patch) == 0 && in.BaseRev == "" {
			return refuse(400, "base_rev required with a whole config (the rev of GET config), or send a patch")
		}
		cand, _, _, _, err := candidate(r)
		if err != nil {
			return nil
		}
		if bad := lockedChanges(live, cand); len(bad) > 0 {
			return refuse(403, "API tokens cannot change %s (web UI or SSH only)", strings.Join(bad, ", "))
		}
	case "rollback":
		var in historyRef
		json.Unmarshal(r.body, &in)
		snap, err := in.snap()
		if err != nil {
			return nil
		}
		y, ok, err := snapshotFile(snap, ConfigPath)
		if err != nil || !ok {
			return nil
		}
		old, err := decodeConfig(y)
		if err != nil {
			return nil
		}
		old.secrets = live.secrets
		old.defaults()
		if bad := lockedChanges(live, old); len(bad) > 0 {
			return refuse(403, "this rollback changes %s: API tokens cannot (web UI or SSH only)", strings.Join(bad, ", "))
		}
	case "confirm", "revert":
		if p, err := readPending(); err == nil && p.Via != r.via {
			return refuse(403, "the pending change was made by %s: a token settles only its own changes", p.Via)
		}
	}
	return nil
}

// lockedChanges: the parts of tokenLocked that differ between a and b, and local file paths b
// references that a does not (a file's content could come back in an error message).
func lockedChanges(a, b *Config) []string {
	an, err1 := canonNode(a)
	bn, err2 := canonNode(b)
	if err1 != nil || err2 != nil {
		return []string{"the config"}
	}
	var out []string
	for _, p := range tokenLocked {
		steps, _ := parsePath(p)
		x, _ := nodeAt(an, steps, false)
		y, _ := nodeAt(bn, steps, false)
		if !nodeEqual(x, y) {
			out = append(out, p)
		}
	}
	have := map[string]bool{}
	for _, v := range fileRefs(an, "") {
		have[v] = true
	}
	refs := fileRefs(bn, "")
	for _, p := range sortedKeys(refs) {
		if !have[refs[p]] {
			out = append(out, p)
		}
	}
	// an item that references a secret (a proxy node, a PPPoE WAN, an SSID, a DDNS record): a token
	// may not add or change one — pointed at a host of its own, the router would send the secret
	// there. Removing one is fine.
	old, now := secretHolders(an, ""), secretHolders(bn, "")
	var holders []string
	for p := range now {
		holders = append(holders, p)
	}
	sort.Strings(holders)
	for _, p := range holders {
		if o, ok := old[p]; !ok || !nodeEqual(o, now[p]) {
			out = append(out, p+" (it references a secret)")
		}
	}
	return out
}

// secretHolders: path → mapping of every mapping under n with a non-empty *_secret key.
func secretHolders(n *yaml.Node, path string) map[string]*yaml.Node {
	out := map[string]*yaml.Node{}
	add := func(m map[string]*yaml.Node) {
		for k, v := range m {
			out[k] = v
		}
	}
	switch n.Kind {
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i].Value, n.Content[i+1]
			if strings.HasSuffix(k, "_secret") && v.Kind == yaml.ScalarNode && v.Value != "" {
				out[path] = n
			}
			p := fmtKey(k)
			if path != "" {
				p = path + "." + p
			}
			add(secretHolders(v, p))
		}
	case yaml.SequenceNode:
		k := seqKey(n)
		for i, it := range n.Content {
			sel := fmt.Sprint(i)
			if k != "" {
				sel = fmtSel(mapIndex(it)[k].Value)
			}
			add(secretHolders(it, path+"["+sel+"]"))
		}
	}
	return out
}

// fileRefs: path → value of every non-empty key named *_file under n.
func fileRefs(n *yaml.Node, path string) map[string]string {
	out := map[string]string{}
	add := func(m map[string]string) {
		for k, v := range m {
			out[k] = v
		}
	}
	switch n.Kind {
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i].Value, n.Content[i+1]
			p := fmtKey(k)
			if path != "" {
				p = path + "." + p
			}
			if strings.HasSuffix(k, "_file") && v.Kind == yaml.ScalarNode && v.Value != "" {
				out[p] = v.Value
			}
			add(fileRefs(v, p))
		}
	case yaml.SequenceNode:
		k := seqKey(n)
		for i, it := range n.Content {
			sel := fmt.Sprint(i)
			if k != "" {
				sel = fmtSel(mapIndex(it)[k].Value)
			}
			add(fileRefs(it, path+"["+sel+"]"))
		}
	}
	return out
}

// ---- last use ----

type tokenUse struct {
	Time int64  `json:"time"`
	From string `json:"from"`
}

// updateUses changes a last-use file under an exclusive lock; f returns false to leave it alone.
func updateUses(path string, f func(m map[string]tokenUse) bool) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return
	}
	fd, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return
	}
	defer fd.Close()
	if syscall.Flock(int(fd.Fd()), syscall.LOCK_EX) != nil {
		return
	}
	m := map[string]tokenUse{}
	b, _ := io.ReadAll(fd)
	json.Unmarshal(b, &m)
	if !f(m) {
		return
	}
	out, _ := json.Marshal(m)
	if fd.Truncate(0) == nil {
		fd.WriteAt(out, 0)
	}
}

// noteTokenUse: every use in /run, at most one write an hour per token to flash (survives a reboot).
func noteTokenUse(name, remote string) {
	u := tokenUse{Time: time.Now().Unix(), From: remote}
	updateUses(tokenUsedRun, func(m map[string]tokenUse) bool { m[name] = u; return true })
	updateUses(tokenUsedDisk, func(m map[string]tokenUse) bool {
		if u.Time-m[name].Time < 3600 {
			return false
		}
		m[name] = u
		return true
	})
}

// tokenUses: the last use of every token that was used (the later of both records).
func tokenUses() map[string]tokenUse {
	out := map[string]tokenUse{}
	for _, p := range []string{tokenUsedDisk, tokenUsedRun} {
		m := map[string]tokenUse{}
		if b, err := os.ReadFile(p); err == nil {
			json.Unmarshal(b, &m)
		}
		for k, v := range m {
			if v.Time >= out[k].Time { // the same second: /run (read last) is the precise one
				out[k] = v
			}
		}
	}
	return out
}

// loginWait: seconds the source is still locked by the login throttle (0: not locked). Read only.
func loginWait(remote string) int64 {
	f, err := os.Open(loginFile)
	if err != nil {
		return 0
	}
	defer f.Close()
	syscall.Flock(int(f.Fd()), syscall.LOCK_SH)
	var m map[string]*loginRec
	if json.NewDecoder(f).Decode(&m) != nil {
		return 0
	}
	if r := m[loginKey(remote)]; r != nil {
		if w := r.Until - loginClock().Unix(); w > 0 {
			return w
		}
	}
	return 0
}

// ---- mr token ----

const tokenUsage = `mr token list
mr token create NAME [-scope read|operate|apply] [-from CIDR,...] [-expires YYYY-MM-DD] [-allow ACTION,...]
mr token revoke NAME`

// tokenCommand manages tokens on the live router: create and revoke are applied at once (a change in
// the history, via "mr token"); the token is printed once.
func tokenCommand(args []string, cfgPath, secPath string) error {
	if len(args) == 0 {
		return errors.New(tokenUsage)
	}
	switch args[0] {
	case "list":
		c, err := loadConfig(cfgPath, secPath)
		if err != nil {
			return err
		}
		uses := tokenUses()
		if len(c.API.Tokens) == 0 {
			fmt.Println("no API tokens")
		}
		for _, t := range c.API.Tokens {
			last := "never"
			if u, ok := uses[t.Name]; ok {
				last = time.Unix(u.Time, 0).Format("2006-01-02 15:04") + " from " + u.From
			}
			from, exp, allow := "any", "never", ""
			if len(t.From) > 0 {
				from = strings.Join(t.From, ",")
			}
			if t.Expires != "" {
				exp = t.Expires
			}
			if len(t.Allow) > 0 {
				allow = "  allow " + strings.Join(t.Allow, ",")
			}
			fmt.Printf("%-15s %-7s from %s  expires %s  last used %s%s\n", t.Name, t.Scope, from, exp, last, allow)
		}
		return nil
	case "create", "revoke":
	default:
		return errors.New(tokenUsage)
	}
	if cfgPath != ConfigPath {
		return errors.New("mr token changes the live router.yaml (no -c)")
	}
	if len(args) < 2 || strings.HasPrefix(args[1], "-") {
		return errors.New(tokenUsage)
	}
	name := args[1]
	fl := flag.NewFlagSet("token", flag.ContinueOnError)
	scope := fl.String("scope", "read", "read | operate | apply")
	from := fl.String("from", "", "source addresses / CIDRs, comma-separated")
	expires := fl.String("expires", "", "YYYY-MM-DD")
	allow := fl.String("allow", "", "actions, comma-separated (group.* for a group)")
	if err := fl.Parse(args[2:]); err != nil {
		return err
	}
	cur, err := os.ReadFile(cfgPath)
	if err != nil {
		return err
	}
	sec, err := readSecretsFrom(secPath)
	if err != nil {
		return err
	}
	var y []byte
	var tok string
	if args[0] == "create" {
		t := APIToken{Name: name, Scope: *scope, Expires: *expires, From: splitList(*from), Allow: splitList(*allow)}
		y, tok, err = tokenCreate(cur, sec, t)
	} else {
		y, err = tokenRevoke(cur, sec, name)
	}
	if err != nil {
		return err
	}
	dir, err := os.MkdirTemp(RunDir, "token-")
	if err != nil {
		if err = os.MkdirAll(RunDir, 0700); err == nil {
			dir, err = os.MkdirTemp(RunDir, "token-")
		}
		if err != nil {
			return err
		}
	}
	defer os.RemoveAll(dir)
	cy, cs := filepath.Join(dir, "router.yaml"), filepath.Join(dir, "secrets.yaml")
	if err := writeAtomic(cy, y, 0600); err != nil {
		return err
	}
	if err := writeSecrets(cs, sec); err != nil {
		return err
	}
	comment := "API token " + name + " revoked"
	if tok != "" {
		comment = "API token " + name + " created (" + *scope + ")"
	}
	if err := ApplyCandidate(cy, cs, 0, applyOpts{Via: "mr token", Comment: comment}); err != nil {
		return err
	}
	if tok != "" {
		fmt.Printf("\nAPI token %s (shown only now; the router keeps its hash):\n%s\n", name, tok)
	}
	return nil
}

func splitList(s string) []string {
	var out []string
	for _, x := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' }) {
		out = append(out, x)
	}
	return out
}

// tokenCreate: router.yaml text cur with token t added (layout kept), sec with its hash; the token.
func tokenCreate(cur []byte, sec map[string]string, t APIToken) ([]byte, string, error) {
	item, err := yaml.Marshal(t)
	if err != nil {
		return nil, "", err
	}
	n, err := parseValue(string(item))
	if err != nil {
		return nil, "", err
	}
	tok, hash := newToken()
	y, err := tokenEdit(cur, sec, patchOp{Op: "add", Path: "api.tokens", node: n}, t.Name, hash)
	return y, tok, err
}

// tokenRevoke: cur without token name, its hash removed from sec.
func tokenRevoke(cur []byte, sec map[string]string, name string) ([]byte, error) {
	return tokenEdit(cur, sec, patchOp{Op: "del", Path: "api.tokens[" + fmtSel(name) + "]"}, name, "")
}

func tokenEdit(cur []byte, sec map[string]string, op patchOp, name, hash string) ([]byte, error) {
	y, c, _, err := editYAML(cur, []patchOp{op})
	if err != nil {
		return nil, err
	}
	delete(sec, tokenSecretPrefix+name)
	if hash != "" {
		sec[tokenSecretPrefix+name] = hash
	}
	pruneTokenSecrets(c, sec)
	c.secrets = sec
	c.defaults()
	if errs := c.Validate(); len(errs) > 0 {
		return nil, fmt.Errorf("invalid:\n  %s", strings.Join(errs, "\n  "))
	}
	return y, nil
}

// pruneTokenSecrets drops the hashes of tokens c no longer has: a name used again later must not
// bring an old token back.
func pruneTokenSecrets(c *Config, sec map[string]string) {
	have := map[string]bool{}
	for _, t := range c.API.Tokens {
		have[tokenSecretPrefix+t.Name] = true
	}
	for k := range sec {
		if strings.HasPrefix(k, tokenSecretPrefix) && !have[k] {
			delete(sec, k)
		}
	}
}
