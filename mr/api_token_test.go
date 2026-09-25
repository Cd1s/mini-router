package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// tokenEnv: the home config with synthetic tokens (and their hashes), throttle and last-use state in
// a temp dir. Returns the config, the tokens by name, and a clock the test moves.
func tokenEnv(t *testing.T) (*Config, map[string]string, func(time.Duration)) {
	t.Helper()
	_, advance := loginEnv(t)
	oldR, oldD := tokenUsedRun, tokenUsedDisk
	t.Cleanup(func() { tokenUsedRun, tokenUsedDisk = oldR, oldD })
	d := t.TempDir()
	tokenUsedRun, tokenUsedDisk = filepath.Join(d, "run", "api-used.json"), filepath.Join(d, "state", "api-used.json")
	c := testConfig(t)
	c.API.Tokens = []APIToken{
		{Name: "ha", Scope: "read", Allow: []string{"status", "mon.*"}},
		{Name: "reader", Scope: "read"},
		{Name: "ops", Scope: "operate"},
		{Name: "agent", Scope: "apply", From: []string{"192.0.2.0/24", "2001:db8::/64"}},
		{Name: "old", Scope: "read", Expires: "2020-01-01"},
	}
	toks := map[string]string{}
	for _, tk := range c.API.Tokens {
		tok, hash := newToken()
		toks[tk.Name] = tok
		c.secrets[tokenSecretPrefix+tk.Name] = hash
	}
	return c, toks, advance
}

func authStatus(c *Config, action, remote, auth string) int {
	_, e := tokenAuth(apiReq{action: action, remote: remote, auth: auth}, c, time.Now())
	if e == nil {
		return 200
	}
	return e.status
}

func TestTokenScopes(t *testing.T) {
	c, tok, _ := tokenEnv(t)
	if errs := c.Validate(); len(errs) > 0 {
		t.Fatalf("token config invalid: %v", errs)
	}
	const lan = "192.0.2.10"
	for _, x := range []struct {
		token, action string
		want          int
	}{
		{"reader", "status", 200}, {"reader", "config", 200}, {"reader", "mon.conns", 200}, {"reader", "history", 200}, {"reader", "schema", 200},
		{"reader", "apply", 403}, {"reader", "plan", 403}, {"reader", "net.redial", 403}, {"reader", "confirm", 403},
		{"ops", "net.redial", 200}, {"ops", "wifi.kick", 200}, {"ops", "status", 200}, {"ops", "apply", 403}, {"ops", "rollback", 403},
		{"agent", "apply", 200}, {"agent", "plan", 200}, {"agent", "rollback", 200}, {"agent", "revert", 200}, {"agent", "net.redial", 200}, {"agent", "status", 200},
		{"ha", "status", 200}, {"ha", "mon.now", 200}, {"ha", "mon.devices", 200}, {"ha", "config", 403}, {"ha", "wifi.stations", 403},
		{"old", "status", 401},
	} {
		if got := authStatus(c, x.action, lan, "Bearer "+tok[x.token]); got != x.want {
			t.Errorf("%s %s: %d, want %d", x.token, x.action, got, x.want)
		}
	}
	// never, whatever the scope
	for _, a := range []string{"password", "login", "setup", "logout", "session", "reboot", "logs", "sys.logs", "sys.backup", "sys.restore",
		"sys.fw", "sys.fwupload", "sys.fwupgrade", "sys.factoryreset", "sys.sshkeys", "proxy.fetch", "proxy.parse", "proxy.lists",
		"dns.querylog", "tokens", "nosuch"} {
		if got := authStatus(c, a, lan, "Bearer "+tok["agent"]); got != 403 {
			t.Errorf("apply token, %s: %d", a, got)
		}
	}
	// sources
	for remote, want := range map[string]int{"192.0.2.99": 200, "::ffff:192.0.2.99": 200, "2001:db8::5": 200, "198.51.100.1": 403, "2001:db8:1::5": 403, "": 403} {
		if got := authStatus(c, "status", remote, "Bearer "+tok["agent"]); got != want {
			t.Errorf("agent from %q: %d, want %d", remote, got, want)
		}
	}
	// expiry: the token works until the day begins (router time)
	c.API.Tokens[4].Expires = time.Now().In(sysLocation(c)).AddDate(0, 0, 1).Format("2006-01-02")
	if got := authStatus(c, "status", lan, "Bearer "+tok["old"]); got != 200 {
		t.Errorf("token expiring tomorrow: %d", got)
	}
}

// Bad tokens count against the source like wrong passwords; a locked source is refused at once, even
// with a valid token; a valid token never clears the count (Cd1s/mini-router#22).
func TestTokenThrottle(t *testing.T) {
	c, tok, advance := tokenEnv(t)
	valid := "Bearer " + tok["reader"]
	for _, bad := range []string{"Basic cm9vdDpyb290", "Bearer " + strings.TrimPrefix(tok["reader"], tokenPrefix), "Bearer " + tok["reader"] + "x"} {
		if got := authStatus(c, "status", "192.0.2.50", bad); got != 401 {
			t.Errorf("%q: %d", bad, got)
		}
	}
	if got := authStatus(c, "status", "192.0.2.50", valid); got != 200 {
		t.Fatalf("valid token: %d", got)
	}
	for i := 3; i < loginMax; i++ {
		if got := authStatus(c, "status", "192.0.2.50", "Bearer mrt_guess"); got != 401 {
			t.Fatalf("guess %d: %d", i, got)
		}
	}
	if got := authStatus(c, "status", "192.0.2.50", valid); got != 429 {
		t.Errorf("locked source, valid token: %d (the valid use in between must not have cleared the count)", got)
	}
	if got := authStatus(c, "status", "192.0.2.51", valid); got != 200 {
		t.Errorf("other source: %d", got)
	}
	advance(loginBase + time.Second)
	if got := authStatus(c, "status", "192.0.2.50", valid); got != 200 {
		t.Errorf("after the lock: %d", got)
	}
}

func TestTokenValidation(t *testing.T) {
	c, _, _ := tokenEnv(t)
	c.API.Tokens = append(c.API.Tokens,
		APIToken{Name: "ha", Scope: "read"},
		APIToken{Name: "Bad Name", Scope: "read"},
		APIToken{Name: "x1", Scope: "admin"},
		APIToken{Name: "x2", Scope: "read", Allow: []string{"apply"}},
		APIToken{Name: "x3", Scope: "read", Allow: []string{"rm -rf"}},
		APIToken{Name: "x4", Scope: "read", From: []string{"192.0.2.0/33"}},
		APIToken{Name: "x5", Scope: "read", Expires: "next year"})
	for _, n := range []string{"x1", "x2", "x3", "x4", "x5"} {
		c.secrets[tokenSecretPrefix+n] = tokenHash("mrt_" + n)
	}
	c.secrets[tokenSecretPrefix+"reader"] = "plaintext-token"
	errs := strings.Join(c.Validate(), "\n")
	for _, want := range []string{"api.tokens[ha]: duplicate name", `api.tokens[6].name`, "api.tokens[x1].scope", `"apply" matches no action of scope read`,
		`api.tokens[x3].allow: action name`, "api.tokens[x4].from", "api.tokens[x5].expires", "api.tokens[reader]: no token hash", "api.tokens[6]: no token hash"} {
		if !strings.Contains(errs, want) {
			t.Errorf("missing %q in:\n%s", want, errs)
		}
	}
}

// The actions tokens can reach exist; the sensitive ones are not among them.
func TestTokenActions(t *testing.T) {
	core := map[string]bool{"status": true, "config": true, "validate": true, "apply": true, "job": true, "confirm": true,
		"revert": true, "history": true, "history.diff": true, "rollback": true}
	for a, s := range tokenActions {
		found := core[a]
		for _, m := range modules {
			_, ok := m.API[a]
			found = found || ok
		}
		if !found {
			t.Errorf("tokenActions: %q is no API action", a)
		}
		if scopeLevel[s] == 0 {
			t.Errorf("tokenActions: %q has scope %q", a, s)
		}
	}
}

// Token changes cannot touch the token list, SSH, sysctl or point at new local files.
func TestLockedChanges(t *testing.T) {
	base := testConfig(t)
	for name, f := range map[string]func(c *Config){
		"services.ssh":  func(c *Config) { c.Services.SSH.Keys = append(c.Services.SSH.Keys, "ssh-ed25519 AAAA x") },
		"system.sysctl": func(c *Config) { c.System.Sysctl = map[string]string{"kernel.core_pattern": "|/bin/sh"} },
		"api":           func(c *Config) { c.API.Tokens = append(c.API.Tokens, APIToken{Name: "more", Scope: "apply"}) },
		"dns.split":     func(c *Config) { c.DNS.Split[0].DomainsFile = SecretsPath },
		"guard":         func(c *Config) { c.Guard.NeverExpose = nil; c.Guard.Offload = "off" },
		"wan[":          func(c *Config) { c.WAN[0].MTU = 1400 }, // a PPPoE WAN references its password
		"":              func(c *Config) { c.Firewall.Offload = "off"; c.DNS.Split = nil },
	} {
		c := testConfig(t)
		f(c)
		got := strings.Join(lockedChanges(base, c), ",")
		if (name == "" && got != "") || !strings.HasPrefix(got, name) {
			t.Errorf("%s: locked %q", name, got)
		}
	}
}

// The web UI / API guard: a token's patch to a locked path, a token hash, a whole config without
// base_rev, and settling someone else's pending change are refused.
func TestTokenGuard(t *testing.T) {
	_, cfg, secf := confirmEnv(t)
	old := liveConfig
	t.Cleanup(func() { liveConfig = old })
	liveConfig = cfg
	live, err := loadConfig(cfg, secf)
	if err != nil {
		t.Fatal(err)
	}
	req := func(action, body string) apiReq {
		return apiReq{method: "POST", action: action, body: []byte(body), via: "api:agent"}
	}
	for body, want := range map[string]int{
		`{"patch":[{"op":"set","path":"services.ssh.port","value":2222}]}`:                                         403,
		`{"patch":[{"op":"set","path":"firewall.offload","value":"software"}]}`:                                    0,
		`{"patch":[{"op":"set","path":"firewall.offload","value":"x"}],"secrets":{"api_token_agent":"sha256:00"}}`: 403,
		`{"config":{}}`: 400,
	} {
		got := 0
		if e := tokenGuard(req("apply", body), live); e != nil {
			got = e.status
		}
		if got != want {
			t.Errorf("%s: %d, want %d (0 = allowed)", body, got, want)
		}
	}
	if e := tokenGuard(req("confirm", "{}"), live); e != nil {
		t.Errorf("confirm without a pending change: %v", e.body)
	}
	if err := claimPending(pendingApply{Snapshot: "x.tar.gz", State: statePending, Via: "web UI"}); err != nil {
		t.Fatal(err)
	}
	for _, a := range []string{"confirm", "revert"} {
		if e := tokenGuard(req(a, "{}"), live); e == nil || e.status != 403 {
			t.Errorf("%s of the web UI's change: %v", a, e)
		}
	}
	os.Remove(ConfirmFile)
	claimPending(pendingApply{Snapshot: "x.tar.gz", State: statePending, Via: "api:agent"})
	if e := tokenGuard(req("confirm", "{}"), live); e != nil {
		t.Errorf("confirm of its own change: %v", e.body)
	}
}

// A patch through the API edits the live router.yaml in place; base_rev catches a file that changed.
func TestPatchCandidateAndBaseRev(t *testing.T) {
	d := t.TempDir()
	old := liveConfig
	t.Cleanup(func() { liveConfig = old })
	liveConfig = filepath.Join(d, "router.yaml")
	src := homeYAML(t)
	os.WriteFile(liveConfig, []byte(src), 0644)
	rev := configRev()
	if len(rev) != 16 || staleBase("") != nil || staleBase(rev) != nil {
		t.Fatalf("rev %q", rev)
	}
	fwd := testConfig(t).Firewall.Forwards[0].Name
	c, y, _, _, err := candidate(apiReq{body: []byte(`{"patch":[{"op":"set","path":"firewall.forwards[` + fwd + `].enabled","value":false},` +
		`{"op":"add","path":"dhcp.hosts","value":{"name":"newdev","mac":"02:00:00:00:00:77","ip":"192.0.2.77"}}]}`)})
	if err != nil {
		t.Fatal(err)
	}
	if on(c.Firewall.Forwards[0].Enabled) || c.DHCP.Hosts[len(c.DHCP.Hosts)-1].Name != "newdev" {
		t.Errorf("patch not applied")
	}
	gone, added := lineDiff(src, string(y))
	if len(gone) != 1 || len(added) != 2 {
		t.Errorf("patch text: -%q +%q", gone, added)
	}
	os.WriteFile(liveConfig, append([]byte(src), "\n# edited elsewhere\n"...), 0644)
	if e := staleBase(rev); e == nil || e.status != 409 || e.body.(map[string]any)["rev"] != configRev() {
		t.Errorf("stale base_rev: %+v", e)
	}
	if r := apiValidate(apiReq{body: []byte(`{"base_rev":"` + rev + `","patch":[]}`)}); r.status != 409 {
		t.Errorf("validate with a stale base_rev: %d", r.status)
	}
	if r := apiPlan(apiReq{body: []byte(`{"base_rev":"` + rev + `"}`)}); r.status != 409 {
		t.Errorf("plan with a stale base_rev: %d", r.status)
	}
}

// mr token create / revoke: the token section is added to the file (nothing else changes), only the
// hash is kept, the token authenticates; revoking takes the file back and drops the hash.
func TestTokenCreateRevoke(t *testing.T) {
	src := homeYAML(t)
	sec := readSecretsFile("testdata/secrets.yaml")
	y, tok, err := tokenCreate([]byte(src), sec, APIToken{Name: "agent", Scope: "apply", From: []string{"192.0.2.0/24"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(tok, tokenPrefix) || len(tok) != len(tokenPrefix)+43 || strings.Contains(string(y), tok) {
		t.Fatalf("token %q", tok)
	}
	if gone, _ := lineDiff(src, string(y)); len(gone) > 0 {
		t.Errorf("create removed lines %q", gone)
	}
	c, err := decodeConfig(y)
	if err != nil {
		t.Fatal(err)
	}
	c.secrets = sec
	if found := findToken(c, tok); found == nil || found.Scope != "apply" || sec[tokenSecretPrefix+"agent"] != tokenHash(tok) {
		t.Fatalf("created token not found")
	}
	if _, _, err := tokenCreate(y, sec, APIToken{Name: "agent", Scope: "read"}); err == nil {
		t.Error("second token with the same name")
	}
	if _, _, err := tokenCreate(y, sec, APIToken{Name: "x", Scope: "root"}); err == nil {
		t.Error("bad scope accepted")
	}
	sec["api_token_gone"] = "sha256:" + strings.Repeat("0", 64) // an orphan from a hand edit
	y2, err := tokenRevoke(y, sec, "agent")
	if err != nil {
		t.Fatal(err)
	}
	if string(y2) != src {
		gone, added := lineDiff(src, string(y2))
		t.Errorf("create + revoke is not the original: -%q +%q", gone, added)
	}
	for k := range sec {
		if strings.HasPrefix(k, tokenSecretPrefix) {
			t.Errorf("hash %s left after revoke", k)
		}
	}
	if _, err := tokenRevoke(y2, sec, "agent"); err == nil {
		t.Error("revoke of an unknown token")
	}
}

func TestTokenLastUse(t *testing.T) {
	tokenEnv(t)
	noteTokenUse("ha", "192.0.2.1")
	noteTokenUse("ha", "192.0.2.2")
	noteTokenUse("agent", "192.0.2.3")
	u := tokenUses()
	if u["ha"].From != "192.0.2.2" || u["agent"].From != "192.0.2.3" || u["ha"].Time == 0 {
		t.Errorf("uses %+v", u)
	}
	if b := mustRead(t, tokenUsedDisk); !strings.Contains(b, "192.0.2.1") || strings.Contains(b, "192.0.2.2") {
		t.Errorf("flash record written more than once an hour: %s", b)
	}
}

// A token cannot point anything that references a secret at a host of its own: a new item with a
// *_secret, or a changed field of an item that has one. Removing such an item is allowed.
func TestTokenSecretHolders(t *testing.T) {
	base := proxyNodesTestConfig(t)
	for name, f := range map[string]func(c *Config){
		"new node reusing a secret": func(c *Config) {
			c.Proxy.Nodes = append(c.Proxy.Nodes, ProxyNode{Name: "evil", Type: "trojan", Server: "203.0.113.66", Port: 443, Password: c.Proxy.Nodes[0].Password})
		},
		"node pointed elsewhere": func(c *Config) { c.Proxy.Nodes[0].Server = "203.0.113.66" },
	} {
		c := proxyNodesTestConfig(t)
		f(c)
		if got := strings.Join(lockedChanges(base, c), ","); !strings.Contains(got, "references a secret") {
			t.Errorf("%s: not locked (%q)", name, got)
		}
	}
	c := proxyNodesTestConfig(t)
	c.Proxy.Nodes = c.Proxy.Nodes[1:]
	c.Proxy.Groups = nil
	if got := strings.Join(lockedChanges(base, c), ","); strings.Contains(got, "references a secret") {
		t.Errorf("removing a node refused: %v", got)
	}
}
