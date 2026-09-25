package main

// Web UI backend: `mr api` runs as a CGI program under busybox httpd (no resident process).
//
// Security: session cookie (HttpOnly, SameSite=Strict) + custom header X-MR on every request
// (blocks cross-site form posts), PBKDF2-SHA256 password hash in secrets.yaml, login throttling per
// source address shared by all CGI processes (api_login.go), first-time password only from the LAN.

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	RunDir      = "/run/mini-router"
	SessionDir  = RunDir + "/sessions"
	JobFile     = RunDir + "/job.json"
	JobLog      = RunDir + "/job.log"
	sessionTTL  = 12 * time.Hour
	pwSecretKey = "webui_password"
	pbkdfIter   = 120000
)

// the apply job's input (variables so tests can point them elsewhere)
var (
	CandidateYAML = RunDir + "/candidate.yaml"
	CandidateSec  = RunDir + "/candidate-secrets.yaml"
)

type apiReq struct {
	method string
	action string
	body   []byte
	cookie string
	remote string
	header string
}

type apiResp struct {
	status int
	body   any
	cookie string
}

func runAPI() error {
	r := apiReq{
		method: os.Getenv("REQUEST_METHOD"),
		cookie: os.Getenv("HTTP_COOKIE"),
		remote: os.Getenv("REMOTE_ADDR"),
		header: os.Getenv("HTTP_X_MR"),
	}
	for _, kv := range strings.Split(os.Getenv("QUERY_STRING"), "&") {
		if strings.HasPrefix(kv, "a=") {
			r.action = strings.TrimPrefix(kv, "a=")
		}
	}
	if n, _ := strconv.Atoi(os.Getenv("CONTENT_LENGTH")); n > 0 && n < 4<<20 {
		r.body, _ = io.ReadAll(io.LimitReader(os.Stdin, int64(n)))
	}
	resp := handleAPI(r)
	fmt.Printf("Content-Type: application/json\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n")
	if resp.cookie != "" {
		fmt.Printf("Set-Cookie: %s\r\n", resp.cookie)
	}
	// every page shows a change waiting for confirmation, whoever made it (web UI, SSH, an agent)
	if v := pendingView(); v != nil && validSession(r.cookie) {
		if b, err := json.Marshal(v); err == nil {
			fmt.Printf("X-MR-Pending: %s\r\n", b)
		}
	}
	if resp.status != 0 && resp.status != 200 {
		fmt.Printf("Status: %d\r\n", resp.status)
	}
	fmt.Print("\r\n")
	return json.NewEncoder(os.Stdout).Encode(resp.body)
}

func errResp(code int, msg string, a ...any) apiResp {
	return apiResp{status: code, body: map[string]any{"error": fmt.Sprintf(msg, a...)}}
}

func handleAPI(r apiReq) apiResp {
	if r.header != "1" {
		return errResp(403, "missing X-MR header")
	}
	os.MkdirAll(SessionDir, 0700)
	secrets := readSecrets()

	switch r.action {
	case "session":
		_, hasPw := secrets[pwSecretKey]
		return apiResp{body: map[string]any{"authenticated": validSession(r.cookie), "password_set": hasPw}}
	case "login":
		return apiLogin(r, secrets)
	case "setup":
		return apiSetup(r, secrets)
	}
	if !validSession(r.cookie) {
		return errResp(401, "not logged in")
	}
	switch r.action {
	case "logout":
		if tok := sessionToken(r.cookie); tok != "" {
			os.Remove(filepath.Join(SessionDir, tok))
		}
		return apiResp{body: map[string]any{"ok": true}, cookie: "mrsid=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict"}
	case "status":
		return apiStatus()
	case "config":
		return apiGetConfig(secrets)
	case "validate":
		return apiValidate(r)
	case "apply":
		return apiApply(r)
	case "job":
		return apiJob()
	case "confirm":
		if r.method != "POST" {
			return errResp(405, "POST required")
		}
		ok, err := confirm()
		if err != nil {
			return errResp(409, "%v", err)
		}
		return apiResp{body: map[string]any{"ok": true, "confirmed": ok}}
	case "revert": // undo a pending --confirm apply right now instead of waiting for the timer
		if r.method != "POST" {
			return errResp(405, "POST required")
		}
		p, err := readPending()
		if err != nil || p.State != statePending {
			return errResp(409, "nothing pending")
		}
		p.State = stateReverting // the timer leaves it alone; the rollback removes the marker when done
		if err := setPending(*p); err != nil {
			return errResp(500, "%v", err)
		}
		self, _ := os.Executable()
		startDetached(self, "rollback", filepath.Base(p.Snapshot))
		return apiResp{body: map[string]any{"ok": true}}
	case "history":
		return apiHistory()
	case "history.diff":
		return apiHistoryDiff(r)
	case "rollback":
		return apiRollback(r)
	case "logs":
		return apiLogs()
	case "password":
		return apiPassword(r, secrets)
	case "reboot":
		if r.method != "POST" {
			return errResp(405, "POST required")
		}
		appendChangeLog("webui: reboot")
		startDetached("/bin/sh", "-c", "sleep 2; reboot")
		return apiResp{body: map[string]any{"ok": true}}
	}
	for _, m := range modules {
		if h, ok := m.API[r.action]; ok {
			return h(r)
		}
	}
	return errResp(404, "unknown action %q", r.action)
}

// ---- auth ----

func hashPassword(pw string) string {
	salt := make([]byte, 16)
	rand.Read(salt)
	key, _ := pbkdf2.Key(sha256.New, pw, salt, pbkdfIter, 32)
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", pbkdfIter, hex.EncodeToString(salt), hex.EncodeToString(key))
}

func checkPassword(stored, pw string) bool {
	p := strings.Split(stored, "$")
	if len(p) != 4 || p[0] != "pbkdf2-sha256" {
		return false
	}
	iter, _ := strconv.Atoi(p[1])
	salt, err1 := hex.DecodeString(p[2])
	want, err2 := hex.DecodeString(p[3])
	if err1 != nil || err2 != nil || iter < 1000 {
		return false
	}
	got, _ := pbkdf2.Key(sha256.New, pw, salt, iter, len(want))
	return subtle.ConstantTimeCompare(got, want) == 1
}

func newSession() string {
	b := make([]byte, 24)
	rand.Read(b)
	tok := base64.RawURLEncoding.EncodeToString(b)
	os.WriteFile(filepath.Join(SessionDir, tok), []byte(time.Now().Add(sessionTTL).Format(time.RFC3339)), 0600)
	return tok
}

func sessionToken(cookie string) string {
	for _, part := range strings.Split(cookie, ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "mrsid=") {
			tok := strings.TrimPrefix(part, "mrsid=")
			if len(tok) == 32 && !strings.ContainsAny(tok, "/.") {
				return tok
			}
		}
	}
	return ""
}

func validSession(cookie string) bool {
	tok := sessionToken(cookie)
	if tok == "" {
		return false
	}
	b, err := os.ReadFile(filepath.Join(SessionDir, tok))
	if err != nil {
		return false
	}
	exp, err := time.Parse(time.RFC3339, strings.TrimSpace(string(b)))
	if err != nil || time.Now().After(exp) {
		os.Remove(filepath.Join(SessionDir, tok))
		return false
	}
	return true
}

func sessionCookie(tok string) string {
	return fmt.Sprintf("mrsid=%s; Path=/; Max-Age=%d; HttpOnly; SameSite=Strict", tok, int(sessionTTL.Seconds()))
}

func apiLogin(r apiReq, secrets map[string]string) apiResp {
	if r.method != "POST" {
		return errResp(405, "POST required")
	}
	var in struct{ Password string }
	json.Unmarshal(r.body, &in)
	stored, ok := secrets[pwSecretKey]
	if !ok {
		return errResp(409, "no password set yet")
	}
	if e := checkPasswordFrom(r.remote, stored, in.Password, "wrong password"); e != nil {
		return *e
	}
	return apiResp{body: map[string]any{"ok": true}, cookie: sessionCookie(newSession())}
}

func fromLAN(remote string) bool {
	c, err := loadConfig(ConfigPath, SecretsPath)
	if err != nil {
		return false
	}
	_, n, err := net.ParseCIDR(c.LAN.IPv4)
	ip := net.ParseIP(remote)
	return err == nil && ip != nil && n.Contains(ip)
}

func apiSetup(r apiReq, secrets map[string]string) apiResp {
	if r.method != "POST" {
		return errResp(405, "POST required")
	}
	if _, ok := secrets[pwSecretKey]; ok {
		return errResp(409, "password already set")
	}
	if !fromLAN(r.remote) {
		return errResp(403, "first-time setup is only allowed from the LAN")
	}
	var in struct{ Password string }
	json.Unmarshal(r.body, &in)
	if len(in.Password) < 8 {
		return errResp(400, "password must be at least 8 characters")
	}
	secrets[pwSecretKey] = hashPassword(in.Password)
	if err := writeSecrets(SecretsPath, secrets); err != nil {
		return errResp(500, "%v", err)
	}
	appendChangeLog("webui: admin password set")
	return apiResp{body: map[string]any{"ok": true}, cookie: sessionCookie(newSession())}
}

func apiPassword(r apiReq, secrets map[string]string) apiResp {
	if r.method != "POST" {
		return errResp(405, "POST required")
	}
	var in struct{ Old, New string }
	json.Unmarshal(r.body, &in)
	if e := checkPasswordFrom(r.remote, secrets[pwSecretKey], in.Old, "current password is wrong"); e != nil {
		return *e
	}
	if len(in.New) < 8 {
		return errResp(400, "password must be at least 8 characters")
	}
	secrets[pwSecretKey] = hashPassword(in.New)
	if err := writeSecrets(SecretsPath, secrets); err != nil {
		return errResp(500, "%v", err)
	}
	os.RemoveAll(SessionDir) // log out everyone else
	os.MkdirAll(SessionDir, 0700)
	appendChangeLog("webui: admin password changed")
	return apiResp{body: map[string]any{"ok": true}, cookie: sessionCookie(newSession())}
}

func readSecrets() map[string]string {
	m := map[string]string{}
	if b, err := os.ReadFile(SecretsPath); err == nil {
		yaml.Unmarshal(b, &m)
	}
	return m
}

func writeSecrets(path string, m map[string]string) error {
	b, err := yaml.Marshal(m)
	if err != nil {
		return err
	}
	return writeAtomic(path, b, 0600)
}

// ---- config <-> JSON (reusing the yaml tags so the web UI sees the same keys as router.yaml) ----

func configToJSON(c *Config) (map[string]any, error) {
	b, err := yaml.Marshal(c)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := yaml.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func configFromJSON(raw json.RawMessage) (*Config, []byte, error) {
	var m any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, nil, err
	}
	y, err := yaml.Marshal(m)
	if err != nil {
		return nil, nil, err
	}
	c := &Config{}
	dec := yaml.NewDecoder(strings.NewReader(string(y)))
	dec.KnownFields(true)
	if err := dec.Decode(c); err != nil {
		return nil, nil, err
	}
	return c, y, nil
}

// secretKeys lists every secret referenced by the config (the UI may set them, never read them).
func secretKeys(c *Config) []string {
	set := map[string]bool{}
	for _, w := range c.WAN {
		if w.Password != "" {
			set[w.Password] = true
		}
	}
	for _, r := range c.WiFi.Radios {
		for _, s := range r.SSIDs {
			if s.Key != "" {
				set[s.Key] = true
			}
		}
	}
	for _, m := range modules {
		if m.Secrets != nil {
			for _, k := range m.Secrets(c) {
				if k != "" {
					set[k] = true
				}
			}
		}
	}
	var out []string
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func apiGetConfig(secrets map[string]string) apiResp {
	c, err := loadConfig(ConfigPath, SecretsPath)
	if err != nil {
		return errResp(500, "%v", err)
	}
	m, err := configToJSON(c)
	if err != nil {
		return errResp(500, "%v", err)
	}
	present := map[string]bool{}
	for _, k := range secretKeys(c) {
		_, present[k] = secrets[k]
	}
	return apiResp{body: map[string]any{"config": m, "secrets_set": present}}
}

type configSubmit struct {
	Config  json.RawMessage   `json:"config"`
	Secrets map[string]string `json:"secrets"` // only keys being changed; empty value = keep
	Confirm int               `json:"confirm"`
	Comment string            `json:"comment"` // for the history
}

// candidate builds the would-be config + secrets without touching the live files.
func candidate(r apiReq) (*Config, []byte, map[string]string, int, error) {
	var in configSubmit
	if err := json.Unmarshal(r.body, &in); err != nil {
		return nil, nil, nil, 0, err
	}
	c, y, err := configFromJSON(in.Config)
	if err != nil {
		return nil, nil, nil, 0, err
	}
	sec := readSecrets()
	for k, v := range in.Secrets {
		if k == pwSecretKey || !regexpSecretKey(k) {
			return nil, nil, nil, 0, fmt.Errorf("invalid secret key %q", k)
		}
		if v != "" {
			sec[k] = v
		}
	}
	c.secrets = sec
	c.defaults()
	return c, y, sec, in.Confirm, nil
}

func regexpSecretKey(k string) bool {
	if k == "" || len(k) > 40 {
		return false
	}
	for _, ch := range k {
		if !(ch == '_' || ch == '-' || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9')) {
			return false
		}
	}
	return true
}

func apiValidate(r apiReq) apiResp {
	c, _, _, _, err := candidate(r)
	if err != nil {
		return apiResp{body: map[string]any{"errors": []string{err.Error()}}}
	}
	if errs := c.Validate(); len(errs) > 0 {
		return apiResp{body: map[string]any{"errors": errs}}
	}
	p, err := plan(c)
	if err != nil {
		return apiResp{body: map[string]any{"errors": []string{err.Error()}}}
	}
	changes, known := changesSinceApplied(c)
	if changes == nil {
		changes = []string{}
	}
	return apiResp{body: map[string]any{"errors": []string{}, "plan": p.String(), "empty": p.Empty(),
		"changes": changes, "changes_known": known, "risk": classifyRisk(p, changes, findAdminPath(r.remote))}}
}

type jobState struct {
	State   string `json:"state"` // running | ok | failed
	Started int64  `json:"started"`
	Ended   int64  `json:"ended,omitempty"`
	Output  string `json:"output"`
	Confirm int    `json:"confirm"`
	Via     string `json:"via,omitempty"` // origin recorded in the pending marker (web UI | restore | rollback)
	From    string `json:"from,omitempty"`
	Comment string `json:"comment,omitempty"`
}

func apiApply(r apiReq) apiResp {
	if r.method != "POST" {
		return errResp(405, "POST required")
	}
	if j := readJob(); j.State == "running" {
		return errResp(409, "another apply is running")
	}
	if err := pendingBlocks(); err != nil {
		return apiResp{status: 409, body: map[string]any{"error": err.Error(), "pending": pendingView()}}
	}
	c, y, sec, confirmSecs, err := candidate(r)
	if err != nil {
		return errResp(400, "%v", err)
	}
	if errs := c.Validate(); len(errs) > 0 {
		return apiResp{status: 400, body: map[string]any{"errors": errs}}
	}
	if confirmSecs <= 0 {
		confirmSecs = 120
	}
	var in configSubmit
	json.Unmarshal(r.body, &in)
	if len(in.Comment) > 200 || strings.ContainsAny(in.Comment, "\r\n") {
		return errResp(400, "comment: one line, at most 200 characters")
	}
	os.MkdirAll(RunDir, 0700)
	if err := writeAtomic(CandidateYAML, uiConfigYAML(y, c), 0600); err != nil {
		return errResp(500, "%v", err)
	}
	if err := writeSecrets(CandidateSec, sec); err != nil {
		return errResp(500, "%v", err)
	}
	writeJob(jobState{State: "running", Started: time.Now().Unix(), Confirm: confirmSecs, Via: "web UI", From: r.remote, Comment: in.Comment})
	self, _ := os.Executable()
	startDetached(self, "apply-job", strconv.Itoa(confirmSecs))
	return apiResp{body: map[string]any{"ok": true, "confirm": confirmSecs}}
}

// runApplyJob executes a web-UI apply in the background and records the outcome for polling.
func runApplyJob(confirmSecs int) error {
	logFile, _ := os.OpenFile(JobLog, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	os.Stdout, os.Stderr = logFile, logFile
	j0 := readJob()
	o := applyOpts{Via: j0.Via, From: j0.From, Comment: j0.Comment}
	if o.Via == "" {
		o.Via = "web UI"
	}
	err := ApplyCandidate(CandidateYAML, CandidateSec, confirmSecs, o)
	logFile.Close()
	out, _ := os.ReadFile(JobLog)
	j := readJob()
	j.Ended = time.Now().Unix()
	j.Output = string(out)
	if err != nil {
		j.State = "failed"
		j.Output += "\n" + err.Error()
	} else {
		j.State = "ok"
	}
	writeJob(j)
	return err
}

func readJob() jobState {
	var j jobState
	if b, err := os.ReadFile(JobFile); err == nil {
		json.Unmarshal(b, &j)
	}
	return j
}

func writeJob(j jobState) { b, _ := json.Marshal(j); writeAtomic(JobFile, b, 0600) }

func apiJob() apiResp {
	j := readJob()
	if j.State == "running" {
		if b, err := os.ReadFile(JobLog); err == nil {
			j.Output = string(b)
		}
	}
	_, pending := os.Stat(ConfirmFile)
	return apiResp{body: map[string]any{"job": j, "confirm_pending": pending == nil, "pending": pendingView()}}
}

// pendingView is what the web UI shows of the pending marker (nil: nothing pending).
func pendingView() map[string]any {
	p, err := readPending()
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return map[string]any{"state": "unknown", "via": "", "left": 0}
	}
	return map[string]any{"state": p.State, "via": p.Via, "left": p.left()}
}

// apiHistory: the revisions, newest first, and snapshots older than revisions (no record).
func apiHistory() apiResp {
	rs := readRevisions()
	known := map[string]bool{}
	for _, r := range rs {
		known[r.Snapshot] = true
	}
	for i, j := 0, len(rs)-1; i < j; i, j = i+1, j-1 {
		rs[i], rs[j] = rs[j], rs[i]
	}
	ents, _ := os.ReadDir(HistoryDir)
	var older []string
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".tar.gz") && !known[e.Name()] && !strings.HasSuffix(e.Name(), "-restore-lists.tar.gz") {
			older = append(older, e.Name())
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(older)))
	if rs == nil {
		rs = []revision{}
	}
	return apiResp{body: map[string]any{"revisions": rs, "snapshots": older}}
}

type historyRef struct {
	Rev      int    `json:"rev"`
	Snapshot string `json:"snapshot"`
}

// snap resolves a revision number or a snapshot file name to the snapshot's path.
func (h historyRef) snap() (string, error) {
	if h.Rev > 0 {
		return revSnapshot(h.Rev)
	}
	name := filepath.Base(h.Snapshot)
	if !strings.HasSuffix(name, ".tar.gz") {
		return "", errors.New("bad snapshot")
	}
	return filepath.Join(HistoryDir, name), nil
}

// apiHistoryDiff: what changed from the config before a revision to the live one.
func apiHistoryDiff(r apiReq) apiResp {
	var in historyRef
	json.Unmarshal(r.body, &in)
	snap, err := in.snap()
	if err != nil {
		return errResp(400, "%v", err)
	}
	ch, err := snapshotChanges(snap)
	if err != nil {
		return errResp(404, "%v", err)
	}
	if ch == nil {
		ch = []string{}
	}
	return apiResp{body: map[string]any{"changes": ch}}
}

// apiRollback puts the config from before a revision back as a new change: the standard apply job
// (verify, confirm countdown, automatic rollback) with the snapshot's router.yaml and secrets.
func apiRollback(r apiReq) apiResp {
	if r.method != "POST" {
		return errResp(405, "POST required")
	}
	if j := readJob(); j.State == "running" {
		return errResp(409, "another apply is running")
	}
	if err := pendingBlocks(); err != nil {
		return apiResp{status: 409, body: map[string]any{"error": err.Error(), "pending": pendingView()}}
	}
	var in historyRef
	json.Unmarshal(r.body, &in)
	snap, err := in.snap()
	if err != nil {
		return errResp(400, "%v", err)
	}
	if err := stageSnapshot(snap); err != nil {
		return errResp(404, "%v", err)
	}
	comment := "back to before " + filepath.Base(snap)
	if in.Rev > 0 {
		comment = fmt.Sprintf("back to before #%d", in.Rev)
	}
	writeJob(jobState{State: "running", Started: time.Now().Unix(), Confirm: 120, Via: "rollback", From: r.remote, Comment: comment})
	self, _ := os.Executable()
	startDetached(self, "apply-job", "120")
	return apiResp{body: map[string]any{"ok": true, "confirm": 120}}
}

func apiLogs() apiResp {
	b, _ := os.ReadFile("/var/log/messages")
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) > 300 {
		lines = lines[len(lines)-300:]
	}
	return apiResp{body: map[string]any{"lines": lines}}
}

func apiStatus() apiResp {
	c, err := loadConfig(ConfigPath, SecretsPath)
	if err != nil {
		return errResp(500, "%v", err)
	}
	st, err := collectStatus(c)
	if err != nil {
		return errResp(500, "%v", err)
	}
	return apiResp{body: st}
}
