package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	tgTestToken  = "123456789:test-token-not-real_0123456789ab"
	hookTestPath = "/hook/s3cr3t-path-not-real"
)

// fakePush records what the notification services got; fail makes it answer 500.
type fakePush struct {
	mu   sync.Mutex
	reqs []pushReq
	fail bool
	tg   string // Telegram answer body (default {"ok":true})
}

type pushReq struct {
	Path, Title, Priority, Ctype string
	Body                         map[string]any
	Raw                          string
}

func (f *fakePush) handler(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	raw, _ := io.ReadAll(r.Body)
	q := pushReq{Path: r.URL.RequestURI(), Title: r.Header.Get("Title"), Priority: r.Header.Get("Priority"), Ctype: r.Header.Get("Content-Type"), Raw: string(raw)}
	json.Unmarshal(raw, &q.Body)
	f.reqs = append(f.reqs, q)
	if f.fail {
		w.WriteHeader(500)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/bot") {
		if f.tg != "" {
			w.WriteHeader(400)
			io.WriteString(w, f.tg)
			return
		}
		io.WriteString(w, `{"ok":true,"result":{}}`)
		return
	}
	w.WriteHeader(204)
}

func (f *fakePush) take() []pushReq {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := f.reqs
	f.reqs = nil
	return r
}

// notifyEnv: event state in a temp dir, a fake push service (Telegram API and webhooks), the home
// config with one webhook channel (json) whose URL is a secret.
func notifyEnv(t *testing.T) (*Config, *fakePush, *httptest.Server, *time.Time, *float64) {
	t.Helper()
	_, now, up, _ := eventEnv(t)
	f := &fakePush{}
	srv := httptest.NewServer(http.HandlerFunc(f.handler))
	t.Cleanup(srv.Close)
	old := tgAPIBase
	tgAPIBase = srv.URL
	t.Cleanup(func() { tgAPIBase = old })
	c := testConfig(t)
	c.System.Timezone = "UTC0" // message times do not depend on the example's zone
	c.secrets["notify_hook"] = srv.URL + hookTestPath + "?key=s3cr3t-query"
	c.secrets["notify_tg"] = tgTestToken
	c.Notify = Notify{Channels: []NotifyChannel{{Name: "hook", Type: "webhook", URL: "notify_hook"}}}
	c.defaults()
	mustValid(t, c)
	notifyInit(c)
	return c, f, srv, now, up
}

// noSecret fails when a secret shows up in any state file, the event log or s.
func noSecret(t *testing.T, where string, s ...string) {
	t.Helper()
	for _, p := range []string{notifyStateFile, notifyCursorFile, eventRunFile, eventLog} {
		b, _ := os.ReadFile(p)
		s = append(s, string(b))
	}
	for _, x := range s {
		for _, sec := range []string{tgTestToken, "s3cr3t-path-not-real", "s3cr3t-query"} {
			if strings.Contains(x, sec) {
				t.Errorf("%s: a secret (%s…) leaked: %s", where, sec[:6], x)
			}
		}
	}
}

func TestNotifyValidate(t *testing.T) {
	c := testConfig(t)
	if y, _ := yaml.Marshal(c); strings.Contains(string(y), "notify") {
		t.Error("an absent notify section appears in the canonical config")
	}
	c.secrets["tg_ok"] = tgTestToken
	c.secrets["tg_bad"] = "not a token"
	c.secrets["hook_ok"] = "https://ntfy.example.com/topic"
	c.secrets["hook_bad"] = "ftp://example.com/x"
	c.secrets["hook_nl"] = "https://example.com/a\nb"
	d := 3
	c.Notify = Notify{
		Channels: []NotifyChannel{
			{Name: "tg", Type: "telegram", Token: "tg_ok", ChatID: "-1001234567890"}, // valid
			{Name: "ntfy", Type: "webhook", URL: "hook_ok", Format: "text"},          // valid
			{Name: "tg", Type: "telegram", Token: "tg_bad", ChatID: "12 34", URL: "hook_ok"},
			{Name: "Bad Name", Type: "webhook", URL: "hook_bad", Format: "xml", Token: "tg_ok"},
			{Name: "gone", Type: "webhook", URL: "hook_missing"},
			{Name: "nl", Type: "webhook", URL: "hook_nl"},
			{Name: "x", Type: "email"},
		},
		Events:     []string{"wan_down", "wan_down", "spam"},
		Rate:       61,
		QuietHours: "07:00-07:00",
		Doctor:     &d,
	}
	c.defaults()
	errs := strings.Join(c.Validate(), "\n")
	for _, s := range []string{
		"notify.channels: at most 4", `notify.channels[2].name: duplicate "tg"`, "notify.channels[2].token_secret: the secret is not a Telegram bot token",
		"notify.channels[2].chat_id", "notify.channels[2]: url_secret / format are for webhooks", "notify.channels[3].name",
		"notify.channels[3].url_secret: the secret is not an http:// or https:// URL", `notify.channels[3].format: json | text, got "xml"`,
		"notify.channels[3]: token_secret / chat_id are for telegram", `notify.channels[4].url_secret: secret "hook_missing" missing`,
		"notify.channels[5].url_secret: the secret is not a single-line URL", `notify.channels[6].type: telegram | webhook, got "email"`,
		`notify.events: duplicate "wan_down"`, `notify.events: unknown "spam"`, "notify.rate: 1-60", "notify.quiet_hours", "notify.doctor_interval: 5-1440",
	} {
		if !strings.Contains(errs, s) {
			t.Errorf("want error %q in:\n%s", s, errs)
		}
	}
	if strings.Contains(errs, "channels[0]") || strings.Contains(errs, "channels[1]") {
		t.Errorf("a valid channel rejected:\n%s", errs)
	}
	for _, sec := range []string{tgTestToken, "ntfy.example.com", "ftp://example.com"} {
		if strings.Contains(errs, sec) {
			t.Errorf("a validation message shows a secret value (%s)", sec)
		}
	}
	// defaults: rate, every event but apply (cert: the reverse proxy's certificates), a background doctor
	// while channels exist, json webhooks
	c.Notify = Notify{Channels: []NotifyChannel{{Name: "hook", Type: "webhook", URL: "hook_ok"}}}
	c.defaults()
	mustValid(t, c)
	n := c.Notify
	if n.Rate != 10 || strings.Join(n.Events, ",") != "wan_down,wan_up,failover,rollback,login_lock,new_device,boot,upgrade,doctor,cert" ||
		n.Doctor == nil || *n.Doctor != 30 || n.Channels[0].Format != "json" {
		t.Errorf("defaults: %+v", n)
	}
	if k := strings.Join(secretKeys(c), " "); !strings.Contains(k, "hook_ok") {
		t.Errorf("secretKeys lacks the webhook: %s", k)
	}
	// agents and API tokens cannot silence or redirect the owner's alerts
	locked := false
	for _, p := range tokenLocked {
		locked = locked || p == "notify"
	}
	if !locked {
		t.Error("notify is not token-locked")
	}
}

func TestNotifyQuietWindow(t *testing.T) {
	at := func(hm string) time.Time { t0, _ := time.Parse("15:04", hm); return t0 }
	for _, tc := range []struct {
		win, at string
		left    int64
	}{
		{"23:00-07:00", "23:30", 7*3600 + 1800}, {"23:00-07:00", "06:59", 60}, {"23:00-07:00", "07:00", 0}, {"23:00-07:00", "12:00", 0},
		{"12:00-13:00", "12:15", 45 * 60}, {"12:00-13:00", "13:15", 0}, {"", "12:00", 0}, {"25:00-07:00", "03:00", 0},
	} {
		if got := quietLeft(tc.win, at(tc.at)); got != tc.left {
			t.Errorf("quietLeft(%q, %s) = %d, want %d", tc.win, tc.at, got, tc.left)
		}
	}
	for n, want := range map[int]float64{0: 1, 1: 1, 2: 2, 3: 4, 5: 16, 6: 30, 9: 30} {
		if got := notifyBackoff(n); got != want {
			t.Errorf("notifyBackoff(%d) = %v, want %v", n, got, want)
		}
	}
}

// A webhook gets the pending events as one message; a failure keeps them and backs off; a new
// event (hook) tries at once; the cursor only moves after a message went out; no secret anywhere.
func TestNotifyFlushWebhook(t *testing.T) {
	c, f, _, now, up := notifyEnv(t)
	eventAdd(c, "wan_down", "warn", "wan", "wan lost its connection (pppoe on pppoe-wan)", false)
	*now = now.Add(95 * time.Second)
	eventAdd(c, "wan_up", "info", "wan", "wan is connected again after 1m35s down", false)
	eventAdd(c, "apply", "info", "7", "change #7 (web UI) confirmed", false) // not wanted by default
	st, err := notifyFlush(c, notifyRun{})
	if err != nil {
		t.Fatal(err)
	}
	r := f.take()
	if len(r) != 1 || r[0].Path != hookTestPath+"?key=s3cr3t-query" || r[0].Ctype != "application/json" {
		t.Fatalf("requests: %+v", r)
	}
	b := r[0].Body
	evs, _ := b["events"].([]any)
	if b["title"] != "mini-router: WAN down (+1)" || b["severity"] != "warn" || b["priority"] != 8.0 || len(evs) != 2 || b["host"] != "mini-router" ||
		b["message"] != "08:00 WARN WAN down: wan lost its connection (pppoe on pppoe-wan)\n08:01 WAN up: wan is connected again after 1m35s down" {
		t.Errorf("webhook body: %v", b)
	}
	if len(st) != 1 || st[0].Pending != 0 || st[0].LastOK == 0 || st[0].Error != "" {
		t.Errorf("status: %+v", st)
	}
	if _, err := notifyFlush(c, notifyRun{}); err != nil || len(f.take()) != 0 {
		t.Error("sent again")
	}

	// the service fails: kept, backed off, retried when due or at once for a new event
	f.fail = true
	eventAdd(c, "boot", "warn", "", "booted after an unexpected restart", false)
	notifyFlush(c, notifyRun{})
	if len(f.take()) != 1 {
		t.Fatal("no attempt")
	}
	s := notifyStatuses(c)[0]
	if s.Pending != 1 || s.Error != "webhook: HTTP 500" || s.Held != "retry" || s.RetryIn != 60 {
		t.Errorf("after a failure: %+v", s)
	}
	if b, _ := os.ReadFile(eventDueFile); strings.TrimSpace(string(b)) != "1060" {
		t.Errorf("event.due %q, want 1060 (uptime 1000 + 1 min)", b)
	}
	notifyFlush(c, notifyRun{})
	if len(f.take()) != 0 {
		t.Error("retried before the backoff ended")
	}
	*up += 61
	notifyFlush(c, notifyRun{})
	if len(f.take()) != 1 || notifyStatuses(c)[0].RetryIn != 120 {
		t.Errorf("second failure: %+v", notifyStatuses(c)[0])
	}
	f.fail = false
	notifyFlush(c, notifyRun{hook: true})
	if r := f.take(); len(r) != 1 || !strings.Contains(r[0].Body["message"].(string), "booted after an unexpected restart") {
		t.Errorf("hook flush: %+v", r)
	}
	if s := notifyStatuses(c)[0]; s.Pending != 0 || s.Error != "" || s.Held != "" {
		t.Errorf("after recovery: %+v", s)
	}
	stj, _ := json.Marshal(notifyStatuses(c))
	noSecret(t, "webhook", string(stj))

	// a connection that fails names neither the URL's path nor its query
	c.secrets["notify_hook"] = "http://127.0.0.1:1" + hookTestPath + "?key=s3cr3t-query"
	eventAdd(c, "boot", "info", "", "booted", false)
	notifyFlush(c, notifyRun{hook: true})
	s = notifyStatuses(c)[0]
	if !strings.HasPrefix(s.Error, "webhook: dial tcp 127.0.0.1:1: ") {
		t.Errorf("connection error: %q", s.Error)
	}
	noSecret(t, "connection error", s.Error)
}

// ntfy: plain text with Title / Priority headers.
func TestNotifyTextFormat(t *testing.T) {
	c, f, _, _, _ := notifyEnv(t)
	c.Notify.Channels[0].Format = "text"
	eventAdd(c, "login_lock", "warn", "192.0.2.9", "5 failed web UI logins from 192.0.2.9: locked for 30s", false)
	notifyFlush(c, notifyRun{})
	r := f.take()
	if len(r) != 1 || r[0].Title != "mini-router: Login locked" || r[0].Priority != "high" || !strings.HasPrefix(r[0].Ctype, "text/plain") ||
		r[0].Raw != "08:00 WARN Login locked: 5 failed web UI logins from 192.0.2.9: locked for 30s" {
		t.Errorf("ntfy request: %+v", r)
	}
}

// Telegram: sendMessage with the token only in the path; its refusal is reported, the token never.
func TestNotifyTelegram(t *testing.T) {
	c, f, srv, _, _ := notifyEnv(t)
	c.Notify.Channels = []NotifyChannel{{Name: "tg", Type: "telegram", Token: "notify_tg", ChatID: "-1001234567890"}}
	c.defaults()
	mustValid(t, c)
	notifyInit(c)
	eventAdd(c, "rollback", "warn", "8", "change #8 (mr apply) rolled back: not confirmed", false)
	notifyFlush(c, notifyRun{})
	r := f.take()
	if len(r) != 1 || r[0].Path != "/bot"+tgTestToken+"/sendMessage" || r[0].Body["chat_id"] != "-1001234567890" ||
		r[0].Body["text"] != "mini-router: Rollback\n08:00 WARN Rollback: change #8 (mr apply) rolled back: not confirmed" || r[0].Body["parse_mode"] != nil {
		t.Fatalf("Telegram request: %+v", r)
	}
	f.tg = `{"ok":false,"error_code":400,"description":"Bad Request: chat not found"}`
	res, err := notifyTest(c, "tg")
	if err != nil || len(res) != 1 || res[0]["ok"] != false || res[0]["error"] != "Telegram: HTTP 400 Bad Request: chat not found" {
		t.Errorf("test message refused: %v %v", res, err)
	}
	f.take()
	srv.Close()
	res, _ = notifyTest(c, "")
	e, _ := res[0]["error"].(string)
	if !strings.HasPrefix(e, "Telegram: dial tcp ") {
		t.Errorf("connection error: %q", e)
	}
	noSecret(t, "telegram", e)
	if _, err := notifyTest(c, "nope"); err == nil {
		t.Error("unknown channel accepted")
	}
}

// Rate limit per channel and hour; quiet hours hold info events but not warnings (which take the
// held ones along); a new channel starts at the end of the log; a removed one loses its cursor.
func TestNotifyRateQuietChannels(t *testing.T) {
	c, f, _, now, up := notifyEnv(t)
	c.Notify.Rate = 2
	for i := 0; i < 3; i++ {
		eventAdd(c, "new_device", "info", "", "dev", false)
		notifyFlush(c, notifyRun{hook: true})
		*up += 10
	}
	if n := len(f.take()); n != 2 {
		t.Errorf("rate 2: %d messages", n)
	}
	s := notifyStatuses(c)[0]
	if s.Held != "rate" || s.Pending != 1 {
		t.Errorf("rate: %+v", s)
	}
	if b, _ := os.ReadFile(eventDueFile); strings.TrimSpace(string(b)) != "4601" { // the first send (uptime 1000) + 1 h + 1 s
		t.Errorf("event.due %q", b)
	}
	*up += 3600
	notifyFlush(c, notifyRun{})
	if len(f.take()) != 1 {
		t.Error("held message not sent after the hour")
	}

	// router time is 08:00 (UTC0)
	c.Notify.QuietHours = "07:00-09:00"
	eventAdd(c, "new_device", "info", "", "quiet one", false)
	notifyFlush(c, notifyRun{hook: true})
	if len(f.take()) != 0 || notifyStatuses(c)[0].Held != "quiet_hours" {
		t.Errorf("info sent in quiet hours: %+v", notifyStatuses(c)[0])
	}
	*now = now.Add(time.Minute)
	eventAdd(c, "wan_down", "warn", "wan", "wan lost its connection", false)
	notifyFlush(c, notifyRun{hook: true})
	if r := f.take(); len(r) != 1 || !strings.Contains(r[0].Body["message"].(string), "quiet one") {
		t.Errorf("a warning in quiet hours: %+v", r)
	}

	// channels: a new one starts at the end, a removed one is forgotten
	c.Notify.Channels = append(c.Notify.Channels, NotifyChannel{Name: "ntfy", Type: "webhook", URL: "notify_hook", Format: "text"})
	notifyInit(c)
	notifyFlush(c, notifyRun{hook: true})
	if len(f.take()) != 0 {
		t.Error("a new channel got old events")
	}
	c.Notify.Channels = c.Notify.Channels[1:]
	notifyFlush(c, notifyRun{})
	var cur map[string]int64
	readJSONFile(notifyCursorFile, &cur)
	if _, ok := cur["hook"]; ok || len(cur) != 1 {
		t.Errorf("cursors: %v", cur)
	}
}

func TestNotifyBuild(t *testing.T) {
	c := testConfig(t)
	c.System.Timezone = "UTC0"
	now := time.Unix(1_800_000_000, 0)
	var evs []event
	for i := 0; i < 3; i++ {
		evs = append(evs, event{Seq: int64(i + 1), Time: now.Unix() + int64(60*i), Type: "wan_down", Sev: "warn", Key: "wan", Msg: "wan lost its connection"})
	}
	evs = append(evs, event{Seq: 4, Time: now.Unix() - 86400, Type: "new_device", Sev: "info", Msg: "设备 got 192.168.1.9"})
	m := notifyBuild(c, evs, now)
	if m.Title != "mini-router: WAN down (+1)" || m.Sev != "warn" ||
		m.Text != "08:00 WARN WAN down: wan lost its connection (x3, last 08:02)\n01-14 08:00 New device: 设备 got 192.168.1.9" {
		t.Errorf("message: %+v", m)
	}
	evs = nil
	for i := 0; i < 40; i++ {
		evs = append(evs, event{Seq: int64(i + 1), Time: now.Unix(), Type: "new_device", Sev: "info", Msg: strings.Repeat("x", 200) + string(rune('A'+i))})
	}
	m = notifyBuild(c, evs, now)
	if len(m.Text) > notifyMaxText+40 || !strings.HasSuffix(m.Text, "\n… (mr event list)") {
		t.Errorf("long message: %d bytes, ends %q", len(m.Text), m.Text[len(m.Text)-30:])
	}
	m = notifyBuild(c, evs[:35], now)
	if strings.Count(m.Text, "\n") > notifyMaxLines+1 {
		t.Errorf("%d lines", strings.Count(m.Text, "\n")+1)
	}
	c.System.Hostname = "路由"
	if m := notifyBuild(c, evs[:1], now); m.Title != "??: New device" {
		t.Errorf("non-ASCII title: %q", m.Title)
	}
}

func TestNotifyCommandAndAPI(t *testing.T) {
	d, _, _, _ := eventEnv(t)
	c := testConfig(t)
	for _, bad := range [][]string{nil, {"flush", "--now"}, {"nope"}} {
		if notifyCommand(c, bad) == nil {
			t.Errorf("mr notify %v accepted", bad)
		}
	}
	// flush --hook with a waiter present leaves at once
	w := flock(notifyWaitFile, false)
	t0 := time.Now()
	if err := notifyCommand(c, []string{"flush", "--hook"}); err != nil || time.Since(t0) > time.Second {
		t.Errorf("flush --hook with a waiter: %v, %v", err, time.Since(t0))
	}
	w.Close()
	if st := apiSysNotifyTest(apiReq{method: "GET"}).status; st != 405 {
		t.Errorf("GET sys.notifytest: %d", st)
	}
	if st := apiSysNotifyTest(apiReq{method: "POST", body: []byte(`{"name":"a b"}`)}).status; st != 400 {
		t.Errorf("bad name: %d", st)
	}
	oc, os_ := sysConfigPath, sysSecretsPath
	t.Cleanup(func() { sysConfigPath, sysSecretsPath = oc, os_ })
	sysConfigPath, sysSecretsPath = filepath.Join(d, "router.yaml"), "testdata/secrets.yaml"
	y, _ := os.ReadFile("../examples/router.yaml")
	os.WriteFile(sysConfigPath, y, 0644)
	if st := apiSysNotifyTest(apiReq{method: "POST", body: []byte(`{}`)}).status; st != 409 {
		t.Errorf("no channels: %d", st)
	}
}
