package main

// sys module: notifications (router.yaml notify; Cd1s/mini-router#16) — events of the event log
// (mod_sys_event.go) pushed to Telegram or to a webhook (ntfy, Bark, Gotify, Slack / Mattermost-style,
// Home Assistant, anything that takes a POST). Nothing resident:
//
//   - an event whose type is wanted starts `mr notify flush --hook` detached; it waits 5 s (one waiter at a
//     time, like DDNS), so a burst — a PPPoE reconnect is a down and an up — becomes one message;
//   - every channel has a cursor, the last event it got (/etc/mini-router/state/notify.json, written only
//     after a message went out): nothing is lost to a failed send, a WAN outage or a reboot — the next
//     flush sends everything after the cursor as one message (30 lines at most, repeats folded). A new
//     channel starts at the end of the log (history is not replayed);
//   - a failed send backs off 1, 2, 4 … 30 minutes (/run/mini-router/notify.json); the retry is an uptime
//     in /run/mini-router/event.due, which mr-mon's sampler compares every minute (a new event tries at once);
//   - rate limit: at most `rate` messages per channel and hour (default 10), the rest goes out together
//     later; quiet_hours ("23:00-07:00", router time): only warn / risk events are sent then, the others
//     wait for the end of the window (or ride along with a warning).
//
// Secrets: the Telegram bot token (part of the API URL) and the webhook URL (it usually carries a key)
// live in secrets.yaml and go only to their own service; they are never logged, stored in state or
// returned — error texts drop the URL and are scrubbed of both. HTTPS verifies against the system CA
// bundle; no proxy from the environment, no redirects, answers capped at 64 KiB.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

// Notify is router.yaml notify.
type Notify struct {
	Channels []NotifyChannel `yaml:"channels,omitempty"`
	// Events: the types to send (default: all but apply). See eventTypes.
	Events []string `yaml:"events,omitempty"`
	// Rate: messages per channel and hour, 1-60 (default 10); the rest waits and goes out together.
	Rate int `yaml:"rate,omitempty"`
	// QuietHours: "HH:MM-HH:MM" (router time): only warn / risk events are sent then.
	QuietHours string `yaml:"quiet_hours,omitempty"`
	// Doctor: minutes between background `mr doctor` runs whose new findings become events (5-1440;
	// 0 = off). Default 30 while channels exist, else off.
	Doctor *int `yaml:"doctor_interval,omitempty"`
}

// NotifyChannel is one destination.
type NotifyChannel struct {
	Name   string `yaml:"name"`
	Type   string `yaml:"type"`                   // telegram | webhook
	Token  string `yaml:"token_secret,omitempty"` // telegram: secrets.yaml key of the bot token (123456:ABC…)
	ChatID string `yaml:"chat_id,omitempty"`      // telegram: numeric chat id (-100… for groups) or @channel
	URL    string `yaml:"url_secret,omitempty"`   // webhook: secrets.yaml key of the URL
	Format string `yaml:"format,omitempty"`       // webhook: json (default: title / message / body / text …) | text (ntfy)
}

const (
	notifyDefaultRate   = 10
	notifyDefaultDoctor = 30
	notifyMaxChannels   = 4
	notifyMaxLines      = 30
	notifyMaxText       = 3500
	notifyMaxBody       = 64 << 10
	notifyDebounce      = 5 * time.Second
)

// runtime paths and hooks (variables so tests can use a temp dir / a fake service / no processes)
var (
	notifyCursorFile = "/etc/mini-router/state/notify.json"
	notifyStateFile  = RunDir + "/notify.json"
	notifyLockFile   = RunDir + "/notify.lock"
	notifyWaitFile   = RunDir + "/notify.wait"
	tgAPIBase        = "https://api.telegram.org"
	// notifyKick starts a background `mr notify flush --hook` unless one is already waiting.
	notifyKick = func() {
		if f := flock(notifyWaitFile, false); f != nil {
			f.Close() // the child takes it; of two kicks at once the second child finds it taken and exits
			self, args := selfCmd("notify", "flush", "--hook")
			startDetached(self, args...)
		}
	}
)

// notifyDefaultEvents: every type but apply (the owner usually made the change himself).
func notifyDefaultEvents() []string {
	var out []string
	for _, t := range eventTypes {
		if t != "apply" {
			out = append(out, t)
		}
	}
	return out
}

func notifyDefaults(c *Config) {
	n := &c.Notify
	if len(n.Channels) == 0 && len(n.Events) == 0 && n.Rate == 0 && n.QuietHours == "" && n.Doctor == nil {
		return // an absent section stays absent (plan / history of configs without it)
	}
	if n.Rate == 0 {
		n.Rate = notifyDefaultRate
	}
	if len(n.Events) == 0 {
		n.Events = notifyDefaultEvents()
	}
	if n.Doctor == nil && len(n.Channels) > 0 {
		d := notifyDefaultDoctor
		n.Doctor = &d
	}
	for i := range n.Channels {
		if ch := &n.Channels[i]; ch.Type == "webhook" && ch.Format == "" {
			ch.Format = "json"
		}
	}
}

var (
	reTGToken = lazyRegexp(`^[0-9]{3,20}:[A-Za-z0-9_-]{20,80}$`)
	reTGChat  = lazyRegexp(`^(-?[0-9]{1,20}|@[A-Za-z][A-Za-z0-9_]{3,31})$`)
	reHHMM    = lazyRegexp(`^([01][0-9]|2[0-3]):([0-5][0-9])-([01][0-9]|2[0-3]):([0-5][0-9])$`)
)

// notifyURLProblem says what is wrong with a webhook URL ("" = fine). It never repeats the URL.
func notifyURLProblem(s string) string {
	if len(s) > 2048 || !safeText(s) || strings.ContainsAny(s, " \t") {
		return "not a single-line URL (at most 2048 characters, no spaces)"
	}
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.Opaque != "" {
		return "not an http:// or https:// URL"
	}
	return ""
}

// quietWindow parses "HH:MM-HH:MM" into minutes of the day.
func quietWindow(s string) (from, to int, ok bool) {
	m := reHHMM.FindStringSubmatch(s)
	if m == nil {
		return 0, 0, false
	}
	from, to = atoi(m[1])*60+atoi(m[2]), atoi(m[3])*60+atoi(m[4])
	return from, to, from != to
}

// quietLeft: seconds until the quiet window around t ends (0 = t is outside it).
func quietLeft(s string, t time.Time) int64 {
	from, to, ok := quietWindow(s)
	if !ok {
		return 0
	}
	m := t.Hour()*60 + t.Minute()
	in := (from < to && m >= from && m < to) || (from > to && (m >= from || m < to))
	if !in {
		return 0
	}
	left := (to - m + 1440) % 1440
	return int64(left*60 - t.Second())
}

func validateNotify(c *Config, v *Validator) {
	n := c.Notify
	if len(n.Channels) > notifyMaxChannels {
		v.Add("notify.channels: at most %d", notifyMaxChannels)
	}
	seen := map[string]bool{}
	for i, ch := range n.Channels {
		p := fmt.Sprintf("notify.channels[%d]", i)
		if !reName.MatchString(ch.Name) {
			v.Add("%s.name: [a-z][a-z0-9_-]{0,14}, got %q", p, ch.Name)
		} else if seen[ch.Name] {
			v.Add("%s.name: duplicate %q", p, ch.Name)
		}
		seen[ch.Name] = true
		secret := func(key, name string, ok func(string) string) {
			if !reDDNSSecret.MatchString(name) {
				v.Add("%s.%s: secret name [a-z0-9_-]{1,40} required, got %q", p, key, name)
			} else if val, err := c.Secret(name); err != nil {
				v.Add("%s.%s: %v", p, key, err)
			} else if msg := ok(val); msg != "" {
				v.Add("%s.%s: the secret is %s", p, key, msg)
			}
		}
		switch ch.Type {
		case "telegram":
			secret("token_secret", ch.Token, func(s string) string {
				if !reTGToken.MatchString(s) {
					return "not a Telegram bot token (digits:letters, from @BotFather)"
				}
				return ""
			})
			if !reTGChat.MatchString(ch.ChatID) {
				v.Add("%s.chat_id: a numeric chat id (e.g. 123456789, -1001234567890) or @channelname, got %q", p, ch.ChatID)
			}
			if ch.URL != "" || ch.Format != "" {
				v.Add("%s: url_secret / format are for webhooks", p)
			}
		case "webhook":
			secret("url_secret", ch.URL, notifyURLProblem)
			if ch.Format != "json" && ch.Format != "text" {
				v.Add("%s.format: json | text, got %q", p, ch.Format)
			}
			if ch.Token != "" || ch.ChatID != "" {
				v.Add("%s: token_secret / chat_id are for telegram", p)
			}
		default:
			v.Add("%s.type: telegram | webhook, got %q", p, ch.Type)
		}
	}
	known := map[string]bool{}
	for _, t := range eventTypes {
		known[t] = true
	}
	dup := map[string]bool{}
	for _, t := range n.Events {
		if !known[t] {
			v.Add("notify.events: unknown %q (%s)", t, strings.Join(eventTypes, ", "))
		} else if dup[t] {
			v.Add("notify.events: duplicate %q", t)
		}
		dup[t] = true
	}
	if n.Rate < 0 || n.Rate > 60 {
		v.Add("notify.rate: 1-60 messages per hour, got %d", n.Rate)
	}
	if n.QuietHours != "" {
		if _, _, ok := quietWindow(n.QuietHours); !ok {
			v.Add("notify.quiet_hours: HH:MM-HH:MM (e.g. 23:00-07:00), got %q", n.QuietHours)
		}
	}
	if d := n.Doctor; d != nil && *d != 0 && (*d < 5 || *d > 1440) {
		v.Add("notify.doctor_interval: 5-1440 minutes or 0 (off), got %d", *d)
	}
}

func notifySecrets(c *Config) []string {
	var out []string
	for _, ch := range c.Notify.Channels {
		for _, s := range []string{ch.Token, ch.URL} {
			if s != "" {
				out = append(out, s)
			}
		}
	}
	return out
}

// notifyWants: some channel should get events of type typ.
func notifyWants(c *Config, typ string) bool {
	if len(c.Notify.Channels) == 0 {
		return false
	}
	for _, t := range c.Notify.Events {
		if t == typ {
			return true
		}
	}
	return false
}

func notifyDoctorInterval(c *Config) int {
	if c == nil || c.Notify.Doctor == nil {
		return 0
	}
	return *c.Notify.Doctor
}

// ---- state ----

// notifyChState: how a channel's sends went (RAM; uptimes are only valid within one boot).
type notifyChState struct {
	Fails   int       `json:"fails,omitempty"`
	Retry   float64   `json:"retry,omitempty"` // uptime (s): no automatic attempt before
	Sent    []float64 `json:"sent,omitempty"`  // uptimes of this hour's messages (rate)
	LastOK  int64     `json:"last_ok,omitempty"`
	Error   string    `json:"error,omitempty"`
	ErrorAt int64     `json:"error_at,omitempty"`
	Held    string    `json:"held,omitempty"` // why events wait: retry | rate | quiet_hours
}

// notifyStatus: what `mr notify status` / sys.events show of a channel (never a secret).
type notifyStatus struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Pending int    `json:"pending"` // events waiting for this channel
	LastOK  int64  `json:"last_ok,omitempty"`
	Error   string `json:"error,omitempty"`
	ErrorAt int64  `json:"error_at,omitempty"`
	RetryIn int64  `json:"retry_in,omitempty"` // seconds
	Held    string `json:"held,omitempty"`
}

func readJSONFile(path string, v any) { // missing / broken: v stays as it is
	if b, err := os.ReadFile(path); err == nil {
		json.Unmarshal(b, v)
	}
}

func notifyLoad() (map[string]int64, map[string]*notifyChState) {
	cur := map[string]int64{}
	st := map[string]*notifyChState{}
	readJSONFile(notifyCursorFile, &cur)
	readJSONFile(notifyStateFile, &st)
	for k, s := range st {
		if s == nil {
			delete(st, k)
		}
	}
	return cur, st
}

// notifyBackoff: minutes until the next automatic attempt after the n-th failure in a row.
func notifyBackoff(n int) float64 {
	if n < 1 {
		n = 1
	}
	if n > 6 {
		return 30
	}
	return min(float64(int(1)<<(n-1)), 30)
}

// notifyPending: the events after cursor that channel settings want.
func notifyPending(c *Config, evs []event, cursor int64) []event {
	want := map[string]bool{}
	for _, t := range c.Notify.Events {
		want[t] = true
	}
	var out []event
	for _, e := range evs {
		if e.Seq > cursor && want[e.Type] {
			out = append(out, e)
		}
	}
	return out
}

// notifyInit gives channels without a cursor the end of the log (an apply that adds a channel: only
// what happens from now on is sent) and drops the cursors of removed channels.
func notifyInit(c *Config) {
	lk := flock(notifyLockFile, true)
	if lk != nil {
		defer lk.Close()
	}
	cur, _ := notifyLoad()
	last := eventLastSeq()
	out := map[string]int64{}
	for _, ch := range c.Notify.Channels {
		if v, ok := cur[ch.Name]; ok && v <= last {
			out[ch.Name] = v
		} else {
			out[ch.Name] = last
		}
	}
	if fmt.Sprint(out) != fmt.Sprint(cur) {
		b, _ := json.Marshal(out)
		writeAtomic(notifyCursorFile, b, 0600)
	}
}

// ---- flush ----

type notifyRun struct {
	hook bool // started by a new event: try at once whatever the backoff says
}

// notifyFlush sends every channel what is pending for it, as far as backoff, rate and quiet hours
// allow, and schedules the next attempt.
func notifyFlush(c *Config, o notifyRun) ([]notifyStatus, error) {
	lk := flock(notifyLockFile, true)
	if lk == nil {
		return nil, errors.New("cannot lock " + notifyLockFile)
	}
	defer lk.Close()
	cur, st := notifyLoad()
	all := eventsRead(0, 0)
	last := int64(0)
	if len(all) > 0 {
		last = all[len(all)-1].Seq
	}
	up, now := eventUptime(), eventNow()
	due := 0.0
	later := func(t float64) {
		if t > 0 && (due == 0 || t < due) {
			due = t
		}
	}
	curChanged := false
	var hc *http.Client
	keep := map[string]bool{}
	for _, ch := range c.Notify.Channels {
		keep[ch.Name] = true
		s := st[ch.Name]
		if s == nil {
			s = &notifyChState{}
			st[ch.Name] = s
		}
		cr, ok := cur[ch.Name]
		switch {
		case !ok: // a channel this flush has not seen before: from now on
			cur[ch.Name], curChanged = last, true
			continue
		case cr > last: // the log was reset
			cr, cur[ch.Name], curChanged = 0, 0, true
		}
		var sent []float64
		for _, t := range s.Sent {
			if t > up-3600 && t <= up {
				sent = append(sent, t)
			}
		}
		s.Sent = sent
		pend := notifyPending(c, all, cr)
		if len(pend) == 0 {
			s.Held = ""
			continue
		}
		urgent := false
		for _, e := range pend {
			urgent = urgent || e.Sev != "info"
		}
		if left := quietLeft(c.Notify.QuietHours, now.In(sysLocation(c))); left > 0 && !urgent {
			s.Held = "quiet_hours"
			later(up + float64(left) + 1)
			continue
		}
		if !o.hook && up < s.Retry {
			s.Held = "retry"
			later(s.Retry)
			continue
		}
		if rate := c.Notify.Rate; rate > 0 && len(s.Sent) >= rate {
			s.Held = "rate"
			later(s.Sent[0] + 3600 + 1)
			continue
		}
		if hc == nil {
			hc = ddnsHTTP()
		}
		err := notifySend(c, hc, ch, notifyBuild(c, pend, now))
		if err != nil {
			if err.Error() != s.Error {
				logf("notify %s: %s", ch.Name, err)
			}
			s.Fails++
			s.Retry = up + 60*notifyBackoff(s.Fails)
			s.Error, s.ErrorAt, s.Held = err.Error(), now.Unix(), "retry"
			later(s.Retry)
			continue
		}
		if s.Error != "" {
			logf("notify %s: works again", ch.Name)
		}
		s.Sent = append(s.Sent, up)
		s.LastOK, s.Fails, s.Retry, s.Error, s.ErrorAt, s.Held = now.Unix(), 0, 0, "", 0, ""
		cur[ch.Name], curChanged = last, true
	}
	for k := range st {
		if !keep[k] {
			delete(st, k)
		}
	}
	for k := range cur {
		if !keep[k] {
			delete(cur, k)
			curChanged = true
		}
	}
	b, _ := json.Marshal(st)
	writeAtomic(notifyStateFile, b, 0600)
	if curChanged {
		b, _ := json.Marshal(cur)
		if err := writeAtomic(notifyCursorFile, b, 0600); err != nil {
			logf("notify: %v", err)
		}
	}
	eventRunUpdate(func(r *eventRun) { r.NotifyDue = due })
	return notifyStatusFrom(c, all, cur, st, up), nil
}

func notifyStatusFrom(c *Config, all []event, cur map[string]int64, st map[string]*notifyChState, up float64) []notifyStatus {
	out := []notifyStatus{}
	for _, ch := range c.Notify.Channels {
		ns := notifyStatus{Name: ch.Name, Type: ch.Type}
		if cr, ok := cur[ch.Name]; ok {
			ns.Pending = len(notifyPending(c, all, cr))
		}
		if s := st[ch.Name]; s != nil {
			ns.LastOK, ns.Error, ns.ErrorAt, ns.Held = s.LastOK, s.Error, s.ErrorAt, s.Held
			if s.Retry > up {
				ns.RetryIn = int64(s.Retry - up)
			}
		}
		if ns.Pending == 0 {
			ns.Held = ""
		}
		out = append(out, ns)
	}
	return out
}

// notifyStatuses: the channels' state without sending anything.
func notifyStatuses(c *Config) []notifyStatus {
	cur, st := notifyLoad()
	return notifyStatusFrom(c, eventsRead(0, 0), cur, st, eventUptime())
}

// ---- messages ----

type notifyMsg struct {
	Title  string // "<host>: <what>" (ASCII: also an HTTP header for ntfy)
	Text   string // one line per event
	Sev    string // worst: info | warn | risk
	Events []event
}

var sevRank = map[string]int{"info": 0, "warn": 1, "risk": 2}

// notifyBuild makes one message of events (oldest first): repeats of the same event are folded,
// at most notifyMaxLines lines, times in the router's zone.
func notifyBuild(c *Config, evs []event, now time.Time) notifyMsg {
	loc := sysLocation(c)
	type row struct {
		e    event
		n    int
		last int64
	}
	var rows []*row
	idx := map[string]*row{}
	worst := "info"
	for _, e := range evs {
		if sevRank[e.Sev] > sevRank[worst] {
			worst = e.Sev
		}
		k := e.Type + "\x00" + e.Key + "\x00" + e.Msg
		if r := idx[k]; r != nil {
			r.n++
			r.last = e.Time
			continue
		}
		r := &row{e: e, n: 1}
		idx[k] = r
		rows = append(rows, r)
	}
	today := now.In(loc).Format("2006-01-02")
	stamp := func(t int64) string {
		lt := time.Unix(t, 0).In(loc)
		if lt.Format("2006-01-02") == today {
			return lt.Format("15:04")
		}
		return lt.Format("01-02 15:04")
	}
	var lines []string
	head := ""
	for i, r := range rows {
		if i >= notifyMaxLines {
			lines = append(lines, fmt.Sprintf("… and %d more (mr event list)", len(rows)-i))
			break
		}
		l := stamp(r.e.Time) + " "
		if r.e.Sev != "info" {
			l += strings.ToUpper(r.e.Sev) + " "
		}
		l += eventLabels[r.e.Type] + ": " + r.e.Msg
		if r.n > 1 {
			l += fmt.Sprintf(" (x%d, last %s)", r.n, stamp(r.last))
		}
		lines = append(lines, l)
		if head == "" && r.e.Sev == worst {
			head = eventLabels[r.e.Type]
		}
	}
	title := c.System.Hostname + ": " + head
	if len(rows) > 1 {
		title += fmt.Sprintf(" (+%d)", len(rows)-1)
	}
	text := strings.Join(lines, "\n")
	if len(text) > notifyMaxText { // whole lines only (Telegram takes 4096 characters)
		cut := strings.LastIndexByte(text[:notifyMaxText], '\n')
		if cut < 0 {
			cut = 0
		}
		text = text[:cut] + "\n… (mr event list)"
	}
	return notifyMsg{Title: asciiOnly(title), Text: text, Sev: worst, Events: evs}
}

func asciiOnly(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r > 0x7e {
			return '?'
		}
		return r
	}, s)
}

// notifyErr: a send failure as one line without the URL and without any secret of the channel.
func notifyErr(err error, secrets ...string) error {
	s := ddnsErrText(err)
	for _, x := range secrets {
		if x == "" {
			continue
		}
		for _, v := range []string{x, url.PathEscape(x), url.QueryEscape(x)} {
			s = strings.ReplaceAll(s, v, "***")
		}
	}
	return errors.New(s)
}

// notifySend delivers one message to one channel.
func notifySend(c *Config, hc *http.Client, ch NotifyChannel, m notifyMsg) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	switch ch.Type {
	case "telegram":
		tok, err := c.Secret(ch.Token)
		if err != nil {
			return err
		}
		return notifyErrIf(tgSend(ctx, hc, tok, ch.ChatID, m), tok)
	case "webhook":
		u, err := c.Secret(ch.URL)
		if err != nil {
			return err
		}
		if p := notifyURLProblem(u); p != "" {
			return errors.New("url_secret: " + p)
		}
		return notifyErrIf(hookSend(ctx, hc, u, ch.Format, c.System.Hostname, m), u)
	}
	return fmt.Errorf("unknown channel type %q", ch.Type)
}

func notifyErrIf(err error, secret string) error {
	if err == nil {
		return nil
	}
	return notifyErr(err, secret)
}

// httpPost sends body and reads at most notifyMaxBody of the answer.
func httpPost(ctx context.Context, hc *http.Client, u, ctype string, hdr map[string]string, body []byte) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", u, bytes.NewReader(body))
	if err != nil {
		return 0, nil, errors.New("bad request")
	}
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", "mini-router/"+version)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, notifyMaxBody))
	return resp.StatusCode, raw, nil
}

// tgSend: Bot API sendMessage, plain text (no parse mode: nothing in an event can become markup).
func tgSend(ctx context.Context, hc *http.Client, token, chat string, m notifyMsg) error {
	body, _ := json.Marshal(map[string]any{"chat_id": chat, "text": m.Title + "\n" + m.Text, "disable_web_page_preview": true})
	code, raw, err := httpPost(ctx, hc, tgAPIBase+"/bot"+token+"/sendMessage", "application/json", nil, body)
	if err != nil {
		return fmt.Errorf("Telegram: %w", err)
	}
	var r struct {
		OK   bool   `json:"ok"`
		Desc string `json:"description"`
	}
	if json.Unmarshal(raw, &r) != nil {
		return fmt.Errorf("Telegram: HTTP %d, not an API answer", code)
	}
	if !r.OK || code/100 != 2 {
		return fmt.Errorf("Telegram: HTTP %d %s", code, eventClean(r.Desc, 160))
	}
	return nil
}

// hookSend: json = {title, message, body, text, content, priority, severity, host, events} (the keys
// Gotify, Bark, Slack / Mattermost and Discord read; Home Assistant and custom receivers get the
// events); text = the lines as a plain body with Title / Priority headers (ntfy).
func hookSend(ctx context.Context, hc *http.Client, u, format, host string, m notifyMsg) error {
	var code int
	var err error
	if format == "text" {
		prio := "default"
		if m.Sev != "info" {
			prio = "high"
		}
		code, _, err = httpPost(ctx, hc, u, "text/plain; charset=utf-8", map[string]string{"Title": m.Title, "Priority": prio}, []byte(m.Text))
	} else {
		prio := 5
		if m.Sev != "info" {
			prio = 8
		}
		full := m.Title + "\n" + m.Text
		body, _ := json.Marshal(map[string]any{"title": m.Title, "message": m.Text, "body": m.Text, "text": full, "content": full,
			"priority": prio, "severity": m.Sev, "host": host, "events": m.Events})
		code, _, err = httpPost(ctx, hc, u, "application/json", nil, body)
	}
	if err != nil {
		return fmt.Errorf("webhook: %w", err)
	}
	if code/100 != 2 {
		return fmt.Errorf("webhook: HTTP %d", code)
	}
	return nil
}

// notifyTest sends a test message to one channel (or all) now — no rate limit, quiet hours or backoff.
func notifyTest(c *Config, name string) ([]map[string]any, error) {
	var out []map[string]any
	found := false
	hc := ddnsHTTP()
	for _, ch := range c.Notify.Channels {
		if name != "" && ch.Name != name {
			continue
		}
		found = true
		m := notifyMsg{Title: asciiOnly(c.System.Hostname + ": test"), Sev: "info",
			Text: fmt.Sprintf("Test message from mini-router %s (channel %s, %s). Events sent here: %s.", c.System.Hostname, ch.Name, ch.Type, strings.Join(c.Notify.Events, ", "))}
		r := map[string]any{"name": ch.Name, "ok": true}
		if err := notifySend(c, hc, ch, m); err != nil {
			r["ok"], r["error"] = false, err.Error()
		}
		out = append(out, r)
	}
	if !found {
		if name == "" {
			return nil, errors.New("notify has no channels")
		}
		return nil, fmt.Errorf("no notify channel %q", name)
	}
	return out, nil
}

// ---- mr notify, API ----

// notifyCommand: `mr notify status | test [NAME] | flush [--hook]`.
func notifyCommand(c *Config, args []string) error {
	usage := errors.New("usage: mr notify status | test [NAME] | flush [--hook]")
	if len(args) == 0 {
		return usage
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", " ")
	switch args[0] {
	case "status":
		return enc.Encode(notifyStatuses(c))
	case "test":
		name := ""
		if len(args) > 1 {
			name = args[1]
		}
		r, err := notifyTest(c, name)
		if err != nil {
			return err
		}
		return enc.Encode(r)
	case "flush":
		o := notifyRun{}
		if len(args) > 1 {
			if args[1] != "--hook" {
				return usage
			}
			// debounce: one waiter at a time, released before the log is read, so an event after this
			// point starts the next waiter
			w := flock(notifyWaitFile, false)
			if w == nil {
				return nil
			}
			time.Sleep(notifyDebounce)
			w.Close()
			o.hook = true
		}
		if len(c.Notify.Channels) == 0 {
			return nil
		}
		_, err := notifyFlush(c, o)
		return err
	}
	return usage
}

// apiSysNotifyTest: POST {name (optional)} sends a test message now; → {results: [{name, ok, error}]}.
func apiSysNotifyTest(r apiReq) apiResp {
	if r.method != "POST" {
		return errResp(405, "POST required")
	}
	var in struct {
		Name string `json:"name"`
	}
	json.Unmarshal(r.body, &in)
	if in.Name != "" && !reName.MatchString(in.Name) {
		return errResp(400, "bad channel name")
	}
	c, err := loadConfig(ConfigPath, SecretsPath)
	if err != nil {
		return errResp(500, "%v", err)
	}
	if len(c.Notify.Channels) == 0 {
		return errResp(409, "no notify channels (apply a config with notify.channels first)")
	}
	res, err := notifyTest(c, in.Name)
	if err != nil {
		return errResp(400, "%v", err)
	}
	sort.SliceStable(res, func(i, j int) bool { return fmt.Sprint(res[i]["name"]) < fmt.Sprint(res[j]["name"]) })
	return apiResp{body: map[string]any{"results": res}}
}
