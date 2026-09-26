package main

// DNS ad blocking (dns.adblock, Cd1s/mini-router#30), off by default. No new process: `mr dns adblock
// update` downloads the lists (https only), keeps valid domain names, drops duplicates and names under
// another listed name, removes the allowed ones, and writes one `local=/name/` line per domain to
// adblockConf, which both dnsmasq instances (main, proxy) load. A blocked name and everything under it
// answers NXDOMAIN; an allowed name under a blocked one is forwarded as usual (`server=/name/#`).
//
// Updates never make things worse: a list that fails to download or does not look like a domain list
// (fewer than half of its lines usable) keeps the previous file, and so does a result above
// max_domains. After a new file dnsmasq (and the proxy's instance) restart — DNS pauses for a second
// or two — and if dnsmasq does not answer again, the previous file is put back.
//
// Schedule: crond runs `mr dns adblock update --cron` every hour. It only downloads when the file is
// 20 hours old or was built from other settings (lists, allow, max_domains), so the first download
// after switching it on, and a retry after a failure, come within the hour. Never while a change waits
// for confirmation. The router's own traffic does not go through the proxy.
//
// Cost: dnsmasq keeps roughly 100 bytes per domain and instance (HaGeZi Multi NORMAL, ~165k: ~16 MB,
// twice with the proxy's instance), the file ~25 bytes per domain on flash (UBIFS compresses it).

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Adblock struct {
	Enabled    bool     `yaml:"enabled"`
	Lists      []string `yaml:"lists"`       // https URLs: plain domains, hosts, adblock (||name^) or dnsmasq lines
	Allow      []string `yaml:"allow"`       // never blocked, with everything under them
	MaxDomains int      `yaml:"max_domains"` // default 300000
}

const (
	adblockDefaultMax = 300000
	adblockListBytes  = 64 << 20 // per download
	adblockMaxLists   = 8
	adblockMaxAllow   = 1000
	adblockAge        = 20 * time.Hour
)

// variables so tests can point them elsewhere
var (
	adblockConf   = "/etc/mini-router/state/adblock.conf"
	adblockStatus = RunDir + "/adblock.json"
	adblockLock   = RunDir + "/adblock.lock"
	adblockHTTP   = func() *http.Client {
		return &http.Client{Timeout: 2 * time.Minute, CheckRedirect: func(r *http.Request, via []*http.Request) error {
			if r.URL.Scheme != "https" || len(via) >= 5 {
				return errors.New("redirect to " + r.URL.Scheme + " refused")
			}
			return nil
		}}
	}
	adblockNow = time.Now
	// adblockReload restarts the dnsmasq instances that load the file and waits until dnsmasq answers
	adblockReload = func() error {
		if err := restartDnsmasq(); err != nil {
			return err
		}
		if _, err := run("rc-service", "mr-proxy-dns", "status"); err == nil {
			run("rc-service", "mr-proxy-dns", "restart")
		}
		if !waitFor(time.Now().Add(30*time.Second), func() bool {
			_, _, err := dnsQuery(dnsLocal, "localhost", dnsTypeA, dnsClassIN, time.Second)
			return err == nil
		}) {
			return errors.New("dnsmasq does not answer")
		}
		return nil
	}
)

const adblockEmpty = "# mr dns adblock: no list yet (`mr dns adblock update`)\n"

// adblockLines: what dnsmasq.conf (and the proxy's) gets while ad blocking is on.
func adblockLines(c *Config) []string {
	if !c.DNS.Adblock.Enabled {
		return nil
	}
	return []string{"conf-file=" + adblockConf}
}

// adblockRender: the file must exist before dnsmasq starts with conf-file= (dnsmasq refuses a missing
// one); an existing file is left to the updater and never becomes part of a plan or a snapshot.
func adblockRender(c *Config, out *Out) {
	if !c.DNS.Adblock.Enabled {
		return
	}
	if _, err := os.Stat(adblockConf); err != nil {
		out.Add(adblockConf, 0644, adblockEmpty)
	}
}

func adblockValidate(c *Config, v *Validator) {
	a := &c.DNS.Adblock
	if a.Enabled && len(a.Lists) == 0 {
		v.Add("dns.adblock.lists: at least one list while enabled")
	}
	if len(a.Lists) > adblockMaxLists {
		v.Add("dns.adblock.lists: at most %d", adblockMaxLists)
	}
	for i, l := range a.Lists {
		if !adblockURLOK(l) {
			v.Add("dns.adblock.lists[%d]: an https:// URL (no user, no spaces, at most 512 characters), got %q", i, l)
		}
	}
	if len(a.Allow) > adblockMaxAllow {
		v.Add("dns.adblock.allow: at most %d", adblockMaxAllow)
	}
	for i, d := range a.Allow {
		if adblockName(d) == "" {
			v.Add("dns.adblock.allow[%d]: a domain name like example.com, got %q", i, d)
		}
	}
	if a.MaxDomains != 0 && (a.MaxDomains < 1000 || a.MaxDomains > 1000000) {
		v.Add("dns.adblock.max_domains: 1000-1000000, got %d", a.MaxDomains)
	}
}

func adblockURLOK(s string) bool {
	u, err := url.Parse(s)
	return err == nil && len(s) <= 512 && u.Scheme == "https" && u.Hostname() != "" && u.User == nil &&
		!strings.ContainsAny(s, " \t\r\n\"'\\") && u.Fragment == ""
}

// adblockName normalizes one name from a list: lower case, no leading "*." / "." or trailing ".",
// a valid DNS name with at least two labels that is not an IP address. "" = not usable.
func adblockName(s string) string {
	s = strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(s, "*."), "."), "."))
	if !strings.Contains(s, ".") || !validDNSName(s) || net.ParseIP(s) != nil || s == "localhost.localdomain" {
		return ""
	}
	return s
}

// adblockLineNames: the names one list line blocks, nil when the line is not usable. Formats: a plain
// name (or *.name), hosts ("0.0.0.0 name …"), adblock ("||name^", "||name^$important"), dnsmasq
// ("local=/name/", "address=/name/…", "server=/name/").
func adblockLineNames(l string) []string {
	var raw []string
	f := strings.Fields(l)
	switch {
	case strings.HasPrefix(l, "||"):
		name, rest, ok := strings.Cut(l[2:], "^")
		if !ok || (rest != "" && rest != "$important" && rest != "|") {
			return nil
		}
		raw = []string{name}
	case strings.HasPrefix(l, "local=/") || strings.HasPrefix(l, "address=/") || strings.HasPrefix(l, "server=/"):
		key, rest, _ := strings.Cut(l, "=/")
		parts := strings.Split(rest, "/")
		// server=/name/1.2.3.4 forwards and server=/name/# is an exception: only an empty server= blocks
		if len(parts) < 2 || (key != "address" && parts[len(parts)-1] != "") {
			return nil
		}
		raw = parts[:len(parts)-1]
	case len(f) >= 2 && net.ParseIP(f[0]) != nil:
		raw = f[1:]
	case len(f) == 1:
		raw = f
	default:
		return nil
	}
	var out []string
	for _, r := range raw {
		n := adblockName(r)
		if n == "" {
			if r == "localhost" || r == "localhost.localdomain" || r == "local" || r == "broadcasthost" ||
				strings.HasPrefix(r, "ip6-") { // the standard lines at the top of a hosts file
				continue
			}
			return nil
		}
		out = append(out, n)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// adblockParse reads one list into set; good / total count the lines that are not comments.
func adblockParse(r io.Reader, set map[string]bool) (good, total int, err error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l == "" || l[0] == '#' || l[0] == '!' || l[0] == '[' {
			continue
		}
		// a comment after the entry ("0.0.0.0 ads.example # tracker"); "example.com##.ad" is an
		// element-hiding rule, not a name, and stays unusable
		if i := strings.Index(l, " #"); i >= 0 {
			l = strings.TrimSpace(l[:i])
		} else if i := strings.Index(l, "\t#"); i >= 0 {
			l = strings.TrimSpace(l[:i])
		}
		total++
		if strings.Contains(l, "#") && !strings.HasPrefix(l, "address=/") { // address=/name/# = the null address
			continue
		}
		names := adblockLineNames(l)
		if names == nil {
			continue
		}
		good++
		for _, n := range names {
			set[n] = true
		}
	}
	return good, total, sc.Err()
}

// under reports whether d is name or a name below it.
func under(d, name string) bool { return d == name || strings.HasSuffix(d, "."+name) }

// adblockBuild: the names to block (sorted, none under another), and the allowed names that sit
// under a blocked one (forwarded as usual). allow also removes everything under it.
func adblockBuild(set map[string]bool, allow []string) (block, fwd []string) {
	parentIn := func(d string, m map[string]bool) bool {
		for p := d; ; {
			i := strings.IndexByte(p, '.')
			if i < 0 {
				return false
			}
			p = p[i+1:]
			if m[p] {
				return true
			}
		}
	}
	allowed := map[string]bool{}
	for _, a := range allow {
		allowed[a] = true
	}
	kept := map[string]bool{}
	for d := range set {
		if allowed[d] || parentIn(d, allowed) || parentIn(d, set) {
			continue
		}
		kept[d] = true
		block = append(block, d)
	}
	sort.Strings(block)
	for _, a := range dedup(allow) {
		if parentIn(a, kept) {
			fwd = append(fwd, a)
		}
	}
	sort.Strings(fwd)
	return block, fwd
}

// adblockImplicitAllow: names the router itself needs: the lists' hosts (or updates would block
// themselves), the NTP servers, the local domain.
func adblockImplicitAllow(c *Config) []string {
	var out []string
	for _, l := range c.DNS.Adblock.Lists {
		if u, err := url.Parse(l); err == nil && adblockName(u.Hostname()) != "" {
			out = append(out, adblockName(u.Hostname()))
		}
	}
	for _, h := range ntpHostnames(c) {
		if n := adblockName(h); n != "" {
			out = append(out, n)
		}
	}
	if n := adblockName(c.DHCP.Domain); n != "" {
		out = append(out, n)
	}
	return out
}

// adblockConfigHash: what the file was built from (the header records it; --cron rebuilds on a change).
func adblockConfigHash(c *Config) string {
	a := &c.DNS.Adblock
	h := sha256.Sum256([]byte(strings.Join(a.Lists, "\n") + "\x00" + strings.Join(a.Allow, "\n") + "\x00" + strconv.Itoa(adblockMax(c))))
	return hex.EncodeToString(h[:6])
}

func adblockMax(c *Config) int {
	if n := c.DNS.Adblock.MaxDomains; n > 0 {
		return n
	}
	return adblockDefaultMax
}

// adblockHeader is the file's first line: "# mr dns adblock: domains=N time=UNIX config=HASH".
type adblockHeader struct {
	Domains int
	Time    int64
	Config  string
}

func adblockReadHeader() adblockHeader {
	var h adblockHeader
	f, err := os.Open(adblockConf)
	if err != nil {
		return h
	}
	defer f.Close()
	line, _ := bufio.NewReader(f).ReadString('\n')
	for _, kv := range strings.Fields(strings.TrimPrefix(line, "# mr dns adblock:")) {
		k, v, _ := strings.Cut(kv, "=")
		switch k {
		case "domains":
			h.Domains, _ = strconv.Atoi(v)
		case "time":
			h.Time, _ = strconv.ParseInt(v, 10, 64)
		case "config":
			h.Config = v
		}
	}
	return h
}

type adblockListResult struct {
	URL     string `json:"url"`
	Domains int    `json:"domains"` // usable lines
	Lines   int    `json:"lines"`
	Error   string `json:"error,omitempty"`
}

type adblockResult struct {
	Time    int64               `json:"time"`
	OK      bool                `json:"ok"`
	Domains int                 `json:"domains"`
	Changed bool                `json:"changed"`
	Lists   []adblockListResult `json:"lists"`
	Error   string              `json:"error,omitempty"`
}

// adblockFetch downloads and parses one list into set.
func adblockFetch(ctx context.Context, hc *http.Client, u string, set map[string]bool) adblockListResult {
	r := adblockListResult{URL: u}
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		r.Error = err.Error()
		return r
	}
	req.Header.Set("User-Agent", "mini-router")
	resp, err := hc.Do(req)
	if err != nil {
		r.Error = ddnsErrText(err)
		return r
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		r.Error = "HTTP " + resp.Status
		return r
	}
	one := map[string]bool{}
	lr := &io.LimitedReader{R: resp.Body, N: adblockListBytes + 1}
	good, total, err := adblockParse(lr, one)
	switch {
	case err != nil:
		r.Error = ddnsErrText(err)
	case lr.N <= 0:
		r.Error = fmt.Sprintf("larger than %d MiB", adblockListBytes>>20)
	case good == 0 || good*2 < total:
		r.Error = fmt.Sprintf("not a domain list (%d of %d lines usable)", good, total)
	}
	r.Domains, r.Lines = good, total
	if r.Error == "" {
		for d := range one {
			set[d] = true
		}
	}
	return r
}

// adblockUpdate is `mr dns adblock update [--cron] [--no-reload]`.
func adblockUpdate(c *Config, cron, reload bool) (*adblockResult, error) {
	if !c.DNS.Adblock.Enabled {
		return nil, errors.New("dns.adblock is off")
	}
	lk := flock(adblockLock, false)
	if lk == nil {
		if cron {
			return nil, nil
		}
		return nil, errors.New("an update is already running")
	}
	defer lk.Close()
	if err := pendingBlocks(); err != nil {
		if cron {
			return nil, nil
		}
		return nil, err
	}
	hdr, cfg := adblockReadHeader(), adblockConfigHash(c)
	if cron && hdr.Config == cfg && adblockNow().Sub(time.Unix(hdr.Time, 0)) < adblockAge {
		return nil, nil
	}
	res := &adblockResult{Time: adblockNow().Unix()}
	defer func() {
		b, _ := json.Marshal(res)
		writeAtomic(adblockStatus, b, 0644)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	set, hc := map[string]bool{}, adblockHTTP()
	var failed []string
	for _, u := range c.DNS.Adblock.Lists {
		r := adblockFetch(ctx, hc, u, set)
		res.Lists = append(res.Lists, r)
		if r.Error != "" {
			failed = append(failed, u+": "+r.Error)
		}
	}
	if len(failed) > 0 {
		res.Error = "kept the previous lists: " + strings.Join(failed, "; ")
		logf("dns: adblock: %s", res.Error)
		return res, errors.New(res.Error)
	}
	var allow []string
	for _, a := range append(append([]string{}, c.DNS.Adblock.Allow...), adblockImplicitAllow(c)...) {
		if n := adblockName(a); n != "" {
			allow = append(allow, n)
		}
	}
	block, fwd := adblockBuild(set, allow)
	if len(block) > adblockMax(c) {
		res.Error = fmt.Sprintf("kept the previous lists: %d domains, above max_domains %d", len(block), adblockMax(c))
		logf("dns: adblock: %s", res.Error)
		return res, errors.New(res.Error)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# mr dns adblock: domains=%d time=%d config=%s\n", len(block), res.Time, cfg)
	b.WriteString("# generated by `mr dns adblock update` from dns.adblock — do not edit\n")
	for _, a := range fwd {
		b.WriteString("server=/" + a + "/#\n")
	}
	for _, d := range block {
		b.WriteString("local=/" + d + "/\n")
	}
	os.MkdirAll(filepath.Dir(adblockConf), 0755)
	old, _ := os.ReadFile(adblockConf)
	body := func(s string) string { _, rest, _ := strings.Cut(s, "\n"); return rest }
	res.Changed = body(string(old)) != body(b.String())
	if err := writeAtomic(adblockConf, []byte(b.String()), 0644); err != nil {
		res.Error = err.Error()
		return res, err
	}
	if res.Changed && reload {
		if err := adblockReload(); err != nil {
			writeAtomic(adblockConf, old, 0644)
			adblockReload()
			res.Error = "dnsmasq did not come back with the new lists (" + err.Error() + "); the previous ones are back"
			logf("dns: adblock: %s", res.Error)
			return res, errors.New(res.Error)
		}
	}
	res.OK, res.Domains = true, len(block)
	logf("dns: adblock: %d domains from %d lists%s", len(block), len(c.DNS.Adblock.Lists), map[bool]string{false: " (unchanged)"}[res.Changed])
	return res, nil
}

// adblockState: what `mr dns adblock status` and the web UI show.
func adblockState(c *Config) map[string]any {
	h := adblockReadHeader()
	st := map[string]any{"enabled": c.DNS.Adblock.Enabled, "domains": h.Domains, "updated": h.Time,
		"current": h.Config != "" && h.Config == adblockConfigHash(c)}
	if b, err := os.ReadFile(adblockStatus); err == nil {
		var last adblockResult
		if json.Unmarshal(b, &last) == nil {
			st["last"] = last
		}
	}
	if lk := flock(adblockLock, false); lk == nil {
		st["running"] = true
	} else {
		lk.Close()
	}
	return st
}

// adblockCronLine: hourly (the update itself decides whether to download), at a minute fixed per router.
func adblockCronLine(c *Config) []string {
	if !c.DNS.Adblock.Enabled {
		return nil
	}
	h := fnv.New32a()
	h.Write([]byte(c.System.Hostname + "|adblock"))
	return []string{"# dns ad blocking (dns.adblock)", fmt.Sprintf("%d * * * * %s dns adblock update --cron", h.Sum32()%60, mrBin)}
}

func adblockCommand(c *Config, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: mr dns adblock status | update [--cron] [--no-reload]")
	}
	switch args[0] {
	case "status":
		b, _ := json.MarshalIndent(adblockState(c), "", "  ")
		fmt.Println(string(b))
		return nil
	case "update":
		cron, reload := false, true
		for _, a := range args[1:] {
			switch a {
			case "--cron":
				cron = true
			case "--no-reload":
				reload = false
			default:
				return fmt.Errorf("unknown option %q", a)
			}
		}
		res, err := adblockUpdate(c, cron, reload)
		if err == nil && res != nil && !cron {
			fmt.Printf("%d domains blocked%s\n", res.Domains, map[bool]string{false: " (unchanged)"}[res.Changed])
		}
		return err
	}
	return fmt.Errorf("unknown: mr dns adblock %s", args[0])
}

// apiDNSAdblock: GET = status; POST {"update": true} starts an update in the background.
func apiDNSAdblock(r apiReq) apiResp {
	c, err := loadConfig(ConfigPath, SecretsPath)
	if err != nil {
		return errResp(500, "%v", err)
	}
	if r.method != "POST" {
		return apiResp{body: adblockState(c)}
	}
	var in struct {
		Update bool `json:"update"`
	}
	json.Unmarshal(r.body, &in)
	if !in.Update {
		return errResp(400, "update: true expected")
	}
	if !c.DNS.Adblock.Enabled {
		return errResp(409, "ad blocking is off (dns.adblock.enabled)")
	}
	if err := pendingBlocks(); err != nil {
		return errResp(409, "%v", err)
	}
	self, args := selfCmd("dns", "adblock", "update")
	startDetached(self, args...)
	return apiResp{body: map[string]any{"ok": true, "started": true}}
}
