package main

// proxy module: node import for the web UI and the shell. proxy.parse turns pasted share links into
// nodes; proxy.fetch downloads a subscription (base64 / plain list of share links) with busybox
// wget first. Both only return a preview: the UI puts the chosen nodes into the config and the
// credentials into the secrets it saves with it. The responses carry the credentials found in the
// links the user supplied (never stored secrets). Nothing here logs a link or a subscription URL.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	proxySubMax     = 2 << 20 // largest subscription / pasted text accepted
	proxySubTimeout = 45 * time.Second
	// subscription services pick the format by User-Agent; a v2rayN agent gets base64 share links
	proxySubUA = "v2rayN/7.0"
)

// proxyWget is the downloader (busybox wget; https through ssl_client). A variable for tests.
var proxyWget = "wget"

// proxySubURLOK: an http(s) URL without whitespace, quotes or control characters.
func proxySubURLOK(s string) bool {
	if len(s) > 2048 || !(strings.HasPrefix(s, "https://") || strings.HasPrefix(s, "http://")) {
		return false
	}
	for _, r := range s {
		if r <= ' ' || r >= 0x7f || strings.ContainsRune("\"'`\\<>", r) {
			return false
		}
	}
	u, err := url.Parse(s)
	return err == nil && u.Host != "" && !strings.HasPrefix(u.Host, "-")
}

// proxyCapBuf keeps at most max bytes (wget's stderr).
type proxyCapBuf struct {
	bytes.Buffer
	max int
}

func (b *proxyCapBuf) Write(p []byte) (int, error) {
	if room := b.max - b.Len(); room > 0 {
		b.Buffer.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

var reProxyHTTPStatus = regexp.MustCompile(`^HTTP/[0-9.]+ ([0-9]{3})`)

// proxyWgetInfo reads wget -S output: the last HTTP status and the subscription-userinfo header
// (upload / download / total bytes, expire unix time) many subscription services send.
func proxyWgetInfo(stderr string) (int, map[string]int64) {
	status := 0
	var info map[string]int64
	for _, l := range strings.Split(stderr, "\n") {
		l = strings.TrimSpace(l)
		if m := reProxyHTTPStatus.FindStringSubmatch(l); m != nil {
			status, _ = strconv.Atoi(m[1])
		}
		k, v, ok := strings.Cut(l, ":")
		if !ok || !strings.EqualFold(strings.TrimSpace(k), "subscription-userinfo") {
			continue
		}
		info = map[string]int64{}
		for _, kv := range strings.Split(v, ";") {
			k, v, _ := strings.Cut(strings.TrimSpace(kv), "=")
			switch k = strings.ToLower(strings.TrimSpace(k)); k {
			case "upload", "download", "total", "expire":
				if n, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil && n >= 0 {
					info[k] = int64(n)
				}
			}
		}
	}
	return status, info
}

// proxyFetchURL downloads a subscription (at most proxySubMax bytes, proxySubTimeout). Errors never
// contain the URL (it usually carries an access token).
func proxyFetchURL(link string) ([]byte, map[string]int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), proxySubTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, proxyWget, "-q", "-S", "-T", "20", "-U", proxySubUA, "-O", "-", "--", link)
	// own process group: wget's helpers (ssl_client) go down with it on timeout / oversize
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	kill := func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.Cancel = kill
	cmd.WaitDelay = 2 * time.Second
	errb := &proxyCapBuf{max: 64 << 10}
	cmd.Stderr = errb
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, nil, fmt.Errorf("cannot run wget: %v", err)
	}
	body, _ := io.ReadAll(io.LimitReader(out, proxySubMax+1))
	if len(body) > proxySubMax {
		kill()
		cmd.Wait()
		return nil, nil, fmt.Errorf("subscription larger than %d KiB", proxySubMax>>10)
	}
	werr := cmd.Wait()
	status, info := proxyWgetInfo(errb.String())
	switch {
	case ctx.Err() != nil:
		return nil, nil, fmt.Errorf("download timed out after %s", proxySubTimeout)
	case status >= 400:
		return nil, nil, fmt.Errorf("download failed: HTTP %d", status)
	case werr != nil:
		return nil, nil, fmt.Errorf("download failed: %s", proxyWgetError(errb.String(), link, werr))
	}
	return body, info, nil
}

// proxyWgetError picks wget's own error line, with the URL (and anything like it) removed.
func proxyWgetError(stderr, link string, err error) string {
	msg := ""
	for _, l := range strings.Split(stderr, "\n") {
		if l != "" && l[0] != ' ' && l[0] != '\t' { // -S headers are indented
			msg = strings.TrimSpace(l)
		}
	}
	if msg == "" {
		return err.Error()
	}
	msg = strings.ReplaceAll(msg, link, "<URL>")
	if u, e := url.Parse(link); e == nil && u.RawQuery != "" {
		msg = strings.ReplaceAll(msg, u.RawQuery, "…")
	}
	if u, e := url.Parse(link); e == nil && u.Path != "" && u.Path != "/" {
		msg = strings.ReplaceAll(msg, u.Path, "/…") // tokens are often in the path too
	}
	if len(msg) > 200 {
		msg = msg[:200] + "…"
	}
	return msg
}

// proxyNodeMap converts a node to its router.yaml / web UI form (same keys as router.yaml).
func proxyNodeMap(n *ProxyNode) map[string]any {
	var m map[string]any
	if b, err := yaml.Marshal(n); err == nil {
		yaml.Unmarshal(b, &m)
	}
	return m
}

// proxyParseResult is the JSON answer of proxy.parse / proxy.fetch.
func proxyParseResult(items []proxyParsed, errs []proxyLinkErr) map[string]any {
	nodes := []map[string]any{}
	for i := range items {
		it := &items[i]
		nodes = append(nodes, map[string]any{"line": it.Line, "remark": it.Remark, "node": proxyNodeMap(&it.Node),
			"secrets": it.Secrets, "warnings": it.Warnings, "summary": proxyNodeSummary(&it.Node)})
	}
	return map[string]any{"nodes": nodes, "errors": errs}
}

func proxyTakenSet(list []string) map[string]bool {
	m := map[string]bool{}
	for _, s := range list {
		m[s] = true
	}
	return m
}

// apiProxyParse: POST {links: "one per line (or base64)", taken: [names in use]} → preview.
func apiProxyParse(r apiReq) apiResp {
	if r.method != "POST" {
		return errResp(405, "POST required")
	}
	var in struct {
		Links string   `json:"links"`
		Taken []string `json:"taken"`
	}
	if err := json.Unmarshal(r.body, &in); err != nil {
		return errResp(400, "bad request")
	}
	if len(in.Links) > proxySubMax {
		return errResp(413, "too much text (max %d KiB)", proxySubMax>>10)
	}
	items, errs := proxyParseLinks(in.Links, proxyTakenSet(in.Taken), nil)
	return apiResp{body: proxyParseResult(items, errs)}
}

// proxySubLink resolves a fetch request: a URL, or the name of a saved subscription (URL in secrets.yaml).
func proxySubLink(c *Config, link, sub string) (string, error) {
	if sub != "" {
		for _, s := range c.Proxy.Subscriptions {
			if s.Name == sub {
				v, err := c.Secret(s.URL)
				if err != nil {
					return "", err
				}
				link = v
				break
			}
		}
		if link == "" {
			return "", fmt.Errorf("no subscription %q", sub)
		}
	}
	if !proxySubURLOK(link) {
		return "", fmt.Errorf("subscription URL: http:// or https:// without spaces or quotes")
	}
	return link, nil
}

// apiProxyFetch: POST {url} or {subscription: name}, plus taken → downloads through the router and
// answers like proxy.parse, with "info" (traffic / expiry) when the service sends it.
func apiProxyFetch(r apiReq) apiResp {
	if r.method != "POST" {
		return errResp(405, "POST required")
	}
	var in struct {
		URL          string   `json:"url"`
		Subscription string   `json:"subscription"`
		Taken        []string `json:"taken"`
	}
	if err := json.Unmarshal(r.body, &in); err != nil {
		return errResp(400, "bad request")
	}
	c := &Config{}
	if in.Subscription != "" { // the URL is in secrets.yaml
		var bad *apiResp
		if c, bad = proxyLive(); bad != nil {
			return *bad
		}
	}
	link, err := proxySubLink(c, strings.TrimSpace(in.URL), in.Subscription)
	if err != nil {
		return errResp(400, "%v", err)
	}
	body, info, err := proxyFetchURL(link)
	if err != nil {
		return errResp(502, "%v", err)
	}
	items, errs := proxyParseLinks(string(body), proxyTakenSet(in.Taken), nil)
	res := proxyParseResult(items, errs)
	if info != nil {
		res["info"] = info
	}
	return apiResp{body: res}
}

// proxyImportCmd: `mr proxy parse [--secrets] [FILE]` / `mr proxy fetch [--secrets] URL|SUBSCRIPTION`
// prints router.yaml node entries; secret values only with --secrets (names otherwise).
func proxyImportCmd(c *Config, fetch bool, args []string) error {
	show := false
	var rest []string
	for _, a := range args {
		if a == "--secrets" {
			show = true
		} else {
			rest = append(rest, a)
		}
	}
	var text []byte
	var info map[string]int64
	var err error
	switch {
	case fetch:
		if len(rest) != 1 {
			return fmt.Errorf("usage: mr proxy fetch [--secrets] URL|SUBSCRIPTION")
		}
		link, sub := rest[0], ""
		if !strings.Contains(link, "://") {
			link, sub = "", rest[0]
		}
		if link, err = proxySubLink(c, link, sub); err != nil {
			return err
		}
		if text, info, err = proxyFetchURL(link); err != nil {
			return err
		}
	case len(rest) == 0 || rest[0] == "-":
		text, err = io.ReadAll(io.LimitReader(os.Stdin, proxySubMax+1))
	default:
		text, err = os.ReadFile(rest[0])
	}
	if err != nil {
		return err
	}
	if len(text) > proxySubMax {
		return fmt.Errorf("too much input (max %d KiB)", proxySubMax>>10)
	}
	names, secrets := map[string]bool{}, map[string]bool{}
	for _, n := range c.Proxy.Nodes {
		names[n.Name] = true
	}
	for _, g := range c.Proxy.Groups {
		names[g.Name] = true
	}
	for k := range c.secrets {
		secrets[k] = true
	}
	items, errs := proxyParseLinks(string(text), names, secrets)
	for _, e := range errs {
		fmt.Fprintf(os.Stderr, "line %d: %s\n", e.Line, e.Error)
	}
	if len(items) == 0 {
		return fmt.Errorf("no usable links")
	}
	if info != nil {
		fmt.Printf("# subscription: upload %d, download %d, total %d bytes", info["upload"], info["download"], info["total"])
		if e := info["expire"]; e > 0 {
			fmt.Printf(", expires %s", time.Unix(e, 0).UTC().Format("2006-01-02"))
		}
		fmt.Println()
	}
	fmt.Println("# proxy.nodes entries for router.yaml")
	var keys []string
	vals := map[string]string{}
	for i := range items {
		it := &items[i]
		var yn yaml.Node
		if err := yn.Encode(&it.Node); err != nil { // struct: router.yaml key order
			return err
		}
		yn.Style = yaml.FlowStyle
		b, _ := yaml.Marshal(&yn)
		fmt.Printf("    - %s", b)
		for _, w := range it.Warnings {
			fmt.Printf("      # line %d: %s\n", it.Line, w)
		}
		for k, v := range it.Secrets {
			keys = append(keys, k)
			vals[k] = v
		}
	}
	sort.Strings(keys)
	fmt.Println("# secrets.yaml")
	for _, k := range keys {
		if show {
			b, _ := yaml.Marshal(map[string]string{k: vals[k]})
			fmt.Print(string(b))
		} else {
			fmt.Printf("%s: ...   # value hidden; run with --secrets to print it\n", k)
		}
	}
	return nil
}
