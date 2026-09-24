package main

// proxy module: post-apply verification and web UI API. The browser never talks to sing-box:
// these handlers call its clash API on 127.0.0.1 with the per-start secret from /run/mr-proxy.

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ---- verification ----

func proxyVerify(c *Config, restarted []string) []string {
	p := &c.Proxy
	if !p.Enabled {
		return nil
	}
	var errs []string
	if !proxyServicesEnabled() {
		// the nft rules are only loaded with both services enabled (see proxyServicesEnabled)
		errs = append(errs, "mr-proxy / mr-proxy-dns not enabled in the default runlevel: proxy rules not loaded")
	}
	deadline := verifyDeadline()
	fake := netip.MustParsePrefix(proxyFake4)
	for _, s := range restarted {
		switch s {
		case "mr-proxy":
			ok := waitFor(deadline, func() bool {
				ip, _, err := dnsQueryA(fmt.Sprintf("127.0.0.1:%d", p.dnsPort()), "verify.mr-proxy.invalid", 2*time.Second)
				return err == nil && fake.Contains(ip)
			})
			if !ok {
				errs = append(errs, "mr-proxy: sing-box fake-ip DNS not answering")
			}
		case "mr-proxy-dns":
			ok := waitFor(deadline, func() bool {
				_, _, err := dnsQueryA(fmt.Sprintf("127.0.0.1:%d", p.lanDNSPort()), "localhost", 2*time.Second)
				return err == nil
			})
			if !ok {
				errs = append(errs, "mr-proxy-dns: not answering")
			}
		}
	}
	return errs
}

// dnsQueryA sends one A query over UDP; it returns the first A record (invalid Addr if none) and the rcode.
func dnsQueryA(server, name string, timeout time.Duration) (netip.Addr, int, error) {
	conn, err := net.DialTimeout("udp", server, timeout)
	if err != nil {
		return netip.Addr{}, 0, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	id := uint16(time.Now().UnixNano())
	q := []byte{byte(id >> 8), byte(id), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, l := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if l == "" || len(l) > 63 {
			return netip.Addr{}, 0, fmt.Errorf("bad name %q", name)
		}
		q = append(append(q, byte(len(l))), l...)
	}
	q = append(q, 0, 0, 1, 0, 1) // root, QTYPE A, QCLASS IN
	if _, err := conn.Write(q); err != nil {
		return netip.Addr{}, 0, err
	}
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return netip.Addr{}, 0, err
	}
	return dnsParseA(buf[:n], id)
}

func dnsParseA(m []byte, id uint16) (netip.Addr, int, error) {
	if len(m) < 12 || binary.BigEndian.Uint16(m) != id || m[2]&0x80 == 0 {
		return netip.Addr{}, 0, fmt.Errorf("bad DNS response")
	}
	rcode := int(m[3] & 0x0f)
	qd, an := int(binary.BigEndian.Uint16(m[4:])), int(binary.BigEndian.Uint16(m[6:]))
	off := 12
	skipName := func() bool {
		for off < len(m) {
			l := int(m[off])
			switch {
			case l == 0:
				off++
				return true
			case l&0xc0 == 0xc0:
				off += 2
				return off <= len(m)
			}
			off += 1 + l
		}
		return false
	}
	for i := 0; i < qd; i++ {
		if !skipName() {
			return netip.Addr{}, rcode, fmt.Errorf("truncated DNS response")
		}
		off += 4
	}
	for i := 0; i < an; i++ {
		if !skipName() || off+10 > len(m) {
			break
		}
		typ, rdlen := binary.BigEndian.Uint16(m[off:]), int(binary.BigEndian.Uint16(m[off+8:]))
		off += 10
		if off+rdlen > len(m) {
			break
		}
		if typ == 1 && rdlen == 4 {
			return netip.AddrFrom4([4]byte(m[off : off+4])), rcode, nil
		}
		off += rdlen
	}
	return netip.Addr{}, rcode, nil
}

// ---- sing-box clash API client (loopback only) ----

var reProxyAPISecret = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

func proxyAPISecret() string {
	var v struct {
		Experimental struct {
			ClashAPI struct {
				Secret string `json:"secret"`
			} `json:"clash_api"`
		} `json:"experimental"`
	}
	if b, err := os.ReadFile(proxyRunDir + "/api.json"); err == nil {
		json.Unmarshal(b, &v)
	}
	return v.Experimental.ClashAPI.Secret
}

// clashCall does one HTTP/1.0 request to sing-box's clash API on loopback. A few lines instead of
// net/http, which would add ~3 MB to the mr binary. HTTP/1.0: no chunked encoding, the server
// closes the connection after the body.
func clashCall(p *Proxy, method, path string, body, out any, timeout time.Duration) error {
	for _, r := range path {
		if r <= ' ' || r >= 0x7f {
			return fmt.Errorf("bad API path %q", path)
		}
	}
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", p.apiPort()), timeout)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	var b []byte
	if body != nil {
		b, _ = json.Marshal(body)
	}
	var req bytes.Buffer
	fmt.Fprintf(&req, "%s %s HTTP/1.0\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: %d\r\n", method, path, len(b))
	if s := proxyAPISecret(); s != "" && reProxyAPISecret.MatchString(s) {
		fmt.Fprintf(&req, "Authorization: Bearer %s\r\n", s)
	}
	req.WriteString("\r\n")
	req.Write(b)
	if _, err := conn.Write(req.Bytes()); err != nil {
		return err
	}
	resp, err := io.ReadAll(io.LimitReader(conn, 16<<20))
	if err != nil {
		return err
	}
	code, data, err := clashParse(resp)
	if err != nil {
		return err
	}
	if code >= 300 {
		var e struct {
			Message string `json:"message"`
		}
		json.Unmarshal(data, &e)
		if e.Message == "" {
			e.Message = fmt.Sprintf("HTTP %d", code)
		}
		return fmt.Errorf("%s", e.Message)
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}

// clashParse splits an HTTP/1.x response into status code and body.
func clashParse(resp []byte) (int, []byte, error) {
	head, data, ok := bytes.Cut(resp, []byte("\r\n\r\n"))
	status, _, _ := bytes.Cut(head, []byte("\r\n"))
	f := strings.Fields(string(status))
	if !ok || len(f) < 2 || !strings.HasPrefix(f[0], "HTTP/1.") {
		return 0, nil, fmt.Errorf("bad HTTP response from sing-box")
	}
	code, err := strconv.Atoi(f[1])
	if err != nil {
		return 0, nil, fmt.Errorf("bad HTTP status %q", f[1])
	}
	return code, data, nil
}

type clashProxy struct {
	Type    string   `json:"type"`
	Now     string   `json:"now,omitempty"`
	All     []string `json:"all,omitempty"`
	UDP     bool     `json:"udp"`
	History []struct {
		Delay int `json:"delay"`
	} `json:"history"`
}

type clashConn struct {
	ID       string `json:"id"`
	Metadata struct {
		Network         string `json:"network"`
		Type            string `json:"type"`
		SourceIP        string `json:"sourceIP"`
		SourcePort      string `json:"sourcePort"`
		DestinationIP   string `json:"destinationIP"`
		DestinationPort string `json:"destinationPort"`
		Host            string `json:"host"`
	} `json:"metadata"`
	Upload   int64     `json:"upload"`
	Download int64     `json:"download"`
	Start    time.Time `json:"start"`
	Chains   []string  `json:"chains"`
	Rule     string    `json:"rule"`
}

// proxyLive loads the live config for API handlers.
func proxyLive() (*Config, *apiResp) {
	c, err := loadConfig(ConfigPath, SecretsPath)
	if err != nil {
		r := errResp(500, "%v", err)
		return nil, &r
	}
	return c, nil
}

// apiProxyStatus: running state, outbound groups and nodes (current choice, last delay), traffic
// totals and the proxied connections. Also which proxy secrets are set (names only, never values).
func apiProxyStatus(r apiReq) apiResp {
	c, bad := proxyLive()
	if bad != nil {
		return *bad
	}
	return apiResp{body: proxyStatus(c)}
}

func proxyStatus(c *Config) map[string]any {
	p := &c.Proxy
	secrets := map[string]bool{}
	var refs []string
	for _, n := range p.Nodes {
		refs = append(refs, n.secretRefs()...)
	}
	for _, sub := range p.Subscriptions {
		refs = append(refs, sub.URL)
	}
	for _, k := range refs {
		if k != "" {
			_, err := c.Secret(k)
			secrets[k] = err == nil
		}
	}
	out := map[string]any{"enabled": p.Enabled, "running": false, "secrets_set": secrets}
	if !p.Enabled {
		return out
	}
	var ver struct {
		Version string `json:"version"`
	}
	if err := clashCall(p, "GET", "/version", nil, &ver, 2*time.Second); err != nil {
		out["error"] = "sing-box not reachable: " + err.Error()
		return out
	}
	out["running"], out["version"] = true, ver.Version

	var px struct {
		Proxies map[string]clashProxy `json:"proxies"`
	}
	proxies := map[string]any{}
	if err := clashCall(p, "GET", "/proxies", nil, &px, 3*time.Second); err == nil {
		add := func(name string) {
			x, ok := px.Proxies[name]
			if !ok {
				return
			}
			d := 0
			if len(x.History) > 0 {
				d = x.History[len(x.History)-1].Delay
			}
			proxies[name] = map[string]any{"type": x.Type, "now": x.Now, "all": x.All, "udp": x.UDP, "delay": d}
		}
		for _, n := range p.Nodes {
			add(n.Name)
		}
		for _, g := range p.Groups {
			add(g.Name)
		}
	}
	out["proxies"] = proxies

	var cs struct {
		DownloadTotal int64       `json:"downloadTotal"`
		UploadTotal   int64       `json:"uploadTotal"`
		Memory        int64       `json:"memory"`
		Connections   []clashConn `json:"connections"`
	}
	if err := clashCall(p, "GET", "/connections", nil, &cs, 3*time.Second); err == nil {
		sort.Slice(cs.Connections, func(i, j int) bool { return cs.Connections[i].Start.After(cs.Connections[j].Start) })
		out["connections_total"] = len(cs.Connections)
		if len(cs.Connections) > 300 {
			cs.Connections = cs.Connections[:300]
		}
		now := time.Now()
		var conns []map[string]any
		for _, x := range cs.Connections {
			m := x.Metadata
			dst := m.Host
			if dst == "" {
				dst = m.DestinationIP
			}
			conns = append(conns, map[string]any{
				"network": m.Network, "src": net.JoinHostPort(m.SourceIP, m.SourcePort), "dst": net.JoinHostPort(dst, m.DestinationPort),
				"chains": x.Chains, "rule": x.Rule, "up": x.Upload, "down": x.Download, "age": int64(now.Sub(x.Start).Seconds()),
			})
		}
		out["connections"] = conns
		out["upload_total"], out["download_total"], out["memory"] = cs.UploadTotal, cs.DownloadTotal, cs.Memory
	}
	return out
}

// proxyCheck probes both DNS services once (used by `mr proxy check`).
func proxyCheck(c *Config) []string {
	p := &c.Proxy
	var errs []string
	ip, _, err := dnsQueryA(fmt.Sprintf("127.0.0.1:%d", p.dnsPort()), "verify.mr-proxy.invalid", 2*time.Second)
	if err != nil || !netip.MustParsePrefix(proxyFake4).Contains(ip) {
		errs = append(errs, fmt.Sprintf("sing-box fake-ip DNS (127.0.0.1:%d): got %v, %v", p.dnsPort(), ip, err))
	}
	if _, _, err := dnsQueryA(fmt.Sprintf("127.0.0.1:%d", p.lanDNSPort()), "localhost", 2*time.Second); err != nil {
		errs = append(errs, fmt.Sprintf("mr-proxy-dns (127.0.0.1:%d): %v", p.lanDNSPort(), err))
	}
	for _, rs := range c.Proxy.Rules {
		if len(rs.Domains) == 0 {
			continue
		}
		// a proxied domain asked through mr-proxy-dns must come back as a fake IP
		d, _ := proxyNormDomain(rs.Domains[0])
		ip, _, err := dnsQueryA(fmt.Sprintf("127.0.0.1:%d", p.lanDNSPort()), d, 3*time.Second)
		if err != nil || !netip.MustParsePrefix(proxyFake4).Contains(ip) {
			errs = append(errs, fmt.Sprintf("%s via mr-proxy-dns: got %v, %v (want a fake IP)", d, ip, err))
		}
		break
	}
	return errs
}

// proxyCmd: `mr proxy status|check|delay [NAME]|select GROUP NODE|parse|fetch` for the shell / agent.
func proxyCmd(c *Config, args []string) error {
	usage := fmt.Errorf("usage: mr proxy status | check | delay [NODE|GROUP] | select GROUP NODE | parse [--secrets] [FILE] | fetch [--secrets] URL|SUBSCRIPTION")
	if len(args) == 0 {
		return usage
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	switch args[0] {
	case "parse", "fetch":
		return proxyImportCmd(c, args[0] == "fetch", args[1:])
	case "status":
		return enc.Encode(proxyStatus(c))
	case "check":
		if !c.Proxy.Enabled {
			return fmt.Errorf("proxy is disabled")
		}
		if errs := proxyCheck(c); len(errs) > 0 {
			return fmt.Errorf("proxy check failed:\n  %s", strings.Join(errs, "\n  "))
		}
		fmt.Println("ok")
		return nil
	case "delay":
		name := ""
		if len(args) > 1 {
			name = args[1]
		}
		res, errs, err := proxyDelay(c, name)
		if err != nil {
			return err
		}
		return enc.Encode(map[string]any{"results": res, "errors": errs})
	case "select":
		if len(args) != 3 {
			return usage
		}
		if _, err := proxySelect(c, args[1], args[2]); err != nil {
			return err
		}
		fmt.Println("ok")
		return nil
	}
	return usage
}

// proxyDelay tests one node/group (name) or every node (name empty) through sing-box, in parallel.
func proxyDelay(c *Config, name string) (map[string]int, map[string]string, error) {
	p := &c.Proxy
	if !p.Enabled {
		return nil, nil, fmt.Errorf("proxy is disabled")
	}
	var names []string
	for _, n := range p.Nodes {
		if name == "" || name == n.Name {
			names = append(names, n.Name)
		}
	}
	for _, g := range p.Groups {
		if name == g.Name {
			names = append(names, g.Name)
		}
	}
	if len(names) == 0 {
		return nil, nil, fmt.Errorf("no node or group %q", name)
	}
	results, errs := map[string]int{}, map[string]string{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, name := range names {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			var d struct {
				Delay int `json:"delay"`
			}
			err := clashCall(p, "GET", "/proxies/"+name+"/delay?timeout=5000", nil, &d, 8*time.Second)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				results[name], errs[name] = -1, err.Error()
			} else {
				results[name] = d.Delay
			}
		}(name)
	}
	wg.Wait()
	return results, errs, nil
}

// proxySelect switches a selector group to one of its nodes (runtime state; sing-box keeps the
// choice in its cache file across restarts). The int is an HTTP status for the API.
func proxySelect(c *Config, group, node string) (int, error) {
	p := &c.Proxy
	if !p.Enabled {
		return 409, fmt.Errorf("proxy is disabled")
	}
	for _, g := range p.Groups {
		if g.Name != group || g.Type != "selector" {
			continue
		}
		for _, n := range g.Nodes {
			if n == node {
				if err := clashCall(p, "PUT", "/proxies/"+g.Name, map[string]string{"name": n}, nil, 3*time.Second); err != nil {
					return 502, fmt.Errorf("sing-box: %v", err)
				}
				return 200, nil
			}
		}
		return 400, fmt.Errorf("%q is not a member of %q", node, group)
	}
	return 404, fmt.Errorf("no selector group %q", group)
}

func apiProxyDelay(r apiReq) apiResp {
	if r.method != "POST" {
		return errResp(405, "POST required")
	}
	var in struct {
		Name string `json:"name"`
	}
	json.Unmarshal(r.body, &in)
	c, bad := proxyLive()
	if bad != nil {
		return *bad
	}
	res, errs, err := proxyDelay(c, in.Name)
	if err != nil {
		return errResp(400, "%v", err)
	}
	return apiResp{body: map[string]any{"results": res, "errors": errs}}
}

func apiProxySelect(r apiReq) apiResp {
	if r.method != "POST" {
		return errResp(405, "POST required")
	}
	var in struct {
		Group string `json:"group"`
		Node  string `json:"node"`
	}
	json.Unmarshal(r.body, &in)
	c, bad := proxyLive()
	if bad != nil {
		return *bad
	}
	if code, err := proxySelect(c, in.Group, in.Node); err != nil {
		return errResp(code, "%v", err)
	}
	appendChangeLog(fmt.Sprintf("webui: proxy group %s -> %s", in.Group, in.Node))
	return apiResp{body: map[string]any{"ok": true}}
}

// List files the web UI may create/edit: /etc/mini-router/proxy/<name>.domains|.cidrs only
// (rules may reference any absolute path, but the UI can never read or write outside this directory).
var reProxyListFile = regexp.MustCompile(`^[A-Za-z0-9_-]{1,40}\.(domains|cidrs)$`)

type proxyListInfo struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	Entries int    `json:"entries"`
	Size    int64  `json:"size"`
}

// proxyCheckList validates list content; returns up to 10 problems (line numbers, never echoing much).
func proxyCheckList(c *Config, kind, content string) (string, []string) {
	var lines, errs []string
	for i, l := range strings.Split(strings.ReplaceAll(content, "\r", ""), "\n") {
		t := strings.TrimSpace(l)
		lines = append(lines, t)
		e := t
		if k := strings.IndexByte(e, '#'); k >= 0 {
			e = strings.TrimSpace(e[:k])
		}
		if e == "" {
			continue
		}
		bad := ""
		if kind == "domains" {
			if _, ok := proxyNormDomain(e); !ok {
				bad = "not a domain"
			}
		} else if p, ok := proxyNormCIDR(e); !ok {
			bad = "not a CIDR or IP address"
		} else {
			bad = proxyCIDRProblem(c, p)
		}
		if bad != "" && len(errs) < 10 {
			if len(e) > 60 {
				e = e[:60] + "…"
			}
			errs = append(errs, fmt.Sprintf("line %d %q: %s", i+1, e, bad))
		}
	}
	return strings.TrimRight(strings.Join(lines, "\n"), "\n") + "\n", errs
}

func apiProxyLists(r apiReq) apiResp {
	var in struct {
		File    string `json:"file"`
		Content string `json:"content"`
		Save    bool   `json:"save"`
	}
	json.Unmarshal(r.body, &in)
	if in.File == "" {
		files := []proxyListInfo{}
		ents, _ := os.ReadDir(proxyListDir)
		for _, e := range ents {
			if !e.Type().IsRegular() || !reProxyListFile.MatchString(e.Name()) {
				continue
			}
			path := filepath.Join(proxyListDir, e.Name())
			info := proxyListInfo{Name: e.Name(), Path: path}
			if fi, err := e.Info(); err == nil {
				info.Size = fi.Size()
			}
			if lines, _, err := proxyReadList(path); err == nil {
				info.Entries = len(lines)
			}
			files = append(files, info)
		}
		return apiResp{body: map[string]any{"dir": proxyListDir, "files": files}}
	}
	if !reProxyListFile.MatchString(in.File) {
		return errResp(400, "list file name: letters, digits, _ - with .domains or .cidrs")
	}
	path := filepath.Join(proxyListDir, in.File)
	fi, err := os.Lstat(path)
	exists := err == nil
	if exists && !fi.Mode().IsRegular() {
		return errResp(400, "%s is not a regular file", path)
	}
	if !in.Save {
		content := ""
		if exists {
			content = readFile(path)
		}
		return apiResp{body: map[string]any{"file": in.File, "path": path, "exists": exists, "content": content}}
	}
	if r.method != "POST" {
		return errResp(405, "POST required")
	}
	c, bad := proxyLive()
	if bad != nil {
		return *bad
	}
	kind := strings.TrimPrefix(filepath.Ext(in.File), ".")
	data, errs := proxyCheckList(c, kind, in.Content)
	if len(errs) > 0 {
		return apiResp{status: 400, body: map[string]any{"error": "invalid entries", "errors": errs}}
	}
	if err := os.MkdirAll(proxyListDir, 0755); err != nil {
		return errResp(500, "%v", err)
	}
	if err := writeAtomic(path, []byte(data), 0644); err != nil {
		return errResp(500, "%v", err)
	}
	appendChangeLog("webui: proxy list " + in.File + " saved")
	return apiResp{body: map[string]any{"ok": true, "path": path}}
}
