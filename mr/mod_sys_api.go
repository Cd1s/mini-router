package main

// sys module: web UI actions that are not tied to one config area — diagnostics, service control,
// the services overview (with Tailscale peers), filtered system log — and the `mr sys` subcommands.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var hostRe = lazyRegexp(`^[A-Za-z0-9.:-]{1,253}$`)

// apiDiag runs ping / ping6 / traceroute / traceroute6 / nslookup with a hard timeout. Arguments are
// fixed; only the target is user-supplied and must look like a host name or address. The old
// {tool: ping|traceroute, ipv6: true} form still works.
func apiDiag(r apiReq) apiResp {
	if r.method != "POST" {
		return errResp(405, "POST required")
	}
	var in struct {
		Tool string `json:"tool"`
		Host string `json:"host"`
		IPv6 bool   `json:"ipv6"`
	}
	json.Unmarshal(r.body, &in)
	if !hostRe.MatchString(in.Host) || strings.HasPrefix(in.Host, "-") {
		return errResp(400, "bad host")
	}
	tool := in.Tool
	if in.IPv6 && (tool == "ping" || tool == "traceroute") {
		tool += "6"
	}
	var args []string
	switch tool {
	case "ping":
		args = []string{"ping", "-4", "-c", "4", "-W", "2", in.Host}
	case "ping6":
		args = []string{"ping", "-6", "-c", "4", "-W", "2", in.Host}
	case "traceroute":
		args = []string{"traceroute", "-4", "-n", "-w", "2", "-q", "1", "-m", "20", in.Host}
	case "traceroute6":
		args = []string{"traceroute6", "-n", "-w", "2", "-q", "1", "-m", "20", in.Host}
	case "nslookup":
		args = []string{"nslookup", in.Host, "127.0.0.1"}
	default:
		return errResp(400, "unknown tool")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, args[0], args[1:]...).CombinedOutput()
	return apiResp{body: map[string]any{"output": string(out), "command": strings.Join(args, " ")}}
}

// apiService starts / stops / restarts one service the config enables (used by several modules'
// pages: POST {name, op}).
func apiService(r apiReq) apiResp {
	if r.method != "POST" {
		return errResp(405, "POST required")
	}
	var in struct {
		Name string `json:"name"`
		Op   string `json:"op"`
	}
	json.Unmarshal(r.body, &in)
	c, err := loadConfig(ConfigPath, SecretsPath)
	if err != nil {
		return errResp(500, "%v", err)
	}
	known := false
	for _, s := range enabledServices(c) {
		known = known || s == in.Name
	}
	if !known || (in.Op != "restart" && in.Op != "start" && in.Op != "stop") {
		return errResp(400, "bad service or op")
	}
	if in.Name == "mr-network" {
		return errResp(400, "mr-network is re-run by apply, not restarted")
	}
	if _, err := os.Stat("/etc/init.d/" + in.Name); err != nil {
		return errResp(404, "no such service")
	}
	appendChangeLog("webui: " + in.Op + " " + in.Name)
	startDetached("rc-service", in.Name, in.Op)
	return apiResp{body: map[string]any{"ok": true}}
}

// ---- services overview ----

type svcRow struct {
	Name      string `json:"name"`
	Label     string `json:"label"`
	Cfg       string `json:"cfg,omitempty"` // config switch: services.<cfg> (or system.zram / schedules)
	Wanted    bool   `json:"wanted"`        // the config enables it
	Installed bool   `json:"installed"`     // /etc/init.d/<name> exists
	Running   bool   `json:"running"`
}

// sysServiceRows: the services the sys module switches, in page order.
func sysServiceRows(c *Config) []svcRow {
	sv := c.Services
	return []svcRow{
		{Name: "tailscale", Label: "Tailscale", Cfg: "tailscale", Wanted: sv.Tailscale.Enabled},
		{Name: "lucky", Label: "Lucky", Cfg: "lucky", Wanted: sv.Lucky.Enabled},
		{Name: "lucky-dns-inotify", Label: "Lucky 域名 → dnsmasq", Cfg: "lucky", Wanted: sv.Lucky.Enabled},
		{Name: "dstatus-agent", Label: "dstatus 探针", Cfg: "dstatus", Wanted: sv.Dstatus.Enabled},
		{Name: "stubby", Label: "stubby (DoT)", Cfg: "stubby", Wanted: sv.Stubby.Enabled},
		{Name: "dropbear", Label: "SSH (dropbear)", Cfg: "ssh", Wanted: sv.SSH.Enabled},
		{Name: "mr-panel", Label: "Web 管理 (httpd)", Cfg: "panel", Wanted: sv.Panel.Enabled},
		{Name: "ntpd", Label: "NTP (ntpd)", Wanted: true},
		{Name: "mr-edge", Label: "HTTPS 反向代理 (mr edge)", Cfg: "edge", Wanted: edgeOn(c)},
		{Name: "crond", Label: "计划任务 (crond)", Cfg: "schedules", Wanted: cronWanted(c)},
		{Name: "mr-zram", Label: "zram 压缩内存", Cfg: "zram", Wanted: c.System.Zram},
	}
}

// serviceRunning asks OpenRC (in parallel for all names).
func servicesRunning(names []string) map[string]bool {
	out := make(map[string]bool, len(names))
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, n := range names {
		if _, err := os.Stat("/etc/init.d/" + n); err != nil {
			continue
		}
		wg.Add(1)
		go func(n string) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			err := exec.CommandContext(ctx, "rc-service", n, "status").Run()
			mu.Lock()
			out[n] = err == nil
			mu.Unlock()
		}(n)
	}
	wg.Wait()
	return out
}

type tsNode struct {
	HostName       string   `json:"host"`
	DNSName        string   `json:"dns"`
	OS             string   `json:"os"`
	TailscaleIPs   []string `json:"ips"`
	Online         bool     `json:"online"`
	Active         bool     `json:"active"`
	ExitNode       bool     `json:"exit_node"`
	ExitNodeOption bool     `json:"exit_node_option"`
	Relay          string   `json:"relay"`
	CurAddr        string   `json:"direct"` // "ip:port" when a direct path is up, "" = via DERP relay
	RxBytes        int64    `json:"rx"`
	TxBytes        int64    `json:"tx"`
	LastSeen       string   `json:"last_seen"`
	PrimaryRoutes  []string `json:"routes"`
}

// tsIn is a node as `tailscale status --json` writes it (field names = JSON keys).
type tsIn struct {
	HostName, DNSName, OS, Relay, CurAddr, LastSeen string
	TailscaleIPs, PrimaryRoutes                     []string
	Online, Active, ExitNode, ExitNodeOption        bool
	RxBytes, TxBytes                                int64
}

func (n *tsIn) node() *tsNode {
	if n == nil {
		return nil
	}
	return &tsNode{HostName: n.HostName, DNSName: n.DNSName, OS: n.OS, TailscaleIPs: n.TailscaleIPs,
		Online: n.Online, Active: n.Active, ExitNode: n.ExitNode, ExitNodeOption: n.ExitNodeOption,
		Relay: n.Relay, CurAddr: n.CurAddr, RxBytes: n.RxBytes, TxBytes: n.TxBytes, LastSeen: n.LastSeen,
		PrimaryRoutes: n.PrimaryRoutes}
}

// tailscaleStatus parses `tailscale status --json` into what the services page shows.
func tailscaleStatus(raw []byte) (map[string]any, error) {
	var t struct {
		BackendState   string
		AuthURL        string
		MagicDNSSuffix string
		Self           *tsIn
		Peer           map[string]*tsIn
		CurrentTailnet *struct{ Name string }
	}
	if err := json.Unmarshal(raw, &t); err != nil {
		return nil, err
	}
	peers := []*tsNode{}
	online := 0
	for _, p := range t.Peer {
		if p == nil {
			continue
		}
		if p.Online {
			online++
		}
		peers = append(peers, p.node())
	}
	sort.Slice(peers, func(i, j int) bool {
		if peers[i].Online != peers[j].Online {
			return peers[i].Online
		}
		return strings.ToLower(peers[i].HostName) < strings.ToLower(peers[j].HostName)
	})
	out := map[string]any{"state": t.BackendState, "self": t.Self.node(), "peers": peers,
		"peers_online": online, "peers_total": len(peers), "suffix": t.MagicDNSSuffix}
	if t.CurrentTailnet != nil {
		out["tailnet"] = t.CurrentTailnet.Name
	}
	if t.BackendState == "NeedsLogin" && strings.HasPrefix(t.AuthURL, "https://") {
		out["auth_url"] = t.AuthURL // the admin opens it to add this router to the tailnet
	}
	return out, nil
}

func apiSysServices(r apiReq) apiResp {
	c, err := loadConfig(ConfigPath, SecretsPath)
	if err != nil {
		return errResp(500, "%v", err)
	}
	rows := sysServiceRows(c)
	mine := map[string]bool{}
	var names []string
	for _, s := range rows {
		mine[s.Name] = true
		names = append(names, s.Name)
	}
	var others []svcRow
	for _, s := range enabledServices(c) {
		if !mine[s] {
			others = append(others, svcRow{Name: s, Label: s, Wanted: true})
			names = append(names, s)
		}
	}
	running := servicesRunning(names)
	for _, list := range [][]svcRow{rows, others} {
		for i := range list {
			_, err := os.Stat("/etc/init.d/" + list[i].Name)
			list[i].Installed = err == nil
			list[i].Running = running[list[i].Name]
		}
	}
	body := map[string]any{"services": rows, "others": others,
		"lucky_port": c.Services.Lucky.Port, "ssh_port": c.Services.SSH.Port,
		"tailscale_port": c.Services.Tailscale.Port}
	if ip, _, ok := strings.Cut(c.LAN.IPv4, "/"); ok {
		body["lan_ip"] = ip
	}
	if c.Services.Tailscale.Enabled {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		// JSON mode may exit non-zero in some backend states and still print the status
		raw, err := exec.CommandContext(ctx, "tailscale", "status", "--json").Output()
		if ts, perr := tailscaleStatus(raw); len(bytes.TrimSpace(raw)) > 0 && perr == nil {
			body["tailscale"] = ts
		} else {
			body["tailscale"] = map[string]any{"state": "unavailable", "error": firstLine(fmt.Sprint(errors.Join(err, perr)))}
		}
	}
	return apiResp{body: body}
}

// ---- system log ----

// logFiles: busybox syslogd's file and its rotation (older first). Variable for tests.
var logFiles = []string{"/var/log/messages.0", "/var/log/messages"}

var logLevels = map[string]int{"emerg": 0, "panic": 0, "alert": 1, "crit": 2, "err": 3, "error": 3,
	"warn": 4, "warning": 4, "notice": 5, "info": 6, "debug": 7}

// logEntry is one parsed syslog line: time, level (0-7, -1 unknown), facility, tag, message.
type logEntry struct {
	T, Fac, Tag, Msg string
	Lvl              int
}

var reLogTag = lazyRegexp(`^([A-Za-z0-9_./@-]{1,64})(\[[0-9]+\])?:`)

// parseSyslogLine reads busybox syslogd's "Mmm dd hh:mm:ss host facility.level tag[pid]: message".
func parseSyslogLine(l string) logEntry {
	e := logEntry{Lvl: -1, Msg: l}
	if len(l) < 17 || l[15] != ' ' || l[3] != ' ' || l[9] != ':' {
		return e
	}
	e.T, e.Msg = l[:15], l[16:]
	f := strings.SplitN(e.Msg, " ", 3)
	if len(f) == 3 {
		if fac, pri, ok := strings.Cut(f[1], "."); ok {
			if n, known := logLevels[pri]; known {
				e.Fac, e.Lvl, e.Msg = fac, n, f[2]
			}
		}
	}
	if m := reLogTag.FindStringSubmatch(e.Msg); m != nil {
		e.Tag = m[1]
		e.Msg = strings.TrimPrefix(e.Msg[len(m[0]):], " ")
	}
	return e
}

func tailBytes(p string, max int64) []byte {
	f, err := os.Open(p)
	if err != nil {
		return nil
	}
	defer f.Close()
	if fi, err := f.Stat(); err == nil && fi.Size() > max {
		f.Seek(fi.Size()-max, io.SeekStart)
	}
	b, _ := io.ReadAll(io.LimitReader(f, max))
	return b
}

func readSyslog() []string {
	var buf bytes.Buffer
	for _, p := range logFiles {
		buf.Write(tailBytes(p, 2<<20))
	}
	if buf.Len() == 0 { // syslogd in circular-buffer mode (-C): logread
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if out, err := exec.CommandContext(ctx, "logread").Output(); err == nil {
			buf.Write(out)
		}
	}
	return strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
}

// apiSysLogs: GET = newest 500 lines; POST {level: 0-7 (show this and more severe), tag, q, limit}.
func apiSysLogs(r apiReq) apiResp {
	in := struct {
		Level *int   `json:"level"`
		Tag   string `json:"tag"`
		Q     string `json:"q"`
		Limit int    `json:"limit"`
	}{}
	if len(r.body) > 0 {
		if err := json.Unmarshal(r.body, &in); err != nil {
			return errResp(400, "bad request")
		}
	}
	level := 7
	if in.Level != nil {
		if *in.Level < 0 || *in.Level > 7 {
			return errResp(400, "level: 0-7")
		}
		level = *in.Level
	}
	if in.Limit <= 0 {
		in.Limit = 500
	}
	if in.Limit > 5000 || len(in.Q) > 200 || len(in.Tag) > 64 {
		return errResp(400, "limit up to 5000, q up to 200 characters")
	}
	q := strings.ToLower(in.Q)
	tags := map[string]int{}
	var rows [][]any
	lines := readSyslog()
	total := 0
	for i := len(lines) - 1; i >= 0; i-- { // newest first
		if lines[i] == "" {
			continue
		}
		total++
		e := parseSyslogLine(lines[i])
		if e.Tag != "" {
			tags[e.Tag]++
		}
		// a level filter hides lines whose level is unknown
		if len(rows) >= in.Limit || e.Lvl > level || (e.Lvl < 0 && level < 7) || (in.Tag != "" && e.Tag != in.Tag) ||
			(q != "" && !strings.Contains(strings.ToLower(lines[i]), q)) {
			continue
		}
		rows = append(rows, []any{e.T, e.Lvl, e.Fac, e.Tag, e.Msg})
	}
	if rows == nil {
		rows = [][]any{}
	}
	return apiResp{body: map[string]any{"lines": rows, "total": total, "tags": tags}}
}

// ---- mr sys ... ----

func sysCommand(c *Config, args []string) error {
	usage := errors.New("usage: mr sys run ACTION [TARGET] | backup [-secrets] FILE|- | restore [-confirm SECS] FILE | keys")
	if len(args) == 0 {
		return usage
	}
	switch args[0] {
	case "run":
		return sysRunTask(c, args[1:])
	case "backup":
		return sysBackupCommand(args[1:])
	case "restore":
		return sysRestoreCommand(args[1:])
	case "restore-watch": // internal: started by a restore
		if len(args) != 4 {
			return usage
		}
		secs, _ := strconv.Atoi(args[1])
		off, _ := strconv.ParseInt(args[3], 10, 64)
		return sysRestoreWatch(secs, args[2], off)
	case "keys":
		b, _ := os.ReadFile(authKeysFile)
		inside := false
		for _, l := range strings.Split(string(b), "\n") {
			switch t := strings.TrimSpace(l); {
			case t == akBegin:
				inside = true
			case t == akEnd:
				inside = false
			case t != "" && !strings.HasPrefix(t, "#"):
				where := "other  "
				if inside {
					where = "managed"
				}
				if k, err := parseKeyLine(t); err == nil {
					fmt.Printf("%s %s %s %s\n", where, k.FP, k.Type, k.Comment)
				} else {
					fmt.Printf("%s (not parsed: %v)\n", where, err)
				}
			}
		}
		return nil
	}
	return usage
}
