package main

// DHCP leases, lease release, temporary query logging, the dns web UI actions and `mr dns`.

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	// LeaseFile is dnsmasq's dhcp-leasefile (rootfs/etc/conf.d/dnsmasq creates it for the dnsmasq user).
	LeaseFile = "/tmp/dhcp.leases"
	// QueryLogFlag switches on dnsmasq --log-queries (read by rootfs/etc/conf.d/dnsmasq). It lives in
	// /run, holds the unix time the logging ends, and never survives a reboot.
	QueryLogFlag   = RunDir + "/dns-querylog"
	queryLogMaxMin = 60
)

type lease struct {
	MAC      string `json:"mac"`
	IP       string `json:"ip"`
	Name     string `json:"name"`
	Expires  int64  `json:"expires"` // unix time, 0 = infinite
	Network  string `json:"network,omitempty"`
	Static   bool   `json:"static,omitempty"`
	clientID string
}

type lease6 struct {
	IAID    string `json:"iaid"`
	IP      string `json:"ip"`
	Name    string `json:"name"`
	Expires int64  `json:"expires"`
	DUID    string `json:"duid"`
}

// parseLeases reads dnsmasq's lease file: "EXPIRY MAC IP NAME CLIENTID" for DHCPv4, then a
// "duid ..." line and "EXPIRY IAID IPV6 NAME DUID" for DHCPv6.
func parseLeases(data string) (v4 []lease, v6 []lease6) {
	for _, l := range strings.Split(data, "\n") {
		f := strings.Fields(l)
		if len(f) < 4 || f[0] == "duid" {
			continue
		}
		exp, err := strconv.ParseInt(f[0], 10, 64)
		ip := net.ParseIP(f[2])
		if err != nil || ip == nil {
			continue
		}
		clid := ""
		if len(f) >= 5 && f[4] != "*" {
			clid = f[4]
		}
		if ip.To4() != nil && !strings.Contains(f[2], ":") {
			v4 = append(v4, lease{MAC: f[1], IP: f[2], Name: f[3], Expires: exp, clientID: clid})
		} else {
			v6 = append(v6, lease6{IAID: f[1], IP: f[2], Name: f[3], Expires: exp, DUID: clid})
		}
	}
	return v4, v6
}

// readLeases returns the current leases, annotated with their network and static assignment.
func readLeases(c *Config) ([]lease, []lease6) {
	v4, v6 := parseLeases(readFile(LeaseFile))
	static := map[string]bool{}
	for _, h := range c.DHCP.Hosts {
		static[strings.ToLower(h.MAC)] = true
	}
	for i := range v4 {
		l := &v4[i]
		l.Static = static[strings.ToLower(l.MAC)]
		if n := lanNetFor(c, net.ParseIP(l.IP)); n != nil {
			l.Network = n.Name
		}
	}
	return v4, v6
}

func lanNetFor(c *Config, ip net.IP) *LANNet {
	for _, n := range c.LANNets() {
		if _, nn, err := net.ParseCIDR(n.IPv4); err == nil && ip != nil && nn.Contains(ip) {
			return &n
		}
	}
	return nil
}

// dhcpReleasePacket builds the DHCPRELEASE a client would send for its lease (like dnsmasq's
// contrib dhcp_release): BOOTREQUEST, ciaddr = lease, chaddr = MAC, option 53 = 7, option 54 = server.
func dhcpReleasePacket(server, client net.IP, mac net.HardwareAddr, clid []byte) []byte {
	p := make([]byte, 240, 300)
	p[0], p[1], p[2] = 1, 1, byte(len(mac)) // BOOTREQUEST, Ethernet
	copy(p[12:16], client.To4())            // ciaddr
	copy(p[28:44], mac)                     // chaddr
	binary.BigEndian.PutUint32(p[236:], 0x63825363)
	p = append(p, 53, 1, 7)
	p = append(p, 54, 4)
	p = append(p, server.To4()...)
	if len(clid) > 0 && len(clid) < 256 {
		p = append(p, 61, byte(len(clid)))
		p = append(p, clid...)
	}
	p = append(p, 255)
	for len(p) < 300 {
		p = append(p, 0)
	}
	return p
}

// releaseLease makes dnsmasq drop one DHCPv4 lease by sending the DHCPRELEASE the client would
// send. dnsmasq owns the lease file (it rewrites it from memory), so the file is never edited here.
func releaseLease(c *Config, ipStr, mac string) error {
	ip := net.ParseIP(ipStr)
	if ip == nil || ip.To4() == nil || strings.Contains(ipStr, ":") {
		return fmt.Errorf("bad IPv4 address %q", ipStr)
	}
	if mac != "" && !reMAC.MatchString(mac) {
		return fmt.Errorf("bad MAC %q", mac)
	}
	v4, _ := parseLeases(readFile(LeaseFile))
	var l *lease
	for i := range v4 {
		if net.ParseIP(v4[i].IP).Equal(ip) && (mac == "" || strings.EqualFold(v4[i].MAC, mac)) {
			l = &v4[i]
		}
	}
	if l == nil {
		return fmt.Errorf("no lease for %s %s", ipStr, mac)
	}
	hw, err := net.ParseMAC(l.MAC)
	if err != nil || len(hw) != 6 {
		return fmt.Errorf("lease %s: unsupported hardware address %q", ipStr, l.MAC)
	}
	n := lanNetFor(c, ip)
	if n == nil {
		return fmt.Errorf("%s is not inside a LAN network", ipStr)
	}
	server, _, _ := net.ParseCIDR(n.IPv4)
	var clid []byte
	if l.clientID != "" {
		clid, _ = hex.DecodeString(strings.ReplaceAll(l.clientID, ":", ""))
	}
	if err := sendDHCPRelease(n.Bridge, server, dhcpReleasePacket(server, ip, hw, clid)); err != nil {
		return fmt.Errorf("send DHCPRELEASE: %w", err)
	}
	for i := 0; i < 30; i++ {
		time.Sleep(100 * time.Millisecond)
		gone := true
		cur, _ := parseLeases(readFile(LeaseFile))
		for _, x := range cur {
			if net.ParseIP(x.IP).Equal(ip) && strings.EqualFold(x.MAC, l.MAC) {
				gone = false
			}
		}
		if gone {
			logf("dhcp: released lease %s %s", ipStr, l.MAC)
			return nil
		}
	}
	return fmt.Errorf("dnsmasq kept the lease for %s (is dnsmasq running?)", ipStr)
}

// ---- temporary query logging ----

// queryLogUntil returns the unix time query logging ends (0 = off).
func queryLogUntil() int64 {
	b, err := os.ReadFile(QueryLogFlag)
	if err != nil {
		return 0
	}
	t, _ := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if t <= time.Now().Unix() {
		return 0
	}
	return t
}

func restartDnsmasq() error {
	if out, err := run("rc-service", "dnsmasq", "restart"); err != nil {
		return fmt.Errorf("restart dnsmasq: %v %s", err, strings.TrimSpace(out))
	}
	return nil
}

// setQueryLog switches dnsmasq query logging on for minutes (1-60) or off. dnsmasq restarts
// (its cache is lost); a detached `mr dns querylog-expire` switches it off again.
func setQueryLog(on bool, minutes int) error {
	if !on {
		if _, err := os.Stat(QueryLogFlag); err != nil {
			return nil
		}
		os.Remove(QueryLogFlag)
		logf("dns: query logging off")
		return restartDnsmasq()
	}
	if minutes < 1 || minutes > queryLogMaxMin {
		return fmt.Errorf("minutes: 1-%d", queryLogMaxMin)
	}
	until := time.Now().Add(time.Duration(minutes) * time.Minute).Unix()
	os.MkdirAll(RunDir, 0700)
	if err := writeAtomic(QueryLogFlag, []byte(strconv.FormatInt(until, 10)+"\n"), 0600); err != nil {
		return err
	}
	logf("dns: query logging on for %d min", minutes)
	if err := restartDnsmasq(); err != nil {
		os.Remove(QueryLogFlag)
		restartDnsmasq()
		return err
	}
	self, _ := os.Executable()
	startDetached(self, "dns", "querylog-expire", strconv.FormatInt(until, 10))
	return nil
}

// queryLogExpire sleeps until `until`, then switches logging off unless it was re-armed or turned off.
func queryLogExpire(until int64) error {
	if d := time.Until(time.Unix(until, 0)); d > 0 {
		time.Sleep(d)
	}
	b, err := os.ReadFile(QueryLogFlag)
	if err != nil || strings.TrimSpace(string(b)) != strconv.FormatInt(until, 10) {
		return nil
	}
	os.Remove(QueryLogFlag)
	logf("dns: query logging expired")
	return restartDnsmasq()
}

// queryLogLines: the most recent dnsmasq query-log lines from syslog.
func queryLogLines(limit int) []string {
	data := readFile("/var/log/messages")
	if data == "" {
		data, _ = run("logread")
	}
	return filterQueryLog(data, limit)
}

// filterQueryLog keeps dnsmasq's query-log lines, minus the statistics probes `mr` itself sends
// (the web UI polls them every 5 s: 12 lines per poll would push real queries out of the view).
func filterQueryLog(data string, limit int) []string {
	var out []string
	for _, l := range strings.Split(data, "\n") {
		if !strings.Contains(l, "dnsmasq[") || isStatsProbe(l) {
			continue
		}
		for _, k := range []string{" query[", " reply ", " cached ", " forwarded ", " config ", " cached-stale "} {
			if strings.Contains(l, k) {
				out = append(out, l)
				break
			}
		}
	}
	if len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out
}

// isStatsProbe: "query[TXT] hits.bind from 127.0.0.1" / "config hits.bind is <TXT>".
func isStatsProbe(l string) bool {
	for _, n := range statsBindNames {
		if strings.Contains(l, " "+n+" from 127.0.0.1") || strings.Contains(l, " "+n+" is <TXT>") {
			return true
		}
	}
	return false
}

// ---- web UI actions ----

func apiDNSStats(r apiReq) apiResp {
	c, err := loadConfig(ConfigPath, SecretsPath)
	if err != nil {
		return errResp(500, "%v", err)
	}
	v4, v6 := readLeases(c)
	body := map[string]any{"upstream": c.DNS.Upstream, "leases": len(v4), "leases6": len(v6), "querylog_until": queryLogUntil()}
	if st, err := queryDnsmasqStats(dnsLocal); err != nil {
		body["error"] = "dnsmasq: " + err.Error()
	} else {
		body["dnsmasq"] = st
	}
	return apiResp{body: body}
}

func apiDNSLeases(r apiReq) apiResp {
	c, err := loadConfig(ConfigPath, SecretsPath)
	if err != nil {
		return errResp(500, "%v", err)
	}
	v4, v6 := readLeases(c)
	if v4 == nil {
		v4 = []lease{}
	}
	if v6 == nil {
		v6 = []lease6{}
	}
	return apiResp{body: map[string]any{"now": time.Now().Unix(), "leases": v4, "leases6": v6}}
}

func apiDNSRelease(r apiReq) apiResp {
	if r.method != "POST" {
		return errResp(405, "POST required")
	}
	var in struct {
		IP  string `json:"ip"`
		MAC string `json:"mac"`
	}
	if err := json.Unmarshal(r.body, &in); err != nil {
		return errResp(400, "bad request")
	}
	if !reMAC.MatchString(in.MAC) {
		return errResp(400, "bad mac")
	}
	c, err := loadConfig(ConfigPath, SecretsPath)
	if err != nil {
		return errResp(500, "%v", err)
	}
	if err := releaseLease(c, in.IP, in.MAC); err != nil {
		return errResp(400, "%v", err)
	}
	appendChangeLog("webui: dhcp lease released " + in.IP + " " + strings.ToLower(in.MAC))
	return apiResp{body: map[string]any{"ok": true}}
}

func apiDNSQueryLog(r apiReq) apiResp {
	if r.method == "POST" {
		var in struct {
			On      bool `json:"on"`
			Minutes int  `json:"minutes"`
		}
		if err := json.Unmarshal(r.body, &in); err != nil {
			return errResp(400, "bad request")
		}
		if err := setQueryLog(in.On, in.Minutes); err != nil {
			return errResp(400, "%v", err)
		}
	}
	return apiResp{body: map[string]any{"until": queryLogUntil(), "now": time.Now().Unix(), "lines": queryLogLines(300)}}
}

// ---- mr dns ... ----

const dnsUsage = `mr dns stats                         dnsmasq cache / upstream statistics (JSON)
mr dns query NAME [TYPE] [SERVER]    ask dnsmasq (or SERVER ip[#port]); TYPE A AAAA CNAME PTR SRV TXT
mr dns leases                        DHCP leases (JSON)
mr dns release IP [MAC]              make dnsmasq drop a DHCPv4 lease
mr dns querylog on [MINUTES]|off|show  temporary query logging (default 10 min, max 60, gone after reboot)
mr dns adblock status | update [--cron] [--no-reload]   ad blocking lists (dns.adblock)`

func dnsCommand(c *Config, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage:\n%s", dnsUsage)
	}
	pj := func(v any) error {
		b, _ := json.MarshalIndent(v, "", "  ")
		fmt.Println(string(b))
		return nil
	}
	switch args[0] {
	case "adblock":
		return adblockCommand(c, args[1:])
	case "stats":
		st, err := queryDnsmasqStats(dnsLocal)
		if err != nil {
			return err
		}
		return pj(st)
	case "query":
		if len(args) < 2 {
			return fmt.Errorf("usage: mr dns query NAME [TYPE] [SERVER]")
		}
		name, typ, server := args[1], "A", dnsLocal
		if len(args) > 2 {
			typ = strings.ToUpper(args[2])
		}
		qt, ok := dnsTypes[typ]
		if !ok {
			return fmt.Errorf("type: A AAAA CNAME PTR SRV TXT")
		}
		if ip := net.ParseIP(name); ip != nil && qt == dnsTypePTR {
			name = reverseName(ip)
		}
		if !validDNSName(name) {
			return fmt.Errorf("bad name %q", name)
		}
		if len(args) > 3 {
			if !validServer(args[3]) {
				return fmt.Errorf("server: ip[#port]")
			}
			h, p, has := strings.Cut(args[3], "#")
			if !has {
				p = "53"
			}
			server = net.JoinHostPort(h, p)
		}
		rc, rrs, err := dnsQuery(server, name, qt, dnsClassIN, 3*time.Second)
		if err != nil {
			return err
		}
		fmt.Printf(";; %s %s: %s, %d answers\n", name, typ, rcodeName(rc), len(rrs))
		for _, rr := range rrs {
			fmt.Printf("%s\t%d\t%s\t%s\n", rr.Name, rr.TTL, rr.Type, rr.Data)
		}
		return nil
	case "leases":
		v4, v6 := readLeases(c)
		return pj(map[string]any{"leases": v4, "leases6": v6})
	case "release":
		if len(args) < 2 {
			return fmt.Errorf("usage: mr dns release IP [MAC]")
		}
		mac := ""
		if len(args) > 2 {
			mac = args[2]
		}
		if err := releaseLease(c, args[1], mac); err != nil {
			return err
		}
		fmt.Println("released", args[1])
		return nil
	case "querylog":
		op := "show"
		if len(args) > 1 {
			op = args[1]
		}
		switch op {
		case "on":
			mins := 10
			if len(args) > 2 {
				n, err := strconv.Atoi(args[2])
				if err != nil {
					return fmt.Errorf("minutes: 1-%d", queryLogMaxMin)
				}
				mins = n
			}
			return setQueryLog(true, mins)
		case "off":
			return setQueryLog(false, 0)
		case "show":
			if u := queryLogUntil(); u > 0 {
				fmt.Printf("# query logging on until %s\n", time.Unix(u, 0).Format("15:04:05"))
			} else {
				fmt.Println("# query logging off")
			}
			for _, l := range queryLogLines(300) {
				fmt.Println(l)
			}
			return nil
		}
		return fmt.Errorf("usage: mr dns querylog on [MINUTES]|off|show")
	case "querylog-expire": // internal: started detached by `querylog on`
		if len(args) < 2 {
			return fmt.Errorf("querylog-expire UNIXTIME")
		}
		t, err := strconv.ParseInt(args[1], 10, 64)
		if err != nil {
			return err
		}
		return queryLogExpire(t)
	}
	return fmt.Errorf("usage:\n%s", dnsUsage)
}
