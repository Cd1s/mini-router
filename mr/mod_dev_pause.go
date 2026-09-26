package main

// dev module: pausing a device's internet access at runtime — `mr pause`, `mr unpause`, the web UI's
// 暂停 buttons (dev.pause / dev.unpause / dev.paused). Nothing in router.yaml changes, there is no
// confirm window and nothing resident: the kernel ends the pause by itself.
//
// State: /run/mini-router/pause.json (tmpfs: a reboot ends every pause) lists the paused MACs, when
// each pause ends in seconds since boot (the clock the kernel's set timeouts run on; wall-clock jumps
// at boot, when NTP first sets the clock, do not matter) and the addresses the device had. fwLoad
// (every firewall reload: apply, PPPoE / DHCP hooks, `mr fw`) turns it into, in the same transaction
// as the ruleset:
//
//	set paused   { type ether_addr; flags timeout }  the MACs, each with its remaining time
//	set paused_4 / paused_6                          their addresses, same timeouts
//	input:   LAN-side, ether saddr @paused, not for the router itself (DNS, DHCP stay) → drop
//	         (a transparent proxy takes traffic through input, not forward)
//	forward: LAN-side, ether saddr @paused, to a WAN → drop
//	         from a WAN to @paused_4 / @paused_6 → drop
//
// inserted at the top of both chains, above flow offload and the established accept. A pause always
// reloads the whole table: replacing it replaces the flowtable, which sends every offloaded flow (PPE
// or software fast path) back to the CPU path, so the device's established connections — a running
// video, a game — stop at once in both directions; everyone else's flows are offloaded again by
// their next packet. (Deleting the device's conntrack entries would need nf_conntrack_netlink, which
// the platform kernel does not build.) The addresses matter for connections that were established
// before the pause: their replies arrive from the WAN before the device sends anything.
// Pausing again sets a new end time; unpausing reloads without the device. When all pauses have
// ended the (empty) rules stay until the next reload.

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	pauseMaxSecs = 7 * 86400
	pauseMaxMACs = 256
)

// variables so tests can point them elsewhere
var (
	pauseFile      = RunDir + "/pause.json"
	pauseLock      = RunDir + "/pause.lock"
	pauseLeaseFile = LeaseFile
	devConfigPath  = ConfigPath
	devSecretsPath = SecretsPath
	pauseUptime    = func() int64 { // seconds since boot
		f := strings.Fields(readFile("/proc/uptime"))
		if len(f) > 0 {
			if s, err := strconv.ParseFloat(f[0], 64); err == nil {
				return int64(s)
			}
		}
		return time.Now().Unix()
	}
	pauseReload = fwLoad
	// pauseLoaded reports whether the loaded @paused set holds mac (a failed reload keeps the old table).
	pauseLoaded = func(macs []string) error {
		out, err := run("nft", "list", "set", "inet", "mr", "paused")
		if err != nil {
			return fmt.Errorf("the pause is not in the firewall (nft: %s)", firstLine(strings.TrimSpace(out)))
		}
		for _, m := range macs {
			if !strings.Contains(out, m) {
				return fmt.Errorf("the pause of %s is not in the firewall", m)
			}
		}
		return nil
	}
)

type pauseEntry struct {
	MAC   string   `json:"mac"`
	Until int64    `json:"until"`         // seconds since boot
	Ref   string   `json:"ref,omitempty"` // what was paused: a device, group:NAME, a dhcp.hosts name or the MAC
	By    string   `json:"by,omitempty"`  // cli | web | api:<token>
	IPs   []string `json:"ips,omitempty"` // the device's addresses (cut inbound replies after a reload)
}

// pauseRead returns the pauses that have not ended at now. Everything is checked again: it is
// rendered into nft commands.
func pauseRead(now int64) []pauseEntry {
	var st struct {
		Paused []pauseEntry `json:"paused"`
	}
	b, err := os.ReadFile(pauseFile)
	if err != nil || json.Unmarshal(b, &st) != nil {
		return nil
	}
	var out []pauseEntry
	for _, e := range st.Paused {
		if !reMAC.MatchString(e.MAC) || e.Until <= now || e.Until-now > pauseMaxSecs || len(out) >= pauseMaxMACs {
			continue
		}
		e.MAC = strings.ToLower(e.MAC)
		var ips []string
		for _, a := range e.IPs {
			if ip := net.ParseIP(a); ip != nil && len(ips) < 32 {
				ips = append(ips, ip.String())
			}
		}
		e.IPs = ips
		if !safeText(e.Ref) || len(e.Ref) > 64 {
			e.Ref = ""
		}
		if !safeText(e.By) || len(e.By) > 64 {
			e.By = ""
		}
		out = append(out, e)
	}
	return out
}

func pauseWrite(ents []pauseEntry) error {
	if len(ents) == 0 {
		if err := os.Remove(pauseFile); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	b, _ := json.Marshal(map[string]any{"paused": ents})
	return writeAtomic(pauseFile, b, 0600)
}

// pauseScript: the nft commands for the active pauses ("" when there is none), run by fwLoad after
// the ruleset in the same transaction.
func pauseScript(c *Config) string {
	now := pauseUptime()
	ents := pauseRead(now)
	if len(ents) == 0 {
		return ""
	}
	neigh, owner := pauseNeigh(c)
	lans := "{ " + quoteList(c.LANBridges()) + " }"
	wans := "{ " + quoteList(c.WANIfnames()) + " }"
	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f+"\n", a...) }
	w("add set inet mr paused { type ether_addr; size %d; flags timeout; }", pauseMaxMACs)
	w("add set inet mr paused_4 { type ipv4_addr; size 4096; flags timeout; }")
	w("add set inet mr paused_6 { type ipv6_addr; size 4096; flags timeout; }")
	// insert = at the top: the last one inserted ends up first
	w("insert rule inet mr input iifname %s ether saddr @paused fib daddr type != { local, broadcast, multicast, anycast } counter drop comment \"pause\"", lans)
	w("insert rule inet mr forward iifname %s ip6 daddr @paused_6 counter drop comment \"pause\"", wans)
	w("insert rule inet mr forward iifname %s ip daddr @paused_4 counter drop comment \"pause\"", wans)
	w("insert rule inet mr forward iifname %s ether saddr @paused oifname %s counter drop comment \"pause\"", lans, wans)
	var macs []string
	elems := map[string][]string{}
	left := map[string]int64{} // address → the longest remaining pause among the MACs that use it
	for _, e := range ents {
		secs := e.Until - now
		macs = append(macs, fmt.Sprintf("%s timeout %ds", e.MAC, secs))
		for _, a := range dedup(append(append([]string{}, e.IPs...), neigh[e.MAC]...)) {
			ip := net.ParseIP(a)
			if ip == nil || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() || ip.IsLoopback() {
				continue
			}
			if o := owner[ip.String()]; o != "" && o != e.MAC {
				continue // another device uses it now (the paused one left, its lease was given away)
			}
			set := "paused_6"
			if ip.To4() != nil {
				set = "paused_4"
			}
			k := ip.String()
			if _, seen := left[k]; !seen {
				elems[set] = append(elems[set], k)
			}
			left[k] = max(left[k], secs)
		}
	}
	w("add element inet mr paused { %s }", strings.Join(macs, ", "))
	for _, set := range []string{"paused_4", "paused_6"} {
		if len(elems[set]) == 0 {
			continue
		}
		var xs []string
		for _, a := range elems[set] {
			xs = append(xs, fmt.Sprintf("%s timeout %ds", a, left[a]))
		}
		w("add element inet mr %s { %s }", set, strings.Join(xs, ", "))
	}
	return b.String()
}

// pauseNeigh: the addresses the router knows for each MAC right now — neighbour table (ARP + NDP),
// DHCP leases, fixed addresses of dhcp.hosts / devices — and, from the neighbour table, which MAC
// holds an address now.
var pauseNeigh = func(c *Config) (byMAC map[string][]string, owner map[string]string) {
	out, owner := map[string][]string{}, map[string]string{}
	if nb, err := monNeighbours(); err == nil {
		for _, x := range nb {
			m := strings.ToLower(x.MAC)
			if m == "" || !x.Addr.IsValid() {
				continue
			}
			out[m] = append(out[m], x.Addr.String())
			owner[x.Addr.Unmap().String()] = m
		}
	}
	v4, _ := parseLeases(readFile(pauseLeaseFile))
	for _, l := range v4 {
		m := strings.ToLower(l.MAC)
		out[m] = append(out[m], l.IP)
	}
	for _, h := range c.knownHosts() {
		if h.IP != "" {
			m := strings.ToLower(h.MAC)
			out[m] = append(out[m], h.IP)
		}
	}
	return out, owner
}

// pauseTarget resolves what to pause: a device, group:NAME, a dhcp.hosts name or a MAC.
func pauseTarget(c *Config, t string) ([]string, error) {
	switch {
	case reMAC.MatchString(t):
		if hw, _ := net.ParseMAC(t); hw[0]&1 != 0 {
			return nil, fmt.Errorf("%s is not a unicast MAC", t)
		}
		return []string{strings.ToLower(t)}, nil
	case len(t) > 64 || !safeText(t):
		return nil, fmt.Errorf("a device, group:NAME, dhcp.hosts name or MAC")
	}
	if m, ok := devRefMACs(c, t); ok {
		if len(m) == 0 {
			return nil, fmt.Errorf("%s has no devices", t)
		}
		return m, nil
	}
	for _, h := range c.DHCP.Hosts {
		if h.Name != "" && strings.EqualFold(h.Name, t) && reMAC.MatchString(h.MAC) {
			return []string{strings.ToLower(h.MAC)}, nil
		}
	}
	return nil, fmt.Errorf("unknown device %q (a device, group:NAME, dhcp.hosts name or MAC)", t)
}

// pauseDuration parses 30m, 1h, 1h30m, 90s, 1d, 2d (1 second to 7 days) into seconds.
func pauseDuration(s string) (int64, error) {
	var secs int64
	if n, ok := strings.CutSuffix(s, "d"); ok && monIsNum(n) && len(n) <= 2 {
		secs = int64(atoi(n)) * 86400
	} else if d, err := time.ParseDuration(s); err == nil {
		secs = int64(d / time.Second)
	}
	if secs < 1 || secs > pauseMaxSecs {
		return 0, fmt.Errorf("duration: 30m, 1h, 2h30m, 1d … (1s to 7d), got %q", s)
	}
	return secs, nil
}

// pauseSet pauses every MAC of target for secs and reloads the firewall.
func pauseSet(c *Config, target string, secs int64, by string) ([]string, error) {
	macs, err := pauseTarget(c, target)
	if err != nil {
		return nil, err
	}
	if lk := flock(pauseLock, true); lk != nil {
		defer lk.Close()
	}
	now := pauseUptime()
	ents := pauseRead(now)
	neigh, _ := pauseNeigh(c)
	for _, m := range macs {
		i := 0
		for i < len(ents) && ents[i].MAC != m {
			i++
		}
		if i == len(ents) {
			ents = append(ents, pauseEntry{MAC: m})
		}
		e := &ents[i]
		e.Until, e.Ref, e.By = now+secs, target, by
		e.IPs = dedup(append(e.IPs, neigh[m]...))
		if len(e.IPs) > 32 {
			e.IPs = e.IPs[len(e.IPs)-32:]
		}
	}
	if len(ents) > pauseMaxMACs {
		return nil, fmt.Errorf("at most %d paused MACs", pauseMaxMACs)
	}
	if err := pauseWrite(ents); err != nil {
		return nil, err
	}
	if err := pauseReload(c); err != nil {
		return nil, err
	}
	logf("pause: %s (%s) for %ds by %s", target, strings.Join(macs, " "), secs, by)
	return macs, pauseLoaded(macs)
}

// pauseClear ends the pauses of target ("all": every pause) and reloads the firewall.
func pauseClear(c *Config, target, by string) ([]string, error) {
	var macs []string
	if target != "all" {
		var err error
		if macs, err = pauseTarget(c, target); err != nil {
			return nil, err
		}
	}
	if lk := flock(pauseLock, true); lk != nil {
		defer lk.Close()
	}
	ents := pauseRead(pauseUptime())
	var keep []pauseEntry
	var gone []string
	for _, e := range ents {
		if target == "all" || containsString(macs, e.MAC) {
			gone = append(gone, e.MAC)
		} else {
			keep = append(keep, e)
		}
	}
	if err := pauseWrite(keep); err != nil {
		return nil, err
	}
	if len(gone) == 0 {
		return nil, nil // nothing was paused: no reload
	}
	logf("unpause: %s (%s) by %s", target, strings.Join(gone, " "), by)
	return gone, pauseReload(c)
}

// pauseView is one active pause as the web UI and `mr pause list` show it.
type pauseView struct {
	MAC  string   `json:"mac"`
	Name string   `json:"name,omitempty"` // device / dhcp.hosts / DHCP client name
	Ref  string   `json:"ref,omitempty"`
	By   string   `json:"by,omitempty"`
	Left int64    `json:"left"` // seconds
	IPs  []string `json:"ips,omitempty"`
}

func pauseList(c *Config) []pauseView {
	now := pauseUptime()
	ents := pauseRead(now)
	if len(ents) == 0 {
		return []pauseView{}
	}
	names := map[string]string{}
	v4, _ := parseLeases(readFile(pauseLeaseFile))
	for _, l := range v4 {
		if l.Name != "" && l.Name != "*" {
			names[strings.ToLower(l.MAC)] = eventClean(l.Name, 64)
		}
	}
	for _, h := range c.knownHosts() {
		if h.Name != "" {
			names[strings.ToLower(h.MAC)] = h.Name
		}
	}
	out := []pauseView{}
	for _, e := range ents {
		out = append(out, pauseView{MAC: e.MAC, Name: names[e.MAC], Ref: e.Ref, By: e.By, Left: e.Until - now, IPs: e.IPs})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Left < out[j].Left })
	return out
}

// pauseStatus (status JSON, overview card): the active pauses, only when there are some.
func pauseStatus(c *Config, st map[string]any) {
	if l := pauseList(c); len(l) > 0 {
		st["paused"] = l
	}
}

// ---- web UI / API ----

func pauseBy(r apiReq) string {
	if r.via != "" {
		return r.via
	}
	return "web"
}

func apiDevPaused(r apiReq) apiResp {
	c, err := loadConfig(devConfigPath, devSecretsPath)
	if err != nil {
		return errResp(500, "%v", err)
	}
	return apiResp{body: map[string]any{"paused": pauseList(c)}}
}

// apiDevPause (POST {target, duration}): pause a device, group or MAC.
func apiDevPause(r apiReq) apiResp {
	if r.method != "POST" {
		return errResp(405, "POST required")
	}
	var in struct {
		Target   string `json:"target"`
		Duration string `json:"duration"`
	}
	if err := json.Unmarshal(r.body, &in); err != nil {
		return errResp(400, "bad request")
	}
	secs, err := pauseDuration(in.Duration)
	if err != nil {
		return errResp(400, "%v", err)
	}
	c, err := loadConfig(devConfigPath, devSecretsPath)
	if err != nil {
		return errResp(500, "%v", err)
	}
	macs, err := pauseSet(c, in.Target, secs, pauseBy(r))
	if err != nil {
		return errResp(400, "%v", err)
	}
	appendChangeLog(fmt.Sprintf("%s: pause %s (%s) for %s", pauseBy(r), in.Target, strings.Join(macs, " "), in.Duration))
	return apiResp{body: map[string]any{"ok": true, "paused": pauseList(c)}}
}

// apiDevUnpause (POST {target}): end the pause of a device, group or MAC ("all": every pause).
func apiDevUnpause(r apiReq) apiResp {
	if r.method != "POST" {
		return errResp(405, "POST required")
	}
	var in struct {
		Target string `json:"target"`
	}
	if err := json.Unmarshal(r.body, &in); err != nil {
		return errResp(400, "bad request")
	}
	c, err := loadConfig(devConfigPath, devSecretsPath)
	if err != nil {
		return errResp(500, "%v", err)
	}
	gone, err := pauseClear(c, in.Target, pauseBy(r))
	if err != nil {
		return errResp(400, "%v", err)
	}
	if len(gone) > 0 {
		appendChangeLog(fmt.Sprintf("%s: unpause %s (%s)", pauseBy(r), in.Target, strings.Join(gone, " ")))
	}
	return apiResp{body: map[string]any{"ok": true, "paused": pauseList(c)}}
}

// ---- mr pause / mr unpause ----

const pauseUsage = `mr pause TARGET DURATION   pause internet access: TARGET = device, group:NAME, dhcp.hosts name or MAC;
                           DURATION = 30m, 1h, 2h30m, 1d … (max 7d); pausing again sets a new end
mr pause list [--json]     the active pauses
mr unpause TARGET|all      end a pause now`

func pauseCommand(c *Config, args []string) error {
	if len(args) >= 1 && args[0] == "list" {
		l := pauseList(c)
		if len(args) > 1 && args[1] == "--json" {
			b, _ := json.MarshalIndent(map[string]any{"paused": l}, "", "  ")
			fmt.Println(string(b))
			return nil
		}
		if len(l) == 0 {
			fmt.Println("nothing paused")
		}
		for _, p := range l {
			fmt.Printf("%-17s  %-20s  %-12s  %s left  %s\n", p.MAC, orDash(p.Name), orDash(p.Ref), fmtLeft(p.Left), strings.Join(p.IPs, " "))
		}
		return nil
	}
	if len(args) != 2 {
		return fmt.Errorf("usage:\n%s", pauseUsage)
	}
	secs, err := pauseDuration(args[1])
	if err != nil {
		return err
	}
	macs, err := pauseSet(c, args[0], secs, "cli")
	if err != nil {
		return err
	}
	fmt.Printf("paused %s (%s) for %s\n", args[0], strings.Join(macs, " "), fmtLeft(secs))
	return nil
}

func unpauseCommand(c *Config, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage:\n%s", pauseUsage)
	}
	gone, err := pauseClear(c, args[0], "cli")
	if err != nil {
		return err
	}
	if len(gone) == 0 {
		fmt.Println("was not paused")
		return nil
	}
	fmt.Printf("unpaused %s\n", strings.Join(gone, " "))
	return nil
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// fmtLeft: 59m59s, 1h0m0s, 25h0m0s (whole seconds).
func fmtLeft(secs int64) string { return (time.Duration(secs) * time.Second).String() }
