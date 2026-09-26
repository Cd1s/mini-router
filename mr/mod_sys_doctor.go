package main

// sys module: `mr doctor` (Cd1s/mini-router#16) — a fixed set of read-only checks, each finding with
// a severity (ok | warn | risk | skip) and a one-line fix. The first thing to run when something is
// wrong (agents: `mr doctor --json`); also API sys.doctor (web UI 状态 ›
// 体检与事件) and, with notify.doctor_interval, a background run from `mr event tick` whose new
// findings become events.
//
// Checks: config (validates, guard, edits not applied), pending (a change waiting for confirmation, a
// failed boot rollback), wan (address, health, CGNAT behind port forwards, overlap with a LAN subnet), routes (main default route,
// per-WAN tables), dns (a lookup through dnsmasq on 127.0.0.1), ipv6 (delegated prefix on the LAN), offload
// (flowtable, hardware flag, PPE entries), services (wanted vs running), wifi (radios / BSSes up), clock
// (plausible, NTP synced), storage (config flash, /tmp), memory, conntrack, temp, crash (pstore records,
// oops / OOM in this boot's kernel log), ssh (password logins), certs (the reverse proxy's certificates).
//
// No arbitrary commands: the only programs run are `ip -j`, `nft list flowtable inet mr ft` and
// `rc-service NAME status` for the services the config enables; everything else is read from /proc,
// /sys, /run and the config. The last result is kept in /run/mini-router/doctor.json (`mr status` shows
// its problems on the overview).

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// docFinding is one result line.
type docFinding struct {
	ID     string `json:"id"`    // check[.subject]: wan.wan2, services.dnsmasq, storage.config
	Check  string `json:"check"` // the check that made it
	Sev    string `json:"sev"`   // ok | warn | risk | skip
	Title  string `json:"title"`
	Detail string `json:"detail"`
	Fix    string `json:"fix,omitempty"`
	// NoEvent: a standing choice or a moment of an apply, not a fault — the background run does not
	// turn it into an event (it would come back after every reboot, or with every change)
	NoEvent bool `json:"-"`
}

type docResult struct {
	Time   int64        `json:"time"`
	Risk   int          `json:"risk"`
	Warn   int          `json:"warn"`
	OK     int          `json:"ok"`
	Checks []docFinding `json:"checks"`
}

// docEnv: everything the checks read from the system (tests replace it).
type docEnv struct {
	now       time.Time
	uptime    float64
	read      func(path string) string
	exists    func(path string) bool
	mtime     func(path string) (time.Time, bool)
	addrs4    func(dev string) []string              // "addr/prefix"
	health    func(c *Config) map[string]string      // WAN -> up | down (multi-WAN checker)
	routes    func(args ...string) []map[string]any  // ip -j route show ARGS
	global6   func(dev string) []net.IP              // usable global IPv6 addresses
	resolve   func(name string) error                // A lookup through the router's dnsmasq
	flowtable func() (string, error)                 // nft list flowtable inet mr ft
	hwFlows   func() int                             // conntrack entries offloaded to the PPE
	running   func(names []string) map[string]bool   // installed services -> running
	df        func(path string) (total, avail int64) // KiB
	ntp       func() (synced, known bool, age time.Duration)
	pending   func() (*pendingApply, error)
	validate  func(c *Config) []string
	unapplied func(c *Config) ([]string, bool)
	klog      func() (string, error)
	pstore    func() ([]string, string)
	wifi      func(c *Config) []string
}

// doctorFile keeps the last result (tmpfs).
var doctorFile = RunDir + "/doctor.json"

// ntpSyncDir: mr-clock creates it for ntpd's user; clock-save (ntpd -S) touches synced in it on every
// sync report and removes it on "unsync". adjtimex cannot tell: busybox ntpd never lowers the kernel's
// maxerror, so STA_UNSYNC stays set while it keeps the clock right.
var ntpSyncDir = "/run/mr-clock"

// ntpMarker: synced = ntpd reported a sync within 30 minutes (it does every 11 minutes while synced).
func ntpMarker() (synced, known bool, age time.Duration) {
	if _, err := os.Stat(ntpSyncDir); err != nil {
		return false, false, 0
	}
	fi, err := os.Stat(filepath.Join(ntpSyncDir, "synced"))
	if err != nil {
		return false, true, 0
	}
	age = time.Since(fi.ModTime())
	return age < 30*time.Minute, true, age
}

// newDocEnv: the real system (a variable: tests of the background run use a fake one).
var newDocEnv = func() *docEnv {
	return &docEnv{
		now:    time.Now(),
		uptime: atof(firstField(readFile("/proc/uptime"))),
		read:   readFile,
		exists: func(p string) bool { _, err := os.Stat(p); return err == nil },
		mtime: func(p string) (time.Time, bool) {
			fi, err := os.Stat(p)
			if err != nil {
				return time.Time{}, false
			}
			return fi.ModTime(), true
		},
		addrs4:  ipv4Addrs,
		health:  wanHealthMap,
		routes:  ipRoutes,
		global6: ipGlobal6,
		resolve: func(name string) error {
			a, rc, err := dnsQueryA("127.0.0.1:53", name, 3*time.Second)
			switch {
			case err != nil:
				return err
			case rc != 0:
				return fmt.Errorf("answer code %d", rc)
			case !a.IsValid():
				return errors.New("no address in the answer")
			}
			return nil
		},
		flowtable: func() (string, error) {
			out, err := run("nft", "list", "flowtable", "inet", "mr", "ft")
			if err != nil {
				return "", errors.New(firstLine(strings.TrimSpace(out)))
			}
			return out, nil
		},
		hwFlows: func() int {
			f, err := os.Open("/proc/net/nf_conntrack")
			if err != nil {
				return 0
			}
			defer f.Close()
			n := 0
			sc := bufio.NewScanner(f)
			sc.Buffer(make([]byte, 0, 4096), 64<<10)
			for sc.Scan() {
				if strings.Contains(sc.Text(), "[HW_OFFLOAD]") {
					n++
				}
			}
			return n
		},
		running:   servicesRunning,
		df:        dfKB,
		ntp:       ntpMarker,
		pending:   readPending,
		validate:  func(c *Config) []string { return c.Validate() },
		unapplied: changesSinceApplied,
		klog:      monKlog,
		pstore:    pstoreRecords,
		wifi:      wifiNotReady,
	}
}

// doctorChecks in the order they are shown.
var doctorChecks = []struct {
	name string
	f    func(c *Config, e *docEnv) []docFinding
}{
	{"config", docConfig}, {"pending", docPending}, {"wan", docWAN}, {"routes", docRoutes}, {"dns", docDNS},
	{"ipv6", docIPv6}, {"offload", docOffload}, {"services", docServices}, {"wifi", docWiFi}, {"clock", docClock},
	{"storage", docStorage}, {"memory", docMemory}, {"conntrack", docConntrack}, {"temp", docTemp},
	{"crash", docCrash}, {"ssh", docSSH}, {"certs", docCerts},
}

// runDoctor runs every check and saves the result.
func runDoctor(c *Config, e *docEnv) docResult {
	r := docResult{Time: e.now.Unix(), Checks: []docFinding{}}
	for _, ck := range doctorChecks {
		for _, f := range ck.f(c, e) {
			f.Check = ck.name
			if f.ID == "" {
				f.ID = ck.name
			}
			switch f.Sev {
			case "risk":
				r.Risk++
			case "warn":
				r.Warn++
			case "ok":
				r.OK++
			}
			r.Checks = append(r.Checks, f)
		}
	}
	b, _ := json.Marshal(r)
	writeAtomic(doctorFile, b, 0600)
	return r
}

// ---- checks ----

func docOK(title, detail string) docFinding {
	return docFinding{Sev: "ok", Title: title, Detail: detail}
}

func docConfig(c *Config, e *docEnv) []docFinding {
	var out []docFinding
	errs := e.validate(c)
	guard := 0
	for _, x := range errs {
		if strings.HasPrefix(x, "guard.") {
			guard++
		}
	}
	other := len(errs) - guard
	if guard > 0 {
		out = append(out, docFinding{ID: "config.guard", Sev: "risk", Title: "Guard",
			Detail: fmt.Sprintf("the live config breaks the owner's baseline (%d): %s", guard, firstMatching(errs, "guard.")),
			Fix:    "should be impossible (every change is validated): mr validate; mr history (who changed it); restore the setting"})
	}
	if other > 0 {
		out = append(out, docFinding{ID: "config.valid", Sev: "risk", Title: "router.yaml",
			Detail: fmt.Sprintf("does not validate (%d problems): %s", other, firstMatching(errs, "")),
			Fix:    "mr validate; fix router.yaml (or mr rollback N) before the next apply"})
	}
	if ch, known := e.unapplied(c); known && len(ch) > 0 {
		out = append(out, docFinding{ID: "config.unapplied", Sev: "warn", Title: "router.yaml",
			Detail: fmt.Sprintf("%d change(s) not applied yet: %s", len(ch), eventClean(ch[0], 120)),
			Fix:    "mr plan; mr apply --confirm 120 (or undo the edit)", NoEvent: true})
	}
	if len(out) == 0 {
		out = append(out, docOK("router.yaml", "valid, guard kept, nothing unapplied"))
	}
	return out
}

func firstMatching(xs []string, prefix string) string {
	for _, x := range xs {
		if (prefix != "") == strings.HasPrefix(x, prefix) {
			return eventClean(x, 160)
		}
	}
	return ""
}

func docPending(c *Config, e *docEnv) []docFinding {
	var out []docFinding
	p, err := e.pending()
	switch {
	case err == nil && p.State == stateApplying:
		out = append(out, docFinding{Sev: "warn", Title: "Change", Detail: fmt.Sprintf("an apply (%s) is running", eventClean(p.Via, 40)), Fix: "wait for it: mr history", NoEvent: true})
	case err == nil && p.State == stateReverting:
		out = append(out, docFinding{Sev: "warn", Title: "Change", Detail: fmt.Sprintf("a change (%s) is being rolled back", eventClean(p.Via, 40)), Fix: "wait for it: mr history", NoEvent: true})
	case err == nil:
		out = append(out, docFinding{Sev: "warn", Title: "Change", Detail: fmt.Sprintf("a change (%s) waits for confirmation: rolled back in %ds; no other change can be applied", eventClean(p.Via, 40), p.left()),
			Fix: "check it works, then mr confirm (keep) — or mr rollback (undo)", NoEvent: true})
	case !errors.Is(err, fs.ErrNotExist):
		out = append(out, docFinding{Sev: "warn", Title: "Change", Detail: eventClean(err.Error(), 160), Fix: "mr confirm clears an unreadable marker; mr history"})
	}
	for _, sfx := range []string{".failed", ".bad"} {
		if e.exists(ConfirmFile + sfx) {
			out = append(out, docFinding{ID: "pending.boot", Sev: "warn", Title: "Boot rollback",
				Detail: "a rollback at boot failed or found an unreadable marker (" + filepath.Base(ConfirmFile) + sfx + ")",
				Fix:    "tail /etc/router-changes.log; mr history; check the config, then rm " + ConfirmFile + sfx})
		}
	}
	if len(out) == 0 {
		out = append(out, docOK("Change", "nothing waiting for confirmation"))
	}
	return out
}

// wanUp: WAN name -> its first IPv4 address (only WANs that have one).
func docWANsUp(c *Config, e *docEnv) map[string]string {
	up := map[string]string{}
	for _, w := range c.WAN {
		if a := e.addrs4(w.Ifname()); len(a) > 0 {
			up[w.Name] = strings.SplitN(a[0], "/", 2)[0]
		}
	}
	return up
}

func docWAN(c *Config, e *docEnv) []docFinding {
	if len(c.WAN) == 0 {
		return []docFinding{{Sev: "skip", Title: "WAN", Detail: "no WAN configured"}}
	}
	up, health := docWANsUp(c, e), e.health(c)
	var out []docFinding
	usable := 0
	for _, w := range c.WAN {
		f := docFinding{ID: "wan." + w.Name, Title: "WAN " + w.Name}
		svc := netService(w)
		restart := "mr wan status"
		if svc != "" {
			restart += "; rc-service " + svc + " restart"
		}
		ip, isUp := up[w.Name]
		switch {
		case !isUp:
			f.Sev, f.Detail = "warn", fmt.Sprintf("no IPv4 address on %s (%s)", w.Ifname(), w.Proto)
			f.Fix = restart + "; grep -E 'pppd|udhcpc' /var/log/messages | tail (cable, account, ISP)"
		case health[w.Name] == "down":
			f.Sev, f.Detail = "warn", fmt.Sprintf("has %s but fails the health check (no reply from the multiwan targets)", ip)
			f.Fix = "mr wan health; ping -I " + w.Ifname() + " <target>; " + strings.TrimPrefix(restart, "mr wan status; ")
		default:
			usable++
			f.Sev, f.Detail = "ok", fmt.Sprintf("up on %s, %s", w.Ifname(), ip)
			if n, pfx := docLANOverlap(c, ip); n != "" { // a hotel / upstream router using the LAN's range
				f.Sev = "risk"
				f.Detail += fmt.Sprintf(" is inside %s's subnet %s: LAN and WAN overlap, some destinations are unreachable", n, pfx)
				f.Fix = "move the LAN to another range (lan.ipv4, e.g. 192.168.77.1/24; DHCP clients follow) — or the upstream network"
			} else if cls := addrClass(ip); cls != "" && len(fwEnabledForwards(c)) > 0 {
				f.Sev = "warn"
				f.Detail += fmt.Sprintf(" is a %s address: the port forwards cannot be reached from the internet", cls)
				f.Fix = "ask the ISP for a public IPv4 address (or bridge mode on its modem); or reach the LAN over IPv6 / Tailscale"
			}
		}
		out = append(out, f)
	}
	if usable == 0 { // no internet at all
		for i := range out {
			if out[i].Sev == "warn" {
				out[i].Sev = "risk"
			}
		}
	}
	return out
}

// docLANOverlap: the LAN-side network whose subnet contains the WAN address ip ("" = none).
func docLANOverlap(c *Config, ip string) (string, string) {
	a := net.ParseIP(ip)
	for _, n := range c.LANNets() {
		if _, pfx, err := net.ParseCIDR(n.IPv4); err == nil && a != nil && pfx.Contains(a) {
			return n.Name, pfx.String()
		}
	}
	return "", ""
}

func docRoutes(c *Config, e *docEnv) []docFinding {
	up, health := docWANsUp(c, e), e.health(c)
	if len(up) == 0 {
		return []docFinding{{Sev: "skip", Title: "Routes", Detail: "no WAN is up"}}
	}
	var out []docFinding
	if len(e.routes("default")) == 0 {
		out = append(out, docFinding{ID: "routes.main", Sev: "risk", Title: "Routes", Detail: "the main table has no default route although a WAN is up",
			Fix: "mr routes (re-installs every WAN's routes and reloads the firewall)"})
	}
	for _, w := range c.WAN {
		if _, ok := up[w.Name]; !ok || health[w.Name] == "down" {
			continue
		}
		t, _ := c.WANTable(w.Name)
		if len(e.routes("default", "table", fmt.Sprint(t))) == 0 {
			out = append(out, docFinding{ID: "routes." + w.Name, Sev: "warn", Title: "Routes",
				Detail: fmt.Sprintf("table %d (%s) has no default route: policy routes and balancing via %s use the main table", t, w.Name, w.Name),
				Fix:    "mr routes"})
		}
	}
	if len(out) == 0 {
		out = append(out, docOK("Routes", "default route in the main table and in every WAN table"))
	}
	return out
}

// docProbeName: a name the router needs anyway (its first NTP server), else pool.ntp.org.
func docProbeName(c *Config) string {
	for _, s := range c.System.NTP {
		if net.ParseIP(s) == nil && validDNSName(strings.TrimSuffix(s, ".")) && strings.Contains(s, ".") {
			return strings.TrimSuffix(s, ".")
		}
	}
	return "pool.ntp.org"
}

func docDNS(c *Config, e *docEnv) []docFinding {
	if len(docWANsUp(c, e)) == 0 {
		return []docFinding{{Sev: "skip", Title: "DNS", Detail: "no WAN is up"}}
	}
	name := docProbeName(c)
	if err := e.resolve(name); err != nil {
		return []docFinding{{Sev: "risk", Title: "DNS", Detail: fmt.Sprintf("the router's DNS (dnsmasq, 127.0.0.1) does not resolve %s: %s", name, eventClean(err.Error(), 120)),
			Fix: "rc-service dnsmasq status; mr dns query " + name + "; cat /run/mini-router/resolv.conf (upstreams)"}}
	}
	return []docFinding{docOK("DNS", "dnsmasq resolves "+name)}
}

func docIPv6(c *Config, e *docEnv) []docFinding {
	up := docWANsUp(c, e)
	var pd []string
	for _, w := range c.WAN {
		if _, isUp := up[w.Name]; isUp && w.IPv6 && w.IPv6PD {
			pd = append(pd, w.Name)
		}
	}
	if len(pd) == 0 || !c.LAN.IPv6RA {
		return []docFinding{{Sev: "skip", Title: "IPv6", Detail: "no WAN that is up asks for a delegated prefix (ipv6_pd) for the LAN (lan.ipv6_ra)"}}
	}
	as := e.global6(c.LAN.Bridge)
	if len(as) == 0 {
		return []docFinding{{Sev: "warn", Title: "IPv6", Detail: fmt.Sprintf("%s has no global IPv6 address: no delegated prefix from %s", c.LAN.Bridge, strings.Join(pd, ", ")),
			Fix: "rc-service mr-dhcpcd status; grep dhcpcd /var/log/messages | tail; some ISPs need a reconnect: rc-service mr-pppoe." + pd[0] + " restart"}}
	}
	return []docFinding{docOK("IPv6", fmt.Sprintf("%s has %s", c.LAN.Bridge, as[0]))}
}

func docOffload(c *Config, e *docEnv) []docFinding {
	mode := c.Firewall.Offload
	if mode == "off" {
		return []docFinding{{Sev: "warn", Title: "Flow offload", Detail: "firewall.offload is off: every packet goes through the CPU",
			Fix: "mr set firewall.offload=hardware; mr plan; mr apply --confirm 120", NoEvent: true}}
	}
	ft, err := e.flowtable()
	if err != nil {
		return []docFinding{{Sev: "risk", Title: "Flow offload", Detail: "no flowtable in the loaded firewall (" + eventClean(err.Error(), 100) + "): nothing is offloaded",
			Fix: "mr fw (reloads the firewall); nft list table inet mr | head"}}
	}
	if mode == "hardware" && !strings.Contains(ft, "flags offload") {
		return []docFinding{{Sev: "warn", Title: "Flow offload", Detail: "the flowtable has no hardware offload flag: connections use the software fast path only",
			Fix: "mr fw; dmesg | grep -i -E 'ppe|flow' (driver refused hardware offload?)"}}
	}
	d := "software fast path on"
	if mode == "hardware" {
		d = fmt.Sprintf("hardware offload on, %d connections in the PPE now", e.hwFlows())
	}
	return []docFinding{docOK("Flow offload", d)}
}

func docServices(c *Config, e *docEnv) []docFinding {
	want := enabledServices(c)
	st := e.running(want)
	var out []docFinding
	for _, s := range want {
		r, installed := st[s]
		switch {
		case !installed:
			out = append(out, docFinding{ID: "services." + s, Sev: "warn", Title: "Service " + s, Detail: "wanted by the config but not installed (/etc/init.d/" + s + ")",
				Fix: "an image or package without it: upgrade the firmware, or switch it off in router.yaml"})
		case !r:
			out = append(out, docFinding{ID: "services." + s, Sev: "risk", Title: "Service " + s, Detail: "not running",
				Fix: "rc-service " + s + " start; grep " + s + " /var/log/messages | tail"})
		}
	}
	if len(out) == 0 {
		out = append(out, docOK("Services", fmt.Sprintf("all %d wanted services run", len(want))))
	}
	return out
}

func docWiFi(c *Config, e *docEnv) []docFinding {
	if len(c.WiFi.Radios) == 0 {
		return []docFinding{{Sev: "skip", Title: "WiFi", Detail: "no radios configured"}}
	}
	var out []docFinding
	for _, b := range e.wifi(c) {
		out = append(out, docFinding{ID: "wifi." + strings.SplitN(b, ":", 2)[0], Sev: "risk", Title: "WiFi", Detail: eventClean(b, 160),
			Fix: "mr wifi status; rc-service mr-hostapd restart; grep hostapd /var/log/messages | tail"})
	}
	if len(out) == 0 {
		out = append(out, docOK("WiFi", fmt.Sprintf("%d radio(s) up with every SSID", len(c.WiFi.Radios))))
	}
	return out
}

func docClock(c *Config, e *docEnv) []docFinding {
	if built, ok := e.mtime("/etc/mini-router-release"); ok && e.now.Before(built.Add(-24*time.Hour)) {
		return []docFinding{{Sev: "risk", Title: "Clock", Detail: "the clock is before this firmware was built: it was never set (no RTC)",
			Fix: "NTP needs a WAN and DNS: see those checks; rc-service ntpd restart"}}
	}
	synced, known, age := e.ntp()
	switch {
	case !known:
		return []docFinding{{Sev: "skip", Title: "Clock", Detail: "NTP sync state unknown (no " + ntpSyncDir + ": mr-clock of an older image)"}}
	case synced:
		return []docFinding{docOK("Clock", "NTP synced "+fmtSecs(int64(age.Seconds()))+" ago")}
	case e.uptime < 900:
		return []docFinding{docOK("Clock", "NTP not synced yet, booted "+fmtSecs(int64(e.uptime))+" ago")}
	}
	d := "NTP has not synced since boot"
	if age > 0 {
		d = "NTP last synced " + fmtSecs(int64(age.Seconds())) + " ago"
	}
	return []docFinding{{Sev: "warn", Title: "Clock", Detail: d + ": time-based rules, logs and certificates drift",
		Fix: "rc-service ntpd restart; mr dns query " + docProbeName(c) + " (system.ntp reachable?)"}}
}

func docStorage(c *Config, e *docEnv) []docFinding {
	var out []docFinding
	for _, d := range []struct{ id, path, what string }{{"config", "/etc/mini-router", "config storage (flash)"}, {"tmp", "/tmp", "/tmp (RAM)"}} {
		total, avail := e.df(d.path)
		if total <= 0 {
			continue
		}
		pct := avail * 100 / total
		f := docFinding{ID: "storage." + d.id, Sev: "ok", Title: "Storage", Detail: fmt.Sprintf("%s: %s free of %s (%d%%)", d.what, fmtKiB(avail), fmtKiB(total), pct)}
		if d.id == "config" {
			switch {
			case avail < 2048:
				f.Sev = "risk"
			case avail < 8192 || pct < 10:
				f.Sev = "warn"
			}
			f.Fix = "fewer snapshots (system.history), old boot logs in /etc/mini-router/state/bootlog, big lists; du -a /etc/mini-router | sort -n | tail"
		} else {
			switch {
			case pct < 3:
				f.Sev = "risk"
			case pct < 10:
				f.Sev = "warn"
			}
			f.Fix = "a firmware upload or capture left in /tmp takes RAM: ls -la /tmp; remove what is not needed"
		}
		if f.Sev == "ok" {
			f.Fix = ""
		}
		out = append(out, f)
	}
	if len(out) == 0 {
		out = append(out, docFinding{Sev: "skip", Title: "Storage", Detail: "cannot read the file systems"})
	}
	return out
}

func fmtKiB(k int64) string {
	if k >= 1024*1024 {
		return fmt.Sprintf("%.1f GiB", float64(k)/1024/1024)
	}
	if k >= 1024 {
		return fmt.Sprintf("%.1f MiB", float64(k)/1024)
	}
	return fmt.Sprintf("%d KiB", k)
}

func docMemory(c *Config, e *docEnv) []docFinding {
	m := monParseMeminfo(e.read("/proc/meminfo"))
	total, avail := m["MemTotal"], m["MemAvailable"]
	if total <= 0 {
		return []docFinding{{Sev: "skip", Title: "Memory", Detail: "cannot read /proc/meminfo"}}
	}
	pct := avail * 100 / total
	f := docFinding{Sev: "ok", Title: "Memory", Detail: fmt.Sprintf("%s available of %s (%d%%)", fmtKiB(avail), fmtKiB(total), pct)}
	switch {
	case pct < 10:
		f.Sev = "risk"
	case pct < 20:
		f.Sev = "warn"
	}
	if f.Sev != "ok" {
		f.Fix = "mr mon procs (largest first); switch off services you do not use (services.*); system.zram: true"
	}
	return []docFinding{f}
}

func docConntrack(c *Config, e *docEnv) []docFinding {
	n := atoi(strings.TrimSpace(e.read("/proc/sys/net/netfilter/nf_conntrack_count")))
	mx := atoi(strings.TrimSpace(e.read("/proc/sys/net/netfilter/nf_conntrack_max")))
	if mx <= 0 {
		return []docFinding{{Sev: "skip", Title: "Connections", Detail: "conntrack is not loaded"}}
	}
	pct := n * 100 / mx
	f := docFinding{Sev: "ok", Title: "Connections", Detail: fmt.Sprintf("%d of %d conntrack entries (%d%%)", n, mx, pct)}
	switch {
	case pct >= 90:
		f.Sev = "risk"
	case pct >= 75:
		f.Sev = "warn"
	}
	if f.Sev != "ok" {
		f.Fix = "mr mon conns '{\"limit\":20}' (top_src: who opens them); a full table drops new connections; raise system.sysctl net.netfilter.nf_conntrack_max"
	}
	return []docFinding{f}
}

func docTemp(c *Config, e *docEnv) []docFinding {
	t := strings.TrimSpace(e.read("/sys/class/thermal/thermal_zone0/temp"))
	if t == "" {
		return []docFinding{{Sev: "skip", Title: "Temperature", Detail: "no thermal sensor"}}
	}
	mc := atoi(t)
	f := docFinding{Sev: "ok", Title: "Temperature", Detail: fmt.Sprintf("SoC %.1f °C", float64(mc)/1000)}
	switch {
	case mc >= 105000:
		f.Sev = "risk"
	case mc >= 90000:
		f.Sev = "warn"
	}
	if f.Sev != "ok" {
		f.Fix = "airflow (not stacked, vents free); the SoC slows down and may reset when too hot"
	}
	return []docFinding{f}
}

func docCrash(c *Config, e *docEnv) []docFinding {
	var out []docFinding
	if ids, first := e.pstore(); len(ids) > 0 {
		out = append(out, docFinding{ID: "crash.pstore", Sev: "warn", Title: "Kernel crash",
			Detail: fmt.Sprintf("%d crash record(s) from an earlier boot in %s: %s", len(ids), pstoreDir, first),
			Fix:    "cat " + pstoreDir + "/dmesg-*; keep a copy (and report it), then rm " + pstoreDir + "/dmesg-* to clear this"})
	}
	if k, err := e.klog(); err == nil {
		n := 0
		first := ""
		for _, l := range strings.Split(k, "\n") {
			if x := crashLine(l); x != "" {
				n++
				if first == "" {
					first = x
				}
			}
		}
		if n > 0 {
			out = append(out, docFinding{ID: "crash.klog", Sev: "warn", Title: "Kernel log",
				Detail: fmt.Sprintf("%d oops / BUG / OOM / lockup line(s) in this boot: %s", n, first),
				Fix:    "mr mon dmesg (or dmesg | grep -iE 'oops|bug|panic|out of memory|lockup'); a reboot clears it, the cause stays"})
		}
	}
	if len(out) == 0 {
		out = append(out, docOK("Kernel", "no crash records, no oops / OOM in this boot"))
	}
	return out
}

func docSSH(c *Config, e *docEnv) []docFinding {
	s := c.Services.SSH
	if s.Enabled && s.PasswordLogin {
		return []docFinding{{Sev: "warn", Title: "SSH", Detail: "accepts password logins (root)",
			Fix: "add your key to services.ssh.authorized_keys, check it works, then services.ssh.password_login: false", NoEvent: true}}
	}
	if !s.Enabled {
		return []docFinding{docOK("SSH", "off")}
	}
	return []docFinding{docOK("SSH", "keys only")}
}

// docCerts: the HTTPS reverse proxy's certificates (services.edge): missing or expired = risk, less
// than 14 days left or a failed renewal = warn. Reads the certificate files' leaves, never a key.
func docCerts(c *Config, e *docEnv) []docFinding {
	if !edgeOn(c) {
		return []docFinding{{Sev: "skip", Title: "Certificates", Detail: "the reverse proxy (services.edge) is off"}}
	}
	var out []docFinding
	fix := "mr edge status; mr edge renew (grep edge: /var/log/messages)"
	for _, x := range edgeStatusCerts(c, edgeLoadState()) {
		f := docFinding{ID: "certs." + x.Name, Title: "Certificate " + x.Name, Fix: fix}
		left := time.Unix(x.NotAfter, 0).Sub(e.now)
		switch {
		case x.State == "missing" || x.State == "expired":
			f.Sev, f.Detail = "risk", x.State
		case x.Error != "":
			f.Sev, f.Detail = "warn", "renewal failed: "+eventClean(x.Error, 160)
		case x.State != "ok" && x.State != "due":
			f.Sev, f.Detail = "warn", x.State+" (a renewal is pending)"
		case left < 14*24*time.Hour:
			f.Sev, f.Detail = "warn", fmt.Sprintf("expires in %s", fmtSecs(int64(left/time.Second)))
		default:
			f = docOK(f.Title, fmt.Sprintf("valid for %d more days", int(left.Hours()/24)))
			f.ID = "certs." + x.Name
		}
		out = append(out, f)
	}
	return out
}

// ---- background runs → events ----

// doctorEvents turns findings that are new or worse since the last background run into doctor events,
// and findings that went away into "fine again" ones (NoEvent findings are left out). The state is in
// /run: a reboot reports what is still wrong once more.
func doctorEvents(c *Config, r docResult) {
	var prev map[string]string
	now := map[string]string{}
	eventRunUpdate(func(s *eventRun) {
		prev = s.Doctor
		for _, f := range r.Checks {
			if (f.Sev == "warn" || f.Sev == "risk") && !f.NoEvent {
				now[f.ID] = f.Sev
			}
		}
		s.Doctor = now
	})
	kept := false
	for _, f := range r.Checks {
		if now[f.ID] == f.Sev && sevRank[f.Sev] > sevRank[prev[f.ID]] {
			kept = eventAdd(c, "doctor", f.Sev, f.ID, f.Title+": "+f.Detail, false) || kept
		}
	}
	var gone []string
	for id := range prev {
		if _, still := now[id]; !still {
			gone = append(gone, id)
		}
	}
	sort.Strings(gone)
	for _, id := range gone {
		kept = eventAdd(c, "doctor", "info", id, id+" is fine again", false) || kept
	}
	if kept {
		eventKick(c, "doctor")
	}
}

// doctorSummary for `mr status` (overview card): the last result's problems.
func doctorSummary() map[string]any {
	var r docResult
	b, err := os.ReadFile(doctorFile)
	if err != nil || json.Unmarshal(b, &r) != nil || r.Time == 0 {
		return nil
	}
	probs := []map[string]string{}
	for _, f := range r.Checks {
		if (f.Sev == "risk" || f.Sev == "warn") && len(probs) < 8 {
			probs = append(probs, map[string]string{"id": f.ID, "sev": f.Sev, "title": f.Title, "detail": f.Detail})
		}
	}
	return map[string]any{"time": r.Time, "risk": r.Risk, "warn": r.Warn, "ok": r.OK, "problems": probs}
}

// ---- mr doctor, API ----

// doctorCommand: `mr doctor [--json]`.
func doctorCommand(c *Config, args []string) error {
	asJSON := false
	for _, a := range args {
		if a != "--json" {
			return errors.New("usage: mr doctor [--json]")
		}
		asJSON = true
	}
	r := runDoctor(c, newDocEnv())
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", " ")
		return enc.Encode(r)
	}
	fmt.Print(doctorText(r))
	return nil
}

// doctorText: problems first, then the rest, fixes under their findings.
func doctorText(r docResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "mr doctor: %d risk, %d warning(s), %d ok\n", r.Risk, r.Warn, r.OK)
	order := map[string]int{"risk": 0, "warn": 1, "ok": 2, "skip": 3}
	fs := append([]docFinding{}, r.Checks...)
	sort.SliceStable(fs, func(i, j int) bool { return order[fs[i].Sev] < order[fs[j].Sev] })
	for _, f := range fs {
		sev := f.Sev
		if sev == "risk" || sev == "warn" {
			sev = strings.ToUpper(sev)
		}
		fmt.Fprintf(&b, "%-5s %-18s %s: %s\n", sev, f.ID, f.Title, f.Detail)
		if f.Fix != "" && f.Sev != "ok" {
			fmt.Fprintf(&b, "      fix: %s\n", f.Fix)
		}
	}
	return b.String()
}

// apiSysDoctor: GET → runs the checks now (a few seconds) and returns the result.
func apiSysDoctor(r apiReq) apiResp {
	c, err := loadConfig(sysConfigPath, sysSecretsPath)
	if err != nil {
		return apiResp{body: docResult{Time: time.Now().Unix(), Risk: 1, Checks: []docFinding{{ID: "config.load", Check: "config", Sev: "risk",
			Title: "router.yaml", Detail: eventClean(err.Error(), 200), Fix: "mr validate; fix the file or mr rollback"}}}}
	}
	return apiResp{body: runDoctor(c, newDocEnv())}
}
