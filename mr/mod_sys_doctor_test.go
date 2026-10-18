package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeDocEnv: a healthy router — both WANs up with public addresses, routes, DNS, IPv6 prefix,
// hardware offload, every service running, NTP synced, room everywhere, no crash.
func fakeDocEnv() *docEnv {
	now := time.Unix(1_800_000_000, 0)
	files := map[string]string{
		"/proc/meminfo": "MemTotal:  494324 kB\nMemFree: 1000 kB\nMemAvailable:  250000 kB\n",
		"/proc/sys/net/netfilter/nf_conntrack_count": "757\n", "/proc/sys/net/netfilter/nf_conntrack_max": "100000\n",
		"/sys/class/thermal/thermal_zone0/temp": "52000\n",
	}
	return &docEnv{
		now: now, uptime: 5000,
		read:   func(p string) string { return files[p] },
		exists: func(p string) bool { return p == "/proc/net/pppoe" },
		mtime: func(p string) (time.Time, bool) {
			return now.Add(-30 * 24 * time.Hour), p == "/etc/mini-router-release"
		},
		addrs4: func(dev string) []string {
			return map[string][]string{"pppoe-wan": {"192.0.2.10/32"}, "pppoe-wan2": {"198.51.100.20/32"}}[dev]
		},
		health:    func(*Config) map[string]string { return map[string]string{} },
		routes:    func(...string) []map[string]any { return []map[string]any{{"dst": "default"}} },
		global6:   func(string) []net.IP { return []net.IP{net.ParseIP("2001:db8:1::1")} },
		resolve:   func(string) error { return nil },
		flowtable: func() (string, error) { return "table inet mr {\n\tflowtable ft {\n\t\tflags offload\n\t}\n}\n", nil },
		hwFlows:   func() int { return 26 },
		running: func(names []string) map[string]bool {
			m := map[string]bool{}
			for _, n := range names {
				m[n] = true
			}
			return m
		},
		df: func(p string) (int64, int64) {
			return map[string][2]int64{"/etc/mini-router": {100000, 60000}, "/tmp": {200000, 190000}}[p][0],
				map[string][2]int64{"/etc/mini-router": {100000, 60000}, "/tmp": {200000, 190000}}[p][1]
		},
		ntp:       func() (bool, bool, time.Duration) { return true, true, 5 * time.Minute },
		pending:   func() (*pendingApply, error) { return nil, fs.ErrNotExist },
		validate:  func(*Config) []string { return nil },
		unapplied: func(*Config) ([]string, bool) { return nil, true },
		klog: func() (string, error) {
			return "<6>[    1.2] mtk-wdt 1001c000.watchdog: Watchdog enabled (timeout=31 sec)\n", nil
		},
		pstore: func() ([]string, string) { return nil, "" },
		wifi:   func(*Config) []string { return nil },
	}
}

// findings: id → "sev" for everything that is not ok / skip.
func docProblems(r docResult) string {
	var s []string
	for _, f := range r.Checks {
		if f.Sev == "warn" || f.Sev == "risk" {
			s = append(s, f.ID+"="+f.Sev)
		}
	}
	return strings.Join(s, " ")
}

func docFind(r docResult, id string) docFinding {
	for _, f := range r.Checks {
		if f.ID == id {
			return f
		}
	}
	return docFinding{}
}

func TestDoctorHealthy(t *testing.T) {
	eventEnv(t)
	c := testConfig(t)
	c.Services.Edge = Edge{} // no certificates to check
	r := runDoctor(c, fakeDocEnv())
	if r.Risk != 0 || r.Warn != 0 || docProblems(r) != "" {
		t.Fatalf("healthy router: %d risk, %d warn: %s", r.Risk, r.Warn, docProblems(r))
	}
	seen := map[string]bool{}
	for _, f := range r.Checks {
		seen[f.Check] = true
		if f.Title == "" || f.Detail == "" || (f.Sev != "ok" && f.Sev != "skip") {
			t.Errorf("finding %+v", f)
		}
	}
	for _, ck := range doctorChecks {
		if !seen[ck.name] {
			t.Errorf("check %s produced nothing", ck.name)
		}
	}
	if f := docFind(r, "offload"); f.Detail != "hardware offload on, 26 connections in the PPE now" {
		t.Errorf("offload: %+v", f)
	}
	// saved for the overview: no problems
	if s := doctorSummary(); s == nil || s["risk"] != 0 || len(s["problems"].([]map[string]string)) != 0 {
		t.Errorf("summary: %v", s)
	}
}

func TestDoctorWarnsExtraRANetworkWithoutGlobalPrefix(t *testing.T) {
	eventEnv(t)
	c := testConfig(t)
	c.Networks = []Network{{Name: "iot", IPv4: "192.168.30.1/24", IPv6RA: true}}
	e := fakeDocEnv()
	e.global6 = func(dev string) []net.IP {
		if dev == "br-iot" {
			return nil
		}
		return []net.IP{net.ParseIP("2001:db8:1::1")}
	}
	r := runDoctor(c, e)
	if f := docFind(r, "ipv6.iot"); f.Sev != "warn" || !strings.Contains(f.Detail, "br-iot") {
		t.Fatalf("extra RA network was not diagnosed: %+v", f)
	}
}

// Every check's bad paths, with the severity each deserves.
func TestDoctorFindings(t *testing.T) {
	eventEnv(t)
	c := testConfig(t)
	c.Services.Edge = Edge{} // no certificates to check
	run := func(f func(e *docEnv)) docResult {
		e := fakeDocEnv()
		f(e)
		return runDoctor(c, e)
	}
	t2, _ := c.WANTable("wan2")
	cases := []struct {
		name string
		f    func(e *docEnv)
		want string
	}{
		{"one WAN down", func(e *docEnv) {
			e.addrs4 = func(dev string) []string { return map[string][]string{"pppoe-wan2": {"198.51.100.20/32"}}[dev] }
		}, "wan.wan=warn"},
		{"no internet", func(e *docEnv) { e.addrs4 = func(string) []string { return nil } }, "wan.wan=risk wan.wan2=risk"},
		{"health", func(e *docEnv) {
			e.health = func(*Config) map[string]string { return map[string]string{"wan2": "down"} }
		}, "wan.wan2=warn"},
		{"WAN inside the LAN's subnet (travel)", func(e *docEnv) {
			e.addrs4 = func(dev string) []string {
				return map[string][]string{"pppoe-wan": {"192.168.1.77/24"}, "pppoe-wan2": {"198.51.100.20/32"}}[dev]
			}
		}, "wan.wan=risk"},
		{"CGNAT behind port forwards", func(e *docEnv) {
			e.addrs4 = func(dev string) []string { return []string{"100.64.3.4/32"} }
		}, "wan.wan=warn wan.wan2=warn"},
		{"routes", func(e *docEnv) {
			e.routes = func(args ...string) []map[string]any {
				if len(args) > 1 && args[2] == fmt.Sprint(t2) {
					return nil
				}
				if len(args) == 1 {
					return nil
				}
				return []map[string]any{{"dst": "default"}}
			}
		}, "routes.main=risk routes.wan2=warn"},
		{"dns", func(e *docEnv) { e.resolve = func(string) error { return errors.New("i/o timeout") } }, "dns=risk"},
		{"ipv6", func(e *docEnv) { e.global6 = func(string) []net.IP { return nil } }, "ipv6=warn"},
		{"no flowtable", func(e *docEnv) {
			e.flowtable = func() (string, error) { return "", errors.New("No such file or directory") }
		}, "offload=risk"},
		{"software only", func(e *docEnv) { e.flowtable = func() (string, error) { return "flowtable ft {}", nil } }, "offload=warn"},
		{"services", func(e *docEnv) {
			e.running = func(names []string) map[string]bool { m := fakeDocEnv().running(names); m["dnsmasq"] = false; return m }
		}, "services.dnsmasq=risk"},
		{"wifi", func(e *docEnv) { e.wifi = func(*Config) []string { return []string{"phy1: state DISABLED"} } }, "wifi.phy1=risk"},
		{"clock never set", func(e *docEnv) {
			e.mtime = func(string) (time.Time, bool) { return e.now.Add(48 * time.Hour), true }
		}, "clock=risk"},
		{"ntp lost", func(e *docEnv) { e.ntp = func() (bool, bool, time.Duration) { return false, true, 2 * time.Hour } }, "clock=warn"},
		{"storage", func(e *docEnv) {
			e.df = func(p string) (int64, int64) {
				if p == "/tmp" {
					return 200000, 10000
				}
				return 100000, 1000
			}
		}, "storage.config=risk storage.tmp=warn"},
		{"memory", func(e *docEnv) {
			e.read = func(p string) string {
				if p == "/proc/meminfo" {
					return "MemTotal: 494324 kB\nMemAvailable: 30000 kB\n"
				}
				return fakeDocEnv().read(p)
			}
		}, "memory=risk"},
		{"conntrack", func(e *docEnv) {
			e.read = func(p string) string {
				if p == "/proc/sys/net/netfilter/nf_conntrack_count" {
					return "80000"
				}
				return fakeDocEnv().read(p)
			}
		}, "conntrack=warn"},
		{"temperature", func(e *docEnv) {
			e.read = func(p string) string {
				if p == "/sys/class/thermal/thermal_zone0/temp" {
					return "106000"
				}
				return fakeDocEnv().read(p)
			}
		}, "temp=risk"},
		{"crash", func(e *docEnv) {
			e.pstore = func() ([]string, string) { return []string{"dmesg-ramoops-0@1"}, "Kernel panic - not syncing" }
			e.klog = func() (string, error) { return "<4>[ 55.1] Out of memory: Killed process 9 (x)\n", nil }
		}, "crash.pstore=warn crash.klog=warn"},
		{"config", func(e *docEnv) {
			e.validate = func(*Config) []string { return []string{"guard.never_expose: ssh is forwarded", "wan[0].mtu: bad"} }
			e.unapplied = func(*Config) ([]string, bool) { return []string{"~ lan.ipv6_ra: true → false"}, true }
		}, "config.guard=risk config.valid=risk config.unapplied=warn"},
		{"pending", func(e *docEnv) {
			e.pending = func() (*pendingApply, error) { return &pendingApply{State: statePending, Via: "web UI\x1b[2J"}, nil }
			e.exists = func(p string) bool { return p == ConfirmFile+".failed" }
		}, "pending=warn pending.boot=warn"},
	}
	for _, tc := range cases {
		if got := docProblems(run(tc.f)); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
	// fixes are there for problems; the detail of an untrusted string is cleaned
	r := run(cases[len(cases)-1].f)
	if f := docFind(r, "pending"); !strings.Contains(f.Detail, "(web UI [2J)") || f.Fix == "" || !f.NoEvent {
		t.Errorf("pending: %+v", f)
	}
	// choices, not faults: off / password logins are warnings the background run does not report
	c.Firewall.Offload = "off"
	c.Services.SSH.PasswordLogin = true
	r = run(func(*docEnv) {})
	if docProblems(r) != "offload=warn ssh=warn" || !docFind(r, "offload").NoEvent || !docFind(r, "ssh").NoEvent {
		t.Errorf("choices: %s", docProblems(r))
	}
	c.Firewall.Offload, c.Services.SSH.PasswordLogin = "hardware", false
	// unknown NTP state (an image without the marker directory), early after boot
	r = run(func(e *docEnv) { e.ntp = func() (bool, bool, time.Duration) { return false, false, 0 } })
	if f := docFind(r, "clock"); f.Sev != "skip" || !strings.Contains(f.Detail, "mr-clock of an older image") {
		t.Errorf("clock unknown: %+v", f)
	}
	r = run(func(e *docEnv) { e.uptime = 100; e.ntp = func() (bool, bool, time.Duration) { return false, true, 0 } })
	if f := docFind(r, "clock"); f.Sev != "ok" {
		t.Errorf("clock right after boot: %+v", f)
	}
	txt := doctorText(run(cases[1].f))
	if !strings.HasPrefix(txt, "mr doctor: 2 risk, 0 warning(s), ") || !strings.Contains(txt, "\nRISK  wan.wan ") || !strings.Contains(txt, "      fix: mr wan status; rc-service mr-pppoe.wan restart") {
		t.Errorf("text:\n%s", txt)
	}
	if !strings.HasPrefix(strings.Split(txt, "\n")[1], "RISK") {
		t.Errorf("problems not first:\n%s", txt)
	}
}

func TestDoctorRequiresPublicIPGiveUpIsRisk(t *testing.T) {
	tempState(t)
	c := testConfig(t)
	c.WAN[0].RequirePublicIP = true
	e := fakeDocEnv()
	e.addrs4 = func(dev string) []string {
		if dev == c.WAN[0].Ifname() {
			return []string{"100.64.3.4/32"}
		}
		return []string{"198.51.100.20/32"}
	}
	e.health = func(*Config) map[string]string { return map[string]string{"wan": "down"} }
	if err := os.MkdirAll(filepath.Dir(requirePublicFile), 0700); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(map[string]requirePublicRecord{"wan": {Attempts: requirePublicMax, Risk: true}})
	if err := os.WriteFile(requirePublicFile, b, 0600); err != nil {
		t.Fatal(err)
	}
	f := docFind(runDoctor(c, e), "wan.wan")
	if f.Sev != "risk" || !strings.Contains(f.Detail, "stopped") {
		t.Fatalf("give-up state: %+v", f)
	}
}

func TestDoctorHintsDHCPLineAfterPPPoEOutage(t *testing.T) {
	c := testConfig(t)
	e := fakeDocEnv()
	e.now = time.Unix(1_800_000_600, 0)
	e.addrs4 = func(dev string) []string {
		if dev == c.WAN[1].Ifname() {
			return []string{"198.51.100.20/32"}
		}
		return nil
	}
	e.dhcpOffer = func(port string) bool { return port == c.WAN[0].LinkDev() }
	d := t.TempDir() + "/doctor-dhcp.json"
	old := doctorDHCPStateFile
	doctorDHCPStateFile = d
	t.Cleanup(func() { doctorDHCPStateFile = old })
	b, _ := json.Marshal(map[string]doctorDHCPRecord{"wan": {FirstSeen: e.now.Add(-3 * time.Minute).Unix()}})
	if err := os.WriteFile(d, b, 0600); err != nil {
		t.Fatal(err)
	}
	f := docFind(runDoctor(c, e), "wan.wan")
	if !strings.Contains(f.Detail, "switched to DHCP") || !strings.Contains(f.Fix, "detect") {
		t.Fatalf("DHCP switch hint: %+v", f)
	}
}

func TestDoctorDHCPProbeIsThrottledAndClearedWhenUp(t *testing.T) {
	c := testConfig(t)
	e := fakeDocEnv()
	e.now = time.Unix(1_800_000_600, 0)
	e.dhcpOffer = func(string) bool { return true }
	d := t.TempDir() + "/doctor-dhcp.json"
	old := doctorDHCPStateFile
	doctorDHCPStateFile = d
	t.Cleanup(func() { doctorDHCPStateFile = old })
	b, _ := json.Marshal(map[string]doctorDHCPRecord{"wan": {FirstSeen: e.now.Add(-3 * time.Minute).Unix()}})
	if err := os.WriteFile(d, b, 0600); err != nil {
		t.Fatal(err)
	}
	calls := 0
	e.dhcpOffer = func(string) bool { calls++; return true }
	w := c.WAN[0]
	if !docDHCPHint(w, e, e.now.Unix(), false) || calls != 1 {
		t.Fatalf("first probe: hint/calls=%v/%d", true, calls)
	}
	if !docDHCPHint(w, e, e.now.Add(5*time.Minute).Unix(), false) || calls != 1 {
		t.Fatalf("cooldown ignored: calls=%d", calls)
	}
	docDHCPHint(w, e, e.now.Add(5*time.Minute).Unix(), true)
	if _, err := os.Stat(d); !os.IsNotExist(err) {
		t.Fatalf("up WAN did not clear DHCP state: %v", err)
	}
}

func TestDoctorDHCPNegativeProbeIsThrottled(t *testing.T) {
	c := testConfig(t)
	e := fakeDocEnv()
	e.now = time.Unix(1_800_000_600, 0)
	d := t.TempDir() + "/doctor-dhcp.json"
	old := doctorDHCPStateFile
	doctorDHCPStateFile = d
	t.Cleanup(func() { doctorDHCPStateFile = old })
	b, _ := json.Marshal(map[string]doctorDHCPRecord{"wan": {FirstSeen: e.now.Add(-3 * time.Minute).Unix()}})
	if err := os.WriteFile(d, b, 0600); err != nil {
		t.Fatal(err)
	}
	calls := 0
	e.dhcpOffer = func(string) bool { calls++; return false }
	w := c.WAN[0]
	for i := 0; i < 3; i++ {
		if docDHCPHint(w, e, e.now.Add(time.Duration(i)*time.Minute).Unix(), false) {
			t.Fatal("negative DHCP probe reported an offer")
		}
	}
	if calls != 1 {
		t.Fatalf("negative result was probed %d times, want 1", calls)
	}
}

func TestDoctorIgnoresStalePublicRiskWhenGuardDisabled(t *testing.T) {
	tempState(t)
	c := testConfig(t)
	c.WAN[0].RequirePublicIP = false
	e := fakeDocEnv()
	e.addrs4 = func(dev string) []string {
		if dev == c.WAN[0].Ifname() {
			return []string{"100.64.3.4/32"}
		}
		return []string{"198.51.100.20/32"}
	}
	e.health = func(*Config) map[string]string { return map[string]string{"wan": "down"} }
	b, _ := json.Marshal(map[string]requirePublicRecord{"wan": {Attempts: requirePublicMax, Risk: true}})
	if err := os.WriteFile(requirePublicFile, b, 0600); err != nil {
		t.Fatal(err)
	}
	f := docFind(runDoctor(c, e), "wan.wan")
	if f.Sev == "risk" || strings.Contains(f.Detail, "automatic public-IP redial stopped") {
		t.Fatalf("disabled guard kept stale risk: %+v", f)
	}
}

// The background run: a finding that is new or worse becomes an event, a repeat does not, a finding
// that went away is "fine again"; NoEvent findings never become events.
func TestDoctorEvents(t *testing.T) {
	_, now, _, kicks := eventEnv(t)
	c := testConfig(t)
	c.Services.Edge = Edge{} // no certificates to check
	c.Notify.Channels = []NotifyChannel{{Name: "tg", Type: "telegram", Token: "x", ChatID: "1"}}
	c.Notify.Events = notifyDefaultEvents()
	e := fakeDocEnv()
	e.read = func(p string) string {
		if p == "/sys/class/thermal/thermal_zone0/temp" {
			return "92000"
		}
		return fakeDocEnv().read(p)
	}
	e.unapplied = func(*Config) ([]string, bool) { return []string{"~ x"}, true }
	doctorEvents(c, runDoctor(c, e))
	doctorEvents(c, runDoctor(c, e))
	ev := eventsRead(0, 0)
	if len(ev) != 1 || ev[0].Type != "doctor" || ev[0].Key != "temp" || ev[0].Sev != "warn" || ev[0].Msg != "Temperature: SoC 92.0 °C" {
		t.Fatalf("first runs: %+v", ev)
	}
	if *kicks != 1 {
		t.Errorf("kicks %d", *kicks)
	}
	*now = now.Add(30 * time.Minute)
	e.read = func(p string) string {
		if p == "/sys/class/thermal/thermal_zone0/temp" {
			return "107000"
		}
		return fakeDocEnv().read(p)
	}
	doctorEvents(c, runDoctor(c, e))
	e.read = fakeDocEnv().read
	doctorEvents(c, runDoctor(c, e))
	var got []string
	for _, x := range eventsRead(1, 0) {
		got = append(got, x.Sev+" "+x.Msg)
	}
	if strings.Join(got, "|") != "risk Temperature: SoC 107.0 °C|info temp is fine again" {
		t.Errorf("worse / fine again: %q", got)
	}
}

func TestDoctorCommandAndAPI(t *testing.T) {
	d, _, _, _ := eventEnv(t)
	old := newDocEnv
	newDocEnv = fakeDocEnv
	t.Cleanup(func() { newDocEnv = old })
	c := testConfig(t)
	c.Services.Edge = Edge{} // no certificates to check
	if doctorCommand(c, []string{"--fix"}) == nil {
		t.Error("mr doctor --fix accepted")
	}
	// the API loads the live config: a broken one is itself the finding
	oc, os_ := sysConfigPath, sysSecretsPath
	t.Cleanup(func() { sysConfigPath, sysSecretsPath = oc, os_ })
	sysConfigPath = d + "/router.yaml"
	os.WriteFile(sysConfigPath, []byte("lan: [\n"), 0644)
	b, _ := json.Marshal(apiSysDoctor(apiReq{method: "GET"}).body)
	if !strings.Contains(string(b), `"id":"config.load"`) || !strings.Contains(string(b), `"risk":1`) {
		t.Errorf("broken config: %s", b)
	}
	y, _ := os.ReadFile("../examples/router.yaml")
	os.WriteFile(sysConfigPath, y, 0644)
	sysSecretsPath = "testdata/secrets.yaml"
	var r docResult
	b, _ = json.Marshal(apiSysDoctor(apiReq{method: "GET"}).body)
	json.Unmarshal(b, &r)
	if len(r.Checks) < len(doctorChecks) {
		t.Errorf("sys.doctor: %s", b)
	}
	sec, _ := os.ReadFile("testdata/secrets.yaml")
	for _, l := range strings.Split(string(sec), "\n") {
		if _, v, ok := strings.Cut(l, ": "); ok && len(strings.Trim(v, `"`)) >= 6 && strings.Contains(string(b), strings.Trim(v, `"`)) {
			t.Errorf("a secret value is in the doctor's answer")
		}
	}
}

// A PPPoE WAN without the kernel's PPPoE (Alpine's linux-virt) names that cause, not the cable.
func TestDoctorPPPoEWithoutKernelSupport(t *testing.T) {
	eventEnv(t)
	c := testConfig(t)
	c.Services.Edge = Edge{}
	e := fakeDocEnv()
	e.addrs4 = func(string) []string { return nil }
	e.read = func(p string) string { return map[string]string{"/proc/sys/kernel/osrelease": "6.18.35-0-virt\n"}[p] }
	e.exists = func(string) bool { return false }
	f := docFind(runDoctor(c, e), "wan.wan")
	if f.Sev != "risk" || !strings.Contains(f.Detail, "6.18.35-0-virt has no PPPoE") || !strings.Contains(f.Fix, "linux-lts") {
		t.Fatalf("no /proc/net/pppoe: %+v", f)
	}
	e.exists = func(p string) bool { return p == "/proc/net/pppoe" }
	if f := docFind(runDoctor(c, e), "wan.wan"); strings.Contains(f.Detail, "PPPoE") || !strings.Contains(f.Fix, "cable") {
		t.Fatalf("the module is loaded: the usual hint: %+v", f)
	}
}
