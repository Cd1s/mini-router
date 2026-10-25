package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestDNSUnblockDefaultOffIsEmpty(t *testing.T) {
	c := testConfig(t)
	c.DNS.Unblock = &DNSUnblock{}
	c.defaults()
	got := renderMap(t, c)
	if got[dnsUnblockConf] != "" {
		t.Fatalf("default-off config rendered dns-unblock config: %q", got[dnsUnblockConf])
	}
	if strings.Contains(got[GenDir+"/services"], "mr-dns-unblock") {
		t.Fatal("default-off config enabled mr-dns-unblock")
	}
	if got := dnsUpstreamLines(c); strings.Contains(strings.Join(got, "\n"), "resolv-lan.conf") {
		t.Fatalf("default-off upstreams unexpectedly use dns-unblock: %v", got)
	}
}

func TestDNSUnblockRenderRulesAndUpstreams(t *testing.T) {
	c := testConfig(t)
	tr, te := true, true
	c.DNS.Unblock = &DNSUnblock{Enabled: true, BlockIPs: []string{"125.26.170.3", "2001:db8::3"}, RetryPrivate: &tr, RetryEmpty: &te, Fallback: "custom", Protocol: "udp", Server: "192.0.2.53#5353"}
	c.DNS.Fallback = []string{"9.9.9.9", "8.8.8.8"}
	c.defaults()
	if errs := c.Validate(); len(errs) > 0 {
		t.Fatal(errs)
	}
	f := renderMap(t, c)
	var got map[string]any
	if err := json.Unmarshal([]byte(f[dnsUnblockConf]), &got); err != nil {
		t.Fatal(err)
	}
	if got["log"].(map[string]any)["level"] != "warn" {
		t.Fatalf("log: %#v", got["log"])
	}
	dns := got["dns"].(map[string]any)
	servers := dns["servers"].([]any)
	if len(servers) != 3 || servers[0].(map[string]any)["tag"] != "isp1" || servers[2].(map[string]any)["tag"] != "trusted" {
		t.Fatalf("servers: %#v", servers)
	}
	rules := dns["rules"].([]any)
	if len(rules) != 9 {
		t.Fatalf("rules length = %d, want 9: %#v", len(rules), rules)
	}
	if rules[0].(map[string]any)["action"] != "evaluate" || rules[0].(map[string]any)["server"] != "isp1" {
		t.Fatalf("first rule: %#v", rules[0])
	}
	if rules[2].(map[string]any)["action"] != "route" || rules[2].(map[string]any)["server"] != "trusted" {
		t.Fatalf("block rule: %#v", rules[1])
	}
	if got["inbounds"].([]any)[0].(map[string]any)["listen_port"] != float64(53) {
		t.Fatalf("inbound: %#v", got["inbounds"])
	}
	lines := dnsUpstreamLines(c)
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "resolv-file="+dnsUnblockRuntimeResolv) {
		t.Fatalf("upstream lines: %v", lines)
	}
	if got := dnsUnblockServices(c); len(got) != 1 || got[0] != "mr-dns-unblock" {
		t.Fatalf("services = %v, want mr-dns-unblock", got)
	}
}

func TestDNSUnblockValidation(t *testing.T) {
	c := testConfig(t)
	c.DNS.Unblock = &DNSUnblock{Enabled: true, BlockIPs: []string{"bad", "1.2.3.4\nserver=x"}, Fallback: "custom", Server: "not-an-ip"}
	c.DNS.Upstream = "dot"
	c.defaults()
	errs := strings.Join(c.Validate(), "\n")
	for _, want := range []string{"dns.unblock: only valid with dns.upstream: isp or manual", "dns.unblock.block_ips: invalid IP", "dns.unblock.server: ip[#port]"} {
		if !strings.Contains(errs, want) {
			t.Errorf("missing %q in:\n%s", want, errs)
		}
	}
}

func TestSingBoxVersion(t *testing.T) {
	for _, tc := range []struct {
		v  string
		ok bool
	}{
		{"sing-box version 1.13.2", false},
		{"sing-box version 1.14.0", true},
		{"sing-box version 1.16.1", true},
		{"unknown", false},
	} {
		if got := singBoxVersionOK(tc.v); got != tc.ok {
			t.Errorf("singBoxVersionOK(%q)=%v, want %v", tc.v, got, tc.ok)
		}
	}
}

func TestDNSUnblockInitialServersManualUsesTwo(t *testing.T) {
	c := testConfig(t)
	c.DNS.Upstream = "manual"
	c.DNS.Servers = []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"}
	c.DNS.Unblock = &DNSUnblock{Enabled: true}
	c.defaults()
	got := dnsUnblockInitialServers(c)
	if strings.Join(got, ",") != "1.1.1.1,2.2.2.2" {
		t.Fatalf("manual servers = %v", got)
	}
}

func TestDNSUnblockRefreshCheckAndNoChange(t *testing.T) {
	c := testConfig(t)
	c.DNS.Unblock = &DNSUnblock{Enabled: true, Fallback: "custom", Protocol: "udp", Server: "9.9.9.9"}
	c.defaults()
	d := t.TempDir()
	oldPath, oldRun, oldResolv := dnsUnblockConfigPath, dnsUnblockRun, dnsUnblockRuntimeResolv
	dnsUnblockConfigPath = filepath.Join(d, "dns-unblock.json")
	dnsUnblockRuntimeResolv = filepath.Join(d, "resolv-lan.conf")
	calls := 0
	dnsUnblockRun = func(name string, args ...string) (string, error) { calls++; return "", nil }
	t.Cleanup(func() { dnsUnblockConfigPath, dnsUnblockRun, dnsUnblockRuntimeResolv = oldPath, oldRun, oldResolv })
	dnsUnblockRefresh(c, []string{"1.1.1.1"})
	if _, err := os.Stat(dnsUnblockConfigPath); err != nil || calls == 0 {
		t.Fatalf("refresh did not write/check config: err=%v calls=%d", err, calls)
	}
	first := calls
	dnsUnblockRefresh(c, []string{"1.1.1.1"})
	if calls != first {
		t.Fatalf("unchanged refresh called commands: %d -> %d", first, calls)
	}
}

func TestDNSUnblockHealthSwitchesAfterTwoProbes(t *testing.T) {
	c := testConfig(t)
	c.DNS.Upstream = "manual"
	c.DNS.Servers = []string{"192.0.2.53", "192.0.2.54"}
	c.DNS.Unblock = &DNSUnblock{Enabled: true}
	c.defaults()
	d := t.TempDir()
	oldResolv, oldState, oldProbe, oldRun := dnsUnblockRuntimeResolv, dnsUnblockHealthState, dnsUnblockProbe, dnsUnblockRun
	dnsUnblockRuntimeResolv = filepath.Join(d, "resolv-lan.conf")
	dnsUnblockHealthState = filepath.Join(d, "health.json")
	good := true
	dnsUnblockProbe = func(*Config) bool { return good }
	dnsUnblockRun = func(string, ...string) (string, error) { return "", nil }
	t.Cleanup(func() {
		dnsUnblockRuntimeResolv, dnsUnblockHealthState, dnsUnblockProbe, dnsUnblockRun = oldResolv, oldState, oldProbe, oldRun
	})

	dnsUnblockHealth(c)
	if _, err := os.Stat(dnsUnblockRuntimeResolv); err == nil {
		t.Fatal("one successful probe switched helper too early")
	}
	dnsUnblockHealth(c)
	if got := readFile(dnsUnblockRuntimeResolv); got != "nameserver 127.0.0.2\n" {
		t.Fatalf("helper upstream = %q", got)
	}
	good = false
	dnsUnblockHealth(c)
	if got := readFile(dnsUnblockRuntimeResolv); got != "nameserver 127.0.0.2\n" {
		t.Fatalf("one failed probe switched away: %q", got)
	}
	dnsUnblockHealth(c)
	if got := readFile(dnsUnblockRuntimeResolv); got != "nameserver 192.0.2.53\nnameserver 192.0.2.54\n" {
		t.Fatalf("direct upstream = %q", got)
	}
}

func TestDNSUnblockRuntimeFileIsNotRendered(t *testing.T) {
	c := testConfig(t)
	c.DNS.Unblock = &DNSUnblock{Enabled: true}
	c.defaults()
	f := renderMap(t, c)
	for path := range f {
		if strings.Contains(path, "resolv-lan.conf") || strings.Contains(path, "dns-unblock-upstream.conf") {
			t.Fatalf("runtime upstream file rendered: %s", path)
		}
	}
}

// unblockHealthLab points the monitor at a temp dir, stubs the probe and records every command the
// monitor would run (rc-service, supervise-daemon).
type unblockHealthLab struct {
	c      *Config
	resolv string
	state  string
	good   bool
	cmds   []string
}

func newUnblockHealthLab(t *testing.T) *unblockHealthLab {
	t.Helper()
	c := testConfig(t)
	c.DNS.Upstream = "manual"
	c.DNS.Servers = []string{"192.0.2.53", "192.0.2.54"}
	c.DNS.Unblock = &DNSUnblock{Enabled: true}
	c.defaults()
	d := t.TempDir()
	l := &unblockHealthLab{c: c, resolv: filepath.Join(d, "resolv-lan.conf"), state: filepath.Join(d, "health.json"), good: true}
	oldResolv, oldState, oldProbe, oldRun := dnsUnblockRuntimeResolv, dnsUnblockHealthState, dnsUnblockProbe, dnsUnblockRun
	dnsUnblockRuntimeResolv, dnsUnblockHealthState = l.resolv, l.state
	dnsUnblockProbe = func(*Config) bool { return l.good }
	dnsUnblockRun = func(name string, args ...string) (string, error) {
		l.cmds = append(l.cmds, name+" "+strings.Join(args, " "))
		return "", nil
	}
	t.Cleanup(func() {
		dnsUnblockRuntimeResolv, dnsUnblockHealthState, dnsUnblockProbe, dnsUnblockRun = oldResolv, oldState, oldProbe, oldRun
	})
	return l
}

const unblockHelperResolv = "nameserver 127.0.0.2\n"

// seed writes the runtime resolver file with an old mtime, so a rewrite (atomic rename) shows.
func (l *unblockHealthLab) seed(t *testing.T, data string) {
	t.Helper()
	if err := os.WriteFile(l.resolv, []byte(data), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(l.resolv, time.Unix(1e9, 0), time.Unix(1e9, 0)); err != nil {
		t.Fatal(err)
	}
}

// untouched fails when the runtime resolver file was rewritten since seed.
func (l *unblockHealthLab) untouched(t *testing.T, want, when string) {
	t.Helper()
	fi, err := os.Stat(l.resolv)
	if err != nil {
		t.Fatalf("%s: %v", when, err)
	}
	if fi.ModTime().Unix() != 1e9 || readFile(l.resolv) != want {
		t.Fatalf("%s: resolv-lan.conf was rewritten (mtime %v, content %q)", when, fi.ModTime(), readFile(l.resolv))
	}
}

func (l *unblockHealthLab) hups() int {
	n := 0
	for _, c := range l.cmds {
		if strings.HasSuffix(c, " reload") {
			n++
		}
	}
	return n
}

func (l *unblockHealthLab) stateMode(t *testing.T) string {
	t.Helper()
	var st struct{ Mode string }
	if err := json.Unmarshal([]byte(readFile(l.state)), &st); err != nil {
		t.Fatalf("health state: %v", err)
	}
	return st.Mode
}

// R3-1: after a boot the init script has seeded the helper, and there is no state file yet. The first
// successful probe must not flip dnsmasq to the ISP resolvers for the five seconds until the second one.
func TestDNSUnblockHealthHelperFileWithoutStateStaysHelper(t *testing.T) {
	l := newUnblockHealthLab(t)
	l.seed(t, unblockHelperResolv)
	dnsUnblockHealth(l.c)
	l.untouched(t, unblockHelperResolv, "first probe, file already helper, no state")
	if m := l.stateMode(t); m != "helper" {
		t.Fatalf("state mode = %q, want helper", m)
	}
	dnsUnblockHealth(l.c)
	l.untouched(t, unblockHelperResolv, "second probe")
}

// R3-1, the other sequence: the state says direct (helper was down), then the init script restarts the
// helper and seeds the helper form again. The file is the truth; two failed probes still switch away.
func TestDNSUnblockHealthHelperRestartedWhileStateSaysDirect(t *testing.T) {
	l := newUnblockHealthLab(t)
	if err := os.WriteFile(l.state, []byte(`{"mode":"direct","since":1,"good":0,"bad":7}`+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	l.seed(t, unblockHelperResolv)
	dnsUnblockHealth(l.c)
	l.untouched(t, unblockHelperResolv, "first probe after the helper was restarted")
	l.good = false // still starting: one failure is not enough
	dnsUnblockHealth(l.c)
	l.untouched(t, unblockHelperResolv, "one failed probe")
	dnsUnblockHealth(l.c)
	if got := readFile(l.resolv); got != "nameserver 192.0.2.53\nnameserver 192.0.2.54\n" {
		t.Fatalf("two failed probes: resolv = %q", got)
	}
}

// R3-2: dnsmasq caches what the ISP answered while it forwarded directly (min-cache-ttl); going back to the
// helper must clear that cache (SIGHUP, not a restart), going to the ISP must not.
func TestDNSUnblockHealthSignalsDnsmasqOnlyWhenSwitchingToHelper(t *testing.T) {
	l := newUnblockHealthLab(t)
	hup := []string{"rc-service dnsmasq reload", "rc-service mr-proxy-dns reload"}
	dnsUnblockHealth(l.c) // good #1: still direct
	if len(l.cmds) != 0 {
		t.Fatalf("commands before the switch: %v", l.cmds)
	}
	dnsUnblockHealth(l.c) // good #2: helper
	if got := strings.Join(l.cmds, "|"); got != strings.Join(hup, "|") {
		t.Fatalf("switch to helper ran %q, want %q", got, hup)
	}
	l.cmds = nil
	l.good = false
	dnsUnblockHealth(l.c)
	dnsUnblockHealth(l.c) // bad #2: direct
	if got := readFile(l.resolv); got != "nameserver 192.0.2.53\nnameserver 192.0.2.54\n" {
		t.Fatalf("direct upstream = %q", got)
	}
	if len(l.cmds) != 0 {
		t.Fatalf("switching to direct ran %v (the ISP answers must not be flushed)", l.cmds)
	}
	l.good = true
	dnsUnblockHealth(l.c)
	dnsUnblockHealth(l.c) // back to helper
	if l.hups() != 2 {
		t.Fatalf("switch back ran %v, want one HUP per dnsmasq", l.cmds)
	}
	for _, c := range l.cmds {
		if strings.Contains(c, "restart") {
			t.Fatalf("dnsmasq must not be restarted: %v", l.cmds)
		}
	}
}

// R3-2 at boot: the helper was seeded by the init script after dnsmasq may already have forwarded to the
// ISP, so the first run that finds the helper in the file clears the cache once; later runs do not.
func TestDNSUnblockHealthAdoptingHelperFlushesOnce(t *testing.T) {
	l := newUnblockHealthLab(t)
	l.seed(t, unblockHelperResolv)
	dnsUnblockHealth(l.c)
	if l.hups() != 2 {
		t.Fatalf("first run with the helper in the file ran %v", l.cmds)
	}
	l.cmds = nil
	dnsUnblockHealth(l.c)
	dnsUnblockHealth(l.c)
	if len(l.cmds) != 0 {
		t.Fatalf("steady helper ran %v", l.cmds)
	}
}

// R3-3: only a router with dns.unblock gets the five-second probe loop in mr-mon; every other
// router's conf.d/mr-mon is exactly what main renders, so mon-collect behaves as before for it.
func TestDNSUnblockMonSamplerFlagOnlyWhenEnabled(t *testing.T) {
	confD := func(c *Config) string {
		t.Helper()
		files, err := Render(c)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			if f.Path == monConfD {
				return f.Data
			}
		}
		t.Fatal("conf.d/mr-mon not rendered")
		return ""
	}
	const mainConf = "# generated by mr (mon) — physical WAN devices whose counters the history sampler sums\nMON_WAN=\"wan\"\n"
	c := testConfig(t)
	if got := confD(c); got != mainConf {
		t.Fatalf("no dns.unblock: conf.d/mr-mon = %q, want main's %q", got, mainConf)
	}
	c.DNS.Unblock = &DNSUnblock{Enabled: false}
	c.defaults()
	if got := confD(c); got != mainConf {
		t.Fatalf("dns.unblock disabled: conf.d/mr-mon = %q, want main's %q", got, mainConf)
	}
	c.DNS.Unblock.Enabled = true
	if got := confD(c); !strings.Contains(got, "\nMON_DNS_UNBLOCK=1\n") || !strings.Contains(got, "\nMON_WAN=\"wan\"\n") {
		t.Fatalf("dns.unblock enabled: conf.d/mr-mon = %q", got)
	}
	if serviceFor(monConfD) != "mr-mon" {
		t.Fatal("a change of conf.d/mr-mon must restart mr-mon (that is how the loop starts and stops)")
	}
}

// R3-3: switching the feature off removes the helper config and the runtime files, so nothing that
// looks at them (mr-mon's gate, mr dns unblock-health, doctor) sees a feature that is not there.
func TestDNSUnblockOrphans(t *testing.T) {
	d := t.TempDir()
	oldConf, oldResolv, oldState, oldRunConf := dnsUnblockConfigPath, dnsUnblockRuntimeResolv, dnsUnblockHealthState, dnsUnblockRunConf
	dnsUnblockConfigPath = filepath.Join(d, "dns-unblock.json")
	dnsUnblockRuntimeResolv = filepath.Join(d, "resolv-lan.conf")
	dnsUnblockHealthState = filepath.Join(d, "dns-unblock-health")
	dnsUnblockRunConf = filepath.Join(d, "run-config.json")
	t.Cleanup(func() {
		dnsUnblockConfigPath, dnsUnblockRuntimeResolv, dnsUnblockHealthState, dnsUnblockRunConf = oldConf, oldResolv, oldState, oldRunConf
	})
	all := []string{dnsUnblockConfigPath, dnsUnblockRuntimeResolv, dnsUnblockHealthState, dnsUnblockRunConf}
	c := testConfig(t)

	// nothing to remove: an empty list keeps a plan of a router without the feature empty
	if got := dnsUnblockOrphans(c); len(got) != 0 {
		t.Fatalf("no files, no feature: orphans = %v", got)
	}
	for _, p := range all {
		if err := os.WriteFile(p, []byte("x\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	for name, u := range map[string]*DNSUnblock{"absent": nil, "disabled": {Enabled: false}} {
		c.DNS.Unblock = u
		if got := dnsUnblockOrphans(c); strings.Join(got, ",") != strings.Join(all, ",") {
			t.Fatalf("%s: orphans = %v, want %v", name, got, all)
		}
	}
	c.DNS.Unblock = &DNSUnblock{Enabled: true}
	c.defaults()
	if got := dnsUnblockOrphans(c); len(got) != 0 {
		t.Fatalf("enabled: orphans = %v", got)
	}
	// the module hands them to the core's transactional cleanup
	c.DNS.Unblock = nil
	found := map[string]bool{}
	for _, p := range moduleOrphanPaths(c) {
		found[p] = true
	}
	for _, p := range all {
		if !found[p] {
			t.Fatalf("moduleOrphanPaths misses %s", p)
		}
	}
}

// R3-5: the helper always listens on 127.0.0.2:53 (the service, the probe and dnsmasq's resolver file all
// assume it), so there is no key to set it: a config that carries one is refused like any unknown key.
func TestDNSUnblockHasNoPortKey(t *testing.T) {
	decode := func(doc string) error {
		var v struct {
			Unblock DNSUnblock `yaml:"unblock"`
		}
		dec := yaml.NewDecoder(strings.NewReader(doc))
		dec.KnownFields(true)
		return dec.Decode(&v)
	}
	if err := decode("unblock: {enabled: true, fallback: google}\n"); err != nil {
		t.Fatalf("a valid block was refused: %v", err)
	}
	if err := decode("unblock: {enabled: true, port: 53}\n"); err == nil || !strings.Contains(err.Error(), "port") {
		t.Fatalf("dns.unblock.port accepted: %v", err)
	}
	c := testConfig(t)
	c.DNS.Unblock = &DNSUnblock{Enabled: true}
	c.defaults()
	b, err := yaml.Marshal(c.DNS.Unblock)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "port") {
		t.Fatalf("defaults carry a port: %s", b)
	}
}
