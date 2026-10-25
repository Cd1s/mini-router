package main

import (
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestProxyNat46DefaultsOffDoesNotRenderOrEnable(t *testing.T) {
	c := testConfig(t)
	files := renderMap(t, c)
	if _, ok := files[proxyNat46Gen]; ok {
		t.Fatal("nat46 generated while disabled")
	}
	if strings.Contains(files[GenDir+"/services"], "mr-nat46") {
		t.Fatal("mr-nat46 enabled while disabled")
	}
}

func TestProxyNat46RenderAndValidation(t *testing.T) {
	c := proxyTestConfig(t)
	c.Proxy.Nat46.Enabled = true
	if errs := c.Validate(); len(errs) != 0 {
		t.Fatalf("valid nat46 config rejected: %v", errs)
	}
	files := renderMap(t, c)
	if got := files[proxyNat46Gen]; !strings.Contains(got, `"listen":"127.0.0.1:1094"`) || !strings.Contains(got, `"prefix":"64:ff9b::/96"`) {
		t.Fatalf("nat46 config missing defaults: %s", got)
	}
	if !strings.Contains(files[GenDir+"/services"], "mr-nat46") {
		t.Fatal("mr-nat46 missing from enabled services")
	}

	c.Proxy.Nat46.Listen = "0.0.0.0:1094"
	c.Proxy.Nat46.Prefix = "64:ff9b::/64"
	errs := strings.Join(c.Validate(), "\n")
	if !strings.Contains(errs, "proxy.nat46.listen") || !strings.Contains(errs, "proxy.nat46.prefix") {
		t.Fatalf("bad nat46 values were accepted: %s", errs)
	}
}

func TestProxyNat46DisabledPreservesEnabledProxyRender(t *testing.T) {
	mainConfig := proxyTestConfig(t)
	mainRender := renderMap(t, mainConfig)
	withDefaults := proxyTestConfig(t)
	proxyNat46Defaults(withDefaults)
	defaultRender := renderMap(t, withDefaults)
	if !reflect.DeepEqual(mainRender, defaultRender) {
		t.Fatalf("nat46 defaults changed an existing proxy render")
	}
	if _, ok := defaultRender[proxyNat46Gen]; ok {
		t.Fatal("nat46 file rendered while disabled")
	}
	if _, ok := defaultRender[proxyNat46DNS64Gen]; ok {
		t.Fatal("dns64 file rendered while disabled")
	}
	if strings.Contains(defaultRender[GenDir+"/services"], "mr-nat46") || strings.Contains(defaultRender[GenDir+"/services"], "mr-dns64") {
		t.Fatal("nat46 service enabled while disabled")
	}
}

func TestProxyNat46PortsAndRestartAreValidated(t *testing.T) {
	c := proxyTestConfig(t)
	c.Proxy.Nat46.Enabled = true
	c.Proxy.Nat46.Listen = "127.0.0.1:7893"
	c.Proxy.Nat46.DNS64.Enabled = true
	c.Proxy.Nat46.DNS64.Listen = "[::1]:1153"
	old := unboundBinaryExists
	unboundBinaryExists = func() bool { return true }
	defer func() { unboundBinaryExists = old }()
	errs := strings.Join(c.Validate(), "\n")
	for _, want := range []string{"proxy.nat46.listen: port", "proxy.nat46.dns64.listen: loopback"} {
		if !strings.Contains(errs, want) {
			t.Errorf("missing validation %q in %s", want, errs)
		}
	}
	if got := serviceFor(proxyNat46Gen); got != "mr-nat46" {
		t.Fatalf("nat46 restart mapping: %q", got)
	}
	if got := serviceFor(proxyNat46DNS64Gen); got != "mr-dns64" {
		t.Fatalf("dns64 restart mapping: %q", got)
	}
}

func TestProxyNat46DisablePlansAllOwnedFilesForRemoval(t *testing.T) {
	dir := t.TempDir()
	oldNat, oldDNS, oldRun := proxyNat46Gen, proxyNat46DNS64Gen, proxyNat46DNS64Run
	proxyNat46Gen, proxyNat46DNS64Gen, proxyNat46DNS64Run = filepath.Join(dir, "nat46.json"), filepath.Join(dir, "dns64.conf"), filepath.Join(dir, "runtime.conf")
	defer func() { proxyNat46Gen, proxyNat46DNS64Gen, proxyNat46DNS64Run = oldNat, oldDNS, oldRun }()
	for _, path := range []string{proxyNat46Gen, proxyNat46DNS64Gen, proxyNat46DNS64Run} {
		if err := os.WriteFile(path, []byte("generated"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	c := proxyTestConfig(t)
	c.Proxy.Nat46.Enabled = false
	got := proxyNat46Orphans(c)
	if len(got) != 3 {
		t.Fatalf("disable cleanup paths: %v", got)
	}
	for _, path := range got {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	if got := proxyNat46Orphans(c); len(got) != 0 {
		t.Fatalf("cleanup left files: %v", got)
	}
}

func TestProxyNat46VerifyDetectsDeadListeners(t *testing.T) {
	c := proxyTestConfig(t)
	c.Proxy.Nat46.Enabled = true
	c.Proxy.Nat46.DNS64.Enabled = true
	oldCheck, oldDeadline := proxyNat46ListenCheck, verifyDeadline
	proxyNat46ListenCheck = func(string) bool { return false }
	verifyDeadline = func(...*Config) time.Time { return time.Now() }
	defer func() { proxyNat46ListenCheck, verifyDeadline = oldCheck, oldDeadline }()
	errs := proxyVerify(c, []string{"mr-nat46", "mr-dns64"})
	joined := strings.Join(errs, "\n")
	if !strings.Contains(joined, "mr-nat46: SOCKS5 listener not answering") || !strings.Contains(joined, "mr-dns64: DNS64 listener not answering") {
		t.Fatalf("dead listener verification: %s", joined)
	}
}

func TestProxyNat46FullAddressMustBeLocal(t *testing.T) {
	if _, ok := parseLocalIPv6("2001:db8::c001"); ok {
		t.Fatal("non-local full IPv6 username accepted")
	}
}

func TestProxyNat46LocalSuffixUsesCompleteInterfaceID(t *testing.T) {
	old := localIPv6ForLookup
	localIPv6ForLookup = func() []netip.Addr {
		return []netip.Addr{
			netip.MustParseAddr("2001:db8:1:2::c101"),
			netip.MustParseAddr("2001:db8::c101"),       // same low 16 bits, different interface ID
			netip.MustParseAddr("2001:db8:1:2:1::c102"), // high interface-ID bits: not a candidate
		}
	}
	defer func() { localIPv6ForLookup = old }()
	if _, ok := (localSourceTable{}).Lookup("c101"); ok {
		t.Fatal("ambiguous complete interface ID accepted")
	}
	localIPv6ForLookup = func() []netip.Addr { return []netip.Addr{netip.MustParseAddr("2001:db8:1:2::c101")} }
	if got, ok := (localSourceTable{}).Lookup("c101"); !ok || got.String() != "2001:db8:1:2::c101" {
		t.Fatalf("unique interface ID lookup: %s %v", got, ok)
	}
}

func TestProxyNat46ServeReadsGeneratedConfigWithoutSecrets(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nat46.json")
	if err := os.WriteFile(path, []byte(`{"listen":"127.0.0.1:1094","prefix":"64:ff9b::/96","max_conns":8}`), 0644); err != nil {
		t.Fatal(err)
	}
	old := proxyNat46Gen
	proxyNat46Gen = path
	defer func() { proxyNat46Gen = old }()
	if cfg, err := nat46ServeConfigFromFile(); err != nil || cfg.Listen != "127.0.0.1:1094" || cfg.MaxConns != 8 {
		t.Fatalf("generated serve config: %+v, %v", cfg, err)
	}
	// An unreadable secrets path must not be touched by the serve subcommand. An extra argument
	// makes it return before binding, while still exercising dispatch's early serve branch.
	if err := dispatch([]string{"proxy", "nat46", "serve", "unexpected"}, filepath.Join(dir, "router.yaml"), filepath.Join(dir, "secrets.yaml")); err == nil || !strings.Contains(err.Error(), "usage") {
		t.Fatalf("serve branch loaded router/secrets instead of validating its own args: %v", err)
	}
}

func TestProxyNat46DNS64RenderAndForwardSync(t *testing.T) {
	c := proxyTestConfig(t)
	c.Proxy.Nat46.Enabled = true
	c.Proxy.Nat46.DNS64.Enabled = true
	c.DNS.Fallback = []string{"192.0.2.53#53", "198.51.100.53"}
	oldExists := unboundBinaryExists
	unboundBinaryExists = func() bool { return true }
	defer func() { unboundBinaryExists = oldExists }()
	files := renderMap(t, c)
	conf := files[proxyNat46DNS64Gen]
	wantLines := []string{
		"server:", "    interface: 127.0.0.1", "    port: 1153", "    access-control: 127.0.0.0/8 allow",
		"    do-ip6: no", "    module-config: \"dns64 iterator\"", "    local-zone: \"test.\" transparent", "    dns64-prefix: 64:ff9b::/96",
		"    dns64-synthall: yes", "    dns64-ignore-aaaa: ::/0", "    cache-min-ttl: 30", "    cache-max-ttl: 300",
		"    num-threads: 1", "    msg-cache-size: 2m", "    rrset-cache-size: 4m", "    username: \"unbound\"",
	}
	gotLines := strings.Split(strings.TrimSuffix(conf, "\n"), "\n")
	if !reflect.DeepEqual(gotLines, wantLines) {
		t.Fatalf("dns64 config lines:\n%v\nwant:\n%v", gotLines, wantLines)
	}

	dir := t.TempDir()
	gen, run, resolv := filepath.Join(dir, "dns64.conf"), filepath.Join(dir, "run.conf"), filepath.Join(dir, "resolv.conf")
	if err := os.WriteFile(gen, []byte(conf), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(resolv, []byte("nameserver 203.0.113.2\nnameserver 203.0.113.3\nnameserver 2001:db8::53\n"), 0644); err != nil {
		t.Fatal(err)
	}
	oldGen, oldRun, oldResolv, oldCheck := proxyNat46DNS64Gen, proxyNat46DNS64Run, resolvConf, runUnboundCheckconf
	oldStatus, oldAction := nat46DNS64ServiceRunning, nat46DNS64ServiceAction
	proxyNat46DNS64Gen, proxyNat46DNS64Run, resolvConf = gen, run, resolv
	checks := 0
	var actions []string
	runUnboundCheckconf = func(string) error { checks++; return nil }
	nat46DNS64ServiceRunning = func() bool { return false }
	nat46DNS64ServiceAction = func(action string) error { actions = append(actions, action); return nil }
	defer func() {
		proxyNat46DNS64Gen, proxyNat46DNS64Run, resolvConf, runUnboundCheckconf = oldGen, oldRun, oldResolv, oldCheck
		nat46DNS64ServiceRunning, nat46DNS64ServiceAction = oldStatus, oldAction
	}()
	if err := proxyNat46DNS64Sync(c); err != nil {
		t.Fatal(err)
	}
	if checks != 1 || !reflect.DeepEqual(actions, []string{"start"}) {
		t.Fatalf("first DNS64 sync: checks=%d actions=%v", checks, actions)
	}
	nat46DNS64ServiceRunning = func() bool { return true }
	if err := proxyNat46DNS64Sync(c); err != nil {
		t.Fatal(err)
	}
	if checks != 1 || !reflect.DeepEqual(actions, []string{"start"}) {
		t.Fatalf("unchanged DNS64 sync reloaded: checks=%d actions=%v", checks, actions)
	}
	b, _ := os.ReadFile(run)
	for _, line := range []string{"forward-zone:", "forward-addr: 203.0.113.2", "forward-addr: 203.0.113.3"} {
		if !strings.Contains(string(b), line) {
			t.Errorf("runtime dns64 missing %q:\n%s", line, b)
		}
	}
	if err := os.WriteFile(resolv, []byte("nameserver 203.0.113.4\n"), 0644); err != nil {
		t.Fatal(err)
	}
	nat46DNS64ServiceRunning = func() bool { return true }
	if err := proxyNat46DNS64Sync(c); err != nil {
		t.Fatal(err)
	}
	if checks != 2 || !reflect.DeepEqual(actions, []string{"start", "reload"}) {
		t.Fatalf("changed DNS64 sync did not reload: checks=%d actions=%v", checks, actions)
	}
	b, _ = os.ReadFile(run)
	if !strings.Contains(string(b), "forward-addr: 203.0.113.4") {
		t.Errorf("runtime dns64 did not update:\n%s", b)
	}

	noSynth := false
	c.Proxy.Nat46.DNS64.SynthAll = &noSynth
	conf = proxyNat46DNS64Config(c)
	if strings.Contains(conf, "dns64-synthall") || strings.Contains(conf, "dns64-ignore-aaaa") {
		t.Fatal("synth_all=false still rendered synthall directives")
	}
}

func TestProxyNat46DNS64RejectsBadListen(t *testing.T) {
	c := proxyTestConfig(t)
	c.Proxy.Nat46.Enabled = true
	c.Proxy.Nat46.DNS64.Enabled = true
	c.Proxy.Nat46.DNS64.Listen = "0.0.0.0:1153"
	old := unboundBinaryExists
	unboundBinaryExists = func() bool { return true }
	defer func() { unboundBinaryExists = old }()
	errs := strings.Join(c.Validate(), "\n")
	if !strings.Contains(errs, "proxy.nat46.dns64.listen") {
		t.Fatalf("bad DNS64 listen accepted: %s", errs)
	}
}

func TestProxyNat46DNS64NeedsNat46AndNonLoopbackUpstream(t *testing.T) {
	c := proxyTestConfig(t)
	c.Proxy.Nat46.DNS64.Enabled = true
	old := unboundBinaryExists
	unboundBinaryExists = func() bool { return true }
	defer func() { unboundBinaryExists = old }()
	errs := strings.Join(c.Validate(), "\n")
	if !strings.Contains(errs, "proxy.nat46.dns64: requires proxy.nat46.enabled") {
		t.Fatalf("missing nat46 dependency error: %s", errs)
	}
	c.Proxy.Nat46.Enabled = true
	c.DNS.Upstream = "manual"
	c.DNS.Servers = []string{"127.0.0.1#53"}
	c.DNS.Fallback = nil
	errs = strings.Join(c.Validate(), "\n")
	if !strings.Contains(errs, "non-loopback IPv4") {
		t.Fatalf("loopback upstream accepted: %s", errs)
	}
	if got := proxyNat46DNS64Servers(c); len(got) != 0 {
		t.Fatalf("loopback upstream was rendered: %v", got)
	}
}

func TestProxyNat46DNS64FallbackAndNonISPHook(t *testing.T) {
	c := proxyTestConfig(t)
	c.Proxy.Nat46.Enabled = true
	c.Proxy.Nat46.DNS64.Enabled = true
	c.DNS.Upstream = "manual"
	c.DNS.Servers = []string{"192.0.2.53#53"}
	dir := t.TempDir()
	gen, run, resolv := filepath.Join(dir, "dns64.conf"), filepath.Join(dir, "run.conf"), filepath.Join(dir, "resolv.conf")
	if err := os.WriteFile(gen, []byte(proxyNat46DNS64Config(c)), 0644); err != nil {
		t.Fatal(err)
	}
	oldGen, oldRun, oldResolv, oldCheck := proxyNat46DNS64Gen, proxyNat46DNS64Run, resolvConf, runUnboundCheckconf
	oldStatus, oldAction := nat46DNS64ServiceRunning, nat46DNS64ServiceAction
	proxyNat46DNS64Gen, proxyNat46DNS64Run, resolvConf = gen, run, resolv
	runUnboundCheckconf = func(string) error { return nil }
	nat46DNS64ServiceRunning = func() bool { return false }
	nat46DNS64ServiceAction = func(string) error { return nil }
	defer func() {
		proxyNat46DNS64Gen, proxyNat46DNS64Run, resolvConf, runUnboundCheckconf = oldGen, oldRun, oldResolv, oldCheck
		nat46DNS64ServiceRunning, nat46DNS64ServiceAction = oldStatus, oldAction
	}()
	// writeResolv used to return before this sync for non-ISP upstreams.
	writeResolv(c)
	b, err := os.ReadFile(run)
	if err != nil || !strings.Contains(string(b), "forward-addr: 192.0.2.53@53") {
		t.Fatalf("non-ISP DNS64 forwarder: %q, %v", b, err)
	}
	old := string(b)
	c.DNS.Servers = nil
	if err := proxyNat46DNS64Sync(c); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(run)
	if string(b) != old {
		t.Fatal("DNS64 runtime config changed without any usable DNS")
	}
}
