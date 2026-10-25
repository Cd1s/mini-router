package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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

func TestProxyNat46FullAddressMustBeLocal(t *testing.T) {
	if _, ok := parseLocalIPv6("2001:db8::c001"); ok {
		t.Fatal("non-local full IPv6 username accepted")
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
	for _, line := range []string{"server:", "interface: 127.0.0.1", "port: 1153", "dns64-prefix: 64:ff9b::/96", "dns64-synthall: yes", "dns64-ignore-aaaa: ::/0", "username: \"unbound\""} {
		if !strings.Contains(conf, line) {
			t.Errorf("dns64 config missing %q:\n%s", line, conf)
		}
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
	proxyNat46DNS64Gen, proxyNat46DNS64Run, resolvConf = gen, run, resolv
	runUnboundCheckconf = func(string) error { return nil }
	defer func() {
		proxyNat46DNS64Gen, proxyNat46DNS64Run, resolvConf, runUnboundCheckconf = oldGen, oldRun, oldResolv, oldCheck
	}()
	if err := proxyNat46DNS64Sync(c); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(run)
	for _, line := range []string{"forward-zone:", "forward-addr: 203.0.113.2", "forward-addr: 203.0.113.3"} {
		if !strings.Contains(string(b), line) {
			t.Errorf("runtime dns64 missing %q:\n%s", line, b)
		}
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
