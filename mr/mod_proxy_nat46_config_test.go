package main

import (
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
