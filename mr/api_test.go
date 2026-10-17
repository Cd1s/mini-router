package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestLANConfirmTokenIsScopedAndHashed(t *testing.T) {
	oldConfirm, oldLoad := ConfirmFile, loadLANConfig
	t.Cleanup(func() { ConfirmFile, loadLANConfig = oldConfirm, oldLoad })
	ConfirmFile = t.TempDir() + "/confirm-pending"
	loadLANConfig = func() (*Config, error) { return &Config{LAN: LAN{IPv4: "192.168.2.1/24"}}, nil }
	token := newConfirmToken()
	h := sha256.Sum256([]byte(token))
	if len(token) < 32 || token == newConfirmToken() {
		t.Fatal("confirmation token is missing entropy")
	}
	if err := setPending(pendingApply{Snapshot: "/tmp/snap", State: statePending, Deadline: time.Now().Unix() + 60, ConfirmHash: hex.EncodeToString(h[:])}); err != nil {
		t.Fatal(err)
	}
	if marker, err := os.ReadFile(ConfirmFile); err != nil || bytes.Contains(marker, []byte(token)) {
		t.Fatalf("pending marker contains plaintext token: %q", marker)
	}
	if got := confirmWithToken(token+"x", "192.168.2.44"); got.status != 401 {
		t.Fatalf("wrong token status = %d, want 401", got.status)
	}
	if _, err := os.Stat(ConfirmFile); err != nil {
		t.Fatalf("wrong token consumed pending marker: %v", err)
	}
	// A token cannot confirm while the apply is still running, even when its hash matches.
	if err := setPending(pendingApply{Snapshot: "/tmp/snap", State: stateApplying, Pid: os.Getpid(), ConfirmHash: hex.EncodeToString(h[:])}); err != nil {
		t.Fatal(err)
	}
	if got := confirmWithToken(token, "192.168.2.44"); got.status != 409 {
		t.Fatalf("applying token status = %d, want 409", got.status)
	}
}

func TestLANConfirmTokenSuccessIsOneShotAndLANOnly(t *testing.T) {
	_, _, _ = confirmEnv(t)
	oldLoad := loadLANConfig
	t.Cleanup(func() { loadLANConfig = oldLoad })
	loadLANConfig = func() (*Config, error) { return &Config{LAN: LAN{IPv4: "192.168.2.1/24"}}, nil }
	token := newConfirmToken()
	h := sha256.Sum256([]byte(token))
	if err := setPending(pendingApply{Snapshot: "/tmp/snap", State: statePending, Deadline: time.Now().Unix() + 60, ConfirmHash: hex.EncodeToString(h[:])}); err != nil {
		t.Fatal(err)
	}
	if got := confirmWithToken(token, "192.168.2.44"); got.status != 0 {
		t.Fatalf("valid LAN token status = %d, want success", got.status)
	}
	if got := confirmWithToken(token, "192.168.2.44"); got.status != 409 {
		t.Fatalf("reused token status = %d, want 409", got.status)
	}
	if err := setPending(pendingApply{Snapshot: "/tmp/snap", State: statePending, Deadline: time.Now().Unix() + 60, ConfirmHash: hex.EncodeToString(h[:])}); err != nil {
		t.Fatal(err)
	}
	if got := confirmWithToken(token, "192.168.9.44"); got.status != 403 {
		t.Fatalf("non-LAN token status = %d, want 403", got.status)
	}
}

func TestNormalizeRemoteAddrBusyboxFormats(t *testing.T) {
	for _, tc := range []struct {
		raw, want string
	}{
		{"192.168.1.5", "192.168.1.5"},
		{"[::ffff:192.168.1.5]", "192.168.1.5"},
		{"[fd00:1::5]", "fd00:1::5"},
		{"[fe80::8857:6eff:fe5a:947a%br-lan]", "fe80::8857:6eff:fe5a:947a%br-lan"},
	} {
		if got := normalizeRemoteAddr(tc.raw); got != tc.want {
			t.Errorf("normalizeRemoteAddr(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

func TestSetupReportsInvalidConfigSeparatelyFromLANAccess(t *testing.T) {
	oldLoad := loadLANConfig
	t.Cleanup(func() { loadLANConfig = oldLoad })
	loadLANConfig = func() (*Config, error) { return nil, errors.New("router.yaml: invalid") }
	r := apiSetup(apiReq{method: "POST", remote: "192.168.1.20", body: []byte(`{"password":"correct horse"}`)}, map[string]string{})
	msg := r.body.(map[string]any)["error"].(string)
	if r.status != 500 || !strings.Contains(msg, "配置文件缺失") || strings.Contains(msg, "router.yaml: invalid") {
		t.Fatalf("invalid config setup response: %d %v", r.status, r.body)
	}
}

func TestFromLANAcceptsIPv6OnLANBridge(t *testing.T) {
	oldLoad, oldAddrs, oldSource := loadLANConfig, lanBridgeAddrs, lanIPv6Source
	t.Cleanup(func() { loadLANConfig, lanBridgeAddrs, lanIPv6Source = oldLoad, oldAddrs, oldSource })
	loadLANConfig = func() (*Config, error) {
		return &Config{LAN: LAN{Bridge: "br-lan", IPv4: "192.168.1.1/24"}}, nil
	}
	lanBridgeAddrs = func(string) ([]net.Addr, error) {
		return []net.Addr{&net.IPNet{IP: net.ParseIP("fe80::1"), Mask: net.CIDRMask(64, 128)}, &net.IPNet{IP: net.ParseIP("fd00:1::1"), Mask: net.CIDRMask(64, 128)}}, nil
	}
	lanIPv6Source = func(remote, bridge string) bool {
		return bridge == "br-lan" && (remote == "fe80::abcd%br-lan" || remote == "fd00:1::abcd")
	}
	for _, remote := range []string{"[fe80::abcd%br-lan]", "[fd00:1::abcd]"} {
		ok, err := fromLAN(remote)
		if err != nil || !ok {
			t.Errorf("%s: fromLAN=%v err=%v", remote, ok, err)
		}
	}
	if ok, err := fromLAN("[fd00:2::abcd]"); err != nil || ok {
		t.Errorf("outside LAN IPv6 accepted: %v %v", ok, err)
	}
	if ok, err := fromLAN("[fe80::bad%wan]"); err != nil || ok {
		t.Errorf("WAN link-local IPv6 accepted: %v %v", ok, err)
	}
	if ok, err := fromLAN("[::ffff:192.168.1.20]"); err != nil || !ok {
		t.Errorf("IPv4-mapped IPv6 was not normalized to LAN IPv4: %v %v", ok, err)
	}
}

func TestPasswordHash(t *testing.T) {
	h := hashPassword("correct horse")
	if !strings.HasPrefix(h, "pbkdf2-sha256$") {
		t.Fatal(h)
	}
	if !checkPassword(h, "correct horse") || checkPassword(h, "wrong") || checkPassword("garbage", "x") {
		t.Fatal("password check broken")
	}
	if hashPassword("x") == hashPassword("x") {
		t.Fatal("salt not random")
	}
}

func TestConfigJSONRoundTrip(t *testing.T) {
	c := testConfig(t)
	m, err := configToJSON(c)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(m)
	back, _, err := configFromJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	if back.LAN.IPv4 != c.LAN.IPv4 || len(back.Firewall.Forwards) != len(c.Firewall.Forwards) || back.WiFi.Radios[1].HTMode != "HE160" {
		t.Fatalf("round trip lost data: %+v", back.LAN)
	}
	// unknown keys must be rejected, not silently dropped
	if _, _, err := configFromJSON([]byte(`{"lan":{"ipv4":"192.168.1.1/24","bogus":1}}`)); err == nil {
		t.Fatal("unknown field accepted")
	}
}

func TestAPIRejectsWithoutHeader(t *testing.T) {
	r := handleAPI(apiReq{action: "status"})
	if r.status != 403 {
		t.Fatalf("want 403, got %d", r.status)
	}
}

func TestSecretKeyValidation(t *testing.T) {
	for k, want := range map[string]bool{"wifi_key": true, "pppoe-2": true, "": false, "../x": false, "A": false, "webui_password": true} {
		if got := regexpSecretKey(k); got != want {
			t.Errorf("%q: got %v", k, got)
		}
	}
}

func TestDiagRejectsBadHosts(t *testing.T) {
	for _, h := range []string{"-c1", "a;reboot", "$(id)", "a b", ""} {
		r := apiDiag(apiReq{method: "POST", body: []byte(`{"tool":"ping","host":` + strconv.Quote(h) + `}`)})
		if r.status != 400 {
			t.Errorf("host %q accepted", h)
		}
	}
	if !hostRe.MatchString("2606:4700::1111") || !hostRe.MatchString("www.example.com") {
		t.Error("valid hosts rejected")
	}
	if domainRe.MatchString("a.com;rm") || !domainRe.MatchString("*.cloudflare.com") {
		t.Error("domainRe")
	}
}
