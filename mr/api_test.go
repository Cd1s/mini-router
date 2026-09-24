package main

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
)

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
