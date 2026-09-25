package main

import (
	"bytes"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// wolConfig: the home config with synthetic static hosts on the main LAN and an extra network.
func wolConfig(t *testing.T) *Config {
	t.Helper()
	c := testConfig(t)
	c.Networks = append(c.Networks, Network{Name: "iot", IPv4: "192.168.30.1/24", Zone: "lan"})
	c.DHCP.Hosts = []Host{
		{Name: "nas", MAC: "02:00:00:00:00:01", IP: "192.168.1.20"},
		{Name: "cam", MAC: "02:00:00:00:00:02", IP: "192.168.30.5"},
	}
	c.DHCP.HostLeases = nil
	c.defaults()
	return c
}

func TestWOLPacket(t *testing.T) {
	mac, _ := net.ParseMAC("02:00:00:00:00:01")
	p := wolPacket(mac)
	if len(p) != 102 || !bytes.Equal(p[:6], bytes.Repeat([]byte{0xff}, 6)) {
		t.Fatalf("packet %x", p)
	}
	for i := 0; i < 16; i++ {
		if !bytes.Equal(p[6+6*i:12+6*i], mac) {
			t.Fatalf("repetition %d: %x", i, p[6+6*i:12+6*i])
		}
	}
}

func TestWOLTarget(t *testing.T) {
	c := wolConfig(t)
	for _, tc := range []struct{ target, network, mac, host, net, dev string }{
		{"nas", "", "02:00:00:00:00:01", "nas", "lan", "br-lan"},
		{"NAS", "", "02:00:00:00:00:01", "nas", "lan", "br-lan"},
		{"cam", "", "02:00:00:00:00:02", "cam", "iot", "br-iot"},               // network from the host's address
		{"02:00:00:00:00:02", "", "02:00:00:00:00:02", "cam", "iot", "br-iot"}, // a known MAC finds its host
		{"02:00:00:00:00:09", "", "02:00:00:00:00:09", "", "lan", "br-lan"},    // unknown MAC: main LAN
		{"02:00:00:00:00:09", "iot", "02:00:00:00:00:09", "", "iot", "br-iot"}, // explicit network
		{"02:AA:BB:CC:DD:EE", "lan", "02:aa:bb:cc:dd:ee", "", "lan", "br-lan"},
	} {
		mac, host, n, err := wolTarget(c, tc.target, tc.network)
		if err != nil || mac.String() != tc.mac || host != tc.host || n.Name != tc.net || n.Bridge != tc.dev {
			t.Errorf("%s %s: %v %q %+v %v", tc.target, tc.network, mac, host, n, err)
		}
	}
	for target, network := range map[string]string{"tv": "", "nas;reboot": "", "01:00:5e:00:00:01": "", "00:00:00:00:00:00": "",
		"ff:ff:ff:ff:ff:ff": "", "nas": "office", "": "", "02:00:00:00:00:01 ": "", "-nas": ""} {
		if _, _, _, err := wolTarget(c, target, network); err == nil {
			t.Errorf("%q on %q accepted", target, network)
		}
	}
	for cidr, want := range map[string]string{"192.168.1.6/24": "192.168.1.255", "10.0.0.1/8": "10.255.255.255", "192.168.5.9/30": "192.168.5.11", "172.16.1.1/23": "172.16.1.255"} {
		src, b, err := wolBroadcast(LANNet{Name: "x", IPv4: cidr})
		if err != nil || b.String() != want || src.String() != strings.Split(cidr, "/")[0] {
			t.Errorf("%s: %v %v %v", cidr, src, b, err)
		}
	}
	if _, _, err := wolBroadcast(LANNet{Name: "p2p", IPv4: "10.0.0.1/31"}); err == nil {
		t.Error("/31 has no broadcast address")
	}
}

// wolWake sends on the bridge of the host's network to its directed broadcast, from the router's address.
func TestWOLWake(t *testing.T) {
	c := wolConfig(t)
	var dev string
	var src, dst net.IP
	var pkt []byte
	old := wolSend
	wolSend = func(d string, s, b net.IP, p []byte) error { dev, src, dst, pkt = d, s, b, p; return nil }
	t.Cleanup(func() { wolSend = old })
	r, err := wolWake(c, "cam", "")
	if err != nil || dev != "br-iot" || src.String() != "192.168.30.1" || dst.String() != "192.168.30.255" || len(pkt) != 102 {
		t.Fatalf("%+v %v: dev %s src %v dst %v len %d", r, err, dev, src, dst, len(pkt))
	}
	if r != (wolResult{MAC: "02:00:00:00:00:02", Host: "cam", Network: "iot", Dev: "br-iot", Broadcast: "192.168.30.255"}) {
		t.Errorf("result %+v", r)
	}
}

// the real socket code (without the device binding): three packets reach a listener on loopback
func TestWOLSendSocket(t *testing.T) {
	l, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skip("no loopback UDP:", err)
	}
	defer l.Close()
	old := wolPort
	wolPort = l.LocalAddr().(*net.UDPAddr).Port
	t.Cleanup(func() { wolPort = old })
	mac, _ := net.ParseMAC("02:00:00:00:00:01")
	if err := wolSend("", net.IPv4(127, 0, 0, 1), net.IPv4(127, 0, 0, 1), wolPacket(mac)); err != nil {
		t.Fatal(err)
	}
	l.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 200)
	for i := 0; i < 3; i++ {
		n, from, err := l.ReadFromUDP(buf)
		if err != nil || n != 102 || !bytes.Equal(buf[:n], wolPacket(mac)) || !from.IP.Equal(net.IPv4(127, 0, 0, 1)) {
			t.Fatalf("packet %d: %d bytes from %v: %v", i, n, from, err)
		}
	}
}

// schedule action wol: a dhcp.hosts name or a MAC, checked like every other target
func TestWOLSchedule(t *testing.T) {
	sysTemp(t)
	c := wolConfig(t)
	c.Schedules = []Schedule{{Name: "wake-nas", Cron: "0 7 * * 1-5", Action: "wol", Target: "nas"}}
	if errs := c.Validate(); len(errs) > 0 {
		t.Fatal(errs)
	}
	if f := renderMap(t, c); !strings.Contains(f[cronFile], "\n0 7 * * 1-5 /usr/sbin/mr sys run wol nas\n") {
		t.Errorf("crontab:\n%s", f[cronFile])
	}
	for _, target := range []string{"", "tv", "nas; reboot", "01:00:5e:00:00:01"} {
		c.Schedules[0].Target = target
		if errs := strings.Join(c.Validate(), "\n"); !strings.Contains(errs, "schedules[0]: wol") {
			t.Errorf("target %q: %s", target, errs)
		}
	}
	// `mr sys run wol` sends (and checks the target against the live config again)
	var sent []string
	old := wolSend
	wolSend = func(d string, s, b net.IP, p []byte) error { sent = append(sent, d+" "+b.String()); return nil }
	t.Cleanup(func() { wolSend = old })
	oldLog := ChangeLog
	ChangeLog = t.TempDir() + "/changes.log"
	t.Cleanup(func() { ChangeLog = oldLog })
	if err := sysRunTask(c, []string{"wol", "nas"}); err != nil || strings.Join(sent, ",") != "br-lan 192.168.1.255" {
		t.Errorf("sys run wol nas: %v %v", err, sent)
	}
	if b, _ := os.ReadFile(ChangeLog); !strings.Contains(string(b), "schedule: wol nas") {
		t.Errorf("change log: %q", b)
	}
	if err := sysRunTask(c, []string{"wol", "tv"}); err == nil {
		t.Error("sys run wol with an unknown host accepted")
	}
}

func TestWOLAPI(t *testing.T) {
	if st := apiSysWOL(apiReq{method: "GET"}).status; st != 405 {
		t.Errorf("sys.wol via GET: %d", st)
	}
	for _, body := range []string{`{}`, `{"target":"nas;reboot"}`, `{"target":"$(id)"}`, `{"target":"nas","network":"a b"}`, `{"target":"01:00:5e"}`} {
		if st := apiSysWOL(apiReq{method: "POST", body: []byte(body)}).status; st != 400 {
			t.Errorf("sys.wol %s: %d", body, st)
		}
	}
}
