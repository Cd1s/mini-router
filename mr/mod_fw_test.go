package main

import (
	"os"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// fixedClock pins the render clock: 2026-07-01 12:00 UTC, kernel timezone UTC.
func fixedClock(t *testing.T, kernelMW int) {
	t.Helper()
	oldNow, oldK := fwNow, fwKernelMW
	fwNow = func() time.Time { return time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC) }
	fwKernelMW = func() int { return kernelMW }
	t.Cleanup(func() { fwNow, fwKernelMW = oldNow, oldK })
}

// fwLabConfig: the home config plus a guest and an IoT network, with the firewall section of the
// lab fragment examples/lab.d/40-fw.yaml (every fw feature).
func fwLabConfig(t *testing.T) *Config {
	t.Helper()
	c := testConfig(t)
	c.Networks = []Network{
		{Name: "guest", IPv4: "192.168.20.1/24", Zone: "guest", DHCP: Pool{Enabled: true, Start: 100, End: 199}},
		{Name: "iot", IPv4: "192.168.30.1/24", Zone: "lan"},
	}
	b, err := os.ReadFile("../examples/lab.d/40-fw.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var frag struct {
		Firewall Firewall `yaml:"firewall"`
	}
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(&frag); err != nil {
		t.Fatal(err)
	}
	c.Firewall = frag.Firewall
	c.defaults()
	return c
}

func mustContain(t *testing.T, what, s string, subs ...string) {
	t.Helper()
	for _, x := range subs {
		if !strings.Contains(s, x) {
			t.Errorf("%s missing %q", what, x)
		}
	}
}

func mustNotContain(t *testing.T, what, s string, subs ...string) {
	t.Helper()
	for _, x := range subs {
		if strings.Contains(s, x) {
			t.Errorf("%s must not contain %q", what, x)
		}
	}
}

// The real home config must keep its forwards, open 443, masquerade, NAT loopback and offload.
func TestFwHomeEquivalent(t *testing.T) {
	fixedClock(t, 0)
	c := testConfig(t)
	if errs := c.Validate(); len(errs) > 0 {
		t.Fatal(errs)
	}
	out := renderNft(c, func(string) bool { return true })
	mustContain(t, "home nft", out,
		`iifname { "pppoe-wan", "pppoe-wan2" } tcp dport 45000-45100 dnat ip to 192.168.1.241 comment "vps-45000-45100"`,
		`iifname { "pppoe-wan", "pppoe-wan2" } udp dport 45000-45100 dnat ip to 192.168.1.241 comment "vps-45000-45100"`,
		`iifname { "pppoe-wan", "pppoe-wan2" } tcp dport 7443 dnat ip to 192.168.1.66:9999 comment "desktop-7443"`,
		`iifname { "pppoe-wan", "pppoe-wan2" } udp dport 46001-46020 dnat ip to 192.168.1.237 comment "workstation"`,
		`iifname { "pppoe-wan", "pppoe-wan2" } tcp dport 443 accept comment "lucky-https"`,
		`oifname { "pppoe-wan", "pppoe-wan2" } meta nfproto ipv4 masquerade`,
		`iifname "br-lan" oifname "br-lan" ct status dnat ip saddr 192.168.1.0/24 masquerade comment "nat-reflection"`,
		`iifname "br-lan" fib daddr type local ip daddr != 192.168.1.6 tcp dport 7443 dnat ip to 192.168.1.66:9999`,
		"type nat hook prerouting priority dstnat + 1;",
		"\t\tmeta l4proto { tcp, udp } ct state established flow add @ft\n",
		"flags offload",
		"ct state vmap { established : accept, related : accept, invalid : drop }",
		`iifname { "br-lan", "tailscale0" } accept`,
		"tcp flags & (fin|syn|rst|ack) == syn limit rate over 50/second burst 100 packets drop",
		"icmp type echo-request limit rate 20/second accept",
		`ip6 saddr fc00::/6 ip6 daddr fc00::/6 udp dport 546 accept`,
		`iifname { "pppoe-wan", "pppoe-wan2" } udp dport 41641 accept comment "tailscale"`,
		`iifname { "pppoe-wan", "pppoe-wan2" } counter drop comment "wan-in-drop"`,
		"ct status dnat accept",
	)
	// nothing the home config did not ask for
	mustNotContain(t, "home nft", out, "@ac_4", "meta hour", "log prefix", "v6in:", "rule:", "dhcp-client")
	// the open port must come before the final WAN drop
	if strings.Index(out, `comment "lucky-https"`) > strings.Index(out, `comment "wan-in-drop"`) {
		t.Error("open port rendered after the WAN drop")
	}
}

func TestFwLabRender(t *testing.T) {
	fixedClock(t, 0)
	c := fwLabConfig(t)
	if errs := c.Validate(); len(errs) > 0 {
		t.Fatalf("lab fw invalid:\n%s", strings.Join(errs, "\n"))
	}
	out := renderNft(c, func(string) bool { return true })
	mustContain(t, "lab nft", out,
		// toggles
		`limit rate 10/minute burst 20 packets log prefix "mr-drop wan-in: " level info`,
		// forwards: WAN subset + source restriction, guest/iot targets, loopback for every trusted bridge
		`iifname { "pppoe-wan2" } ip saddr { 203.0.113.0/24, 198.51.100.7 } tcp dport 2222 dnat ip to 192.168.1.241:22 comment "nas-ssh-office"`,
		`tcp dport 8554 dnat ip to 192.168.20.50 comment "guest-cam"`,
		`iifname { "br-lan", "br-iot" } fib daddr type local ip daddr != { 192.168.1.6, 192.168.20.1, 192.168.30.1 } udp dport 5683 dnat ip to 192.168.30.20`,
		`iifname "br-iot" oifname "br-iot" ct status dnat ip saddr 192.168.30.0/24 masquerade comment "nat-reflection"`,
		// open ports per family
		`iifname { "pppoe-wan" } ip saddr 203.0.113.0/24 udp dport { 51820, 51821 } accept comment "wg-office"`,
		`iifname { "pppoe-wan" } ip6 saddr 2001:db8:100::/48 udp dport { 51820, 51821 } accept comment "wg-office"`,
		// IPv6 pinholes by interface identifier / EUI-64
		`iifname { "pppoe-wan", "pppoe-wan2" } oifname { "br-lan", "br-guest", "br-iot" } ip6 daddr & ::ffff:ffff:ffff:ffff == ::211:32ff:fe12:3456 tcp dport { 443, 8443 } counter accept comment "v6in:nas-https"`,
		`iifname { "pppoe-wan2" } oifname { "br-lan", "br-guest", "br-iot" } ip6 saddr 2001:db8:100::/48 ip6 daddr & ::ffff:ffff:ffff:ffff == ::c3:6ff:fed6:7f8a tcp dport 22 counter accept comment "v6in:desktop-ssh"`,
		`ip6 daddr & ::ffff:ffff:ffff:ffff == ::10 udp dport 27000-27050 counter accept comment "v6in:game-v6"`,
		// traffic rules
		`iifname { "br-lan", "br-iot", "tailscale0" } oifname { "pppoe-wan", "pppoe-wan2" } tcp dport 25 counter reject with tcp reset comment "rule:no-smtp-out"`,
		`meta l4proto { tcp, udp } th dport 853 limit rate 10/minute burst 5 packets log prefix "mr-rule no-dot-bypass: " level info`,
		`meta l4proto { tcp, udp } th dport 853 reject with icmpx admin-prohibited comment "rule:no-dot-bypass"`,
		`iifname { "br-guest" } oifname { "br-lan", "br-iot", "tailscale0" } ip daddr 192.168.1.50 tcp dport { 631, 9100 } counter accept comment "rule:guest-printer"`,
		`ether saddr aa:bb:cc:00:11:22 tcp dport 22 drop comment "rule:tv-no-router-ssh"`,
		// 01:00-06:00 at UTC+8 = 17:00-22:00 UTC the previous day
		`ip saddr 192.168.30.0/24 meta hour 61200-79199 counter drop comment "rule:iot-quiet-hours"`,
		`iifname { "pppoe-wan", "pppoe-wan2" } ip saddr 192.0.2.0/24 counter drop comment "rule:block-bad-net"`,
		`iifname { "pppoe-wan", "pppoe-wan2" } ip6 saddr 2001:db8:bad::/48 counter drop comment "rule:block-bad-net"`,
		`oifname { "br-lan", "br-iot", "tailscale0" } ip6 daddr 2001:db8:1::/64 meta l4proto ipv6-icmp accept comment "rule:v6-icmp-lab"`,
		// access control: learning, offload exclusion, windowed drops, proxy-bypass guard
		"set ac_4 { type ipv4_addr; size 4096; flags dynamic,timeout; timeout 6h; }",
		"set ac1_6 { type ipv6_addr; size 1024; flags dynamic,timeout; timeout 6h; }",
		`ether saddr { aa:bb:cc:dd:ee:01, aa:bb:cc:dd:ee:02 } update @ac_4 { ip saddr } update @ac0_4 { ip saddr }`,
		`ether saddr aa:bb:cc:dd:ee:03 oifname { "pppoe-wan", "pppoe-wan2" } counter drop comment "access:blocked-tv"`,
		`iifname { "pppoe-wan", "pppoe-wan2" } ip daddr @ac1_4 counter drop comment "access:blocked-tv"`,
		`iifname { "pppoe-wan", "pppoe-wan2" } ip6 daddr @ac1_6 counter drop comment "access:blocked-tv"`,
		"meta nfproto ipv4 meta l4proto { tcp, udp } ct state established ip saddr != @ac_4 ip daddr != @ac_4 flow add @ft",
		"meta nfproto ipv6 meta l4proto { tcp, udp } ct state established ip6 saddr != @ac_6 ip6 daddr != @ac_6 flow add @ft",
		`ether saddr aa:bb:cc:dd:ee:03 fib daddr type != { local, broadcast, multicast, anycast } counter drop comment "access:blocked-tv"`,
		// school hours: Mon-Fri whole local day at UTC+8 = Sun 16:00 .. Fri 16:00 UTC
		`meta day { Friday } meta hour 0-57599 counter drop comment "access:school-hours"`,
		`meta day { Monday, Tuesday, Wednesday, Thursday } counter drop comment "access:school-hours"`,
		`meta day { Sunday } meta hour 57600-86399 counter drop comment "access:school-hours"`,
	)
	mustNotContain(t, "lab nft", out,
		"icmp type echo-request limit rate 20/second accept", // wan_ping: false
		"old-game", "old-http", "off-v6", "disabled-rule", "off-entry", "ac3_4", // disabled entries
	)
	// order: access control → offload → ct state → rules → LAN accept → pinholes
	order := []string{`comment "access:kid-bedtime"`, "flow add @ft", "ct state vmap", `"rule:no-smtp-out"`, `iifname { "br-lan", "br-iot", "tailscale0" } accept`, `"v6in:nas-https"`}
	fwd := out[strings.Index(out, "chain forward {"):]
	last := -1
	for _, s := range order {
		i := strings.Index(fwd, s)
		if i < 0 || i < last {
			t.Errorf("forward chain order: %q at %d (after %d)", s, i, last)
		}
		last = i
	}
	in := out[strings.Index(out, "chain input {"):strings.Index(out, "chain forward {")]
	if a, b := strings.Index(in, `"rule:tv-no-router-ssh"`), strings.Index(in, `iifname { "br-lan", "br-iot", "tailscale0" } accept`); a < 0 || a > b {
		t.Error("router-bound rule must precede the LAN accept in input")
	}
	if a, b := strings.Index(in, `"access:blocked-tv"`), strings.Index(in, "ct state vmap"); a < 0 || a > b {
		t.Error("access-control guard must precede ct state in input (cuts established proxied connections too)")
	}
	if strings.Contains(out[strings.Index(out, "chain forward {"):], `"rule:tv-no-router-ssh"`) {
		t.Error("router-bound rule rendered into forward")
	}
}

func TestFwNoFlowtableNoFlowAdd(t *testing.T) {
	fixedClock(t, 0)
	c := testConfig(t)
	out := renderNft(c, func(string) bool { return false })
	mustNotContain(t, "nft without devices", out, "flow add", "flowtable ft")
	c.Firewall.Offload = "off"
	mustNotContain(t, "nft offload off", renderNft(c, func(string) bool { return true }), "flow add", "flowtable ft")
}

func TestFwToggles(t *testing.T) {
	fixedClock(t, 0)
	c := testConfig(t)
	f := false
	c.Firewall.WANPing, c.Firewall.DropInvalid = &f, &f
	c.WAN[1].Proto = "dhcp"
	out := renderNft(c, func(string) bool { return true })
	mustNotContain(t, "toggles", out, "icmp type echo-request limit", "invalid : drop")
	mustContain(t, "toggles", out, "ct state vmap { established : accept, related : accept }",
		"meta nfproto ipv6 icmpv6 type echo-request limit rate 20/second accept",
		`iifname { "wan" } meta nfproto ipv4 udp sport 67 udp dport 68 accept comment "dhcp-client"`)
}

func TestFwValidateRejects(t *testing.T) {
	c := fwLabConfig(t)
	fw := &c.Firewall
	fw.Forwards[0].Name = `x" accept #`
	fw.Forwards[1].To = "192.168.1.6"
	fw.Forwards[2].To = "192.168.30.255"
	fw.Forwards[3].SrcIP = []string{"2001:db8::/32"}
	fw.Forwards[4].WAN = []string{"wan9"}
	fw.Forwards[5].Port, fw.Forwards[5].ToPort = "5000-5010", "6000-6010"
	fw.Forwards[6].Enabled = boolp(true)
	fw.Forwards[6].Proto, fw.Forwards[6].Port = []string{"tcp"}, "443" // collides with the open lucky-https port
	fw.Forwards[6].Desc = "line\nbreak"
	fw.Open[1].SrcIP = []string{"203.0.113.0/24; drop"}
	fw.Open[2].Port = "80,x"
	fw.IPv6Allow[0].IID = "2001:db8::1"
	fw.IPv6Allow[1].IID = "::5" // both iid and mac
	fw.IPv6Allow[2].IID = "::"  // zero identifier
	fw.IPv6Allow[3].SrcIP = []string{"10.0.0.0/8"}
	fw.Rules[0].Action = "masquerade"
	fw.Rules[1].Src = "dmz"
	fw.Rules[2].SrcMAC = []string{"aa:bb:cc:dd:ee"}
	fw.Rules[3].Action = "accept" // towards the router
	fw.Rules[4].Schedule = []FwTime{{Days: []string{"monday"}, Time: "25:00-07:00"}}
	fw.Rules[5].SrcIP, fw.Rules[5].DestIP = []string{"192.168.1.0/24"}, []string{"2001:db8::/32"}
	fw.Rules[6].Action, fw.Rules[6].SrcIP = "accept", nil // accept from the WAN with no destination
	fw.Rules[7].DestPort, fw.Rules[7].Proto = "22", []string{"icmp"}
	fw.Rules[8] = FwRule{Name: "all", Action: "drop", Enabled: boolp(true)}
	fw.Access[0].MACs = []string{"aa:bb:cc:dd:ee:0g"}
	fw.Access[1].Schedule = []FwTime{{Time: "10:00-10:00"}}
	fw.Access[2].Name = "school-hours\n"
	fw.Access[3].MACs = nil
	fw.Offload = "turbo"
	errs := strings.Join(c.Validate(), "\n")
	for _, s := range []string{
		"forwards[0].name", "forwards[1].to: must be an IPv4 inside", "that is the router itself", "network or broadcast address",
		"forwards[3].src_ip: port forwards are IPv4 only", `forwards[4].wan: unknown wan "wan9"`, "forwards[5].to_port: a port range maps",
		"both take tcp port 443", "forwards[6].desc",
		"open[1].src_ip", "open[2].port",
		"ipv6_allow[0].iid", "ipv6_allow[1]: set exactly one of iid or mac", "ipv6_allow[2].iid", "ipv6_allow[3].src_ip",
		"rules[0].action", "rules[1].src", "rules[2].src_mac", "rules[3]: rules towards the router can only drop or reject",
		`rules[4].schedule[0].days: mon|tue|wed|thu|fri|sat|sun, got "monday"`, "rules[4].schedule[0].time",
		"rules[5]: src_ip and dest_ip have no address family in common",
		"rules[6]: an accept rule whose source may be the WAN needs dest_ip or dest_port",
		"rules[7].dest_port: needs proto tcp and/or udp only", "rules[8]: matches everything",
		"access[0].macs", "access[1].schedule[0].time", "access[2].name", "access[3].macs",
		"firewall.offload",
	} {
		if !strings.Contains(errs, s) {
			t.Errorf("want error containing %q in:\n%s", s, errs)
		}
	}
}

func TestFwValidateGuestZoneNeedsNetwork(t *testing.T) {
	c := testConfig(t)
	c.Firewall.Rules = []FwRule{{Name: "g", Action: "drop", Src: "guest", Proto: []string{"udp"}}}
	c.defaults()
	if !strings.Contains(strings.Join(c.Validate(), "\n"), "no network has zone guest") {
		t.Error("guest zone without guest networks accepted")
	}
	c.Firewall.Rules = []FwRule{{Name: "r", Action: "drop", Dest: "router", Src: "lan"}}
	if !strings.Contains(strings.Join(c.Validate(), "\n"), "a rule towards the router needs") {
		t.Error("zone-wide router lockout rule accepted")
	}
}

func TestFwTimeMatches(t *testing.T) {
	bkk := fwClock{LocalOff: 7 * 3600}
	cases := []struct {
		name string
		clk  fwClock
		sch  []FwTime
		want []string
	}{
		{"always", bkk, nil, []string{""}},
		{"whole week", bkk, []FwTime{{Days: []string{"mon", "tue", "wed", "thu", "fri", "sat", "sun"}}}, []string{""}},
		{"daily bedtime UTC+7", bkk, []FwTime{{Time: "22:00-07:00"}}, []string{"meta hour 54000-86399"}},
		{"weekday office UTC+7", bkk, []FwTime{{Days: []string{"mon", "tue", "wed", "thu", "fri"}, Time: "08:00-17:30"}},
			[]string{"meta day { Monday, Tuesday, Wednesday, Thursday, Friday } meta hour 3600-37799"}},
		{"crosses UTC midnight", bkk, []FwTime{{Days: []string{"mon"}, Time: "05:00-09:00"}},
			[]string{"meta day { Monday } meta hour 0-7199", "meta day { Sunday } meta hour 79200-86399"}},
		{"kernel tz UTC+7", fwClock{LocalOff: 7 * 3600, KernelMW: -420}, []FwTime{{Days: []string{"mon"}, Time: "05:00-09:00"}},
			[]string{"meta day { Monday } meta hour 0-7199", "meta day { Monday } meta hour 79200-86399"}},
		{"UTC sunday late", fwClock{}, []FwTime{{Days: []string{"sun"}, Time: "22:00-24:00"}}, []string{"meta day { Sunday } meta hour 79200-86399"}},
		{"UTC-5 saturday night into sunday", fwClock{LocalOff: -5 * 3600}, []FwTime{{Days: []string{"sat"}, Time: "23:00-01:00"}},
			[]string{"meta day { Sunday } meta hour 14400-21599"}},
		{"week wrap", fwClock{LocalOff: -3600}, []FwTime{{Days: []string{"sat"}, Time: "23:30-24:00"}},
			[]string{"meta day { Sunday } meta hour 1800-3599"}},
	}
	for _, tc := range cases {
		got := fwTimeMatches(tc.sch, tc.clk)
		if strings.Join(got, "|") != strings.Join(tc.want, "|") {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestTZOffset(t *testing.T) {
	d := func(s string) time.Time { x, _ := time.Parse(time.RFC3339, s); return x }
	cases := []struct {
		tz   string
		at   string
		want int
	}{
		{"<+07>-7", "2026-07-01T00:00:00Z", 7 * 3600},
		{"ICT-7", "2026-01-01T00:00:00Z", 7 * 3600},
		{"UTC0", "2026-01-01T00:00:00Z", 0},
		{"", "2026-01-01T00:00:00Z", 0},
		{"<+0530>-5:30", "2026-01-01T00:00:00Z", 5*3600 + 1800},
		{"<-03>3", "2026-01-01T00:00:00Z", -3 * 3600},
		{"CET-1CEST,M3.5.0,M10.5.0/3", "2026-01-15T12:00:00Z", 3600},
		{"CET-1CEST,M3.5.0,M10.5.0/3", "2026-07-01T12:00:00Z", 7200},
		{"CET-1CEST,M3.5.0,M10.5.0/3", "2026-03-29T00:59:59Z", 3600}, // last Sunday of March, 02:00 CET = 01:00 UTC
		{"CET-1CEST,M3.5.0,M10.5.0/3", "2026-03-29T01:00:00Z", 7200},
		{"CET-1CEST,M3.5.0,M10.5.0/3", "2026-10-25T00:59:59Z", 7200}, // 03:00 CEST = 01:00 UTC
		{"CET-1CEST,M3.5.0,M10.5.0/3", "2026-10-25T01:00:00Z", 3600},
		{"EST5EDT,M3.2.0,M11.1.0", "2026-07-01T12:00:00Z", -4 * 3600},
		{"EST5EDT,M3.2.0,M11.1.0", "2026-12-01T12:00:00Z", -5 * 3600},
		{"AEST-10AEDT,M10.1.0,M4.1.0/3", "2026-01-15T00:00:00Z", 11 * 3600}, // southern hemisphere
		{"AEST-10AEDT,M10.1.0,M4.1.0/3", "2026-07-15T00:00:00Z", 10 * 3600},
		{"garbage", "2026-07-15T00:00:00Z", 0},
	}
	for _, tc := range cases {
		if got := tzOffset(tc.tz, d(tc.at)); got != tc.want {
			t.Errorf("tzOffset(%q, %s) = %d, want %d", tc.tz, tc.at, got, tc.want)
		}
	}
}

func TestFwIID(t *testing.T) {
	for in, want := range map[string]string{
		"::10": "::10", "::211:32ff:fe12:3456": "::211:32ff:fe12:3456", "0::0:0:1:2": "::1:2",
		"::ffff:1.2.3.4": "::ffff:102:304", "::1:0:0:0": "::1:0:0:0",
		"2001:db8::1": "", "::": "", "10.0.0.1": "", "::1/64": "", "x": "",
	} {
		if got := fwParseIID(in); got != want {
			t.Errorf("fwParseIID(%q) = %q, want %q", in, got, want)
		}
	}
	if got := fwEUI64("00:11:32:12:34:56"); got != "::211:32ff:fe12:3456" {
		t.Errorf("EUI-64 = %q", got)
	}
	if got := fwEUI64("02:00:00:00:00:01"); got != "::ff:fe00:1" {
		t.Errorf("EUI-64 (U/L bit) = %q", got)
	}
}

func TestFwAccessElements(t *testing.T) {
	c := fwLabConfig(t)
	c.DHCP.Hosts = append(c.DHCP.Hosts, Host{Name: "tv", MAC: "aa:bb:cc:dd:ee:03", IP: "192.168.1.80"})
	got := fwAccessElements(c, []fwNeigh{
		{Dst: "192.168.1.101", LLAddr: "AA:BB:CC:DD:EE:01"},
		{Dst: "2001:db8:1::5", LLAddr: "aa:bb:cc:dd:ee:02"},
		{Dst: "fe80::1", LLAddr: "aa:bb:cc:dd:ee:02"},             // link-local: never forwarded
		{Dst: "192.168.1.9", LLAddr: "11:22:33:44:55:66"},         // not controlled
		{Dst: "192.168.1.77; flush", LLAddr: "aa:bb:cc:dd:ee:01"}, // garbage is dropped, never rendered
		{Dst: "192.168.1.120", LLAddr: "aa:bb:cc:dd:ee:05"},       // disabled entry
	}, []fwLearnedElem{ // learned before the reload: offload exclusion only, remaining lifetime kept
		{"192.168.1.33", 3600}, {"2001:db8:1::77", 100}, {"bogus }", 50},
		{"192.168.1.101", 20}, // also in the neighbour table: seen now, full timeout
		{"192.168.1.44", 0},   // expiring: dropped
	})
	want := "add element inet mr ac0_4 { 192.168.1.101 }\n" +
		"add element inet mr ac0_6 { 2001:db8:1::5 }\n" +
		"add element inet mr ac1_4 { 192.168.1.80 }\n" +
		"add element inet mr ac_4 { 192.168.1.33 timeout 3600s, 192.168.1.101, 192.168.1.80 }\n" +
		"add element inet mr ac_6 { 2001:db8:1::77 timeout 100s, 2001:db8:1::5 }\n"
	if got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
	if s := fwAccessElements(testConfig(t), nil, []fwLearnedElem{{"192.168.1.33", 10}}); s != "" {
		t.Errorf("no access entries: %q", s)
	}
	j := `{"nftables": [{"metainfo": {}}, {"set": {"family": "inet", "name": "ac_4", "table": "mr", "type": "ipv4_addr",
	  "elem": [{"elem": {"val": "192.168.1.80", "timeout": 21600, "expires": 21590}}, {"elem": {"val": "192.168.1.82", "expires": 7}},
	    {"elem": {"val": "192.168.1.83"}}, "192.168.1.81"]}}]}`
	if got := fwSetElems([]byte(j)); len(got) != 2 || got[0] != (fwLearnedElem{"192.168.1.80", 21590}) || got[1] != (fwLearnedElem{"192.168.1.82", 7}) {
		t.Errorf("fwSetElems = %+v", got)
	}
}

// IPv4-mapped IPv6 would be printed as plain IPv4 inside an ip6 match, which nft rejects.
func TestFwAddrsRejectsMapped(t *testing.T) {
	for _, x := range []string{"::ffff:192.0.2.1", "::ffff:192.0.2.0/120", "::ffff:0:0/96", "192.0.2.1/33", "fe80::1%eth0"} {
		if _, _, ok := fwAddrs([]string{x}); ok {
			t.Errorf("fwAddrs accepted %q", x)
		}
	}
	v4, v6, ok := fwAddrs([]string{"192.0.2.1", "198.51.100.0/24", "2001:db8::1", "::/0", "::1.2.3.4"})
	if !ok || strings.Join(v4, ",") != "192.0.2.1,198.51.100.0/24" || strings.Join(v6, ",") != "2001:db8::1,::/0,::102:304" {
		t.Errorf("fwAddrs = %v %v %v", v4, v6, ok)
	}
	c := fwLabConfig(t)
	c.Firewall.IPv6Allow[0].SrcIP = []string{"::ffff:203.0.113.0/120"}
	if !strings.Contains(strings.Join(c.Validate(), "\n"), "ipv6_allow[0].src_ip") {
		t.Error("IPv4-mapped pinhole source accepted")
	}
}

func TestFwParseCounters(t *testing.T) {
	j := `{"nftables": [{"metainfo": {"json_schema_version": 1}}, {"table": {"family": "inet", "name": "mr"}},
	 {"rule": {"family": "inet", "table": "mr", "chain": "forward", "handle": 7, "comment": "access:kid",
	   "expr": [{"match": {}}, {"counter": {"packets": 3, "bytes": 180}}, {"drop": null}]}},
	 {"rule": {"family": "inet", "table": "mr", "chain": "forward", "handle": 8, "comment": "access:kid",
	   "expr": [{"counter": {"packets": 2, "bytes": 100}}, {"drop": null}]}},
	 {"rule": {"family": "inet", "table": "mr", "chain": "input", "handle": 9, "comment": "lucky-https", "expr": [{"accept": null}]}},
	 {"rule": {"family": "inet", "table": "mr", "chain": "input", "handle": 10, "expr": [{"counter": {"packets": 1, "bytes": 1}}]}}]}`
	got := fwParseCounters([]byte(j))
	if len(got) != 1 || got["access:kid"] != (fwCounter{5, 280}) {
		t.Errorf("counters = %+v", got)
	}
	if lines := fwLogLines("[1.0] x\n[2.0] mr-drop wan-in: IN=pppoe-wan SRC=1.2.3.4\n[3.0] mr-rule a: IN=br-lan\n", 1); len(lines) != 1 || !strings.Contains(lines[0], "mr-rule a") {
		t.Errorf("log lines = %q", lines)
	}
}

// Every hook must still be emitted with all fw features on (module_test checks the base config).
func TestFwHooksWithEverything(t *testing.T) {
	fixedClock(t, 0)
	c := fwLabConfig(t)
	seen := map[string]bool{}
	register(&Module{Name: "probe", Prio: 99, Nft: func(c *Config, hook string, n *Nft) { seen[hook] = true }})
	defer func() { modules = modules[:len(modules)-1] }()
	renderNft(c, func(string) bool { return true })
	for _, h := range nftHooks {
		if !seen[h] {
			t.Errorf("hook %q not emitted", h)
		}
	}
}
