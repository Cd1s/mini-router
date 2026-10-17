package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func testConfig(t *testing.T) *Config {
	t.Helper()
	c, err := loadConfig("../examples/router.yaml", "testdata/secrets.yaml")
	if err != nil {
		t.Fatal(err)
	}
	abs, _ := filepath.Abs("testdata/split.domains")
	c.DNS.Split[0].DomainsFile = abs
	return c
}

func TestExampleValidates(t *testing.T) {
	c := testConfig(t)
	if errs := c.Validate(); len(errs) > 0 {
		t.Fatalf("example invalid:\n%s", strings.Join(errs, "\n"))
	}
}

func TestRender(t *testing.T) {
	c := testConfig(t)
	files, err := Render(c)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, f := range files {
		got[f.Path] = f.Data
	}
	want := map[string][]string{
		"/etc/ppp/peers/wan":             {"nic-wan", "ifname pppoe-wan", "usepeerdns", "+ipv6", `password "test-pw-not-real"`},
		"/etc/ppp/peers/wan2":            {"ifname pppoe-wan2", "ipparam wan2"},
		"/etc/dnsmasq.conf":              {"dhcp-range=set:lan,192.168.1.100,192.168.1.249,255.255.255.0,12h", "dhcp-option=tag:lan,option:router,192.168.1.6", "dhcp-host=02:c3:06:d6:7f:8a,192.168.1.66,desktop", "min-cache-ttl=3600", "resolv-file=" + ResolvPPP + "\nresolv-file=" + resolvConf, "use-stale-cache=3600", "servers-file=" + GenDir + "/dns-split.servers", "enable-ra"},
		GenDir + "/dns-split.servers":    {"server=/example-a.com/127.0.0.1#5453", "server=/example-b.net/127.0.0.1#5453", "server=/example-c.org/127.0.0.1#5453"},
		"/etc/hostapd/hostapd-phy1.conf": {"country_code=PA", "channel=36", "vht_oper_centr_freq_seg0_idx=50", "he_oper_chwidth=2", "[VHT160]", "wpa_key_mgmt=SAE WPA-PSK WPA-PSK-SHA256", "interface=phy1-ap0", "[HT40+]", "he_bss_color="},
		"/etc/modprobe.d/mt7915e.conf":   {"options mt7915e wed_enable=1"},
		"/etc/hostapd/hostapd-phy0.conf": {"hw_mode=g", "channel=0", "chanlist=1-11", "[HT40+]", "noscan=1"},
		"/etc/dhcpcd.conf":               {"interface pppoe-wan2", "ia_pd 2 br-lan/0/64/1"},
		GenDir + "/network.sh":           {"ip link set wan address a4:a9:30:6e:2b:89", "ip -4 rule add fwmark 0x102 lookup 102 pref 5300", "ip -6 rule add fwmark 0x200 lookup 200 pref 5300", "p=$(mr_phy 2);", "iw phy \"$p\" interface add phy1-ap0 type __ap"},
		GenDir + "/wifi-post.sh":         {"iw dev phy1-ap0 set txpower fixed 3000"},
	}
	for path, subs := range want {
		data, ok := got[path]
		if !ok {
			t.Errorf("missing %s", path)
			continue
		}
		for _, s := range subs {
			if !strings.Contains(data, s) {
				t.Errorf("%s: missing %q", path, s)
			}
		}
	}
}

func TestNft(t *testing.T) {
	c := testConfig(t)
	all := renderNft(c, func(string) bool { return true })
	for _, s := range []string{
		`iifname { "pppoe-wan", "pppoe-wan2" } tcp dport 45000-45100 dnat ip to 192.168.1.241`,
		`iifname { "pppoe-wan", "pppoe-wan2" } tcp dport 7443 dnat ip to 192.168.1.66:9999`,
		`udp dport 46001-46020 dnat ip to 192.168.1.237`,
		`ether saddr 02:c3:06:d6:7f:8a ip daddr != 192.168.1.0/24 ct state new ct mark set 0x102 meta mark set 0x102`,
		`ip6 daddr != @lan6 ct state new ct mark set 0x102 meta mark set 0x102`,
		`iifname "pppoe-wan" ct state new ct mark set 0x200`,
		`iifname "pppoe-wan2" ct state new ct mark set 0x102`,
		`iifname "br-lan" ct mark != 0x0 meta mark set ct mark return`,
		`flags offload`, `"phy1-ap0"`, `masquerade`, `dport 41641 accept`,
		`dnat ip to 192.168.1.6 comment "dns-redirect"`,
	} {
		if !strings.Contains(all, s) {
			t.Errorf("nft missing %q", s)
		}
	}
	none := renderNft(c, func(d string) bool { return !strings.HasPrefix(d, "pppoe-") && !strings.HasSuffix(d, "-ap0") })
	if strings.Contains(none, `"pppoe-wan"`+", ") && strings.Contains(none, "devices = {") && strings.Contains(none, `"phy1-ap0"`) {
		t.Error("flowtable must only list present devices")
	}
}

func TestValidateCatchesErrors(t *testing.T) {
	c := testConfig(t)
	c.Firewall.Forwards[0].To = "10.0.0.5"
	c.WiFi.Radios[1].Channel = "140"
	c.WiFi.Radios[1].HTMode = "HE160"
	c.DHCP.Hosts = append(c.DHCP.Hosts, Host{Name: "dup", MAC: "aa:bb:cc:dd:ee:ff", IP: "192.168.1.66"})
	errs := strings.Join(c.Validate(), "\n")
	for _, s := range []string{"must be an IPv4 inside", "cannot carry HE160", "duplicate 192.168.1.66"} {
		if !strings.Contains(errs, s) {
			t.Errorf("expected error containing %q, got:\n%s", s, errs)
		}
	}
}

func TestCenterChan(t *testing.T) {
	cases := map[[2]string]int{{"36", "HE160"}: 50, {"64", "HE160"}: 50, {"100", "HE160"}: 114, {"149", "HE80"}: 155, {"44", "HE80"}: 42, {"40", "HE40"}: 38, {"149", "HE160"}: 163, {"140", "HE160"}: 0}
	for k, want := range cases {
		n := atoi(k[0])
		if got := centerChan(n, k[1]); got != want {
			t.Errorf("centerChan(%s,%s)=%d want %d", k[0], k[1], got, want)
		}
	}
}

func TestHostapdUpstreamCompatible(t *testing.T) {
	c := testConfig(t)
	for _, r := range c.WiFi.Radios {
		s, err := renderHostapd(c, r)
		if err != nil {
			t.Fatal(err)
		}
		// noscan is the one OpenWrt patch our hostapd carries (build/hostapd); everything else must be upstream
		for _, bad := range []string{"ht_coex=", "he_bss_color=128"} {
			if strings.Contains(s, bad) {
				t.Errorf("%s: OpenWrt-only option %q", r.Phy, bad)
			}
		}
		if n := bssColor(r.Phy); n < 1 || n > 63 {
			t.Errorf("bss color %d out of range", n)
		}
	}
}

func TestStaticRoutesAndMulticast(t *testing.T) {
	c := testConfig(t)
	c.Routes = []Route{{Name: "lab", Target: "10.9.0.0/16", Via: "192.168.1.50"}, {Name: "v6", Target: "2001:db8::/32", Dev: "pppoe-wan"}}
	c.Mcast = Mcast{Snooping: true, IGMPProxy: true, Upstream: "wan2"}
	if errs := c.Validate(); len(errs) > 0 {
		t.Fatal(errs)
	}
	files, err := Render(c)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, f := range files {
		got[f.Path] = f.Data
	}
	for p, subs := range map[string][]string{
		GenDir + "/network.sh": {"ip -4 route replace 10.9.0.0/16 via 192.168.1.50", "ip -6 route replace 2001:db8::/32 dev pppoe-wan", "echo 1 > /sys/class/net/br-lan/bridge/multicast_snooping"},
		"/etc/igmpproxy.conf":  {"phyint pppoe-wan2 upstream", "phyint br-lan downstream", "phyint pppoe-wan disabled"},
		GenDir + "/services":   {"igmpproxy"},
	} {
		for _, s := range subs {
			if !strings.Contains(got[p], s) {
				t.Errorf("%s missing %q", p, s)
			}
		}
	}
	if !strings.Contains(renderNft(c, func(string) bool { return true }), `iifname "pppoe-wan2" ip daddr 224.0.0.0/4 accept`) {
		t.Error("nft: multicast from upstream not accepted")
	}
	c.Routes = []Route{{Name: "bad", Target: "10.0.0.0/8", Via: "2001:db8::1"}}
	c.Mcast.Upstream = "nope"
	errs := strings.Join(c.Validate(), "\n")
	for _, s := range []string{"same family", "unknown wan \"nope\""} {
		if !strings.Contains(errs, s) {
			t.Errorf("want error %q in:\n%s", s, errs)
		}
	}
}
