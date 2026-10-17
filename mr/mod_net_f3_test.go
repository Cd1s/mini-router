package main

import (
	"os"
	"strings"
	"testing"
)

func TestF3StaticWANOverlapRejected(t *testing.T) {
	c := testConfig(t)
	c.WAN = []WAN{{Name: "hotel", Device: "wan", Proto: "static", IPv4: "192.168.1.10/24", Gateway: "192.168.1.1", Metric: 10}}
	c.defaults()
	errs := c.Validate()
	if !strings.Contains(strings.Join(errs, "\n"), "wan[0].ipv4: overlaps LAN") {
		t.Fatalf("static overlap was accepted: %v", errs)
	}
}

func TestF3ModemRendersAliasRouteAndMasquerade(t *testing.T) {
	c := testConfig(t)
	c.WAN[0].Modem = Modem{Address: "192.168.1.1"}
	c.defaults()
	mustValid(t, c)
	f := renderMap(t, c)
	sh := f[GenDir+"/network.sh"]
	if !strings.Contains(sh, "ip addr replace 192.168.1.2/32 dev wan") {
		t.Errorf("modem alias missing:\n%s", sh)
	}
	if !strings.Contains(sh, "ip route replace 192.168.1.1/32 dev wan") {
		t.Errorf("modem host route missing:\n%s", sh)
	}
	nft := renderNft(c, allExist)
	if !strings.Contains(nft, `ip daddr 192.168.1.1 ip saddr 192.168.1.0/24 masquerade comment "modem:wan"`) {
		t.Errorf("modem masquerade missing:\n%s", nft)
	}
}

func TestF3ModemCanBeOutsideCurrentLAN(t *testing.T) {
	c := &Config{
		System:   System{Hostname: "modemtest"},
		LAN:      LAN{Bridge: "br-lan", Ports: []string{"lan2"}, IPv4: "192.168.77.6/24"},
		WAN:      []WAN{{Name: "wan", Device: "wan", Proto: "pppoe", Username: "u", Password: "pw", Metric: 10, Modem: Modem{Address: "192.168.1.1"}}},
		DNS:      DNS{Upstream: "manual", Servers: []string{"9.9.9.9"}},
		Firewall: Firewall{Offload: "off"},
		DHCP:     DHCP{Start: 100, End: 200, Lease: "12h", Domain: "lan"},
	}
	c.secrets = map[string]string{"pw": "secret"}
	c.defaults()
	mustValid(t, c)
	f := renderMap(t, c)
	if !strings.Contains(f[GenDir+"/network.sh"], "ip addr replace 192.168.1.2/32 dev wan") {
		t.Fatalf("modem alias outside LAN subnet missing:\n%s", f[GenDir+"/network.sh"])
	}
	nft := renderNft(c, allExist)
	if !strings.Contains(nft, `ip daddr 192.168.1.1 ip saddr 192.168.77.0/24 masquerade comment "modem:wan"`) {
		t.Fatalf("modem NAT outside LAN subnet missing:\n%s", nft)
	}
}

func TestF3OverlappingGatewayMasqueradesOnlyGateway(t *testing.T) {
	tempState(t)
	c := testConfig(t)
	writeLease("wan", wanLease{IP: "192.168.1.2", Gateway: "192.168.1.1", Dev: "wan", DNS: []string{"192.168.1.1"}})
	nft := renderNft(c, allExist)
	if !strings.Contains(nft, `ip daddr 192.168.1.1 ip saddr 192.168.1.0/24 masquerade comment "wan-gateway:wan"`) {
		t.Fatalf("overlap gateway NAT missing:\n%s", nft)
	}
	if strings.Contains(nft, `ip saddr 192.168.1.0/24 masquerade comment "wan-gateway:wan"`) && strings.Contains(nft, `ip daddr 192.168.1.2 ip saddr 192.168.1.0/24 masquerade comment "wan-gateway:wan"`) {
		t.Fatal("gateway NAT widened beyond the gateway /32")
	}
}

func TestF3DHCPv6ExpiryKeepsIPv4DNS(t *testing.T) {
	tempState(t)
	c := testConfig(t)
	c.defaults()
	w := c.WANByName("wan")
	writeLease("wan", wanLease{IP: "203.0.113.2", Gateway: "203.0.113.1", DNS: []string{"203.0.113.53"}, DNS6: []string{"2001:db8::53"}, Dev: w.Ifname()})
	if !updateDHCP6DNS(w, "EXPIRE6") {
		t.Fatal("EXPIRE6 did not update DNS6")
	}
	l, ok := readLease("wan")
	if !ok || len(l.DNS) != 1 || l.DNS[0] != "203.0.113.53" || len(l.DNS6) != 0 {
		t.Fatalf("lease after EXPIRE6: %+v", l)
	}
}

func TestF3ModemAddressValidation(t *testing.T) {
	for _, address := range []string{"192.168.1.1/24", "192.168.1.1\naccept", "8.8.8.8", "127.0.0.1", "224.0.0.1"} {
		c := testConfig(t)
		c.WAN[0].Modem = Modem{Address: address}
		c.defaults()
		if len(c.Validate()) == 0 {
			t.Errorf("invalid modem address accepted: %q", address)
		}
	}
}

func TestF3ModemOnlyTrustedLAN(t *testing.T) {
	c := testConfig(t)
	c.Networks = []Network{{Name: "guest", IPv4: "192.168.20.1/24", Zone: "guest"}}
	c.WAN[0].Modem = Modem{Address: "192.168.1.1"}
	c.defaults()
	mustValid(t, c)
	nft := renderNft(c, allExist)
	if strings.Contains(nft, `iifname "br-guest" oifname "wan" ip daddr 192.168.1.1`) {
		t.Fatalf("guest modem access rendered:\n%s", nft)
	}
}

func TestF3GatewayRouteCommands(t *testing.T) {
	got := gatewayRouteCommands("192.168.1.1", "wan", "192.168.1.2", 200)
	joined := make([]string, len(got))
	for i, args := range got {
		joined[i] = strings.Join(args, " ")
	}
	want := []string{
		"ip route replace 192.168.1.1/32 dev wan src 192.168.1.2 metric 0",
		"ip route replace 192.168.1.1/32 dev wan src 192.168.1.2 metric 0 table 200",
	}
	if strings.Join(joined, "\n") != strings.Join(want, "\n") {
		t.Fatalf("gateway route commands:\n%s\nwant:\n%s", strings.Join(joined, "\n"), strings.Join(want, "\n"))
	}
}

func TestF3DHCPv6RuleUsesWANAndPorts(t *testing.T) {
	c := testConfig(t)
	c.WAN[0].IPv6 = true
	c.WAN[1].IPv6 = false
	c.defaults()
	nft := renderNft(c, allExist)
	want := `iifname { "pppoe-wan" } ip6 daddr fe80::/10 udp sport 547 udp dport 546 accept comment "dhcpv6-client"`
	if !strings.Contains(nft, want) {
		t.Fatalf("DHCPv6 rule missing:\n%s", nft)
	}
	if strings.Contains(nft, "ip6 saddr fc00::/6") {
		t.Fatalf("DHCPv6 rule still restricts source:\n%s", nft)
	}
}

func TestF3DNSFallbackRendersAndWritesWhenPeersUnavailable(t *testing.T) {
	c := testConfig(t)
	c.DNS.Fallback = []string{"9.9.9.9"}
	for i := range c.WAN {
		c.WAN[i].PeerDNS = false
		c.WAN[i].DNS = nil
	}
	c.defaults()
	mustValid(t, c)
	f := renderMap(t, c)
	if !strings.Contains(f["/etc/dnsmasq.conf"], "resolv-file=/run/mini-router/resolv.conf") {
		t.Fatalf("isp fallback does not read merged resolv file:\n%s", f["/etc/dnsmasq.conf"])
	}
	tempState(t)
	writeResolv(c)
	b, err := os.ReadFile(resolvConf)
	if err != nil || !strings.Contains(string(b), "nameserver 9.9.9.9") {
		t.Fatalf("fallback resolv.conf: %q (%v)", b, err)
	}
}
