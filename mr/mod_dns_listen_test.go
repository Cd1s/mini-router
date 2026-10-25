package main

import (
	"reflect"
	"strings"
	"testing"
)

// dnsmasq listens on every address of lo as soon as it has an interface= line, one UDP + one TCP socket
// per address. ss-nodes keeps hundreds of /128 source addresses on lo (two prefixes at once while the
// operator's prefix changes), which used up the 1024 descriptors of all three dnsmasq instances: no DNS,
// `mr proxy check` failing, the migration never finishing. They listen on their LAN bridges (bind-dynamic
// follows the prefix) plus the two loopback addresses mr itself uses, and on nothing else on lo.
func TestDnsmasqListensOnBridgesAndLoopbackOnly(t *testing.T) {
	c := proxyTestConfig(t)
	c.Networks = []Network{{Name: "iot", IPv4: "192.168.30.1/24", Zone: "lan", IPv6RA: true}}
	c.Devices = devConfig(t).Devices
	c.Groups = map[string][]string{"kids": {"kid-tablet", "game-console"}}
	c.DNS.Parental = Parental{Devices: []string{"group:kids"}, SafeSearch: true}
	c.defaults()
	if errs := c.Validate(); len(errs) > 0 {
		t.Fatal(errs)
	}
	bridges := c.LANBridges()
	if len(bridges) < 2 {
		t.Fatalf("want two LAN bridges, got %v", bridges)
	}
	f := renderMap(t, c)
	for name, conf := range map[string]string{
		"dnsmasq.conf":      f["/etc/dnsmasq.conf"],
		"proxy-dns.conf":    f[proxyGenDNS],
		"parental-dns.conf": f[parentalConf],
	} {
		if conf == "" {
			t.Fatalf("%s not rendered", name)
		}
		var ifaces, listen, except []string
		for _, l := range strings.Split(conf, "\n") {
			k, v, _ := strings.Cut(l, "=")
			switch k {
			case "interface":
				ifaces = append(ifaces, v)
			case "listen-address":
				listen = append(listen, v)
			case "except-interface":
				except = append(except, v)
			case "bind-interfaces":
				t.Errorf("%s: bind-interfaces would not follow the delegated prefix", name)
			}
		}
		if !reflect.DeepEqual(ifaces, bridges) {
			t.Errorf("%s: interface= lines %v, want the LAN bridges %v", name, ifaces, bridges)
		}
		if !reflect.DeepEqual(except, []string{"lo"}) {
			t.Errorf("%s: except-interface= lines %v, want lo (dnsmasq adds all of lo itself)", name, except)
		}
		if !reflect.DeepEqual(listen, []string{"127.0.0.1", "::1"}) {
			t.Errorf("%s: listen-address= lines %v, want 127.0.0.1 and ::1", name, listen)
		}
		mustContain(t, name, conf, "\nbind-dynamic\n")
	}
}
