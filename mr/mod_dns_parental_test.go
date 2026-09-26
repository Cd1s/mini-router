package main

import (
	"strings"
	"testing"
)

func TestParental(t *testing.T) {
	c := devConfig(t)
	c.DNS.Parental = Parental{Devices: []string{"group:kids"}, SafeSearch: true, Block: []string{"Games.example"}}
	c.defaults()
	if errs := c.Validate(); len(errs) > 0 {
		t.Fatal(errs)
	}
	f := renderMap(t, c)
	mustContain(t, "parental-dns.conf", f[parentalConf], "port=5356\n", "interface=br-lan\n", "no-resolv\n", "server=127.0.0.1#53\n",
		"address=/www.google.com/216.239.38.120\n", "local=/games.example/\n")
	mustContain(t, "services", f[GenDir+"/services"], "mr-parental-dns\n")
	mustContain(t, "nft", renderNft(c, allExist), `ether saddr { aa:bb:cc:00:00:21, aa:bb:cc:00:00:22, aa:bb:cc:00:00:23 } meta l4proto { tcp, udp } th dport 53 redirect to :5356 comment "parental-dns"`)

	c.DNS.Parental.Block = []string{"bad domain", "x.example\nserver=1.2.3.4"}
	c.DNS.Parental.Devices = []string{"nobody"}
	errs := strings.Join(c.Validate(), "\n")
	for _, s := range []string{`dns.parental.block: invalid domain "bad domain"`, `invalid domain "x.example\nserver=1.2.3.4"`, `dns.parental.devices`} {
		if !strings.Contains(errs, s) {
			t.Errorf("want %q in:\n%s", s, errs)
		}
	}
	// the home config: nothing
	if f := renderMap(t, testConfig(t)); f[parentalConf] != "" || strings.Contains(f[GenDir+"/services"], "parental") {
		t.Error("home config renders parental DNS")
	}
}
