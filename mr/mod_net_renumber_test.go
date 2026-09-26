package main

import (
	"reflect"
	"testing"
)

// `ip -j -6 addr show dev BR scope global` as iproute2 prints it (the router's iproute2-minimal too):
// only addresses dnsmasq advertises as current count.
func TestLan6Addrs(t *testing.T) {
	j := []byte(`[{"ifname":"br-lan","addr_info":[
		{"family":"inet6","local":"2001:db8:1::1","prefixlen":64,"scope":"global","dynamic":true,"valid_life_time":2550450,"preferred_life_time":2550450},
		{"family":"inet6","local":"2001:db8:2::1","prefixlen":64,"scope":"global","deprecated":true,"valid_life_time":3600,"preferred_life_time":0},
		{"family":"inet6","local":"2001:db8:3::1","prefixlen":64,"scope":"global","tentative":true,"valid_life_time":3600,"preferred_life_time":3600},
		{"family":"inet6","local":"2001:db8:4::1","prefixlen":64,"scope":"global","valid_life_time":7200,"preferred_life_time":10},
		{"family":"inet6","local":"fe80::1","prefixlen":64,"scope":"link","valid_life_time":4294967295,"preferred_life_time":4294967295},
		{"family":"inet6","local":"2001:db8:5::abcd:1","prefixlen":64,"scope":"global","temporary":true,"valid_life_time":600,"preferred_life_time":600},
		{}]}]`)
	if got := lan6Addrs(j); !reflect.DeepEqual(got, []string{"2001:db8:1::1/64"}) {
		t.Errorf("got %v", got)
	}
}

// Within one boot dnsmasq has seen every change itself; after a reboot, recorded prefixes that did not
// come back are stale (RFC 9096). A bridge that no longer does RA is left alone.
func TestLan6Plan(t *testing.T) {
	prev := lan6State{Boot: "boot-1", Addrs: map[string][]string{
		"br-lan": {"2001:db8:1::1/64", "2001:db8:2::1/64"},
		"br-old": {"2001:db8:9::1/64"},
	}}
	cur := map[string][]string{"br-lan": {"2001:db8:2::1/64", "2001:db8:3::1/64"}, "br-iot": {}}
	stale, next := lan6Plan(prev, "boot-1", cur)
	if len(stale) != 0 {
		t.Errorf("same boot: stale %v", stale)
	}
	if !reflect.DeepEqual(next.Addrs, map[string][]string{"br-lan": {"2001:db8:2::1/64", "2001:db8:3::1/64"}}) || next.Boot != "boot-1" {
		t.Errorf("next record: %+v", next)
	}
	stale, next = lan6Plan(prev, "boot-2", cur)
	if !reflect.DeepEqual(stale, map[string][]string{"br-lan": {"2001:db8:1::1/64"}}) {
		t.Errorf("new boot: stale %v", stale)
	}
	if next.Boot != "boot-2" {
		t.Errorf("next boot %q", next.Boot)
	}
	// no record yet (first boot with this version): nothing is stale
	if stale, _ := lan6Plan(lan6State{}, "boot-2", cur); len(stale) != 0 {
		t.Errorf("no record: stale %v", stale)
	}
	// a garbage record entry is skipped, never passed to ip(8)
	prev.Addrs["br-lan"] = append(prev.Addrs["br-lan"], "2001:db8:1::1/64 dev eth0", "10.0.0.1/24")
	if stale, _ := lan6Plan(prev, "boot-3", cur); !reflect.DeepEqual(stale, map[string][]string{"br-lan": {"2001:db8:1::1/64"}}) {
		t.Errorf("garbage in the record: stale %v", stale)
	}
}

func TestRALeaseSecs(t *testing.T) {
	for in, want := range map[string]int{"": 7200, "1800": 1800, "9000": 7200, "30m": 1800, "1h": 3600, "12h": 7200, "infinite": 7200, "90s": 90, "0m": 7200} {
		if got := raLeaseSecs(in); got != want {
			t.Errorf("raLeaseSecs(%q) = %d, want %d", in, got, want)
		}
	}
}
