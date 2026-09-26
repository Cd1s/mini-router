package main

import (
	"net/netip"
	"reflect"
	"strings"
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

// The first dhcpcd events after a boot (PREINIT, CARRIER) come before the delegation: the bridge has
// no prefix yet. Nothing is stale then; the record waits until a prefix arrives, and the one the ISP
// handed out again is never announced as stale.
func TestLan6PlanWaitsForPrefix(t *testing.T) {
	prev := lan6State{Boot: "boot-1", Addrs: map[string][]string{"br-lan": {"2001:db8:1::1/64", "2001:db8:2::1/64"}}}
	stale, next := lan6Plan(prev, "boot-2", map[string][]string{"br-lan": nil})
	if len(stale) != 0 {
		t.Fatalf("no prefix yet: stale %v", stale)
	}
	stale, next = lan6Plan(next, "boot-2", map[string][]string{"br-lan": {"2001:db8:1::1/64"}})
	if !reflect.DeepEqual(stale, map[string][]string{"br-lan": {"2001:db8:2::1/64"}}) {
		t.Errorf("prefix back: stale %v", stale)
	}
	if next.Pending != nil {
		t.Errorf("still pending: %v", next.Pending)
	}
	// judged once only
	if stale, _ = lan6Plan(next, "boot-2", map[string][]string{"br-lan": {"2001:db8:1::1/64"}}); len(stale) != 0 {
		t.Errorf("second event: stale %v", stale)
	}
}

// Two PPPoE WANs delegate to br-lan at different times (the home config): wan2's recorded prefix is
// judged only once wan2 has delegated again, never while only wan's prefix is back.
func TestLan6PlanPerWAN(t *testing.T) {
	wans := []string{"wan", "wan2"}
	pds := map[string][]netip.Prefix{"wan": {netip.MustParsePrefix("2001:db8:a::/56")}}
	prev := lan6State{Boot: "boot-1", Addrs: map[string][]string{"wan br-lan": {"2001:db8:a::1/64"}, "wan2 br-lan": {"2001:db8:b::1/64"}}}
	stale, next := lan6Plan(prev, "boot-2", lan6ByWAN(map[string][]string{"br-lan": {"2001:db8:a::1/64"}}, wans, pds))
	if len(stale) != 0 || !reflect.DeepEqual(next.Pending, map[string][]string{"wan2 br-lan": {"2001:db8:b::1/64"}}) {
		t.Fatalf("only wan back: stale %v, pending %v", stale, next.Pending)
	}
	pds["wan2"] = []netip.Prefix{netip.MustParsePrefix("2001:db8:c::/56")} // wan2 got a new prefix
	stale, next = lan6Plan(next, "boot-2", lan6ByWAN(map[string][]string{"br-lan": {"2001:db8:a::1/64", "2001:db8:c::1/64"}}, wans, pds))
	if !reflect.DeepEqual(stale, map[string][]string{"wan2 br-lan": {"2001:db8:b::1/64"}}) || next.Pending != nil {
		t.Errorf("wan2 renumbered: stale %v, pending %v", stale, next.Pending)
	}
	if !reflect.DeepEqual(next.Addrs, map[string][]string{"wan br-lan": {"2001:db8:a::1/64"}, "wan2 br-lan": {"2001:db8:c::1/64"}}) {
		t.Errorf("record %v", next.Addrs)
	}
}

// RFC 9096: what dnsmasq advertises (min of address lifetime and lease) stays within 2700 s.
func TestRALeaseCap(t *testing.T) {
	var b strings.Builder
	renderRA(&b, "br-lan", RA{Lease: "1d"})
	renderRA(&b, "br-iot", RA{Lease: "30m"})
	renderRA(&b, "br-guest", RA{Lease: "infinite"})
	for _, s := range []string{"constructor:br-lan,ra-only,45m\n", "constructor:br-iot,ra-only,30m\n", "constructor:br-guest,ra-only,45m\n"} {
		if !strings.Contains(b.String(), s) {
			t.Errorf("missing %q in\n%s", s, b.String())
		}
	}
}

func TestRALeaseSecs(t *testing.T) {
	for in, want := range map[string]int{"": 2700, "1800": 1800, "9000": 2700, "30m": 1800, "1h": 2700, "12h": 2700, "infinite": 2700, "90s": 90, "0m": 2700, "99999999999d": 2700} {
		if got := raLeaseSecs(in); got != want {
			t.Errorf("raLeaseSecs(%q) = %d, want %d", in, got, want)
		}
	}
}
