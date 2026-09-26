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

// lan6Events runs lan6Plan over a sequence of bridge states (by bridge) with the WANs' delegated
// prefixes at that moment, as the dhcpcd hook does; it returns every stale announcement and the record.
type lan6Event struct {
	br  map[string][]string
	pds map[string][]netip.Prefix
}

func lan6Events(st lan6State, evs ...lan6Event) (map[string][]string, lan6State) {
	all := map[string][]string{}
	for _, e := range evs {
		var stale map[string][]string
		stale, st = lan6Plan(st, lan6ByWAN(e.br, []string{"wan", "wan2"}, e.pds))
		for k, as := range stale {
			all[k] = append(all[k], as...)
		}
	}
	return all, st
}

var (
	pdA = map[string][]netip.Prefix{"wan": {netip.MustParsePrefix("2001:db8:a::/56")}}
	pdB = map[string][]netip.Prefix{"wan": {netip.MustParsePrefix("2001:db8:b::/56")}}
	up  = func(pd map[string][]netip.Prefix, as ...string) lan6Event {
		return lan6Event{map[string][]string{"br-lan": as}, pd}
	}
	down = lan6Event{map[string][]string{"br-lan": nil}, nil} // release / STOP6 / STOPPED: pd6 and addresses gone
)

// #102: the shutdown events empty the bridge and the pd6 record; the record survives them (no write),
// and the next boot's new prefix announces the old one as stale.
func TestLan6ShutdownThenNewPrefix(t *testing.T) {
	_, st := lan6Events(lan6State{}, up(pdA, "2001:db8:a::1/64"))
	stale, st2 := lan6Events(st, down, down, down)
	if len(stale) != 0 || !reflect.DeepEqual(st2, st) {
		t.Fatalf("shutdown: stale %v, record %v", stale, st2)
	}
	// reboot: the first events come before the delegation, then the new prefix
	stale, st = lan6Events(st2, down, up(pdB, "2001:db8:b::1/64"), up(pdB, "2001:db8:b::1/64"))
	if !reflect.DeepEqual(stale, map[string][]string{"wan br-lan": {"2001:db8:a::1/64"}}) {
		t.Errorf("reboot: stale %v", stale)
	}
	if !reflect.DeepEqual(st.Addrs, map[string][]string{"wan br-lan": {"2001:db8:b::1/64"}}) {
		t.Errorf("record %v", st.Addrs)
	}
	// no record yet: nothing is stale; garbage in the record never reaches ip(8)
	if stale, _ := lan6Events(lan6State{}, up(pdB, "2001:db8:b::1/64")); len(stale) != 0 {
		t.Errorf("no record: stale %v", stale)
	}
	bad := lan6State{Addrs: map[string][]string{"wan br-lan": {"2001:db8:a::1/64 dev eth0", "10.0.0.1/24"}}}
	if stale, _ := lan6Events(bad, up(pdB, "2001:db8:b::1/64")); len(stale) != 0 {
		t.Errorf("garbage: stale %v", stale)
	}
}

// A PPPoE redial within one boot: a new prefix makes the old one stale, the same prefix back does not.
func TestLan6Redial(t *testing.T) {
	_, st := lan6Events(lan6State{}, up(pdA, "2001:db8:a::1/64"))
	if stale, _ := lan6Events(st, down, up(pdA, "2001:db8:a::1/64")); len(stale) != 0 {
		t.Errorf("same prefix: stale %v", stale)
	}
	stale, _ := lan6Events(st, down, up(pdB, "2001:db8:b::1/64"))
	if !reflect.DeepEqual(stale, map[string][]string{"wan br-lan": {"2001:db8:a::1/64"}}) {
		t.Errorf("new prefix: stale %v", stale)
	}
	// both prefixes on the bridge for a moment, then the old one goes
	ab := map[string][]netip.Prefix{"wan": {pdA["wan"][0], pdB["wan"][0]}}
	stale, _ = lan6Events(st, up(ab, "2001:db8:a::1/64", "2001:db8:b::1/64"), up(pdB, "2001:db8:b::1/64"))
	if !reflect.DeepEqual(stale, map[string][]string{"wan br-lan": {"2001:db8:a::1/64"}}) {
		t.Errorf("overlap: stale %v", stale)
	}
}

// Two PPPoE WANs on br-lan (the home config): wan2 is renumbered while wan keeps its prefix; wan's
// prefix is never stale, wan2's old one is once wan2 has delegated again.
func TestLan6PerWAN(t *testing.T) {
	both := func(p2 string, as ...string) lan6Event {
		pds := map[string][]netip.Prefix{"wan": pdA["wan"]}
		if p2 != "" {
			pds["wan2"] = []netip.Prefix{netip.MustParsePrefix(p2)}
		}
		return lan6Event{map[string][]string{"br-lan": as}, pds}
	}
	_, st := lan6Events(lan6State{}, both("2001:db8:c::/56", "2001:db8:a::1/64", "2001:db8:c::1/64"))
	stale, st := lan6Events(st, both("", "2001:db8:a::1/64"), both("2001:db8:d::/56", "2001:db8:a::1/64", "2001:db8:d::1/64"))
	if !reflect.DeepEqual(stale, map[string][]string{"wan2 br-lan": {"2001:db8:c::1/64"}}) {
		t.Errorf("wan2 renumbered: stale %v", stale)
	}
	if !reflect.DeepEqual(st.Addrs, map[string][]string{"wan br-lan": {"2001:db8:a::1/64"}, "wan2 br-lan": {"2001:db8:d::1/64"}}) {
		t.Errorf("record %v", st.Addrs)
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
