package main

// sys module, DDNS: where a record's address comes from (services.ddns.records[].ipv4 / ipv6).
//
//	ipv4: active | <wan> — the WAN lease records (mod_sys_ddns.go ddnsIPv4)
//	ipv6: router | ::IID — the delegated prefix (ddnsIPv6)
//	url:https://…        — an external lookup ("what is my address"): the first address of the family in
//	                       the answer. IPv4 goes out from the address of the WAN `active` would pick
//	                       (healthy first, lowest metric; a private / CGNAT address counts here — that is
//	                       what a lookup is for: the router behind another NAT), so the WAN's policy rule
//	                       (from <address> lookup <its table>) sends it through that WAN and the answer is
//	                       that WAN's public address; without a WAN address, the default route. IPv6 uses
//	                       the default route. Once per URL and sync; `mr ddns status` and the web UI show
//	                       the result of the last sync (they never contact anyone).
//	mac:MAC              — a LAN device: IPv4 from its DHCP lease (else the neighbour table, else its
//	                       fixed address); IPv6 its global address in a LAN prefix from the neighbour
//	                       table — inside the delegated prefix of the WAN a policy route pins the device to
//	                       (policy_routes mac / device without dst / domains, first match) when it has one
//	                       there (Cd1s/mini-router#108); among those the EUI-64 one if there is one, else
//	                       the one published before while it is still there, else the lowest (privacy
//	                       addresses change: give such a device a stable address, or use ::IID).
//	a fixed address      — published as is (IPv4: public only).
//
// Private (RFC 1918, link-local) and CGNAT IPv4 addresses are never published, whatever the source.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

// test hooks: the neighbour table, the DHCP lease file, the HTTP client of a lookup
var (
	ddnsNeigh = func() []monNeigh {
		nb, _ := monNeighbours()
		return nb
	}
	ddnsLeaseFile = LeaseFile
	// ddnsLookupHTTP: a client that dials only network (tcp4 / tcp6), from local when set
	ddnsLookupHTTP = func(network string, local net.IP) *http.Client {
		d := &net.Dialer{Timeout: 10 * time.Second}
		if local != nil {
			d.LocalAddr = &net.TCPAddr{IP: local}
		}
		tr := ddnsTransport()
		tr.DialContext = func(ctx context.Context, _, addr string) (net.Conn, error) { return d.DialContext(ctx, network, addr) }
		tr.ForceAttemptHTTP2 = true
		return &http.Client{Timeout: 20 * time.Second, Transport: tr, CheckRedirect: ddnsNoRedirect}
	}
)

const ddnsLookupMax = 4 << 10 // answer bytes read from a lookup URL

// ddnsKind: what an ipv4 / ipv6 value names — off, active, wan (a WAN name), router, iid (::IID),
// url, mac, ip (a fixed address) — or "" (nothing valid).
func ddnsKind(v string, v6 bool) string {
	switch {
	case v == "off":
		return "off"
	case strings.HasPrefix(v, "url:"):
		return "url"
	case strings.HasPrefix(v, "mac:"):
		return "mac"
	case !v6 && v == "active":
		return "active"
	case v6 && v == "router":
		return "router"
	case v6 && ddnsIID(v) != nil:
		return "iid"
	}
	if ip := net.ParseIP(v); ip != nil && (ip.To4() == nil) == v6 && strings.Contains(v, ":") == v6 {
		return "ip"
	}
	if !v6 {
		return "wan"
	}
	return ""
}

// ddnsPublic: whether ip may be published as is (IPv4: public unicast; IPv6: global unicast, not ULA).
func ddnsPublic(ip net.IP) bool {
	if ip == nil || !ip.IsGlobalUnicast() {
		return false
	}
	if a := ip.To4(); a != nil {
		return addrClass(a.String()) == "" && a[0] != 0 && a[0] < 240
	}
	return !ulaNet.Contains(ip)
}

// ddnsSrcOK: whether an ipv4 / ipv6 value is valid, and if not, why (" (reason)" or "").
func ddnsSrcOK(c *Config, v string, v6 bool) (bool, string) {
	switch ddnsKind(v, v6) {
	case "off", "active", "router", "iid":
		return true, ""
	case "wan":
		return reName.MatchString(v) && c.WANByName(v) != nil, " (no such WAN)"
	case "url":
		if p := ddnsURLProblem(strings.TrimPrefix(v, "url:"), false); p != "" {
			return false, " (" + p + ")"
		}
		return true, ""
	case "mac":
		m := strings.TrimPrefix(v, "mac:")
		hw, err := net.ParseMAC(m)
		return err == nil && reMAC.MatchString(m) && hw[0]&1 == 0, " (not a unicast MAC)"
	case "ip":
		if v6 {
			return ddnsPublic(net.ParseIP(v)), " (not a global address)"
		}
		return ddnsPublic(net.ParseIP(v)), " (private, CGNAT and reserved addresses are never published)"
	}
	return false, ""
}

// ddnsSrc resolves the values of one run: a sync (online: url: sources are looked up, once per URL
// and family) or a status (offline: a url: source shows the last sync's result).
type ddnsSrc struct {
	c      *Config
	online bool
	urls   map[string][2]string
	neigh  []monNeigh
	nbRead bool
}

// local: the address r publishes as typ now, or "" and why not. prev is the record's state (the url:
// result of the last sync, the IPv6 address a mac: source published).
func (x *ddnsSrc) local(r DDNSRecord, typ string, prev *ddnsState) (string, string) {
	v6 := typ == "AAAA"
	v := ddnsSource(r, typ)
	switch ddnsKind(v, v6) {
	case "url":
		if !x.online {
			if prev != nil && (prev.Local != "" || prev.Note != "") {
				return prev.Local, prev.Note
			}
			return "", "looked up at the next sync"
		}
		key := typ + " " + v
		if res, ok := x.urls[key]; ok {
			return res[0], res[1]
		}
		ip, note := ddnsLookup(x.c, strings.TrimPrefix(v, "url:"), v6)
		if x.urls == nil {
			x.urls = map[string][2]string{}
		}
		x.urls[key] = [2]string{ip, note}
		return ip, note
	case "mac":
		return x.byMAC(strings.ToLower(strings.TrimPrefix(v, "mac:")), v6, prev)
	case "ip":
		return net.ParseIP(v).String(), ""
	case "off", "":
		return "", ""
	}
	if v6 {
		return ddnsIPv6(x.c, v)
	}
	return ddnsIPv4(x.c, v)
}

// ddnsWANAddr4: the IPv4 address of the WAN `active` would use (healthy first, by metric), whatever
// its class; nil without one.
func ddnsWANAddr4(c *Config) net.IP {
	for _, w := range sortedWANs(c, wanHealthMap(c)) {
		if l, ok := readLease(w.Name); ok {
			if a := net.ParseIP(l.IP).To4(); a != nil && !a.IsUnspecified() && !a.IsLoopback() {
				return a
			}
		}
	}
	return nil
}

// ddnsLookup asks raw for the router's public address of the family.
func ddnsLookup(c *Config, raw string, v6 bool) (string, string) {
	network, local := "tcp4", ddnsWANAddr4(c)
	if v6 {
		network, local = "tcp6", nil
	}
	host := raw
	if u, err := url.Parse(raw); err == nil {
		host = u.Host
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	ip, err := ddnsFetchIP(ctx, ddnsLookupHTTP(network, local), raw, v6)
	if err != nil {
		return "", "lookup " + host + ": " + ddnsErrText(err)
	}
	if !ddnsPublic(ip) {
		cls := addrClass(ip.String())
		if cls == "" {
			cls = "non-public"
		}
		return "", fmt.Sprintf("lookup %s answered a %s address %s, not published", host, cls, ip)
	}
	return ip.String(), ""
}

// ddnsFetchIP: the first address of the family in the answer to a GET of raw (plain text, JSON or
// HTML: any run of hex digits, dots and colons that parses).
func ddnsFetchIP(ctx context.Context, hc *http.Client, raw string, v6 bool) (net.IP, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", raw, nil)
	if err != nil {
		return nil, errors.New("bad URL")
	}
	req.Header.Set("User-Agent", "mini-router-ddns/"+version)
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, ddnsLookupMax))
	for _, tok := range strings.FieldsFunc(string(b), func(r rune) bool {
		return !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F' || r == '.' || r == ':')
	}) {
		ip := net.ParseIP(strings.Trim(tok, ".:"))
		if tok == "::" || ip == nil || (ip.To4() == nil) != v6 {
			continue
		}
		if !v6 {
			ip = ip.To4()
		}
		return ip, nil
	}
	fam := "IPv4"
	if v6 {
		fam = "IPv6"
	}
	return nil, errors.New("no " + fam + " address in the answer")
}

func (x *ddnsSrc) neighbours() []monNeigh {
	if !x.nbRead {
		x.neigh, x.nbRead = ddnsNeigh(), true
	}
	return x.neigh
}

// byMAC: the address of the LAN device mac (lower case).
func (x *ddnsSrc) byMAC(mac string, v6 bool, prev *ddnsState) (string, string) {
	if !v6 {
		ip := ""
		v4, _ := parseLeases(readFile(ddnsLeaseFile))
		var best int64 = -1
		for _, l := range v4 {
			if strings.EqualFold(l.MAC, mac) {
				exp := l.Expires
				if exp == 0 {
					exp = 1 << 62 // infinite
				}
				if exp > best {
					best, ip = exp, l.IP
				}
			}
		}
		if ip == "" {
			for _, n := range x.neighbours() {
				if n.MAC == mac && n.Addr.Is4() {
					ip = n.Addr.String()
					break
				}
			}
		}
		if ip == "" {
			for _, h := range x.c.knownHosts() {
				if strings.EqualFold(h.MAC, mac) && h.IP != "" {
					ip = h.IP
				}
			}
		}
		if ip == "" {
			return "", "no DHCP lease or neighbour entry for " + mac
		}
		if a := net.ParseIP(ip); !ddnsPublic(a) {
			cls := addrClass(ip)
			if cls == "" {
				cls = "non-public"
			}
			return "", fmt.Sprintf("%s has the %s address %s, not published", mac, cls, ip)
		}
		return ip, ""
	}
	// IPv6: the device's global addresses inside a /64 of the LAN bridges' global addresses (a stale
	// neighbour entry from an old prefix does not count)
	var pfx []*net.IPNet
	for _, br := range x.c.LANBridges() {
		for _, a := range ddnsAddrs6(br) {
			pfx = append(pfx, &net.IPNet{IP: a.Mask(net.CIDRMask(64, 128)), Mask: net.CIDRMask(64, 128)})
		}
	}
	if len(pfx) == 0 {
		return "", "no global IPv6 prefix on the LAN"
	}
	var cands []net.IP
	for _, n := range x.neighbours() {
		if n.MAC != mac || !n.Addr.Is6() || n.Addr.Is4In6() {
			continue
		}
		ip := net.IP(n.Addr.AsSlice())
		if !ddnsPublic(ip) {
			continue
		}
		for _, p := range pfx {
			if p.Contains(ip) {
				cands = append(cands, ip)
				break
			}
		}
	}
	if len(cands) == 0 {
		return "", mac + " has no global IPv6 address in the neighbour table (yet)"
	}
	if pin := ddnsPinnedPrefixes(x.c, mac); len(pin) > 0 {
		var in []net.IP
		for _, ip := range cands {
			for _, p := range pin {
				if p.Contains(ip) {
					in = append(in, ip)
					break
				}
			}
		}
		if len(in) > 0 {
			cands = in
		}
	}
	hw, _ := net.ParseMAC(mac)
	eui := []byte{hw[0] ^ 2, hw[1], hw[2], 0xff, 0xfe, hw[3], hw[4], hw[5]}
	for _, ip := range cands {
		if bytes.Equal(ip[8:], eui) {
			return ip.String(), ""
		}
	}
	if prev != nil {
		for _, ip := range cands {
			if ip.String() == prev.Published {
				return ip.String(), ""
			}
		}
	}
	low := cands[0]
	for _, ip := range cands[1:] {
		if bytes.Compare(ip, low) < 0 {
			low = ip
		}
	}
	return low.String(), ""
}

// ddnsPinnedPrefixes: the recorded delegated prefixes of the WAN the first policy route that pins mac
// (by mac or device, IPv6, every destination) sends it to; nil without one.
func ddnsPinnedPrefixes(c *Config, mac string) []*net.IPNet {
	for _, p := range c.Policy {
		if p.Dst != "" || p.byDomain() || !slices.Contains(policyFams(p), 6) {
			continue
		}
		macs := []string{p.MAC}
		if p.Device != "" {
			macs, _ = devRefMACs(c, p.Device)
		}
		if !slices.ContainsFunc(macs, func(m string) bool { return strings.EqualFold(m, mac) }) {
			continue
		}
		var out []*net.IPNet
		for _, s := range pd6Prefixes(p.Via) {
			if _, n, err := net.ParseCIDR(s); err == nil {
				out = append(out, n)
			}
		}
		return out
	}
	return nil
}
