package main

// fw module: the nftables ruleset skeleton (table inet mr, see mod_fw_nft.go), zones, flow offload,
// port forwards + NAT loopback, open router ports, IPv6 inbound pinholes, ordered traffic rules,
// device internet access control, masquerade. Owns: router.yaml firewall.
// Other modules add rules through Module.Nft hooks (see nftHooks in module.go); the skeleton must
// keep emitting every hook at its documented place.
//
// Zones (small and fixed, see fwZoneIfs):
//
//	lan    trusted: main LAN, networks with zone lan, tailscale0 — may reach the router and anything
//	guest  internet only: networks with zone guest — router only for DHCP/DNS/ICMP, forward only to wan
//	wan    every WAN L3 interface — input/forward policy drop; only established/related, open ports,
//	       port forwards, IPv6 pinholes and the ICMP the protocols need get in

import (
	"fmt"
	"net"
	"strings"
)

type Firewall struct {
	Offload     string      `yaml:"offload"` // hardware | software | off
	SynFlood    bool        `yaml:"synflood_protect"`
	WANPing     *bool       `yaml:"wan_ping,omitempty"`     // accept ICMPv4 echo from WAN (rate limited); default true
	DropInvalid *bool       `yaml:"drop_invalid,omitempty"` // drop ct state invalid; default true
	LogDrops    bool        `yaml:"log_drops,omitempty"`    // rate-limited kernel log of dropped WAN input
	Forwards    []Forward   `yaml:"forwards"`
	Open        []Open      `yaml:"open"`
	IPv6Allow   []FwV6Allow `yaml:"ipv6_allow"`
	Rules       []FwRule    `yaml:"rules"`
	Access      []FwAccess  `yaml:"access"`
}

// Forward is an IPv4 port forward (DNAT) from WAN to a LAN-side host, with NAT loopback.
type Forward struct {
	Name    string   `yaml:"name"`
	Enabled *bool    `yaml:"enabled,omitempty"` // default true
	Proto   []string `yaml:"proto"`
	Port    string   `yaml:"port"` // external port or range a-b
	To      string   `yaml:"to"`   // LAN-side IPv4, or a device (devices:) with ip
	ToPort  string   `yaml:"to_port"`
	WAN     []string `yaml:"wan,omitempty"`    // only these WANs (default: all)
	SrcIP   []string `yaml:"src_ip,omitempty"` // only these IPv4 sources (default: any)
	Desc    string   `yaml:"desc,omitempty"`
}

// Open opens a port on the router itself to the WAN side (v4 and v6).
type Open struct {
	Name    string   `yaml:"name"`
	Enabled *bool    `yaml:"enabled,omitempty"`
	Proto   []string `yaml:"proto"`
	Port    string   `yaml:"port"` // "443", "8000-8100", "80,443"
	WAN     []string `yaml:"wan,omitempty"`
	SrcIP   []string `yaml:"src_ip,omitempty"` // IPv4 and/or IPv6 CIDRs
	Desc    string   `yaml:"desc,omitempty"`
}

// FwV6Allow is an IPv6 inbound pinhole to a LAN-side host (no NAT on IPv6). The host is matched by
// its interface identifier (low 64 bits), so the rule survives a changing delegated prefix.
type FwV6Allow struct {
	Name    string   `yaml:"name"`
	Enabled *bool    `yaml:"enabled,omitempty"`
	IID     string   `yaml:"iid,omitempty"` // "::10", "::211:32ff:fe12:3456"
	MAC     string   `yaml:"mac,omitempty"` // or: derive the EUI-64 identifier from this MAC
	Proto   []string `yaml:"proto"`
	Port    string   `yaml:"port"`
	SrcIP   []string `yaml:"src_ip,omitempty"` // IPv6 CIDRs
	WAN     []string `yaml:"wan,omitempty"`
	Desc    string   `yaml:"desc,omitempty"`
}

// FwRule is an ordered traffic rule, evaluated for new connections before the zone policy
// (dest router → input chain before the LAN accept; otherwise forward chain, forward_early).
type FwRule struct {
	Name     string   `yaml:"name"`
	Enabled  *bool    `yaml:"enabled,omitempty"`
	Action   string   `yaml:"action"`              // accept | drop | reject
	Src      string   `yaml:"src,omitempty"`       // zone lan | guest | wan; empty = any
	Dest     string   `yaml:"dest,omitempty"`      // zone lan | guest | wan | router; empty = any forwarded
	SrcIP    []string `yaml:"src_ip,omitempty"`    // CIDRs, v4 and/or v6
	SrcMAC   []string `yaml:"src_mac,omitempty"`   // needs a LAN-side source
	DestIP   []string `yaml:"dest_ip,omitempty"`   // CIDRs
	Proto    []string `yaml:"proto,omitempty"`     // tcp | udp | icmp; empty = any
	DestPort string   `yaml:"dest_port,omitempty"` // "25", "8000-8100", "80,443" (tcp/udp only)
	Schedule []FwTime `yaml:"schedule,omitempty"`  // active only in these windows; empty = always
	Counter  bool     `yaml:"counter,omitempty"`
	Log      bool     `yaml:"log,omitempty"` // rate-limited kernel log (prefix "mr-rule <name>: ")
	Desc     string   `yaml:"desc,omitempty"`
}

// FwAccess blocks internet (WAN) access for devices, always or during weekly windows.
type FwAccess struct {
	Name     string   `yaml:"name"`
	Enabled  *bool    `yaml:"enabled,omitempty"`
	MACs     []string `yaml:"macs"`
	Devices  []string `yaml:"devices,omitempty"`  // devices / group:NAME from the inventory (mod_dev.go), with or instead of macs
	Schedule []FwTime `yaml:"schedule,omitempty"` // blocked only in these windows; empty = always blocked
	Desc     string   `yaml:"desc,omitempty"`
}

// FwTime is a weekly window in the router's local time (system.timezone).
type FwTime struct {
	Days []string `yaml:"days,omitempty" json:"days,omitempty"` // mon..sun; empty = every day
	Time string   `yaml:"time,omitempty" json:"time,omitempty"` // "HH:MM-HH:MM", may cross midnight; empty = all day
}

func init() {
	register(&Module{
		Name:     "fw",
		Prio:     40,
		Defaults: fwDefaults,
		Validate: fwValidate,
		Nft:      fwNft,
		API: map[string]func(r apiReq) apiResp{
			"fw.stats": fwAPIStats,
		},
	})
}

func boolp(b bool) *bool { return &b }

// on reports whether an optional "enabled"-style flag is set (nil = default true).
func on(b *bool) bool { return b == nil || *b }

func fwDefaults(c *Config) {
	f := &c.Firewall
	if f.Offload == "" {
		f.Offload = "hardware"
	}
	if f.WANPing == nil {
		f.WANPing = boolp(true)
	}
	if f.DropInvalid == nil {
		f.DropInvalid = boolp(true)
	}
	for i := range f.Forwards {
		if f.Forwards[i].Enabled == nil {
			f.Forwards[i].Enabled = boolp(true)
		}
	}
	for i := range f.Open {
		if f.Open[i].Enabled == nil {
			f.Open[i].Enabled = boolp(true)
		}
	}
	for i := range f.IPv6Allow {
		if f.IPv6Allow[i].Enabled == nil {
			f.IPv6Allow[i].Enabled = boolp(true)
		}
	}
	for i := range f.Rules {
		if f.Rules[i].Enabled == nil {
			f.Rules[i].Enabled = boolp(true)
		}
	}
	for i := range f.Access {
		if f.Access[i].Enabled == nil {
			f.Access[i].Enabled = boolp(true)
		}
	}
}

// ---- validation (the security boundary: everything below ends up in the nft ruleset) ----

const fwMaxList = 64

var (
	reFwTime = lazyRegexp(`^([01][0-9]|2[0-3]):([0-5][0-9])-([01][0-9]|2[0-4]):([0-5][0-9])$`)
	fwDayNum = map[string]int{"sun": 0, "mon": 1, "tue": 2, "wed": 3, "thu": 4, "fri": 5, "sat": 6}
)

func fwValidate(c *Config, v *Validator) {
	f := &c.Firewall
	switch f.Offload {
	case "hardware", "software", "off":
	default:
		v.Add("firewall.offload: hardware|software|off, got %q", f.Offload)
	}

	names := map[string]bool{}
	for i, x := range f.Forwards {
		p := fmt.Sprintf("firewall.forwards[%d]", i)
		fwCheckName(v, p, x.Name, names)
		fwCheckDesc(v, p, x.Desc)
		if !validPorts(x.Port) {
			v.Add("%s.port: invalid %q", p, x.Port)
		}
		if x.ToPort != "" && !validPorts(x.ToPort) {
			v.Add("%s.to_port: invalid %q", p, x.ToPort)
		} else if x.ToPort != "" && x.ToPort != x.Port && strings.Contains(x.Port, "-") && strings.Contains(x.ToPort, "-") {
			v.Add("%s.to_port: a port range maps to the same range or to one port, got %s -> %s", p, x.Port, x.ToPort)
		}
		if d := c.device(x.To); d != nil {
			if d.IP == "" {
				v.Add("%s.to: device %s has no ip (a forward needs a fixed address)", p, x.To)
			}
		} else if net.ParseIP(x.To) == nil && reDevName.MatchString(x.To) {
			v.Add("%s.to: unknown device %q (devices:)", p, x.To)
		} else if err := fwCheckTarget(c, x.To); err != "" {
			v.Add("%s.to: must be an IPv4 inside a LAN-side network (%s) or a device, got %q: %s", p, c.LAN.IPv4, x.To, err)
		}
		if !validProtos(x.Proto) {
			v.Add("%s.proto: tcp/udp list, got %v", p, x.Proto)
		}
		fwCheckWANs(c, v, p, x.WAN)
		if v4, v6, ok := fwAddrs(x.SrcIP); !ok {
			v.Add("%s.src_ip: IPv4 addresses or CIDRs, max %d, got %v", p, fwMaxList, x.SrcIP)
		} else if len(v6) > 0 || (len(x.SrcIP) > 0 && len(v4) == 0) {
			v.Add("%s.src_ip: port forwards are IPv4 only, got %v", p, x.SrcIP)
		}
	}
	fwCheckOverlaps(c, v)

	names = map[string]bool{}
	for i, o := range f.Open {
		p := fmt.Sprintf("firewall.open[%d]", i)
		fwCheckName(v, p, o.Name, names)
		fwCheckDesc(v, p, o.Desc)
		if _, ok := fwPortList(o.Port); !ok {
			v.Add("%s.port: invalid %q", p, o.Port)
		}
		if !validProtos(o.Proto) {
			v.Add("%s.proto: tcp/udp list, got %v", p, o.Proto)
		}
		fwCheckWANs(c, v, p, o.WAN)
		if _, _, ok := fwAddrs(o.SrcIP); !ok {
			v.Add("%s.src_ip: addresses or CIDRs, max %d, got %v", p, fwMaxList, o.SrcIP)
		}
	}

	names = map[string]bool{}
	for i, a := range f.IPv6Allow {
		p := fmt.Sprintf("firewall.ipv6_allow[%d]", i)
		fwCheckName(v, p, a.Name, names)
		fwCheckDesc(v, p, a.Desc)
		if (a.IID == "") == (a.MAC == "") {
			v.Add("%s: set exactly one of iid or mac", p)
		} else if a.MAC != "" && !reMAC.MatchString(a.MAC) {
			v.Add("%s.mac: invalid %q", p, a.MAC)
		} else if a.IID != "" && fwParseIID(a.IID) == "" {
			v.Add("%s.iid: interface identifier like ::10 or ::211:32ff:fe12:3456 (upper 64 bits zero, not ::), got %q", p, a.IID)
		}
		if _, ok := fwPortList(a.Port); !ok {
			v.Add("%s.port: invalid %q", p, a.Port)
		}
		if !validProtos(a.Proto) {
			v.Add("%s.proto: tcp/udp list, got %v", p, a.Proto)
		}
		fwCheckWANs(c, v, p, a.WAN)
		if v4, _, ok := fwAddrs(a.SrcIP); !ok || len(v4) > 0 {
			v.Add("%s.src_ip: IPv6 addresses or CIDRs, max %d, got %v", p, fwMaxList, a.SrcIP)
		}
	}

	names = map[string]bool{}
	for i, r := range f.Rules {
		p := fmt.Sprintf("firewall.rules[%d]", i)
		fwCheckName(v, p, r.Name, names)
		fwCheckDesc(v, p, r.Desc)
		fwCheckRule(c, v, p, r)
	}

	names = map[string]bool{}
	for i, a := range f.Access {
		p := fmt.Sprintf("firewall.access[%d]", i)
		fwCheckName(v, p, a.Name, names)
		fwCheckDesc(v, p, a.Desc)
		for _, m := range a.MACs {
			if !reMAC.MatchString(m) {
				v.Add("%s.macs: invalid %q", p, m)
			}
		}
		devCheckRefs(c, v, p+".devices", a.Devices)
		if n := len(fwAccessMACs(c, a)); n == 0 || n > fwMaxList || len(a.MACs) > fwMaxList {
			v.Add("%s.macs: 1-%d device MACs required (macs and / or devices)", p, fwMaxList)
		}
		fwCheckSchedule(v, p, a.Schedule)
	}
}

func fwCheckName(v *Validator, p, name string, seen map[string]bool) {
	if !reLabel.MatchString(name) {
		v.Add("%s.name: letters, digits, _ . - (1-40), got %q", p, name)
	}
	if seen[name] {
		v.Add("%s.name: duplicate %q", p, name)
	}
	seen[name] = true
}

// fwCheckDesc: descriptions only live in router.yaml / the UI, never in generated files; still no
// control characters and a sane length.
func fwCheckDesc(v *Validator, p, d string) {
	if !safeText(d) || len(d) > 120 {
		v.Add("%s.desc: max 120 characters, no control characters", p)
	}
}

func fwCheckWANs(c *Config, v *Validator, p string, wans []string) {
	seen := map[string]bool{}
	for _, w := range wans {
		if c.WANByName(w) == nil {
			v.Add("%s.wan: unknown wan %q", p, w)
		}
		if seen[w] {
			v.Add("%s.wan: duplicate %q", p, w)
		}
		seen[w] = true
	}
}

// fwCheckTarget: a port-forward target must be a host address inside one LAN-side network
// (guest networks included: the target is then inside that guest network), not the router itself,
// the network or the broadcast address.
func fwCheckTarget(c *Config, to string) string {
	t := net.ParseIP(to)
	if t == nil || t.To4() == nil || strings.Contains(to, ":") {
		return "not an IPv4 address"
	}
	t = t.To4()
	for _, ln := range c.LANNets() {
		rip, nn, err := net.ParseCIDR(ln.IPv4)
		if err != nil || !nn.Contains(t) {
			continue
		}
		bcast := make(net.IP, 4)
		for i := range bcast {
			bcast[i] = nn.IP.To4()[i] | ^nn.Mask[i]
		}
		switch {
		case t.Equal(rip):
			return "that is the router itself"
		case t.Equal(nn.IP), t.Equal(bcast):
			return "network or broadcast address"
		}
		return ""
	}
	return "outside every LAN-side network"
}

// fwCheckOverlaps rejects forwards that can never match because an earlier forward (or an open
// router port, which DNAT would shadow) already takes the same protocol/port on the same WAN.
func fwCheckOverlaps(c *Config, v *Validator) {
	type claim struct {
		what      string
		protos    []string
		lo, hi    int
		wans      map[string]bool
		restrictd bool
	}
	wanSet := func(ws []string) map[string]bool {
		m := map[string]bool{}
		if len(ws) == 0 {
			for _, w := range c.WAN {
				m[w.Name] = true
			}
		}
		for _, w := range ws {
			m[w] = true
		}
		return m
	}
	var claims []claim
	for _, f := range c.Firewall.Forwards {
		if !on(f.Enabled) || !validPorts(f.Port) {
			continue
		}
		lo, hi := portRange(f.Port)
		claims = append(claims, claim{"forward " + f.Name, f.Proto, lo, hi, wanSet(f.WAN), len(f.SrcIP) > 0})
	}
	nfwd := len(claims)
	for _, o := range c.Firewall.Open {
		ps, ok := fwPortList(o.Port)
		if !on(o.Enabled) || !ok {
			continue
		}
		for _, pr := range ps {
			lo, hi := portRange(pr)
			claims = append(claims, claim{"open " + o.Name, o.Proto, lo, hi, wanSet(o.WAN), len(o.SrcIP) > 0})
		}
	}
	for i := 0; i < nfwd; i++ {
		for j := i + 1; j < len(claims); j++ {
			a, b := claims[i], claims[j]
			if a.restrictd || b.restrictd || a.what == b.what || a.hi < b.lo || b.hi < a.lo {
				continue
			}
			common := false
			for w := range a.wans {
				common = common || b.wans[w]
			}
			for _, pa := range a.protos {
				for _, pb := range b.protos {
					if pa == pb && common {
						v.Add("firewall: %s and %s both take %s port %s on the same WAN", a.what, b.what, pa, fmtRange(max(a.lo, b.lo), min(a.hi, b.hi)))
					}
				}
			}
		}
	}
}

func portRange(s string) (int, int) {
	parts := strings.SplitN(s, "-", 2)
	lo := atoi(parts[0])
	hi := lo
	if len(parts) == 2 {
		hi = atoi(parts[1])
	}
	return lo, hi
}

func fmtRange(lo, hi int) string {
	if lo == hi {
		return fmt.Sprint(lo)
	}
	return fmt.Sprintf("%d-%d", lo, hi)
}

func fwCheckRule(c *Config, v *Validator, p string, r FwRule) {
	switch r.Action {
	case "accept", "drop", "reject":
	default:
		v.Add("%s.action: accept|drop|reject, got %q", p, r.Action)
	}
	zoneOK := func(key, z string, extra ...string) {
		ok := z == "" || z == "any" || z == "lan" || z == "wan" || z == "guest"
		for _, e := range extra {
			ok = ok || z == e
		}
		if !ok {
			v.Add("%s.%s: lan|guest|wan%s or empty (any), got %q", p, key, strings.Join(prefixAll("|", extra), ""), z)
		} else if z == "guest" && len(fwZoneIfs(c, "guest")) == 0 {
			v.Add("%s.%s: no network has zone guest", p, key)
		}
	}
	zoneOK("src", r.Src)
	zoneOK("dest", r.Dest, "router")
	if r.Dest == "router" && r.Action == "accept" {
		v.Add("%s: rules towards the router can only drop or reject (open router ports with firewall.open; the LAN is trusted already)", p)
	}
	srcWAN := r.Src == "" || r.Src == "any" || r.Src == "wan"
	if r.Action == "accept" && srcWAN && len(r.DestIP) == 0 && r.DestPort == "" {
		v.Add("%s: an accept rule whose source may be the WAN needs dest_ip or dest_port", p)
	}
	anyZone := func(z string) bool { return z == "" || z == "any" }
	narrow := len(r.SrcIP)+len(r.SrcMAC)+len(r.DestIP)+len(r.Proto) > 0 || r.DestPort != ""
	switch {
	case r.Dest == "router" && !narrow:
		// a whole zone cut off from the router would include the admin's own access
		v.Add("%s: a rule towards the router needs src_ip, src_mac, dest_ip, proto or dest_port", p)
	case anyZone(r.Src) && anyZone(r.Dest) && !narrow:
		v.Add("%s: matches everything; set at least one of src, dest, src_ip, src_mac, dest_ip, proto, dest_port", p)
	}
	for _, m := range r.SrcMAC {
		if !reMAC.MatchString(m) {
			v.Add("%s.src_mac: invalid %q", p, m)
		}
	}
	if len(r.SrcMAC) > fwMaxList {
		v.Add("%s.src_mac: max %d", p, fwMaxList)
	}
	if len(r.SrcMAC) > 0 && r.Src == "wan" {
		v.Add("%s.src_mac: only for LAN-side sources", p)
	}
	s4, s6, ok1 := fwAddrs(r.SrcIP)
	d4, d6, ok2 := fwAddrs(r.DestIP)
	if !ok1 {
		v.Add("%s.src_ip: addresses or CIDRs, max %d, got %v", p, fwMaxList, r.SrcIP)
	}
	if !ok2 {
		v.Add("%s.dest_ip: addresses or CIDRs, max %d, got %v", p, fwMaxList, r.DestIP)
	}
	if ok1 && ok2 && len(fwFamilies(s4, s6, d4, d6, len(r.SrcIP) > 0, len(r.DestIP) > 0)) == 0 {
		v.Add("%s: src_ip and dest_ip have no address family in common", p)
	}
	seen := map[string]bool{}
	for _, x := range r.Proto {
		if x != "tcp" && x != "udp" && x != "icmp" {
			v.Add("%s.proto: tcp|udp|icmp, got %q", p, x)
		}
		if seen[x] {
			v.Add("%s.proto: duplicate %q", p, x)
		}
		seen[x] = true
	}
	if r.DestPort != "" {
		if _, ok := fwPortList(r.DestPort); !ok {
			v.Add("%s.dest_port: invalid %q", p, r.DestPort)
		}
		if len(r.Proto) == 0 || seen["icmp"] {
			v.Add("%s.dest_port: needs proto tcp and/or udp only", p)
		}
	}
	fwCheckSchedule(v, p, r.Schedule)
}

func prefixAll(pre string, xs []string) []string {
	out := make([]string, len(xs))
	for i, x := range xs {
		out[i] = pre + x
	}
	return out
}

func fwCheckSchedule(v *Validator, p string, sch []FwTime) {
	if len(sch) > 16 {
		v.Add("%s.schedule: max 16 windows", p)
	}
	for j, t := range sch {
		q := fmt.Sprintf("%s.schedule[%d]", p, j)
		if len(t.Days) == 0 && t.Time == "" {
			v.Add("%s: set days and/or time", q)
		}
		seen := map[string]bool{}
		for _, d := range t.Days {
			if _, ok := fwDayNum[d]; !ok {
				v.Add("%s.days: mon|tue|wed|thu|fri|sat|sun, got %q", q, d)
			}
			if seen[d] {
				v.Add("%s.days: duplicate %q", q, d)
			}
			seen[d] = true
		}
		if t.Time != "" {
			s, e, ok := fwParseWindow(t.Time)
			if !ok || s == e || (e == 86400 && s == 0) {
				v.Add("%s.time: HH:MM-HH:MM (24h, may cross midnight, not empty), got %q", q, t.Time)
			}
		}
	}
}

// fwParseWindow parses "HH:MM-HH:MM" into seconds since midnight.
func fwParseWindow(s string) (int, int, bool) {
	m := reFwTime.FindStringSubmatch(s)
	if m == nil {
		return 0, 0, false
	}
	start := atoi(m[1])*3600 + atoi(m[2])*60
	end := atoi(m[3])*3600 + atoi(m[4])*60
	if end > 86400 {
		return 0, 0, false
	}
	return start, end, true
}

// fwPortList parses "80", "8000-8100" or "80,443,8000-8100" (max 16 entries).
func fwPortList(s string) ([]string, bool) {
	if s == "" {
		return nil, false
	}
	var out []string
	for _, x := range strings.Split(s, ",") {
		x = strings.TrimSpace(x)
		if !validPorts(x) {
			return nil, false
		}
		out = append(out, x)
	}
	return out, len(out) <= 16
}

// fwAddrs parses addresses / CIDRs and returns them normalized per family (safe to render).
// IPv4-mapped IPv6 ("::ffff:1.2.3.4") is refused: Go prints it as plain IPv4, which nft would reject
// in an ip6 match.
func fwAddrs(xs []string) (v4, v6 []string, ok bool) {
	if len(xs) > fwMaxList {
		return nil, nil, false
	}
	for _, x := range xs {
		var s string
		var is4 bool
		if strings.Contains(x, "/") {
			ip, n, err := net.ParseCIDR(x)
			if err != nil || (ip.To4() != nil && strings.Contains(x, ":")) {
				return nil, nil, false
			}
			is4 = ip.To4() != nil
			s = n.String()
		} else {
			ip := net.ParseIP(x)
			if ip == nil || (ip.To4() != nil && strings.Contains(x, ":")) {
				return nil, nil, false
			}
			is4 = ip.To4() != nil
			s = ip.String()
		}
		if is4 {
			v4 = append(v4, s)
		} else {
			v6 = append(v6, s)
		}
	}
	return dedup(v4), dedup(v6), true
}

// fwFamilies returns the address families ("ip", "ip6") a rule must be rendered for; nil means
// the rule can never match. hasSrc/hasDst say whether src_ip/dest_ip were given at all.
func fwFamilies(s4, s6, d4, d6 []string, hasSrc, hasDst bool) []string {
	var out []string
	if (!hasSrc || len(s4) > 0) && (!hasDst || len(d4) > 0) {
		out = append(out, "ip")
	}
	if (!hasSrc || len(s6) > 0) && (!hasDst || len(d6) > 0) {
		out = append(out, "ip6")
	}
	return out
}

// fwParseIID returns the canonical "::x:x" form of an interface identifier ("" if invalid): an
// IPv6 address whose upper 64 bits are zero and whose lower 64 bits are not.
func fwParseIID(s string) string {
	if !strings.Contains(s, ":") || strings.Contains(s, "/") {
		return ""
	}
	ip := net.ParseIP(s).To16()
	if ip == nil {
		return ""
	}
	nonzero := false
	for i := 0; i < 16; i++ {
		if i < 8 && ip[i] != 0 {
			return ""
		}
		nonzero = nonzero || (i >= 8 && ip[i] != 0)
	}
	if !nonzero {
		return ""
	}
	return fwIIDString(ip[8:])
}

// fwEUI64 derives the modified EUI-64 interface identifier from a MAC (RFC 4291 appendix A).
func fwEUI64(mac string) string {
	hw, err := net.ParseMAC(mac)
	if err != nil || len(hw) != 6 {
		return ""
	}
	iid := []byte{hw[0] ^ 0x02, hw[1], hw[2], 0xff, 0xfe, hw[3], hw[4], hw[5]}
	return fwIIDString(iid)
}

// fwIIDString formats 8 bytes as "::a:b:c:d" in hex groups (leading zero groups dropped, never
// dotted-quad, so it is always read as IPv6).
func fwIIDString(b []byte) string {
	var g []string
	for i := 0; i < 4; i++ {
		v := int(b[2*i])<<8 | int(b[2*i+1])
		if v == 0 && len(g) == 0 && i < 3 {
			continue
		}
		g = append(g, fmt.Sprintf("%x", v))
	}
	return "::" + strings.Join(g, ":")
}

// iid returns the rendered interface identifier of a pinhole.
func (a FwV6Allow) iid() string {
	if a.MAC != "" {
		return fwEUI64(a.MAC)
	}
	return fwParseIID(a.IID)
}

// fwZoneIfs returns the interfaces of a firewall zone (see the package comment).
func fwZoneIfs(c *Config, zone string) []string {
	var out []string
	switch zone {
	case "lan":
		for _, ln := range c.LANNets() {
			if ln.Zone == "lan" {
				out = append(out, ln.Bridge)
			}
		}
		out = append(out, "tailscale0")
	case "guest":
		for _, ln := range c.LANNets() {
			if ln.Zone == "guest" {
				out = append(out, ln.Bridge)
			}
		}
	case "wan":
		out = c.WANIfnames()
	}
	return out
}
