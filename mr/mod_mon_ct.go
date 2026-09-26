package main

// Conntrack views: mon.devices (traffic per LAN device) and mon.conns (connection list + totals).
//
// Source: /proc/net/nf_conntrack with byte accounting on (net.netfilter.nf_conntrack_acct=1 in
// /etc/sysctl.d/91-mon.conf; only connections created after it was switched on carry counters).
// Flow-offloaded connections ([OFFLOAD] software fast path, [HW_OFFLOAD] PPE/WED) bypass the
// per-packet accounting: their counters are refreshed by the flowtable GC about once a second and
// only when the flowtable has the `counter` flag, so their numbers lag and move in steps.
//
// Rates are exact per flow: each mon.devices call stores (flow key → bytes) in a RAM snapshot and
// the next call diffs against it, so connections opening/closing between polls do not distort the
// numbers (closed connections stay in the table for TIME_WAIT/CLOSE, with their final counters).

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"math"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	monCTMax      = 30000 // entries parsed per request: bounds the CGI during a conntrack flood
	monConnsLimit = 2000
	monTop        = 10
)

const (
	monCTAssured = 1 << iota
	monCTUnreplied
	monCTOffload   // software flow offload
	monCTHWOffload // hardware flow offload (PPE / WED)
)

type monTuple struct {
	Src, Dst     netip.Addr
	Sport, Dport uint16 // ICMP: Sport = id, Dport = type<<8 | code
}

type monCT struct {
	Fam    int    // 4 | 6
	Proto  string // tcp, udp, icmp, icmpv6, ...
	PNum   int
	TTL    int    // seconds until expiry; -1 while offloaded (the kernel does not print it then)
	State  string // TCP/SCTP/DCCP state, "" for others
	O, R   monTuple
	OP, OB uint64 // original direction (initiator → responder): packets, bytes
	RP, RB uint64 // reply direction
	Flags  int
	Mark   uint32
}

func monIsNum(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
}

// monParseCT parses one /proc/net/nf_conntrack line, e.g.
//
//	ipv4 2 tcp 6 7431 ESTABLISHED src=192.168.1.2 dst=1.1.1.1 sport=5000 dport=443 packets=3 bytes=180
//	  src=1.1.1.1 dst=10.0.0.2 sport=443 dport=5000 packets=2 bytes=120 [ASSURED] mark=0 zone=0 use=2
func monParseCT(line string, e *monCT) bool {
	f := strings.Fields(line)
	if len(f) < 8 {
		return false
	}
	*e = monCT{TTL: -1}
	switch f[0] {
	case "ipv4":
		e.Fam = 4
	case "ipv6":
		e.Fam = 6
	default:
		return false
	}
	e.Proto, e.PNum = f[2], atoi(f[3])
	i := 4
	if monIsNum(f[i]) {
		e.TTL = atoi(f[i])
		i++
	}
	if i < len(f) && !strings.ContainsAny(f[i], "=[") {
		e.State = f[i]
		i++
	}
	side := 0
	for ; i < len(f); i++ {
		tok := f[i]
		switch tok {
		case "[ASSURED]":
			e.Flags |= monCTAssured
			continue
		case "[UNREPLIED]":
			e.Flags |= monCTUnreplied
			continue
		case "[OFFLOAD]":
			e.Flags |= monCTOffload
			continue
		case "[HW_OFFLOAD]":
			e.Flags |= monCTHWOffload
			continue
		}
		k, v, ok := strings.Cut(tok, "=")
		if !ok {
			continue
		}
		if k == "src" {
			side++
			if side > 2 {
				return false
			}
		}
		t := &e.O
		if side == 2 {
			t = &e.R
		}
		n, _ := strconv.ParseUint(v, 10, 64)
		switch k {
		case "src":
			t.Src, _ = netip.ParseAddr(v)
		case "dst":
			t.Dst, _ = netip.ParseAddr(v)
		case "sport":
			t.Sport = uint16(n)
		case "dport":
			t.Dport = uint16(n)
		case "id":
			t.Sport = uint16(n)
		case "type":
			t.Dport |= uint16(n&0xff) << 8
		case "code":
			t.Dport |= uint16(n & 0xff)
		case "packets":
			if side == 1 {
				e.OP = n
			} else {
				e.RP = n
			}
		case "bytes":
			if side == 1 {
				e.OB = n
			} else {
				e.RB = n
			}
		case "mark":
			e.Mark = uint32(n)
		}
	}
	return side == 2 && e.O.Src.IsValid() && e.O.Dst.IsValid() && e.R.Src.IsValid() && e.R.Dst.IsValid()
}

func (e *monCT) icmp() bool { return e.Proto == "icmp" || e.Proto == "icmpv6" }

// key identifies a connection across polls (original tuple).
func (e *monCT) key() uint64 {
	var b [38]byte
	b[0], b[1] = byte(e.Fam), byte(e.PNum)
	s, d := e.O.Src.As16(), e.O.Dst.As16()
	copy(b[2:18], s[:])
	copy(b[18:34], d[:])
	binary.BigEndian.PutUint16(b[34:], e.O.Sport)
	binary.BigEndian.PutUint16(b[36:], e.O.Dport)
	h := fnv.New64a()
	h.Write(b[:])
	return h.Sum64()
}

// monReadCT streams the conntrack table; e is reused between calls (copy it to keep it).
func monReadCT(fn func(e *monCT)) (n int, truncated, ok bool) {
	f, err := os.Open(monPath("/proc/net/nf_conntrack"))
	if err != nil {
		return 0, false, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 4096), 64*1024)
	var e monCT
	for sc.Scan() {
		if !monParseCT(sc.Text(), &e) {
			continue
		}
		if n >= monCTMax {
			return n, true, true
		}
		n++
		fn(&e)
	}
	return n, false, true
}

// ---- who is who: LAN addresses → device (MAC) → name ----

type monNeigh struct {
	Addr    netip.Addr
	MAC     string
	Ifindex int
}

// Injected for tests: ifindex + prefixes of a netdev, every local address, the neighbour table.
var (
	monLink = func(name string) (int, []netip.Prefix) {
		ifi, err := net.InterfaceByName(name)
		if err != nil {
			return 0, nil
		}
		addrs, _ := ifi.Addrs()
		return ifi.Index, monPrefixes(addrs)
	}
	monLocalAddrs = func() []netip.Prefix {
		addrs, _ := net.InterfaceAddrs()
		return monPrefixes(addrs)
	}
	monNeighbours = monNeighDump
)

func monPrefixes(addrs []net.Addr) []netip.Prefix {
	var out []netip.Prefix
	for _, a := range addrs {
		if p, err := netip.ParsePrefix(a.String()); err == nil {
			out = append(out, p)
		}
	}
	return out
}

type monNames struct {
	self    map[netip.Addr]bool
	lan     []netip.Prefix
	ipMAC   map[netip.Addr]string
	macName map[string]string
}

func monLoadNames(c *Config) *monNames {
	n := &monNames{self: map[netip.Addr]bool{}, ipMAC: map[netip.Addr]string{}, macName: map[string]string{}}
	for _, p := range monLocalAddrs() {
		n.self[p.Addr()] = true
	}
	lanIdx := map[int]bool{}
	if c != nil {
		for _, ln := range c.LANNets() {
			if p, err := netip.ParsePrefix(ln.IPv4); err == nil {
				n.lan = append(n.lan, p.Masked())
			}
			idx, pfx := monLink(ln.Bridge)
			if idx > 0 {
				lanIdx[idx] = true
			}
			for _, p := range pfx {
				// fe80::/64 is on every link, WAN included (the ISP's DHCPv6 server answers from its
				// link-local address): link-local LAN devices are known from the neighbour table instead
				if p.Addr().IsLinkLocalUnicast() {
					continue
				}
				n.lan = append(n.lan, p.Masked())
			}
		}
	}
	// neighbour table first (current truth), then DHCP leases, then static hosts
	if nb, err := monNeighbours(); err == nil {
		for _, x := range nb {
			if lanIdx[x.Ifindex] {
				n.ipMAC[x.Addr] = x.MAC
			}
		}
	}
	for _, l := range strings.Split(readFile(monPath("/tmp/dhcp.leases")), "\n") {
		f := strings.Fields(l) // expiry mac ip name client-id
		if len(f) < 4 || !reMAC.MatchString(f[1]) {
			continue
		}
		mac := strings.ToLower(f[1])
		if a, err := netip.ParseAddr(f[2]); err == nil {
			if _, ok := n.ipMAC[a]; !ok {
				n.ipMAC[a] = mac
			}
		}
		if f[3] != "*" {
			n.macName[mac] = f[3]
		}
	}
	if c != nil {
		for _, h := range c.knownHosts() {
			mac := strings.ToLower(h.MAC)
			if h.Name != "" {
				n.macName[mac] = h.Name
			}
			if a, err := netip.ParseAddr(h.IP); err == nil {
				if _, ok := n.ipMAC[a]; !ok {
					n.ipMAC[a] = mac
				}
			}
		}
	}
	return n
}

// isLAN: a LAN-side device (not the router itself).
func (n *monNames) isLAN(a netip.Addr) bool {
	if !a.IsValid() || n.self[a] {
		return false
	}
	if _, ok := n.ipMAC[a]; ok {
		return true
	}
	for _, p := range n.lan {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// id: the device key (MAC when known, else the address).
func (n *monNames) id(a netip.Addr) (id, mac string) {
	if m, ok := n.ipMAC[a]; ok {
		return m, m
	}
	return a.String(), ""
}

func (n *monNames) name(a netip.Addr) string { return n.macName[n.ipMAC[a]] }

// ---- mon.devices ----

type monDevice struct {
	ID       string   `json:"id"` // MAC, or the address when the MAC is unknown; "other" = not a LAN device
	MAC      string   `json:"mac,omitempty"`
	Name     string   `json:"name,omitempty"`
	IPs      []string `json:"ips"`
	Conns    int      `json:"conns"`
	Up       uint64   `json:"up"`        // bytes sent by the device, summed over its current connections
	Down     uint64   `json:"down"`      // bytes received
	UpRate   float64  `json:"up_rate"`   // bytes/s since the previous poll (0 when dt = 0)
	DownRate float64  `json:"down_rate"` // bytes/s

	ips         map[netip.Addr]bool
	dUp, dDown  uint64
	sortKeyRate float64
}

func (d *monDevice) finish(dt float64) {
	var ips []netip.Addr
	for a := range d.ips {
		ips = append(ips, a)
	}
	sort.Slice(ips, func(i, j int) bool {
		if ips[i].Is4() != ips[j].Is4() {
			return ips[i].Is4()
		}
		return ips[i].Less(ips[j])
	})
	d.IPs = []string{}
	for _, a := range ips {
		d.IPs = append(d.IPs, a.String())
	}
	if dt > 0 {
		d.UpRate = math.Round(float64(d.dUp) / dt)
		d.DownRate = math.Round(float64(d.dDown) / dt)
	}
	d.sortKeyRate = d.UpRate + d.DownRate
}

func monDevices(c *Config) (map[string]any, error) {
	names := monLoadNames(c)
	now := monUptime()
	prev, prevUp, havePrev := monLoadFlows(monPath(monFlowFile))
	dt := now - prevUp
	if !havePrev || dt < 0.5 || dt > 120 {
		dt = 0 // first poll (or a long pause): this call only sets the baseline
	}
	// The previous poll stopped at monCTMax entries (conntrack flood): a flow missing from it may be
	// an old one that only now falls inside the parsed part of the table, not a new one.
	prevCut := len(prev) >= monCTMax
	next := make(map[uint64][2]uint64, len(prev)+64)
	devs := map[string]*monDevice{}
	other := &monDevice{ID: "other", ips: map[netip.Addr]bool{}}
	total, truncated, ok := monReadCT(func(e *monCT) {
		k := e.key()
		next[k] = [2]uint64{e.OB, e.RB}
		dO, dR := e.OB, e.RB // a flow not seen before started after the previous poll
		if p, seen := prev[k]; seen {
			if e.OB >= p[0] && e.RB >= p[1] {
				dO, dR = e.OB-p[0], e.RB-p[1]
			}
		} else if prevCut {
			dO, dR = 0, 0 // its lifetime bytes are not this interval's
		}
		d := other
		up, down, dUp, dDown := e.OB, e.RB, dO, dR
		var addr netip.Addr
		switch {
		case names.isLAN(e.O.Src): // the device opened it
			addr = e.O.Src
		case names.isLAN(e.R.Src): // inbound: port forward (DNAT) or IPv6 pinhole
			addr = e.R.Src
			up, down, dUp, dDown = e.RB, e.OB, dR, dO
		}
		if addr.IsValid() {
			id, mac := names.id(addr)
			if d = devs[id]; d == nil {
				d = &monDevice{ID: id, MAC: mac, Name: names.macName[mac], ips: map[netip.Addr]bool{}}
				devs[id] = d
			}
			d.ips[addr] = true
		}
		d.Conns++
		d.Up += up
		d.Down += down
		d.dUp += dUp
		d.dDown += dDown
	})
	flowtable, counter := monNftFlowCounter(readFile(monPath(GenDir + "/nftables.nft")))
	res := map[string]any{
		"available": ok, "t": time.Now().UnixMilli(), "dt": math.Round(dt*1000) / 1000,
		"acct":      strings.TrimSpace(readFile(monPath("/proc/sys/net/netfilter/nf_conntrack_acct"))) == "1",
		"flowtable": flowtable, "flow_counter": counter, "entries": total, "truncated": truncated,
	}
	if !ok {
		res["devices"] = []*monDevice{}
		return res, nil
	}
	if err := monSaveFlows(monPath(monFlowFile), now, next); err != nil {
		res["warning"] = "rate snapshot not saved: " + err.Error()
	}
	list := make([]*monDevice, 0, len(devs))
	for _, d := range devs {
		d.finish(dt)
		list = append(list, d)
	}
	sort.Slice(list, func(i, j int) bool {
		a, b := list[i], list[j]
		if a.sortKeyRate != b.sortKeyRate {
			return a.sortKeyRate > b.sortKeyRate
		}
		if a.Up+a.Down != b.Up+b.Down {
			return a.Up+a.Down > b.Up+b.Down
		}
		return a.ID < b.ID
	})
	other.finish(dt)
	res["devices"], res["other"] = list, other
	return res, nil
}

// monNftFlowCounter reports whether the loaded ruleset has a flowtable and whether it counts bytes
// of offloaded flows into conntrack (a `counter` statement inside the flowtable block).
func monNftFlowCounter(nft string) (flowtable, counter bool) {
	depth := 0 // brace depth inside the current flowtable block
	for _, l := range strings.Split(nft, "\n") {
		t := strings.TrimSpace(l)
		if depth == 0 {
			head, body, ok := strings.Cut(t, "{")
			if !ok || !strings.HasPrefix(head, "flowtable ") {
				continue
			}
			flowtable, depth, t = true, 1, body
		}
		for _, stmt := range strings.FieldsFunc(t, func(r rune) bool { return r == ';' || r == '{' || r == '}' }) {
			if strings.TrimSpace(stmt) == "counter" && depth == 1 {
				counter = true
			}
		}
		if depth += strings.Count(t, "{") - strings.Count(t, "}"); depth < 0 {
			depth = 0
		}
	}
	return flowtable, counter
}

// Flow snapshot: "MRF1", uptime (float64 bits), count, then count × (key, orig bytes, reply bytes).
func monSaveFlows(path string, up float64, m map[uint64][2]uint64) error {
	b := make([]byte, 0, 16+24*len(m))
	b = append(b, "MRF1"...)
	b = binary.LittleEndian.AppendUint64(b, math.Float64bits(up))
	b = binary.LittleEndian.AppendUint32(b, uint32(len(m)))
	for k, v := range m {
		b = binary.LittleEndian.AppendUint64(b, k)
		b = binary.LittleEndian.AppendUint64(b, v[0])
		b = binary.LittleEndian.AppendUint64(b, v[1])
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".flows-*")
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(f.Name())
		return err
	}
	return os.Rename(f.Name(), path)
}

func monLoadFlows(path string) (map[uint64][2]uint64, float64, bool) {
	b, err := os.ReadFile(path)
	if err != nil || len(b) < 16 || string(b[:4]) != "MRF1" {
		return nil, 0, false
	}
	up := math.Float64frombits(binary.LittleEndian.Uint64(b[4:12]))
	n := int(binary.LittleEndian.Uint32(b[12:16]))
	if len(b)-16 != n*24 {
		return nil, 0, false
	}
	m := make(map[uint64][2]uint64, n)
	for i := 16; i < len(b); i += 24 {
		m[binary.LittleEndian.Uint64(b[i:])] = [2]uint64{binary.LittleEndian.Uint64(b[i+8:]), binary.LittleEndian.Uint64(b[i+16:])}
	}
	return m, up, true
}

// ---- mon.conns ----

type monConnFilter struct {
	Proto   string `json:"proto"`   // "" | tcp | udp | icmp | icmpv6 | sctp | gre | other
	Family  int    `json:"family"`  // 0 | 4 | 6
	IP      string `json:"ip"`      // address or CIDR; matches any address of either direction
	Port    int    `json:"port"`    // matches any port of either direction (not ICMP)
	State   string `json:"state"`   // TCP state, e.g. ESTABLISHED
	Offload string `json:"offload"` // "" | hw | sw | any | none
	Sort    string `json:"sort"`    // bytes (default) | none (kernel order)
	Limit   int    `json:"limit"`   // 1..2000, default 200

	pfx netip.Prefix
}

var monTCPStates = map[string]bool{"NONE": true, "SYN_SENT": true, "SYN_RECV": true, "ESTABLISHED": true, "FIN_WAIT": true,
	"CLOSE_WAIT": true, "LAST_ACK": true, "TIME_WAIT": true, "CLOSE": true, "SYN_SENT2": true}

func monParseConnFilter(body []byte) (*monConnFilter, error) {
	f := &monConnFilter{}
	if len(strings.TrimSpace(string(body))) > 0 {
		dec := json.NewDecoder(strings.NewReader(string(body)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(f); err != nil {
			return nil, fmt.Errorf("bad filter: %v", err)
		}
	}
	switch f.Proto {
	case "", "tcp", "udp", "icmp", "icmpv6", "sctp", "gre", "other":
	default:
		return nil, fmt.Errorf("proto: unknown %q", f.Proto)
	}
	if f.Family != 0 && f.Family != 4 && f.Family != 6 {
		return nil, fmt.Errorf("family: 0, 4 or 6")
	}
	if f.IP != "" {
		if len(f.IP) > 64 {
			return nil, fmt.Errorf("ip: too long")
		}
		if p, err := netip.ParsePrefix(f.IP); err == nil {
			f.pfx = p.Masked()
		} else if a, err := netip.ParseAddr(f.IP); err == nil && a.Zone() == "" {
			f.pfx = netip.PrefixFrom(a, a.BitLen())
		} else {
			return nil, fmt.Errorf("ip: need an address or CIDR, got %q", f.IP)
		}
	}
	if f.Port < 0 || f.Port > 65535 {
		return nil, fmt.Errorf("port: 0-65535")
	}
	if f.State != "" && !monTCPStates[f.State] {
		return nil, fmt.Errorf("state: unknown %q", f.State)
	}
	switch f.Offload {
	case "", "hw", "sw", "any", "none":
	default:
		return nil, fmt.Errorf("offload: hw, sw, any or none")
	}
	switch f.Sort {
	case "", "bytes", "none":
	default:
		return nil, fmt.Errorf("sort: bytes or none")
	}
	if f.Limit <= 0 {
		f.Limit = 200
	}
	if f.Limit > monConnsLimit {
		f.Limit = monConnsLimit
	}
	return f, nil
}

func (f *monConnFilter) match(e *monCT) bool {
	if f.Family != 0 && e.Fam != f.Family {
		return false
	}
	switch f.Proto {
	case "":
	case "other":
		switch e.Proto {
		case "tcp", "udp", "icmp", "icmpv6":
			return false
		}
	default:
		if e.Proto != f.Proto {
			return false
		}
	}
	if f.State != "" && e.State != f.State {
		return false
	}
	hw, sw := e.Flags&monCTHWOffload != 0, e.Flags&monCTOffload != 0
	switch f.Offload {
	case "hw":
		if !hw {
			return false
		}
	case "sw":
		if !sw {
			return false
		}
	case "any":
		if !hw && !sw {
			return false
		}
	case "none":
		if hw || sw {
			return false
		}
	}
	if f.pfx.IsValid() && !f.pfx.Contains(e.O.Src) && !f.pfx.Contains(e.O.Dst) && !f.pfx.Contains(e.R.Src) && !f.pfx.Contains(e.R.Dst) {
		return false
	}
	if f.Port != 0 {
		p := uint16(f.Port)
		if e.icmp() || (e.O.Sport != p && e.O.Dport != p && e.R.Sport != p && e.R.Dport != p) {
			return false
		}
	}
	return true
}

type monConnOut struct {
	Proto     string `json:"p"`
	Fam       int    `json:"f"`
	State     string `json:"st,omitempty"`
	TTL       int    `json:"ttl"` // -1 while offloaded
	Src       string `json:"src"`
	Dst       string `json:"dst"`
	Sport     uint16 `json:"sport"`
	Dport     uint16 `json:"dport"`
	ICMP      string `json:"icmp,omitempty"`    // "type/code"
	NatSrc    string `json:"nat_src,omitempty"` // SNAT / masquerade: the address the router used towards the responder
	NatSport  uint16 `json:"nat_sport,omitempty"`
	NatDst    string `json:"nat_dst,omitempty"` // DNAT / port forward: the real responder
	NatDport  uint16 `json:"nat_dport,omitempty"`
	OB        uint64 `json:"ob"` // bytes initiator → responder
	RB        uint64 `json:"rb"` // bytes responder → initiator
	OP        uint64 `json:"op"`
	RP        uint64 `json:"rp"`
	Off       string `json:"off,omitempty"` // hw | sw
	Assured   bool   `json:"assured,omitempty"`
	Unreplied bool   `json:"unreplied,omitempty"`
	Mark      uint32 `json:"mark,omitempty"`
}

func monConnJSON(e *monCT) monConnOut {
	o := monConnOut{Proto: e.Proto, Fam: e.Fam, State: e.State, TTL: e.TTL, Src: e.O.Src.String(), Dst: e.O.Dst.String(),
		OB: e.OB, RB: e.RB, OP: e.OP, RP: e.RP, Assured: e.Flags&monCTAssured != 0, Unreplied: e.Flags&monCTUnreplied != 0, Mark: e.Mark}
	if e.icmp() {
		o.ICMP = fmt.Sprintf("%d/%d", e.O.Dport>>8, e.O.Dport&0xff)
	} else {
		o.Sport, o.Dport = e.O.Sport, e.O.Dport
	}
	if e.R.Dst != e.O.Src || (!e.icmp() && e.R.Dport != e.O.Sport) {
		o.NatSrc = e.R.Dst.String()
		if !e.icmp() {
			o.NatSport = e.R.Dport
		}
	}
	if e.R.Src != e.O.Dst || (!e.icmp() && e.R.Sport != e.O.Dport) {
		o.NatDst = e.R.Src.String()
		if !e.icmp() {
			o.NatDport = e.R.Sport
		}
	}
	switch {
	case e.Flags&monCTHWOffload != 0:
		o.Off = "hw"
	case e.Flags&monCTOffload != 0:
		o.Off = "sw"
	}
	return o
}

type monTalker struct {
	IP    string `json:"ip"`
	Name  string `json:"name,omitempty"`
	Conns int    `json:"conns"`
	Bytes uint64 `json:"bytes"`
}

func monTopTalkers(m map[netip.Addr]*monTalker, names *monNames) []monTalker {
	out := make([]monTalker, 0, len(m))
	for a, t := range m {
		t.IP, t.Name = a.String(), names.name(a)
		out = append(out, *t)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Bytes != out[j].Bytes {
			return out[i].Bytes > out[j].Bytes
		}
		if out[i].Conns != out[j].Conns {
			return out[i].Conns > out[j].Conns
		}
		return out[i].IP < out[j].IP
	})
	if len(out) > monTop {
		out = out[:monTop]
	}
	return out
}

// monConns: totals over the whole table (by protocol, TCP state, offload, family), top talkers
// and the connection list over the filtered set, sorted by bytes, cut to the limit.
func monConns(c *Config, body []byte) (any, error) {
	f, err := monParseConnFilter(body)
	if err != nil {
		return nil, err
	}
	names := monLoadNames(c)
	byProto, byState := map[string]int{}, map[string]int{}
	byOff := map[string]int{"hw": 0, "sw": 0, "none": 0}
	byFam := map[string]int{"4": 0, "6": 0}
	src, dst := map[netip.Addr]*monTalker{}, map[netip.Addr]*monTalker{}
	var matched []monCT
	total, truncated, ok := monReadCT(func(e *monCT) {
		byProto[e.Proto]++
		if e.Proto == "tcp" && e.State != "" {
			byState[e.State]++
		}
		switch {
		case e.Flags&monCTHWOffload != 0:
			byOff["hw"]++
		case e.Flags&monCTOffload != 0:
			byOff["sw"]++
		default:
			byOff["none"]++
		}
		byFam[strconv.Itoa(e.Fam)]++
		if !f.match(e) {
			return
		}
		matched = append(matched, *e)
		for _, x := range []struct {
			m map[netip.Addr]*monTalker
			a netip.Addr
		}{{src, e.O.Src}, {dst, e.O.Dst}} {
			t := x.m[x.a]
			if t == nil {
				t = &monTalker{}
				x.m[x.a] = t
			}
			t.Conns++
			t.Bytes += e.OB + e.RB
		}
	})
	if f.Sort != "none" {
		sort.SliceStable(matched, func(i, j int) bool { return matched[i].OB+matched[i].RB > matched[j].OB+matched[j].RB })
	}
	n := len(matched)
	if n > f.Limit {
		matched = matched[:f.Limit]
	}
	conns := make([]monConnOut, 0, len(matched))
	shown := map[string]string{}
	for i := range matched {
		e := &matched[i]
		conns = append(conns, monConnJSON(e))
		for _, a := range []netip.Addr{e.O.Src, e.O.Dst, e.R.Src, e.R.Dst} {
			if nm := names.name(a); nm != "" {
				shown[a.String()] = nm
			}
		}
	}
	flowtable, counter := monNftFlowCounter(readFile(monPath(GenDir + "/nftables.nft")))
	return map[string]any{
		"available": ok, "total": total, "truncated": truncated, "matched": n, "limit": f.Limit,
		"acct":      strings.TrimSpace(readFile(monPath("/proc/sys/net/netfilter/nf_conntrack_acct"))) == "1",
		"flowtable": flowtable, "flow_counter": counter,
		"by_proto": byProto, "by_state": byState, "by_offload": byOff, "by_family": byFam,
		"top_src": monTopTalkers(src, names), "top_dst": monTopTalkers(dst, names),
		"names": shown, "conns": conns,
	}, nil
}

// monParseNeigh decodes one RTM_NEWNEIGH payload (struct ndmsg + rtattrs). Entries without a
// usable MAC (incomplete, failed, noarp) are skipped.
func monParseNeigh(b []byte) (monNeigh, bool) {
	const ndmsgLen = 12
	if len(b) < ndmsgLen {
		return monNeigh{}, false
	}
	ifindex := int(int32(binary.NativeEndian.Uint32(b[4:8])))
	state := binary.NativeEndian.Uint16(b[8:10])
	// NUD_REACHABLE | NUD_STALE | NUD_DELAY | NUD_PROBE | NUD_PERMANENT
	if state&0x9e == 0 {
		return monNeigh{}, false
	}
	var n monNeigh
	n.Ifindex = ifindex
	for a := b[ndmsgLen:]; len(a) >= 4; {
		l := int(binary.NativeEndian.Uint16(a[0:2]))
		typ := binary.NativeEndian.Uint16(a[2:4]) & 0x3fff
		if l < 4 || l > len(a) {
			break
		}
		v := a[4:l]
		switch typ {
		case 1: // NDA_DST
			if ad, ok := netip.AddrFromSlice(v); ok {
				n.Addr = ad.Unmap()
			}
		case 2: // NDA_LLADDR
			if len(v) == 6 {
				n.MAC = net.HardwareAddr(v).String()
			}
		}
		step := (l + 3) &^ 3
		if step > len(a) {
			break
		}
		a = a[step:]
	}
	return n, n.Addr.IsValid() && n.MAC != "" && n.MAC != "00:00:00:00:00:00"
}
