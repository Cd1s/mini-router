package main

// A tiny DNS client (UDP, one question, no dependencies). Used to read dnsmasq's statistics
// (CHAOS TXT cachesize.bind, hits.bind, misses.bind, servers.bind, ...), to read back local
// records after an apply (Verify), and by `mr dns query`. Nothing stays resident.

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	dnsTypeA      = 1
	dnsTypeCNAME  = 5
	dnsTypePTR    = 12
	dnsTypeTXT    = 16
	dnsTypeAAAA   = 28
	dnsTypeSRV    = 33
	dnsClassIN    = 1
	dnsClassCHAOS = 3

	dnsLocal = "127.0.0.1:53" // dnsmasq
)

var dnsTypes = map[string]uint16{"A": dnsTypeA, "CNAME": dnsTypeCNAME, "PTR": dnsTypePTR, "TXT": dnsTypeTXT, "AAAA": dnsTypeAAAA, "SRV": dnsTypeSRV}

var rcodeNames = []string{"NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED"}

func rcodeName(rc int) string {
	if rc >= 0 && rc < len(rcodeNames) {
		return rcodeNames[rc]
	}
	return "RCODE" + strconv.Itoa(rc)
}

func dnsTypeName(t uint16) string {
	for k, v := range dnsTypes {
		if v == t {
			return k
		}
	}
	return "TYPE" + strconv.Itoa(int(t))
}

type dnsRR struct {
	Name string   `json:"name"`
	Type string   `json:"type"`
	TTL  uint32   `json:"ttl"`
	Data string   `json:"data"`
	TXT  []string `json:"-"`
}

var (
	errDNSShort   = errors.New("dns: truncated message")
	errDNSWrongID = errors.New("dns: reply id mismatch")
)

func dnsEncodeQuery(id uint16, name string, qtype, qclass uint16) ([]byte, error) {
	msg := make([]byte, 12, 64+len(name))
	binary.BigEndian.PutUint16(msg[0:], id)
	binary.BigEndian.PutUint16(msg[2:], 0x0100) // RD
	binary.BigEndian.PutUint16(msg[4:], 1)      // QDCOUNT
	name = strings.TrimSuffix(name, ".")
	if name != "" {
		for _, l := range strings.Split(name, ".") {
			if l == "" || len(l) > 63 {
				return nil, fmt.Errorf("dns: bad name %q", name)
			}
			msg = append(msg, byte(len(l)))
			msg = append(msg, l...)
		}
	}
	if len(msg)-12 > 254 {
		return nil, fmt.Errorf("dns: name too long")
	}
	return append(msg, 0, byte(qtype>>8), byte(qtype), byte(qclass>>8), byte(qclass)), nil
}

// dnsReadName decodes a possibly compressed name at off and returns it plus the offset after it.
func dnsReadName(msg []byte, off int) (string, int, error) {
	var labels []string
	end, jumps, total := -1, 0, 0
	for {
		if off < 0 || off >= len(msg) {
			return "", 0, errDNSShort
		}
		l := int(msg[off])
		switch {
		case l == 0:
			if end < 0 {
				end = off + 1
			}
			return strings.Join(labels, "."), end, nil
		case l&0xC0 == 0xC0:
			if off+1 >= len(msg) {
				return "", 0, errDNSShort
			}
			if end < 0 {
				end = off + 2
			}
			if jumps++; jumps > 64 {
				return "", 0, errors.New("dns: compression loop")
			}
			off = int(binary.BigEndian.Uint16(msg[off:]) & 0x3FFF)
		case l&0xC0 != 0:
			return "", 0, errors.New("dns: bad label type")
		default:
			if off+1+l > len(msg) {
				return "", 0, errDNSShort
			}
			if total += l + 1; total > 255 {
				return "", 0, errors.New("dns: name too long")
			}
			labels = append(labels, string(msg[off+1:off+1+l]))
			off += 1 + l
		}
	}
}

// dnsParseResponse checks the header against id and decodes the answer section.
func dnsParseResponse(msg []byte, id uint16) (int, []dnsRR, error) {
	if len(msg) < 12 {
		return 0, nil, errDNSShort
	}
	if binary.BigEndian.Uint16(msg) != id {
		return 0, nil, errDNSWrongID
	}
	flags := binary.BigEndian.Uint16(msg[2:])
	if flags&0x8000 == 0 {
		return 0, nil, errors.New("dns: not a response")
	}
	rcode := int(flags & 0xF)
	qd, an := int(binary.BigEndian.Uint16(msg[4:])), int(binary.BigEndian.Uint16(msg[6:]))
	off := 12
	for i := 0; i < qd; i++ {
		_, next, err := dnsReadName(msg, off)
		if err != nil {
			return rcode, nil, err
		}
		if off = next + 4; off > len(msg) {
			return rcode, nil, errDNSShort
		}
	}
	var rrs []dnsRR
	for i := 0; i < an; i++ {
		name, next, err := dnsReadName(msg, off)
		if err != nil {
			return rcode, rrs, err
		}
		if next+10 > len(msg) {
			return rcode, rrs, errDNSShort
		}
		typ := binary.BigEndian.Uint16(msg[next:])
		ttl := binary.BigEndian.Uint32(msg[next+4:])
		rdlen := int(binary.BigEndian.Uint16(msg[next+8:]))
		rd := next + 10
		if rd+rdlen > len(msg) {
			return rcode, rrs, errDNSShort
		}
		rr := dnsRR{Name: name, Type: dnsTypeName(typ), TTL: ttl}
		data := msg[rd : rd+rdlen]
		switch typ {
		case dnsTypeA, dnsTypeAAAA:
			if len(data) == 4 || len(data) == 16 {
				rr.Data = net.IP(data).String()
			}
		case dnsTypeCNAME, dnsTypePTR:
			rr.Data, _, err = dnsReadName(msg, rd)
		case dnsTypeSRV:
			if len(data) > 6 {
				var t string
				t, _, err = dnsReadName(msg, rd+6)
				rr.Data = fmt.Sprintf("%d %d %d %s", binary.BigEndian.Uint16(data), binary.BigEndian.Uint16(data[2:]), binary.BigEndian.Uint16(data[4:]), t)
			}
		case dnsTypeTXT:
			for j := 0; j < len(data); {
				l := int(data[j])
				if j+1+l > len(data) {
					return rcode, rrs, errDNSShort
				}
				rr.TXT = append(rr.TXT, string(data[j+1:j+1+l]))
				j += 1 + l
			}
			rr.Data = strings.Join(rr.TXT, " ")
		default:
			rr.Data = fmt.Sprintf("(%d bytes)", len(data))
		}
		if err != nil {
			return rcode, rrs, err
		}
		rrs = append(rrs, rr)
		off = rd + rdlen
	}
	return rcode, rrs, nil
}

// dnsQuery sends one question to server ("ip:port") and returns the rcode and answer records.
func dnsQuery(server, name string, qtype, qclass uint16, timeout time.Duration) (int, []dnsRR, error) {
	var idb [2]byte
	rand.Read(idb[:])
	id := binary.BigEndian.Uint16(idb[:])
	q, err := dnsEncodeQuery(id, name, qtype, qclass)
	if err != nil {
		return 0, nil, err
	}
	conn, err := net.DialTimeout("udp", server, timeout)
	if err != nil {
		return 0, nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(q); err != nil {
		return 0, nil, err
	}
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return 0, nil, err
		}
		rc, rrs, err := dnsParseResponse(buf[:n], id)
		if err == errDNSWrongID {
			continue // stray datagram
		}
		return rc, rrs, err
	}
}

// ---- dnsmasq statistics (CHAOS class TXT records, answered by dnsmasq itself) ----

type upstreamStat struct {
	Server  string `json:"server"`
	Queries int64  `json:"queries"`
	Failed  int64  `json:"failed"`
}

type dnsmasqStats struct {
	CacheSize  int64          `json:"cache_size"`
	Insertions int64          `json:"insertions"`
	Evictions  int64          `json:"evictions"`
	Hits       int64          `json:"hits"`   // answered locally (cache, records, DHCP names)
	Misses     int64          `json:"misses"` // forwarded upstream
	Servers    []upstreamStat `json:"servers"`
}

func chaosTXT(server, name string) ([]string, error) {
	rc, rrs, err := dnsQuery(server, name, dnsTypeTXT, dnsClassCHAOS, 2*time.Second)
	if err != nil {
		return nil, err
	}
	if rc != 0 {
		return nil, fmt.Errorf("%s: %s", name, rcodeName(rc))
	}
	var out []string
	for _, rr := range rrs {
		out = append(out, rr.TXT...)
	}
	return out, nil
}

// statsBindNames are the CHAOS names queryDnsmasqStats asks for.
var statsBindNames = []string{"cachesize.bind", "insertions.bind", "evictions.bind", "hits.bind", "misses.bind", "servers.bind"}

func queryDnsmasqStats(server string) (*dnsmasqStats, error) {
	st := &dnsmasqStats{Servers: []upstreamStat{}}
	for _, x := range []struct {
		name string
		dst  *int64
	}{{"cachesize.bind", &st.CacheSize}, {"insertions.bind", &st.Insertions}, {"evictions.bind", &st.Evictions},
		{"hits.bind", &st.Hits}, {"misses.bind", &st.Misses}} {
		txt, err := chaosTXT(server, x.name)
		if err != nil {
			return nil, err
		}
		if len(txt) > 0 {
			*x.dst, _ = strconv.ParseInt(txt[0], 10, 64)
		}
	}
	txt, err := chaosTXT(server, "servers.bind")
	if err != nil {
		return nil, err
	}
	for _, s := range txt { // "1.1.1.1#53 1234 5"
		f := strings.Fields(s)
		if len(f) != 3 {
			continue
		}
		q, _ := strconv.ParseInt(f[1], 10, 64)
		fl, _ := strconv.ParseInt(f[2], 10, 64)
		st.Servers = append(st.Servers, upstreamStat{Server: f[0], Queries: q, Failed: fl})
	}
	return st, nil
}

// ---- post-apply verification ----

// dnsVerify: after dnsmasq restarted, wait until it answers, then read back the local A/AAAA
// records (the ones home servers depend on). After stubby restarted, wait until it listens.
func dnsVerify(c *Config, restarted []string) []string {
	var errs []string
	for _, s := range restarted {
		switch s {
		case "stubby":
			addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(c.DNS.DoT.Port))
			if !waitFor(verifyDeadline(), func() bool {
				conn, err := net.DialTimeout("tcp", addr, time.Second)
				if err == nil {
					conn.Close()
				}
				return err == nil
			}) {
				errs = append(errs, "stubby not listening on "+addr)
			}
		case "dnsmasq":
			if !waitFor(verifyDeadline(), func() bool {
				_, _, err := dnsQuery(dnsLocal, "localhost", dnsTypeA, dnsClassIN, time.Second)
				return err == nil
			}) {
				return append(errs, "dnsmasq not answering")
			}
			errs = append(errs, verifyRecords(c, dnsLocal)...)
		}
	}
	return errs
}

// verifyRecords checks (up to 20) plain A/AAAA records against a running dnsmasq.
func verifyRecords(c *Config, server string) []string {
	var errs []string
	n := 0
	for _, r := range c.DNS.Records {
		if (r.Type != "A" && r.Type != "AAAA") || strings.HasPrefix(r.Name, "*.") {
			continue
		}
		if n++; n > 20 {
			break
		}
		want := net.ParseIP(r.Value)
		rc, rrs, err := dnsQuery(server, r.Name, dnsTypes[r.Type], dnsClassIN, 2*time.Second)
		ok := false
		for _, rr := range rrs {
			if ip := net.ParseIP(rr.Data); ip != nil && ip.Equal(want) {
				ok = true
			}
		}
		if !ok {
			errs = append(errs, fmt.Sprintf("dns record %s %s %s not served (rcode %s, err %v)", r.Name, r.Type, r.Value, rcodeName(rc), err))
		}
	}
	return errs
}
