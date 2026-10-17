package main

// WAN discovery is deliberately a one-shot operation.  It never installs an address,
// route, lease or service; the DHCP probe stops after an OFFER and the PPPoE probe is
// an independent discovery session.  The small parsers are kept separate so captures
// from real switches can be tested without a network namespace.

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type detectLink struct {
	Carrier bool   `json:"carrier"`
	Speed   int    `json:"speed_mbps,omitempty"`
	Duplex  string `json:"duplex,omitempty"`
}

type detectPPPoE struct {
	PADO    bool   `json:"pado"`
	AC      string `json:"ac_name,omitempty"`
	Service string `json:"service_name,omitempty"`
}

type detectDHCP struct {
	Offer   bool     `json:"offer"`
	Address string   `json:"address,omitempty"`
	Mask    string   `json:"mask,omitempty"`
	Gateway string   `json:"gateway,omitempty"`
	DNS     []string `json:"dns,omitempty"`
}

type detectRA struct {
	Seen   bool   `json:"seen"`
	Prefix string `json:"prefix,omitempty"`
	M      bool   `json:"managed"`
	O      bool   `json:"other_config"`
}

type wanDetectResult struct {
	Port           string      `json:"port"`
	Link           detectLink  `json:"link"`
	PPPoE          detectPPPoE `json:"pppoe"`
	DHCP           detectDHCP  `json:"dhcp"`
	IPv6RA         detectRA    `json:"ipv6_ra"`
	Recommendation string      `json:"recommendation"` // pppoe | dhcp | static
	LANConflict    bool        `json:"lan_conflict"`
	SuggestedLAN   string      `json:"suggested_lan,omitempty"`
	ElapsedMS      int64       `json:"elapsed_ms"`
}

type detectObservation struct {
	PPPoE detectPPPoE
	DHCP  detectDHCP
	RA    detectRA
}

var detectMu sync.Mutex

// detectProbe is injectable in tests.  Production probing intentionally has no
// persistent state and is bounded by the context supplied by detectWAN.
type detectProbe func(context.Context, string) (detectObservation, error)

var wanDetectProbe detectProbe = probeWAN

func linkDetect(port string) detectLink {
	d := filepath.Join("/sys/class/net", port)
	return detectLink{Carrier: strings.TrimSpace(readFile(filepath.Join(d, "carrier"))) == "1",
		Speed: atoi(readFile(filepath.Join(d, "speed"))), Duplex: strings.TrimSpace(readFile(filepath.Join(d, "duplex")))}
}

func detectWAN(c *Config, port string, timeout time.Duration) wanDetectResult {
	started := time.Now()
	r := wanDetectResult{Port: port, Link: linkDetect(port), Recommendation: "unknown"}
	if timeout <= 0 || timeout > 8*time.Second {
		timeout = 8 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	o, _ := wanDetectProbe(ctx, port)
	r.PPPoE, r.DHCP, r.IPv6RA = o.PPPoE, o.DHCP, o.RA
	switch {
	case r.PPPoE.PADO:
		r.Recommendation = "pppoe"
	case r.DHCP.Offer:
		r.Recommendation = "dhcp"
	}
	if r.DHCP.Offer {
		if _, n, err := net.ParseCIDR(c.LAN.IPv4); err == nil {
			ip := net.ParseIP(r.DHCP.Address)
			r.LANConflict = ip != nil && n.Contains(ip)
			if r.LANConflict {
				r.SuggestedLAN = suggestLAN(n)
			}
		}
	}
	r.ElapsedMS = time.Since(started).Milliseconds()
	return r
}

func suggestLAN(upstream *net.IPNet) string {
	// Prefer the familiar 192.168.2.0/24, then private 10/8 subnets.
	for _, s := range []string{"192.168.2.1/24", "192.168.50.1/24", "10.0.0.1/24", "10.10.0.1/24"} {
		_, n, _ := net.ParseCIDR(s)
		if !ipnetsOverlap(n, upstream) {
			return s
		}
	}
	return "10.254.0.1/24"
}

func ipnetsOverlap(a, b *net.IPNet) bool {
	return a.Contains(b.IP) || b.Contains(a.IP)
}

func probeWAN(ctx context.Context, port string) (detectObservation, error) {
	detectMu.Lock()
	defer detectMu.Unlock()
	var out detectObservation
	type result struct {
		kind string
		ppp  detectPPPoE
		dhcp detectDHCP
		err  error
	}
	results := make(chan result, 2)
	pppCtx, pppCancel := context.WithTimeout(ctx, 3*time.Second)
	dhcpCtx, dhcpCancel := context.WithTimeout(ctx, 4*time.Second)
	defer pppCancel()
	defer dhcpCancel()
	go func() { p, err := probePPPoE(pppCtx, port); results <- result{kind: "pppoe", ppp: p, err: err} }()
	go func() { d, err := probeDHCP(dhcpCtx, port); results <- result{kind: "dhcp", dhcp: d, err: err} }()
	var pppErr, dhcpErr error
	for n := 0; n < 2; n++ {
		select {
		case r := <-results:
			if r.kind == "pppoe" {
				out.PPPoE, pppErr = r.ppp, r.err
			} else {
				out.DHCP, dhcpErr = r.dhcp, r.err
			}
		case <-ctx.Done():
			return out, ctx.Err()
		}
	}
	if pppErr != nil && dhcpErr != nil {
		return out, fmt.Errorf("wan probes: pppoe=%v dhcp=%v", pppErr, dhcpErr)
	}
	return out, nil
}

func probePPPoE(ctx context.Context, port string) (detectPPPoE, error) {
	p, err := exec.LookPath("pppoe-discovery")
	if err != nil {
		return detectPPPoE{}, err
	}
	cmd := exec.CommandContext(ctx, p, "-I", port, "-U", "-a", "1", "-t", "1")
	b, err := cmd.CombinedOutput()
	return parsePPPoEDiscovery(string(b), err == nil), err
}

func deadline(ctx context.Context) time.Time {
	d, ok := ctx.Deadline()
	if !ok {
		return time.Now().Add(2 * time.Second)
	}
	return d
}

func parsePPPoEDiscovery(s string, success bool) detectPPPoE {
	p := detectPPPoE{PADO: false}
	for _, line := range strings.Split(s, "\n") {
		l := strings.TrimSpace(line)
		low := strings.ToLower(l)
		for _, key := range []string{"access-concentrator", "ac-name", "access concentrator", "service-name", "service name"} {
			if i := strings.Index(low, key); i >= 0 {
				v := strings.Trim(strings.TrimSpace(l[i+len(key):]), "=: \t\"")
				if strings.Contains(key, "service") {
					p.Service = v
				} else {
					p.AC = v
				}
			}
		}
	}
	p.PADO = success && p.AC != ""
	return p
}

func probeDHCP(ctx context.Context, port string) (detectDHCP, error) {
	var out detectDHCP
	mac, err := net.ParseMAC(strings.TrimSpace(readFile(filepath.Join("/sys/class/net", port, "address"))))
	if err != nil || len(mac) != 6 {
		return out, fmt.Errorf("no mac")
	}
	iface, err := net.InterfaceByName(port)
	if err != nil {
		return out, err
	}
	// AF_PACKET avoids the global UDP/68 bind used by dhcpcd/udhcpc. The
	// socket is bound to this interface and only sees the one-shot Ethernet
	// exchange, so an active DHCP client remains untouched.
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(0x0003)))
	if err != nil {
		return out, err
	}
	defer syscall.Close(fd)
	if err := syscall.Bind(fd, &syscall.SockaddrLinklayer{Protocol: htons(0x0800), Ifindex: iface.Index, Halen: 6, Addr: [8]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}}); err != nil {
		return out, err
	}
	var xidb [4]byte
	_, _ = rand.Read(xidb[:])
	xid := binary.BigEndian.Uint32(xidb[:])
	pkt := dhcpDiscover(xid, mac)
	frame := dhcpEthernetFrame(pkt, mac)
	if _, err = syscall.Write(fd, frame); err != nil {
		return out, err
	}
	d := time.Until(deadline(ctx))
	if d <= 0 {
		return out, context.DeadlineExceeded
	}
	tv := syscall.NsecToTimeval(d.Nanoseconds())
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
	buf := make([]byte, 2048)
	for {
		n, _, e := syscall.Recvfrom(fd, buf, 0)
		if e != nil {
			return out, e
		}
		if len(buf) >= 14+20+8 && binary.BigEndian.Uint16(buf[12:14]) == 0x0800 {
			i := 14 + int(buf[14]&0x0f)*4
			if i+8 <= n && buf[14+9] == 17 && binary.BigEndian.Uint16(buf[i+2:i+4]) == 68 {
				if d, ok := parseDHCPOffer(buf[i+8:n], xid); ok {
					return d, nil
				}
			}
		}
	}
}

func htons(v uint16) uint16 { return (v<<8)&0xff00 | v>>8 }

func dhcpEthernetFrame(payload []byte, mac net.HardwareAddr) []byte {
	iplen := 20 + 8 + len(payload)
	f := make([]byte, 14+iplen)
	for i := 0; i < 6; i++ {
		f[i] = 0xff
		f[6+i] = mac[i]
	}
	binary.BigEndian.PutUint16(f[12:14], 0x0800)
	f[14], f[15], f[16], f[17] = 0x45, 0, byte(iplen>>8), byte(iplen)
	f[18], f[19] = 0, 1
	f[20], f[21] = 0x80, 0
	f[22], f[23], f[24], f[25] = 128, 17, 0, 0
	copy(f[26:30], net.IPv4zero.To4())
	copy(f[30:34], net.IPv4bcast.To4())
	binary.BigEndian.PutUint16(f[24:26], ipv4Checksum(f[14:34]))
	binary.BigEndian.PutUint16(f[34:36], 68)
	binary.BigEndian.PutUint16(f[36:38], 67)
	binary.BigEndian.PutUint16(f[38:40], uint16(8+len(payload)))
	copy(f[42:], payload)
	return f
}

func ipv4Checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + sum>>16
	}
	return ^uint16(sum)
}

// probeRA listens for an ICMPv6 Router Advertisement on the requested link.
// It does not install an address or route.  A router may already be sending
// periodic RAs; listening is deliberately passive so this probe remains safe
// while dhcpcd is managing the same interface.
func probeRA(ctx context.Context, port string) (detectRA, error) {
	var out detectRA
	pc, err := net.ListenPacket("ip6:ipv6-icmp", "::")
	if err != nil {
		return out, err
	}
	defer pc.Close()
	if raw, ok := pc.(syscall.Conn); ok {
		if sc, e := raw.SyscallConn(); e == nil {
			var bindErr error
			_ = sc.Control(func(fd uintptr) {
				bindErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, port)
			})
			if bindErr != nil {
				return out, bindErr
			}
		} else {
			return out, e
		}
	} else {
		return out, fmt.Errorf("raw ICMPv6 socket unavailable")
	}
	_ = pc.SetReadDeadline(deadline(ctx))
	buf := make([]byte, 2048)
	for {
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			return out, err
		}
		if r := parseRouterAdvertisement(buf[:n]); r.Seen {
			return r, nil
		}
	}
}

func dhcpDiscover(xid uint32, mac net.HardwareAddr) []byte {
	b := make([]byte, 240, 300)
	b[0], b[1], b[2], b[3] = 1, 1, 6, 0
	binary.BigEndian.PutUint32(b[4:8], xid)
	b[10] = 0x80
	copy(b[28:34], mac)
	copy(b[236:240], []byte{99, 130, 83, 99})
	b = append(b, 53, 1, 1, 55, 3, 1, 3, 6, 255)
	return b
}

func parseDHCPOffer(b []byte, xid uint32) (detectDHCP, bool) {
	var d detectDHCP
	if len(b) < 240 || b[0] != 2 || binary.BigEndian.Uint32(b[4:8]) != xid || !strings.EqualFold(hex.EncodeToString(b[236:240]), "63825363") {
		return d, false
	}
	if ip := net.IP(b[16:20]); ip.To4() != nil {
		d.Address = ip.String()
	}
	for i := 240; i+1 < len(b); {
		if b[i] == 255 {
			break
		}
		if b[i] == 0 {
			i++
			continue
		}
		if i+2+int(b[i+1]) > len(b) {
			break
		}
		v := b[i+2 : i+2+int(b[i+1])]
		switch b[i] {
		case 53:
			d.Offer = len(v) > 0 && v[0] == 2
		case 1:
			if len(v) == 4 {
				d.Mask = net.IP(v).String()
			}
		case 3:
			if len(v) >= 4 {
				d.Gateway = net.IP(v[:4]).String()
			}
		case 6:
			for j := 0; j+3 < len(v); j += 4 {
				d.DNS = append(d.DNS, net.IP(v[j:j+4]).String())
			}
		}
		i += 2 + int(b[i+1])
	}
	return d, d.Offer
}

// parseRouterAdvertisement parses an ICMPv6 RA payload (including the 8-byte
// ICMP header). Prefix Information options are type 3.
func parseRouterAdvertisement(b []byte) detectRA {
	var r detectRA
	if len(b) < 16 || b[0] != 134 {
		return r
	}
	r.Seen, r.M, r.O = true, b[5]&0x80 != 0, b[5]&0x40 != 0
	for i := 16; i+1 < len(b); {
		n := int(b[i+1]) * 8
		if n < 8 || i+n > len(b) {
			break
		}
		if b[i] == 3 && n >= 32 {
			ip := net.IP(b[i+16 : i+32])
			bits := int(b[i+2])
			r.Prefix = fmt.Sprintf("%s/%d", ip, bits)
		}
		i += n
	}
	return r
}

func apiNetWANDetect(r apiReq) apiResp {
	if r.method != "POST" {
		return errResp(405, "POST required")
	}
	var in struct {
		Port    string `json:"port"`
		Timeout int    `json:"timeout"`
	}
	if json.Unmarshal(r.body, &in) != nil || !validDetectPort(in.Port) {
		return errResp(400, "bad port")
	}
	if in.Timeout == 0 {
		in.Timeout = 8
	}
	if in.Timeout < 1 || in.Timeout > 8 {
		return errResp(400, "timeout must be 1-8 seconds")
	}
	c, err := loadConfig(ConfigPath, SecretsPath)
	if err != nil {
		return errResp(500, "%v", err)
	}
	return apiResp{body: detectWAN(c, in.Port, time.Duration(in.Timeout)*time.Second)}
}

func wanDetectCommand(c *Config, args []string) error {
	if len(args) < 2 || args[0] != "detect" {
		return fmt.Errorf("mr wan detect PORT [--timeout SECONDS]")
	}
	port := args[1]
	timeout := 8
	for i := 2; i < len(args); i++ {
		if args[i] == "--timeout" && i+1 < len(args) {
			timeout, _ = strconv.Atoi(args[i+1])
			i++
		} else {
			return fmt.Errorf("mr wan detect PORT [--timeout SECONDS]")
		}
	}
	if !validDetectPort(port) || timeout < 1 || timeout > 8 {
		return fmt.Errorf("bad port or timeout (1-8 seconds)")
	}
	return json.NewEncoder(os.Stdout).Encode(detectWAN(c, port, time.Duration(timeout)*time.Second))
}

func validDetectPort(port string) bool {
	if !validDev(port) {
		return false
	}
	d := filepath.Join("/sys/class/net", port)
	if _, err := os.Stat(filepath.Join(d, "address")); err != nil {
		return false
	}
	if _, err := os.Stat(filepath.Join(d, "bridge")); err == nil {
		return false
	}
	if port == "lo" || strings.HasPrefix(port, "br-") || strings.HasPrefix(port, "ppp") || strings.HasPrefix(port, "tun") {
		return false
	}
	return true
}
