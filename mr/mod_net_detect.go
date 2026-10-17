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
	"syscall"
	"time"
)

type detectLink struct {
	Carrier bool   `json:"carrier"`
	Speed   int    `json:"speed_mbps,omitempty"`
	Duplex  string `json:"duplex,omitempty"`
}

type detectPPPoE struct {
	PADO bool   `json:"pado"`
	AC   string `json:"ac_name,omitempty"`
	Service string `json:"service_name,omitempty"`
}

type detectDHCP struct {
	Offer  bool     `json:"offer"`
	Address string   `json:"address,omitempty"`
	Mask    string   `json:"mask,omitempty"`
	Gateway string   `json:"gateway,omitempty"`
	DNS     []string `json:"dns,omitempty"`
}

type detectRA struct {
	Seen   bool     `json:"seen"`
	Prefix string   `json:"prefix,omitempty"`
	M      bool     `json:"managed"`
	O      bool     `json:"other_config"`
}

type wanDetectResult struct {
	Port          string       `json:"port"`
	Link          detectLink   `json:"link"`
	PPPoE         detectPPPoE  `json:"pppoe"`
	DHCP          detectDHCP   `json:"dhcp"`
	IPv6RA        detectRA     `json:"ipv6_ra"`
	Recommendation string      `json:"recommendation"` // pppoe | dhcp | static
	LANConflict   bool         `json:"lan_conflict"`
	SuggestedLAN  string       `json:"suggested_lan,omitempty"`
	ElapsedMS     int64        `json:"elapsed_ms"`
}

type detectObservation struct {
	PPPoE detectPPPoE
	DHCP  detectDHCP
	RA    detectRA
}

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
	r := wanDetectResult{Port: port, Link: linkDetect(port), Recommendation: "dhcp"}
	if timeout <= 0 || timeout > 8*time.Second {
		timeout = 8 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	o, _ := wanDetectProbe(ctx, port)
	r.PPPoE, r.DHCP, r.IPv6RA = o.PPPoE, o.DHCP, o.RA
	switch {
	case r.PPPoE.PADO:
		r.Recommendation = "pppoe"
	case r.DHCP.Offer:
		r.Recommendation = "dhcp"
	case r.Link.Carrier:
		r.Recommendation = "static"
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
		if !n.Contains(upstream.IP) {
			return s
		}
	}
	return "10.254.0.1/24"
}

func probeWAN(ctx context.Context, port string) (detectObservation, error) {
	var out detectObservation
	// pppoe-discovery is part of the Alpine ppp package on supported images.  It
	// sends PADI/PADR discovery only and never starts pppd or changes the link.
	if p, err := exec.LookPath("pppoe-discovery"); err == nil {
		sec := int(time.Until(deadline(ctx)).Seconds())
		if sec < 1 { sec = 1 }
		cmd := exec.CommandContext(ctx, p, "-I", port, "-t", strconv.Itoa(sec))
		if b, e := cmd.Output(); e == nil {
			out.PPPoE = parsePPPoEDiscovery(string(b))
		}
	}
	if d, err := probeDHCP(ctx, port); err == nil {
		out.DHCP = d
	}
	return out, nil
}

func deadline(ctx context.Context) time.Time {
	d, ok := ctx.Deadline(); if !ok { return time.Now().Add(2*time.Second) }; return d
}

func parsePPPoEDiscovery(s string) detectPPPoE {
	p := detectPPPoE{PADO: strings.Contains(strings.ToLower(s), "pado") || strings.Contains(strings.ToLower(s), "access concentrator")}
	for _, line := range strings.Split(s, "\n") {
		l := strings.TrimSpace(line); low := strings.ToLower(l)
		for _, key := range []string{"ac-name", "access concentrator", "service-name", "service name"} {
			if i := strings.Index(low, key); i >= 0 {
				v := strings.Trim(strings.TrimSpace(l[i+len(key):]), "=: \t\"")
				if strings.Contains(key, "service") { p.Service = v } else { p.AC = v }
			}
		}
	}
	return p
}

func probeDHCP(ctx context.Context, port string) (detectDHCP, error) {
	var out detectDHCP
	mac, err := net.ParseMAC(strings.TrimSpace(readFile(filepath.Join("/sys/class/net", port, "address"))))
	if err != nil || len(mac) != 6 { return out, fmt.Errorf("no mac") }
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 68}); if err != nil { return out, err }
	defer conn.Close()
	if f, e := conn.File(); e == nil { _ = syscall.SetsockoptInt(int(f.Fd()), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1); _ = f.Close() }
	var xidb [4]byte; _, _ = rand.Read(xidb[:])
	xid := binary.BigEndian.Uint32(xidb[:]); pkt := dhcpDiscover(xid, mac)
	if _, err = conn.WriteToUDP(pkt, &net.UDPAddr{IP: net.IPv4bcast, Port: 67}); err != nil { return out, err }
	_ = conn.SetReadDeadline(deadline(ctx))
	buf := make([]byte, 1500)
	for {
		n, _, e := conn.ReadFromUDP(buf); if e != nil { return out, e }
		d, ok := parseDHCPOffer(buf[:n], xid); if ok { return d, nil }
	}
}

func dhcpDiscover(xid uint32, mac net.HardwareAddr) []byte {
	b := make([]byte, 240, 300); b[0], b[1], b[2], b[3] = 1, 1, 6, 0; binary.BigEndian.PutUint32(b[4:8], xid); b[10] = 0x80; copy(b[28:34], mac); copy(b[236:240], []byte{99,130,83,99})
	b = append(b, 53, 1, 1, 55, 3, 1, 3, 6, 255); return b
}

func parseDHCPOffer(b []byte, xid uint32) (detectDHCP, bool) {
	var d detectDHCP
	if len(b) < 240 || b[0] != 2 || binary.BigEndian.Uint32(b[4:8]) != xid || !strings.EqualFold(hex.EncodeToString(b[236:240]), "63825363") { return d, false }
	if ip := net.IP(b[16:20]); ip.To4() != nil { d.Address = ip.String() }
	for i := 240; i+1 < len(b); {
		if b[i] == 255 { break }; if b[i] == 0 { i++; continue }; if i+2+int(b[i+1]) > len(b) { break }; v := b[i+2:i+2+int(b[i+1])]
		switch b[i] { case 53: d.Offer = len(v)>0 && v[0]==2; case 1: if len(v)==4 { d.Mask=net.IP(v).String() }; case 3: if len(v)>=4 { d.Gateway=net.IP(v[:4]).String() }; case 6: for j:=0;j+3<len(v);j+=4 { d.DNS=append(d.DNS,net.IP(v[j:j+4]).String()) } }
		i += 2+int(b[i+1])
	}
	return d, d.Offer
}

// parseRouterAdvertisement parses an ICMPv6 RA payload (including the 8-byte
// ICMP header). Prefix Information options are type 3.
func parseRouterAdvertisement(b []byte) detectRA {
	var r detectRA
	if len(b) < 16 || b[0] != 134 { return r }; r.Seen, r.M, r.O = true, b[5]&0x80 != 0, b[5]&0x40 != 0
	for i:=16; i+1<len(b); { n:=int(b[i+1])*8; if n<8 || i+n>len(b) { break }; if b[i]==3 && n>=32 { ip:=net.IP(b[i+16:i+32]); bits:=int(b[i+2]); r.Prefix=fmt.Sprintf("%s/%d",ip,bits) }; i+=n }
	return r
}

func apiNetWANDetect(r apiReq) apiResp {
	if r.method != "POST" { return errResp(405, "POST required") }
	var in struct { Port string `json:"port"`; Timeout int `json:"timeout"` }
	if json.Unmarshal(r.body, &in) != nil || !validDev(in.Port) { return errResp(400, "bad port") }
	if in.Timeout == 0 { in.Timeout = 8 }; if in.Timeout < 1 || in.Timeout > 8 { return errResp(400, "timeout must be 1-8 seconds") }
	c, err := loadConfig(ConfigPath, SecretsPath); if err != nil { return errResp(500, "%v", err) }
	return apiResp{body: detectWAN(c, in.Port, time.Duration(in.Timeout)*time.Second)}
}

func wanDetectCommand(c *Config, args []string) error {
	if len(args)<2 || args[0]!="detect" { return fmt.Errorf("mr wan detect PORT [--timeout SECONDS]") }
	port:=args[1]; timeout:=8
	for i:=2;i<len(args);i++ { if args[i]=="--timeout" && i+1<len(args) { timeout,_=strconv.Atoi(args[i+1]); i++ } else { return fmt.Errorf("mr wan detect PORT [--timeout SECONDS]") } }
	if !validDev(port) || timeout<1 || timeout>8 { return fmt.Errorf("bad port or timeout (1-8 seconds)") }
	return json.NewEncoder(os.Stdout).Encode(detectWAN(c,port,time.Duration(timeout)*time.Second))
}
