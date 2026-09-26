package main

// sys module: Wake-on-LAN — `mr wol MAC|HOST [NETWORK]`, web UI action sys.wol (buttons on 终端设备 and
// DHCP 静态分配), schedule action `wol HOST`.
//
// The magic packet (6 × 0xff, then the MAC 16 times: 102 bytes) is a UDP datagram to port 9 of the
// LAN-side network's directed broadcast (e.g. 192.168.1.255), sent three times from the router's address
// on that network with the socket pinned to its bridge (SO_BINDTODEVICE): it can only leave there, never
// through a WAN (255.255.255.255 would follow the default route). HOST is a dhcp.hosts name or a device; the network
// is the one the host's address is in, else the main LAN. No config, nothing resident. Waking a device
// from outside goes through the web UI (e.g. over Tailscale): there is no WOL listener on the WAN.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
)

// wolPort is the UDP port of the magic packet (discard; a variable for tests).
var wolPort = 9

// wolPacket: 6 × 0xff, then mac 16 times.
func wolPacket(mac net.HardwareAddr) []byte {
	p := bytes.Repeat([]byte{0xff}, 6)
	for i := 0; i < 16; i++ {
		p = append(p, mac...)
	}
	return p
}

// wolTarget resolves a MAC or a dhcp.hosts name, and the optional network name, to the MAC, the host
// name (if known) and the LAN-side network to send on.
func wolTarget(c *Config, target, network string) (net.HardwareAddr, string, LANNet, error) {
	var mac net.HardwareAddr
	var host string
	var hostIP net.IP
	switch {
	case reMAC.MatchString(target):
		mac, _ = net.ParseMAC(target)
		for _, h := range c.knownHosts() {
			if strings.EqualFold(h.MAC, target) {
				host, hostIP = h.Name, net.ParseIP(h.IP)
			}
		}
	case reHostname.MatchString(target):
		for _, h := range c.knownHosts() { // a device with several MACs: the first one
			if h.Name != "" && strings.EqualFold(h.Name, target) {
				mac, _ = net.ParseMAC(h.MAC)
				host, hostIP = h.Name, net.ParseIP(h.IP)
				break
			}
		}
		if mac == nil {
			return nil, "", LANNet{}, fmt.Errorf("no dhcp.hosts entry or device named %q", target)
		}
	default:
		return nil, "", LANNet{}, fmt.Errorf("a MAC address (aa:bb:cc:dd:ee:ff), a dhcp.hosts name or a device, got %q", target)
	}
	if len(mac) != 6 || mac[0]&1 != 0 || bytes.Equal(mac, make(net.HardwareAddr, 6)) {
		return nil, "", LANNet{}, fmt.Errorf("%s is not a unicast MAC address", target)
	}
	nets := c.LANNets()
	var n *LANNet
	switch {
	case network != "":
		for i := range nets {
			if nets[i].Name == network {
				n = &nets[i]
			}
		}
		if n == nil {
			return nil, "", LANNet{}, fmt.Errorf("no LAN-side network %q", network)
		}
	case hostIP != nil:
		n = lanNetFor(c, hostIP)
	}
	if n == nil {
		n = &nets[0]
	}
	return mac, host, *n, nil
}

// wolBroadcast: the router's address on n and n's directed broadcast address.
func wolBroadcast(n LANNet) (src, bcast net.IP, err error) {
	ip, ipn, err := net.ParseCIDR(n.IPv4)
	if err != nil || ip.To4() == nil {
		return nil, nil, fmt.Errorf("network %s has no IPv4 address", n.Name)
	}
	if ones, _ := ipn.Mask.Size(); ones > 30 {
		return nil, nil, fmt.Errorf("network %s (/%d) has no broadcast address", n.Name, ones)
	}
	b := make(net.IP, 4)
	for i, x := range ipn.IP.To4() {
		b[i] = x | ^ipn.Mask[i]
	}
	return ip.To4(), b, nil
}

// wolSend sends pkt three times from src to dst:wolPort with the socket pinned to dev ("" = not pinned).
// Plain syscalls: a one-shot datagram needs none of the net package's poller machinery (a variable for tests).
var wolSend = func(dev string, src, dst net.IP, pkt []byte) error {
	s4, d4 := src.To4(), dst.To4()
	if s4 == nil || d4 == nil {
		return fmt.Errorf("IPv4 addresses required")
	}
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1); err != nil {
		return err
	}
	if dev != "" {
		if err := bindToDev(fd, dev); err != nil {
			return err
		}
	}
	from := &syscall.SockaddrInet4{}
	copy(from.Addr[:], s4)
	if err := syscall.Bind(fd, from); err != nil {
		return err
	}
	to := &syscall.SockaddrInet4{Port: wolPort}
	copy(to.Addr[:], d4)
	for i := 0; i < 3; i++ {
		if err := syscall.Sendto(fd, pkt, 0, to); err != nil {
			return err
		}
	}
	return nil
}

// wolResult: what was sent where (answer of `mr wol` and sys.wol).
type wolResult struct {
	MAC       string `json:"mac"`
	Host      string `json:"host,omitempty"`
	Network   string `json:"network"`
	Dev       string `json:"dev"`
	Broadcast string `json:"broadcast"`
}

// wolWake resolves target (MAC or dhcp.hosts name) and sends the magic packet.
func wolWake(c *Config, target, network string) (wolResult, error) {
	mac, host, n, err := wolTarget(c, target, network)
	if err != nil {
		return wolResult{}, err
	}
	src, b, err := wolBroadcast(n)
	if err != nil {
		return wolResult{}, err
	}
	r := wolResult{MAC: mac.String(), Host: host, Network: n.Name, Dev: n.Bridge, Broadcast: b.String()}
	if err := wolSend(n.Bridge, src, b, wolPacket(mac)); err != nil {
		return r, fmt.Errorf("wol: send on %s: %v", n.Bridge, err)
	}
	logf("wol: magic packet for %s%s to %s:%d on %s", mac, map[bool]string{true: " (" + host + ")"}[host != ""], b, wolPort, n.Bridge)
	return r, nil
}

// wolCommand: `mr wol MAC|HOST [NETWORK]`.
func wolCommand(c *Config, args []string) error {
	if len(args) < 1 || len(args) > 2 {
		return fmt.Errorf("usage: mr wol MAC|HOST [NETWORK]   (HOST: a dhcp.hosts name; NETWORK: lan or a networks[] name)")
	}
	network := ""
	if len(args) == 2 {
		network = args[1]
	}
	r, err := wolWake(c, args[0], network)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(r)
}

// apiSysWOL: POST {target: MAC | dhcp.hosts name, network (optional)} → wolResult.
func apiSysWOL(r apiReq) apiResp {
	if r.method != "POST" {
		return errResp(405, "POST required")
	}
	var in struct {
		Target  string `json:"target"`
		Network string `json:"network"`
	}
	json.Unmarshal(r.body, &in)
	if !reMAC.MatchString(in.Target) && !reHostname.MatchString(in.Target) {
		return errResp(400, "target: a MAC address or a dhcp.hosts name")
	}
	if in.Network != "" && !reName.MatchString(in.Network) {
		return errResp(400, "bad network name")
	}
	c, err := loadConfig(ConfigPath, SecretsPath)
	if err != nil {
		return errResp(500, "%v", err)
	}
	if _, _, _, err := wolTarget(c, in.Target, in.Network); err != nil {
		return errResp(400, "%v", err)
	}
	res, err := wolWake(c, in.Target, in.Network)
	if err != nil {
		return errResp(500, "%v", err)
	}
	return apiResp{body: res}
}
