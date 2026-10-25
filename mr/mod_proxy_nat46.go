package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var proxyNat46Gen = GenDir + "/nat46.json"

var proxyNat46DNS64Gen = GenDir + "/dns64.conf"
var proxyNat46DNS64Run = RunDir + "/dns64.conf"
var unboundBinaryExists = func() bool { _, err := os.Stat("/usr/sbin/unbound"); return err == nil }
var runUnboundCheckconf = func(path string) error {
	return exec.Command("/usr/sbin/unbound-checkconf", path).Run()
}
var nat46DNS64ServiceRunning = func() bool {
	return exec.Command("rc-service", "mr-dns64", "status").Run() == nil
}
var nat46DNS64ServiceAction = func(action string) error {
	return exec.Command("rc-service", "mr-dns64", action).Run()
}

func (n *ProxyNat46) listen() string {
	if n.Listen == "" {
		return "127.0.0.1:1094"
	}
	return n.Listen
}
func (n *ProxyNat46) prefix() string {
	if n.Prefix == "" {
		return "64:ff9b::/96"
	}
	return n.Prefix
}
func (n *ProxyNat46) maxConns() int {
	if n.MaxConns == 0 {
		return 4096
	}
	return n.MaxConns
}

func proxyNat46Defaults(c *Config) {
	// Defaults are applied by ProxyNat46.listen/prefix/maxConns and ProxyDNS64.synthAll.
	// Keep this hook side-effect free so old router.yaml files retain their canonical form.
}

func proxyNat46Validate(c *Config, v *Validator, used map[int]string) {
	n := &c.Proxy.Nat46
	if n.DNS64.Enabled && !n.Enabled {
		v.Add("proxy.nat46.dns64: requires proxy.nat46.enabled")
		return
	}
	if !c.Proxy.Enabled || !n.Enabled {
		return
	}
	listen := n.listen()
	ap, err := netip.ParseAddrPort(listen)
	if err != nil {
		v.Add("proxy.nat46.listen: loopback address required, got %q", listen)
	} else if !ap.Addr().Is4() || !ap.Addr().IsLoopback() {
		v.Add("proxy.nat46.listen: loopback address required, got %q", listen)
	} else if ap.Port() < 1024 || ap.Port() > 65535 {
		v.Add("proxy.nat46.listen: port 1024-65535 required, got %d", ap.Port())
	} else if owner, ok := used[int(ap.Port())]; ok {
		v.Add("proxy.nat46.listen: port %d already used by %s", ap.Port(), owner)
	} else {
		used[int(ap.Port())] = "proxy.nat46.listen"
	}
	prefix := n.prefix()
	p, err := netip.ParsePrefix(prefix)
	if err != nil || !p.Addr().Is6() || p.Bits() != 96 {
		v.Add("proxy.nat46.prefix: IPv6 /96 required, got %q", prefix)
	} else if p != p.Masked() {
		v.Add("proxy.nat46.prefix: network address required, got %q", prefix)
	}
	if n.SourcesFile != "" && !rePath.MatchString(n.SourcesFile) {
		v.Add("proxy.nat46.sources_file: absolute path required, got %q", n.SourcesFile)
	}
	maxConns := n.maxConns()
	if maxConns < 1 || maxConns > 65535 {
		v.Add("proxy.nat46.max_conns: 1-65535, got %d", maxConns)
	}
	if c.Proxy.Nat46.DNS64.Enabled {
		d := &c.Proxy.Nat46.DNS64
		listen := d.listen()
		ap, err := netip.ParseAddrPort(listen)
		if err != nil {
			v.Add("proxy.nat46.dns64.listen: loopback address required, got %q", listen)
		} else if !ap.Addr().Is4() || !ap.Addr().IsLoopback() {
			v.Add("proxy.nat46.dns64.listen: loopback address required, got %q", listen)
		} else if ap.Port() < 1024 || ap.Port() > 65535 {
			v.Add("proxy.nat46.dns64.listen: port 1024-65535 required, got %d", ap.Port())
		} else if owner, ok := used[int(ap.Port())]; ok {
			v.Add("proxy.nat46.dns64.listen: port %d already used by %s", ap.Port(), owner)
		} else {
			used[int(ap.Port())] = "proxy.nat46.dns64.listen"
		}
		if !unboundBinaryExists() {
			v.Add("proxy.nat46.dns64: /usr/sbin/unbound is not installed; apk add unbound")
		}
	}
}

func proxyNat46HasDNS(values []string) bool {
	for _, value := range values {
		host := strings.TrimSpace(strings.SplitN(value, "#", 2)[0])
		ip := net.ParseIP(host)
		if ip != nil && ip.To4() != nil && !ip.IsLoopback() && !ip.IsUnspecified() {
			return true
		}
	}
	return false
}

func (d *ProxyDNS64) listen() string {
	if d.Listen == "" {
		return "127.0.0.1:1153"
	}
	return d.Listen
}
func (d *ProxyDNS64) synthAll() bool { return d.SynthAll == nil || *d.SynthAll }

func proxyNat46Render(c *Config, out *Out) error {
	if !c.Proxy.Enabled || !c.Proxy.Nat46.Enabled {
		return nil
	}
	n := c.Proxy.Nat46
	out.Add(proxyNat46Gen, 0644, fmt.Sprintf("{\"listen\":%q,\"prefix\":%q,\"sources_file\":%q,\"max_conns\":%d}\n", n.listen(), n.prefix(), n.SourcesFile, n.maxConns()))
	if n.DNS64.Enabled {
		out.Add(proxyNat46DNS64Gen, 0644, proxyNat46DNS64Config(c))
	}
	return nil
}

func proxyNat46Orphans(c *Config) []string {
	var paths []string
	add := func(path string) {
		if _, err := os.Stat(path); err == nil {
			paths = append(paths, path)
		}
	}
	if !c.Proxy.Enabled || !c.Proxy.Nat46.Enabled {
		add(proxyNat46Gen)
	}
	if !c.Proxy.Enabled || !c.Proxy.Nat46.Enabled || !c.Proxy.Nat46.DNS64.Enabled {
		add(proxyNat46DNS64Gen)
		add(proxyNat46DNS64Run)
	}
	return paths
}

func proxyNat46DNS64Config(c *Config) string {
	d, n := c.Proxy.Nat46.DNS64, c.Proxy.Nat46
	var b strings.Builder
	// Alpine's unbound ships the RFC 6761 .test local zone. Keep it transparent so the lab's
	// authoritative isp.test record exercises the same forwarder and DNS64 path as real domains.
	fmt.Fprintf(&b, "server:\n    interface: %s\n    port: %s\n    access-control: 127.0.0.0/8 allow\n    do-ip6: no\n    module-config: \"dns64 iterator\"\n    local-zone: \"test.\" transparent\n    dns64-prefix: %s\n", d.listenAddr(), d.port(), n.prefix())
	if d.synthAll() {
		b.WriteString("    dns64-synthall: yes\n    dns64-ignore-aaaa: ::/0\n")
	}
	b.WriteString("    cache-min-ttl: 30\n    cache-max-ttl: 300\n    num-threads: 1\n    msg-cache-size: 2m\n    rrset-cache-size: 4m\n    username: \"unbound\"\n")
	return b.String()
}

func (d *ProxyDNS64) listenAddr() string { a, _, _ := net.SplitHostPort(d.listen()); return a }
func (d *ProxyDNS64) port() string       { _, p, _ := net.SplitHostPort(d.listen()); return p }

func proxyNat46DNS64Sync(c *Config) error {
	if !c.Proxy.Enabled || !c.Proxy.Nat46.Enabled || !c.Proxy.Nat46.DNS64.Enabled {
		return nil
	}
	base, err := os.ReadFile(proxyNat46DNS64Gen)
	if err != nil {
		return err
	}
	servers := proxyNat46DNS64Servers(c)
	if len(servers) == 0 {
		return nil // retain the previous runtime config until a usable DNS appears
	}
	var b strings.Builder
	b.Write(base)
	b.WriteString("forward-zone:\n    name: \".\"\n")
	for _, s := range servers {
		fmt.Fprintf(&b, "    forward-addr: %s\n", s)
	}
	data := []byte(b.String())
	old, _ := os.ReadFile(proxyNat46DNS64Run)
	if string(old) == string(data) {
		proxyNat46DNS64EnsureStarted()
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(proxyNat46DNS64Run), 0755); err != nil {
		return err
	}
	tmp := proxyNat46DNS64Run + ".check"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	defer os.Remove(tmp)
	if err := runUnboundCheckconf(tmp); err != nil {
		return fmt.Errorf("unbound-checkconf: %w", err)
	}
	if err := writeAtomic(proxyNat46DNS64Run, data, 0644); err != nil {
		return err
	}
	proxyNat46DNS64Reload()
	return nil
}

func proxyNat46DNS64EnsureStarted() {
	if os.Getenv("MR_DNS64_START_PRE") != "" {
		return
	}
	if nat46DNS64ServiceRunning() {
		return
	}
	if err := nat46DNS64ServiceAction("start"); err != nil {
		log.Printf("mr-dns64 start: %v", err)
	}
}

func proxyNat46DNS64Reload() {
	if os.Getenv("MR_DNS64_START_PRE") != "" {
		return
	}
	action := "start"
	if nat46DNS64ServiceRunning() {
		action = "reload"
	}
	if err := nat46DNS64ServiceAction(action); err != nil {
		log.Printf("mr-dns64 %s: %v", action, err)
	}
}

func proxyNat46DNS64Servers(c *Config) []string {
	var out []string
	seen := map[string]bool{}
	add := func(s string) {
		s = strings.TrimSpace(s)
		parts := strings.SplitN(s, "#", 2)
		host := strings.TrimSpace(parts[0])
		ip := net.ParseIP(host)
		if ip != nil && ip.To4() != nil && !ip.IsLoopback() && !ip.IsUnspecified() && !seen[host] {
			seen[host] = true
			if len(parts) == 2 && strings.TrimSpace(parts[1]) != "" {
				s = host + "@" + strings.TrimSpace(parts[1])
			} else {
				s = host
			}
			out = append(out, s)
		}
	}
	if b, err := os.ReadFile(resolvConf); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) == 2 && f[0] == "nameserver" {
				add(f[1])
			}
			if len(out) >= 2 {
				return out
			}
		}
	}
	// In manual / dot mode writeResolv is intentionally not changed, so use the WAN lease DNS
	// records directly. They are still the ISP resolvers and are independent of LAN DNS mode.
	for _, w := range sortedWANs(c, wanHealthMap(c)) {
		l, ok := readLease(w.Name)
		if !ok {
			continue
		}
		for _, s := range append(append([]string{}, l.DNS...), l.DNS6...) {
			add(s)
			if len(out) >= 2 {
				return out
			}
		}
	}
	for _, s := range c.DNS.Fallback {
		add(s)
		if len(out) >= 2 {
			break
		}
	}
	for _, s := range c.DNS.Servers {
		add(s)
		if len(out) >= 2 {
			return out
		}
	}
	return out
}

// localSourceTable resolves suffixes from current global IPv6 addresses when no table is configured.
type localSourceTable struct{}

var localIPv6ForLookup = localIPv6

func (localSourceTable) Lookup(id string) (netip.Addr, bool) {
	if addr, ok := parseLocalIPv6(id); ok {
		return addr, true
	}
	want, err := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(strings.TrimSpace(id)), "::"), 16, 16)
	if err != nil {
		return netip.Addr{}, false
	}
	var found netip.Addr
	count := 0
	for _, addr := range localIPv6ForLookup() {
		b := addr.As16()
		if id, ok := sourceInterfaceID(b); ok && id == uint16(want) {
			found, count = addr, count+1
		}
	}
	return found, count == 1
}

func parseLocalIPv6(s string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil || !a.Is6() || a.Is4In6() || !a.IsGlobalUnicast() {
		return netip.Addr{}, false
	}
	for _, x := range localIPv6ForLookup() {
		if x == a {
			return a, true
		}
	}
	return netip.Addr{}, false
}

func sourceInterfaceID(b [16]byte) (uint16, bool) {
	for _, x := range b[8:14] {
		if x != 0 {
			return 0, false
		}
	}
	return binary.BigEndian.Uint16(b[14:]), true
}

func localIPv6() []netip.Addr {
	var out []netip.Addr
	ifs, _ := net.Interfaces()
	for _, in := range ifs {
		as, _ := in.Addrs()
		for _, raw := range as {
			s := strings.SplitN(raw.String(), "/", 2)[0]
			if i := strings.LastIndexByte(s, '%'); i >= 0 {
				s = s[:i]
			}
			a, err := netip.ParseAddr(s)
			if err == nil && a.Is6() && a.IsGlobalUnicast() {
				out = append(out, a)
			}
		}
	}
	return out
}

// SOCKS5 应答码（RFC 1928）。
const (
	repSucceeded           = 0x00
	repGeneralFailure      = 0x01
	repNotAllowed          = 0x02
	repHostUnreachable     = 0x04
	repCommandNotSupported = 0x07
	repAddressNotSupported = 0x08
)

// SourceTable 按后缀（如 "c101"）找端口的 IPv6 源地址。文件由 addrs.sh 在每次运行时重写，
// 运营商换前缀后内容会变，所以每次查找前看一眼修改时间，变了就重读。
type SourceTable struct {
	Path string

	mu      sync.Mutex
	modTime time.Time
	size    int64
	byID    map[uint16]netip.Addr
}

// Lookup 的 suffix 是接口标识的最后 16 位（十六进制），前 48 位必须是 0：…::c101。
func (t *SourceTable) Lookup(suffix string) (netip.Addr, bool) {
	if addr, ok := parseLocalIPv6(suffix); ok {
		return addr, true
	}
	id, err := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(suffix), "::"), 16, 16)
	if err != nil {
		return netip.Addr{}, false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if info, err := os.Stat(t.Path); err == nil && (!info.ModTime().Equal(t.modTime) || info.Size() != t.size) {
		t.reload(info)
	}
	addr, ok := t.byID[uint16(id)]
	return addr, ok
}

func (t *SourceTable) reload(info os.FileInfo) {
	file, err := os.Open(t.Path)
	if err != nil {
		log.Printf("读源地址表失败：%v", err)
		return
	}
	defer file.Close()
	table := map[uint16]netip.Addr{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		addr, err := netip.ParseAddr(strings.TrimSpace(scanner.Text()))
		if err != nil || !addr.Is6() || addr.Is4In6() {
			continue
		}
		b := addr.As16()
		if b[8]|b[9]|b[10]|b[11]|b[12]|b[13] != 0 {
			continue
		}
		table[binary.BigEndian.Uint16(b[14:])] = addr
	}
	t.byID, t.modTime, t.size = table, info.ModTime(), info.Size()
}

type Server struct {
	nat64   netip.Prefix
	sources interface {
		Lookup(string) (netip.Addr, bool)
	}
	slots            chan struct{}
	handshakeTimeout time.Duration
	// 测试替换；默认从 src 发起真实的 IPv6 连接。
	dialTCP   func(ctx context.Context, src netip.Addr, dst netip.AddrPort) (net.Conn, error)
	listenUDP func(src netip.Addr) (net.PacketConn, error)
}

func NewServer(nat64 netip.Prefix, sources interface {
	Lookup(string) (netip.Addr, bool)
}, maxConns int) *Server {
	return &Server{
		nat64:            nat64,
		sources:          sources,
		slots:            make(chan struct{}, maxConns),
		handshakeTimeout: 10 * time.Second,
		dialTCP: func(ctx context.Context, src netip.Addr, dst netip.AddrPort) (net.Conn, error) {
			dialer := net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second, LocalAddr: &net.TCPAddr{IP: src.AsSlice()}}
			return dialer.DialContext(ctx, "tcp6", dst.String())
		},
		listenUDP: func(src netip.Addr) (net.PacketConn, error) {
			return net.ListenUDP("udp6", &net.UDPAddr{IP: src.AsSlice()})
		},
	}
}

func (s *Server) Serve(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			var temporary interface{ Temporary() bool }
			if errors.As(err, &temporary) && temporary.Temporary() {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return err
		}
		select {
		case s.slots <- struct{}{}:
			go func() {
				defer func() { <-s.slots }()
				s.handle(conn)
			}()
		default:
			conn.Close()
		}
	}
}

// synthesize 把 IPv4 嵌进 NAT64 前缀的最后 32 位（RFC 6052 /96）。
func (s *Server) synthesize(v4 netip.Addr) netip.Addr {
	b := s.nat64.Addr().As16()
	v := v4.As4()
	copy(b[12:], v[:])
	return netip.AddrFrom16(b)
}

func (s *Server) unsynthesize(addr netip.Addr) (netip.Addr, bool) {
	if !s.nat64.Contains(addr) {
		return netip.Addr{}, false
	}
	b := addr.As16()
	return netip.AddrFrom4([4]byte(b[12:])), true
}

// 不经 NAT64 的 IPv4 特殊用途段（IsGlobalUnicast/IsPrivate 之外的）：本网络、CGNAT/Tailscale、
// IETF 协议分配、基准测试（sing-box fakeip 也用它）、保留。
var nonRoutable = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

// destination 把客户端给的目标换成 NAT64 地址。内网、回环、CGNAT 等地址经 NAT64 本来就到不了，
// 直接拒绝，也就不会经代理端口摸到路由器本机或局域网。
func (s *Server) destination(addr netip.Addr) (netip.Addr, byte) {
	addr = addr.Unmap()
	switch {
	case addr.Is4():
		if !addr.IsGlobalUnicast() || addr.IsPrivate() || containsAddr(nonRoutable, addr) {
			return netip.Addr{}, repNotAllowed
		}
		return s.synthesize(addr), repSucceeded
	case s.nat64.Contains(addr):
		return addr, repSucceeded
	default:
		return netip.Addr{}, repNotAllowed
	}
}

func (s *Server) handle(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(s.handshakeTimeout))
	reader := bufio.NewReader(conn)

	src, ok := s.negotiate(conn, reader)
	if !ok {
		return
	}
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil || header[0] != 5 {
		return
	}
	command := header[1]
	target, rep := s.readAddress(reader, header[3])
	if rep != repSucceeded {
		writeReply(conn, rep, nil)
		return
	}
	switch command {
	case 1:
		s.connect(conn, reader, src, target)
	case 3:
		s.associate(conn, reader, src)
	default:
		writeReply(conn, repCommandNotSupported, nil)
	}
}

// negotiate 只接受用户名/密码认证：用户名是端口源地址的后缀，密码不检查（只监听本机）。
func (s *Server) negotiate(conn net.Conn, reader *bufio.Reader) (netip.Addr, bool) {
	var greeting [2]byte
	if _, err := io.ReadFull(reader, greeting[:]); err != nil || greeting[0] != 5 {
		return netip.Addr{}, false
	}
	methods := make([]byte, greeting[1])
	if _, err := io.ReadFull(reader, methods); err != nil {
		return netip.Addr{}, false
	}
	if !containsByte(methods, 2) {
		conn.Write([]byte{5, 0xff})
		return netip.Addr{}, false
	}
	conn.Write([]byte{5, 2})

	username, password, ok := readCredentials(reader)
	_ = password
	if !ok {
		return netip.Addr{}, false
	}
	if s.sources == nil {
		conn.Write([]byte{1, 1})
		return netip.Addr{}, false
	}
	src, found := s.sources.Lookup(username)
	if !found {
		conn.Write([]byte{1, 1})
		log.Printf("未知的源地址后缀 %q", username)
		return netip.Addr{}, false
	}
	conn.Write([]byte{1, 0})
	return src, true
}

func readCredentials(reader *bufio.Reader) (string, string, bool) {
	version, err := reader.ReadByte()
	if err != nil || version != 1 {
		return "", "", false
	}
	username, err := readShortString(reader)
	if err != nil {
		return "", "", false
	}
	password, err := readShortString(reader)
	if err != nil {
		return "", "", false
	}
	return username, password, true
}

func readShortString(reader *bufio.Reader) (string, error) {
	length, err := reader.ReadByte()
	if err != nil {
		return "", err
	}
	buf := make([]byte, length)
	_, err = io.ReadFull(reader, buf)
	return string(buf), err
}

// readAddress 读请求里的目标；域名不处理（sing-box 只会把 IP 字面量交过来）。
func (s *Server) readAddress(reader *bufio.Reader, atyp byte) (netip.AddrPort, byte) {
	var addr netip.Addr
	switch atyp {
	case 1:
		var b [4]byte
		if _, err := io.ReadFull(reader, b[:]); err != nil {
			return netip.AddrPort{}, repGeneralFailure
		}
		addr = netip.AddrFrom4(b)
	case 4:
		var b [16]byte
		if _, err := io.ReadFull(reader, b[:]); err != nil {
			return netip.AddrPort{}, repGeneralFailure
		}
		addr = netip.AddrFrom16(b)
	case 3:
		if name, err := readShortString(reader); err == nil {
			io.ReadFull(reader, make([]byte, 2))
			_ = name
		}
		return netip.AddrPort{}, repAddressNotSupported
	default:
		return netip.AddrPort{}, repAddressNotSupported
	}
	var port [2]byte
	if _, err := io.ReadFull(reader, port[:]); err != nil {
		return netip.AddrPort{}, repGeneralFailure
	}
	return netip.AddrPortFrom(addr, binary.BigEndian.Uint16(port[:])), repSucceeded
}

func (s *Server) connect(conn net.Conn, reader *bufio.Reader, src netip.Addr, target netip.AddrPort) {
	dst, rep := s.destination(target.Addr())
	if rep != repSucceeded {
		writeReply(conn, rep, nil)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	upstream, err := s.dialTCP(ctx, src, netip.AddrPortFrom(dst, target.Port()))
	cancel()
	if err != nil {
		writeReply(conn, repHostUnreachable, nil)
		return
	}
	defer upstream.Close()
	if err := writeReply(conn, repSucceeded, nil); err != nil {
		return
	}
	conn.SetDeadline(time.Time{})
	// 握手时多读进缓冲区的字节（客户端紧跟着发的首包）也要转发。
	if buffered := reader.Buffered(); buffered > 0 {
		data, _ := reader.Peek(buffered)
		if _, err := upstream.Write(data); err != nil {
			return
		}
	}
	relay(conn, upstream)
}

// relay 双向转发；一边结束后半关闭另一边，再给剩下的方向一分钟收尾，防止半开连接一直挂着。
func relay(a, b net.Conn) {
	done := make(chan struct{}, 2)
	copyHalf := func(dst, src net.Conn) {
		io.Copy(dst, src)
		if closer, ok := dst.(interface{ CloseWrite() error }); ok {
			closer.CloseWrite()
		}
		done <- struct{}{}
	}
	go copyHalf(a, b)
	go copyHalf(b, a)
	<-done
	deadline := time.Now().Add(time.Minute)
	a.SetDeadline(deadline)
	b.SetDeadline(deadline)
	<-done
}

// associate 处理 UDP：本机一侧收发带 SOCKS 头的数据报，远端一侧用端口源地址收发到 NAT64 地址。
// 控制连接断开时结束。
func (s *Server) associate(conn net.Conn, reader *bufio.Reader, src netip.Addr) {
	localIP := net.IPv4(127, 0, 0, 1)
	if tcp, ok := conn.LocalAddr().(*net.TCPAddr); ok {
		localIP = tcp.IP
	}
	local, err := net.ListenUDP("udp", &net.UDPAddr{IP: localIP})
	if err != nil {
		writeReply(conn, repGeneralFailure, nil)
		return
	}
	defer local.Close()
	remote, err := s.listenUDP(src)
	if err != nil {
		writeReply(conn, repGeneralFailure, nil)
		return
	}
	defer remote.Close()
	if err := writeReply(conn, repSucceeded, local.LocalAddr().(*net.UDPAddr)); err != nil {
		return
	}
	conn.SetDeadline(time.Time{})

	var client atomic.Pointer[net.UDPAddr]
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := local.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if !from.IP.IsLoopback() && !from.IP.Equal(localIP) {
				continue
			}
			client.Store(from)
			target, payload, ok := parseUDPHeader(buf[:n])
			if !ok {
				continue
			}
			dst, rep := s.destination(target.Addr())
			if rep != repSucceeded {
				continue
			}
			remote.WriteTo(payload, net.UDPAddrFromAddrPort(netip.AddrPortFrom(dst, target.Port())))
		}
	}()
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := remote.ReadFrom(buf)
			if err != nil {
				return
			}
			to := client.Load()
			udp, ok := from.(*net.UDPAddr)
			if to == nil || !ok {
				continue
			}
			addr, _ := netip.AddrFromSlice(udp.IP)
			v4, ok := s.unsynthesize(addr.Unmap())
			if !ok {
				continue
			}
			local.WriteToUDP(buildUDPHeader(netip.AddrPortFrom(v4, uint16(udp.Port)), buf[:n]), to)
		}
	}()
	io.Copy(io.Discard, reader)
}

// parseUDPHeader 解析 SOCKS5 UDP 头（RSV RSV FRAG ATYP ADDR PORT DATA），不支持分片和域名。
func parseUDPHeader(packet []byte) (netip.AddrPort, []byte, bool) {
	if len(packet) < 4 || packet[2] != 0 {
		return netip.AddrPort{}, nil, false
	}
	var addr netip.Addr
	rest := packet[4:]
	switch packet[3] {
	case 1:
		if len(rest) < 6 {
			return netip.AddrPort{}, nil, false
		}
		addr = netip.AddrFrom4([4]byte(rest[:4]))
		rest = rest[4:]
	case 4:
		if len(rest) < 18 {
			return netip.AddrPort{}, nil, false
		}
		addr = netip.AddrFrom16([16]byte(rest[:16]))
		rest = rest[16:]
	default:
		return netip.AddrPort{}, nil, false
	}
	return netip.AddrPortFrom(addr, binary.BigEndian.Uint16(rest[:2])), rest[2:], true
}

func buildUDPHeader(from netip.AddrPort, payload []byte) []byte {
	v4 := from.Addr().As4()
	packet := make([]byte, 0, 10+len(payload))
	packet = append(packet, 0, 0, 0, 1)
	packet = append(packet, v4[:]...)
	packet = binary.BigEndian.AppendUint16(packet, from.Port())
	return append(packet, payload...)
}

func writeReply(conn net.Conn, rep byte, bound *net.UDPAddr) error {
	reply := []byte{5, rep, 0, 1, 0, 0, 0, 0, 0, 0}
	if bound != nil {
		if v4 := bound.IP.To4(); v4 != nil {
			copy(reply[4:8], v4)
		}
		binary.BigEndian.PutUint16(reply[8:], uint16(bound.Port))
	}
	_, err := conn.Write(reply)
	return err
}

func containsAddr(prefixes []netip.Prefix, addr netip.Addr) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func containsByte(list []byte, value byte) bool {
	for _, b := range list {
		if b == value {
			return true
		}
	}
	return false
}

func isClosed(err error) bool {
	return errors.Is(err, net.ErrClosed)
}

// proxyNat46Serve is the long-running command used by mr-nat46. The config is loaded by the
// core dispatcher, so the service never needs a second copy of the router configuration.
type nat46ServeConfig struct {
	Listen      string `json:"listen"`
	Prefix      string `json:"prefix"`
	SourcesFile string `json:"sources_file"`
	MaxConns    int    `json:"max_conns"`
}

func nat46ServeConfigFromProxy(c *Config) nat46ServeConfig {
	n := c.Proxy.Nat46
	return nat46ServeConfig{Listen: n.listen(), Prefix: n.prefix(), SourcesFile: n.SourcesFile, MaxConns: n.maxConns()}
}

func nat46ServeConfigFromFile() (nat46ServeConfig, error) {
	b, err := os.ReadFile(proxyNat46Gen)
	if err != nil {
		return nat46ServeConfig{}, err
	}
	var cfg nat46ServeConfig
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nat46ServeConfig{}, fmt.Errorf("%s: %w", proxyNat46Gen, err)
	}
	return cfg, nil
}

func serveNat46(cfg nat46ServeConfig) error {
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:1094"
	}
	if cfg.Prefix == "" {
		cfg.Prefix = "64:ff9b::/96"
	}
	if cfg.MaxConns == 0 {
		cfg.MaxConns = 4096
	}
	listen, err := netip.ParseAddrPort(cfg.Listen)
	if err != nil || !listen.Addr().Is4() || !listen.Addr().IsLoopback() || listen.Port() < 1024 || listen.Port() > 65535 {
		return fmt.Errorf("NAT46 listen must be an IPv4 loopback address on port 1024-65535: %q", cfg.Listen)
	}
	prefix, err := netip.ParsePrefix(cfg.Prefix)
	if err != nil || !prefix.Addr().Is6() || prefix.Bits() != 96 {
		return fmt.Errorf("NAT64 prefix must be IPv6 /96: %q", cfg.Prefix)
	}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	var sources interface {
		Lookup(string) (netip.Addr, bool)
	}
	if cfg.SourcesFile == "" {
		sources = localSourceTable{}
	} else {
		sources = &SourceTable{Path: cfg.SourcesFile}
	}
	server := NewServer(prefix, sources, cfg.MaxConns)
	log.Printf("mr-nat46 listening on %s, prefix %s, sources %s", ln.Addr(), prefix, cfg.SourcesFile)
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
		<-sig
		_ = ln.Close()
	}()
	if err := server.Serve(ln); err != nil && !isClosed(err) {
		return err
	}
	return nil
}

// proxyNat46Serve is retained for direct module tests and the command dispatcher after config load.
func proxyNat46Serve(c *Config, args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("usage: mr proxy nat46 serve")
	}
	if !c.Proxy.Enabled || !c.Proxy.Nat46.Enabled {
		return fmt.Errorf("proxy.nat46 is disabled")
	}
	return serveNat46(nat46ServeConfigFromProxy(c))
}

// proxyNat46ServeFromFile is called before dispatch loads router.yaml or secrets.yaml. The
// generated file is 0644 and contains only the four values required by the unprivileged daemon.
func proxyNat46ServeFromFile(args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("usage: mr proxy nat46 serve")
	}
	cfg, err := nat46ServeConfigFromFile()
	if err != nil {
		return err
	}
	return serveNat46(cfg)
}
