package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

var wellKnown = netip.MustParsePrefix("64:ff9b::/96")

type staticSources map[string]netip.Addr

func (s staticSources) Lookup(suffix string) (netip.Addr, bool) {
	addr, ok := s[suffix]
	return addr, ok
}

func TestSynthesizeEmbedsIPv4InLast32Bits(t *testing.T) {
	s := &Server{nat64: wellKnown}
	got := s.synthesize(netip.MustParseAddr("124.222.230.137"))
	if got.String() != "64:ff9b::7cde:e689" {
		t.Fatalf("got %s", got)
	}
	back, ok := s.unsynthesize(got)
	if !ok || back.String() != "124.222.230.137" {
		t.Fatalf("round trip: %s %v", back, ok)
	}
	if _, ok := s.unsynthesize(netip.MustParseAddr("2001:db8::1")); ok {
		t.Fatal("prefix 外的地址不能还原")
	}
}

func TestDestinationRejectsAddressesNAT64CannotReach(t *testing.T) {
	s := &Server{nat64: wellKnown}
	for _, blocked := range []string{"127.0.0.1", "192.168.1.6", "10.1.2.3", "172.16.0.1", "100.97.13.115", "169.254.1.1", "198.18.0.1", "0.1.2.3", "255.255.255.255", "2001:db8::1"} {
		if _, rep := s.destination(netip.MustParseAddr(blocked)); rep != repNotAllowed {
			t.Errorf("%s 应当拒绝，得到 %d", blocked, rep)
		}
	}
	for addr, want := range map[string]string{"8.8.8.8": "64:ff9b::808:808", "::ffff:1.1.1.1": "64:ff9b::101:101", "64:ff9b::a04f:680a": "64:ff9b::a04f:680a"} {
		got, rep := s.destination(netip.MustParseAddr(addr))
		if rep != repSucceeded || got.String() != want {
			t.Errorf("%s → %s (%d)，想要 %s", addr, got, rep, want)
		}
	}
}

func TestSourceTableFollowsPrefixRewrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sources.txt")
	if err := os.WriteFile(path, []byte("2001:db8:1:2::c001\n2001:db8:1:2::c101\nnot-an-address\n2001:db8:1:2:1::c102\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	table := &SourceTable{Path: path}
	if addr, ok := table.Lookup("c101"); !ok || addr.String() != "2001:db8:1:2::c101" {
		t.Fatalf("c101 → %s %v", addr, ok)
	}
	if addr, ok := table.Lookup("C001"); !ok || addr.String() != "2001:db8:1:2::c001" {
		t.Fatalf("大写后缀 → %s %v", addr, ok)
	}
	for _, missing := range []string{"c102", "c999", "zz", ""} {
		if _, ok := table.Lookup(missing); ok {
			t.Errorf("%q 不应找到", missing)
		}
	}

	// addrs.sh 换前缀后重写文件：下一次查找拿到新地址。
	later := time.Now().Add(2 * time.Second)
	if err := os.WriteFile(path, []byte("2001:db8:9:9::c101\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	os.Chtimes(path, later, later)
	if addr, ok := table.Lookup("c101"); !ok || addr.String() != "2001:db8:9:9::c101" {
		t.Fatalf("换前缀后 → %s %v", addr, ok)
	}
	if _, ok := table.Lookup("c001"); ok {
		t.Fatal("旧前缀的条目应当消失")
	}
}

type dialRecord struct {
	src netip.Addr
	dst netip.AddrPort
}

func startServer(t *testing.T, s *Server) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go s.Serve(ln)
	return ln.Addr().String()
}

func newTestServer(dial func(context.Context, netip.Addr, netip.AddrPort) (net.Conn, error)) *Server {
	s := NewServer(wellKnown, nil, 16)
	s.sources = staticSources{"c101": netip.MustParseAddr("2001:db8:1:2::c101")}
	s.dialTCP = dial
	return s
}

// socksHandshake 走完问候、认证和请求，返回应答码和连接。
func socksHandshake(t *testing.T, addr, user string, command byte, target []byte) (net.Conn, []byte) {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	conn.Write([]byte{5, 1, 2})
	method := make([]byte, 2)
	if _, err := io.ReadFull(conn, method); err != nil || method[1] != 2 {
		t.Fatalf("method %v %v", method, err)
	}
	auth := append([]byte{1, byte(len(user))}, user...)
	auth = append(auth, 1, 'x')
	conn.Write(auth)
	status := make([]byte, 2)
	if _, err := io.ReadFull(conn, status); err != nil {
		t.Fatal(err)
	}
	if status[1] != 0 {
		return conn, status
	}
	conn.Write(append([]byte{5, command, 0}, target...))
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("reply: %v", err)
	}
	return conn, reply
}

func ipv4Target(addr string, port uint16) []byte {
	v4 := netip.MustParseAddr(addr).As4()
	return binary.BigEndian.AppendUint16(append([]byte{1}, v4[:]...), port)
}

func TestConnectGoesThroughNAT64FromThePortSource(t *testing.T) {
	var mu sync.Mutex
	var record dialRecord
	s := newTestServer(func(_ context.Context, src netip.Addr, dst netip.AddrPort) (net.Conn, error) {
		mu.Lock()
		record = dialRecord{src, dst}
		mu.Unlock()
		client, upstream := net.Pipe()
		go func() { io.Copy(upstream, upstream) }() // 回声
		return client, nil
	})
	addr := startServer(t, s)

	conn, reply := socksHandshake(t, addr, "c101", 1, ipv4Target("124.222.230.137", 443))
	defer conn.Close()
	if reply[1] != repSucceeded {
		t.Fatalf("应答 %d", reply[1])
	}
	mu.Lock()
	got := record
	mu.Unlock()
	if got.src.String() != "2001:db8:1:2::c101" || got.dst.String() != "[64:ff9b::7cde:e689]:443" {
		t.Fatalf("从 %s 连 %s", got.src, got.dst)
	}
	conn.Write([]byte("ping"))
	echo := make([]byte, 4)
	if _, err := io.ReadFull(conn, echo); err != nil || string(echo) != "ping" {
		t.Fatalf("回声 %q %v", echo, err)
	}
}

func TestConnectRefusals(t *testing.T) {
	dialed := false
	s := newTestServer(func(context.Context, netip.Addr, netip.AddrPort) (net.Conn, error) {
		dialed = true
		return nil, errors.New("不该拨号")
	})
	addr := startServer(t, s)

	conn, status := socksHandshake(t, addr, "c999", 1, nil)
	conn.Close()
	if status[1] != 1 {
		t.Fatalf("未知后缀应当认证失败，得到 %v", status)
	}

	domain := append([]byte{3, 11}, "example.com"...)
	domain = binary.BigEndian.AppendUint16(domain, 443)
	conn, reply := socksHandshake(t, addr, "c101", 1, domain)
	conn.Close()
	if reply[1] != repAddressNotSupported {
		t.Fatalf("域名应答 %d", reply[1])
	}

	conn, reply = socksHandshake(t, addr, "c101", 1, ipv4Target("192.168.1.6", 80))
	conn.Close()
	if reply[1] != repNotAllowed {
		t.Fatalf("内网地址应答 %d", reply[1])
	}
	if dialed {
		t.Fatal("被拒绝的请求不应拨号")
	}
}

func TestConnectFailureReportsUnreachable(t *testing.T) {
	s := newTestServer(func(context.Context, netip.Addr, netip.AddrPort) (net.Conn, error) {
		return nil, errors.New("no route")
	})
	conn, reply := socksHandshake(t, startServer(t, s), "c101", 1, ipv4Target("8.8.8.8", 53))
	conn.Close()
	if reply[1] != repHostUnreachable {
		t.Fatalf("应答 %d", reply[1])
	}
}

func TestUDPHeaderRoundTrip(t *testing.T) {
	from := netip.MustParseAddrPort("8.8.8.8:53")
	packet := buildUDPHeader(from, []byte("answer"))
	target, payload, ok := parseUDPHeader(packet)
	if !ok || target != from || string(payload) != "answer" {
		t.Fatalf("%v %q %v", target, payload, ok)
	}
	if _, _, ok := parseUDPHeader([]byte{0, 0, 1, 1, 8, 8, 8, 8, 0, 53}); ok {
		t.Fatal("分片包应当丢弃")
	}
	if _, _, ok := parseUDPHeader(append([]byte{0, 0, 0, 3, 3}, "a.b"...)); ok {
		t.Fatal("域名应当丢弃")
	}
}

// fakePacketConn 代替远端 IPv6 UDP 套接字：记录发出去的包，按需注入回包。
type fakePacketConn struct {
	sent    chan sentPacket
	inbound chan sentPacket
	closed  chan struct{}
	once    sync.Once
}

type sentPacket struct {
	data []byte
	addr net.Addr
}

func newFakePacketConn() *fakePacketConn {
	return &fakePacketConn{sent: make(chan sentPacket, 4), inbound: make(chan sentPacket, 4), closed: make(chan struct{})}
}

func (f *fakePacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	select {
	case p := <-f.inbound:
		return copy(b, p.data), p.addr, nil
	case <-f.closed:
		return 0, nil, net.ErrClosed
	}
}

func (f *fakePacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	f.sent <- sentPacket{bytes.Clone(b), addr}
	return len(b), nil
}

func (f *fakePacketConn) Close() error { f.once.Do(func() { close(f.closed) }); return nil }
func (f *fakePacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("2001:db8:1:2::c101")}
}
func (f *fakePacketConn) SetDeadline(time.Time) error      { return nil }
func (f *fakePacketConn) SetReadDeadline(time.Time) error  { return nil }
func (f *fakePacketConn) SetWriteDeadline(time.Time) error { return nil }

func TestUDPAssociateRelaysThroughNAT64(t *testing.T) {
	remote := newFakePacketConn()
	var boundSource netip.Addr
	s := newTestServer(nil)
	s.listenUDP = func(src netip.Addr) (net.PacketConn, error) {
		boundSource = src
		return remote, nil
	}
	ctrl, reply := socksHandshake(t, startServer(t, s), "c101", 3, ipv4Target("0.0.0.0", 0))
	if reply[1] != repSucceeded {
		t.Fatalf("应答 %d", reply[1])
	}
	if boundSource.String() != "2001:db8:1:2::c101" {
		t.Fatalf("远端套接字绑在 %s", boundSource)
	}
	relayAddr := &net.UDPAddr{IP: net.IP(reply[4:8]), Port: int(binary.BigEndian.Uint16(reply[8:10]))}

	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.SetDeadline(time.Now().Add(5 * time.Second))
	query := append([]byte{0, 0, 0}, ipv4Target("8.8.8.8", 53)...)
	client.WriteToUDP(append(query, "query"...), relayAddr)

	select {
	case p := <-remote.sent:
		if string(p.data) != "query" || p.addr.String() != "[64:ff9b::808:808]:53" {
			t.Fatalf("发往 %s：%q", p.addr, p.data)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("没有转发出去")
	}

	remote.inbound <- sentPacket{[]byte("answer"), &net.UDPAddr{IP: net.ParseIP("64:ff9b::808:808"), Port: 53}}
	buf := make([]byte, 64)
	n, _, err := client.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	from, payload, ok := parseUDPHeader(buf[:n])
	if !ok || from.String() != "8.8.8.8:53" || string(payload) != "answer" {
		t.Fatalf("回包 %v %q %v", from, payload, ok)
	}

	ctrl.Close()
	select {
	case <-remote.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("控制连接断开后应当关掉远端套接字")
	}
}
