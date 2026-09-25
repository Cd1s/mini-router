package main

// proxy module: node types. Every structured type is validated here and rendered to exactly one
// sing-box 1.14 outbound. Credentials (UUIDs, passwords) live in secrets.yaml and are referenced by
// name (*_secret); everything else (server, SNI, reality public key, transport path, ...) is plain
// config. Anything else sing-box supports goes through a custom node (outbound JSON in a secret).

import (
	"encoding/base64"
	"fmt"
	"net"
	"reflect"
	"regexp"
	"strconv"
	"strings"
)

// proxyTypeSpec describes one node type: which router.yaml keys it uses and how TLS works.
type proxyTypeSpec struct {
	Label     string
	Keys      map[string]bool // allowed keys besides name and type
	TLS       int             // 0 no TLS, 1 optional (tls: true), 2 always on (QUIC / TLS-only protocols)
	UTLS      bool            // uTLS fingerprint (TCP TLS only; QUIC has no uTLS)
	Reality   bool
	Transport bool // V2Ray transports: ws | grpc | http | httpupgrade
}

const (
	proxyKeysTLS       = "tls sni alpn insecure "
	proxyKeysTransport = "transport path host service_name early_data "
)

func proxySpec(label string, keys string, tls int, utls, reality, transport bool) *proxyTypeSpec {
	s := &proxyTypeSpec{Label: label, Keys: map[string]bool{}, TLS: tls, UTLS: utls, Reality: reality, Transport: transport}
	if tls > 0 {
		keys += " " + proxyKeysTLS
	}
	if utls {
		keys += " fingerprint"
	}
	if reality {
		keys += " reality_public_key reality_short_id"
	}
	if transport {
		keys += " " + proxyKeysTransport
	}
	for _, k := range strings.Fields(keys) {
		s.Keys[k] = true
	}
	return s
}

// proxyTypes: every node type ("" = shadowsocks, for configs written before types existed).
var proxyTypes = map[string]*proxyTypeSpec{
	"shadowsocks": proxySpec("Shadowsocks", "server port method password_secret tcp_only tfo", 0, false, false, false),
	"vless":       proxySpec("VLESS", "server port uuid_secret flow packet_encoding tcp_only tfo", 1, true, true, true),
	"vmess":       proxySpec("VMess", "server port uuid_secret security alter_id packet_encoding tcp_only tfo", 1, true, false, true),
	"trojan":      proxySpec("Trojan", "server port password_secret tcp_only tfo", 1, true, true, true),
	"hysteria2":   proxySpec("Hysteria2", "server port password_secret up_mbps down_mbps obfs obfs_password_secret hop_ports tcp_only", 2, false, false, false),
	"tuic":        proxySpec("TUIC", "server port uuid_secret password_secret congestion_control udp_relay_mode tcp_only", 2, false, false, false),
	"anytls":      proxySpec("AnyTLS", "server port password_secret tfo", 2, true, true, false),
	"socks":       proxySpec("SOCKS5", "server port username password_secret tcp_only tfo", 0, false, false, false),
	"http":        proxySpec("HTTP", "server port username password_secret tfo", 1, true, false, false),
	"custom":      proxySpec("custom", "json_secret", 0, false, false, false),
}

// proxyTypeNames lists the node types in the order the docs and errors show them.
var proxyTypeNames = []string{"shadowsocks", "vless", "vmess", "trojan", "hysteria2", "tuic", "anytls", "socks", "http", "custom"}

// proxyNodeType returns the effective type ("" means shadowsocks).
func proxyNodeType(n *ProxyNode) string {
	if n.Type == "" {
		return "shadowsocks"
	}
	return n.Type
}

// proxySecretFields: node keys that hold secret NAMES, with the suffix used for generated names.
var proxySecretFields = []struct{ Key, Suffix string }{
	{"password_secret", "password"}, {"uuid_secret", "uuid"}, {"obfs_password_secret", "obfs"}, {"json_secret", "json"},
}

// secretRefs returns the secret names this node references (non-empty only).
func (n *ProxyNode) secretRefs() []string {
	var out []string
	for _, k := range []string{n.Password, n.UUID, n.ObfsPassword, n.JSON} {
		if k != "" {
			out = append(out, k)
		}
	}
	return out
}

// secretField returns a pointer to the node field holding the secret name for a key ("uuid_secret").
func (n *ProxyNode) secretField(key string) *string {
	switch key {
	case "password_secret":
		return &n.Password
	case "uuid_secret":
		return &n.UUID
	case "obfs_password_secret":
		return &n.ObfsPassword
	case "json_secret":
		return &n.JSON
	}
	return nil
}

// proxyNodeKeys lists the router.yaml keys set on n (non-zero), except name and type.
func proxyNodeKeys(n *ProxyNode) []string {
	v := reflect.ValueOf(n).Elem()
	t := v.Type()
	var out []string
	for i := 0; i < t.NumField(); i++ {
		k, _, _ := strings.Cut(t.Field(i).Tag.Get("yaml"), ",")
		if k == "" || k == "-" || k == "name" || k == "type" || v.Field(i).IsZero() {
			continue
		}
		out = append(out, k)
	}
	return out
}

var (
	reProxyUUID    = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	reProxyALPN    = regexp.MustCompile(`^[A-Za-z0-9._/-]{1,32}$`)
	reProxyPath    = regexp.MustCompile(`^/[A-Za-z0-9._~!$&()*+,;=:@%/-]{0,200}$`)
	reProxyGRPC    = regexp.MustCompile(`^[A-Za-z0-9._~/-]{1,128}$`)
	reProxyShortID = regexp.MustCompile(`^([0-9a-fA-F]{2}){0,8}$`)
	reProxyHop     = regexp.MustCompile(`^[0-9]{1,5}(-[0-9]{1,5})?(,[0-9]{1,5}(-[0-9]{1,5})?){0,15}$`)
)

// value sets (enums) of the structured node fields
var (
	proxyFingerprints = []string{"chrome", "firefox", "edge", "safari", "360", "qq", "ios", "android", "random", "randomized"}
	proxyTransports   = []string{"ws", "grpc", "http", "httpupgrade"}
	proxyVMessSec     = []string{"auto", "none", "zero", "aes-128-gcm", "chacha20-poly1305"}
	proxyPacketEnc    = []string{"xudp", "packetaddr", "none"}
	proxyCongestion   = []string{"cubic", "new_reno", "bbr"}
	proxyUDPRelay     = []string{"native", "quic"}
	proxyFlows        = []string{"xtls-rprx-vision"}
)

func proxyOneOf(v string, set []string) bool {
	for _, s := range set {
		if v == s {
			return true
		}
	}
	return false
}

// proxyHostOK: an IP address or a DNS name (the same check as for server).
func proxyHostOK(s string) bool {
	return net.ParseIP(s) != nil || (len(s) <= 253 && reProxyHost.MatchString(s))
}

// proxyUserOK: a proxy user name — printable ASCII without spaces, quotes or backslashes.
func proxyUserOK(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for _, r := range s {
		if r <= ' ' || r >= 0x7f || r == '"' || r == '\'' || r == '\\' || r == '`' {
			return false
		}
	}
	return true
}

// proxyRealityKeyOK: an X25519 public key as sing-box expects it (base64url without padding, 32 bytes).
func proxyRealityKeyOK(s string) bool {
	b, err := base64.RawURLEncoding.DecodeString(s)
	return err == nil && len(b) == 32
}

// proxySecretLookup returns a secret's value; ok=false when it is not available.
type proxySecretLookup func(key string) (string, bool)

// proxyNodeProblems checks one node. Problems are "<key>: <message>" (the caller adds the path);
// they never contain secret values. With needSecrets, every referenced secret must exist.
func proxyNodeProblems(n *ProxyNode, secret proxySecretLookup, needSecrets bool) []string {
	var errs []string
	add := func(f string, a ...any) { errs = append(errs, fmt.Sprintf(f, a...)) }
	typ := proxyNodeType(n)
	spec := proxyTypes[typ]
	if spec == nil {
		add("type: one of %s; got %q", strings.Join(proxyTypeNames, ", "), n.Type)
		return errs
	}
	for _, k := range proxyNodeKeys(n) {
		if !spec.Keys[k] {
			add("%s: not used by %s nodes", k, spec.Label)
		}
	}
	// secrets: the name must be well-formed; the value is checked when it is available
	secretVal := func(key, name string, required bool) (string, bool) {
		if name == "" {
			if required {
				add("%s: secret name [a-z0-9_-]{1,40} required, got %q", key, name)
			}
			return "", false
		}
		if !reProxySecret.MatchString(name) {
			add("%s: secret name [a-z0-9_-]{1,40} required, got %q", key, name)
			return "", false
		}
		v, ok := secret(name)
		if !ok && needSecrets {
			add("%s: secret %q missing from secrets.yaml", key, name)
		}
		return v, ok
	}
	password := func(key, name string, required bool) {
		if v, ok := secretVal(key, name, required); ok {
			if v == "" {
				add("%s: empty password", key)
			} else if !safeText(v) || len(v) > 1024 {
				add("%s: password must be printable text up to 1024 bytes", key)
			}
		}
	}
	if typ == "custom" {
		if raw, ok := secretVal("json_secret", n.JSON, true); ok {
			if _, _, err := proxyCustomOutbound(raw); err != nil {
				add("json_secret: %v", err)
			}
		}
		return errs
	}

	if !proxyHostOK(n.Server) {
		add("server: IP address or hostname, got %q", n.Server)
	}
	if n.Port < 1 || n.Port > 65535 {
		add("port: 1-65535, got %d", n.Port)
	}
	switch typ {
	case "shadowsocks":
		keyLen, ok := proxySSMethods[n.Method]
		if !ok {
			add("method: one of 2022-blake3-aes-128-gcm, 2022-blake3-aes-256-gcm, 2022-blake3-chacha20-poly1305, aes-128-gcm, aes-192-gcm, aes-256-gcm, chacha20-ietf-poly1305, xchacha20-ietf-poly1305; got %q", n.Method)
		}
		if pw, ok := secretVal("password_secret", n.Password, true); ok {
			if msg := proxyCheckSSPassword(pw, keyLen); msg != "" {
				add("password_secret: %s", msg)
			}
		}
	case "vless", "vmess", "tuic":
		if v, ok := secretVal("uuid_secret", n.UUID, true); ok && !reProxyUUID.MatchString(v) {
			add("uuid_secret: the secret is not a UUID (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)")
		}
		if typ == "tuic" {
			password("password_secret", n.Password, true)
		}
	case "trojan", "hysteria2", "anytls":
		password("password_secret", n.Password, true)
	case "socks", "http":
		if n.Username != "" && !proxyUserOK(n.Username) {
			add("username: printable ASCII without spaces or quotes (max 128), got %q", n.Username)
		}
		password("password_secret", n.Password, false)
	}

	if n.Flow != "" {
		if !proxyOneOf(n.Flow, proxyFlows) {
			add("flow: xtls-rprx-vision or empty, got %q", n.Flow)
		}
		if !n.TLS || n.Transport != "" {
			add("flow: xtls-rprx-vision needs tls (or reality) over plain TCP (no transport)")
		}
	}
	if n.Security != "" && !proxyOneOf(n.Security, proxyVMessSec) {
		add("security: one of %s; got %q", strings.Join(proxyVMessSec, ", "), n.Security)
	}
	if n.AlterID < 0 || n.AlterID > 65535 {
		add("alter_id: 0-65535, got %d", n.AlterID)
	}
	if n.PacketEncoding != "" && !proxyOneOf(n.PacketEncoding, proxyPacketEnc) {
		add("packet_encoding: xudp, packetaddr or none; got %q", n.PacketEncoding)
	}
	for _, x := range []struct {
		key string
		v   int
	}{{"up_mbps", n.UpMbps}, {"down_mbps", n.DownMbps}} {
		if x.v < 0 || x.v > 100000 {
			add("%s: 0-100000 (0 = automatic), got %d", x.key, x.v)
		}
	}
	switch n.Obfs {
	case "":
		if n.ObfsPassword != "" {
			add("obfs_password_secret: only with obfs: salamander")
		}
	case "salamander":
		password("obfs_password_secret", n.ObfsPassword, true)
	default:
		add("obfs: salamander or empty, got %q", n.Obfs)
	}
	if n.HopPorts != "" {
		ok := reProxyHop.MatchString(n.HopPorts)
		for _, r := range strings.Split(n.HopPorts, ",") {
			ok = ok && validPorts(r)
		}
		if !ok {
			add("hop_ports: ports or ranges, e.g. 20000-30000 or 443,20000-30000; got %q", n.HopPorts)
		}
	}
	if n.CongestionControl != "" && !proxyOneOf(n.CongestionControl, proxyCongestion) {
		add("congestion_control: cubic, new_reno or bbr; got %q", n.CongestionControl)
	}
	if n.UDPRelayMode != "" && !proxyOneOf(n.UDPRelayMode, proxyUDPRelay) {
		add("udp_relay_mode: native or quic; got %q", n.UDPRelayMode)
	}

	// TLS
	tlsOn := spec.TLS == 2 || n.TLS
	if !tlsOn && spec.TLS == 1 && (n.SNI != "" || len(n.ALPN) > 0 || n.Insecure || n.Fingerprint != "" || n.RealityKey != "" || n.RealityShortID != "") {
		add("tls: sni / alpn / insecure / fingerprint / reality need tls: true")
	}
	if n.SNI != "" && !proxyHostOK(n.SNI) {
		add("sni: hostname, got %q", n.SNI)
	}
	if len(n.ALPN) > 8 {
		add("alpn: at most 8 entries")
	}
	for _, a := range n.ALPN {
		if !reProxyALPN.MatchString(a) {
			add("alpn: protocol names like h2, http/1.1, h3; got %q", a)
		}
	}
	if n.Fingerprint != "" && !proxyOneOf(n.Fingerprint, proxyFingerprints) {
		add("fingerprint: one of %s; got %q", strings.Join(proxyFingerprints, ", "), n.Fingerprint)
	}
	if n.RealityKey != "" {
		if !proxyRealityKeyOK(n.RealityKey) {
			add("reality_public_key: base64url X25519 public key (43 characters), got %q", n.RealityKey)
		}
		if n.SNI == "" {
			add("sni: reality needs the server name of the site it borrows (e.g. www.example.com)")
		}
	} else if n.RealityShortID != "" {
		add("reality_short_id: only with reality_public_key")
	}
	if n.RealityShortID != "" && !reProxyShortID.MatchString(n.RealityShortID) {
		add("reality_short_id: 0-16 hex digits (even count), got %q", n.RealityShortID)
	}

	// transport
	switch n.Transport {
	case "":
		if n.Path != "" || n.Host != "" || n.ServiceName != "" || n.EarlyData != 0 {
			add("transport: path / host / service_name / early_data need a transport (ws, grpc, http, httpupgrade)")
		}
	case "ws", "http", "httpupgrade":
		if n.ServiceName != "" {
			add("service_name: only for transport grpc")
		}
		if n.EarlyData != 0 && n.Transport != "ws" {
			add("early_data: only for transport ws")
		}
	case "grpc":
		if n.Path != "" || n.Host != "" || n.EarlyData != 0 {
			add("transport: grpc uses service_name (no path / host / early_data)")
		}
	default:
		add("transport: one of %s; got %q", strings.Join(proxyTransports, ", "), n.Transport)
	}
	if n.Path != "" && !reProxyPath.MatchString(n.Path) {
		add("path: /… without spaces, quotes, ? or #; got %q", n.Path)
	}
	if n.Host != "" && !proxyHostOK(n.Host) {
		add("host: hostname, got %q", n.Host)
	}
	if n.ServiceName != "" && !reProxyGRPC.MatchString(n.ServiceName) {
		add("service_name: letters, digits, . _ ~ / -; got %q", n.ServiceName)
	}
	if n.EarlyData < 0 || n.EarlyData > 65535 {
		add("early_data: 0-65535 bytes, got %d", n.EarlyData)
	}
	return errs
}

// proxyTLSObj renders the TLS block of a node.
func proxyTLSObj(n *ProxyNode) proxyObj {
	t := proxyObj{"enabled": true}
	if n.SNI != "" {
		t["server_name"] = n.SNI
	}
	if len(n.ALPN) > 0 {
		t["alpn"] = n.ALPN
	}
	if n.Insecure {
		t["insecure"] = true
	}
	fp := n.Fingerprint
	if n.RealityKey != "" {
		if fp == "" {
			fp = "chrome" // sing-box: uTLS is required by the reality client
		}
		t["reality"] = proxyObj{"enabled": true, "public_key": n.RealityKey, "short_id": n.RealityShortID}
	}
	if fp != "" {
		t["utls"] = proxyObj{"enabled": true, "fingerprint": fp}
	}
	return t
}

// proxyTransportObj renders the V2Ray transport of a node (nil: plain TCP).
func proxyTransportObj(n *ProxyNode) proxyObj {
	switch n.Transport {
	case "ws":
		t := proxyObj{"type": "ws"}
		if n.Path != "" {
			t["path"] = n.Path
		}
		if n.Host != "" {
			t["headers"] = proxyObj{"Host": n.Host}
		}
		if n.EarlyData > 0 {
			// Xray-compatible 0-RTT (path "?ed=2048" in share links): early data in Sec-WebSocket-Protocol
			t["max_early_data"] = n.EarlyData
			t["early_data_header_name"] = "Sec-WebSocket-Protocol"
		}
		return t
	case "http":
		t := proxyObj{"type": "http"}
		if n.Host != "" {
			t["host"] = []string{n.Host}
		}
		if n.Path != "" {
			t["path"] = n.Path
		}
		return t
	case "httpupgrade":
		t := proxyObj{"type": "httpupgrade"}
		if n.Host != "" {
			t["host"] = n.Host
		}
		if n.Path != "" {
			t["path"] = n.Path
		}
		return t
	case "grpc":
		t := proxyObj{"type": "grpc"}
		if n.ServiceName != "" {
			t["service_name"] = n.ServiceName
		}
		return t
	}
	return nil
}

// proxyNodeOutbound renders one node. endpoint=true: the object belongs to sing-box's "endpoints"
// (WireGuard is an endpoint since sing-box 1.11; it can still be used like an outbound).
func proxyNodeOutbound(c *Config, n *ProxyNode) (o proxyObj, endpoint bool, err error) {
	typ := proxyNodeType(n)
	sec := func(name string) string {
		if err != nil || name == "" {
			return ""
		}
		v, e := c.Secret(name)
		if e != nil {
			err = e
		}
		return v
	}
	if typ == "custom" {
		raw := sec(n.JSON)
		if err != nil {
			return nil, false, err
		}
		o, endpoint, err = proxyCustomOutbound(raw)
		if err != nil {
			return nil, false, fmt.Errorf("proxy node %s: %v", n.Name, err)
		}
		o["tag"] = n.Name
		return o, endpoint, nil
	}
	spec := proxyTypes[typ]
	if spec == nil {
		return nil, false, fmt.Errorf("proxy node %s: unknown type %q", n.Name, n.Type)
	}
	o = proxyObj{"type": typ, "tag": n.Name, "server": n.Server, "server_port": n.Port}
	switch typ {
	case "shadowsocks":
		o["method"], o["password"] = n.Method, sec(n.Password)
	case "vless":
		o["uuid"] = sec(n.UUID)
		if n.Flow != "" {
			o["flow"] = n.Flow
		}
	case "vmess":
		o["uuid"] = sec(n.UUID)
		o["security"] = "auto"
		if n.Security != "" {
			o["security"] = n.Security
		}
		o["alter_id"] = n.AlterID
	case "trojan", "anytls":
		o["password"] = sec(n.Password)
	case "hysteria2":
		o["password"] = sec(n.Password)
		if n.UpMbps > 0 {
			o["up_mbps"] = n.UpMbps
		}
		if n.DownMbps > 0 {
			o["down_mbps"] = n.DownMbps
		}
		if n.Obfs != "" {
			o["obfs"] = proxyObj{"type": n.Obfs, "password": sec(n.ObfsPassword)}
		}
		if n.HopPorts != "" {
			var ports []string
			for _, r := range strings.Split(n.HopPorts, ",") {
				lo, hi, ok := strings.Cut(r, "-")
				if !ok {
					hi = lo
				}
				ports = append(ports, lo+":"+hi) // sing-box wants "from:to", also for one port
			}
			o["server_ports"] = ports
		}
	case "tuic":
		o["uuid"], o["password"] = sec(n.UUID), sec(n.Password)
		if n.CongestionControl != "" {
			o["congestion_control"] = n.CongestionControl
		}
		if n.UDPRelayMode != "" {
			o["udp_relay_mode"] = n.UDPRelayMode
		}
	case "socks", "http":
		if typ == "socks" {
			o["version"] = "5"
		}
		if n.Username != "" {
			o["username"] = n.Username
		}
		if n.Password != "" {
			o["password"] = sec(n.Password)
		}
	}
	if err != nil {
		return nil, false, err
	}
	switch n.PacketEncoding {
	case "xudp", "packetaddr":
		o["packet_encoding"] = n.PacketEncoding
	case "none":
		if typ == "vless" {
			o["packet_encoding"] = "" // vless defaults to xudp; "" switches it off (vmess: off by default)
		}
	}
	if spec.TLS == 2 || (spec.TLS == 1 && n.TLS) {
		o["tls"] = proxyTLSObj(n)
	}
	if t := proxyTransportObj(n); t != nil {
		o["transport"] = t
	}
	if n.TCPOnly {
		o["network"] = "tcp"
	}
	if n.TFO {
		o["tcp_fast_open"] = true
	}
	return o, false, nil
}

// proxyNodeSummary is a short description of a node for lists ("vless · reality · vision").
func proxyNodeSummary(n *ProxyNode) string {
	typ := proxyNodeType(n)
	parts := []string{typ}
	switch typ {
	case "shadowsocks":
		parts = append(parts, n.Method)
	case "vmess":
		if n.Security != "" && n.Security != "auto" {
			parts = append(parts, n.Security)
		}
	case "hysteria2":
		if n.Obfs != "" {
			parts = append(parts, n.Obfs)
		}
		if n.HopPorts != "" {
			parts = append(parts, "hop "+n.HopPorts)
		}
	case "tuic":
		if n.CongestionControl != "" {
			parts = append(parts, n.CongestionControl)
		}
	}
	if n.Transport != "" {
		parts = append(parts, n.Transport)
	}
	if n.RealityKey != "" {
		parts = append(parts, "reality")
	} else if n.TLS && proxyTypes[typ] != nil && proxyTypes[typ].TLS == 1 {
		parts = append(parts, "tls")
	}
	if n.Flow != "" {
		parts = append(parts, "vision")
	}
	if n.Insecure {
		parts = append(parts, "insecure")
	}
	return strings.Join(parts, " · ")
}

// proxySecretName makes a secrets.yaml key for a node field: proxy_<node>_<suffix> in [a-z0-9_-],
// at most 40 characters, not in taken (which it updates).
func proxySecretName(node, suffix string, taken map[string]bool) string {
	base := strings.Map(func(r rune) rune {
		switch {
		case r >= 'A' && r <= 'Z':
			return r + 'a' - 'A'
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_', r == '-':
			return r
		}
		return '_'
	}, node)
	max := 40 - len("proxy__") - len(suffix)
	name := ""
	for i := 1; ; i++ {
		b, tail := base, ""
		if i > 1 {
			tail = strconv.Itoa(i)
		}
		if len(b)+len(tail) > max {
			b = b[:max-len(tail)]
		}
		name = "proxy_" + b + tail + "_" + suffix
		if !taken[name] {
			break
		}
	}
	taken[name] = true
	return name
}
