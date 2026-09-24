package main

// proxy module: share-link import. proxy.parse / proxy.fetch (web UI) and `mr proxy parse|fetch`
// turn share links — ss:// (SIP002 and legacy), vless://, vmess:// (v2 base64 JSON and the URI
// form), trojan://, hysteria2:// / hy2://, tuic://, anytls://, socks5:// / socks://, http(s):// — or
// a base64 subscription of them into nodes plus the credential values to store as secrets. Every
// node passes the same validation as router.yaml. Errors name the line and never echo the link
// (it contains credentials).

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	proxyLinkMaxLine  = 16 << 10 // one link
	proxyLinkMaxNodes = 1000
)

// proxyParsed is one share link turned into a node.
type proxyParsed struct {
	Line     int
	Remark   string            // the link's own name (#fragment), shown next to the node name
	Node     ProxyNode         // secret fields hold generated secret names
	Secrets  map[string]string // secret name → value
	Warnings []string
}

type proxyLinkErr struct {
	Line  int    `json:"line"`
	Error string `json:"error"`
}

// proxyLinkNode is what a scheme parser returns: the node without name and secret names.
type proxyLinkNode struct {
	node   ProxyNode
	remark string
	sec    map[string]string // node key ("uuid_secret") → value
	warn   []string
}

// proxyB64 decodes standard or URL-safe base64, padded or not.
func proxyB64(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", false
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil && utf8.Valid(b) {
			return string(b), true
		}
	}
	return "", false
}

// proxyLinkText returns the share links in text: as is, or decoded from a base64 subscription.
func proxyLinkText(text string) (string, bool) {
	t := strings.TrimSpace(strings.TrimPrefix(text, "\ufeff"))
	if strings.Contains(t, "://") {
		return t, true
	}
	compact := strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, t)
	if b, ok := proxyB64(compact); ok && strings.Contains(b, "://") {
		return b, true
	}
	return t, false
}

// proxyShow quotes a short non-secret value from a link for an error message.
func proxyShow(s string) string {
	if len(s) > 32 {
		s = s[:32] + "…"
	}
	return strconv.Quote(s)
}

func proxyUnescape(s string) string {
	if u, err := url.PathUnescape(s); err == nil {
		return u
	}
	return s
}

func proxyTrue(s string) bool {
	switch strings.ToLower(s) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// proxyURL is a share link split into its parts (percent-decoded; '+' is kept, not a space).
type proxyURL struct {
	User, Pass       string
	HasUser, HasPass bool
	Host, Port       string // Port is raw ("443", or "443,20000-30000" for hysteria2)
	Path             string
	Q                map[string]string
	Remark           string
}

// q returns the first non-empty query parameter among keys.
func (u *proxyURL) q(keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(u.Q[k]); v != "" {
			return v
		}
	}
	return ""
}

// port parses the port (def when missing; def 0 = required).
func (u *proxyURL) port(def int) (int, error) {
	if u.Port == "" {
		if def == 0 {
			return 0, fmt.Errorf("missing port")
		}
		return def, nil
	}
	p, err := strconv.Atoi(u.Port)
	if err != nil || p < 1 || p > 65535 {
		return 0, fmt.Errorf("bad port %s", proxyShow(u.Port))
	}
	return p, nil
}

// proxySplitURL splits scheme://[user[:pass]@]host[:port][/path][?query][#remark]. It is more
// lenient than net/url: hysteria2 port lists, unencoded '/', '@' or '+' in passwords.
func proxySplitURL(line string) (*proxyURL, error) {
	_, rest, _ := strings.Cut(line, "://")
	u := &proxyURL{Q: map[string]string{}}
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		u.Remark = strings.TrimSpace(proxyUnescape(rest[i+1:]))
		rest = rest[:i]
	}
	if i := strings.IndexByte(rest, '?'); i >= 0 {
		for _, kv := range strings.Split(rest[i+1:], "&") {
			k, v, _ := strings.Cut(kv, "=")
			if k = proxyUnescape(k); k != "" {
				if _, dup := u.Q[k]; !dup {
					u.Q[k] = proxyUnescape(v)
				}
			}
		}
		rest = rest[:i]
	}
	if i := strings.LastIndexByte(rest, '@'); i >= 0 {
		user, pass, hasPass := strings.Cut(rest[:i], ":")
		u.User, u.Pass, u.HasUser, u.HasPass = proxyUnescape(user), proxyUnescape(pass), true, hasPass
		rest = rest[i+1:]
	}
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		u.Path, rest = rest[i:], rest[:i]
	}
	if strings.HasPrefix(rest, "[") {
		end := strings.IndexByte(rest, ']')
		if end < 0 {
			return nil, fmt.Errorf("bad IPv6 address")
		}
		u.Host = rest[1:end]
		if after := rest[end+1:]; after != "" {
			if after[0] != ':' {
				return nil, fmt.Errorf("bad server address")
			}
			u.Port = after[1:]
		}
	} else if i := strings.LastIndexByte(rest, ':'); i >= 0 {
		u.Host, u.Port = rest[:i], rest[i+1:]
	} else {
		u.Host = rest
	}
	u.Host = strings.TrimSpace(proxyUnescape(u.Host))
	if u.Host == "" {
		return nil, fmt.Errorf("missing server")
	}
	return u, nil
}

// proxyLinkName turns a link's remark into a unique node name ([A-Za-z0-9_.-], max 40). Flag emoji
// become their country code ("🇭🇰 香港 01" → "HK-01"); names without letters get the type as prefix.
func proxyLinkName(remark, typ string, taken map[string]bool) string {
	var b strings.Builder
	for _, r := range remark {
		switch {
		case r >= 0x1F1E6 && r <= 0x1F1FF: // regional indicator symbols: 🇭🇰 = H K
			b.WriteRune('A' + (r - 0x1F1E6))
		case r < 0x80 && (unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '.' || r == '-'):
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	base := b.String()
	for strings.Contains(base, "--") {
		base = strings.ReplaceAll(base, "--", "-")
	}
	base = strings.Trim(base, "-._")
	if !strings.ContainsFunc(base, unicode.IsLetter) {
		base = strings.Trim(typ+"-"+base, "-")
	}
	if len(base) > 36 {
		base = strings.TrimRight(base[:36], "-._")
	}
	name := base
	for i := 2; taken[name] || proxyReserved[name] || !reLabel.MatchString(name); i++ {
		name = base + "-" + strconv.Itoa(i)
	}
	taken[name] = true
	return name
}

// proxyParseLinks parses share links (one per line, or a base64 subscription). takenNames: node /
// group names already in use; takenSecrets: secret names already in use (both are updated).
func proxyParseLinks(text string, takenNames, takenSecrets map[string]bool) ([]proxyParsed, []proxyLinkErr) {
	out, errs := []proxyParsed{}, []proxyLinkErr{}
	body, ok := proxyLinkText(text)
	if !ok {
		msg := "no share links found: one link per line (ss://, vless://, vmess://, trojan://, hysteria2://, tuic://, anytls://, socks5://, http(s)://) or a base64 subscription"
		if strings.Contains(text, "proxies:") || strings.Contains(text, "\"outbounds\"") {
			msg += "; Clash / sing-box configuration files are not supported"
		}
		return out, append(errs, proxyLinkErr{0, msg})
	}
	if takenNames == nil {
		takenNames = map[string]bool{}
	}
	if takenSecrets == nil {
		takenSecrets = map[string]bool{}
	}
	for i, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		ln := i + 1
		if len(out) >= proxyLinkMaxNodes {
			errs = append(errs, proxyLinkErr{ln, fmt.Sprintf("too many links (max %d)", proxyLinkMaxNodes)})
			break
		}
		if len(line) > proxyLinkMaxLine {
			errs = append(errs, proxyLinkErr{ln, "link too long"})
			continue
		}
		ln0, err := proxyParseLink(line)
		if err != nil {
			errs = append(errs, proxyLinkErr{ln, err.Error()})
			continue
		}
		n := ln0.node
		// validate before naming (a bad link must not use up a name)
		probe := n
		vals := map[string]string{}
		for _, f := range proxySecretFields {
			if v, ok := ln0.sec[f.Key]; ok {
				*probe.secretField(f.Key) = "proxy_x_" + f.Suffix
				vals["proxy_x_"+f.Suffix] = v
			}
		}
		probe.Name = "x"
		if probs := proxyNodeProblems(&probe, func(k string) (string, bool) { v, ok := vals[k]; return v, ok }, true); len(probs) > 0 {
			errs = append(errs, proxyLinkErr{ln, proxyNodeType(&n) + ": " + strings.Join(probs, "; ")})
			continue
		}
		n.Name = proxyLinkName(ln0.remark, proxyNodeType(&n), takenNames)
		p := proxyParsed{Line: ln, Remark: ln0.remark, Secrets: map[string]string{}, Warnings: ln0.warn}
		for _, f := range proxySecretFields {
			if v, ok := ln0.sec[f.Key]; ok {
				name := proxySecretName(n.Name, f.Suffix, takenSecrets)
				*n.secretField(f.Key) = name
				p.Secrets[name] = v
			}
		}
		p.Node = n
		out = append(out, p)
	}
	if len(out) == 0 && len(errs) == 0 {
		errs = append(errs, proxyLinkErr{0, "no share links found"})
	}
	return out, errs
}

// proxyParseLink parses one share link.
func proxyParseLink(line string) (*proxyLinkNode, error) {
	scheme, _, ok := strings.Cut(line, "://")
	if !ok {
		return nil, fmt.Errorf("not a share link")
	}
	switch strings.ToLower(scheme) {
	case "ss":
		return proxyLinkSS(line)
	case "vless":
		return proxyLinkVLESS(line)
	case "vmess":
		return proxyLinkVMess(line)
	case "trojan":
		return proxyLinkTrojan(line)
	case "hysteria2", "hy2":
		return proxyLinkHy2(line)
	case "tuic":
		return proxyLinkTUIC(line)
	case "anytls":
		return proxyLinkAnyTLS(line)
	case "socks", "socks5", "socks5h":
		return proxyLinkSocks(line)
	case "http", "https":
		return proxyLinkHTTP(line, strings.ToLower(scheme) == "https")
	case "ssr":
		return nil, fmt.Errorf("ShadowsocksR is not supported by sing-box")
	case "hysteria":
		return nil, fmt.Errorf("Hysteria v1: use a custom JSON node (type hysteria)")
	case "wireguard", "wg":
		return nil, fmt.Errorf("WireGuard: use a custom JSON node (type wireguard)")
	}
	if len(scheme) <= 16 && strings.IndexFunc(scheme, func(r rune) bool { return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') }) < 0 {
		return nil, fmt.Errorf("unsupported link type %s://", scheme)
	}
	return nil, fmt.Errorf("not a share link")
}

// proxyHostPort parses "host:port" / "[v6]:port" (legacy ss links).
func proxyHostPort(s string) (string, int, error) {
	u, err := proxySplitURL("x://" + s)
	if err != nil {
		return "", 0, err
	}
	p, err := u.port(0)
	return u.Host, p, err
}

// ss:// — SIP002 (ss://base64url(method:password)@host:port or ss://method:password@host:port for
// 2022 methods) and legacy (ss://base64(method:password@host:port)).
func proxyLinkSS(line string) (*proxyLinkNode, error) {
	body := line[strings.Index(line, "://")+3:]
	r := &proxyLinkNode{node: ProxyNode{}, sec: map[string]string{}}
	var method, pass string
	if b, _, _ := strings.Cut(body, "#"); !strings.Contains(b, "@") {
		if i := strings.IndexByte(body, '#'); i >= 0 {
			r.remark = strings.TrimSpace(proxyUnescape(body[i+1:]))
			body = body[:i]
		}
		if q := strings.IndexByte(body, '?'); q >= 0 {
			if strings.Contains(body[q:], "plugin=") {
				return nil, fmt.Errorf("SIP003 plugins are not supported (use a custom JSON node)")
			}
			body = body[:q]
		}
		body = strings.TrimSuffix(body, "/")
		dec, ok := proxyB64(proxyUnescape(body))
		if !ok {
			return nil, fmt.Errorf("bad base64")
		}
		i := strings.LastIndexByte(dec, '@')
		if i < 0 {
			return nil, fmt.Errorf("missing server")
		}
		var ok2 bool
		if method, pass, ok2 = strings.Cut(dec[:i], ":"); !ok2 {
			return nil, fmt.Errorf("missing password")
		}
		host, port, err := proxyHostPort(dec[i+1:])
		if err != nil {
			return nil, err
		}
		r.node.Server, r.node.Port = host, port
	} else {
		u, err := proxySplitURL(line)
		if err != nil {
			return nil, err
		}
		if u.q("plugin") != "" {
			return nil, fmt.Errorf("SIP003 plugins are not supported (use a custom JSON node)")
		}
		r.remark = u.Remark
		if u.HasPass {
			method, pass = u.User, u.Pass
		} else {
			dec, ok := proxyB64(u.User)
			if !ok {
				return nil, fmt.Errorf("bad base64 in user info")
			}
			var ok2 bool
			if method, pass, ok2 = strings.Cut(dec, ":"); !ok2 {
				return nil, fmt.Errorf("missing password")
			}
		}
		r.node.Server = u.Host
		if r.node.Port, err = u.port(0); err != nil {
			return nil, err
		}
	}
	method = strings.ToLower(strings.TrimSpace(method))
	switch method { // names other clients use for the IETF variants
	case "chacha20-poly1305":
		method = "chacha20-ietf-poly1305"
	case "xchacha20-poly1305":
		method = "xchacha20-ietf-poly1305"
	}
	if _, ok := proxySSMethods[method]; !ok {
		return nil, fmt.Errorf("cipher %s not supported (use an AEAD or 2022 cipher)", proxyShow(method))
	}
	r.node.Method = method
	r.sec["password_secret"] = pass
	return r, nil
}

// proxyLinkStream reads TLS / REALITY / uTLS and the V2Ray transport from link parameters
// (vless, trojan, vmess). security: "", none, tls or reality.
func proxyLinkStream(r *proxyLinkNode, q func(keys ...string) string, security string) error {
	n := &r.node
	switch strings.ToLower(security) {
	case "", "none":
	case "tls":
		n.TLS = true
	case "reality":
		n.TLS = true
		n.RealityKey = strings.TrimRight(q("pbk", "publicKey", "public-key"), "=")
		n.RealityShortID = q("sid", "shortId", "short-id")
		if n.RealityKey == "" {
			return fmt.Errorf("reality link without public key (pbk)")
		}
	default:
		return fmt.Errorf("security %s not supported", proxyShow(security))
	}
	if n.TLS {
		n.SNI = q("sni", "peer", "serverName", "servername")
		for _, a := range strings.Split(q("alpn"), ",") {
			if a = strings.TrimSpace(a); a != "" {
				n.ALPN = append(n.ALPN, a)
			}
		}
		n.Insecure = proxyTrue(q("allowInsecure", "insecure", "allow_insecure", "skip-cert-verify"))
		if fp := strings.ToLower(q("fp", "fingerprint", "client-fingerprint")); fp != "" {
			switch {
			case proxyOneOf(fp, proxyFingerprints):
				n.Fingerprint = fp
			case strings.HasPrefix(fp, "randomized"):
				n.Fingerprint = "randomized"
				r.warn = append(r.warn, fmt.Sprintf("uTLS fingerprint %s → randomized", proxyShow(fp)))
			default:
				r.warn = append(r.warn, fmt.Sprintf("uTLS fingerprint %s not supported by sing-box, ignored", proxyShow(fp)))
			}
		}
	}
	host := q("host")
	if h, _, more := strings.Cut(host, ","); more {
		host = strings.TrimSpace(h)
		r.warn = append(r.warn, "several hosts in the link: using the first")
	}
	switch t := strings.ToLower(q("type", "network", "net")); t {
	case "", "tcp", "raw":
		if ht := strings.ToLower(q("headerType")); ht != "" && ht != "none" {
			return fmt.Errorf("TCP with %s header obfuscation is not supported by sing-box", proxyShow(ht))
		}
	case "ws", "websocket":
		n.Transport, n.Host = "ws", host
		path, rawq, _ := strings.Cut(q("path"), "?")
		for _, kv := range strings.Split(rawq, "&") {
			if k, v, _ := strings.Cut(kv, "="); k == "ed" {
				n.EarlyData, _ = strconv.Atoi(v)
			} else if kv != "" {
				r.warn = append(r.warn, "WebSocket path query dropped (sing-box escapes '?' in paths)")
			}
		}
		if ed := q("ed"); ed != "" && n.EarlyData == 0 {
			n.EarlyData, _ = strconv.Atoi(ed)
		}
		n.Path = path
	case "grpc", "gun":
		n.Transport = "grpc"
		n.ServiceName = q("serviceName", "service_name", "service-name")
		if strings.ToLower(q("mode")) == "multi" {
			r.warn = append(r.warn, "gRPC multi mode is not supported by sing-box: using gun mode")
		}
	case "http", "h2":
		n.Transport, n.Host, n.Path = "http", host, q("path")
	case "httpupgrade":
		n.Transport, n.Host, n.Path = "httpupgrade", host, q("path")
	default:
		return fmt.Errorf("transport %s is not supported by sing-box", proxyShow(t))
	}
	if n.Path != "" && !strings.HasPrefix(n.Path, "/") {
		n.Path = "/" + n.Path
	}
	return nil
}

// vless://uuid@host:port?encryption=none&security=tls|reality&type=ws&...#name
func proxyLinkVLESS(line string) (*proxyLinkNode, error) {
	u, err := proxySplitURL(line)
	if err != nil {
		return nil, err
	}
	r := &proxyLinkNode{node: ProxyNode{Type: "vless", Server: u.Host}, remark: u.Remark, sec: map[string]string{"uuid_secret": u.User}}
	if r.node.Port, err = u.port(0); err != nil {
		return nil, err
	}
	if enc := strings.ToLower(u.q("encryption")); enc != "" && enc != "none" {
		return nil, fmt.Errorf("VLESS encryption (Xray) is not supported by sing-box")
	}
	switch flow := u.q("flow"); flow {
	case "", "xtls-rprx-vision":
		r.node.Flow = flow
	case "xtls-rprx-vision-udp443":
		r.node.Flow = "xtls-rprx-vision"
		r.warn = append(r.warn, "flow xtls-rprx-vision-udp443 → xtls-rprx-vision")
	default:
		return nil, fmt.Errorf("flow %s is not supported by sing-box", proxyShow(flow))
	}
	if err := proxyLinkStream(r, u.q, u.q("security")); err != nil {
		return nil, err
	}
	proxyLinkPacketEnc(r, u.q("packetEncoding", "packet_encoding"))
	return r, nil
}

func proxyLinkPacketEnc(r *proxyLinkNode, pe string) {
	switch pe = strings.ToLower(pe); pe {
	case "":
	case "xudp", "packetaddr", "none":
		r.node.PacketEncoding = pe
	default:
		r.warn = append(r.warn, fmt.Sprintf("packet encoding %s ignored", proxyShow(pe)))
	}
}

// vmess:// — v2 (base64 of a JSON object, v2rayN) or the URI form vmess://uuid@host:port?...
func proxyLinkVMess(line string) (*proxyLinkNode, error) {
	body := line[strings.Index(line, "://")+3:]
	b64, frag, _ := strings.Cut(body, "#")
	if dec, ok := proxyB64(proxyUnescape(b64)); ok && strings.HasPrefix(strings.TrimSpace(dec), "{") {
		return proxyLinkVMessJSON(dec, strings.TrimSpace(proxyUnescape(frag)))
	}
	if !strings.Contains(b64, "@") {
		return nil, fmt.Errorf("not a vmess link (base64 JSON or uuid@host:port)")
	}
	u, err := proxySplitURL(line)
	if err != nil {
		return nil, err
	}
	r := &proxyLinkNode{node: ProxyNode{Type: "vmess", Server: u.Host}, remark: u.Remark, sec: map[string]string{"uuid_secret": u.User}}
	if r.node.Port, err = u.port(0); err != nil {
		return nil, err
	}
	if sec := strings.ToLower(u.q("encryption", "security", "scy")); sec != "" && sec != "auto" {
		r.node.Security = sec
	}
	if err := proxyLinkStream(r, u.q, u.q("security")); err != nil {
		return nil, err
	}
	return r, nil
}

func proxyLinkVMessJSON(dec, frag string) (*proxyLinkNode, error) {
	var m map[string]any
	if err := json.Unmarshal([]byte(dec), &m); err != nil {
		return nil, fmt.Errorf("vmess: bad JSON")
	}
	str := func(keys ...string) string {
		for _, k := range keys {
			switch v := m[k].(type) {
			case string:
				if s := strings.TrimSpace(v); s != "" {
					return s
				}
			case float64:
				return strconv.FormatFloat(v, 'f', -1, 64)
			case bool:
				if v {
					return "true"
				}
			}
		}
		return ""
	}
	r := &proxyLinkNode{node: ProxyNode{Type: "vmess", Server: str("add")}, remark: str("ps"), sec: map[string]string{"uuid_secret": str("id")}}
	if r.remark == "" {
		r.remark = frag
	}
	u := &proxyURL{Port: str("port")}
	var err error
	if r.node.Port, err = u.port(0); err != nil {
		return nil, err
	}
	if aid := str("aid", "alterId"); aid != "" {
		if r.node.AlterID, err = strconv.Atoi(aid); err != nil {
			return nil, fmt.Errorf("bad alterId %s", proxyShow(aid))
		}
	}
	if sec := strings.ToLower(str("scy", "security")); sec != "" && sec != "auto" {
		r.node.Security = sec
	}
	// the v2 JSON keys, mapped to the URI parameter names proxyLinkStream reads
	net := strings.ToLower(str("net"))
	q := map[string]string{"type": net, "host": str("host"), "path": str("path"), "sni": str("sni"), "alpn": str("alpn"),
		"fp": str("fp"), "allowInsecure": str("allowInsecure", "insecure", "skip-cert-verify"), "pbk": str("pbk"), "sid": str("sid")}
	switch net {
	case "", "tcp":
		q["headerType"] = str("type")
	case "grpc": // v2rayN keeps the gRPC service name in "path" and the mode in "type"
		q["serviceName"], q["mode"] = str("path", "serviceName"), str("type")
	}
	get := func(keys ...string) string {
		for _, k := range keys {
			if v := q[k]; v != "" {
				return v
			}
		}
		return ""
	}
	tls := strings.ToLower(str("tls"))
	if tls == "none" {
		tls = ""
	}
	if err := proxyLinkStream(r, get, tls); err != nil {
		return nil, err
	}
	return r, nil
}

// trojan://password@host:port?security=tls&sni=...&type=ws&...#name (TLS unless security=none)
func proxyLinkTrojan(line string) (*proxyLinkNode, error) {
	u, err := proxySplitURL(line)
	if err != nil {
		return nil, err
	}
	pw := u.User
	if u.HasPass {
		pw += ":" + u.Pass
	}
	r := &proxyLinkNode{node: ProxyNode{Type: "trojan", Server: u.Host}, remark: u.Remark, sec: map[string]string{"password_secret": pw}}
	if r.node.Port, err = u.port(443); err != nil {
		return nil, err
	}
	sec := u.q("security")
	if sec == "" {
		sec = "tls"
	}
	if err := proxyLinkStream(r, u.q, sec); err != nil {
		return nil, err
	}
	return r, nil
}

// hysteria2://auth@host[:port|:port,from-to]/?sni=&insecure=1&obfs=salamander&obfs-password=&mport=#name
func proxyLinkHy2(line string) (*proxyLinkNode, error) {
	u, err := proxySplitURL(line)
	if err != nil {
		return nil, err
	}
	pw := u.User
	if u.HasPass {
		pw += ":" + u.Pass
	}
	r := &proxyLinkNode{node: ProxyNode{Type: "hysteria2", Server: u.Host}, remark: u.Remark, sec: map[string]string{"password_secret": pw}}
	n := &r.node
	var hops []string
	ranges := false
	for _, p := range strings.Split(u.Port, ",") {
		if p = strings.TrimSpace(p); p == "" {
			continue
		}
		lo, _, isRange := strings.Cut(p, "-")
		ranges = ranges || isRange
		if n.Port == 0 {
			n.Port, _ = strconv.Atoi(lo)
		}
		hops = append(hops, p)
	}
	if u.Port == "" {
		n.Port = 443
	}
	if ranges || len(hops) > 1 {
		n.HopPorts = strings.Join(hops, ",")
	}
	if mp := strings.ReplaceAll(u.q("mport", "ports"), " ", ""); mp != "" {
		n.HopPorts = mp
	}
	n.SNI = u.q("sni", "peer")
	n.Insecure = proxyTrue(u.q("insecure", "allowInsecure", "skip-cert-verify"))
	for _, a := range strings.Split(u.q("alpn"), ",") {
		if a = strings.TrimSpace(a); a != "" {
			n.ALPN = append(n.ALPN, a)
		}
	}
	switch o := strings.ToLower(u.q("obfs")); o {
	case "", "none":
	case "salamander":
		n.Obfs = o
		r.sec["obfs_password_secret"] = u.q("obfs-password", "obfs_password", "obfsParam")
	default:
		return nil, fmt.Errorf("obfs %s not supported (salamander only)", proxyShow(o))
	}
	mbps := func(s string) int {
		s = strings.TrimSpace(strings.TrimSuffix(strings.ToLower(s), "mbps"))
		v, _ := strconv.Atoi(strings.TrimSpace(s))
		return v
	}
	n.UpMbps, n.DownMbps = mbps(u.q("upmbps", "up")), mbps(u.q("downmbps", "down"))
	if u.q("pinSHA256") != "" {
		r.warn = append(r.warn, "certificate pinning (pinSHA256) ignored")
	}
	return r, nil
}

// tuic://uuid:password@host:port?congestion_control=bbr&udp_relay_mode=native&alpn=h3&sni=#name
func proxyLinkTUIC(line string) (*proxyLinkNode, error) {
	u, err := proxySplitURL(line)
	if err != nil {
		return nil, err
	}
	if !u.HasPass {
		return nil, fmt.Errorf("TUIC link needs uuid:password")
	}
	r := &proxyLinkNode{node: ProxyNode{Type: "tuic", Server: u.Host}, remark: u.Remark, sec: map[string]string{"uuid_secret": u.User, "password_secret": u.Pass}}
	n := &r.node
	if n.Port, err = u.port(0); err != nil {
		return nil, err
	}
	n.CongestionControl = strings.ToLower(u.q("congestion_control", "congestion-control", "congestion"))
	n.UDPRelayMode = strings.ToLower(u.q("udp_relay_mode", "udp-relay-mode"))
	n.SNI = u.q("sni", "peer")
	n.Insecure = proxyTrue(u.q("allow_insecure", "insecure", "allowInsecure", "skip-cert-verify"))
	for _, a := range strings.Split(u.q("alpn"), ",") {
		if a = strings.TrimSpace(a); a != "" {
			n.ALPN = append(n.ALPN, a)
		}
	}
	if proxyTrue(u.q("disable_sni")) {
		r.warn = append(r.warn, "disable_sni ignored")
	}
	return r, nil
}

// anytls://password@host:port?sni=&insecure=1&fp=#name
func proxyLinkAnyTLS(line string) (*proxyLinkNode, error) {
	u, err := proxySplitURL(line)
	if err != nil {
		return nil, err
	}
	pw := u.User
	if u.HasPass {
		pw += ":" + u.Pass
	}
	r := &proxyLinkNode{node: ProxyNode{Type: "anytls", Server: u.Host}, remark: u.Remark, sec: map[string]string{"password_secret": pw}}
	if r.node.Port, err = u.port(443); err != nil {
		return nil, err
	}
	sec := "tls"
	if strings.ToLower(u.q("security")) == "reality" {
		sec = "reality"
	}
	if err := proxyLinkStream(r, u.q, sec); err != nil {
		return nil, err
	}
	return r, nil
}

// socks5://user:pass@host:port#name, or v2rayN's socks://base64(user:pass)@host:port#name
func proxyLinkSocks(line string) (*proxyLinkNode, error) {
	u, err := proxySplitURL(line)
	if err != nil {
		return nil, err
	}
	r := &proxyLinkNode{node: ProxyNode{Type: "socks", Server: u.Host}, remark: u.Remark, sec: map[string]string{}}
	if r.node.Port, err = u.port(1080); err != nil {
		return nil, err
	}
	user, pass := u.User, u.Pass
	if u.HasUser && !u.HasPass {
		if dec, ok := proxyB64(u.User); ok && strings.Contains(dec, ":") {
			user, pass, _ = strings.Cut(dec, ":")
		}
	}
	r.node.Username = user
	if pass != "" {
		r.sec["password_secret"] = pass
	}
	return r, nil
}

// http://user:pass@host:port#name, https:// = HTTP proxy over TLS
func proxyLinkHTTP(line string, tls bool) (*proxyLinkNode, error) {
	u, err := proxySplitURL(line)
	if err != nil {
		return nil, err
	}
	if u.Path != "" && u.Path != "/" {
		return nil, fmt.Errorf("an http(s) link with a path is a web address, not a proxy")
	}
	r := &proxyLinkNode{node: ProxyNode{Type: "http", Server: u.Host, Username: u.User, TLS: tls}, remark: u.Remark, sec: map[string]string{}}
	def := 80
	if tls {
		def = 443
		r.node.SNI = u.q("sni", "peer")
		r.node.Insecure = proxyTrue(u.q("insecure", "allowInsecure", "skip-cert-verify"))
	}
	if r.node.Port, err = u.port(def); err != nil {
		return nil, err
	}
	if u.Pass != "" {
		r.sec["password_secret"] = u.Pass
	}
	return r, nil
}
