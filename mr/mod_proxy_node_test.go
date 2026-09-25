package main

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// fake credentials used by the node tests
const (
	testUUID    = "b831381d-6324-4d53-ad4f-8cda48b30811"
	testReality = "LHrjuwEq6GjVwsi-cALKBZ7shC7yUshr_0MQBbg5qQA" // lab-only X25519 public key
)

// proxyNodesTestConfig: the proxy test config plus one node of every structured type.
func proxyNodesTestConfig(t *testing.T) *Config {
	t.Helper()
	c := proxyTestConfig(t)
	for k, v := range map[string]string{
		"proxy_uuid": testUUID, "proxy_pw": "not-a-real-password", "proxy_obfs": "obfs-not-real",
		"proxy_wg": `{"type":"wireguard","address":["10.66.0.2/32"],"private_key":"YNXtAzepDqRv9H52osJVDQnznT5AL11eVLZzBr+nSkg=","peers":[{"address":"203.0.113.9","port":51820,"public_key":"Z1XXLsKYkYxuiYjJIkRvtIKFepCYHTgON+GwPq7SOV4=","allowed_ips":["0.0.0.0/0"]}]}`,
	} {
		c.secrets[k] = v
	}
	c.Proxy.Nodes = append(c.Proxy.Nodes,
		ProxyNode{Name: "vl-reality", Type: "vless", Server: "203.0.113.20", Port: 443, UUID: "proxy_uuid", Flow: "xtls-rprx-vision",
			TLS: true, SNI: "www.example.com", RealityKey: testReality, RealityShortID: "6ba85179e30d4fc2"},
		ProxyNode{Name: "vl-ws", Type: "vless", Server: "vl.example.net", Port: 443, UUID: "proxy_uuid", TLS: true, SNI: "cdn.example.net",
			ALPN: []string{"http/1.1"}, Transport: "ws", Path: "/vl", Host: "cdn.example.net", EarlyData: 2048, PacketEncoding: "none"},
		ProxyNode{Name: "vm-grpc", Type: "vmess", Server: "vm.example.net", Port: 443, UUID: "proxy_uuid", Security: "chacha20-poly1305",
			TLS: true, Fingerprint: "firefox", Transport: "grpc", ServiceName: "vmgrpc", PacketEncoding: "xudp"},
		ProxyNode{Name: "vm-plain", Type: "vmess", Server: "198.51.100.9", Port: 10086, UUID: "proxy_uuid"},
		ProxyNode{Name: "tr-hu", Type: "trojan", Server: "tr.example.net", Port: 443, Password: "proxy_pw", TLS: true,
			Transport: "httpupgrade", Path: "/tr", Host: "tr.example.net", TCPOnly: true},
		ProxyNode{Name: "tr-h2", Type: "trojan", Server: "tr.example.net", Port: 8443, Password: "proxy_pw", TLS: true, Transport: "http", Path: "/h2", Host: "h2.example.net"},
		ProxyNode{Name: "hy2", Type: "hysteria2", Server: "hy.example.net", Port: 443, Password: "proxy_pw", UpMbps: 50, DownMbps: 200,
			Obfs: "salamander", ObfsPassword: "proxy_obfs", HopPorts: "20000-30000,443", SNI: "hy.example.net", ALPN: []string{"h3"}, Insecure: true},
		ProxyNode{Name: "tuic", Type: "tuic", Server: "tu.example.net", Port: 443, UUID: "proxy_uuid", Password: "proxy_pw",
			CongestionControl: "bbr", UDPRelayMode: "quic", ALPN: []string{"h3"}},
		ProxyNode{Name: "anytls", Type: "anytls", Server: "at.example.net", Port: 443, Password: "proxy_pw", SNI: "at.example.net", Fingerprint: "chrome"},
		ProxyNode{Name: "socks", Type: "socks", Server: "203.0.113.30", Port: 1080, Username: "lab", Password: "proxy_pw", TCPOnly: true},
		ProxyNode{Name: "socks-open", Type: "socks", Server: "203.0.113.31", Port: 1080},
		ProxyNode{Name: "https", Type: "http", Server: "hp.example.net", Port: 443, Username: "lab", Password: "proxy_pw", TLS: true, SNI: "hp.example.net"},
		ProxyNode{Name: "wg", Type: "custom", JSON: "proxy_wg"},
	)
	c.Proxy.Groups = append(c.Proxy.Groups, ProxyGroup{Name: "all", Type: "selector", Nodes: []string{"vl-reality", "hy2", "wg"}})
	return c
}

func jsonEqual(t *testing.T, name string, got any, want string) {
	t.Helper()
	var w, g any
	if err := json.Unmarshal([]byte(want), &w); err != nil {
		t.Fatalf("%s: bad expectation: %v", name, err)
	}
	b, _ := json.Marshal(got)
	json.Unmarshal(b, &g)
	if !reflect.DeepEqual(g, w) {
		t.Errorf("%s:\n got %s\nwant %s", name, b, want)
	}
}

// Every structured node type renders to the expected sing-box 1.14 outbound (CI additionally runs
// `sing-box check` on the lab config, which has one node of every type).
func TestProxyNodeRender(t *testing.T) {
	c := proxyNodesTestConfig(t)
	if errs := c.Validate(); len(errs) > 0 {
		t.Fatal(errs)
	}
	var sb struct {
		Outbounds []map[string]any `json:"outbounds"`
		Endpoints []map[string]any `json:"endpoints"`
	}
	if err := json.Unmarshal([]byte(renderMap(t, c)[proxyGenJSON]), &sb); err != nil {
		t.Fatal(err)
	}
	out := map[string]map[string]any{}
	for _, o := range append(sb.Outbounds, sb.Endpoints...) {
		out[o["tag"].(string)] = o
	}
	U, P := `"`+testUUID+`"`, `"not-a-real-password"`
	for tag, want := range map[string]string{
		"sg1": `{"type":"shadowsocks","tag":"sg1","server":"sg1.example.net","server_port":8388,"method":"2022-blake3-aes-128-gcm","password":"AAECAwQFBgcICQoLDA0ODw=="}`,
		"vl-reality": `{"type":"vless","tag":"vl-reality","server":"203.0.113.20","server_port":443,"uuid":` + U + `,"flow":"xtls-rprx-vision",
			"tls":{"enabled":true,"server_name":"www.example.com","utls":{"enabled":true,"fingerprint":"chrome"},
			"reality":{"enabled":true,"public_key":"` + testReality + `","short_id":"6ba85179e30d4fc2"}}}`,
		"vl-ws": `{"type":"vless","tag":"vl-ws","server":"vl.example.net","server_port":443,"uuid":` + U + `,"packet_encoding":"",
			"tls":{"enabled":true,"server_name":"cdn.example.net","alpn":["http/1.1"]},
			"transport":{"type":"ws","path":"/vl","headers":{"Host":"cdn.example.net"},"max_early_data":2048,"early_data_header_name":"Sec-WebSocket-Protocol"}}`,
		"vm-grpc": `{"type":"vmess","tag":"vm-grpc","server":"vm.example.net","server_port":443,"uuid":` + U + `,"security":"chacha20-poly1305","alter_id":0,
			"packet_encoding":"xudp","tls":{"enabled":true,"utls":{"enabled":true,"fingerprint":"firefox"}},"transport":{"type":"grpc","service_name":"vmgrpc"}}`,
		"vm-plain": `{"type":"vmess","tag":"vm-plain","server":"198.51.100.9","server_port":10086,"uuid":` + U + `,"security":"auto","alter_id":0}`,
		"tr-hu": `{"type":"trojan","tag":"tr-hu","server":"tr.example.net","server_port":443,"password":` + P + `,"tls":{"enabled":true},
			"transport":{"type":"httpupgrade","host":"tr.example.net","path":"/tr"},"network":"tcp"}`,
		"tr-h2": `{"type":"trojan","tag":"tr-h2","server":"tr.example.net","server_port":8443,"password":` + P + `,"tls":{"enabled":true},
			"transport":{"type":"http","host":["h2.example.net"],"path":"/h2"}}`,
		"hy2": `{"type":"hysteria2","tag":"hy2","server":"hy.example.net","server_port":443,"password":` + P + `,"up_mbps":50,"down_mbps":200,
			"obfs":{"type":"salamander","password":"obfs-not-real"},"server_ports":["20000:30000","443:443"],
			"tls":{"enabled":true,"server_name":"hy.example.net","alpn":["h3"],"insecure":true}}`,
		"tuic": `{"type":"tuic","tag":"tuic","server":"tu.example.net","server_port":443,"uuid":` + U + `,"password":` + P + `,
			"congestion_control":"bbr","udp_relay_mode":"quic","tls":{"enabled":true,"alpn":["h3"]}}`,
		"anytls": `{"type":"anytls","tag":"anytls","server":"at.example.net","server_port":443,"password":` + P + `,
			"tls":{"enabled":true,"server_name":"at.example.net","utls":{"enabled":true,"fingerprint":"chrome"}}}`,
		"socks":      `{"type":"socks","tag":"socks","server":"203.0.113.30","server_port":1080,"version":"5","username":"lab","password":` + P + `,"network":"tcp"}`,
		"socks-open": `{"type":"socks","tag":"socks-open","server":"203.0.113.31","server_port":1080,"version":"5"}`,
		"https": `{"type":"http","tag":"https","server":"hp.example.net","server_port":443,"username":"lab","password":` + P + `,
			"tls":{"enabled":true,"server_name":"hp.example.net"}}`,
		// WireGuard is an endpoint in sing-box 1.14 (the outbound was removed); groups can still use it
		"wg": `{"type":"wireguard","tag":"wg","address":["10.66.0.2/32"],"private_key":"YNXtAzepDqRv9H52osJVDQnznT5AL11eVLZzBr+nSkg=",
			"peers":[{"address":"203.0.113.9","port":51820,"public_key":"Z1XXLsKYkYxuiYjJIkRvtIKFepCYHTgON+GwPq7SOV4=","allowed_ips":["0.0.0.0/0"]}]}`,
	} {
		jsonEqual(t, tag, out[tag], want)
	}
	if len(sb.Endpoints) != 1 || sb.Endpoints[0]["tag"] != "wg" {
		t.Errorf("endpoints: %v", sb.Endpoints)
	}
	for _, o := range sb.Outbounds {
		if o["type"] == "wireguard" {
			t.Error("wireguard rendered as an outbound")
		}
	}
	// every secret the nodes reference is reported to the UI as set
	st := proxyStatus(c)["secrets_set"].(map[string]bool)
	for _, k := range []string{"proxy_uuid", "proxy_pw", "proxy_obfs", "proxy_wg"} {
		if !st[k] {
			t.Errorf("secrets_set lacks %s: %v", k, st)
		}
	}
	keys := strings.Join(secretKeys(c), " ")
	for _, k := range []string{"proxy_uuid", "proxy_obfs", "proxy_wg"} {
		if !strings.Contains(keys, k) {
			t.Errorf("Module.Secrets lacks %s", k)
		}
	}
}

func TestProxyNodeValidation(t *testing.T) {
	base := map[string]ProxyNode{}
	for _, n := range proxyNodesTestConfig(t).Proxy.Nodes {
		base[n.Name] = n
	}
	for _, tc := range []struct {
		node string
		mod  func(n *ProxyNode)
		want string
	}{
		{"vl-reality", func(n *ProxyNode) { n.UUID = "" }, "uuid_secret: secret name"},
		{"vl-reality", func(n *ProxyNode) { n.UUID = "proxy_pw" }, "uuid_secret: the secret is not a UUID"},
		{"vl-reality", func(n *ProxyNode) { n.Flow = "xtls-rprx-direct" }, "flow: xtls-rprx-vision or empty"},
		{"vl-ws", func(n *ProxyNode) { n.Flow = "xtls-rprx-vision" }, "flow: xtls-rprx-vision needs tls (or reality) over plain TCP"},
		{"vl-ws", func(n *ProxyNode) { n.TLS = false }, "tls: sni / alpn / insecure / fingerprint / reality need tls: true"},
		{"vl-reality", func(n *ProxyNode) { n.RealityKey = "c2hvcnQ" }, "reality_public_key: base64url X25519"},
		{"vl-reality", func(n *ProxyNode) { n.SNI = "" }, "sni: reality needs"},
		{"vl-reality", func(n *ProxyNode) { n.RealityShortID = "abc" }, "reality_short_id: 0-16 hex"},
		{"vl-ws", func(n *ProxyNode) { n.RealityShortID = "ab" }, "reality_short_id: only with reality_public_key"},
		{"vl-ws", func(n *ProxyNode) { n.PacketEncoding = "raw" }, "packet_encoding: xudp, packetaddr or none"},
		{"vl-ws", func(n *ProxyNode) { n.ServiceName = "x" }, "service_name: only for transport grpc"},
		{"vl-ws", func(n *ProxyNode) { n.Path = "/a b\"c" }, "path: /… without spaces"},
		{"vl-ws", func(n *ProxyNode) { n.Path = "/a?ed=2048" }, "path: /… without"},
		{"vl-ws", func(n *ProxyNode) { n.Host = "evil\nhost" }, "host: hostname"},
		{"vl-ws", func(n *ProxyNode) { n.Transport = "kcp" }, "transport: one of ws, grpc, http, httpupgrade"},
		{"vl-ws", func(n *ProxyNode) { n.Transport = "" }, "transport: path / host / service_name / early_data need a transport"},
		{"vl-ws", func(n *ProxyNode) { n.ALPN = []string{"h2\"x"} }, "alpn: protocol names"},
		{"vl-ws", func(n *ProxyNode) { n.SNI = "a\"b.com" }, "sni: hostname"},
		{"vl-ws", func(n *ProxyNode) { n.Fingerprint = "netscape" }, "fingerprint: one of chrome"},
		{"vm-grpc", func(n *ProxyNode) { n.Security = "aes-128-ctr" }, "security: one of auto, none, zero, aes-128-gcm, chacha20-poly1305"},
		{"vm-grpc", func(n *ProxyNode) { n.RealityKey = testReality }, "reality_public_key: not used by VMess nodes"},
		{"vm-grpc", func(n *ProxyNode) { n.Path = "/x" }, "transport: grpc uses service_name"},
		{"vm-grpc", func(n *ProxyNode) { n.AlterID = -1 }, "alter_id: 0-65535"},
		{"tr-hu", func(n *ProxyNode) { n.Method = "aes-128-gcm" }, "method: not used by Trojan nodes"},
		{"tr-hu", func(n *ProxyNode) { n.EarlyData = 2048 }, "early_data: only for transport ws"},
		{"tr-hu", func(n *ProxyNode) { n.Password = "" }, "password_secret: secret name"},
		{"hy2", func(n *ProxyNode) { n.Fingerprint = "chrome" }, "fingerprint: not used by Hysteria2 nodes"},
		{"hy2", func(n *ProxyNode) { n.Transport = "ws" }, "transport: not used by Hysteria2 nodes"},
		{"hy2", func(n *ProxyNode) { n.Obfs = "gfw" }, "obfs: salamander or empty"},
		{"hy2", func(n *ProxyNode) { n.ObfsPassword = "" }, "obfs_password_secret: secret name"},
		{"hy2", func(n *ProxyNode) { n.Obfs = "" }, "obfs_password_secret: only with obfs: salamander"},
		{"hy2", func(n *ProxyNode) { n.HopPorts = "70000-80000" }, "hop_ports: ports or ranges"},
		{"hy2", func(n *ProxyNode) { n.HopPorts = "1-2;reboot" }, "hop_ports: ports or ranges"},
		{"hy2", func(n *ProxyNode) { n.UpMbps = -5 }, "up_mbps: 0-100000"},
		{"tuic", func(n *ProxyNode) { n.CongestionControl = "reno" }, "congestion_control: cubic, new_reno or bbr"},
		{"tuic", func(n *ProxyNode) { n.UDPRelayMode = "x" }, "udp_relay_mode: native or quic"},
		{"tuic", func(n *ProxyNode) { n.Password = "" }, "password_secret: secret name"},
		{"anytls", func(n *ProxyNode) { n.TCPOnly = true }, "tcp_only: not used by AnyTLS nodes"},
		{"hy2", func(n *ProxyNode) { n.TFO = true }, "tfo: not used by Hysteria2 nodes"},
		{"tuic", func(n *ProxyNode) { n.TFO = true }, "tfo: not used by TUIC nodes"},
		{"wg", func(n *ProxyNode) { n.TFO = true }, "tfo: not used by custom nodes"},
		{"socks", func(n *ProxyNode) { n.TLS = true }, "tls: not used by SOCKS5 nodes"},
		{"socks", func(n *ProxyNode) { n.Username = "a b" }, "username: printable ASCII"},
		{"https", func(n *ProxyNode) { n.TCPOnly = true }, "tcp_only: not used by HTTP nodes"},
		{"https", func(n *ProxyNode) { n.Password = "proxy_nope" }, `password_secret: secret "proxy_nope" missing`},
		{"https", func(n *ProxyNode) { n.Server = "-oProxyCommand=x" }, "server: IP address or hostname"},
		{"https", func(n *ProxyNode) { n.Type = "naive" }, "type: one of shadowsocks, vless, vmess, trojan, hysteria2, tuic, anytls, socks, http, custom"},
		{"wg", func(n *ProxyNode) { n.Server = "x.example" }, "server: not used by custom nodes"},
	} {
		c := proxyNodesTestConfig(t)
		for i := range c.Proxy.Nodes {
			if c.Proxy.Nodes[i].Name == tc.node {
				tc.mod(&c.Proxy.Nodes[i])
			}
		}
		errs := strings.Join(c.Validate(), "\n")
		if !strings.Contains(errs, tc.want) {
			t.Errorf("%s: want %q in:\n%s", tc.node, tc.want, errs)
		}
	}
	// secret values: bad ones are reported without echoing them
	c := proxyNodesTestConfig(t)
	c.secrets["proxy_pw"] = "line1\nline2-secret"
	c.secrets["proxy_uuid"] = "not-a-uuid-secret"
	c.secrets["proxy_wg"] = `{"type":"tailscale","auth_key":"tskey-secret"}`
	errs := strings.Join(c.Validate(), "\n")
	for _, s := range []string{"password_secret: password must be printable text", "uuid_secret: the secret is not a UUID", `json_secret: type "tailscale" not allowed`} {
		if !strings.Contains(errs, s) {
			t.Errorf("want %q in:\n%s", s, errs)
		}
	}
	c.secrets["proxy_wg"] = `{"type":"wireguard", "private_key": "tskey-secret"`
	errs += strings.Join(c.Validate(), "\n")
	if !strings.Contains(errs, "not a JSON object (syntax error at byte") {
		t.Errorf("bad JSON not reported: %s", errs)
	}
	if strings.Contains(errs, "secret") && (strings.Contains(errs, "line2-secret") || strings.Contains(errs, "not-a-uuid-secret") || strings.Contains(errs, "tskey")) {
		t.Errorf("secret value echoed:\n%s", errs)
	}
}

func TestProxySubscriptionConfig(t *testing.T) {
	c := proxyTestConfig(t)
	c.secrets["proxy_sub_a"] = "https://sub.example.net/api/v1/client/subscribe?token=abc123"
	c.secrets["proxy_sub_b"] = "javascript:alert(1)"
	c.Proxy.Subscriptions = []ProxySub{{Name: "a", URL: "proxy_sub_a"}}
	if errs := c.Validate(); len(errs) > 0 {
		t.Fatal(errs)
	}
	c.Proxy.Enabled = false
	c.Proxy.Subscriptions = append(c.Proxy.Subscriptions, ProxySub{Name: "a", URL: "proxy_sub_b"}, ProxySub{Name: "c d", URL: "Bad"}, ProxySub{Name: "e", URL: "proxy_sub_missing"})
	errs := strings.Join(c.Validate(), "\n")
	for _, s := range []string{`subscriptions[1].name: duplicate "a"`, "subscriptions[1].url_secret: the secret is not an http(s) URL",
		"subscriptions[2].name", "subscriptions[2].url_secret: secret name", `subscriptions[3].url_secret: secret "proxy_sub_missing" missing`} {
		if !strings.Contains(errs, s) {
			t.Errorf("want %q in:\n%s", s, errs)
		}
	}
	if strings.Contains(errs, "javascript") || strings.Contains(errs, "abc123") {
		t.Error("subscription URL echoed")
	}
	if !strings.Contains(strings.Join(secretKeys(c), " "), "proxy_sub_a") {
		t.Error("subscription secret not reported to the UI")
	}
	if !proxySubURLOK("http://sub.example.net:8080/link/abc?mu=0&flag=v2ray") {
		t.Error("good subscription URL rejected")
	}
	for _, u := range []string{"http:/x", "file:///etc/passwd", "https://a b", "https://x/\"", "https://", "https://-x/", "ftp://x"} {
		if proxySubURLOK(u) {
			t.Errorf("URL %q accepted", u)
		}
	}
}

func TestProxySecretName(t *testing.T) {
	taken := map[string]bool{"proxy_hk-01_password": true}
	if got := proxySecretName("HK-01", "uuid", taken); got != "proxy_hk-01_uuid" {
		t.Errorf("got %s", got)
	}
	if got := proxySecretName("HK-01", "password", taken); got != "proxy_hk-012_password" {
		t.Errorf("collision: got %s", got)
	}
	long := proxySecretName("A.Very-Long.Node_Name-That-Goes-On-And-On", "password", taken)
	if len(long) > 40 || !reProxySecret.MatchString(long) || !strings.HasPrefix(long, "proxy_a_very-long_node_name") {
		t.Errorf("long name: %s", long)
	}
	if again := proxySecretName("A.Very-Long.Node_Name-That-Goes-On-And-On", "password", taken); again == long || len(again) > 40 {
		t.Errorf("long collision: %s", again)
	}
}

// tfo: TCP Fast Open on the dial to the server (TCP protocols only; the server must enable it too).
func TestProxyNodeTFO(t *testing.T) {
	c := proxyNodesTestConfig(t)
	for i := range c.Proxy.Nodes {
		if n := &c.Proxy.Nodes[i]; n.Name == "sg1" || n.Name == "vl-reality" {
			n.TFO = true
		}
	}
	if errs := c.Validate(); len(errs) > 0 {
		t.Fatal(errs)
	}
	js := renderMap(t, c)[proxyGenJSON]
	var sb struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if err := json.Unmarshal([]byte(js), &sb); err != nil {
		t.Fatal(err)
	}
	for _, o := range sb.Outbounds {
		want := o["tag"] == "sg1" || o["tag"] == "vl-reality"
		if got, _ := o["tcp_fast_open"].(bool); got != want {
			t.Errorf("%v: tcp_fast_open %v", o["tag"], o["tcp_fast_open"])
		}
	}
}
