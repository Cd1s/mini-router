package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Share links in the shapes real clients / subscription services produce (fake credentials).
func testLinks() []string {
	b64 := base64.RawURLEncoding.EncodeToString
	std := base64.StdEncoding.EncodeToString
	vmessJSON := func(m map[string]any) string { b, _ := json.Marshal(m); return "vmess://" + std(b) }
	return []string{
		// 1 ss SIP002, base64url user info, flag emoji + Chinese name
		"ss://" + b64([]byte("aes-128-gcm:test-pass-1")) + "@198.51.100.1:8388/?plugin=#%F0%9F%87%AD%F0%9F%87%B0%20%E9%A6%99%E6%B8%AF%2001",
		// 2 ss 2022 with a plain (percent-encoded) user info and an IPv6 server
		"ss://2022-blake3-aes-128-gcm:AAECAwQFBgcICQoLDA0ODw%3D%3D@[2001:db8::1]:443#jp%202022",
		// 3 legacy ss: everything base64, other clients' name for the IETF cipher
		"ss://" + std([]byte("chacha20-poly1305:legacy-pass@legacy.example.net:8389")) + "#legacy",
		// 4 vless + reality + vision (Xray / v2rayN export)
		"vless://" + testUUID + "@203.0.113.20:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.example.com&fp=chrome&pbk=" + testReality + "&sid=6ba85179e30d4fc2&spx=%2F&type=tcp&headerType=none#%F0%9F%87%BA%F0%9F%87%B8%20US%20Reality",
		// 5 vless + ws + tls, 0-RTT in the path, an Xray-only fingerprint
		"vless://" + testUUID + "@cdn.example.net:443?encryption=none&security=tls&sni=vl.example.net&alpn=h2%2Chttp%2F1.1&fp=randomizednoalpn&type=ws&host=vl.example.net&path=%2Fvl%3Fed%3D2048#vless-ws",
		// 6 vless + grpc (multi mode is not in sing-box)
		"vless://" + testUUID + "@grpc.example.net:443?security=tls&type=grpc&serviceName=grpc-svc&mode=multi#vless%20grpc",
		// 7 vmess v2 JSON (v2rayN), strings for numbers
		vmessJSON(map[string]any{"v": "2", "ps": "🇯🇵 日本 03", "add": "vm.example.net", "port": "443", "id": testUUID, "aid": "0", "scy": "auto",
			"net": "ws", "type": "none", "host": "vm.example.net", "path": "/vm", "tls": "tls", "sni": "vm.example.net", "alpn": "", "fp": "chrome"}),
		// 8 vmess v2 JSON with numbers, grpc service name in "path"
		vmessJSON(map[string]any{"v": 2, "ps": "vm grpc", "add": "198.51.100.8", "port": 8443, "id": testUUID, "aid": 0, "scy": "zero",
			"net": "grpc", "type": "gun", "path": "vmsvc", "tls": ""}),
		// 9 trojan, percent-encoded password, ws, allowInsecure
		"trojan://p%40ss%2Fword@tr.example.net:443?security=tls&sni=tr.example.net&type=ws&host=tr.example.net&path=%2Ftr&allowInsecure=1#Trojan%20WS",
		// 10 trojan with defaults (TLS, peer = SNI)
		"trojan://plainpass@tr2.example.net:8443?peer=tr2.example.net#tr2",
		// 11 hysteria2: port list (hopping), obfs, insecure
		"hysteria2://letmein@hy.example.net:443,20000-30000/?sni=hy.example.net&insecure=1&obfs=salamander&obfs-password=obfs-pass#hy2",
		// 12 hy2:// with user:pass auth, mport and bandwidth
		"hy2://user:pass@hy2.example.net:8443?mport=20000-30000&upmbps=50&downmbps=200#hy2b",
		// 13 tuic v5
		"tuic://" + testUUID + ":tuic-pass@tu.example.net:443?congestion_control=bbr&udp_relay_mode=native&alpn=h3&sni=tu.example.net&allow_insecure=1#tuic",
		// 14 anytls
		"anytls://any-pass@at.example.net:443/?sni=at.example.net&insecure=1#anytls",
		// 15-17 socks: plain, v2rayN base64 user info, no auth (default port)
		"socks5://user:sockspw@203.0.113.30:1080#socks",
		"socks://" + std([]byte("user2:sockspw2")) + "@203.0.113.31:1081#v2rayn-socks",
		"socks5://203.0.113.32#noauth",
		// 18-19 http proxies
		"http://user:httppw@203.0.113.40:3128#squid",
		"https://hp.example.net#https-proxy",
	}
}

func TestProxyParseLinks(t *testing.T) {
	links := testLinks()
	items, errs := proxyParseLinks(strings.Join(links, "\n"), map[string]bool{"sg1": true}, nil)
	if len(errs) > 0 || len(items) != len(links) {
		t.Fatalf("%d nodes, errors %v", len(items), errs)
	}
	byLine := map[int]*proxyParsed{}
	for i := range items {
		byLine[items[i].Line] = &items[i]
	}
	sec := func(p *proxyParsed, key string) string { return p.Secrets[*p.Node.secretField(key)] }
	type want struct {
		node    string // JSON of the node without secret names
		secrets map[string]string
		warn    string
	}
	for line, w := range map[int]want{
		1: {`{"name":"HK-01","server":"198.51.100.1","port":8388,"method":"aes-128-gcm"}`, map[string]string{"password_secret": "test-pass-1"}, ""},
		2: {`{"name":"jp-2022","server":"2001:db8::1","port":443,"method":"2022-blake3-aes-128-gcm"}`, map[string]string{"password_secret": "AAECAwQFBgcICQoLDA0ODw=="}, ""},
		3: {`{"name":"legacy","server":"legacy.example.net","port":8389,"method":"chacha20-ietf-poly1305"}`, map[string]string{"password_secret": "legacy-pass"}, ""},
		4: {`{"name":"US-US-Reality","type":"vless","server":"203.0.113.20","port":443,"flow":"xtls-rprx-vision","tls":true,"sni":"www.example.com",
			"fingerprint":"chrome","reality_public_key":"` + testReality + `","reality_short_id":"6ba85179e30d4fc2"}`, map[string]string{"uuid_secret": testUUID}, ""},
		5: {`{"name":"vless-ws","type":"vless","server":"cdn.example.net","port":443,"tls":true,"sni":"vl.example.net","alpn":["h2","http/1.1"],
			"fingerprint":"randomized","transport":"ws","path":"/vl","host":"vl.example.net","early_data":2048}`, map[string]string{"uuid_secret": testUUID}, "randomized"},
		6: {`{"name":"vless-grpc","type":"vless","server":"grpc.example.net","port":443,"tls":true,"transport":"grpc","service_name":"grpc-svc"}`,
			map[string]string{"uuid_secret": testUUID}, "multi mode"},
		7: {`{"name":"JP-03","type":"vmess","server":"vm.example.net","port":443,"tls":true,"sni":"vm.example.net","fingerprint":"chrome",
			"transport":"ws","path":"/vm","host":"vm.example.net"}`, map[string]string{"uuid_secret": testUUID}, ""},
		8: {`{"name":"vm-grpc","type":"vmess","server":"198.51.100.8","port":8443,"security":"zero","transport":"grpc","service_name":"vmsvc"}`,
			map[string]string{"uuid_secret": testUUID}, ""},
		9: {`{"name":"Trojan-WS","type":"trojan","server":"tr.example.net","port":443,"tls":true,"sni":"tr.example.net","insecure":true,
			"transport":"ws","path":"/tr","host":"tr.example.net"}`, map[string]string{"password_secret": "p@ss/word"}, ""},
		10: {`{"name":"tr2","type":"trojan","server":"tr2.example.net","port":8443,"tls":true,"sni":"tr2.example.net"}`, map[string]string{"password_secret": "plainpass"}, ""},
		11: {`{"name":"hy2","type":"hysteria2","server":"hy.example.net","port":443,"obfs":"salamander","hop_ports":"443,20000-30000",
			"sni":"hy.example.net","insecure":true}`, map[string]string{"password_secret": "letmein", "obfs_password_secret": "obfs-pass"}, ""},
		12: {`{"name":"hy2b","type":"hysteria2","server":"hy2.example.net","port":8443,"up_mbps":50,"down_mbps":200,"hop_ports":"20000-30000"}`,
			map[string]string{"password_secret": "user:pass"}, ""},
		13: {`{"name":"tuic","type":"tuic","server":"tu.example.net","port":443,"congestion_control":"bbr","udp_relay_mode":"native",
			"sni":"tu.example.net","alpn":["h3"],"insecure":true}`, map[string]string{"uuid_secret": testUUID, "password_secret": "tuic-pass"}, ""},
		14: {`{"name":"anytls","type":"anytls","server":"at.example.net","port":443,"tls":true,"sni":"at.example.net","insecure":true}`,
			map[string]string{"password_secret": "any-pass"}, ""},
		15: {`{"name":"socks","type":"socks","server":"203.0.113.30","port":1080,"username":"user"}`, map[string]string{"password_secret": "sockspw"}, ""},
		16: {`{"name":"v2rayn-socks","type":"socks","server":"203.0.113.31","port":1081,"username":"user2"}`, map[string]string{"password_secret": "sockspw2"}, ""},
		17: {`{"name":"noauth","type":"socks","server":"203.0.113.32","port":1080}`, map[string]string{}, ""},
		18: {`{"name":"squid","type":"http","server":"203.0.113.40","port":3128,"username":"user"}`, map[string]string{"password_secret": "httppw"}, ""},
		19: {`{"name":"https-proxy","type":"http","server":"hp.example.net","port":443,"tls":true}`, map[string]string{}, ""},
	} {
		p := byLine[line]
		if p == nil {
			t.Errorf("line %d not parsed", line)
			continue
		}
		n := p.Node
		for _, f := range proxySecretFields {
			if name := *n.secretField(f.Key); name != "" {
				if !strings.HasPrefix(name, "proxy_") || !reProxySecret.MatchString(name) {
					t.Errorf("line %d: secret name %q", line, name)
				}
				*n.secretField(f.Key) = ""
			}
		}
		jsonEqual(t, "line "+string(rune('0'+line/10))+string(rune('0'+line%10)), proxyNodeMap(&n), w.node)
		for k, v := range w.secrets {
			if got := sec(p, k); got != v {
				t.Errorf("line %d: %s = %q, want %q", line, k, got, v)
			}
		}
		if len(p.Secrets) != len(w.secrets) {
			t.Errorf("line %d: secrets %v", line, p.Secrets)
		}
		if w.warn != "" && !strings.Contains(strings.Join(p.Warnings, " "), w.warn) {
			t.Errorf("line %d: warnings %v, want %q", line, p.Warnings, w.warn)
		}
	}

	// a base64 subscription (CRLF lines) gives the same nodes; taken names get a suffix
	sub := base64.StdEncoding.EncodeToString([]byte(strings.Join(links, "\r\n") + "\r\n"))
	items2, errs := proxyParseLinks(sub[:40]+"\n"+sub[40:], map[string]bool{"HK-01": true}, nil)
	if len(errs) > 0 || len(items2) != len(links) || items2[0].Node.Name != "HK-01-2" || items2[3].Node.Method != "" || items2[3].Node.Type != "vless" {
		t.Errorf("base64 subscription: %d nodes %v, first %q", len(items2), errs, items2[0].Node.Name)
	}

	// every parsed node, with its secrets, is a valid router.yaml node and renders
	c := proxyTestConfig(t)
	taken := map[string]bool{}
	for _, n := range c.Proxy.Nodes {
		taken[n.Name] = true
	}
	items, _ = proxyParseLinks(strings.Join(links, "\n"), taken, nil)
	for _, p := range items {
		c.Proxy.Nodes = append(c.Proxy.Nodes, p.Node)
		for k, v := range p.Secrets {
			c.secrets[k] = v
		}
	}
	if errs := c.Validate(); len(errs) > 0 {
		t.Fatalf("parsed nodes do not validate: %v", errs)
	}
	if _, err := Render(c); err != nil {
		t.Fatal(err)
	}
}

func TestProxyParseLinkErrors(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString
	vmess := func(m string) string { return "vmess://" + b64([]byte(m)) }
	secret := "sekrit-" + "value"
	for _, tc := range []struct{ link, want string }{
		{"ss://" + base64.RawURLEncoding.EncodeToString([]byte("rc4-md5:"+secret)) + "@1.2.3.4:1", `cipher "rc4-md5" not supported`},
		{"ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:"+secret)) + "@1.2.3.4:1/?plugin=obfs-local%3Bobfs%3Dhttp", "SIP003 plugins"},
		{"ss://2022-blake3-aes-256-gcm:" + secret + "@1.2.3.4:1", "2022 methods need a base64 key of 32 bytes"},
		{"ss://!!!notbase64", "bad base64"},
		{"vless://" + testUUID + "@1.2.3.4:443?encryption=mlkem768x25519plus." + secret + "&security=tls", "VLESS encryption (Xray) is not supported"},
		{"vless://" + testUUID + "@1.2.3.4:443?security=tls&type=xhttp&path=%2Fx", `transport "xhttp" is not supported`},
		{"vless://" + testUUID + "@1.2.3.4:443?security=reality&sni=a.com", "reality link without public key"},
		{"vless://" + testUUID + "@1.2.3.4:443?flow=xtls-rprx-vision", "flow: xtls-rprx-vision needs tls"},
		{"vless://" + secret + "@1.2.3.4:443", "uuid_secret: the secret is not a UUID"},
		{"vless://" + testUUID + "@1.2.3.4", "missing port"},
		{"vless://" + testUUID + "@1.2.3.4:99999", `bad port "99999"`},
		{"vless://" + testUUID + "@evil;host:443", "server: IP address or hostname"},
		{"vless://" + testUUID + "@1.2.3.4:443?security=tls&type=ws&path=%2Fa%22b", "path: /… without"},
		{vmess(`{"add":"1.2.3.4","port":"443","id":"` + testUUID + `","net":"tcp","type":"http","host":"x"}`), "header obfuscation is not supported"},
		{vmess(`{"add":"1.2.3.4","port":"443","id":"` + testUUID + `","net":"kcp"}`), `transport "kcp" is not supported`},
		{vmess(`{"add":"1.2.3.4","port":"443","id":"` + testUUID + `","scy":"aes-128-ctr"}`), "security: one of"},
		{vmess(`not json`), "not a vmess link"},
		{"trojan://" + secret + "@1.2.3.4:443?security=xtls", `security "xtls" not supported`},
		{"hysteria2://" + secret + "@1.2.3.4:443?obfs=gfw", `obfs "gfw" not supported`},
		{"hysteria2://" + secret + "@1.2.3.4:443?obfs=salamander", "obfs_password_secret: empty password"},
		{"tuic://" + testUUID + "@1.2.3.4:443", "TUIC link needs uuid:password"},
		{"https://www.example.com/some/page?" + secret, "web address, not a proxy"},
		{"ssr://" + secret, "ShadowsocksR is not supported"},
		{"hysteria://" + secret, "Hysteria v1"},
		{"wireguard://" + secret, "custom JSON node (type wireguard)"},
		{"foo://" + secret, "unsupported link type foo://"},
		{"just some text " + secret, "not a share link"},
	} {
		items, errs := proxyParseLinks("ss://"+base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:ok"))+"@1.1.1.1:1#ok\n"+tc.link, nil, nil)
		if len(items) != 1 || len(errs) != 1 || errs[0].Line != 2 || !strings.Contains(errs[0].Error, tc.want) {
			t.Errorf("%.40s…: want line 2 %q, got %d nodes %v", tc.link, tc.want, len(items), errs)
			continue
		}
		if strings.Contains(errs[0].Error, secret) {
			t.Errorf("error echoes a credential: %s", errs[0].Error)
		}
	}
	if _, errs := proxyParseLinks("proxies:\n  - {name: a, type: ss}\n", nil, nil); len(errs) != 1 || !strings.Contains(errs[0].Error, "Clash") {
		t.Errorf("clash yaml: %v", errs)
	}
	if items, errs := proxyParseLinks("  \n# only a comment\n", nil, nil); len(items) != 0 || len(errs) != 1 {
		t.Errorf("empty input: %v %v", items, errs)
	}
}

func TestProxyLinkName(t *testing.T) {
	taken := map[string]bool{}
	for in, want := range map[string]string{
		"🇭🇰 香港 01": "HK-01", "香港 01": "vless-01", "": "vless", "美国": "vless-2", "US | IPLC 0.5x": "US-IPLC-0.5x",
		"direct": "direct-2", strings.Repeat("abc", 20): strings.Repeat("abc", 12),
	} {
		if in == "美国" {
			continue // order-dependent, checked below
		}
		if got := proxyLinkName(in, "vless", taken); got != want {
			t.Errorf("proxyLinkName(%q) = %q, want %q", in, got, want)
		}
	}
	if got := proxyLinkName("美国", "vless", taken); got != "vless-2" {
		t.Errorf("second unnamed: %q", got)
	}
	if got := proxyLinkName("🇭🇰 香港 01", "vless", taken); got != "HK-01-2" {
		t.Errorf("duplicate: %q", got)
	}
}

func TestProxyParseAPI(t *testing.T) {
	if r := apiProxyParse(apiReq{method: "GET"}); r.status != 405 {
		t.Errorf("GET: %d", r.status)
	}
	body, _ := json.Marshal(map[string]any{"links": strings.Join(testLinks()[3:5], "\n") + "\nbogus", "taken": []string{"vless-ws"}})
	r := apiProxyParse(apiReq{method: "POST", body: body})
	b, _ := json.Marshal(r.body)
	var res struct {
		Nodes []struct {
			Line    int               `json:"line"`
			Remark  string            `json:"remark"`
			Node    map[string]any    `json:"node"`
			Secrets map[string]string `json:"secrets"`
			Summary string            `json:"summary"`
		} `json:"nodes"`
		Errors []proxyLinkErr `json:"errors"`
	}
	if err := json.Unmarshal(b, &res); err != nil || len(res.Nodes) != 2 || len(res.Errors) != 1 || res.Errors[0].Line != 3 {
		t.Fatalf("%s %v", b, err)
	}
	n := res.Nodes[1]
	// the UI sees router.yaml keys, the generated secret name and its value
	if n.Node["name"] != "vless-ws-2" || n.Node["transport"] != "ws" || n.Node["early_data"] != float64(2048) || n.Remark != "vless-ws" ||
		n.Secrets[n.Node["uuid_secret"].(string)] != testUUID || n.Summary != "vless · ws · tls" {
		t.Errorf("node: %+v", n)
	}
	if res.Nodes[0].Summary != "vless · reality · vision" {
		t.Errorf("summary %q", res.Nodes[0].Summary)
	}
	big, _ := json.Marshal(map[string]string{"links": strings.Repeat("x", proxySubMax+1)})
	if r := apiProxyParse(apiReq{method: "POST", body: big}); r.status != 413 {
		t.Errorf("oversized: %d", r.status)
	}
}

// proxy.fetch runs wget with argv only (URL after "--"), limits size, reads the traffic header and
// never puts the URL (token) into an error.
func TestProxyFetch(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "sub.txt")
	os.WriteFile(sub, []byte(base64.StdEncoding.EncodeToString([]byte(strings.Join(testLinks(), "\n")))), 0644)
	args := filepath.Join(dir, "args")
	wget := filepath.Join(dir, "wget")
	os.WriteFile(wget, []byte(`#!/bin/sh
printf '%s\n' "$@" > `+args+`
for a; do url=$a; done
case $url in
*big*) head -c 3000000 /dev/zero ;;
*404*) printf '  HTTP/1.1 404 Not Found\n' >&2; echo "wget: server returned error: HTTP/1.1 404 Not Found" >&2; exit 1 ;;
*down*) echo "wget: can't connect to remote host: $url: Connection refused" >&2; exit 1 ;;
*) printf '  HTTP/1.1 200 OK\n  Content-Type: text/plain\n  Subscription-Userinfo: upload=1024; download=2048; total=10737418240; expire=1893456000\n' >&2
   cat `+sub+` ;;
esac
`), 0755)
	old := proxyWget
	defer func() { proxyWget = old }()
	proxyWget = wget

	link := "https://sub.example.net/api/v1/client/subscribe?token=SECRETTOKEN&flag=v2ray"
	body, info, err := proxyFetchURL(link)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := os.ReadFile(args)
	if got := string(a); got != "-q\n-S\n-T\n20\n-U\n"+proxySubUA+"\n-O\n-\n--\n"+link+"\n" {
		t.Errorf("wget argv:\n%s", got)
	}
	if info["total"] != 10737418240 || info["expire"] != 1893456000 || info["download"] != 2048 {
		t.Errorf("info %v", info)
	}
	if items, errs := proxyParseLinks(string(body), nil, nil); len(items) != len(testLinks()) || len(errs) > 0 {
		t.Errorf("fetched subscription: %d nodes %v", len(items), errs)
	}
	for _, tc := range []struct{ url, want string }{
		{"https://sub.example.net/404/SECRETTOKEN", "HTTP 404"},
		{"https://sub.example.net/down/SECRETTOKEN?k=SECRETTOKEN", "can't connect"},
		{"https://sub.example.net/big?SECRETTOKEN", "larger than 2048 KiB"},
	} {
		_, _, err := proxyFetchURL(tc.url)
		if err == nil || !strings.Contains(err.Error(), tc.want) || strings.Contains(err.Error(), "SECRETTOKEN") {
			t.Errorf("%s: %v", tc.url, err)
		}
	}
	if r := apiProxyFetch(apiReq{method: "GET"}); r.status != 405 {
		t.Errorf("GET: %d", r.status)
	}
	c := proxyTestConfig(t)
	c.secrets["proxy_sub_a"] = link
	c.Proxy.Subscriptions = []ProxySub{{Name: "a", URL: "proxy_sub_a"}}
	if l, err := proxySubLink(c, "", "a"); err != nil || l != link {
		t.Errorf("saved subscription: %q %v", l, err)
	}
	for _, bad := range [][2]string{{"", "nope"}, {"file:///etc/shadow", ""}, {"https://x/ -O /etc/passwd", ""}} {
		if _, err := proxySubLink(c, bad[0], bad[1]); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
}
