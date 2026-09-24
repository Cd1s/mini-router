package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// proxyUIDriver runs rootfs/www/ui/core.js + proxy.js in node with a minimal DOM and clicks through
// the node page: import share links (the backend's real proxy.parse answer), add a node and switch
// its type, change an imported node's type, rename it, save a subscription, add a custom node.
// It prints {config, secrets, calls}: what the save flow would send to validate/apply.
const proxyUIDriver = `
const vm = require("vm"), fs = require("fs"), path = require("path");
const [ui, inFile] = process.argv.slice(2);
const input = JSON.parse(fs.readFileSync(inFile, "utf8"));
class N { constructor(){ this.childNodes = []; this.parentNode = null; }
  append(...ks){ for (let k of ks){ if (!(k instanceof N)) k = new T(String(k)); k.parentNode = this; this.childNodes.push(k); } }
  prepend(...ks){ const old = this.childNodes; this.childNodes = []; this.append(...ks); this.childNodes.push(...old); }
  replaceChildren(...ks){ this.childNodes = []; this.append(...ks); }
  remove(){ if (this.parentNode){ const c = this.parentNode.childNodes; c.splice(c.indexOf(this), 1); } }
  get textContent(){ return this.childNodes.map(c=>c.textContent).join(""); }
  set textContent(v){ this.childNodes = []; this.append(String(v)); } }
class T extends N { constructor(t){ super(); this.data = t; } get textContent(){ return this.data; } }
class E extends N { constructor(tag){ super(); this.tagName = tag.toUpperCase(); this.attrs = {}; this.on = {}; this.className = "";
    this.value = ""; this.checked = false; this.disabled = false; this.selected = false; this.classList = {toggle(){}, add(){}, remove(){}}; this.dataset = {}; }
  setAttribute(k, v){ this.attrs[k] = String(v); if (k === "value") this.value = String(v); }
  addEventListener(t, f){ (this.on[t] ||= []).push(f); }
  scrollIntoView(){} focus(){} closest(){ return null; } }
const document = { createElement: t=>new E(t), createTextNode: t=>new T(t), querySelector: ()=>null, querySelectorAll: ()=>[],
  head: new E("head"), body: new E("body"), createElementNS: (_, t)=>new E(t) };
const sb = { document, Node: N, window: { addEventListener(){} }, console, setTimeout: ()=>0, clearTimeout(){}, setInterval: ()=>0, clearInterval(){},
  confirm: ()=>true, location: { hash: "" }, JSON, Promise, Object, Array, Set, Map, Date, Math, Number, String, Error, RegExp };
const ctx = vm.createContext(sb);
for (const f of ["core.js", "proxy.js"]) vm.runInContext(fs.readFileSync(path.join(ui, f), "utf8"), ctx, { filename: f });
const calls = [];
sb.__in = input;
sb.__api = async (a, body)=>{ calls.push([a, body]);
  if (a === "proxy.status") return { enabled: true, running: false, secrets_set: {} };
  if (a === "proxy.parse") return JSON.parse(JSON.stringify(input.parse));
  throw new Error("unexpected api " + a); };
vm.runInContext("api = __api; S.cfg = __in.config; S.secretsSet = __in.secrets_set; S.secrets = {}; S.orig = JSON.stringify(S.cfg);", ctx);
const S = vm.runInContext("S", ctx);
const all = r=>{ const o = []; (function w(n){ o.push(n); for (const c of n.childNodes || []) w(c); })(r); return o; };
const fire = (el, type, value)=>{ if (value !== undefined){ el.value = value; el.checked = value === true; } for (const f of el.on[type] || []) f({ target: el, preventDefault(){} }); };
const tick = ()=>new Promise(r=>setImmediate(r));
const fail = m=>{ throw new Error(m); };
(async ()=>{
  const page = await vm.runInContext("PAGES['proxy-nodes']()", ctx);
  const btn = t=>all(page).find(e=>e.tagName === "BUTTON" && e.textContent.trim() === t) || fail("no button " + t);
  const byPh = (tag, ph)=>all(page).find(e=>e.tagName === tag && (e.attrs.placeholder || "").includes(ph)) || fail("no " + tag + " " + ph);
  // the control next to a form label ("服务器" → its input)
  const fieldIn = label=>{ const l = all(page).find(e=>e.tagName === "LABEL" && e.className === "l" && e.textContent === label) || fail("no field " + label);
    const x = l.parentNode.childNodes[l.parentNode.childNodes.indexOf(l) + 1];
    return x.tagName === "LABEL" ? x.childNodes[0] : x; };
  const selectHaving = opt=>all(page).find(e=>e.tagName === "SELECT" && all(e).some(o=>o.tagName === "OPTION" && o.textContent === opt)) || fail("no select with " + opt);
  const row = name=>all(page).find(e=>e.tagName === "TR" && e.childNodes[0] && e.childNodes[0].textContent === name) || fail("no row " + name);
  const p = S.cfg.proxy;

  // 1. import: paste, preview, add everything to group "pick"
  fire(btn("导入链接 / 订阅"), "click");
  fire(byPh("TEXTAREA", "每行一个分享链接"), "input", input.links);
  fire(btn("解析链接"), "click"); await tick(); await tick();
  fire(selectHaving("加入组 pick"), "change", "pick");
  fire(btn("添加选中的节点"), "click");
  // 2. a new node: Shadowsocks → Trojan over WebSocket
  fire(btn("+ 添加节点"), "click");
  fire(selectHaving("Trojan"), "change", "trojan");
  fire(fieldIn("服务器"), "input", "tr9.example.net");
  fire(fieldIn("密码"), "input", "ui-trojan-pw");
  fire(fieldIn("传输"), "change", "ws");
  fire(fieldIn("路径"), "input", "/ws");
  // 3. an imported VLESS REALITY node becomes VMess (keeps UUID and TLS, drops flow / reality), then is renamed
  fire(row("US-US-Reality").childNodes[5].childNodes.find(e=>e.textContent === "编辑"), "click");
  fire(selectHaving("VMess"), "change", "vmess");
  const nameIn = fieldIn("名称");
  fire(nameIn, "input", "us-vmess"); fire(nameIn, "change");
  // 4. hysteria2 import: turn obfs off (its password key goes too)
  fire(row("hy2").childNodes[5].childNodes.find(e=>e.textContent === "编辑"), "click");
  fire(fieldIn("混淆 obfs"), "change", "");
  // 5. a saved subscription (URL goes to the secrets)
  fire(btn("导入链接 / 订阅"), "click");
  fire(byPh("INPUT", "订阅链接"), "input", "https://sub.example.net/api/v1/client/subscribe?token=ui-test");
  fire(byPh("INPUT", "订阅名称"), "input", "airport");
  fire(btn("保存为订阅"), "click");
  // 6. a custom node (JSON in a secret)
  fire(btn("+ 添加节点"), "click");
  fire(selectHaving("自定义 JSON"), "change", "custom");
  fire(fieldIn("Outbound JSON"), "input", JSON.stringify({ type: "shadowtls", server: "st.example.net", server_port: 443, version: 3, password: "ui-st",
    tls: { enabled: true, server_name: "st.example.net" } }));
  // 7. every node's editor renders; a scratch node goes through every type's editor, then is deleted
  const edit = name=>fire(row(name).childNodes[5].childNodes.find(e=>e.textContent === "编辑"), "click");
  for (const n of p.nodes.slice()) { edit(n.name); fieldIn("名称"); }
  fire(btn("+ 添加节点"), "click");
  const scratch = p.nodes[p.nodes.length - 1].name;
  for (const [v, label, want] of [["vless", "VLESS", "流控 flow"], ["vmess", "VMess", "alterId"], ["trojan", "Trojan", "传输"], ["hysteria2", "Hysteria2", "端口跳跃"],
      ["tuic", "TUIC v5", "UDP 中继"], ["anytls", "AnyTLS", "REALITY 公钥"], ["socks", "SOCKS5", "用户名"], ["http", "HTTP / HTTPS", "TLS"], ["custom", "自定义 JSON", "Outbound JSON"], ["", "Shadowsocks", "加密方式"]]) {
    fire(selectHaving(label), "change", v);
    fieldIn(want);
  }
  fire(row(scratch).childNodes[5].childNodes.find(e=>e.textContent === "删除"), "click");
  if (p.nodes.some(n=>n.name === scratch)) fail("scratch node not deleted");
  process.stdout.write(JSON.stringify({ config: S.cfg, secrets: S.secrets, calls }));
})().catch(e=>{ console.error(e.stack || e); process.exit(1); });
`

func TestProxyUINodeFlows(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	c := proxyTestConfig(t)
	m, err := configToJSON(c)
	if err != nil {
		t.Fatal(err)
	}
	set := map[string]bool{}
	for _, k := range secretKeys(c) {
		_, set[k] = c.secrets[k]
	}
	links := strings.Join(testLinks(), "\n") + "\nssr://bm90IHN1cHBvcnRlZA"
	items, errs := proxyParseLinks(links, nil, nil) // what proxy.parse answers
	dir := t.TempDir()
	in, _ := json.Marshal(map[string]any{"config": m, "secrets_set": set, "links": links, "parse": proxyParseResult(items, errs)})
	os.WriteFile(filepath.Join(dir, "in.json"), in, 0600)
	os.WriteFile(filepath.Join(dir, "driver.js"), []byte(proxyUIDriver), 0600)
	out, err := exec.Command(node, filepath.Join(dir, "driver.js"), filepath.Join("..", "rootfs", "www", "ui"), filepath.Join(dir, "in.json")).Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			t.Fatalf("ui driver: %v\n%s", err, ee.Stderr)
		}
		t.Fatal(err)
	}
	var res struct {
		Config  json.RawMessage   `json:"config"`
		Secrets map[string]string `json:"secrets"`
		Calls   [][]any           `json:"calls"`
	}
	if err := json.Unmarshal(out, &res); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	// what apply would do with the UI's submission: parse, merge secrets, validate, render
	back, _, err := configFromJSON(res.Config)
	if err != nil {
		t.Fatal(err)
	}
	back.secrets = map[string]string{}
	for k, v := range c.secrets {
		back.secrets[k] = v
	}
	for k, v := range res.Secrets {
		back.secrets[k] = v
	}
	back.defaults()
	if errs := back.Validate(); len(errs) > 0 {
		t.Fatalf("config from the UI does not validate:\n%s\n%s", strings.Join(errs, "\n"), res.Config)
	}
	if _, err := Render(back); err != nil {
		t.Fatal(err)
	}
	p := &back.Proxy
	nodes := map[string]*ProxyNode{}
	for i := range p.Nodes {
		nodes[p.Nodes[i].Name] = &p.Nodes[i]
	}
	if len(p.Nodes) != 2+len(items)+2 {
		t.Errorf("%d nodes", len(p.Nodes))
	}
	// imported: secret values from the links under proxy_<node>_<field>; a taken name got a suffix
	if n := nodes["HK-01"]; n == nil || back.secrets[n.Password] != "test-pass-1" || n.Password != "proxy_hk-01_password" {
		t.Errorf("imported ss node: %+v", n)
	}
	if n := nodes["tuic"]; n == nil || back.secrets[n.UUID] != testUUID || back.secrets[n.Password] != "tuic-pass" {
		t.Errorf("imported tuic node: %+v", n)
	}
	// type switch vless → vmess kept the UUID and TLS, dropped flow and reality; the rename reached the group
	if n := nodes["us-vmess"]; n == nil || n.Type != "vmess" || back.secrets[n.UUID] != testUUID || !n.TLS || n.Flow != "" || n.RealityKey != "" || n.SNI != "www.example.com" {
		t.Errorf("vless → vmess: %+v", n)
	}
	pick := strings.Join(p.Groups[1].Nodes, " ")
	if !strings.Contains(pick, "us-vmess") || strings.Contains(pick, "US-US-Reality") || !strings.Contains(pick, "HK-01") {
		t.Errorf("group pick: %s", pick)
	}
	if n := nodes["hy2"]; n == nil || n.Obfs != "" || n.ObfsPassword != "" {
		t.Errorf("hy2 obfs off: %+v", n)
	}
	if n := nodes["node1"]; n == nil || n.Type != "trojan" || n.Server != "tr9.example.net" || !n.TLS || n.Transport != "ws" || n.Path != "/ws" ||
		n.Method != "" || back.secrets[n.Password] != "ui-trojan-pw" {
		t.Errorf("new trojan node: %+v", n)
	}
	if n := nodes["node2"]; n == nil || n.Type != "custom" || !strings.Contains(back.secrets[n.JSON], "shadowtls") {
		t.Errorf("custom node: %+v", n)
	}
	if len(p.Subscriptions) != 1 || p.Subscriptions[0].Name != "airport" || !strings.Contains(back.secrets[p.Subscriptions[0].URL], "token=ui-test") {
		t.Errorf("subscription: %+v", p.Subscriptions)
	}
	if len(res.Calls) < 2 || res.Calls[1][0] != "proxy.parse" {
		t.Errorf("api calls: %v", res.Calls)
	}
	js := renderMap(t, back)[proxyGenJSON]
	for _, s := range []string{`"type": "shadowtls"`, `"type": "vmess"`, `"tag": "us-vmess"`, `"server": "tr9.example.net"`} {
		if !strings.Contains(js, s) {
			t.Errorf("sing-box.json lacks %s", s)
		}
	}
}
