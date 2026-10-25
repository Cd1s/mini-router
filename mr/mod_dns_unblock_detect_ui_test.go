package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// detectUIDriver runs rootfs/www/ui/core.js + dns.js in node with a minimal DOM and clicks through the
// "运营商 DNS 屏蔽绕过" card: detect, read the result, "按检测结果填入" (merge only), a result that cannot be
// judged, too many domains, the button while a detection runs, and a failed request.
const detectUIDriver = `
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
for (const f of ["core.js", "dns.js"]) vm.runInContext(fs.readFileSync(path.join(ui, f), "utf8"), ctx, { filename: f });
const calls = [];
let reply = null;            // what the next dns.unblock.detect call resolves with (a function returning a promise)
sb.__in = input;
sb.__api = (a, body)=>{ calls.push([a, body]);
  if (a === "dns.files") return Promise.resolve({ files: [] });
  if (a === "dns.unblock.detect") return reply();
  return Promise.resolve({}); };
vm.runInContext("api = __api; S.cfg = __in.config; S.secretsSet = {}; S.secrets = {}; S.orig = JSON.stringify(S.cfg); S.page = 'dns';", ctx);
const S = vm.runInContext("S", ctx);
const all = r=>{ const o = []; (function w(n){ o.push(n); for (const c of n.childNodes || []) w(c); })(r); return o; };
const fire = (el, type, value)=>{ if (value !== undefined){ el.value = value; el.checked = value === true; } for (const f of el.on[type] || []) f({ target: el, preventDefault(){}, stopPropagation(){} }); };
const tick = async ()=>{ for (let i = 0; i < 6; i++) await new Promise(r=>setImmediate(r)); };
const fail = m=>{ throw new Error(m); };
(async ()=>{
  const page = await vm.runInContext("PAGES['dns']()", ctx);
  await tick();
  const btn = t=>all(page).find(e=>e.tagName === "BUTTON" && e.textContent.trim() === t);
  const has = t=>page.textContent.includes(t);
  const byPh = ph=>all(page).find(e=>e.tagName === "INPUT" && (e.attrs.placeholder || "").includes(ph)) || fail("no input " + ph);
  const unblock = ()=>S.cfg.dns.unblock;
  const out = { junk: [] };
  // the real DOM prints null / undefined children as text: no state may contain either
  const junk = where=>{ for (const w of ["null", "undefined", "NaN", "[object"]) if (page.textContent.includes(w)) out.junk.push(where + ": " + w); };

  // 1. a conclusive result is shown with how each name is blocked; filling merges
  reply = ()=>Promise.resolve(input.ok);
  fire(btn("检测") || fail("no detect button"), "click"); await tick();
  out.shown = ["屏蔽（屏蔽页地址）", "屏蔽（假地址）", "屏蔽（不返回结果）", "错误", "page-a.test", "203.0.113.99", "平均延迟：运营商 12 ms，可信（加密）40 ms"].map(t=>[t, has(t)]);
  out.noBanner = !has("无法判断");
  junk("conclusive");
  out.callBody = calls.filter(c=>c[0] === "dns.unblock.detect").map(c=>c[1]);
  const before = JSON.stringify(unblock());
  fire(byPh("可选：打不开的网站"), "input", "a.example.org, b.example.org  c.example.org");
  fire(btn("按检测结果填入") || fail("no fill button"), "click"); await tick();
  out.filled = unblock(); out.before = JSON.parse(before);

  // 2. nothing found while the feature is on: no fill button, nothing changes
  S.cfg.dns.unblock = { enabled: true, block_ips: ["198.51.100.1"], protocol: "tls", fallback: "cloudflare", retry_private: true, retry_empty: true };
  fire(btn("检测"), "click"); reply = ()=>Promise.resolve(input.nothing); fire(btn("检测"), "click"); await tick();
  junk("nothing found");
  out.nothingFill = !!btn("按检测结果填入"); out.nothingKept = JSON.stringify(unblock());

  // 3. cannot tell: a loud banner, no recommendation, no fill button
  reply = ()=>Promise.resolve(input.bad); fire(btn("检测"), "click"); await tick();
  junk("inconclusive");
  out.badBanner = has("无法判断：可信服务器不可用（1/10 个加密查询成功）"); out.badFill = !!btn("按检测结果填入");
  out.badSuggest = has("建议：");

  // 4. more than 20 names are not even sent
  const n0 = calls.length;
  fire(byPh("可选：打不开的网站"), "input", Array.from({ length: 21 }, (_, i)=>"d" + i + ".test").join(" "));
  fire(btn("检测"), "click"); await tick();
  out.tooMany = has("最多填 20 个域名"); out.tooManySent = calls.length - n0;

  // 5. the button is disabled while a detection runs
  let release; reply = ()=>new Promise(r=>{ release = r; });
  fire(byPh("可选：打不开的网站"), "input", "");
  fire(btn("检测"), "click"); await tick();
  out.busyDisabled = all(page).find(e=>e.tagName === "BUTTON" && e.textContent.trim() === "检测").disabled;
  release(input.ok); await tick();
  out.afterDisabled = all(page).find(e=>e.tagName === "BUTTON" && e.textContent.trim() === "检测").disabled;

  // 6. a failed request is reported
  reply = ()=>Promise.reject(new Error("another DNS unblock detection is running"));
  fire(btn("检测"), "click"); await tick();
  junk("failed");
  out.failed = has("检测失败：another DNS unblock detection is running");
  process.stdout.write(JSON.stringify(out));
})().catch(e=>{ console.error(e.stack || e); process.exit(1); });
`

func TestDetectUIFlows(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	c := testConfig(t)
	c.DNS.Upstream = "isp"
	c.DNS.Unblock = &DNSUnblock{Enabled: false, BlockIPs: []string{"198.51.100.1"}, Fallback: "cloudflare", Protocol: "udp"}
	c.defaults()
	m, err := configToJSON(c)
	if err != nil {
		t.Fatal(err)
	}
	row := func(domain, kind, verdict, reason string, up, tr []string) map[string]any {
		return map[string]any{"domain": domain, "kind": kind, "verdict": verdict, "reason": reason, "upstream": up, "trusted": tr, "servers": []any{}}
	}
	ok := map[string]any{
		"status": "ok", "conclusive": true, "interception": "no", "intercepted": false, "total": 4, "probed": 4, "trusted_tried": 4, "trusted_ok": 4,
		"results": []any{
			row("page-a.test", "block_page", "屏蔽（屏蔽页地址）", "同一地址被多个注册域返回，且可信 DNS 从未返回过它", []string{"203.0.113.99"}, []string{"192.0.2.1"}),
			row("fake.test", "fake_address", "屏蔽（假地址）", "运营商返回私网/回环地址，可信 DNS 返回公网地址", []string{"10.1.2.3"}, []string{"192.0.2.2"}),
			row("nx.test", "empty", "屏蔽（不返回结果）", "运营商返回 NXDOMAIN 或没有地址，可信 DNS 有地址", []string{}, []string{"192.0.2.3"}),
			row("dead.test", "error", "错误", "", []string{}, []string{"192.0.2.4"}),
		},
		"blocked":   []any{map[string]any{"domain": "page-a.test"}, map[string]any{"domain": "fake.test"}, map[string]any{"domain": "nx.test"}},
		"block_ips": []string{"198.51.100.1", "203.0.113.99"}, "errors": []string{},
		"latency":   map[string]int{"upstream_ms": 12, "trusted_ms": 40, "plain_cf_ms": 9},
		"recommend": map[string]any{"enable": true, "block_ips": []string{"198.51.100.1", "203.0.113.99"}, "protocol": "tls"},
	}
	nothing := map[string]any{
		"status": "ok", "conclusive": true, "interception": "unknown", "total": 1, "probed": 1, "trusted_tried": 1, "trusted_ok": 1,
		"results": []any{row("fine.test", "ok", "正常或需人工确认", "", []string{"192.0.2.9"}, []string{"192.0.2.9"})},
		"blocked": []any{}, "block_ips": []string{}, "errors": []string{}, "latency": map[string]int{},
		"recommend": map[string]any{"enable": false, "block_ips": []string{}, "protocol": "tls"},
	}
	bad := map[string]any{
		"status": "inconclusive", "conclusive": false, "total": 10, "probed": 10, "trusted_tried": 10, "trusted_ok": 1,
		"results": []any{row("x.test", "unknown", "无法判断", "", []string{"192.0.2.9"}, []string{})},
		"blocked": []any{}, "block_ips": []string{}, "errors": []string{"trusted tls://1.1.1.1:853: i/o timeout (x9)"}, "latency": map[string]int{},
		"recommend": map[string]any{"enable": false, "block_ips": []string{}, "protocol": ""},
	}
	dir := t.TempDir()
	in, _ := json.Marshal(map[string]any{"config": m, "ok": ok, "nothing": nothing, "bad": bad})
	os.WriteFile(filepath.Join(dir, "in.json"), in, 0600)
	os.WriteFile(filepath.Join(dir, "driver.js"), []byte(detectUIDriver), 0600)
	out, err := exec.Command(node, filepath.Join(dir, "driver.js"), filepath.Join("..", "rootfs", "www", "ui"), filepath.Join(dir, "in.json")).Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			t.Fatalf("ui driver: %v\n%s", err, ee.Stderr)
		}
		t.Fatal(err)
	}
	var res struct {
		Junk          []string          `json:"junk"`
		Shown         [][]any           `json:"shown"`
		NoBanner      bool              `json:"noBanner"`
		CallBody      []map[string]any  `json:"callBody"`
		Before        map[string]any    `json:"before"`
		Filled        map[string]any    `json:"filled"`
		NothingFill   bool              `json:"nothingFill"`
		NothingKept   string            `json:"nothingKept"`
		BadBanner     bool              `json:"badBanner"`
		BadFill       bool              `json:"badFill"`
		BadSuggest    bool              `json:"badSuggest"`
		TooMany       bool              `json:"tooMany"`
		TooManySent   int               `json:"tooManySent"`
		BusyDisabled  bool              `json:"busyDisabled"`
		AfterDisabled bool              `json:"afterDisabled"`
		Failed        bool              `json:"failed"`
		_             map[string]string `json:"-"`
	}
	if err := json.Unmarshal(out, &res); err != nil {
		t.Fatalf("driver output: %v\n%s", err, out)
	}
	if len(res.Junk) > 0 {
		t.Errorf("the page prints placeholder text: %v", res.Junk)
	}
	for _, s := range res.Shown {
		if s[1] != true {
			t.Errorf("result does not show %q", s[0])
		}
	}
	if !res.NoBanner {
		t.Error("a conclusive result shows the 'cannot tell' banner")
	}
	if len(res.CallBody) != 1 || len(res.CallBody[0]["domains"].([]any)) != 0 {
		t.Errorf("first detect request = %v", res.CallBody)
	}
	// filling: switched on, the address it already had is kept and the new one added, plaintext upgraded to TLS
	if res.Before["enabled"] == true || res.Filled["enabled"] != true || res.Filled["protocol"] != "tls" {
		t.Errorf("fill: before=%v after=%v", res.Before, res.Filled)
	}
	if ips, _ := json.Marshal(res.Filled["block_ips"]); string(ips) != `["198.51.100.1","203.0.113.99"]` {
		t.Errorf("block_ips after fill = %s", ips)
	}
	if res.NothingFill {
		t.Error("a result with nothing to apply offers the fill button")
	}
	var kept map[string]any
	json.Unmarshal([]byte(res.NothingKept), &kept)
	if kept["enabled"] != true || kept["protocol"] != "tls" {
		t.Errorf("a detection that found nothing changed the form: %s", res.NothingKept)
	}
	if !res.BadBanner || res.BadFill || res.BadSuggest {
		t.Errorf("inconclusive: banner=%v fill button=%v suggestion=%v", res.BadBanner, res.BadFill, res.BadSuggest)
	}
	if !res.TooMany || res.TooManySent != 0 {
		t.Errorf("21 names: message=%v requests sent=%d", res.TooMany, res.TooManySent)
	}
	if !res.BusyDisabled || res.AfterDisabled {
		t.Errorf("button disabled while running=%v, after=%v", res.BusyDisabled, res.AfterDisabled)
	}
	if !res.Failed {
		t.Error("a failed request is not reported")
	}
}
