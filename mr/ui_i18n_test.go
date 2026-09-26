package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// i18nDriver runs rootfs/www/ui/core.js in node with a minimal DOM (#31): first in Chinese (nothing is
// translated, no dictionary is fetched), then with the real ui/lang/en.json as the dictionary.
const i18nDriver = `
const vm = require("vm"), fs = require("fs"), path = require("path");
const ui = process.argv[2];
class N { constructor(){ this.childNodes = []; }
  append(...ks){ for (const k of ks) this.childNodes.push(k instanceof N ? k : new T(String(k))); }
  get textContent(){ return this.childNodes.map(c=>c.textContent).join(""); } }
class T extends N { constructor(t){ super(); this.data = t; } get textContent(){ return this.data; } }
class E extends N { constructor(tag){ super(); this.tagName = tag.toUpperCase(); this.attrs = {}; }
  setAttribute(k, v){ this.attrs[k] = String(v); } addEventListener(){} }
const document = { createElement: t=>new E(t), createTextNode: t=>new T(t), querySelector: ()=>null, querySelectorAll: ()=>[],
  head: new E("head"), body: new E("body") };
const sb = { document, Node: N, window: { addEventListener(){} }, console, setTimeout: ()=>0, setInterval: ()=>0, clearInterval(){},
  JSON, Promise, Object, Array, Map, Set, Date, Math, Number, String, Error, RegExp };
const ctx = vm.createContext(sb);
vm.runInContext(fs.readFileSync(path.join(ui, "core.js"), "utf8"), ctx, { filename: "core.js" });
const run = code=>vm.runInContext(code, ctx);
const probe = ()=>run(` + "`" + `({
  text: h("b",{title:"保存并应用", placeholder:"密码"}, "保存并应用").textContent,
  attrs: h("input",{title:"保存并应用", placeholder:"密码", value:"密码"}).attrs,
  toast: tr("已恢复 laptop"), dur: tr("已连接 · "+fmtDur(90061)),
  keep: tr("已恢复 客厅电视"), ascii: tr("eth0 up"),
  textarea: h("textarea",{}, "# 保存并应用").textContent,
  lang: LANG })` + "`" + `);
const out = { zh: probe() };
sb.__dict = JSON.parse(fs.readFileSync(path.join(ui, "lang", "en.json"), "utf8"));
run("DICT = __dict; LANG = 'en';");
out.en = probe();
out.bad = run("Object.keys(DICT).filter(k=>tr(k) !== DICT[k])");
process.stdout.write(JSON.stringify(out));
`

func TestUIi18n(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	ui := filepath.Join("..", "rootfs", "www", "ui")
	var en map[string]string
	b, err := os.ReadFile(filepath.Join(ui, "lang", "en.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &en); err != nil {
		t.Fatalf("en.json: %v", err)
	}
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "driver.js"), []byte(i18nDriver), 0600)
	out, err := exec.Command(node, filepath.Join(dir, "driver.js"), ui).Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			t.Fatalf("driver: %v\n%s", err, ee.Stderr)
		}
		t.Fatal(err)
	}
	type probe struct {
		Text, Toast, Dur, Keep, Ascii, Textarea, Lang string
		Attrs                                         map[string]string
	}
	var res struct {
		Zh, En probe
		Bad    []string
	}
	if err := json.Unmarshal(out, &res); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	zh := res.Zh
	if zh.Lang != "zh" || zh.Text != "保存并应用" || zh.Attrs["title"] != "保存并应用" || zh.Toast != "已恢复 laptop" || zh.Dur != "已连接 · 1天 1时 1分" {
		t.Errorf("Chinese mode must not translate: %+v", zh)
	}
	e := res.En
	for _, k := range []string{"保存并应用", "密码", "已恢复 ", "已连接 · ", "天 ", "时 ", "分"} {
		if en[k] == "" {
			t.Fatalf("en.json lacks %q", k)
		}
	}
	if e.Text != en["保存并应用"] || e.Attrs["title"] != en["保存并应用"] || e.Attrs["placeholder"] != en["密码"] {
		t.Errorf("exact match (text, title, placeholder): %+v", e)
	}
	if e.Attrs["value"] != "密码" {
		t.Errorf("an input's value is data, never translated: %q", e.Attrs["value"])
	}
	if want := en["已恢复 "] + "laptop"; e.Toast != want {
		t.Errorf("fragment + value: %q, want %q", e.Toast, want)
	}
	if want := en["已连接 · "] + "1" + en["天 "] + "1" + en["时 "] + "1" + en["分"]; e.Dur != want {
		t.Errorf("concatenated fragments: %q, want %q", e.Dur, want)
	}
	if e.Keep != "已恢复 客厅电视" || e.Ascii != "eth0 up" || e.Textarea != "# 保存并应用" {
		t.Errorf("strings with untranslated CJK, without CJK, and textarea text stay as they are: %+v", e)
	}
	if len(res.Bad) > 0 {
		t.Errorf("tr(key) != en.json[key] for %q", res.Bad)
	}
}
