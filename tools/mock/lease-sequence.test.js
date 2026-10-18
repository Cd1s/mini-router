"use strict";
// Load the real device page and exercise its edit flow with a tiny DOM. This catches regressions
// where changing a device MAC leaves the old dhcp.host_leases entry behind.
const assert = require("assert");
const fs = require("fs");
const vm = require("vm");

class Element {
  constructor(tag) { this.tagName = tag; this.children = []; this.listeners = {}; this.parentNode = null; this.value = ""; }
  append(...xs) { for (const x of xs.flat()) { if (x == null) continue; if (typeof x === "object") x.parentNode = this; this.children.push(x); } }
  prepend(x) { x.parentNode = this; this.children.unshift(x); }
  replaceChildren(...xs) { this.children = []; this.append(...xs); }
  addEventListener(k, f) { (this.listeners[k] ||= []).push(f); }
  dispatch(k, extra = {}) { for (const f of this.listeners[k] || []) f({target: this, ...extra}); }
  setAttribute(k, v) { this[k] = v; }
  remove() { if (this.parentNode) this.parentNode.children = this.parentNode.children.filter(x => x !== this); }
  closest() { return this; }
  get textContent() { return this.children.map(x => x instanceof Element ? x.textContent : String(x.text || x)).join(""); }
  set textContent(v) { this.children = [String(v)]; }
}
class TextNode { constructor(text) { this.text = text; this.parentNode = null; } }
function walk(root, f) { if (!(root instanceof Element)) return; f(root); for (const x of root.children) walk(x, f); }
function findButton(root, label) { let got; walk(root, e => { if (e.tagName === "button" && e.textContent === label) got = e; }); assert(got, `button ${label} not found`); return got; }
function inputs(root) { const out = []; walk(root, e => { if (e.tagName === "input") out.push(e); }); return out; }

const body = new Element("body");
const ctx = {
  console, setTimeout, clearTimeout, Node: Element,
  document: {head: new Element("head"), body, createElement: tag => new Element(tag), createTextNode: x => new TextNode(x)},
  S: {cfg: {devices: [{name: "tablet", macs: ["02:00:00:00:00:99"], ip: "192.168.31.99"}], dhcp: {lease: "12h", host_leases: {"02:00:00:00:00:99": "1h"}}, groups: {}}, orig: "", secrets: {}, secretsSet: {}},
  addCSS: () => {}, touch: () => {}, tr: x => x, fmtDur: x => String(x), clone: x => JSON.parse(JSON.stringify(x)),
  registerPage: (group, id, title, order, render) => { ctx.page = render; },
  h: (tag, attrs, ...kids) => { const e = new Element(tag); for (const [k, v] of Object.entries(attrs || {})) { if (k.startsWith("on")) e.addEventListener(k.slice(2), v); else e[k] = v; } e.append(kids.flat(Infinity).map(x => x instanceof Element || x instanceof TextNode ? x : String(x))); return e; },
  inText: (obj, key, attrs) => ctx.h("input", {...attrs, value: obj[key] || "", oninput: ev => { obj[key] = ev.target.value; }}),
  inList: (obj, key, attrs) => ctx.h("input", {...attrs, value: (obj[key] || []).join(", "), oninput: ev => { obj[key] = ev.target.value.split(/[\s,]+/).filter(Boolean); }}),
  inNum: (obj, key, attrs) => ctx.h("input", {...attrs, value: obj[key] || 0}), inBool: () => ctx.h("input", {type: "checkbox"}), inSel: () => ctx.h("select"),
  field: (label, input) => [ctx.h("label", {}, label), input], form: (...rows) => ctx.h("div", {}, rows), card: (...xs) => ctx.h("div", {}, xs), roTable: (...xs) => ctx.h("table", {}, xs),
  modal: (title, content, buttons) => { const m = ctx.h("div", {}, title, content, ...(buttons || [])); body.append(m); return m; },
  toast: () => {}, confirm: () => true, pauseDlg: () => {}, api: async action => action === "dns.leases" ? {leases: []} : action === "clients" ? {stations: []} : action === "dev.paused" ? {paused: []} : {},
};
ctx.globalThis = ctx;
vm.runInNewContext(fs.readFileSync("rootfs/www/ui/dev.js", "utf8"), ctx, {filename: "rootfs/www/ui/dev.js"});

(async () => {
  const page = await ctx.page();
  findButton(page, "编辑").dispatch("click");
  const ms = body.children[0];
  const is = inputs(ms);
  // editDevice fields: name, MAC list, fixed IPv4, lease, ...
  is[1].value = "02:00:00:00:00:9a";
  is[1].dispatch("input");
  findButton(ms, "确定").dispatch("click");
  assert.deepStrictEqual(ctx.S.cfg.dhcp.host_leases, {"02:00:00:00:00:9a": "1h"});
  console.log("lease sequence real dev.js: new/edit MAC paths leave no orphan lease");
})().catch(err => { console.error(err); process.exitCode = 1; });
