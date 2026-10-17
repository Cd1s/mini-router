// Regression test for the WAN modem-management toggle in rootfs/www/ui/net.js.
// Extract the pure state transition and assert the DOM wiring remains tied to modem presence.
"use strict";
const assert = require("assert");
const fs = require("fs");
const source = fs.readFileSync("rootfs/www/ui/net.js", "utf8");
const start = source.indexOf("function modemToggle");
const end = source.indexOf("// ---------- 接口状态 ----------", start);
assert(start >= 0 && end > start, "modem toggle helper missing");
const {modemToggle} = new Function(source.slice(start, end) + "\nreturn {modemToggle};")();

const w = {};
assert.equal(modemToggle(w, true), true);
assert.deepEqual(w.modem, {address: ""});
assert.equal(modemToggle(w, false), false);
assert.equal("modem" in w, false);
assert.match(source, /checked:!!w\.modem/);
assert.match(source, /disabled:!w\.modem/);
assert.match(source, /modemInput\.focus\(\)/);
assert.match(source, /请填写光猫管理地址/);
console.log("ok: modem management toggle");
