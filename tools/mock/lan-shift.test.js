// Focused regression tests for the pure LAN address shifter in rootfs/www/ui/net.js.
// The UI file has no build step; extract the helper region so this stays a real test
// of the shipped implementation without needing a browser DOM.
"use strict";
const assert = require("assert");
const fs = require("fs");
const source = fs.readFileSync("rootfs/www/ui/net.js", "utf8");
const start = source.indexOf("function lanCIDR");
const end = source.indexOf("function lanRenumberCandidates");
assert(start >= 0 && end > start, "LAN helper region missing");
const {lanCIDR, lanShiftText} = new Function(source.slice(start, end) + "\nreturn {lanCIDR, lanShiftText};")();

const old24 = lanCIDR("192.168.1.6/24");
const new24 = lanCIDR("192.168.2.1/24");
assert.equal(lanShiftText("192.168.1.5", old24, new24), "192.168.2.5");
assert.equal(lanShiftText("192.168.1.0/24", old24, new24), "192.168.2.0/24");
assert.equal(lanShiftText("192.168.0.5", old24, new24), "192.168.0.5");
assert.equal(lanShiftText("192.168.1.300", old24, new24), "192.168.1.300");
assert.equal(lanShiftText("::ffff:192.168.1.5", old24, new24), "::ffff:192.168.1.5");
assert.equal(lanShiftText("64:ff9b::192.168.1.5/128", old24, new24), "64:ff9b::192.168.1.5/128");

const old16 = lanCIDR("192.168.1.6/24");
const new16 = lanCIDR("192.168.0.1/16");
assert.equal(lanShiftText("192.168.1.200", old16, new16), "192.168.0.200");
assert.equal(lanShiftText("192.168.1.200/24", old16, new16), "192.168.0.200/24");
console.log("ok: LAN address shifter");
