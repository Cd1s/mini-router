"use strict";
// Mock verification for the UI's editDevice lease commit sequence. The browser
// draft must clear both the original and final MACs before assigning the lease.
const assert = require("assert");
function commitLeaseDraft(draft, oldMacs, newMacs, ip, leaseValue) {
  const out = {...draft};
  const all = [...oldMacs, ...newMacs].map(x => x.toLowerCase());
  for (const k of Object.keys(out)) if (all.includes(k.toLowerCase())) delete out[k];
  if (ip && leaseValue && newMacs[0]) out[newMacs[0].toLowerCase()] = leaseValue;
  return out;
}
assert.deepStrictEqual(commitLeaseDraft({}, [], ["02:00:00:00:00:9a"], "192.168.31.99", "1h"), {"02:00:00:00:00:9a":"1h"});
assert.deepStrictEqual(commitLeaseDraft({}, ["02:00:00:00:00:99"], ["02:00:00:00:00:9a"], "192.168.31.99", "1h"), {"02:00:00:00:00:9a":"1h"});
console.log("lease sequence mock: new/edit MAC paths leave no orphan lease");
