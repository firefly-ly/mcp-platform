// 网络隔离豁免清单单测（lib/network-isolation.js）——解析容错 + 命中语义
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { parseIsolateOffSet, isolateNetworkOff } = require("../../lib/network-isolation");

test("parseIsolateOffSet：空/未设置 → 空 Set（默认全隔离）", () => {
  assert.equal(parseIsolateOffSet("").size, 0);
  assert.equal(parseIsolateOffSet(undefined).size, 0);
  assert.equal(parseIsolateOffSet(null).size, 0);
});

test("parseIsolateOffSet：逗号分隔 + 去空白 + 丢空项", () => {
  const s = parseIsolateOffSet(" sub_1 , sub_2 ,,mcp-abc ");
  assert.deepEqual([...s].sort(), ["mcp-abc", "sub_1", "sub_2"]);
});

test("isolateNetworkOff：清单为空一律 false（安全默认）", () => {
  assert.equal(isolateNetworkOff(new Set(), "sub_1", { workload_name: "sub_1-wl" }), false);
});

test("isolateNetworkOff：命中提交 id", () => {
  const s = parseIsolateOffSet("sub_1,sub_2");
  assert.equal(isolateNetworkOff(s, "sub_1", {}), true);
  assert.equal(isolateNetworkOff(s, "sub_2", { workload_name: "other" }), true);
  assert.equal(isolateNetworkOff(s, "sub_3", {}), false);
});

test("isolateNetworkOff：命中 workload 名", () => {
  const s = parseIsolateOffSet("retail-mcp");
  assert.equal(isolateNetworkOff(s, "sub_x", { workload_name: "retail-mcp" }), true);
  assert.equal(isolateNetworkOff(s, "sub_x", { workload_name: "retail-mcp-old" }), false);
});

test("isolateNetworkOff：meta 缺 workload_name / 空串不误命中", () => {
  const s = parseIsolateOffSet("retail-mcp");
  assert.equal(isolateNetworkOff(s, "sub_x", {}), false);
  assert.equal(isolateNetworkOff(s, "sub_x", { workload_name: "" }), false);
  assert.equal(isolateNetworkOff(s, "sub_x", null), false);
});
