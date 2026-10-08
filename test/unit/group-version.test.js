// group_key / version 提取单测（lib/group-version.js）。
// 重点回归：全角冒号「：」致版本提取失败静默兜底 1.0.0 的生产缺陷（2026-10-08）。
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { extractGroupAndVersion, normalizeRef } = require("../../lib/group-version");

function sub(ref, meta, type) {
  return { id: "sub_1", payload_ref: ref, meta: meta ? JSON.stringify(meta) : "", type: type || "mcp" };
}

test("半角冒号标准格式 ref:3.0.0 → 提取版本与分组", () => {
  const r = extractGroupAndVersion(sub("retail-mcp:3.0.0"));
  assert.equal(r.version, "3.0.0");
  assert.equal(r.group_key, "retail-mcp");
  assert.equal(r.version_source, "ref");
});

test("空格分隔 ref 1.0.0（原有格式回归）", () => {
  const r = extractGroupAndVersion(sub("dws-explorer 1.0.0"));
  assert.equal(r.version, "1.0.0");
  assert.equal(r.group_key, "dws-explorer");
  assert.equal(r.version_source, "ref");
});

test("连字符 + v 前缀 xxx-v1.0.0（原有格式回归）", () => {
  const r = extractGroupAndVersion(sub("dws-explorer-v1.0.0"));
  assert.equal(r.version, "1.0.0");
  assert.equal(r.group_key, "dws-explorer");
  assert.equal(r.version_source, "ref");
});

test("全角冒号 ref：3.0.0（生产回归 case）→ 不再兜底 1.0.0", () => {
  const r = extractGroupAndVersion(sub("新零售MCP：3.0.0"));
  assert.equal(r.version, "3.0.0");
  assert.equal(r.version_source, "ref");
  assert.equal(r.group_key, "mcp");
});

test("全角冒号 + v 前缀 ref：v3.0.0（生产形态）", () => {
  const r = extractGroupAndVersion(sub("新零售MCP：v3.0.0"));
  assert.equal(r.version, "3.0.0");
  assert.equal(r.version_source, "ref");
});

test("半角冒号 + v 前缀 ref:v2.1.0（旧正则漏掉的形态）", () => {
  const r = extractGroupAndVersion(sub("tool:v2.1.0"));
  assert.equal(r.version, "2.1.0");
  assert.equal(r.version_source, "ref");
});

test("全角横线 + V 大写前缀 xxx－V3.0.0", () => {
  const r = extractGroupAndVersion(sub("retail－mcp－V3.0.0"));
  assert.equal(r.version, "3.0.0");
  assert.equal(r.version_source, "ref");
  assert.equal(r.group_key, "retail-mcp");
});

test("meta.version 显式填写优先于 ref，source=meta", () => {
  const r = extractGroupAndVersion(sub("retail-mcp:3.0.0", { version: "2.5.0" }));
  assert.equal(r.version, "2.5.0");
  assert.equal(r.version_source, "meta");
});

test("meta.group_key 显式填写优先于 ref 推导", () => {
  const r = extractGroupAndVersion(sub("whatever:1.0.0", { group_key: "my-group" }));
  assert.equal(r.group_key, "my-group");
  assert.equal(r.version, "1.0.0");
});

test("meta 与 ref 均无版本 → 兜底 1.0.0 且 source=fallback（供留痕）", () => {
  const r = extractGroupAndVersion(sub("just-a-name"));
  assert.equal(r.version, "1.0.0");
  assert.equal(r.version_source, "fallback");
  assert.equal(r.group_key, "just-a-name");
});

test("ref 与 meta 全空 → group_key 兜底到 sub.id", () => {
  const r = extractGroupAndVersion({ id: "sub_abc123", payload_ref: "", meta: "" });
  assert.equal(r.version, "1.0.0");
  assert.equal(r.version_source, "fallback");
  assert.equal(r.group_key, "sub_abc123");
});

test("带后缀 semver 1.2.3-beta.1 完整保留", () => {
  const r = extractGroupAndVersion(sub("tool:1.2.3-beta.1"));
  assert.equal(r.version, "1.2.3-beta.1");
  assert.equal(r.version_source, "ref");
});

test("meta 非法 JSON 不抛错，照常从 ref 提取", () => {
  const r = extractGroupAndVersion({ id: "sub_1", payload_ref: "tool:2.0.0", meta: "{broken" });
  assert.equal(r.version, "2.0.0");
  assert.equal(r.version_source, "ref");
});

test("normalizeRef 直测：：→ : 、全角空格 → 空格、－ → -", () => {
  assert.equal(normalizeRef("a：b　c－d"), "a:b c-d");
  assert.equal(normalizeRef(""), "");
  assert.equal(normalizeRef(null), "");
});
