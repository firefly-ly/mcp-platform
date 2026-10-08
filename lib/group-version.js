// lib/group-version.js —— 从 payload_ref / meta 提取 group_key 与 version（纯函数，可单测）。
// 2026-10-08 抽离自 server.js：修复全角冒号「：」等标点导致版本提取失败、静默兜底 1.0.0 的缺陷
// （生产实锤：提交 3.0.0 因 ref 含全角冒号，已发布管理与卡片均显示 1.0.0）。
"use strict";

// semver 提取：分隔符（行首/空白/:/-/_//）后跟可选 v/V 前缀再接版本号。
// 合并原两分支（[\s:\-_/] 与 [_-]v?V?），并补上「分隔符后带 v/V」这一此前漏掉的形态。
const VERSION_RE = /(?:^|[\s:\-_/][vV]?)(\d+\.\d+\.\d+(?:[-+.]\w+)*)(?:\s*|:?$)/;

// 归一化 ref 中历史数据常见的全角标点：：→ : 、全角空格 → 空格、－ → -
function normalizeRef(ref) {
  return String(ref || "")
    .replace(/\uFF1A/g, ":")
    .replace(/\u3000/g, " ")
    .replace(/\uFF0D/g, "-");
}

function parseMeta(s) {
  try { return s && s.meta ? JSON.parse(s.meta) : {}; } catch (_) { return {}; }
}

function slugifyText(s) {
  return String(s || "")
    .toLowerCase().trim()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-+|-+$/g, "");
}

// @returns {{ group_key: string, version: string, version_source: "meta"|"ref"|"fallback" }}
// version_source：meta=显式填写；ref=从 payload_ref 提取；fallback=两者皆无，兜底 1.0.0
function extractGroupAndVersion(sub) {
  const meta = parseMeta(sub);
  let group_key = (meta.group_key || "").trim();
  let version = (meta.version || "").trim();
  const ref = normalizeRef(sub.payload_ref).trim();
  let version_source = "meta";

  if (!version) {
    // 尝试从 ref 末尾取 semver：xxx:1.2.3 / xxx-v1.2.3 / xxx：v1.2.3（全角）
    const m = ref.match(VERSION_RE);
    if (m) { version = m[1]; version_source = "ref"; }
  }
  if (!group_key) {
    // 去掉版本后缀
    const base = ref
      .replace(/[\s:\-_/]?[vV]?\d+\.\d+\.\d+(?:[-+.]\w*)*(?:\s*|:?$)/, "")
      .replace(/[\s:\-_/]+$/, "");
    group_key = base || meta.name || ref || sub.id;
  }
  if (!version) {
    version = "1.0.0";
    version_source = "fallback";
  }
  return {
    group_key: slugifyText(group_key).replace(/[^a-z0-9._-]/g, "-").replace(/^-+|-+$/g, ""),
    version,
    version_source,
  };
}

module.exports = { extractGroupAndVersion, normalizeRef, VERSION_RE };
