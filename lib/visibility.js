// lib/visibility.js —— 可见性判定纯函数集（2026-10-08 自 server.js 抽出，逻辑零改动）。
// 抽出目的：可被 node:test 直接单测（无 IO、无状态）；server.js require 后行为不变。
"use strict";

/** visibility 缺省视为全员可见（兼容历史数据与未配置条目）。 @param {Object} meta @returns {Visibility} */
function parseVisibility(meta) {
  const v = meta && meta.visibility;
  if (!v || v.mode !== "restricted")
    return { mode: "all", users: [], groups: [] };
  // 归一化：丢弃 null/undefined（原实现 String(null)="null" 会混进白名单，抽库时顺手加固）
  const norm = (arr) =>
    (Array.isArray(arr) ? arr : [])
      .filter((s) => s != null)
      .map((s) => String(s).toLowerCase().trim())
      .filter(Boolean);
  return {
    mode: "restricted",
    users: norm(v.users),
    groups: norm(v.groups),
  };
}

/** 条目是否已「上线」：仅当管理员显式配置过可见范围后，才对非管理员开放可见/下载/调用。
 *  存量条目无 visibility_configured 字段 → 视为已上线（向后兼容，不强制重配）；
 *  新提交默认 visibility_configured=false → 未上线，仅管理员在「已发布管理」可见，待配可见范围。
 *  @param {Object} meta @returns {boolean} */
function isOnShelf(meta) {
  return !(meta && meta.visibility_configured === false);
}

/** 可见性判定单一入口：admin 恒通过 → 未上架拒绝 → mode=all 通过 → restricted 按 users/groups 命中。
 *  列表过滤、详情、下载、代理调用必须全部走这里，禁止各自内联判定。
 *  @param {Object} meta @param {Actor|null} actor @returns {boolean} */
function canAccessSubmission(meta, actor) {
  if (!actor || actor.admin) return true;
  // 未上线的条目只对管理员可见（普通用户/匿名一律不可见不可调用）
  if (!isOnShelf(meta)) return false;
  const v = parseVisibility(meta);
  if (v.mode !== "restricted") return true;
  if (actor.email && v.users.includes(actor.email)) return true;
  if (Array.isArray(actor.groups) && actor.groups.some((g) => v.groups.includes(g)))
    return true;
  return false;
}

module.exports = { parseVisibility, isOnShelf, canAccessSubmission };
