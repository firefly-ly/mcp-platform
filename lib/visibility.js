// lib/visibility.js —— 可见性判定纯函数集（2026-10-08 自 server.js 抽出，逻辑零改动）。
// 抽出目的：可被 node:test 直接单测（无 IO、无状态）；server.js require 后行为不变。
"use strict";

/**
 * 条目 meta（submissions.meta JSON 解析后的核心结构）。字段随功能演进增加，此处列高频契约字段。
 * @typedef {Object} SubmissionMeta
 * @property {Visibility} [visibility] 可见范围配置
 * @property {boolean} [visibility_configured] 管理员是否显式配置过可见范围（false=未上架）
 * @property {string} [workload_name] ToolHive workload 名（mcp-subXXX）
 * @property {string} [endpoint] 部署成功回填的调用端点
 * @property {string} [deploy_status] unborn|building|loaded|deploying|deployed|undeployed|failed
 * @property {string} [deploy_error] 最近一次部署失败原因
 * @property {string} [deploy_fp] 部署配置指纹（快启路径判定用）
 * @property {string} [mcp_token] 包级代理访问令牌（管理员/应急）
 * @property {string} [name] 条目名
 * @property {string} [owner] 条目 owner
 */

/**
 * submissions 表行（parseMeta 的输入）。
 * @typedef {Object} SubmissionRow
 * @property {string} id 提交 id（sub_XXX / seed_XXX）
 * @property {string} user_id 提交者
 * @property {"mcp"|"skill"} type 类型
 * @property {string} status pending|approved|rejected|removed
 * @property {string} scan_status 安全扫描状态
 * @property {string} created_at
 * @property {string} meta JSON 字符串（parseMeta 解析为 SubmissionMeta）
 */

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

/** 成员级代理 Token 是否可用（2026-10-14 修订：任何可见性模式下均可用，凭证与模式彻底解耦）。
 *  旧规则（mode!=="restricted" 一律 false）已废除——mode=all 下名单 = 已自助签发/管理员
 *  添加的成员，其个人 token 用于调用归因；restricted 下名单即准入名单（不变）。
 *  注意必须读原始 meta.visibility.users——parseVisibility() 在 mode=all 时丢弃名单。
 *  proxy 每次请求实时调用本函数：移出名单即刻失效。
 *  @param {Object} meta @param {string} member @returns {boolean} */
function memberTokenAllowed(meta, member) {
  const m = String(member || "").toLowerCase().trim();
  if (!m) return false;
  const v = meta && meta.visibility;
  const users = Array.isArray(v && v.users) ? v.users : [];
  return users.some((u) => String(u).toLowerCase().trim() === m);
}

/** 可见范围保存解析（2026-10-14）：名单与模式解耦，防止 UI 保存覆盖掉已收编名单。
 *  背景：收编脚本 merge-users 写入的名单，曾被 UI「可见范围」弹窗保存时整体覆盖为
 *  mode=all + 空名单（旧路由对缺省 users 写 []），导致成员 token 被遮蔽、需要人工恢复。
 *  规则：
 *   - mode=all：users/groups 一律保留现值，payload 里的名单字段忽略——全员可见下名单
 *     不参与判定，但保留后切回 restricted 不丢名单；
 *   - mode=restricted：显式提供（Array.isArray）才覆盖，缺省保留现值；
 *   - mode=restricted 且解析结果 users 为空、但库里有成员 token 时：自动并入成员邮箱
 *     （adoptMembers=true，由路由写 audit），避免管理员误保存空名单后全部成员 token 失联。
 *  @param {Object|null} prev 现存 visibility（meta.visibility，可为 null）
 *  @param {Object} body 请求体 { mode, users?, groups? }
 *  @param {string[]} memberEmails 该条目已签发成员 token 的邮箱（归一化前即可）
 *  @returns {{visibility: {mode:string,users:string[],groups:string[]}, adoptMembers: boolean}} */
function resolveVisibilitySave(prev, body, memberEmails) {
  const norm = (arr) =>
    (Array.isArray(arr) ? arr : [])
      .filter((s) => s != null)
      .map((s) => String(s).toLowerCase().trim())
      .filter(Boolean);
  const prevUsers = norm(prev && prev.users);
  const prevGroups = norm(prev && prev.groups);
  const b = body || {};
  const mode = b.mode === "restricted" ? "restricted" : "all";
  if (mode === "all") {
    // 全员可见：名单无判定意义，保留现值（payload 中的名单字段忽略）
    return { visibility: { mode, users: prevUsers, groups: prevGroups }, adoptMembers: false };
  }
  const hasUsers = Array.isArray(b.users);
  const hasGroups = Array.isArray(b.groups);
  let users = hasUsers ? norm(b.users) : prevUsers;
  const groups = hasGroups ? norm(b.groups) : prevGroups;
  let adoptMembers = false;
  if (users.length === 0 && norm(memberEmails).length > 0) {
    users = norm(memberEmails);
    adoptMembers = true;
  }
  return { visibility: { mode, users, groups }, adoptMembers };
}

module.exports = { parseVisibility, isOnShelf, canAccessSubmission, memberTokenAllowed, resolveVisibilitySave };
