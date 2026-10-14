// lib/member-tokens.js —— 成员 token 领域公共函数（2026-10-14 自检整改抽出）。
// 背景：单签/批量/自助三条签发路径各自复制了一份"名单归一化 + 采纳 + 签发/轮换"逻辑，
// 其中一份曾因读错名单基准（parseVisibility 在 mode=all 丢弃名单）产生重复并入 bug。
// 本模块收敛全部名单/凭证操作，路由层只保留资格判定与 audit。
// 名单语义（与 routes/submissions.js merge-users 一致）：读原始 meta.visibility.users，
// 任何可见性模式下均有效；归一化规则统一为小写去空白。
"use strict";
const crypto = require("node:crypto");

/** 邮箱归一化（与可见范围名单同规则：小写去空白） */
function normalizeEmail(s) {
  return String(s || "").toLowerCase().trim();
}

/** 邮箱数组归一化 + 去重 + 排序（确定性输出，便于比对与快照） */
function normalizeEmails(arr) {
  return [...new Set((Array.isArray(arr) ? arr : []).map(normalizeEmail).filter(Boolean))].sort();
}

/** 读条目当前的可见范围名单（原始 meta.visibility.users；勿用 parseVisibility——mode=all 时丢名单） */
function readUsers(meta) {
  const v = meta && meta.visibility;
  return normalizeEmails(v && v.users);
}

/** 读条目可见范围的归一化视图（mode / users / groups），供合并与采纳做基准 */
function readRawVisibility(meta) {
  const v = (meta && meta.visibility) || {};
  return {
    mode: v.mode === "restricted" ? "restricted" : "all",
    users: normalizeEmails(v.users),
    groups: (Array.isArray(v.groups) ? v.groups : [])
      .map((g) => String(g).toLowerCase().trim())
      .filter(Boolean),
  };
}

/** 成员并入名单：返回 { visibility, changed }——模式保留、users 并集排序、groups 原样保留 */
function visibilityWithMember(meta, member) {
  const rv = readRawVisibility(meta);
  const m = normalizeEmail(member);
  const users = rv.users.includes(m) ? rv.users : [...rv.users, m].sort();
  return {
    visibility: { mode: rv.mode, users, groups: rv.groups },
    changed: users.length !== rv.users.length,
  };
}

/** 为成员签发/轮换 token（幂等判定：已有 → 轮换覆盖，无 → 新签发）。返回 { token, action } */
function issueOrRotateToken(db, submissionId, member, now) {
  const m = normalizeEmail(member);
  const existing = db
    .prepare("SELECT token FROM mcp_member_tokens WHERE submission_id=? AND member=?")
    .get(submissionId, m);
  const token = crypto.randomBytes(16).toString("hex");
  if (existing) {
    db.prepare("UPDATE mcp_member_tokens SET token=?, rotated_at=? WHERE submission_id=? AND member=?")
      .run(token, now, submissionId, m);
    return { token, action: "rotated" };
  }
  db.prepare("INSERT INTO mcp_member_tokens VALUES(?,?,?,?,?)")
    .run(submissionId, m, token, now, null);
  return { token, action: "issued" };
}

module.exports = { normalizeEmail, normalizeEmails, readUsers, readRawVisibility, visibilityWithMember, issueOrRotateToken };
