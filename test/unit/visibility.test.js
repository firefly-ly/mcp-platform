// 可见性判定单测：canAccessSubmission / isOnShelf / parseVisibility / memberTokenAllowed（lib/visibility.js）
// 运行：npm run test:unit
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const {
  parseVisibility, isOnShelf, canAccessSubmission, memberTokenAllowed,
} = require("../../lib/visibility");

const user = (email, groups = [], admin = false) => ({ email, groups, admin });

test("parseVisibility：无 visibility / 非 restricted 一律视为全员可见", () => {
  assert.deepEqual(parseVisibility(null), { mode: "all", users: [], groups: [] });
  assert.deepEqual(parseVisibility({}), { mode: "all", users: [], groups: [] });
  assert.deepEqual(parseVisibility({ visibility: { mode: "public" } }), {
    mode: "all", users: [], groups: [],
  });
});

test("parseVisibility：restricted 模式下 users/groups 归一化（大小写 + 去空白 + 过滤空值）", () => {
  const v = parseVisibility({
    visibility: { mode: "restricted", users: [" A@X.com ", "", "b@y.com"], groups: [" Dev Team ", null] },
  });
  assert.equal(v.mode, "restricted");
  assert.deepEqual(v.users, ["a@x.com", "b@y.com"]);
  assert.deepEqual(v.groups, ["dev team"]);
});

test("isOnShelf：无字段视为已上架（存量兼容），显式 false 为未上架", () => {
  assert.equal(isOnShelf(null), true);
  assert.equal(isOnShelf({}), true);
  assert.equal(isOnShelf({ visibility_configured: true }), true);
  assert.equal(isOnShelf({ visibility_configured: false }), false);
});

test("canAccessSubmission：admin 恒通过，且 actor 缺失（匿名/内部）也通过", () => {
  const meta = { visibility_configured: false, visibility: { mode: "restricted", users: [] } };
  assert.equal(canAccessSubmission(meta, user("a@x.com", [], true)), true);
  assert.equal(canAccessSubmission(meta, null), true);
});

test("canAccessSubmission：未上架条目对普通用户/匿名不可见", () => {
  const meta = { visibility_configured: false };
  assert.equal(canAccessSubmission(meta, user("a@x.com")), false);
  assert.equal(canAccessSubmission(meta, user("a@x.com", ["dev"])), false);
});

test("canAccessSubmission：mode=all 对已上架条目全员可见", () => {
  const meta = { visibility_configured: true };
  assert.equal(canAccessSubmission(meta, user("anyone@x.com")), true);
});

test("canAccessSubmission：restricted 按邮箱白名单命中（白名单与 actor.email 均为归一化小写——生产中 actorFromReq 已转小写）", () => {
  const meta = { visibility_configured: true, visibility: { mode: "restricted", users: ["a@x.com"] } };
  assert.equal(canAccessSubmission(meta, user("a@x.com")), true);
  assert.equal(canAccessSubmission(meta, user("b@x.com")), false);
});

test("canAccessSubmission：restricted 按组白名单命中", () => {
  const meta = { visibility_configured: true, visibility: { mode: "restricted", groups: ["dev"] } };
  assert.equal(canAccessSubmission(meta, user("a@x.com", ["qa", "dev"])), true);
  assert.equal(canAccessSubmission(meta, user("a@x.com", ["qa"])), false);
  assert.equal(canAccessSubmission(meta, user("a@x.com")), false);
});

// ---- 成员级代理 Token（双轨制 2026-10-13）----

test("memberTokenAllowed：restricted + 在 users 名单内 → 可用", () => {
  const meta = { visibility: { mode: "restricted", users: ["a@x.com"], groups: [] } };
  assert.equal(memberTokenAllowed(meta, "a@x.com"), true);
});

test("memberTokenAllowed：restricted 但不在 users 名单内 → 不可用（防移出可见范围后旧 token 存活）", () => {
  const meta = { visibility: { mode: "restricted", users: ["a@x.com"], groups: [] } };
  assert.equal(memberTokenAllowed(meta, "b@x.com"), false);
});

test("memberTokenAllowed：mode=all 一律不可用（成员 token 仅 restricted 语义）", () => {
  assert.equal(memberTokenAllowed({}, "a@x.com"), false);
  assert.equal(memberTokenAllowed({ visibility: { mode: "all" } }, "a@x.com"), false);
});

test("memberTokenAllowed：groups 命中不算（D2：groups 授权不参与成员 token，按组授权走包级）", () => {
  const meta = { visibility: { mode: "restricted", users: [], groups: ["dev"] } };
  assert.equal(memberTokenAllowed(meta, "a@x.com"), false);
});

test("memberTokenAllowed：member 大小写/空白归一化，空值拒绝", () => {
  const meta = { visibility: { mode: "restricted", users: ["a@x.com"], groups: [] } };
  assert.equal(memberTokenAllowed(meta, " A@X.COM "), true);
  assert.equal(memberTokenAllowed(meta, ""), false);
  assert.equal(memberTokenAllowed(meta, null), false);
  assert.equal(memberTokenAllowed(meta, undefined), false);
});
