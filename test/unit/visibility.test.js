// 可见性判定单测：canAccessSubmission / isOnShelf / parseVisibility（lib/visibility.js）
// 运行：npm run test:unit
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { parseVisibility, isOnShelf, canAccessSubmission } = require("../../lib/visibility");

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
