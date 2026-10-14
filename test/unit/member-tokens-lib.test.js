// test/unit/member-tokens-lib.test.js —— lib/member-tokens.js 公共函数单测（自检整改 P1-①）
"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const Database = require("better-sqlite3");

const {
  normalizeEmail, normalizeEmails, readUsers, readRawVisibility,
  visibilityWithMember, issueOrRotateToken,
} = require("../../lib/member-tokens");

test("normalizeEmails：归一化/去重/排序", () => {
  assert.deepEqual(normalizeEmails([" B@X.com ", "a@x.com", "b@x.com", ""]), ["a@x.com", "b@x.com"]);
  assert.deepEqual(normalizeEmails(null), []);
});

test("readUsers：mode=all 下也能读到名单（parseVisibility 会丢弃，这里是修正点）", () => {
  const meta = { visibility: { mode: "all", users: ["A@X.com", "b@x.com"], groups: ["g"] } };
  assert.deepEqual(readUsers(meta), ["a@x.com", "b@x.com"]);
  assert.deepEqual(readUsers({}), []);
});

test("readRawVisibility：mode 归一化 + 名单/组保留", () => {
  const rv = readRawVisibility({ visibility: { mode: "restricted", users: ["a@x.com"], groups: ["Dept_1"] } });
  assert.deepEqual(rv, { mode: "restricted", users: ["a@x.com"], groups: ["dept_1"] });
  assert.equal(readRawVisibility({ visibility: {} }).mode, "all");
});

test("visibilityWithMember：并入/幂等/groups 保留", () => {
  const meta = { visibility: { mode: "all", users: ["b@x.com"], groups: ["g1"] } };
  const r1 = visibilityWithMember(meta, "A@X.com");
  assert.deepEqual(r1.visibility, { mode: "all", users: ["a@x.com", "b@x.com"], groups: ["g1"] });
  assert.equal(r1.changed, true);
  const r2 = visibilityWithMember({ visibility: { mode: "all", users: ["a@x.com"] } }, "a@x.com");
  assert.equal(r2.changed, false);
});

test("issueOrRotateToken：首签 issued，重复调用 rotated（token 变化）", () => {
  const db = new Database(":memory:");
  db.exec("CREATE TABLE mcp_member_tokens(submission_id TEXT, member TEXT, token TEXT, created_at TEXT, rotated_at TEXT, PRIMARY KEY(submission_id, member))");
  const r1 = issueOrRotateToken(db, "s1", "a@x.com", "t1");
  assert.equal(r1.action, "issued");
  const r2 = issueOrRotateToken(db, "s1", "a@x.com", "t2");
  assert.equal(r2.action, "rotated");
  assert.notEqual(r1.token, r2.token);
  const row = db.prepare("SELECT token FROM mcp_member_tokens WHERE submission_id='s1' AND member='a@x.com'").get();
  assert.equal(row.token, r2.token);
});
