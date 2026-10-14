// test/unit/adopt-member-tokens.test.js —— 收编切换脚本冒烟（2026-10-14）
// 用临时 sqlite 文件 + 假 API（内存记录调用）验证：目标筛选 / dry-run 不发请求 /
//   execute 依序调 merge-users → batch → rotate-token / 邮箱归一化 / no-rotate / 缺邮箱报错。
"use strict";
const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const Database = require("better-sqlite3");

const { pickTargets, main } = require("../../scripts/adopt-member-tokens");

function makeDbFile() {
  const dbPath = path.join(os.tmpdir(), "adopt-test-" + Date.now() + "-" + process.pid + ".db");
  const db = new Database(dbPath);
  db.exec("CREATE TABLE submissions(id TEXT PRIMARY KEY, user_id TEXT, type TEXT, status TEXT, scan_status TEXT, created_at TEXT, meta TEXT)");
  const ins = db.prepare("INSERT INTO submissions VALUES(?,?,?,?,?,?,?)");
  const now = new Date().toISOString();
  ins.run("sub_all", "u1", "mcp", "approved", "passed", now, JSON.stringify({ name: "全员A", visibility: { mode: "all" } }));
  ins.run("sub_grp", "u1", "mcp", "approved", "passed", now, JSON.stringify({ name: "部门B", visibility: { mode: "restricted", users: [], groups: ["dept_1"] } }));
  ins.run("sub_restricted", "u1", "mcp", "approved", "passed", now, JSON.stringify({ name: "已名单制", visibility: { mode: "restricted", users: ["x@x.com"], groups: [] } }));
  ins.run("sub_pending", "u1", "mcp", "pending", "", now, JSON.stringify({ name: "待审", visibility: { mode: "all" } }));
  ins.run("seed_mcp_9", "u1", "mcp", "approved", "passed", now, JSON.stringify({ name: "种子", visibility: { mode: "all" } }));
  db.close();
  return dbPath;
}

test("pickTargets：只收编 approved 且 mode=all / restricted+groups 的非 seed MCP", () => {
  const db = new Database(":memory:");
  db.exec("CREATE TABLE submissions(id TEXT PRIMARY KEY, user_id TEXT, type TEXT, status TEXT, scan_status TEXT, created_at TEXT, meta TEXT)");
  const ins = db.prepare("INSERT INTO submissions VALUES(?,?,?,?,?,?,?)");
  const now = new Date().toISOString();
  ins.run("sub_all", "u1", "mcp", "approved", "passed", now, JSON.stringify({ visibility: { mode: "all" } }));
  ins.run("sub_grp", "u1", "mcp", "approved", "passed", now, JSON.stringify({ visibility: { mode: "restricted", groups: ["dept_1"] } }));
  ins.run("sub_restricted", "u1", "mcp", "approved", "passed", now, JSON.stringify({ visibility: { mode: "restricted", users: ["x@x.com"] } }));
  ins.run("sub_pending", "u1", "mcp", "pending", "", now, JSON.stringify({ visibility: { mode: "all" } }));
  ins.run("seed_mcp_9", "u1", "mcp", "approved", "passed", now, JSON.stringify({ visibility: { mode: "all" } }));
  const ids = pickTargets(db, null).map((t) => t.id);
  db.close();
  assert.deepStrictEqual(ids, ["sub_all", "sub_grp"]);
});

test("main：dry-run 不发请求；execute 依序三步、邮箱归一化、no-rotate 生效", async () => {
  const dbPath = makeDbFile();
  const calls = [];
  const fakeFetch = async (url, init) => {
    calls.push({ url, body: JSON.parse(init.body) });
    return { status: 200, json: async () => ({ ok: true, added: 2, total: 2, issued: 2 }) };
  };

  // dry-run：零请求
  const dry = await main(["--emails", "a@x.com,b@x.com", "--db", dbPath], { Database, fetch: fakeFetch });
  assert.strictEqual(dry.executed, false);
  assert.strictEqual(calls.length, 0);

  // execute：两个条目 × 3 步（rotate 默认开）
  const out = await main(["--emails", "a@x.com,B@X.com", "--db", dbPath, "--yes"], { Database, fetch: fakeFetch });
  assert.strictEqual(out.executed, true);
  assert.strictEqual(calls.length, 6);
  assert.deepStrictEqual(calls[0].body.users, ["a@x.com", "b@x.com"], "邮箱应归一化去重");
  assert.strictEqual(calls[0].body.drop_groups, true);
  assert.ok(calls[1].url.endsWith("/submissions/sub_all/member-tokens/batch"));
  assert.ok(calls[2].url.endsWith("/submissions/sub_all/rotate-token"));
  assert.ok(calls[5].url.endsWith("/submissions/sub_grp/rotate-token"));

  // no-rotate：每条目只 2 步
  calls.length = 0;
  await main(["--emails", "a@x.com", "--db", dbPath, "--yes", "--no-rotate"], { Database, fetch: fakeFetch });
  assert.strictEqual(calls.length, 4);
  assert.ok(calls.every((c) => !c.url.endsWith("rotate-token")));

  fs.unlinkSync(dbPath);
});

test("parseArgs/main：缺邮箱报错", async () => {
  await assert.rejects(() => main(["--yes"], { Database }), /缺少成员邮箱/);
});
