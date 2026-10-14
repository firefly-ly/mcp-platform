// test/unit/self-issue.test.js —— 自助签发冒烟（2026-10-14，D1/D2 修订）
// 覆盖：mode=all 任何登录用户可自签；restricted+users 命中/未命中；restricted+groups 组命中；
//   未上架条目普通用户拒绝；重复自签=轮换；签发并入 users 名单（名单自增长）；未登录 401。
"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const express = require("express");
const Database = require("better-sqlite3");

const registerMcpRoutes = require("../../routes/mcp");
const { parseVisibility, canAccessSubmission, isOnShelf } = require("../../lib/visibility");

function makeApp() {
  const db = new Database(":memory:");
  db.exec(`CREATE TABLE submissions(id TEXT PRIMARY KEY, user_id TEXT, type TEXT, status TEXT, scan_status TEXT, created_at TEXT, meta TEXT);
    CREATE TABLE mcp_member_tokens(submission_id TEXT, member TEXT, token TEXT, created_at TEXT, rotated_at TEXT, PRIMARY KEY(submission_id, member));
    CREATE TABLE audit_logs(a TEXT,b TEXT,c TEXT,d TEXT,e TEXT,f TEXT,g TEXT,h TEXT,i TEXT);`);
  const now = new Date().toISOString();
  const ins = db.prepare("INSERT INTO submissions VALUES(?,?,?,?,?,?,?)");
  ins.run("sub_all", "u1", "mcp", "approved", "passed", now,
    JSON.stringify({ name: "全员", workload_name: "mcp-all", endpoint: "http://e:1", visibility: { mode: "all" }, visibility_configured: true }));
  ins.run("sub_users", "u1", "mcp", "approved", "passed", now,
    JSON.stringify({ name: "名单", workload_name: "mcp-users", visibility: { mode: "restricted", users: ["in@x.com"], groups: [] }, visibility_configured: true }));
  ins.run("sub_grp", "u1", "mcp", "approved", "passed", now,
    JSON.stringify({ name: "部门", workload_name: "mcp-grp", visibility: { mode: "restricted", users: [], groups: ["dept_1"] }, visibility_configured: true }));
  ins.run("sub_draft", "u1", "mcp", "approved", "passed", now,
    JSON.stringify({ name: "未上架", workload_name: "mcp-draft", visibility: { mode: "all" }, visibility_configured: false }));

  const ctx = {
    db,
    parseMeta: (row) => JSON.parse(row.meta),
    patchMeta: (id, patch) => {
      const row = db.prepare("SELECT meta FROM submissions WHERE id=?").get(id);
      const meta = { ...JSON.parse(row.meta || "{}"), ...patch };
      db.prepare("UPDATE submissions SET meta=? WHERE id=?").run(JSON.stringify(meta), id);
    },
    actorFromReq: (req) => ({
      email: String(req.headers["x-actor-email"] || "").toLowerCase().trim(),
      groups: String(req.headers["x-actor-groups"] || "").split(",").map((s) => s.trim()).filter(Boolean),
      admin: ["1", "true"].includes(String(req.headers["x-actor-admin"] || "").toLowerCase()),
    }),
    audit: () => {},
    deniedThrottled: () => true,
    canAccessSubmission, isOnShelf, parseVisibility,
    LIVE_MCPS: [], pickDisplayVersions: () => [],
    discoverIngressForSubmission: async () => null,
    probeMcpEndpoint: async () => false,
    discoverThvEndpoint: async () => null,
    resolveMcpProxyTarget: async () => null,
    subIdByWorkload: () => null,
    healMcpIngress: async () => {},
    mapMcpRow: (s) => s, publicEndpointFor: () => "https://gw/mcp-fake", mcpAuthHeadersFor: () => ({ "X-MCP-Token": "pkg" }),
    getOrCreateMcpToken: () => null, authHeaderCandidates: () => [null],
    mcpCallAuthed: async () => ({}), rewriteForWsl2: (x) => x, resolveEndpoint: () => null,
    workloadNameFor: (id) => "mcp-" + id, servePackageFile: () => {},
    execFileHidden: async () => "", MAX_BUFFER: 1e6,
    inspectSkillPackage: async () => ({}), MCP_TREE_MAX: 200,
  };
  const app = express();
  app.use(express.json());
  registerMcpRoutes(app, ctx);
  return new Promise((resolve) => {
    const server = app.listen(0, () => resolve({ server, port: server.address().port, db }));
  });
}

function selfIssue(port, id, email, groups = "") {
  return fetch(`http://127.0.0.1:${port}/submissions/${id}/my-member-token`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-actor-email": email, "x-actor-groups": groups },
  }).then(async (r) => ({ status: r.status, json: await r.json() }));
}

test("自助签发：mode=all 任意登录用户；重复自签=轮换；名单自增长", async (t) => {
  const { server, port, db } = await makeApp();
  try {
    const r1 = await selfIssue(port, "sub_all", "newuser@x.com");
    assert.strictEqual(r1.status, 200);
    assert.ok(r1.json.token);
    assert.strictEqual(r1.json.adopted, true, "首次自签应并入 users 名单");
    const meta1 = JSON.parse(db.prepare("SELECT meta FROM submissions WHERE id='sub_all'").get().meta);
    assert.ok(meta1.visibility.users.includes("newuser@x.com"), "签发者应进入名单");

    const r2 = await selfIssue(port, "sub_all", "newuser@x.com");
    assert.strictEqual(r2.status, 200);
    assert.notStrictEqual(r2.json.token, r1.json.token, "二次自签=轮换");
    assert.strictEqual(r2.json.adopted, false);
  } finally { server.close(); }
});

test("自助签发：restricted 名单命中/未命中；groups 组命中并自增长名单", async (t) => {
  const { server, port, db } = await makeApp();
  try {
    // 名单内 → 放行
    const r1 = await selfIssue(port, "sub_users", "in@x.com");
    assert.strictEqual(r1.status, 200);
    // 名单外且无组 → 403
    const r2 = await selfIssue(port, "sub_users", "out@x.com");
    assert.strictEqual(r2.status, 403);
    // 组命中 → 放行 + 并入名单
    const r3 = await selfIssue(port, "sub_grp", "member@x.com", "dept_1,other");
    assert.strictEqual(r3.status, 200);
    const meta = JSON.parse(db.prepare("SELECT meta FROM submissions WHERE id='sub_grp'").get().meta);
    assert.ok(meta.visibility.users.includes("member@x.com"), "组员自签应并入名单");
    // 组不命中 → 403
    const r4 = await selfIssue(port, "sub_grp", "stranger@x.com", "dept_9");
    assert.strictEqual(r4.status, 403);
  } finally { server.close(); }
});

test("自助签发：未上架条目普通用户 403（canAccessSubmission 单一入口）；未登录 401", async (t) => {
  const { server, port } = await makeApp();
  try {
    const r1 = await selfIssue(port, "sub_draft", "anyone@x.com");
    assert.strictEqual(r1.status, 403, "未上架仅管理员可见，普通用户应拒绝");
    const r2 = await fetch(`http://127.0.0.1:${port}/submissions/sub_all/my-member-token`, { method: "POST" })
      .then(async (r) => ({ status: r.status, json: await r.json() }));
    assert.strictEqual(r2.status, 401, "无 x-actor-email 应 401");
  } finally { server.close(); }
});
