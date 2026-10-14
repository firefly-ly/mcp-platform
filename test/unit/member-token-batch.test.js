// test/unit/member-token-batch.test.js —— P1 批量签发 + 名单合并冒烟（2026-10-14）
// 覆盖：merge-users（mode=all 自动收编 restricted / drop_groups / 非管理员 403）；
//   member-tokens/batch（批量签发 / 名单外跳过不中断 / 二次调用轮换 / 单批上限）。
// 全部走真实 express 路由 + 内存 sqlite，audit 用桩收集。
"use strict";
const test = require("node:test");
const assert = require("node:assert");
const express = require("express");
const Database = require("better-sqlite3");

const registerMcpRoutes = require("../../routes/mcp");
const { parseVisibility, canAccessSubmission, isOnShelf } = require("../../lib/visibility");

const ADMIN = "admin@corp.com";

function makeApp() {
  const db = new Database(":memory:");
  db.exec(`CREATE TABLE submissions(id TEXT PRIMARY KEY, type TEXT, meta TEXT);
    CREATE TABLE mcp_member_tokens(submission_id TEXT, member TEXT, token TEXT, created_at TEXT, rotated_at TEXT, PRIMARY KEY(submission_id, member));
    CREATE TABLE audit_logs(a TEXT,b TEXT,c TEXT,d TEXT,e TEXT,f TEXT,g TEXT,h TEXT,i TEXT);`);
  db.prepare("INSERT INTO submissions VALUES(?,?,?)").run(
    "sub_all", "mcp",
    JSON.stringify({ name: "全员可见 MCP", workload_name: "mcp-all", visibility: { mode: "all" } }),
  );
  db.prepare("INSERT INTO submissions VALUES(?,?,?)").run(
    "sub_grp", "mcp",
    JSON.stringify({
      name: "部门可见 MCP", workload_name: "mcp-grp",
      visibility: { mode: "restricted", users: [], groups: ["dept_123"] },
      visibility_configured: true,
    }),
  );

  const auditCalls = [];
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
      groups: String(req.headers["x-actor-groups"] || "").split(",").filter(Boolean),
      admin: ["1", "true"].includes(String(req.headers["x-actor-admin"] || "").toLowerCase()),
    }),
    audit: (req, action, targetType, targetId, detail, result) => {
      auditCalls.push({ action, targetType, targetId, detail, result });
    },
    deniedThrottled: () => true,
    canAccessSubmission, isOnShelf, parseVisibility,
    LIVE_MCPS: [], pickDisplayVersions: () => [],
    discoverIngressForSubmission: async () => null,
    probeMcpEndpoint: async () => false,
    discoverThvEndpoint: async () => null,
    resolveMcpProxyTarget: async () => null,
    subIdByWorkload: () => null,
    healMcpIngress: async () => {},
    mapMcpRow: (s) => s, publicEndpointFor: () => "", mcpAuthHeadersFor: () => null,
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
    const server = app.listen(0, () =>
      resolve({ server, port: server.address().port, db, auditCalls }),
    );
  });
}

function api(port, method, path, body, admin) {
  const headers = { "content-type": "application/json" };
  if (admin) {
    headers["x-actor-email"] = ADMIN;
    headers["x-actor-admin"] = "1";
  } else {
    headers["x-actor-email"] = "mortal@corp.com";
  }
  return fetch(`http://127.0.0.1:${port}${path}`, {
    method, headers, body: body ? JSON.stringify(body) : undefined,
  }).then(async (r) => ({ status: r.status, json: await r.json() }));
}

test("P1：merge-users 收编 mode=all → restricted，批量签发/轮换/名单外跳过", async (t) => {
  const { server, port, db } = await makeApp();
  try {
    // ① 非管理员 → 403
    const r0 = await api(port, "POST", "/submissions/sub_all/visibility/merge-users",
      { users: ["a@corp.com"] }, false);
    assert.strictEqual(r0.status, 403);

    // ② mode=all 条目合并名单 → 自动收编 restricted + 上架
    const r1 = await api(port, "POST", "/submissions/sub_all/visibility/merge-users",
      { users: ["Alice@Corp.com ", "bob@corp.com"] }, true);
    assert.strictEqual(r1.status, 200);
    assert.strictEqual(r1.json.mode, "restricted");
    assert.strictEqual(r1.json.added, 2);
    const meta1 = JSON.parse(db.prepare("SELECT meta FROM submissions WHERE id='sub_all'").get().meta);
    assert.deepStrictEqual(meta1.visibility.users, ["alice@corp.com", "bob@corp.com"]); // 归一化+排序
    assert.strictEqual(meta1.visibility_configured, true);
    assert.ok(isOnShelf(meta1), "合并即视为已配置可见范围 → 上架");

    // ③ 对收编后的条目批量签发（含一个名单外成员 → 跳过不中断）
    const r2 = await api(port, "POST", "/submissions/sub_all/member-tokens/batch",
      { members: ["alice@corp.com", "bob@corp.com", "intruder@evil.com"] }, true);
    assert.strictEqual(r2.status, 200);
    assert.strictEqual(r2.json.issued, 2);
    const bad = r2.json.results.find((r) => r.member === "intruder@evil.com");
    assert.ok(bad && !bad.ok && bad.reason === "not_in_visibility");
    const aliceTok1 = r2.json.results.find((r) => r.member === "alice@corp.com").token;
    const cnt = db.prepare("SELECT COUNT(*) c FROM mcp_member_tokens WHERE submission_id='sub_all'").get().c;
    assert.strictEqual(cnt, 2);

    // ④ 二次批量 → 轮换（token 变化，行数不增）
    const r3 = await api(port, "POST", "/submissions/sub_all/member-tokens/batch",
      { members: ["alice@corp.com"] }, true);
    const aliceTok2 = r3.json.results[0].token;
    assert.strictEqual(r3.json.results[0].action, "rotated");
    assert.notStrictEqual(aliceTok2, aliceTok1);
    const cnt2 = db.prepare("SELECT COUNT(*) c FROM mcp_member_tokens WHERE submission_id='sub_all'").get().c;
    assert.strictEqual(cnt2, 2);

    // ⑤ groups 条目：展开名单并入 + drop_groups 收尾
    const r4 = await api(port, "POST", "/submissions/sub_grp/visibility/merge-users",
      { users: ["carol@corp.com", "dave@corp.com"], drop_groups: true }, true);
    assert.strictEqual(r4.status, 200);
    const meta2 = JSON.parse(db.prepare("SELECT meta FROM submissions WHERE id='sub_grp'").get().meta);
    assert.deepStrictEqual(meta2.visibility.groups, []);
    assert.ok(meta2.visibility.users.includes("carol@corp.com"));
    assert.ok(canAccessSubmission(meta2, { email: "carol@corp.com", groups: [], admin: false }),
      "并入名单后的成员应可见");

    // ⑥ 单批上限保护
    const r5 = await api(port, "POST", "/submissions/sub_all/member-tokens/batch",
      { members: Array.from({ length: 501 }, (_, i) => `u${i}@corp.com`) }, true);
    assert.strictEqual(r5.status, 400);
  } finally {
    server.close();
  }
});
