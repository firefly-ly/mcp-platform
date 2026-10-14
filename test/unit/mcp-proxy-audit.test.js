// test/unit/mcp-proxy-audit.test.js —— P0 调用审计冒烟（2026-10-14）
// 覆盖：包级 token 命中 → caller=package；成员 token 命中 → caller=成员邮箱；
//   JSON-RPC method/工具名提取（rpc 字段）；notifications 跳过；无效 token → 403 且写 proxy_denied；
//   双写 metric_events（actor_id=caller）。不依赖真实平台：内存 sqlite + 假上游 MCP + audit 桩。
"use strict";
const test = require("node:test");
const assert = require("node:assert");
const http = require("node:http");
const express = require("express");
const Database = require("better-sqlite3");

const createMcpProxy = require("../../lib/mcp-proxy");

const MEMBER = "zhangsan@corp.com";
const PKG_TOKEN = "pkg_token_abc";
const MEMBER_TOKEN = "member_token_xyz";

function makeCtx(upstreamPort) {
  const db = new Database(":memory:");
  db.exec(`CREATE TABLE submissions(id TEXT PRIMARY KEY, type TEXT, meta TEXT);
    CREATE TABLE mcp_member_tokens(submission_id TEXT, member TEXT, token TEXT, created_at TEXT, rotated_at TEXT, PRIMARY KEY(submission_id, member));
    CREATE TABLE audit_logs(a TEXT,b TEXT,c TEXT,d TEXT,e TEXT,f TEXT,g TEXT,h TEXT,i TEXT);
    CREATE TABLE metric_events(id TEXT PRIMARY KEY, item_type TEXT, item_ref TEXT, event TEXT, actor_id TEXT, occurred_at TEXT);`);
  db.prepare("INSERT INTO submissions VALUES(?,?,?)").run(
    "sub_test1", "mcp",
    JSON.stringify({
      workload_name: "mcp-fake",
      mcp_token: PKG_TOKEN,
      visibility: { mode: "restricted", users: [MEMBER], groups: [] },
    }),
  );
  db.prepare("INSERT INTO mcp_member_tokens VALUES(?,?,?,?,?)").run(
    "sub_test1", MEMBER, MEMBER_TOKEN, new Date().toISOString(), null,
  );
  const auditCalls = [];
  const ctx = {
    db,
    parseMeta: (row) => JSON.parse(row.meta),
    workloadNameFor: () => "mcp-fake",
    authHeaderCandidates: () => [null],
    deniedThrottled: () => true,
    audit: (req, action, targetType, targetId, detail, result) => {
      auditCalls.push({ action, targetType, targetId, detail, result });
    },
    getIngressPort: async () => upstreamPort,
    ensureStableIngress: async () => null,
    discoverThvEndpoint: async () => null,
    subIdByWorkload: (name) => (name === "mcp-fake" ? "sub_test1" : null),
    healMcpIngress: async () => {},
  };
  return { ctx, db, auditCalls };
}

function startHarness(ctx) {
  const { mcpProxyHandler } = createMcpProxy(ctx);
  const app = express();
  app.all("/mcp-proxy/:name", (req, res) => mcpProxyHandler(req, res, {}));
  return new Promise((resolve) => {
    const server = app.listen(0, () => resolve({ server, port: server.address().port }));
  });
}

function callProxy(port, { path, headers = {}, body = null, method = "POST" }) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      { host: "127.0.0.1", port, path, method, headers },
      (res) => {
        let buf = "";
        res.on("data", (c) => (buf += c));
        res.on("end", () => resolve({ status: res.statusCode, body: buf }));
      },
    );
    req.on("error", reject);
    if (body) req.write(body);
    req.end();
  });
}

const fakeUpstreamBody = JSON.stringify({ jsonrpc: "2.0", id: 1, result: { ok: true } });

test("P0 调用审计：包级/成员 token 归因、rpc 提取、通知跳过、403 拒绝记录", async (t) => {
  const upstream = http.createServer((req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(fakeUpstreamBody);
  });
  await new Promise((r) => upstream.listen(0, r));
  const { ctx, db, auditCalls } = makeCtx(upstream.address().port);
  const { server, port } = await startHarness(ctx);
  try {
    // ① 成员 token 命中：caller=成员邮箱，rpc 提取到 tools/call:query_db
    const r1 = await callProxy(port, {
      path: "/mcp-proxy/mcp-fake",
      headers: { authorization: `Bearer ${MEMBER_TOKEN}` },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "query_db" } }),
    });
    assert.strictEqual(r1.status, 200, "成员 token 应放行");
    const c1 = auditCalls.find((a) => a.action === "proxy_call");
    assert.ok(c1, "应写 proxy_call 审计");
    assert.strictEqual(c1.detail.caller, MEMBER);
    assert.strictEqual(c1.detail.rpc, "tools/call:query_db");
    assert.strictEqual(c1.detail.workload, "mcp-fake");
    const m1 = db.prepare("SELECT actor_id FROM metric_events WHERE item_ref='sub_test1' AND event='call'").get();
    assert.strictEqual(m1.actor_id, MEMBER, "metric_events.actor_id 应记成员邮箱");

    // ② 包级 token 命中：caller=package
    const r2 = await callProxy(port, {
      path: "/mcp-proxy/mcp-fake",
      headers: { "x-mcp-token": PKG_TOKEN },
      body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list" }),
    });
    assert.strictEqual(r2.status, 200);
    const c2 = auditCalls.filter((a) => a.action === "proxy_call").pop();
    assert.strictEqual(c2.detail.caller, "package");
    assert.strictEqual(c2.detail.rpc, "tools/list");

    // ③ notification（无 id）→ 放行但不写 proxy_call
    const callsBefore = auditCalls.filter((a) => a.action === "proxy_call").length;
    await callProxy(port, {
      path: "/mcp-proxy/mcp-fake",
      headers: { authorization: `Bearer ${MEMBER_TOKEN}` },
      body: JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }),
    });
    const callsAfter = auditCalls.filter((a) => a.action === "proxy_call").length;
    assert.strictEqual(callsAfter, callsBefore, "纯通知不应产生 proxy_call");

    // ④ 无效 token（对外口 forceToken 由 server.js 决定，这里以 needToken 触发的 restricted 校验验证）
    const r4 = await callProxy(port, {
      path: "/mcp-proxy/mcp-fake",
      headers: { authorization: "Bearer wrong_token" },
      body: "x",
    });
    assert.strictEqual(r4.status, 403);
    const d4 = auditCalls.find((a) => a.action === "proxy_denied");
    assert.ok(d4, "拒绝应写 proxy_denied");
  } finally {
    server.close();
    upstream.close();
  }
});
