#!/usr/bin/env node
// 安全关键路径自动化测试（重构护航网第二层）。
// 覆盖：rotate-token 权限矩阵、4100 对外口强制 Token、伪造身份头隔离、
//       回环口 restricted Token 强制、列表可见性过滤。
// 原则：不轮换任何真实条目的 Token、不改「新零售」可见性；
//       restricted 场景用临时 DB 条目（sec_test_*），测完立即删除。
// 运行：node scripts/security-test.js（backend 需在 4000/4100 运行中）
"use strict";

const BASE = "http://127.0.0.1:4000";
const EXT = "http://127.0.0.1:4100";
const INIT = {
  jsonrpc: "2.0",
  id: 1,
  method: "initialize",
  params: {
    protocolVersion: "2025-03-26",
    capabilities: {},
    clientInfo: { name: "sec-test", version: "1.0.0" },
  },
};

let pass = 0;
const fails = [];
function check(name, cond, detail = "") {
  if (cond) {
    pass++;
    console.log("  ✓ " + name);
  } else {
    fails.push(name + (detail ? " — " + detail : ""));
    console.log("  ✗ " + name + (detail ? " — " + detail : ""));
  }
}

async function req(url, opts = {}) {
  try {
    const r = await fetch(url, { signal: AbortSignal.timeout(8000), ...opts });
    let body = null;
    try {
      body = await r.json();
    } catch (_) {}
    return { status: r.status, body };
  } catch (e) {
    return { status: 0, body: null, error: String(e.cause?.code || e.message) };
  }
}
const post = (url, headers, payload = INIT) =>
  req(url, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...headers },
    body: JSON.stringify(payload),
  });

(async () => {
  console.log("== A. rotate-token 权限矩阵（不轮换真实条目） ==");
  let r = await post(
    `${BASE}/submissions/sec_test_nonexistent/rotate-token`,
    { "x-actor-email": "someone@example.com" },
    {},
  );
  check("A1 非管理员 rotate 403", r.status === 403, "status=" + r.status);

  r = await post(
    `${BASE}/submissions/sec_test_nonexistent/rotate-token`,
    { "x-actor-email": "admin@example.com", "x-actor-admin": "1" },
    {},
  );
  check("A2 管理员对不存在 id 404", r.status === 404, "status=" + r.status);

  // 找一个真实 Skill 提交验证类型闸门（Skill 无代理 Token）
  const { default: null_ } = {};
  r = await post(
    `${BASE}/submissions/sub_1788423526647/rotate-token`,
    { "x-actor-email": "admin@example.com", "x-actor-admin": "1" },
    {},
  );
  check("A3 对 Skill 类型 rotate 400", r.status === 400, "status=" + r.status);

  console.log("== B. 4100 对外口强制 Token（真实条目，只读调用） ==");
  const betterSqlite3 = require("better-sqlite3");
  // 可写连接：D 段需要插入/删除临时 restricted 条目；真实条目只读不碰
  const db = new betterSqlite3("platform.db");
  const realId = "sub_1788829366889";
  const realMeta = JSON.parse(
    db.prepare("SELECT meta FROM submissions WHERE id=?").get(realId).meta,
  );
  const realToken = realMeta.mcp_token;

  r = await post(`${EXT}/mcp-proxy/${realId}/mcp`, {});
  check("B1 4100 无 token 403", r.status === 403, "status=" + r.status);

  r = await post(`${EXT}/mcp-proxy/${realId}/mcp`, {
    Authorization: "Bearer deadbeef-wrong-token",
  });
  check("B2 4100 错误 token 403", r.status === 403, "status=" + r.status);

  r = await post(`${EXT}/mcp-proxy/${realId}/mcp`, {
    Authorization: `Bearer ${realToken}`,
  });
  check("B3 4100 正确 token 200", r.status === 200, "status=" + r.status);

  r = await req(`${EXT}/audit?limit=1`, {
    headers: { "x-actor-email": "evil@example.com", "x-actor-admin": "1" },
  });
  check(
    "B4 4100 伪造 admin 头访问管理路由 404（路由未挂载）",
    r.status === 404,
    "status=" + r.status,
  );

  console.log("== C. 4000 回环 mode=all 免 Token（语义不变） ==");
  r = await post(`${BASE}/mcp-proxy/${realId}/mcp`, {});
  check("C1 回环无 token 200", r.status === 200, "status=" + r.status);

  console.log("== D. restricted 条目：回环强制 Token + 列表可见性 ==");
  // 临时条目：restricted + 已知 token；proxy 的 token 校验先于实例解析，
  // 因此「带正确 token」预期走到实例解析失败（502/404），断言 ≠403 即证明门生效。
  const testId = "sub_sec_test_" + Date.now();
  const testToken = "sectest" + Math.random().toString(16).slice(2, 18);
  const testMeta = {
    name: "安全测试临时条目(可删)",
    description: "security-test 临时数据",
    owner: "security-test@example.com",
    deploy_status: "undeployed",
    group_key: "sec-test-tmp",
    version: "0.0.1",
    visibility: { mode: "restricted", users: ["member@example.com"], groups: [] },
    mcp_token: testToken,
  };
  db.prepare(
    "INSERT INTO submissions(id,user_id,type,payload_ref,status,scan_status,created_at,meta) VALUES(?,?,?,?,?,?,?,?)",
  ).run(
    testId,
    "security-test@example.com",
    "mcp",
    "sec-test:0.0.1",
    "approved",
    "clean",
    new Date().toISOString(),
    JSON.stringify(testMeta),
  );

  try {
    // D1 匿名列表不含 restricted 条目
    r = await req(`${BASE}/mcp`);
    const anonList = Array.isArray(r.body) ? r.body : [];
    check(
      "D1 匿名列表不含 restricted 条目",
      !anonList.some((x) => x.id === testId),
      "列表 " + anonList.length + " 项",
    );

    // D2 管理员列表可见 restricted 条目
    r = await req(`${BASE}/mcp`, {
      headers: { "x-actor-email": "admin@example.com", "x-actor-admin": "1" },
    });
    const adminList = Array.isArray(r.body) ? r.body : [];
    check(
      "D2 管理员列表含 restricted 条目",
      adminList.some((x) => x.id === testId),
      "status=" + r.status,
    );

    // D3 授权用户（users 命中）列表可见
    r = await req(`${BASE}/mcp`, {
      headers: { "x-actor-email": "member@example.com" },
    });
    const memberList = Array.isArray(r.body) ? r.body : [];
    check(
      "D3 授权用户列表含 restricted 条目",
      memberList.some((x) => x.id === testId),
      "status=" + r.status,
    );

    // D4 未授权用户列表不可见
    r = await req(`${BASE}/mcp`, {
      headers: { "x-actor-email": "outsider@example.com" },
    });
    const outsiderList = Array.isArray(r.body) ? r.body : [];
    check(
      "D4 未授权用户列表不含 restricted 条目",
      !outsiderList.some((x) => x.id === testId),
      "status=" + r.status,
    );

    // D5 回环调 restricted 条目无 token → 403
    r = await post(`${BASE}/mcp-proxy/${testId}/mcp`, {});
    check("D5 回环 restricted 无 token 403", r.status === 403, "status=" + r.status);

    // D6 回环带错误 token → 403
    r = await post(`${BASE}/mcp-proxy/${testId}/mcp`, {
      Authorization: "Bearer wrong-token",
    });
    check("D6 回环 restricted 错误 token 403", r.status === 403, "status=" + r.status);

    // D7 回环带正确 token → 走到实例解析（无实例 → 502/404），只要不是 403 即证明 Token 门通过
    r = await post(`${BASE}/mcp-proxy/${testId}/mcp`, {
      Authorization: `Bearer ${testToken}`,
    });
    check(
      "D7 回环 restricted 正确 token 通过校验(≠403)",
      r.status !== 403,
      "status=" + r.status,
    );
  } finally {
    db.prepare("DELETE FROM submissions WHERE id=?").run(testId);
    const left = db.prepare("SELECT COUNT(*) c FROM submissions WHERE id=?").get(testId).c;
    check("E1 临时条目已清理", left === 0, "残留 " + left);
  }
  db.close();

  console.log(`\n结果: ${pass} 通过 / ${fails.length} 失败`);
  if (fails.length) {
    console.log("失败项:");
    fails.forEach((f) => console.log(" - " + f));
    process.exit(1);
  }
})();
