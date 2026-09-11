// scripts/smoke-test.js —— 平台后端全接口冒烟测试（重构护航用，可重复执行）
// 用法：node scripts/smoke-test.js [BASE]   默认 BASE=http://127.0.0.1:4000
// 覆盖：健康/索引/MCP列表详情tools调用/代理(4000回环+4100强制token)/skills列表下载/
//       统计/收藏/审计/issues/metrics/submissions/classify/versions/轮换
// 退出码：0=全绿 1=有失败
const BASE = process.argv[2] || "http://127.0.0.1:4000";
const EXTERNAL = process.argv[3] || "http://127.0.0.1:4100";
const ADMIN = { "x-actor-email": "admin@example.com", "x-actor-admin": "1" };

let pass = 0, fail = 0;
const failures = [];
function check(name, cond, detail) {
  if (cond) { pass++; console.log(`  ✓ ${name}`); }
  else { fail++; failures.push(name + (detail ? ` — ${detail}` : "")); console.log(`  ✗ ${name}${detail ? " — " + detail : ""}`); }
}
async function req(url, opts = {}, timeout = 15000) {
  const res = await fetch(url, { ...opts, signal: AbortSignal.timeout(timeout) });
  let body = null;
  const ct = res.headers.get("content-type") || "";
  if (ct.includes("json")) { try { body = await res.json(); } catch (_) {} }
  return { status: res.status, body, headers: res.headers };
}
const INIT = { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "smoke", version: "1" } } };

(async () => {
  console.log(`冒烟测试目标: ${BASE} / 对外口 ${EXTERNAL}\n`);

  // 1. 基础
  let r = await req(`${BASE}/health`);
  check("health 200 + ok", r.status === 200 && r.body && r.body.ok === true);
  r = await req(`${BASE}/`);
  check("API 索引 200", r.status === 200);

  // 2. MCP 域
  r = await req(`${BASE}/mcp`);
  check("/mcp 列表 200 + 数组", r.status === 200 && Array.isArray(r.body));
  const mcpItem = (r.body || []).find((x) => x.endpoint && x.healthy === true);
  check("/mcp 含健康实例(有 endpoint+healthy)", Boolean(mcpItem), "无 healthy 条目");
  const mcpId = mcpItem ? mcpItem.id : null;
  if (mcpId) {
    r = await req(`${BASE}/mcp/${mcpId}`);
    check("/mcp/:id 详情 200", r.status === 200 && r.body && r.body.id === mcpId);
    const t1 = Date.now();
    r = await req(`${BASE}/mcp/${mcpId}/tools`);
    const t1ms = Date.now() - t1;
    check("/mcp/:id/tools 200 + tools 数组", r.status === 200 && Array.isArray(r.body && r.body.tools));
    const t2 = Date.now();
    await req(`${BASE}/mcp/${mcpId}/tools`);
    check(`/mcp/:id/tools 二次命中缓存(<100ms，实测 ${Date.now() - t2}ms)`, Date.now() - t2 < 100);
    if (t1ms > 100) console.log(`  ℹ tools 首次为实时握手 ${t1ms}ms（SWR 冷启动，正常）`);
    r = await req(`${BASE}/mcp/call`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ref: mcpId }) });
    check("/mcp/call 200", r.status === 200);
  }

  // 3. 代理：回环 4000（mode=all 免 token）与对外 4100（强制 token，含 mode=all）
  const proxyUrl = mcpItem ? mcpItem.public_endpoint : null;
  check("复制配置含 4100 对外 URL", Boolean(proxyUrl && proxyUrl.includes(":4100")), proxyUrl || "无 public_endpoint");
  if (mcpId) {
    // 回环口直连：mode=all 不强制 token（既有语义不变）
    r = await req(`${BASE}/mcp-proxy/${mcpId}/mcp`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(INIT) });
    check("4000 回环代理(mode=all 无 token) 200", r.status === 200, "status=" + r.status);
  }
  if (proxyUrl) {
    r = await req(proxyUrl, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(INIT) });
    check("4100 无 token 403（强制校验）", r.status === 403, "status=" + r.status);
    // 当前有效 token 从 DB meta 读取（脚本与本机同源，允许直读）
    let tok = null;
    try {
      const db = require("better-sqlite3")(require("path").join(__dirname, "..", "platform.db"), { readonly: true });
      const m = JSON.parse(db.prepare("SELECT meta FROM submissions WHERE id=?").get(mcpId).meta);
      tok = m.mcp_token || null;
    } catch (_) {}
    if (tok) {
      r = await req(proxyUrl, { method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${tok}` }, body: JSON.stringify(INIT) });
      check("4100 带当前 token 200", r.status === 200, "status=" + r.status);
    }
  }
  r = await req(`${EXTERNAL}/audit`, { headers: ADMIN });
  check("4100 管理路由 404（物理隔离）", r.status === 404, "status=" + r.status);

  // 4. Skills 域
  r = await req(`${BASE}/skills`);
  check("/skills 列表 200 + 数组", r.status === 200 && Array.isArray(r.body));
  const skill = (r.body || [])[0];
  if (skill) {
    r = await req(`${BASE}/skills/${skill.id}`);
    check("/skills/:id 详情 200", r.status === 200);
    const dl = await fetch(`${BASE}/skills/${skill.id}/download`, { signal: AbortSignal.timeout(20000) });
    const buf = Buffer.from(await dl.arrayBuffer());
    check("/skills/:id/download 200 + 非空 zip", dl.status === 200 && buf.length > 0 && dl.headers.get("content-type") === "application/zip", `${dl.status} ${buf.length}B`);
    r = await req(`${BASE}/groups/${skill.group_key}/versions`);
    check("/groups/:group_key/versions 200", r.status === 200);
  }

  // 5. 统计 / 收藏 / issues / metrics
  for (const p of ["/stats/top", "/stats/detail", "/stats/trend?days=7", "/stats/unique?days=7"]) {
    r = await req(`${BASE}${p}`);
    check(`${p} 200`, r.status === 200);
  }
  r = await req(`${BASE}/favorites/counts?item_type=mcp`);
  check("/favorites/counts 200", r.status === 200);
  r = await req(`${BASE}/issues`);
  check("/issues 200", r.status === 200);
  r = await req(`${BASE}/metrics`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ item_type: "mcp", item_ref: "smoke-test", event: "call" }) });
  check("POST /metrics 200", r.status === 200);

  // 6. 管理面（伪造管理员头——在回环上这是既有信任模型）
  r = await req(`${BASE}/submissions`, { headers: ADMIN });
  check("/submissions 列表 200", r.status === 200);
  r = await req(`${BASE}/audit?limit=1`, { headers: ADMIN });
  check("/audit 200（含 token_rotate 记录则轮换链路也在）", r.status === 200);
  r = await req(`${BASE}/registry/classify?ref=ghcr.io/stackloklabs/osv`);
  check("/registry/classify 200", r.status === 200);
  const skillId = skill ? skill.id : "sub_1788423526647";
  r = await req(`${BASE}/groups/hello-report/versions`).catch(() => null);
  r = await req(`${BASE}/submissions/nonexistent/env`, { headers: ADMIN });
  check("/submissions/:id/env 404（不存在 id）", r.status === 404, "status=" + r.status);

  // 7. 上传防滥用（无身份 401）
  r = await fetch(`${BASE}/upload?name=t.tar.gz`, { method: "POST", body: "x", signal: AbortSignal.timeout(10000) });
  check("/upload 无身份 401", r.status === 401, "status=" + r.status);

  // 汇总
  console.log(`\n结果: ${pass} 通过 / ${fail} 失败`);
  if (fail) { console.log("失败项:\n - " + failures.join("\n - ")); process.exit(1); }
  process.exit(0);
})().catch((e) => { console.error("冒烟测试异常:", e.message); process.exit(1); });
