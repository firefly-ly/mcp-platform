// scripts/ci-seed.js —— CI/空库环境种子：通过 HTTP API 造一个可下载的最小 Skill
// 用途：smoke-test 的 /skills/:id/download 断言需要一个已审批上架的 Skill；
//       空库（CI）时先跑本脚本再跑冒烟。幂等：已存在同名条目则跳过。
// 用法：node scripts/ci-seed.js [BASE]   默认 BASE=http://127.0.0.1:4000
"use strict";
const BASE = process.argv[2] || process.env.BASE || "http://127.0.0.1:4000";
const INTERNAL = process.env.INTERNAL_PROXY_TOKEN || "thv-internal-proxy";
const ADMIN = { "x-actor-email": "admin@example.com", "x-actor-admin": "1" };

async function req(url, opts = {}, timeout = 20000) {
  const res = await fetch(url, { ...opts, signal: AbortSignal.timeout(timeout) });
  let body = null;
  const ct = res.headers.get("content-type") || "";
  if (ct.includes("json")) { try { body = await res.json(); } catch (_) {} }
  return { status: res.status, body, headers: res.headers };
}

async function main() {
  // 已有则跳过（幂等）
  const list = await req(`${BASE}/skills`, { headers: ADMIN });
  const existing = (list.body || []).find((s) => s.name === "ci-seed");
  if (existing) { console.log("[ci-seed] 已存在，跳过:", existing.id || existing.group_key); return; }

  // 1) 构造最小合法 zip（SKILL.md，内容避开注入规则：不含 URL/编码块/危险 API）
  // lib/pkg 自拆分后为 CTX 工厂（makePkg(ctx)），buildZip 为纯函数不依赖 ctx，传空对象即可
  const { buildZip } = require("../lib/pkg")({});
  const zip = buildZip([{
    name: "SKILL.md",
    data: Buffer.from("---\nname: ci-seed\ndescription: CI seed skill for smoke download\n---\n# ci-seed\nMinimal seed skill.", "utf8"),
  }]);

  // 2) 上传制品（内部令牌）
  const up = await req(`${BASE}/upload?name=ci-seed.zip`, {
    method: "POST",
    headers: { "x-internal-proxy": INTERNAL, "Content-Type": "application/octet-stream" },
    body: zip,
  });
  if (up.status !== 200) throw new Error("upload 失败: " + up.status + " " + JSON.stringify(up.body));
  const artifactKey = up.body.key;

  // 3) 提交
  const sub = await req(`${BASE}/submissions`, {
    method: "POST",
    headers: { ...ADMIN, "Content-Type": "application/json" },
    body: JSON.stringify({
      user_id: "admin@example.com",
      type: "skill",
      payload_ref: "ci-seed",
      meta: { artifact_key: artifactKey, artifact_filename: "ci-seed.zip", name: "ci-seed", version: "1.0.0", description: "CI seed skill for smoke download" },
    }),
  });
  if (sub.status !== 200) throw new Error("提交失败: " + sub.status + " " + JSON.stringify(sub.body));
  const id = sub.body.id;

  // 4) 审批（confirm_prompt_review 防注入闸门要求；扫描异步未返回时闸门放行无告警提交）
  const ap = await req(`${BASE}/submissions/${id}/approve`, {
    method: "POST",
    headers: { ...ADMIN, "Content-Type": "application/json" },
    body: JSON.stringify({ admin_id: "ci", reason: "CI seed", confirm_prompt_review: true }),
  });
  if (ap.status !== 200) throw new Error("审批失败: " + ap.status + " " + JSON.stringify(ap.body));

  // 5) 上线（配置可见范围）
  const vis = await req(`${BASE}/submissions/${id}/visibility`, {
    method: "POST",
    headers: { ...ADMIN, "Content-Type": "application/json" },
    body: JSON.stringify({ mode: "all", users: [], groups: [] }),
  });
  if (vis.status !== 200) throw new Error("上线失败: " + vis.status + " " + JSON.stringify(vis.body));

  // 6) 轮询 /skills 确认可见
  for (let i = 0; i < 10; i++) {
    const chk = await req(`${BASE}/skills`, { headers: ADMIN });
    const found = (chk.body || []).find((s) => s.name === "ci-seed");
    if (found) { console.log("[ci-seed] 种子完成:", id); return; }
    await new Promise((r) => setTimeout(r, 1000));
  }
  throw new Error("种子后 /skills 未见条目");
}

main().catch((e) => { console.error("[ci-seed] 失败:", e.message); process.exit(1); });
