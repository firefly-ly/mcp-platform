// scripts/adopt-member-tokens.js —— MCP 条目一键收编切换（2026-10-14，P1 配套运维脚本）
//
// 用途：把 approved 的 MCP 条目从「包级 token 共用」收编为「restricted + users 名单 + 成员 token」。
//   对每个目标条目依次执行（全部走本机 4000 回环 API，复用真实校验/审计链路）：
//     1) POST /submissions/:id/visibility/merge-users  → 写入名单（mode=all 自动转 restricted，groups 清空）
//     2) POST /submissions/:id/member-tokens/batch     → 名单内每人签发/轮换成员 token
//     3) POST /submissions/:id/rotate-token            → 轮换包级 token（存量已复制配置即刻失效）
//
// 运行位置：248 服务器 backend 仓库根目录（需先部署含 P0/P1 的新代码并重启 backend）。
// 用法：
//   node scripts/adopt-member-tokens.js                          # 默认 dry-run：只打印计划
//   node scripts/adopt-member-tokens.js --emails a@x.com,b@x.com --yes
//   node scripts/adopt-member-tokens.js --emails-file emails.txt --only sub_xxx,sub_yyy --yes
//   node scripts/adopt-member-tokens.js --no-rotate --yes        # 不轮换包级 token（仅收编+签发）
//
// 参数：
//   --emails <逗号分隔> | --emails-file <路径>   成员邮箱名单（必填，归一化小写去重）
//   --only <sub_id,sub_id>                       只处理这些条目；默认处理全部 approved 且非 seed 的 MCP
//   --no-rotate                                  跳过第 3 步（保留包级 token 并行有效）
//   --api <url>                                  backend 地址，默认 http://127.0.0.1:4000
//   --db <path>                                  submissions 清单来源，默认 ./platform.db（只读）
//   --yes                                        真正执行；缺省 dry-run
//
// 注意：回环 4000 信任 x-actor-admin 头是既有设计（前端 Server 端注入同源信任），
//   本脚本必须只在服务器本机执行，不要把 4000 暴露到对外网络。
"use strict";

const fs = require("node:fs");
const path = require("node:path");

function parseArgs(argv) {
  const args = { api: "http://127.0.0.1:4000", db: "./platform.db", rotate: true, yes: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--emails") args.emails = (argv[++i] || "").split(",").map((s) => s.trim()).filter(Boolean);
    else if (a === "--emails-file") args.emailsFile = argv[++i];
    else if (a === "--only") args.only = (argv[++i] || "").split(",").map((s) => s.trim()).filter(Boolean);
    else if (a === "--no-rotate") args.rotate = false;
    else if (a === "--api") args.api = argv[++i];
    else if (a === "--db") args.db = argv[++i];
    else if (a === "--yes") args.yes = true;
    else throw new Error("未知参数: " + a);
  }
  return args;
}

// 条目筛选：approved + type=mcp + 非 seed + （有 --only 时按清单）
function pickTargets(db, only) {
  const rows = db
    .prepare("SELECT id, user_id, status, meta FROM submissions WHERE type='mcp' ORDER BY created_at")
    .all();
  return rows
    .map((r) => {
      let meta = {};
      try { meta = JSON.parse(r.meta || "{}"); } catch (_) {}
      return { id: r.id, status: r.status, meta, name: meta.name || "", visibility: meta.visibility || {} };
    })
    .filter((r) => {
      if (r.id.startsWith("seed_")) return false;
      if (r.status !== "approved") return false;
      if (only && !only.includes(r.id)) return false;
      const mode = r.visibility.mode || "all";
      return mode === "all" || (mode === "restricted" && (r.visibility.groups || []).length > 0);
    });
}

async function callApi(api, pathname, body, doFetch) {
  const f = doFetch || fetch;
  const res = await f(api + pathname, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      // 后端对内信任注入头（与 cloud-ui Server 端同机制），仅限服务器本机调用
      "x-actor-email": "adopt-script@internal",
      "x-actor-admin": "1",
    },
    body: JSON.stringify(body || {}),
  });
  const json = await res.json().catch(() => ({}));
  return { status: res.status, json };
}

async function main(argv, deps = {}) {
  const args = parseArgs(argv || process.argv.slice(2));
  let emails = args.emails || [];
  if (args.emailsFile) {
    emails = fs.readFileSync(path.resolve(args.emailsFile), "utf8")
      .split(/[\s,;]+/).map((s) => s.trim().toLowerCase()).filter(Boolean);
  }
  emails = [...new Set(emails.map((e) => e.toLowerCase().trim()).filter(Boolean))];
  if (!emails.length) throw new Error("缺少成员邮箱：用 --emails 或 --emails-file 提供");

  const Database = deps.Database || require("better-sqlite3");
  const db = new Database(path.resolve(args.db), { readonly: true });
  const targets = pickTargets(db, args.only);
  db.close();

  console.log(`[收编切换] 邮箱 ${emails.length} 个 | 目标条目 ${targets.length} 个 | 模式=${args.yes ? "EXECUTE" : "DRY-RUN"} | 包级轮换=${args.rotate ? "yes" : "no"}`);
  console.log(`[名单] ${emails.join(", ")}`);
  for (const t of targets) {
    const v = t.visibility;
    console.log(`  - ${t.id}「${t.name}」 mode=${v.mode || "all"} users=${(v.users || []).length} groups=${JSON.stringify(v.groups || [])}`);
  }
  if (!args.yes) {
    console.log("\n[dry-run] 未执行任何变更。确认无误后追加 --yes 执行。");
    return { targets, emails, executed: false };
  }

  const doFetch = deps.fetch;
  const results = [];
  for (const t of targets) {
    const r = { id: t.id, steps: [] };
    // 1) 名单合并（mode=all 自动转 restricted；groups 条目 drop_groups 收尾）
    const m = await callApi(args.api, `/submissions/${t.id}/visibility/merge-users`, { users: emails, drop_groups: true }, doFetch);
    r.steps.push({ step: "merge-users", status: m.status, added: m.json.added, total: m.json.total });
    // 2) 批量签发成员 token
    const b = await callApi(args.api, `/submissions/${t.id}/member-tokens/batch`, { members: emails }, doFetch);
    r.steps.push({ step: "member-tokens/batch", status: b.status, issued: b.json.issued });
    // 3) 轮换包级 token（杀存量复制；管理员在 UI 重新拿新包级，成员用各自的）
    if (args.rotate) {
      const rt = await callApi(args.api, `/submissions/${t.id}/rotate-token`, {}, doFetch);
      r.steps.push({ step: "rotate-token", status: rt.status });
    }
    results.push(r);
    console.log(`[done] ${t.id}: ` + r.steps.map((s) => `${s.step}=${s.status}`).join(" "));
  }
  console.log("\n[完成] 全部条目已收编。成员请到 Cloud UI 重新复制各自的接入配置（带个人 token）。");
  return { targets, emails, executed: true, results };
}

if (require.main === module) {
  main().catch((e) => {
    console.error("[失败]", e.message);
    process.exit(1);
  });
}

module.exports = { parseArgs, pickTargets, main };
