// lib/env-secrets.js —— .env 私密配置：dotenv 解析 → ToolHive 加密凭据库 → 部署时 --secret 注入。
// 值全程不进 DB/命令行/日志/审计（2026-09-05 设计定稿）。从 server.js 拆出（2026-09-07）。
"use strict";

module.exports = function makeEnvSecrets(ctx) {
  const { THV_BIN, db, parseMeta, patchMeta, actorFromReq, workloadNameFor, audit } = ctx;

// ---- 源码包 MCP：.env secrets 注入 + 自动构建（docker build）----
// 设计（2026-09-05 定稿）：
//   · .env 单独上传，值经 `thv secret set`（stdin 管道，不进命令行）入 ToolHive
//     加密凭据库（AES-256-GCM + OS keyring）；平台 DB 只存键名与 secret 引用名。
//   · 部署时注入 `-e KEY=${secret:<name>}`——明文值全程只在凭据库与容器启动瞬间出现。
//   · 源码 zip（package.json / requirements.txt 识别）构建本地镜像后走既有部署链。
//   · 审计只记键数；值不入 DB/日志/审计。

// dotenv 标准解析：忽略空行与 # 注释；支持 export 前缀；值剥离成对引号；
// 未加引号时行内 # 起注释（前值保留 trim）。返回 { KEY: value }。
function parseDotenv(text) {
  const out = {};
  for (const rawLine of String(text || "").split(/\r?\n/)) {
    let line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    if (line.startsWith("export ")) line = line.slice(7).trim();
    const eq = line.indexOf("=");
    if (eq <= 0) continue;
    const key = line.slice(0, eq).trim();
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) continue;
    let val = line.slice(eq + 1).trim();
    const q = val[0];
    if ((q === '"' || q === "'") && val.endsWith(q) && val.length >= 2) {
      val = val.slice(1, -1);
    } else {
      const hash = val.indexOf(" #");
      if (hash !== -1) val = val.slice(0, hash).trim();
    }
    out[key] = val;
  }
  return out;
}

// 静态扫描源码文本，提取代码声明的环境变量需求键（用于 .env 缺键告警）。
function scanSourceEnvKeys(text) {
  const keys = new Set();
  const patterns = [
    /process\.env\.([A-Za-z_][A-Za-z0-9_]*)/g,
    /process\.env\[[\s]*["']([A-Za-z_][A-Za-z0-9_]*)["']/g,
    /os\.environ(?:\.get)?\(\s*["']([A-Za-z_][A-Za-z0-9_]*)["']/g,
    /os\.getenv\(\s*["']([A-Za-z_][A-Za-z0-9_]*)["']/g,
    /os\.environ\[["']([A-Za-z_][A-Za-z0-9_]*)["']\]/g,
  ];
  for (const re of patterns) {
    let m;
    while ((m = re.exec(text)) !== null) keys.add(m[1]);
  }
  return [...keys];
}

// 用 spawnSync 的 stdin 传值写入 ToolHive 加密凭据库（值不进命令行/进程列表）。
function thvSecretSet(name, value) {
  const r = require("child_process").spawnSync(
    THV_BIN, ["secret", "set", name],
    { input: value, encoding: "utf8", windowsHide: true, timeout: 30000 },
  );
  if (r.status !== 0) throw new Error(`secret set ${name} 失败: ${(r.stderr || r.stdout || "").slice(0, 200)}`);
}
function thvSecretDelete(name) {
  const r = require("child_process").spawnSync(
    THV_BIN, ["secret", "delete", name],
    { encoding: "utf8", windowsHide: true, timeout: 30000 },
  );
  return r.status === 0;
}

// 上传 .env：解析 → 逐键写入凭据库 → meta.env_refs（KEY→secret名）与 env_keys。
// secret 命名：mcp-<submission_id>-<key 小写>，与条目一一绑定，杜绝跨条目错配。
function secretNameFor(sid, key) {
  return `mcp-${String(sid).toLowerCase()}-${key.toLowerCase()}`;
}
async function storeSubmissionEnv(req, res, sub) {
  const actor = actorFromReq(req);
  const isOwner = actor.email && String(sub.user_id || "").toLowerCase() === actor.email.toLowerCase();
  if (!actor.admin && !isOwner) return res.status(403).json({ error: "仅提交者本人或管理员可配置环境变量" });
  if (sub.type !== "mcp") return res.status(400).json({ error: "仅 MCP 条目支持环境变量" });

  const raw = Buffer.isBuffer(req.body) ? req.body.toString("utf8") : "";
  if (!raw.trim()) return res.status(400).json({ error: "缺少 .env 内容" });
  const parsed = parseDotenv(raw);
  const keys = Object.keys(parsed);
  if (keys.length === 0) return res.status(400).json({ error: "未解析出任何 KEY=VALUE 条目" });

  const meta = parseMeta(sub);
  const workload = meta.workload_name || workloadNameFor(sub.id);
  const refs = {};
  try {
    for (const key of keys) {
      const name = secretNameFor(sub.id, key);
      thvSecretSet(name, parsed[key]);
      refs[key] = name;
    }
  } catch (e) {
    // 失败即回滚已写入的键，避免半套配置
    for (const name of Object.values(refs)) thvSecretDelete(name);
    return res.status(500).json({ error: "凭据库写入失败: " + e.message });
  }
  patchMeta(sub.id, {
    env_refs: refs,
    env_keys: keys,
    env_updated_at: new Date().toISOString(),
  });
  // 审计只记键名清单与数量，绝不记值
  audit(req, "env_configured", sub.type, sub.id, { keys, count: keys.length });
  res.json({ id: sub.id, keys, count: keys.length });
}

// 删除条目的全部 secrets（removed/rejected 清理时调用；值不回传）
function deleteSubmissionSecrets(id) {
  const sub = db.prepare("SELECT meta FROM submissions WHERE id=?").get(id);
  if (!sub) return;
  const meta = parseMeta(sub);
  const refs = meta.env_refs || {};
  for (const name of Object.values(refs)) {
    try { thvSecretDelete(name); } catch (_) { /* 幂等清理，单个失败不阻断 */ }
  }
}

// 部署时把 secrets 引用转成 thv run 的 --secret 参数：
// --secret <secret 名>,target=<KEY> —— ToolHive 启动容器时向凭据库请求解密并注入目标环境变量。
// 官方语法（勿用 -e ${secret:}，那会被原样传入不解析）。
function envInjectArgs(meta) {
  const refs = meta.env_refs || {};
  const args = [];
  for (const [key, secretName] of Object.entries(refs)) {
    args.push("--secret", `${secretName},target=${key}`);
  }
  return args;
}

// ---- 应用自带鉴权（API Key）时，平台代为携带 ----
// 场景：源码 MCP 应用从注入的 env 里读 API Key 做请求鉴权（如 RETAIL_MCP_API_KEY）。
// 平台探测（/mcp/:id/tools）、代调（/mcp/call）、反向代理（/mcp-proxy）都需要携带，
// 否则 initialize/tools/list 全被 401 挡住，详情页工具显示为空、用户也无法调用。
// 值仍从凭据库读回（thv secret get），只在服务端内存短暂缓存，不落盘不进日志。

const secretValueCache = new Map(); // secret 名 -> { v, at }，5 分钟 TTL
function thvSecretGetValue(name) {
  const c = secretValueCache.get(name);
  if (c && Date.now() - c.at < 5 * 60 * 1000) return c.v;
  let r;
  try {
    r = require("child_process").spawnSync(
      THV_BIN, ["secret", "get", String(name)],
      { encoding: "utf8", windowsHide: true, timeout: 15000 },
    );
  } catch (_) {
    return null;
  }
  if (r.status !== 0) return null;
  const v = String(r.stdout || "").trim();
  if (!v) return null;
  secretValueCache.set(name, { v, at: Date.now() });
  return v;
}

// 疑似鉴权凭证的 env 键名匹配与优先级（API Key > Token > Auth > Secret）。
const AUTH_KEY_RE = /API_?KEY|API_?TOKEN|ACCESS_?TOKEN|AUTH_?TOKEN|_TOKEN$|^TOKEN$|API_?SECRET|_SECRET$|AUTHORIZATION|^AUTH$|BEARER/i;
function authKeyPriority(key) {
  if (/API_?KEY|API_?TOKEN/i.test(key)) return 0;
  if (/TOKEN/i.test(key)) return 1;
  if (/AUTH|BEARER/i.test(key)) return 2;
  return 3;
}

// 返回该条目可用的鉴权头候选列表（按优先级降序）。每个候选同时带
// Authorization: Bearer 与 X-Api-Key 两种形态，兼容两类常见校验方式。
function authHeaderCandidates(meta) {
  const keys = (meta && meta.env_keys) || [];
  const refs = (meta && meta.env_refs) || {};
  return keys
    .filter((k) => AUTH_KEY_RE.test(k) && refs[k])
    .sort((a, b) => authKeyPriority(a) - authKeyPriority(b))
    .map((k) => {
      const v = thvSecretGetValue(refs[k]);
      return v ? { Authorization: `Bearer ${v}`, "X-Api-Key": v } : null;
    })
    .filter(Boolean);
}

  return {
    parseDotenv, scanSourceEnvKeys, thvSecretSet, thvSecretDelete, secretNameFor,
    storeSubmissionEnv, deleteSubmissionSecrets, envInjectArgs,
    authHeaderCandidates,
  };
};
