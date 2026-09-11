// MCP + Skill 平台 · 自建后端最小骨架（方案3）
// 技术栈：Node + Express + better-sqlite3 + cors
// 说明：这是"上传/审批/收藏/监控"业务中枢的本地可跑最小版本。
//       生产需补：Casdoor OIDC 回调拿用户/角色、文件上传到对象存储、
//       Trivy 扫描、审批通过调 Registry Admin API 写目录 + 推 Harbor/Git、
//       Prometheus 接 Gateway 调用量（见 runbook 阶段10 警告）。

const express = require("express");
const cors = require("cors");
const Database = require("better-sqlite3");
const fs = require("fs");
const path = require("path");
const { execFile } = require("child_process");
const util = require("util");
const crypto = require("crypto");
const os = require("os");
const { execFileHidden, safeExec } = require("./lib/exec");
const http = require("http");
const zlib = require("zlib");
const objStore = require("./object-store");

// 内置 .env 加载（不依赖 dotenv）：仅填充未设置的环境变量，已导出的优先
(() => {
  const fs = require("fs"), p = path.join(__dirname, ".env");
  if (!fs.existsSync(p)) return;
  for (const line of fs.readFileSync(p, "utf8").split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/);
    if (!m) continue;
    const val = m[2].replace(/^["']|["']$/g, "");
    if (!(m[1] in process.env)) process.env[m[1]] = val;
  }
})();

const PORT = process.env.PORT || 4000;
// 默认只绑本机回环：身份靠前端转发的 x-actor-email 头，直连暴露 0.0.0.0 可被局域网伪造。
// 需要对外（如网关/TRUST_GATEWAY 部署）时显式设 HOST=0.0.0.0。
const HOST = process.env.HOST || "127.0.0.1";
// 重要：WSL2 下 /mnt/c 是 DrvFS(9p)，SQLite 的 fsync/文件锁支持不全，
// 会导致进程卡在 D 态、端口绑不上。故 Linux 下默认把 DB 放到原生文件系统。
const DB_PATH = process.env.DB_PATH ||
  (process.platform === "linux"
    ? path.join(process.env.HOME || "/tmp", ".local/share/platform-backend/platform.db")
    : "platform.db");

fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");

// 5 张业务表（与 Registry 库分离）
db.exec(`
  CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY, name TEXT, role TEXT);
  CREATE TABLE IF NOT EXISTS submissions(id TEXT PRIMARY KEY, user_id TEXT, type TEXT, payload_ref TEXT, status TEXT, scan_status TEXT, created_at TEXT, meta TEXT);
  CREATE TABLE IF NOT EXISTS approvals(id TEXT PRIMARY KEY, submission_id TEXT, admin_id TEXT, decision TEXT, reason TEXT, decided_at TEXT);
  CREATE TABLE IF NOT EXISTS favorites(id TEXT PRIMARY KEY, user_id TEXT, item_type TEXT, item_ref TEXT, created_at TEXT);
  CREATE TABLE IF NOT EXISTS metric_events(id TEXT PRIMARY KEY, item_type TEXT, item_ref TEXT, event TEXT, actor_id TEXT, occurred_at TEXT);
  CREATE TABLE IF NOT EXISTS active_versions(
    group_key TEXT PRIMARY KEY,
    item_type TEXT NOT NULL,
    active_submission_id TEXT NOT NULL,
    updated_at TEXT
  );
  CREATE TABLE IF NOT EXISTS issues(
    id TEXT PRIMARY KEY,
    target_type TEXT NOT NULL,
    target_ref TEXT NOT NULL,
    author TEXT,
    title TEXT,
    body TEXT,
    status TEXT DEFAULT 'open',
    created_at TEXT,
    reply TEXT,
    replied_at TEXT,
    reply_by TEXT
  );
`);
// 兼容已存在的旧库（早期没有 meta 列）
try { db.exec("ALTER TABLE submissions ADD COLUMN meta TEXT;"); } catch (_) {}

// metric_events 查询索引：列表页逐条 COUNT、stats 全表 GROUP BY 都按 (item_type, event, item_ref) 过滤，
// 无索引时随表膨胀线性变慢；occurred_at 纳入索引同时加速时间窗清理与日报表。
try {
  db.exec("CREATE INDEX IF NOT EXISTS idx_metric_events_lookup ON metric_events(item_type, event, item_ref, occurred_at);");
} catch (_) {}

// 统一审计轨迹（2.4.4）：治理动作全量记录，只增不删改（代码中不存在本表的 UPDATE/DELETE）。
// 记录七要素：谁(ts/actor)、做了什么(action)、对什么(target)、怎么做的(detail)、结果(result)。
// 拒绝与失败同权记录（result=denied/error）——审计的另一半价值是"谁试图绕过"。
try {
  db.exec(`CREATE TABLE IF NOT EXISTS audit_logs(
    id TEXT PRIMARY KEY, ts TEXT, actor_email TEXT, actor_admin INTEGER,
    action TEXT, target_type TEXT, target_id TEXT, detail TEXT, result TEXT
  )`);
  db.exec("CREATE INDEX IF NOT EXISTS idx_audit_lookup ON audit_logs(action, target_type, target_id, ts);");
} catch (_) {}

// 首次运行种子：已审批的 demo skill + demo mcp + 一些 demo 指标事件
function seedIfEmpty() {
  try {
    const subCnt = db.prepare("SELECT COUNT(*) c FROM submissions").get().c;
    if (subCnt > 0) return; // 已有人提交过，不再塞 demo
    const now = Date.now();
    const insSub = db.prepare("INSERT INTO submissions VALUES(?,?,?,?,?,?,?,?)");
    const insMet = db.prepare("INSERT INTO metric_events VALUES(?,?,?,?,?,?)");

    // demo 已审批 skill
    const skills = [
      { ref: "dws-explorer:1.0.0", name: "DWS 数据探查器", desc: "一键连接数仓、自动探查表结构与数据质量，生成可视化探查报告。", dl: 128 },
      { ref: "meeting-minutes:0.2.1", name: "会议纪要生成器", desc: "上传会议录音或文字记录，自动提炼决议、待办与责任人，推送企微。", dl: 64 },
      { ref: "code-reviewer:1.1.0", name: "代码审查助手", desc: "针对 PR/MR 做增量审查，给出风险点、合规项与修复建议。", dl: 211 },
    ];
    skills.forEach((d, i) => {
      const id = "seed_skill_" + i;
      insSub.run(
        id, "admin", "skill", d.ref, "approved", "passed",
        new Date(now - i * 86400000).toISOString(),
        JSON.stringify({ name: d.name, description: d.desc, download_url: "", seed_downloads: d.dl, owner: "platform" }),
      );
      const k = Math.min(5, d.dl);
      for (let j = 0; j < k; j++) {
        insMet.run("ev_seed_" + i + "_" + j, "skill", id, "download", "demo", new Date(now - j * 3600000).toISOString());
      }
    });

    // demo 已审批 mcp（用户提交的 MCP，审核通过后进入目录）
    const mcps = [
      { ref: "dingtalk-notify:0.3.0", name: "钉钉通知 MCP", desc: "把告警、审批、定时任务结果推送到钉钉群，支持富文本与@人。", owner: "alice" },
      { ref: "sql-query:1.4.2", name: "SQL 查询 MCP", desc: "面向业务人员的自然语言转 SQL，只读模式连接内网数据库并可视化结果。", owner: "bob" },
    ];
    mcps.forEach((d, i) => {
      const id = "seed_mcp_" + i;
      insSub.run(
        id, d.owner, "mcp", d.ref, "approved", "passed",
        new Date(now - i * 86400000).toISOString(),
        JSON.stringify({ name: d.name, description: d.desc, owner: d.owner }),
      );
      const k = i + 2; // 一些调用事件
      for (let j = 0; j < k; j++) {
        insMet.run("ev_mcp_seed_" + i + "_" + j, "mcp", id, "call", "demo", new Date(now - j * 3600000).toISOString());
      }
    });

    console.log("已写入 demo skill / mcp 与指标种子数据");
  } catch (e) {
    console.warn("种子数据写入失败（可忽略，不影响运行）:", e.message);
  }
}
seedIfEmpty();

// 把 submissions 行映射为对外暴露的 MCP/Skill 视图对象
function mapMcpRow(s, callMap, favMap) {
  let meta = {};
  try { meta = s.meta ? JSON.parse(s.meta) : {}; } catch (_) {}
  return {
    id: s.id,
    item_ref: s.id,
    name: meta.name || s.payload_ref,
    description: meta.description || "",
    payload_ref: s.payload_ref,
    owner: meta.owner || s.user_id,
    call_count: callMap[s.id] || 0,
    favorite_count: favMap[s.id] || 0,
    created_at: s.created_at,
    endpoint: meta.endpoint || undefined,
    transport: meta.transport || undefined,
    image_ref: meta.image_ref || undefined,
    deploy_status: meta.deploy_status || "unborn",
    deploy_error: meta.deploy_error || "",
    workload_name: meta.workload_name || undefined,
    registry_synced: meta.registry_synced || "",
    registry_name: meta.registry_name || "",
    group_key: meta.group_key || "",
    version: meta.version || "1.0.0",
    repository_url: meta.repository_url || undefined,
    mcp_labels: meta.mcp_labels || undefined,
    mcp_inspect: meta.mcp_inspect || undefined,
  };
}

// ---- 真实 MCP 调用（Streamable-HTTP 客户端，零外部依赖，用 Node 原生 fetch）----
// 当前由 ToolHive 实际运行的 MCP server 端点。生产环境应由平台运行时动态写入/发现。
const LIVE_ENDPOINTS = {
  "stackloklabs-toolhive-doc-mcp": "http://127.0.0.1:63281/mcp",
  "toolhive-docs": "http://127.0.0.1:63281/mcp",
};
// ref -> 镜像名关键字（用于 thv list 动态发现运行端点，避免端口变化后失效）
const MCP_IMAGE_ALIASES = {
  "stackloklabs-toolhive-doc-mcp": "stackloklabs/toolhive-doc-mcp",
  "toolhive-docs": "stackloklabs/toolhive-doc-mcp",
};
// 供 /catalog 展示、且可被真实调用的运行实例
// 注：平台应以审批通过的 submissions 或 Registry 条目为唯一来源，避免硬编码演示项
// 与已发布管理出现不一致。
const LIVE_MCPS = [];

// 默认【不改写】：当前后端与 ToolHive MCP server 同处 WSL2，Docker 已把容器
// 端口转发到 WSL2 的 127.0.0.1，直接用即可。若 server 真在 Windows 主机、需跨
// 网络访问，再设 WSL2_REWRITE=1 启用改写（把 127.0.0.1 换成 Windows 主机 IP）。
function rewriteForWsl2(url) {
  if (process.env.WSL2_REWRITE !== "1" || process.platform !== "linux") return url;
  try {
    const osrelease = fs.readFileSync("/proc/sys/kernel/osrelease", "utf8");
    if (!/microsoft|wsl/i.test(osrelease)) return url;
    const resolv = fs.readFileSync("/etc/resolv.conf", "utf8");
    const m = resolv.match(/nameserver\s+(\d+\.\d+\.\d+\.\d+)/);
    const winIp = m && m[1];
    if (!winIp || winIp.startsWith("127.")) return url;
    return url.replace(/^(https?:\/\/)(127\.0\.0\.1|localhost)(:|\/)/, `$1${winIp}$3`);
  } catch (_) {
    return url;
  }
}

async function getIngressPort(workloadName) {
  try {
    const { stdout } = await execFileHidden(
      "docker", ["port", `${workloadName}-ingress`],
      { timeout: 10000, maxBuffer: MAX_BUFFER },
    );
    // docker port 输出每行格式："<container_port>/<proto> -> <host>:<host_port>"
    // 例："31396/tcp -> 127.0.0.1:31396" 或 "13433/tcp -> 0.0.0.0:13433"
    // ToolHive 不同版本/不同环境下 ingress 端口可能动态变化，不能硬编码 13433。
    const lines = stdout.trim().split("\n").filter(Boolean);
    for (const line of lines) {
      const m = line.match(/->\s+(?:127\.0\.0\.1|0\.0\.0\.0|localhost|::1)?:(\d+)/);
      if (m) return m[1];
    }
  } catch (_) {
    /* 无 ingress 或 docker 异常 */
  }
  return null;
}

// 对平台已提交的 MCP，动态发现当前可达的 ingress 端口（优先平台固定端口）。
// 背景：ToolHive 部署时 thv list 先报告内部端口（如 127.0.0.1:21784），此时 ingress
// 容器尚未创建，导致写入 meta.endpoint 的端口浏览器无法访问。详情/调用时重新查一次。
// ensureStableIngress 幂等：固定端口可用时秒回；坏/缺 ingress 时重建（端口不变）。
async function discoverIngressForSubmission(sub, opts = {}) {
  if (!sub || sub.type !== "mcp") return null;
  const meta = parseMeta(sub);
  const workload = meta.workload_name || workloadNameFor(sub.id);
  const p = await ensureStableIngress(workload, meta, opts);
  if (p) return `http://127.0.0.1:${p}/mcp`;
  return meta.endpoint || null;
}

async function discoverThvEndpoint(ref) {
  if (!ref) return null;
  const alias = MCP_IMAGE_ALIASES[ref] || ref;
  const list = await thvListJson();
  const entry = list.find((x) =>
    x.status === "running" &&
    (x.name === ref || (x.package && x.package.includes(alias)))
  );
  if (!entry) return null;
  // thv list 报告的 url 可能不是实际可访问的 ingress 端口（如 14801 不可达，
  // 而 Docker 实际映射的是 13433），优先用 docker port 取 ingress 容器端口。
  const ingressPort = await getIngressPort(entry.name);
  if (ingressPort) return `http://127.0.0.1:${ingressPort}/mcp`;
  return entry.url || null;
}

async function resolveEndpoint(ref, explicit) {
  if (explicit) return explicit;
  if (ref && /^https?:\/\//.test(ref)) return ref;
  // 优先运行时动态发现 ToolHive 实际端口，避免硬编码端口失效
  const discovered = await discoverThvEndpoint(ref);
  if (discovered) return discovered;
  if (ref && LIVE_ENDPOINTS[ref]) return LIVE_ENDPOINTS[ref];
  return null;
}

// 调用前探活：MCP endpoint 对 GET 通常 405，但 TCP 通即可；ECONNREFUSED 会抛错。
async function probeMcpEndpoint(url) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 3000);
  try {
    await fetch(url, { method: "GET", signal: controller.signal });
    return true;
  } catch (_) {
    return false;
  } finally {
    clearTimeout(timer);
  }
}

// 解析 SSE 流，返回所有 message 事件的 data 数组
async function parseSSE(body) {
  const reader = body.getReader();
  const decoder = new TextDecoder();
  let buf = "";
  const events = [];
  const ingest = (text) => {
    buf += text;
    let idx;
    while ((idx = buf.indexOf("\n\n")) >= 0) {
      const chunk = buf.slice(0, idx);
      buf = buf.slice(idx + 2);
      const dataLine = chunk.split("\n").find((l) => l.startsWith("data:"));
      if (dataLine) {
        try { events.push(JSON.parse(dataLine.slice(5).trim())); } catch (_) {}
      }
    }
  };
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    ingest(decoder.decode(value, { stream: true }));
  }
  // 处理没有结尾 \n\n 的最后一个事件（服务器关流时常见）
  if (buf.trim()) ingest(buf + "\n\n");
  return events;
}

async function mcpPost(endpoint, sessionId, body, extraHeaders) {
  const headers = {
    "Content-Type": "application/json",
    Accept: "application/json, text/event-stream",
    ...(extraHeaders || {}),
  };
  if (sessionId) headers["Mcp-Session-Id"] = sessionId;
  const resp = await fetch(endpoint, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });
  const sid = resp.headers.get("Mcp-Session-Id") || sessionId;
  const ct = resp.headers.get("content-type") || "";
  let events;
  if (ct.includes("text/event-stream")) {
    events = await parseSSE(resp.body);
  } else {
    try { events = [await resp.json()]; } catch (_) { events = []; }
  }
  return { sid, events, status: resp.status };
}

// 真实 MCP 调用：initialize -> initialized -> (tools/list | tools/call)
async function mcpCall(endpoint, { tool, args, headers } = {}) {
  const init = await mcpPost(endpoint, null, {
    jsonrpc: "2.0", id: 1, method: "initialize",
    params: {
      protocolVersion: "2024-11-05",
      capabilities: {},
      clientInfo: { name: "platform-backend", version: "1.0" },
    },
  }, headers);
  const payload = init.events[init.events.length - 1] || {};
  if (payload.error) throw new Error("initialize 失败: " + JSON.stringify(payload.error));
  const sid = init.sid;
  await mcpPost(endpoint, sid, { jsonrpc: "2.0", method: "notifications/initialized" }, headers);
  if (!tool) {
    const r = await mcpPost(endpoint, sid, { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }, headers);
    return { stage: "tools/list", events: r.events, status: r.status };
  }
  const r = await mcpPost(endpoint, sid, {
    jsonrpc: "2.0", id: 3, method: "tools/call",
    params: { name: tool, arguments: args || {} },
  }, headers);
  return { stage: "tools/call", events: r.events, status: r.status };
}

// 带鉴权候选的 MCP 调用：条目 env 里配了 API Key/Token 时逐个尝试（按优先级），
// 全部 401/403 才回落到无鉴权（与旧行为一致）。应用未做鉴权时带凭证调用也无害
// （大多数实现忽略多余头），所以凭证候选放在前面，减少一轮往返。
async function mcpCallAuthed(endpoint, opts, meta) {
  const candidates = [{}, ...authHeaderCandidates(meta || {})];
  let last;
  for (let i = 0; i < candidates.length; i++) {
    try {
      const r = await mcpCall(endpoint, { ...opts, headers: candidates[i] });
      const denied = r.status === 401 || r.status === 403;
      if (denied && i < candidates.length - 1) { last = r; continue; }
      return r;
    } catch (e) {
      last = e;
      const denied = r401403(e);
      if (denied && i < candidates.length - 1) continue;
      throw e;
    }
  }
  return last;
}
function r401403(e) {
  return /\b40[13]\b|unauthorized|forbidden/i.test(String((e && e.message) || e));
}

// ---- P3: 审批后通过 ToolHive 自动部署 MCP，并回写运行端点 ----
// 用户提交只带 image_ref（ghcr.io/组织/镜像:tag），平台调 ToolHive 把它跑起来，
// ToolHive 自动分配端点（http://127.0.0.1:<port>/mcp），管理员无需手填地址。
const MAX_BUFFER = 64 * 1024 * 1024;
// thv 二进制：优先环境变量，其次本机已知安装路径，最后回退 PATH 查找。
const THV_BIN = process.env.THV_BIN ||
  (fs.existsSync("C:\\Users\\19076\\AppData\\Local\\ToolHive\\bin\\thv.exe")
    ? "C:\\Users\\19076\\AppData\\Local\\ToolHive\\bin\\thv.exe"
    : "thv");

// ---- 内网镜像仓库（MCP 镜像内网化）配置 ----
// INTERNAL_REGISTRY：内网 OCI registry 地址。本地自测用 localhost:5000，
// 生产换成内网 Harbor 地址即可，代码无需改动（同为标准 OCI 接口）。
const INTERNAL_REGISTRY = (process.env.INTERNAL_REGISTRY || "localhost:5000").replace(/\/+$/, "");
// TRUSTED_REGISTRIES：受信外部镜像源白名单（逗号分隔）。命中的允许提交，标注来源并留痕。
const TRUSTED_REGISTRIES = (process.env.TRUSTED_REGISTRIES || "ghcr.io/stackloklabs,ghcr.io/stacklok")
  .split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);
// INTERNAL_ONLY：严格模式，置 1 时只接受内网 registry 的镜像（档2 一并拒绝）
const INTERNAL_ONLY = process.env.INTERNAL_ONLY === "1" || process.env.INTERNAL_ONLY === "true";
const DOCKER_BIN = process.env.DOCKER_BIN || "docker";
// MCP 镜像 tar 包上传上限（默认 2GB）。超出提示用户改用 ghcr 地址提交。
// 设计原则：tar 经审批后直接 docker load 进本地 daemon 运行，不强制推回内网 registry。
const MAX_TAR_UPLOAD_MB = Number(process.env.MAX_TAR_UPLOAD_MB || 2048);
const MAX_TAR_UPLOAD_BYTES = MAX_TAR_UPLOAD_MB * 1024 * 1024;

// 提取镜像引用的 registry 部分：无域名前缀（如 node:22）视为 docker.io
function registryOf(ref) {
  const s = String(ref || "").trim();
  const first = s.split("/")[0];
  if (first.includes(".") || first.includes(":") || first === "localhost") return first.toLowerCase();
  return "docker.io";
}

function isInternalRegistry(reg) {
  const internal = INTERNAL_REGISTRY.toLowerCase();
  return reg === internal || reg.startsWith(internal + "/");
}

// 分级信任模型：档1 内网直通 / 档2 受信白名单留痕 / 档3 未知来源拦截
// 关键治理原则：用户提交阶段【不允许】直接填写平台内网仓库地址（INTERNAL_REGISTRY）。
// 内网仓库只应由平台在审批通过后写入（mirror / build）。默认模式下 tier-1 拒绝提交；
// INTERNAL_ONLY 严格模式用于纯内网环境，此时只接受已在内网仓库的镜像，由管理员预置。
function classifyRegistry(ref) {
  const reg = registryOf(ref);
  if (!ref) return { tier: 3, registry: reg, allowed: false, message: "缺少镜像引用" };
  if (isInternalRegistry(reg)) {
    if (INTERNAL_ONLY) {
      return { tier: 1, registry: reg, allowed: true, message: "内网镜像源，直接通过" };
    }
    return {
      tier: 1,
      registry: reg,
      allowed: false,
      message: "平台内网仓库地址不接受直接提交；请提供外部镜像源（如 ghcr.io/...），审批通过后由平台同步入内网",
    };
  }
  if (!INTERNAL_ONLY) {
    // 白名单两种粒度：纯域名（ghcr.io）或 域名/命名空间（ghcr.io/stackloklabs）。
    // 命名空间级白名单须按"完整引用前缀"匹配，只比对 registry 域名会漏判。
    const full = String(ref).toLowerCase();
    for (const t of TRUSTED_REGISTRIES) {
      if (reg === t || full.startsWith(t + "/") || reg.endsWith("." + t)) {
        return { tier: 2, registry: reg, allowed: true, message: "受信外部源，审批通过后将同步到内网仓库" };
      }
    }
  }
  return {
    tier: 3,
    registry: reg,
    allowed: false,
    message: INTERNAL_ONLY
      ? "严格模式仅允许内网镜像源 " + INTERNAL_REGISTRY
      : "未知镜像源 " + reg + "：不在受信白名单内，需管理员特批",
  };
}

// —— 提交防刷 / 去重配置 ——
// 同用户 + 同 type + （同名 name 或同 payload_ref）已存在 pending/approved 时拒绝重复提交。
// 限流：同用户 1 小时内提交数超过阈值则返回 429。
const DUP_STATUSES = ["pending", "approved"]; // 这些状态视为"已存在"，拦截重复
const RATE_WINDOW_MS = Number(process.env.RATE_WINDOW_MS || 60 * 60 * 1000); // 1 小时
const RATE_MAX = Number(process.env.RATE_MAX || 20); // 窗口内最多 20 次

// 归一化"名称"用于去重比对：去掉空白、转小写、合并空格，避免大小写/空格差异绕过
function normName(n) {
  return String(n || "").trim().toLowerCase().replace(/\s+/g, " ");
}

// 从制品库读取用户上传的镜像 tar 包并 docker load 进本地 daemon。
// 解析 docker load 输出的镜像名（含 tag）；若无 tag 则按 artifact_key 派生一个稳定 tag，
// 确保 thv run 能按名称定位镜像。返回镜像引用字符串。
// tar 路径不走内网 registry：加载后镜像已在本地 daemon，deployMcp 直接运行它。
function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

// 从 payload_ref / meta 提取 group_key 与 version。
// payload_ref 如 dws-explorer:1.0.0 / dws-explorer 1.0.0 / dws-explorer-v1.0.0
// → group=dws-explorer, version=1.0.0
// 没有显式版本时默认 1.0.0，group_key 回退到 name 或 payload_ref 或 id。
function extractGroupAndVersion(sub) {
  const meta = parseMeta(sub);
  let group_key = (meta.group_key || "").trim();
  let version = (meta.version || "").trim();
  const ref = (sub.payload_ref || "").trim();
  if (!version) {
    // 尝试从 ref 末尾取 semver：xxx:1.2.3 或 xxx-v1.2.3
    const m = ref.match(/(?:^|[\s:\-_/]|[_-]v?V?)(\d+\.\d+\.\d+(?:[-+.]\w+)*)(?:\s*|:?$)/);
    if (m) version = m[1];
  }
  if (!group_key) {
    // 去掉版本后缀
    const base = ref
      .replace(/[\s:\-_/]?v?V?\d+\.\d+\.\d+(?:[-+.]\w*)*(?:\s*|:?$)/, "")
      .replace(/[\s:\-_/]+$/, "");
    group_key = base || meta.name || ref || sub.id;
  }
  return {
    group_key: slugify(group_key).replace(/[^a-z0-9._-]/g, "-").replace(/^-+|-+$/g, ""),
    version: version || "1.0.0",
  };
}

// 确保 meta 里有 group_key / version，并写回 DB
function ensureGroupMeta(sub) {
  const meta = parseMeta(sub);
  if (meta.group_key && meta.version) return { group_key: meta.group_key, version: meta.version };
  const gv = extractGroupAndVersion(sub);
  patchMeta(sub.id, { group_key: gv.group_key, version: gv.version });
  return gv;
}

// （原 getActiveSubmissionId / setActiveSubmission 已随激活指针废弃移除；
//  active_versions 表保留以兼容历史库结构，不再读写。）

// 多版本折叠：每个 group 只展示一条——**最新已上架版本优先**，组内无已上架时回落最新一条。
// （2026-09-08 起废弃 active_versions 指针：用户侧版本下拉已实现自选已上架版本，
//  指针只剩"默认选中项"一个作用，改由"最新已上架"这一确定性规则承担，不再维护指针表。）
//
// ⚠️ 历史坑（保留警示）：粒度必须"按 group 各自决策"，兜底落在 group 内部而不是全局——
//    曾因全局 all-or-nothing 过滤导致"审批一个就只剩一个"。
function pickDisplayVersions(rows) {
  const byGroup = new Map();
  rows.forEach((s) => {
    // 无 group_key 的历史数据以自身 id 为 group，保证各自独立成组、不会互相顶掉
    const gk = parseMeta(s).group_key || s.id;
    if (!byGroup.has(gk)) byGroup.set(gk, []);
    byGroup.get(gk).push(s);
  });
  const byNewest = (a, b) => (a.created_at >= b.created_at ? a : b);
  const picked = [];
  byGroup.forEach((list) => {
    // 最新创建的按序找第一个已上架的；整组都未上架则回落组内最新（用户页后续还有可见性过滤）
    const hit = [...list].sort((a, b) => (a.created_at < b.created_at ? 1 : -1))
      .find((s) => isOnShelf(parseMeta(s)));
    picked.push(hit || list.reduce(byNewest));
  });
  return picked.sort((a, b) => (a.created_at < b.created_at ? 1 : -1));
}

// 列出某 group 下所有 approved 版本
function listGroupVersions(group_key) {
  const rows = db
    .prepare("SELECT * FROM submissions WHERE status='approved' AND (meta LIKE ? OR payload_ref=?) ORDER BY created_at DESC")
    .all(`%"group_key":"${group_key}"%`, group_key);
  return rows;
}

function parseMeta(s) {
  try { return s && s.meta ? JSON.parse(s.meta) : {}; } catch (_) { return {}; }
}

// 由 submission id 派生合法的工作负载名（小写字母数字，DNS label 安全）
function workloadNameFor(id) {
  return "mcp-" + String(id).replace(/[^a-z0-9]/gi, "").toLowerCase();
}

// 读取 thv 当前管理的所有 workload（含 stopped/unhealthy）
async function thvListJson() {
  try {
    const { stdout } = await execFileHidden(
      THV_BIN, ["list", "--format", "json", "--all"],
      { timeout: 20000, maxBuffer: MAX_BUFFER },
    );
    return JSON.parse(stdout || "[]");
  } catch (_) {
    return [];
  }
}

// 局部更新某 submission 的 meta（合并字段）。
// 原子性约束（务必保持，否则会引入丢更新竞态）：
//   1) 函数必须保持全同步——better-sqlite3 同步 API + Node 单线程，SELECT→改→UPDATE
//      中间不会让出事件循环，天然原子；一旦掺入 await，两个并发调用就会互相覆盖。
//   2) patch 必须是「本次要改的增量字段」，禁止调用方把整份旧 meta 快照回写
//      （部署/自愈/registryPublish 三方并发 patch 同一条 submission，整快照回写必丢字段）。
//   3) 全项目写 meta 只允许走本函数（当前 UPDATE submissions SET meta 仅此一处）。
function patchMeta(id, patch) {
  const sub = db.prepare("SELECT * FROM submissions WHERE id=?").get(id);
  if (!sub) return;
  const meta = parseMeta(sub);
  Object.assign(meta, patch);
  db.prepare("UPDATE submissions SET meta=? WHERE id=?")
    .run(JSON.stringify(meta), id);
}

// ---- 模块化拆分（2026-09-07）：制品包/审计/安全扫描/env-secrets/源码构建/workload 对账
// 六个内聚域抽为 lib/ 模块，共享依赖经 CTX 注入（保持单一 db 连接与 patchMeta 原子性）。
const CTX = {
  db, patchMeta, parseMeta, execFileHidden, safeExec, MAX_BUFFER, THV_BIN,
  actorFromReq, workloadNameFor, objStore, thvListJson,
  get TAR_ROOT() { return TAR_ROOT; },
  get PLATFORM_ROOT() { return __dirname; },
  deployMcp: (...a) => __deployService.deployMcp(...a),
  undeployMcp: (...a) => __deployService.undeployMcp(...a),
  audit: (...a) => audit(...a),
};
const {
  tarListFile, tarExtractFile, openSkillPackage, isPathTraversal,
  buildZip, convertArtifactToZip, inspectSkillPackage,
  parseYamlFrontMatter, validateSkillPackage,
} = require("./lib/pkg")(CTX);
// pkg 函数必须挂回 CTX：scan/source-build 等后初始化的模块从 ctx 解构这些函数，
// 不挂载则拿到 undefined（2026-09-07 trivy 源码包扫描报 openSkillPackage is not a function 即此因）。
Object.assign(CTX, {
  tarListFile, tarExtractFile, openSkillPackage, isPathTraversal,
  buildZip, convertArtifactToZip, inspectSkillPackage,
  parseYamlFrontMatter, validateSkillPackage,
});
const { audit, deniedThrottled } = require("./lib/audit")(CTX);
CTX.audit = audit;
const {
  parseDotenv, scanSourceEnvKeys, thvSecretSet, thvSecretDelete, secretNameFor,
  storeSubmissionEnv, deleteSubmissionSecrets, envInjectArgs, authHeaderCandidates,
} = require("./lib/env-secrets")(CTX);
const { buildSourceImage, SOURCE_MAX_MB } = require("./lib/source-build")(CTX);
const {
  trivyUsable, runTrivyScan, runPromptScan, runSubmissionScans, PROMPT_INJECTION_RULES,
} = require("./lib/scan")(CTX);
const { healFailState, HEAL_BACKOFF_MS, reconcileMcpWorkloads } = require("./lib/reconcile")(CTX);

// ---- 可见性控制（方案C变体：管理员在发布时决定哪些成员/组可查看/下载/调用）----
// 身份由前端 Server 端经 header 注入：x-actor-email / x-actor-groups(逗号分隔) / x-actor-admin。
// 浏览器不直连本服务，header 由可信的 Next Server 端写入；普通用户无法伪造 session 身份。
// 安全默认：无身份 header 的调用（外部直连/旧调用方）只能看到 mode=all 的条目。

/**
 * 请求方身份（由可信 Next Server 端写入的 x-actor-* 头解析而来）。
 * 注意：本服务只信任回环调用方——对外 4100 口会在入口剥离这些头（见 proxyApp 装配）。
 * @typedef {Object} Actor
 * @property {string} email  小写去空格后的邮箱；匿名调用为 ""
 * @property {string[]} groups  小写分组列表（逗号分隔头展开）
 * @property {boolean} admin  仅当 x-actor-admin === "1" 时为 true
 */

/**
 * 条目可见性配置（meta.visibility 的规范化形态）。
 * @typedef {Object} Visibility
 * @property {"all"|"restricted"} mode
 * @property {string[]} users  小写邮箱白名单（restricted 生效）
 * @property {string[]} groups  小写分组白名单（restricted 生效）
 */

/** 从请求头解析调用方身份。绝不校验头本身的可信性——信任边界在「仅回环可达」。 @param {import("express").Request} req @returns {Actor} */
function actorFromReq(req) {
  const email = String(req.headers["x-actor-email"] || "").toLowerCase().trim();
  const groups = String(req.headers["x-actor-groups"] || "")
    .split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);
  const admin = String(req.headers["x-actor-admin"] || "") === "1";
  return { email, groups, admin };
}
/** visibility 缺省视为全员可见（兼容历史数据与未配置条目）。 @param {Object} meta @returns {Visibility} */
function parseVisibility(meta) {
  const v = meta && meta.visibility;
  if (!v || v.mode !== "restricted")
    return { mode: "all", users: [], groups: [] };
  return {
    mode: "restricted",
    users: Array.isArray(v.users)
      ? v.users.map((s) => String(s).toLowerCase().trim()).filter(Boolean)
      : [],
    groups: Array.isArray(v.groups)
      ? v.groups.map((s) => String(s).toLowerCase().trim()).filter(Boolean)
      : [],
  };
}
/** 条目是否已「上线」：仅当管理员显式配置过可见范围后，才对非管理员开放可见/下载/调用。
 *  存量条目无 visibility_configured 字段 → 视为已上线（向后兼容，不强制重配）；
 *  新提交默认 visibility_configured=false → 未上线，仅管理员在「已发布管理」可见，待配可见范围。
 *  @param {Object} meta @returns {boolean} */
function isOnShelf(meta) {
  return !(meta && meta.visibility_configured === false);
}
/** 可见性判定单一入口：admin 恒通过 → 未上架拒绝 → mode=all 通过 → restricted 按 users/groups 命中。
 *  列表过滤、详情、下载、代理调用必须全部走这里，禁止各自内联判定。
 *  @param {Object} meta @param {Actor|null} actor @returns {boolean} */
function canAccessSubmission(meta, actor) {
  if (!actor || actor.admin) return true;
  // 未上线的条目只对管理员可见（普通用户/匿名一律不可见不可调用）
  if (!isOnShelf(meta)) return false;
  const v = parseVisibility(meta);
  if (v.mode !== "restricted") return true;
  if (actor.email && v.users.includes(actor.email)) return true;
  if (Array.isArray(actor.groups) && actor.groups.some((g) => v.groups.includes(g)))
    return true;
  return false;
}

// 部署一个 MCP：thv run 起容器 → 轮询 list 拿 url → 写回 endpoint
// 部署/下线服务句柄：由 routes/mcp 装配后创建（见文件末尾装配区），CTX 经惰性箭头引用
let __deployService = null;

// ---- P4: 同步到 Registry Server（thv-registry-api :8080）----
// 平台「审批通过 / 部署成功 / 下线 / 删除」动作，同步在 ToolHive Registry 中
// 创建或删除对应条目，使 ToolHive 客户端与 Cloud UI 能从统一目录消费已发布的
// MCP / Skill。
// 前置：Registry 需存在一个 managed 源（已通过 PUT /v1/sources/platform-managed
// 创建，持久化于 postgres，无需重启容器）。匿名模式无需 token。
const REGISTRY_URL = (process.env.REGISTRY_URL || "http://127.0.0.1:8080").replace(/\/+$/, "");
const REGISTRY_NAMESPACE = process.env.REGISTRY_NAMESPACE || "platform";

// 解析 Registry 可达地址（WSL2 下可经 WSL2_REWRITE=1 改写为 Windows 主机 IP）
function registryUrl() {
  let u = REGISTRY_URL;
  if (process.env.WSL2_REWRITE === "1" && process.platform === "linux") {
    try {
      const osrelease = fs.readFileSync("/proc/sys/kernel/osrelease", "utf8");
      if (!/microsoft|wsl/i.test(osrelease)) return u;
      const resolv = fs.readFileSync("/etc/resolv.conf", "utf8");
      const m = resolv.match(/nameserver\s+(\d+\.\d+\.\d+\.\d+)/);
      const winIp = m && m[1];
      if (winIp && !winIp.startsWith("127.")) {
        u = u.replace(/^(https?:\/\/)127\.0\.0\.1(:\d+)?/, `$1${winIp}$2`);
      }
    } catch (_) {}
  }
  return u;
}

function slugify(s) {
  return String(s || "")
    .toLowerCase().trim()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-+|-+$/g, "");
}

// 推导合法 semver：优先 meta.version，其次镜像 tag，最后 1.0.0
function pickVersion(meta, imageRef) {
  if (meta && meta.version && /^\d+\.\d+\.\d+([-.][0-9A-Za-z.-]+)?$/.test(meta.version)) return meta.version;
  if (imageRef && /:(\d+\.\d+\.\d+([-.][0-9A-Za-z.-]+)?)$/.test(imageRef)) {
    return imageRef.match(/:(\d+\.\d+\.\d+([-.][0-9A-Za-z.-]+)?)$/)[1];
  }
  return "1.0.0";
}

// 计算每个 submission 在 Registry 中的稳定条目名（幂等：算过则复用，避免重复创建）
// 多版本共用同一个 group_key，因此 Registry entryName 按 group_key 生成，version 区分不同提交。
function ensureRegistryMeta(sub) {
  const meta = parseMeta(sub);
  if (meta.registry_name && meta.registry_version) {
    return { entryName: meta.registry_name, namespace: meta.registry_namespace || REGISTRY_NAMESPACE, version: meta.registry_version };
  }
  const gv = ensureGroupMeta(sub);
  const namespace = REGISTRY_NAMESPACE;
  let slug = slugify(gv.group_key);
  // 兜底：历史数据没有 group_key 时仍用 name + id 后缀保证唯一
  if (!slug) {
    const suffix = String(sub.id).replace(/[^a-z0-9]/gi, "").slice(-10);
    const base = slugify(meta.name || sub.payload_ref || sub.id);
    slug = ((base ? base + "-" : "") + suffix).toLowerCase();
    slug = slug.replace(/[^a-z0-9._-]/g, "-").replace(/^[^a-z0-9]+/, "").replace(/[^a-z0-9]+$/, "");
    if (slug.length > 60) slug = slug.slice(0, 60).replace(/[^a-z0-9]+$/, "");
    if (!slug) slug = "item-" + suffix;
  }
  const version = gv.version || pickVersion(meta, meta.image_ref);
  // server 条目名需为 namespace/name；skill 条目名即 name（namespace 单列字段）
  const entryName = sub.type === "mcp" ? namespace + "/" + slug : slug;
  patchMeta(sub.id, { registry_name: entryName, registry_namespace: namespace, registry_version: version });
  return { entryName, namespace, version };
}

// 发布到 Registry Server。MCP 需等部署拿到 endpoint 后再调；Skill 审批时即可发。

// WSL 环境：/proc/version 含 microsoft。WSL 内的非回环 IPv4 是 NAT 地址，
// 对外不可路由、宿主机也无法直连——宁可回退 localhost，不能给"像样的错误地址"。
const IS_WSL = (() => {
  try {
    return /microsoft/i.test(require("fs").readFileSync("/proc/version", "utf8"));
  } catch (_) {
    return false;
  }
})();

// 本机第一个非回环 IPv4（内网地址）。未显式设 PUBLIC_BASE 时用它兜底，
// 避免对外分发的地址是 127.0.0.1（跨机不可达）。
// 动态探测（非启动缓存）：笔记本在 WiFi/热点/有线间切换后，复制的接入配置 URL
// 必须跟随当前网卡，否则生成"看起来像样但谁都连不上"的失效地址。开销微秒级。
function getLanIp() {
  if (IS_WSL) return null; // WSL 内探测到的必是 NAT 地址，禁用
  try {
    const nets = os.networkInterfaces();
    for (const [ifName, list] of Object.entries(nets)) {
      // 排除虚拟交换机网卡（WSL/Hyper-V/Docker）——其地址对局域网不可达
      if (/vethernet|wsl|hyper-v|docker|loopback/i.test(ifName)) continue;
      for (const n of list || []) {
        if (n.family === "IPv4" && !n.internal && n.address) return n.address;
      }
    }
  } catch (_) {
    /* 取不到就用回环兜底 */
  }
  return null;
}

// 对外 MCP 代理监听配置（方案 B 第二口）：仅挂 /mcp-proxy，强制 Token 校验。
// 端口/绑定可用 PROXY_PORT / PROXY_HOST 覆盖；MCP_PROXY_PUBLIC_DISABLED=1 可整体关闭。
const PROXY_PORT = Number(process.env.PROXY_PORT || 4100);
const PROXY_HOST = process.env.PROXY_HOST || "0.0.0.0";

// 平台对外可访问基址：内网部署时建议设置 PUBLIC_BASE（如 http://内网IP:4000），
// 否则外部 Registry 客户端拿到的下载路由指向 localhost，跨机不可达。
// 优先级：PUBLIC_BASE > 请求 host（非回环时）> 自动探测的内网 IP > localhost。
function publicBase(req) {
  if (process.env.PUBLIC_BASE) return process.env.PUBLIC_BASE.replace(/\/$/, "");
  if (req) {
    const host = req.get("host") || "";
    const hostname = host.split(":")[0];
    // 回环地址对终端用户无意义，不能作为对外基址
    if (hostname && !["127.0.0.1", "localhost", "::1", "0.0.0.0"].includes(hostname)) {
      return `${req.protocol}://${host}`;
    }
  }
  const lanIp = getLanIp();
  if (lanIp) return `http://${lanIp}:${PORT}`;
  return `http://localhost:${PORT}`;
}
// 启动时告警一次：回退 localhost 意味着跨机器不可达，提醒部署者显式声明基址
if (!process.env.PUBLIC_BASE && !getLanIp()) {
  console.warn(
    "[publicBase] 未设置 PUBLIC_BASE 且未探测到真实内网 IP：对外地址回退 localhost（仅本机可用）。跨机器访问请设置 PUBLIC_BASE，如 http://<Windows局域网IP>:4000",
  );
}

// 终端用户访问某个 MCP 的固定入口：走平台后端的反向代理（端口即后端自身端口）。
// 这样复制给用户的 URL 不随容器重建漂移，也绕开 ingress 只绑 127.0.0.1 的限制。
function mcpProxyUrl(name, req) {
  // 复制配置/registry 发布统一指向对外代理口（4100，强制 Token）；
  // 可用 MCP_PROXY_PUBLIC_BASE 显式覆盖（IP 固定的部署建议设置）。
  // 无 LAN_IP 时回退 publicBase(req)（通常 localhost:4000，仅本机可用）。
  const lanIp = getLanIp();
  const base =
    process.env.MCP_PROXY_PUBLIC_BASE ||
    (lanIp && !process.env.MCP_PROXY_PUBLIC_DISABLED
      ? `http://${lanIp}:${PROXY_PORT}`
      : null) ||
    publicBase(req);
  return `${base}/mcp-proxy/${encodeURIComponent(name)}/mcp`;
}

// 是否回环/本机地址。只有这类地址才需要改写为对外地址并绕平台代理；
// 外部托管的 MCP（非回环）本身就是终端用户可达的，原样给出即可。
function isLoopbackUrl(url) {
  return /^https?:\/\/(127\.0\.0\.1|localhost|0\.0\.0\.0|\[::1\])(:|\/|$)/i.test(
    url || "",
  );
}

// 为 workload 对应的 submission 取（无则生成）代理访问令牌。
// restricted MCP的 /mcp-proxy 调用需要它；mode=all 不强制但仍随 URL 发放，
// 这样管理员后续把条目改成 restricted 时，已复制配置里的 token 继续有效。
function getOrCreateMcpToken(workload) {
  const sid = subIdByWorkload(workload);
  if (!sid) return null; // LIVE_MCPS 等非 submission 条目
  const meta = parseMeta(db.prepare("SELECT meta FROM submissions WHERE id=?").get(sid));
  if (meta.mcp_token) return meta.mcp_token;
  const token = crypto.randomBytes(16).toString("hex");
  patchMeta(sid, { mcp_token: token });
  return token;
}

// 生成「终端用户可复制」的对外地址。回环地址走平台代理（固定端口、消化 ingress 漂移），
// 非回环地址原样返回，避免把外部可直连的服务绕进代理后反而 502。
// P0-2 后续硬化：URL 不再携带 mcp_token（避免凭证泄漏进浏览器历史/访问日志/Referer），
// token 改经 Authorization Header 传递（见 mcpAuthHeadersFor）；旧的 ?t= 仍被 /mcp-proxy 兼容接受。
function publicEndpointFor(proxyName, endpoint, req) {
  if (!endpoint) return undefined;
  if (!isLoopbackUrl(endpoint)) return endpoint;
  return mcpProxyUrl(proxyName, req);
}

// 代理访问凭证：Authorization Header 形态（前端复制配置时注入 headers 字段）。
// LIVE_MCPS 等无 submission 的条目返回 undefined（mode=all 免凭证）。
function mcpAuthHeadersFor(workload) {
  const token = getOrCreateMcpToken(workload);
  return token ? { Authorization: `Bearer ${token}` } : undefined;
}


async function registryPublish(id) {
  const sub = db.prepare("SELECT * FROM submissions WHERE id=?").get(id);
  if (!sub) return;
  const meta = parseMeta(sub);
  const { entryName, namespace, version } = ensureRegistryMeta(sub);
  let body;
  if (sub.type === "mcp") {
    // 部署时写入 meta.endpoint 的是 thv list 报告的内部端口，浏览器/外部客户端
    // 访问不到；发布前重新发现 ingress 宿主端口，并改写成对外可达地址，
    // 否则 Registry 里的 remote URL 会是 127.0.0.1，跨机消费必然失败。
    const reachableEp = (await discoverIngressForSubmission(sub)) || meta.endpoint;
    if (!reachableEp) {
      patchMeta(id, { registry_synced: "skipped:no-endpoint" });
      return;
    }
    body = {
      server: {
        name: entryName,
        title: meta.name || sub.payload_ref,
        description: meta.description || "",
        version,
        // 条目指向内网镜像引用：已同步则用 internal_ref，外部客户端也从我方内网拉
        packages: (meta.internal_ref || meta.image_ref)
          ? [{ registryType: "oci", identifier: meta.internal_ref || meta.image_ref, version }]
          : [],
        // 指向平台反向代理而非容器直连端口：直连端口会随容器重建漂移且只绑 127.0.0.1
        remotes: [
          {
            type: "http",
            url: mcpProxyUrl(meta.workload_name || workloadNameFor(sub.id)),
          },
        ],
      },
      claims: {},
    };
  } else {
    // Skill 制品：优先指向平台内部下载路由（本体在 ObjectStore，平台直接服务字节）。
    // 若无 artifact_key 则回退旧 download_url（外部 URL）。
    const gk = meta.group_key || sub.payload_ref;
    const ver = meta.version || "1.0.0";
    const dl = meta.artifact_key
      ? `${publicBase(null)}/skills/${encodeURIComponent(gk)}/${encodeURIComponent(ver)}/download`
      : (meta.download_url || "");
    body = {
      skill: {
        namespace,
        name: entryName,
        version,
        title: meta.name || sub.payload_ref,
        description: meta.description || "",
        repository: dl ? { url: dl } : undefined,
        packages: dl
          ? [{ registryType: "oci", url: dl, identifier: meta.artifact_key || dl }]
          : [],
      },
      claims: {},
    };
  }
  try {
    const res = await fetch(registryUrl() + "/v1/entries", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (res.status === 201 || res.status === 200 || res.status === 409) {
      patchMeta(id, { registry_synced: "published", registry_sync_error: "" });
    } else {
      const txt = await res.text();
      patchMeta(id, { registry_synced: "error", registry_sync_error: "HTTP " + res.status + " " + txt.slice(0, 300) });
      console.error("[registry] publish 失败", id, res.status, txt.slice(0, 200));
    }
  } catch (e) {
    patchMeta(id, { registry_synced: "error", registry_sync_error: String((e && e.message) || e).slice(0, 300) });
    console.error("[registry] publish 异常", id, e && e.message);
  }
}

// 从 Registry Server 删除条目（下线 / 删除时调用）。无 registry_name 视为从未发布，跳过。
async function registryDelete(id) {
  const sub = db.prepare("SELECT * FROM submissions WHERE id=?").get(id);
  if (!sub) return;
  const meta = parseMeta(sub);
  const name = meta.registry_name;
  const version = meta.registry_version;
  if (!name || !version) return;
  const entryType = sub.type === "mcp" ? "server" : "skill";
  const url = `${registryUrl()}/v1/entries/${entryType}/${encodeURIComponent(name)}/versions/${encodeURIComponent(version)}`;
  try {
    const res = await fetch(url, { method: "DELETE" });
    if (res.status === 204 || res.status === 404) {
      patchMeta(id, { registry_synced: "deleted", registry_sync_error: "" });
    } else {
      const txt = await res.text();
      patchMeta(id, { registry_synced: "delete-error", registry_sync_error: "HTTP " + res.status + " " + txt.slice(0, 300) });
      console.error("[registry] delete 失败", id, res.status, txt.slice(0, 200));
    }
  } catch (e) {
    patchMeta(id, { registry_synced: "delete-error", registry_sync_error: String((e && e.message) || e).slice(0, 300) });
    console.error("[registry] delete 异常", id, e && e.message);
  }
}

const app = express();

// —— MCP 镜像 tar 包上传（流式落盘 + 体积上限 + sha256 + 结构校验）——
// 注册在 express.json 之前，避免 body parser 把二进制缓冲进内存；直接以流方式写盘，
// 支持 GB 级镜像包而不撑爆内存。tar 经审批后由 deployMcp 直接 docker load 运行，
// 不强制推回内网 registry（与 ghcr 的外部源镜像同步是两条独立、互不影响路径）。
function sanitizeUploadName(name) {
  return String(name || "mcp-image.tar").replace(/[^a-zA-Z0-9._-]/g, "_").slice(-120) || "mcp-image.tar";
}

// 制品分区分目录：待审暂存区(staging/) 与 已发布区(published/)。
// 上传先落 staging，审批通过后再提升(promote)到 published；拒绝/删除时按当前所在区清理。
function randSuffix() {
  return crypto.randomBytes(4).toString("hex");
}
function stagingKey(prefix, filename) {
  const fn = String(filename || "artifact").replace(/[^a-zA-Z0-9._-]/g, "_").slice(-120) || "artifact";
  return `staging/${prefix}_${randSuffix()}_${fn}`;
}
// 将 staging 制品提升为 published（复制后删源），返回新 key；源不存在返回 null。
async function promoteArtifact(stagingK, group, version, filename) {
  const obj = await objStore.get(stagingK);
  if (!obj) return null;
  const pubKey = `published/${objStore.makeKey(group, version, String(filename || "artifact"))}`;
  await objStore.put(pubKey, obj.buffer);
  try { await objStore.del(stagingK); } catch (_) { /* 源清理失败不影响发布 */ }
  return pubKey;
}

// ---- P0-1 修复：网关信任门（TRUST_GATEWAY=1 时启用）----
// 生产网关模式下，除健康检查外所有请求必须携带 X-Gateway-Token（由前置网关注入，
// 强随机值），否则 403 —— 关闭「任何人直连 4000 伪造 x-actor-* 身份」的通道。
// 未开启（本地开发 TRUST_GATEWAY 未设）：不拦截，现有开发流完全不受影响。
// 回退：unset TRUST_GATEWAY 重启即恢复旧行为。
if (process.env.TRUST_GATEWAY === "1") {
  const GATEWAY_TOKEN = process.env.GATEWAY_TOKEN;
  if (!GATEWAY_TOKEN) {
    console.error("拒绝启动：TRUST_GATEWAY=1 必须显式设置 GATEWAY_TOKEN（强随机值，如 openssl rand -hex 32）。");
    process.exit(1);
  }
  app.use((req, res, next) => {
    if (req.path === "/health") return next();
    if (req.headers["x-gateway-token"] === GATEWAY_TOKEN) return next();
    return res.status(403).json({ error: "forbidden: gateway token required" });
  });
  console.log("[安全] 网关信任模式已开启：除 /health 外所有请求需携带 X-Gateway-Token");
}

app.post("/upload/tar", (req, res) => {
  const who = uploadAuthOk(req);
  if (!who) return res.status(401).json({ error: "upload/tar 需要登录身份（请经平台前端上传）" });
  if (!uploadAllowed(who)) return res.status(429).json({ error: "上传过于频繁，请稍后再试" });
  const filename = sanitizeUploadName(req.query.name);
  const key = stagingKey("mcp", filename);
  const fp = path.join(TAR_ROOT, key);
  fs.mkdirSync(path.dirname(fp), { recursive: true });
  const hash = crypto.createHash("sha256");
  let size = 0;
  let aborted = false;
  const ws = fs.createWriteStream(fp);
  const fail = (code, msg) => {
    if (aborted) return;
    aborted = true;
    try { ws.destroy(); } catch (_) {}
    fs.unlink(fp, () => {});
    if (!res.headersSent) res.status(code).json({ error: msg });
  };
  req.on("data", (chunk) => {
    if (aborted) return;
    size += chunk.length;
    if (size > MAX_TAR_UPLOAD_BYTES) {
      return fail(413, `镜像包体积超过上限 ${MAX_TAR_UPLOAD_MB}MB，请精简镜像或改用 ghcr 地址提交`);
    }
    hash.update(chunk);
    ws.write(chunk, (e) => { if (e) fail(500, "写盘失败: " + e.message); });
  });
  req.on("error", (e) => fail(400, "上传中断: " + e.message));
  ws.on("error", (e) => fail(500, "写盘失败: " + e.message));
  req.on("end", () => {
    if (aborted) return;
    ws.end(async () => {
      try {
        const fd = fs.openSync(fp, "r");
        const head = Buffer.alloc(262);
        const n = fs.readSync(fd, head, 0, 262, 0);
        fs.closeSync(fd);
        const isGzip = head[0] === 0x1f && head[1] === 0x8b;
        const isTar = n >= 262 && head.toString("ascii", 257, 262) === "ustar";
        if (!isGzip && !isTar) {
          return fail(400, "文件不是合法的 docker save 镜像包（需 .tar 或 .tar.gz）");
        }
        // 魔数通过还不够：源码压缩包也是合法 tar。docker save 产物在 tar 根目录
        // 必然包含 manifest.json（或 OCI 的 index.json）与 repositories。缺失即可判定
        // 不是镜像包，提前在上传阶段拦截，避免到部署时才报「缺少 image_ref」。
        // 解析失败（超大镜像等）则放行，交由审批后的 docker load 兜底校验。
        const tf = await tarListFile(fp);
        if (!tf.err) {
          const names = tf.stdout.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
          const looksLikeImage = names.some((nm) =>
            /^(manifest\.json|repositories|index\.json|oci-layout)$/.test(nm),
          );
          if (!looksLikeImage) {
            return fail(400, "文件不是合法的 docker save 镜像包（根目录缺少 manifest.json / repositories）。请使用 `docker save 镜像名:tag -o 文件.tar` 导出后上传，不要上传源码或普通压缩包。");
          }
        }
      } catch (e) {
        return fail(400, "校验失败: " + (e && e.message));
      }
      if (!res.headersSent) res.json({ key, sha256: hash.digest("hex"), size });
    });
  });
});

// TRUST_GATEWAY=1（生产网关模式）下禁用跨域：API 只接受同源/网关转发，
// 防止任意网页在浏览器端跨站调用；本地开发保持全开（Next 与 4000 跨端口）。
app.use(cors(process.env.TRUST_GATEWAY === "1" ? { origin: false } : {}));

// ---- MCP 反向代理：给终端用户的固定端口入口 ----
// 背景（本机实测）：ToolHive 给每个 MCP 分配的宿主端口会随容器重建漂移，且 ingress
// 容器只绑定 127.0.0.1，跨机不可达。试图直接暴露的两种做法都失败过：
//   · `--host 0.0.0.0` —— thv 代理进程启动后崩溃（14500 从未监听成功）
//   · `--proxy-port`   —— thv 代理短暂监听后退出（14501 监听后消失）
// 而 Docker ingress 映射始终可用（/health 稳定 200）。
// 故改由平台后端统一转发：对外只暴露后端自身端口（4000），对内动态发现 ingress 端口。
// ---- 兜底：thv 未自动创建 <workload>-ingress 时的自愈 ----
// 背景：thv 对「纯容器 image run」(尤其无 OCI provenance label 的镜像) 有时不会自动
// 建 squid ingress 容器 → getIngressPort 拿不到端口 → /mcp-proxy 全 502。
// 方案：探测到无 ingress 时，自动起一个 socat 反向代理容器（命名 <workload>-ingress，
// 复刻 thv ingress 结构：连 toolhive-external 提供 host publish + connect 到 workload
// 的 internal 网络以路由到主容器），把主容器 MCP 端口暴露到 host 固定端口。
async function findMcpMainContainer(workload) {
  try {
    const { stdout } = await execFileHidden(
      "docker", ["inspect", "--format", "{{json .}}", workload],
      { timeout: 12000, maxBuffer: MAX_BUFFER },
    );
    const info = JSON.parse(stdout);
    const nets = (info.NetworkSettings && info.NetworkSettings.Networks) || {};
    // 主容器所在网络通常是 toolhive-<workload>-internal
    const netName =
      Object.keys(nets).find((n) => n === `toolhive-${workload}-internal`) ||
      Object.keys(nets).find((n) => n.includes("-internal")) ||
      Object.keys(nets)[0];
    const ip = netName ? nets[netName].IPAddress : null;
    // MCP 监听端口。注意容器 env 里的 MCP_PORT / FASTMCP_PORT 是 thv 按 --target-port
    // 回写的"假设值"（写死 3000 时代它会跟着错），不是事实——-authoritative 是镜像自己的
    // EXPOSE（作者声明）。容器 Config.ExposedPorts 也会被 thv 追加污染，所以查镜像配置。
    let port = null;
    try {
      const imgRef = (info.Config && info.Config.Image) || workload;
      const imgOut = await execFileHidden("docker", ["inspect", "--format", "{{json .Config.ExposedPorts}}", imgRef], { timeout: 12000, maxBuffer: MAX_BUFFER });
      const imgExposed = JSON.parse(String(imgOut.stdout || "{}").trim() || "{}");
      const keys = Object.keys(imgExposed);
      if (keys.length) {
        // 多端口时优先平台约定的 3000，否则取第一个
        const hit = keys.find((k) => String(k).split("/")[0] === "3000") || keys[0];
        port = Number(String(hit).split("/")[0]) || null;
      }
    } catch (_) { /* 镜像配置读不到再走 env/端口映射回退 */ }
    if (!port) {
      const env = (info.Config && info.Config.Env) || [];
      const pv = env.find((e) => e.startsWith("MCP_PORT=")) ||
                  env.find((e) => e.startsWith("FASTMCP_PORT="));
      if (pv) port = Number(pv.split("=")[1]) || null;
    }
    if (!port) {
      const ex = (info.NetworkSettings && info.NetworkSettings.Ports) || {};
      port = Number(Object.keys(ex)[0] && Object.keys(ex)[0].split("/")[0]) || null;
    }
    return { ip, port, netName };
  } catch (_) {
    return null;
  }
}

// 基于 workload 名派生的稳定 host 端口（36000-36999）：同一名永远算出同一端口，
// 这是「固定端口」层的根基——ingress 重建后端口不变，meta.endpoint 不再漂移。
function stablePortFor(workload, offset = 0) {
  return 36000 + ((hashCode(workload) + offset) % 1000);
}

// 固定端口 ingress（幂等确保）：
//   1) 现有 ingress 端口 == 固定值且探测通过 → 直接复用（快路径）
//   2) 现有 ingress 可用但非固定端口（如 thv 的动态 squid）→ rebuild=false 时先用它；
//      rebuild=true（部署/自愈）时重建为固定端口 socat ingress
//   3) 坏 ingress（端口在但 502）或无 ingress → 重建；固定端口被占时线性后移重试
// 返回实际可用的 host 端口；彻底失败时回退现有动态端口（若有）。
// 同一 workload 的 ingress 重建任务表（单飞）：并发重建会互相 rm 掉对方刚建好的
// 容器，造成 ingress 反复抖动、接口拖死——同 workload 的重建必须共享一个任务
const ingressRebuildJobs = new Map();

async function ensureStableIngress(workload, meta = {}, { rebuild = true } = {}) {
  const fixed = Number(meta && meta.ingress_port) || stablePortFor(workload);
  const cur = await getIngressPort(workload);
  if (cur === String(fixed)) {
    if (await probeMcpEndpoint(`http://127.0.0.1:${fixed}/mcp`)) return fixed;
  } else if (cur && (await probeMcpEndpoint(`http://127.0.0.1:${cur}/mcp`))) {
    if (!rebuild) return Number(cur);
  }
  if (!rebuild) return null;
  let job = ingressRebuildJobs.get(workload);
  if (!job) {
    job = rebuildIngress(workload, cur).finally(() =>
      ingressRebuildJobs.delete(workload),
    );
    ingressRebuildJobs.set(workload, job);
  }
  return job;
}

async function rebuildIngress(workload, cur) {
  const ingressName = `${workload}-ingress`;
  const main = await findMcpMainContainer(workload);
  if (!main || !main.ip || !main.port) return cur ? Number(cur) : null;
  // 需要 external 网络作 host publish 通道
  let extNet = "toolhive-external";
  try {
    const { stdout } = await execFileHidden("docker", ["network", "ls", "--format", "{{.Name}}"], { timeout: 8000, maxBuffer: MAX_BUFFER });
    const all = stdout.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
    if (!all.includes(extNet)) {
      const fallback = all.find((n) => n.includes("external"));
      if (fallback) extNet = fallback;
      else return cur ? Number(cur) : null; // 无 external 网络，无法 host publish
    }
  } catch (_) { return cur ? Number(cur) : null; }
  for (let off = 0; off < 5; off++) {
    const hostPort = stablePortFor(workload, off * 37);
    // 清理同名旧容器（无论它是 thv 的动态 squid 还是坏死的 socat）——统一收敛到固定端口
    try { await execFileHidden("docker", ["rm", "-f", ingressName], { timeout: 15000, maxBuffer: MAX_BUFFER }); } catch (_) {}
    try {
      await execFileHidden(
        "docker", ["run", "-d", "--restart", "unless-stopped", "--name", ingressName, "--network", extNet,
          "-p", `127.0.0.1:${hostPort}:${hostPort}`, "alpine/socat",
          `TCP-LISTEN:${hostPort},fork,reuseaddr`, `TCP:${main.ip}:${main.port}`],
        { timeout: 60000, maxBuffer: MAX_BUFFER },
      );
      // 加入 internal 网络使 socat 能路由到主容器
      await execFileHidden("docker", ["network", "connect", main.netName, ingressName], { timeout: 15000, maxBuffer: MAX_BUFFER }).catch(() => {});
    } catch (_) { continue; }
    // 等 socat 就绪后探测确认（docker port 对已退出容器也显示映射，probe 才是真验证）
    await sleep(2000);
    const p = await getIngressPort(workload);
    if (String(p) === String(hostPort) && (await probeMcpEndpoint(`http://127.0.0.1:${hostPort}/mcp`))) {
      return hostPort;
    }
  }
  return cur ? Number(cur) : null;
}

function hashCode(str) {
  let h = 0;
  for (let i = 0; i < str.length; i++) {
    h = (Math.imul(31, h) + str.charCodeAt(i)) | 0;
  }
  return Math.abs(h);
}

// 探测+自愈+回写（「健康探测自愈」层核心）：固定端口 ingress 不可用则重建（端口不变），
// 并把真实端口/endpoint 回写 meta——保证 DB 里的 endpoint 始终等于实际在听的端口。
async function healMcpIngress(id) {
  const sub = db.prepare("SELECT * FROM submissions WHERE id=?").get(id);
  if (!sub || sub.type !== "mcp") return null;
  const meta = parseMeta(sub);
  if (meta.deploy_status !== "deployed") return null;
  const workload = meta.workload_name || workloadNameFor(id);
  const p = await ensureStableIngress(workload, meta);
  if (!p) return null;
  const endpoint = `http://127.0.0.1:${p}/mcp`;
  if (endpoint !== meta.endpoint || p !== Number(meta.ingress_port)) {
    patchMeta(id, { endpoint, ingress_port: p, deploy_error: "" });
  }
  return endpoint;
}

// 按 workload 名反查 submission id（proxy 转发失败时触发自愈用）
function subIdByWorkload(workload) {
  if (!workload) return null;
  const row = db
    .prepare("SELECT id FROM submissions WHERE type='mcp' AND meta LIKE ?")
    .get(`%"workload_name":"${workload}"%`);
  return row ? row.id : null;
}

// 用户复制到的 URL 因此永久有效，不随容器重建变化。
async function resolveMcpProxyTarget(name) {
  let workload = null;
  let meta = {};
  // 1) name 是 submission id —— 换算 workload 名；name 直接是 workload 名也算
  const sub = db
    .prepare("SELECT * FROM submissions WHERE id=? AND type='mcp'")
    .get(name);
  if (sub) {
    meta = parseMeta(sub);
    workload = meta.workload_name || workloadNameFor(sub.id);
  } else if (name && /^mcp-/.test(name)) {
    workload = name;
  }
  if (workload) {
    // 现有 ingress 端口（自愈任务会把它维持在固定端口上）
    const direct = await getIngressPort(workload);
    if (direct) return { host: "127.0.0.1", port: Number(direct), path: "/mcp", workload };
    // 无 ingress → 幂等重建固定端口 socat ingress
    const p = await ensureStableIngress(workload, meta);
    if (p) return { host: "127.0.0.1", port: p, path: "/mcp", workload };
  }
  // 2) name 是 item_ref（LIVE_MCPS 等）—— 经 thv list 按镜像别名动态发现
  const ep = await discoverThvEndpoint(name);
  if (ep) {
    try {
      const u = new URL(ep);
      return { host: u.hostname, port: Number(u.port) || 80, path: u.pathname };
    } catch (_) {
      /* 解析失败继续返回 null */
    }
  }
  return null;
}

// 注意：必须注册在 express.json() 之前，否则请求体已被消费，管道转发会拿到空 body。
app.use("/mcp-proxy/:name", (req, res) => mcpProxyHandler(req, res, {}));

// 代理处理器主体（4000 回环口与 4100 对外口共用）。
// opts.forceToken=true（对外口）：无条件校验 token——对外口上 token 是唯一凭证，
// mode=all 也不例外（回环口维持原语义：仅 restricted 校验）。
/**
 * MCP 代理处理器：token 门禁 → 解析目标实例 → 管道转发。
 * 安全语义（两个监听口共用此函数，差异仅由 opts.forceToken 表达）：
 *  - 回环 4000：restricted 条目要求 Bearer/X-MCP-Token/?t= 三来源之一命中 meta.mcp_token；
 *  - 对外 4100：forceToken=true，所有条目（含 mode=all）一律强制校验，token 是唯一门禁；
 *  - token 校验先于实例解析——无 token 的 restricted/对外请求在碰 Docker 之前就被 403。
 * @param {import("express").Request} req
 * @param {import("express").Response} res
 * @param {{forceToken?: boolean}} opts
 */
async function mcpProxyHandler(req, res, opts = {}) {
  if (req.method === "OPTIONS") return res.sendStatus(204);

  const name = req.params.name;
  const sid = subIdByWorkload(name) || (String(name).startsWith("sub_") ? name : null);
  let proxyMeta = null;
  if (sid) {
    const row = db.prepare("SELECT meta FROM submissions WHERE id=?").get(sid);
    if (row) {
      const meta = parseMeta(row);
      proxyMeta = meta;
      const v = meta.visibility;
      const needToken = opts.forceToken || (v && v.mode === "restricted");
      if (needToken) {
        // token 三来源（按优先级）：Authorization: Bearer / X-MCP-Token 头 / 旧 ?t=（兼容已复制配置）
        const auth = String(req.headers["authorization"] || "");
        const headerToken = auth.startsWith("Bearer ")
          ? auth.slice(7).trim()
          : String(req.headers["x-mcp-token"] || "").trim();
        let t = headerToken || null;
        if (!t) {
          try { t = new URL(req.url, "http://x").searchParams.get("t"); } catch (_) {}
        }
        if (!meta.mcp_token || t !== meta.mcp_token) {
          if (deniedThrottled("proxy:" + sid + ":" + (req.socket.remoteAddress || ""))) {
            audit(req, "proxy_denied", "mcp", sid, { workload: meta.workload_name || "", reason: opts.forceToken ? "external without valid token" : "restricted without valid token" }, "denied");
          }
          return res.status(403).json({ error: "forbidden: 该 MCP 仅限授权成员调用（缺少或错误的访问令牌）" });
        }
      }
    } else if (opts.forceToken) {
      // 对外口：查无条目（或非 submission 条目）无法验证凭证 → 一律拒绝
      return res.status(403).json({ error: "forbidden" });
    }
  } else if (opts.forceToken) {
    return res.status(403).json({ error: "forbidden" });
  }

  resolveMcpProxyTarget(req.params.name)
    .then((target) => {
      if (!target) {
        return res.status(502).json({
          error: "MCP 未运行或找不到 ingress 端口",
          name: req.params.name,
        });
      }
      const headers = { ...req.headers };
      delete headers.host;
      delete headers.connection;
      // 平台凭证代理：条目 env 里配了 API Key/Token 时，把调用方的平台凭证
      // （mcp_token）替换为应用自身的鉴权头再转发——调用方无需（也不应）知道应用凭证。
      const appAuth = authHeaderCandidates(proxyMeta || {})[0];
      if (appAuth) {
        delete headers.authorization;
        Object.assign(headers, appAuth);
      }

      const upstream = http.request(
        {
          host: target.host,
          port: target.port,
          path: req.url || target.path,
          method: req.method,
          headers,
        },
        (upRes) => {
          res.writeHead(upRes.statusCode || 502, upRes.headers);
          upRes.pipe(res);
        },
      );
      upstream.on("error", (e) => {
        if (!res.headersSent) {
          res.status(502).json({ error: "转发到 MCP 失败", detail: e.message });
        } else {
          res.end();
        }
        // 转发失败（端口漂移/ingress 坏死）→ 后台自愈：重建固定端口 ingress 并回写 meta。
        // 本次请求不重试（SSE/POST 非幂等），下一次请求即恢复。
        const sid = target && target.workload ? subIdByWorkload(target.workload) : null;
        if (sid) healMcpIngress(sid).catch(() => {});
      });
      req.pipe(upstream);
    })
    .catch((e) => {
      if (!res.headersSent) {
        res.status(500).json({ error: "代理异常", detail: e.message });
      }
    });
}

app.use(express.json());

// 制品存储：用户提交的 Skill 包上传后落入 ObjectStore（默认本地 fs，可切 MinIO）。
// 平台后端只持有 artifact_key + sha256 这把"钥匙"，字节本体在专用存储，满足"存放"语义。
// 存储根目录与 object-store 的 fs 后端保持一致（支持 OBJECT_STORE_FS_ROOT 覆盖），
// 确保 docker load 回查、静态服务、ObjectStore 三处指向同一物理目录。
const ARTIFACT_FS_ROOT = process.env.OBJECT_STORE_FS_ROOT
  ? path.resolve(process.env.OBJECT_STORE_FS_ROOT)
  : path.join(__dirname, "uploads");
fs.mkdirSync(ARTIFACT_FS_ROOT, { recursive: true });

// 静态路由收紧：公共只暴露"已发布区(published/)"，待审 staging/ 直链一律 403。
// staging 制品仅允许经可信代理（Next 服务端、已管理员鉴权）携带内部令牌回源，
// 杜绝待审制品被外部枚举 artifact_key 直链下载。
// 内部回源令牌：前端 Next 服务端代理下载 staging 制品时携带（x-internal-proxy header）。
// 它是「待审制品防直链枚举」的唯一防线——默认值是写死的弱口令，生产环境必须显式配置
// 强随机值（NODE_ENV=production 且未配置时直接拒启），否则等于没锁。
const INTERNAL_PROXY_TOKEN_SET = Boolean(process.env.INTERNAL_PROXY_TOKEN);
const INTERNAL_PROXY_TOKEN = process.env.INTERNAL_PROXY_TOKEN || "thv-internal-proxy";
if (process.env.NODE_ENV === "production" && !INTERNAL_PROXY_TOKEN_SET) {
  console.error("拒绝启动：生产环境必须显式设置 INTERNAL_PROXY_TOKEN（强随机值），否则 staging 制品可被任意下载。");
  process.exit(1);
}
if (!INTERNAL_PROXY_TOKEN_SET) {
  console.warn("[安全警告] INTERNAL_PROXY_TOKEN 未配置，使用弱默认值（仅限本地开发）。生产部署前必须显式配置。");
}
const artifactStatic = express.static(ARTIFACT_FS_ROOT);
app.use("/artifacts", (req, res, next) => {
  if (
    req.path.startsWith("/staging") &&
    req.headers["x-internal-proxy"] !== INTERNAL_PROXY_TOKEN
  ) {
    return res
      .status(403)
      .json({ error: "forbidden: staging artifacts require internal proxy" });
  }
  return artifactStatic(req, res, next);
});

// tar 落盘根目录：与 object-store 的 fs 后端保持一致，确保 docker load 时按同一路径回查。
const TAR_ROOT = ARTIFACT_FS_ROOT;



// 健康检查（供探针/网关使用）
app.get("/health", (_req, res) => res.json({ ok: true, ts: Date.now() }));

// API 索引
app.get("/", (_req, res) => res.json({
  service: "platform-backend",
  endpoints: [
    "POST /submissions", "GET /submissions", "POST /submissions/:id/approve", "POST /submissions/:id/deploy", "POST /submissions/:id/undeploy", "POST /submissions/:id/sync",
    "GET /groups/:group_key/versions",
    "POST /favorites", "DELETE /favorites", "GET /favorites", "GET /favorites/counts",
    "GET /skills", "GET /skills/:group_key/:version/download", "GET /skills/:id/download",
    "GET /mcp", "GET /mcp/:id", "POST /mcp/call", "GET /stats/top", "GET /stats/detail", "GET /stats/counts", "POST /metrics", "GET /health"
  ]
}));



// ---- Skill 路由：渐进式拆分第二步（2026-09-11）迁至 routes/skills.js ----
// 按原位置顺序装配；servePackageFile 为声明式函数（提升可用），经 ctx 注入。
// 注意：MCP_TREE_MAX 原声明在更靠后位置（const 无提升），已上移至此，否则 TDZ 崩溃。
// 文件树最多落库条数，防止超大包把 meta 撑爆
const MCP_TREE_MAX = 2000;
require("./routes/skills")(app, {
  ...CTX,
  canAccessSubmission,
  pickDisplayVersions,
  MCP_TREE_MAX,
  servePackageFile,
});

// 指标上报（下载/调用/收藏等事件）——/metrics 路由定义在下方 /metrics 处
// ---- MCP 路由：渐进式拆分第三步（2026-09-11）迁至 routes/mcp.js ----
// rtCache/toolsCache 两层 SWR 缓存与 6 条路由已迁出；部署事件经 invalidateMcpRuntimeCaches 钩子双清。
// servePackageFile 为 MCP/Skill 共享实现，留在本文件。
// 源码包单文件内容预览（「代码」标签页点文件查看）。
// 安全约束：路径必须存在于文件树中且通过 traversal 校验；敏感文件（.env/密钥/凭据类）拒绝读取；
// 仅返回文本内容（探测到二进制或超过 256KB 时拒绝），值不落盘、即取即回。
// 源码包单文件内容预览的共享实现（MCP 与 Skill 共用）。
// 安全约束：路径必须存在于文件树中且通过 traversal 校验；敏感文件（.env/密钥/凭据类）拒绝读取；
// 仅返回文本内容（探测到二进制或超过 256KB 时拒绝），值不落盘、即取即回。
async function servePackageFile(req, res, s) {
  const meta = parseMeta(s);
  // 注意：skill 提交没有 source_type 字段，这里只以 artifact_key 为准
  if (!meta.artifact_key) {
    return res.status(400).json({ error: "该记录没有源码包" });
  }
  const filePath = String(req.query.path || "");
  if (isPathTraversal(filePath)) {
    return res.status(400).json({ error: "非法路径" });
  }
  if (MCP_SENSITIVE_FILE_RE.test(filePath)) {
    return res.status(403).json({ error: "疑似敏感文件（.env/密钥/凭据类），不提供内容预览" });
  }
  const tree = meta.mcp_tree || meta.skill_tree || [];
  if (tree.length && !tree.includes(filePath)) {
    return res.status(404).json({ error: "文件不在源码包内" });
  }
  let obj;
  try { obj = await objStore.get(meta.artifact_key); } catch (_) {}
  if (!obj || !obj.buffer) return res.status(404).json({ error: "源码包不存在或已清理" });
  const pkg = await openSkillPackage(obj.buffer, String(meta.artifact_key).toLowerCase());
  if (pkg.error) return res.status(500).json({ error: "源码包解压失败" });
  try {
    const entry = pkg.entries.find(
      (e) => e === filePath || e.replace(/\\/g, "/") === filePath.replace(/\\/g, "/")
    );
    if (!entry) return res.status(404).json({ error: "文件不在源码包内" });
    const buf = await pkg.readEntry(entry);
    if (!buf) return res.status(404).json({ error: "文件内容为空或读取失败" });
    // 二进制探测：前 8KB 出现 NUL 字节视为二进制；文本上限 256KB
    const probe = buf.subarray(0, 8192);
    if (probe.includes(0)) {
      return res.status(415).json({ error: "二进制文件不支持预览" });
    }
    if (buf.length > 256 * 1024) {
      return res.status(413).json({ error: "文件过大（>256KB），不支持预览" });
    }
    res.json({ path: entry, content: buf.toString("utf8"), size: buf.length });
  } finally {
    if (pkg.cleanup) pkg.cleanup();
  }
}

const __mcpRuntime = require("./routes/mcp")(app, {
  ...CTX,
  canAccessSubmission, pickDisplayVersions, isOnShelf, LIVE_MCPS,
  discoverIngressForSubmission, probeMcpEndpoint, discoverThvEndpoint,
  resolveMcpProxyTarget, subIdByWorkload, healMcpIngress,
  mapMcpRow, publicEndpointFor, mcpAuthHeadersFor, getOrCreateMcpToken,
  authHeaderCandidates, mcpCallAuthed, rewriteForWsl2, resolveEndpoint,
  workloadNameFor, servePackageFile, execFileHidden, MAX_BUFFER,
});
// 部署/下线服务：extractMcpInspect 由 routes/mcp 提供（部署成功后的镜像元数据提取）
__deployService = require("./services/deploy")({
  ...CTX,
  discoverIngressForSubmission, probeMcpEndpoint, thvListJson, healMcpIngress,
  workloadNameFor, registryPublish, runTrivyScan,
  envInjectArgs, buildSourceImage, sleep, DOCKER_BIN,
  extractMcpInspect: __mcpRuntime.extractMcpInspect,
  invalidateMcpRuntimeCaches: __mcpRuntime.invalidate,
});


// ---- 收藏 / 统计 / 反馈(Issues) / 审计路由：渐进式拆分第一步（2026-09-11）迁至 routes/ ----
// 按原位置顺序装配，中间件链不变（位于 express.json 之后、rescan 之前）。
require("./routes/favorites")(app, CTX);
require("./routes/stats")(app, CTX);
require("./routes/issues")(app, CTX);
require("./routes/audit")(app, CTX);



app.post("/metrics", (req, res) => {
  const { item_type, item_ref, event, actor_id } = req.body || {};
  if (!item_type || !item_ref || !event)
    return res.status(400).json({ error: "item_type, item_ref, event 必填" });
  const id = "ev_" + Date.now() + "_" + Math.floor(Math.random() * 1000);
  db.prepare("INSERT INTO metric_events VALUES(?,?,?,?,?,?)")
    .run(id, item_type, item_ref, event, actor_id || "", new Date().toISOString());
  res.json({ ok: true });
});

// ---- 对外 MCP 代理监听（方案 B）：仅挂 /mcp-proxy，强制 Token，与管理 API 物理隔离 ----
// 该口上：1) x-actor-* 头一律剥离（外部身份不可伪造进审计）；2) token 无条件校验
// （mode=all 也不例外——对外口上 token 是唯一凭证）；3) 除 /mcp-proxy 外无任何路由。
// MCP_PROXY_PUBLIC_DISABLED=1 可整体关闭此监听。
if (process.env.MCP_PROXY_PUBLIC_DISABLED !== "1") {
  const proxyApp = express();
  proxyApp.disable("x-powered-by");
  proxyApp.use("/mcp-proxy/:name", (req, res, next) => {
    delete req.headers["x-actor-email"];
    delete req.headers["x-actor-groups"];
    delete req.headers["x-actor-admin"];
    next();
  });
  proxyApp.use("/mcp-proxy/:name", (req, res) =>
    mcpProxyHandler(req, res, { forceToken: true }),
  );
  proxyApp.listen(PROXY_PORT, PROXY_HOST, () =>
    console.log(
      `对外 MCP 代理已监听: ${PROXY_HOST}:${PROXY_PORT}（仅 /mcp-proxy，强制 Token 校验）`,
    ),
  );
}

// ---- Submissions 路由：渐进式拆分第四步（2026-09-11）迁至 routes/submissions.js ----
// 上传/提交/审批/部署/下线/同步/版本/状态/重扫/env 全域。此处为延迟装配（文件末尾）：
// 其依赖的常量（RATE_*/DUP_STATUSES/MCP_TREE_MAX/MCP_README_INSPECT_VERSION 等）声明靠后，
// const 无提升——延迟到所有常量初始化之后再装配，规避 TDZ。
require("./routes/submissions")(app, {
  ...CTX,
  canAccessSubmission, pickDisplayVersions, isOnShelf,
  stagingKey, sanitizeUploadName, normName, promoteArtifact,
  ensureGroupMeta, ensureRegistryMeta, registryDelete, registryPublish, listGroupVersions,
  classifyRegistry, INTERNAL_REGISTRY, INTERNAL_ONLY, TRUSTED_REGISTRIES,
  deniedThrottled, runSubmissionScans, deleteSubmissionSecrets, storeSubmissionEnv,
  deployMcp: __deployService.deployMcp, undeployMcp: __deployService.undeployMcp,
  RATE_WINDOW_MS, RATE_MAX, DUP_STATUSES, INTERNAL_PROXY_TOKEN,
  MCP_TREE_MAX, MAX_BUFFER,
});

// 显式绑 0.0.0.0：WSL2 下 localhost 常解析到 127.0.0.1，
// 若只绑默认的 IPv6 :: 会导致 curl localhost 连接被拒。
const server = app.listen(PORT, HOST, () =>
  console.log(
    `平台后端已启动: http://localhost:${PORT} (${HOST}:${PORT})`,
  ),
);
server.on("error", (err) => {
  console.error("监听失败（端口可能被占用或权限不足）:", err);
  process.exit(1);
});

// ---- 启动对账：卡在「扫描中」的提交重新排队 ----
// 扫描是 fire-and-forget：后端进程在扫描完成前重启/崩溃，异步任务连同超时定时器一起丢失，
// meta.trivy / meta.prompt_scan 会永远停在 scanning（2026-09-07 flowvision 首条提交即此情况）。
// 启动后统一检查，把卡在 scanning 的记录重新入队（runSubmissionScans 内部为全局串行队列）。
function requeueStuckScans() {
  let n = 0;
  const rows = db.prepare("SELECT id, type, meta FROM submissions").all();
  for (const r of rows) {
    let m;
    try { m = JSON.parse(r.meta || "{}"); } catch { continue; }
    const trivyStuck = m.trivy && m.trivy.status === "scanning";
    const promptStuck = m.prompt_scan && m.prompt_scan.status === "scanning";
    if (trivyStuck || promptStuck) {
      runSubmissionScans(r.id, r.type);
      n++;
    }
  }
  if (n) console.log(`[scan] 启动对账：${n} 条提交卡在扫描中，已重新排队`);
}
requeueStuckScans();

// ---- 后台自愈（「健康探测自愈」层）：每 60s 巡检所有 deployed MCP 的固定端口 ingress ----
// 探测失败 → 重建 socat ingress（端口不变，hash 派生）→ 回写 meta.endpoint。
// 这样即使无人访问列表页/代理（以前只有被动触发），坏 ingress 也会在 1 分钟内被修好。
// 单飞锁防重入；巡检逐条串行，避免并发打爆 docker。
let healing = false;

async function selfHealIngresses() {
  if (healing) return;
  healing = true;
  try {
    await reconcileMcpWorkloads().catch((e) => console.error("[workload 对账] 异常:", e.message));
    const now = Date.now();
    const rows = db.prepare("SELECT id FROM submissions WHERE type='mcp'").all();
    for (const r of rows) {
      const st = healFailState.get(r.id);
      if (st && st.fails >= 3 && now < st.nextTryAt) continue; // 退避中
      try {
        const p = await healMcpIngress(r.id);
        if (p) healFailState.delete(r.id);
        else {
          const fails = ((healFailState.get(r.id) || {}).fails || 0) + 1;
          healFailState.set(r.id, { fails, nextTryAt: now + (fails >= 3 ? HEAL_BACKOFF_MS : 0) });
        }
      } catch (_) { /* 单条失败不影响其余 */ }
    }
  } finally {
    healing = false;
  }
}
setInterval(() => { selfHealIngresses().catch(() => {}); }, 60 * 1000).unref();

// ---- 数据库日常维护：每日备份 + 埋点表清理 ----
// 备份：VACUUM INTO 生成一致性快照（在线安全，不动 WAL），保留最近 14 份。
// SQLite 单文件无备份 = 磁盘损坏/误操作即全站数据丢失，这是上线底线配置。
const BACKUP_DIR = path.join(__dirname, "backups");
const BACKUP_KEEP = 14;
function backupDatabase() {
  try {
    fs.mkdirSync(BACKUP_DIR, { recursive: true });
    const stamp = new Date().toISOString().slice(0, 10);
    const dest = path.join(BACKUP_DIR, `platform-${stamp}.db`);
    if (fs.existsSync(dest)) return; // 同一天已有备份，不覆盖
    db.prepare("VACUUM INTO ?").run(dest);
    // 只保留最近 N 份
    const files = fs.readdirSync(BACKUP_DIR)
      .filter((f) => /^platform-\d{4}-\d{2}-\d{2}\.db$/.test(f))
      .sort();
    while (files.length > BACKUP_KEEP) {
      try { fs.unlinkSync(path.join(BACKUP_DIR, files.shift())); } catch (_) { break; }
    }
    console.log("[维护] 数据库备份完成:", dest);
  } catch (e) {
    console.error("[维护] 数据库备份失败:", e.message);
  }
}
// metric_events 是无限增长的埋点表（只有 INSERT 没有清理），且列表页/stats 会全表聚合——
// 不清理必然拖慢查询。保留 90 天，ISO 字符串可直接字典序比较。
function pruneMetricEvents() {
  try {
    const cutoff = new Date(Date.now() - 90 * 24 * 3600 * 1000).toISOString();
    const info = db.prepare("DELETE FROM metric_events WHERE occurred_at < ?").run(cutoff);
    if (info.changes > 0) console.log(`[维护] metric_events 清理 ${info.changes} 条（>90 天）`);
  } catch (e) {
    console.error("[维护] metric_events 清理失败:", e.message);
  }
}
function runDailyMaintenance() { backupDatabase(); pruneMetricEvents(); }
runDailyMaintenance(); // 启动时先跑一次（当天已有备份则跳过）
setInterval(runDailyMaintenance, 24 * 3600 * 1000).unref();

// ---- 启动恢复：进程被杀可能留下永久卡死的 deploy_status='deploying'（部署轮询随进程一起死）----
// 重启后按事实对齐：workload 真在跑 → 收敛为 deployed（含固定端口 ingress/endpoint 回写）；
// workload 不在 → 标记 failed，让管理员用「重新部署」按钮重试（deployMcp 本身幂等可重入）。
(async () => {
  try {
    const stale = db
      .prepare("SELECT id FROM submissions WHERE type='mcp'")
      .all()
      .filter((r) => parseMeta(db.prepare("SELECT meta FROM submissions WHERE id=?").get(r.id)).deploy_status === "deploying");
    if (!stale.length) return;
    const list = await thvListJson().catch(() => []);
    for (const r of stale) {
      const meta = parseMeta(db.prepare("SELECT meta FROM submissions WHERE id=?").get(r.id));
      const workload = meta.workload_name || workloadNameFor(r.id);
      const entry = list.find((x) => x.name === workload);
      if (entry && entry.status === "running") {
        await healMcpIngress(r.id).catch(() => {});
        const now = parseMeta(db.prepare("SELECT meta FROM submissions WHERE id=?").get(r.id));
        if (now.deploy_status === "deploying") {
          // 容器在跑但 ingress 收敛失败：至少把状态从 deploying 里解放出来
          patchMeta(r.id, { deploy_status: "deployed", deploy_error: "" });
        }
      } else {
        patchMeta(r.id, { deploy_status: "failed", deploy_error: "服务重启中断部署，workload 不在运行。请点击「重新部署」重试。" });
      }
      console.log("[启动恢复] 处理卡死的部署:", r.id);
    }
  } catch (e) {
    console.error("[启动恢复] 失败:", e.message);
  }
})();

// 优雅退出：先关监听、再关 db，让 SQLite 正常 checkpoint WAL，
// 避免被 pkill/SIGTERM 强杀时留下"热 WAL"导致下次启动挂起（D 态）。
function shutdown(signal) {
  console.log(`收到 ${signal}，正在优雅关闭...`);
  server.close(() => {
    try { db.close(); } catch (_) {}
    process.exit(0);
  });
  // 兜底：5s 内未关完则强退
  setTimeout(() => process.exit(1), 5000).unref();
}
process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
