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
async function loadTarImage(key) {
  const fp = path.join(TAR_ROOT, key);
  if (!fs.existsSync(fp)) throw new Error("tar 文件不存在: " + key);
  const out = await execFileHidden(DOCKER_BIN, ["load", "-i", fp], { timeout: 600000, maxBuffer: MAX_BUFFER });
  const txt = (out.stdout || "") + (out.stderr || "");
  const m1 = txt.match(/Loaded image:\s*([^\r\n]+)/i);
  if (m1 && m1[1].trim()) return m1[1].trim();
  const m2 = txt.match(/Loaded image ID:\s*([^\r\n]+)/i);
  if (m2 && m2[1].trim()) {
    const id = m2[1].trim();
    const tag = "mcp-tar/" + key.replace(/[^a-zA-Z0-9._-]/g, "-") + ":loaded";
    await execFileHidden(DOCKER_BIN, ["tag", id, tag], { timeout: 60000, maxBuffer: MAX_BUFFER });
    return tag;
  }
  return null;
}

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
  deployMcp: (...a) => deployMcp(...a),
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
function actorFromReq(req) {
  const email = String(req.headers["x-actor-email"] || "").toLowerCase().trim();
  const groups = String(req.headers["x-actor-groups"] || "")
    .split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);
  const admin = String(req.headers["x-actor-admin"] || "") === "1";
  return { email, groups, admin };
}
// visibility 缺省视为全员可见（兼容历史数据与未配置条目）
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
// 条目是否已「上线」：仅当管理员显式配置过可见范围后，才对非管理员开放可见/下载/调用。
// 存量条目无 visibility_configured 字段 → 视为已上线（向后兼容，不强制重配）；
// 新提交默认 visibility_configured=false → 未上线，仅管理员在「已发布管理」可见，待配可见范围。
function isOnShelf(meta) {
  return !(meta && meta.visibility_configured === false);
}
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
async function deployMcp(id) {
  toolsCache?.delete(id); // 部署会变更实例与 tools 清单，主动失效 SWR 缓存
  rtCache?.delete(id); // 同步失效实例运行时缓存（端点/健康状态）
  const sub = db.prepare("SELECT * FROM submissions WHERE id=?").get(id);
  if (!sub || sub.type !== "mcp") return;
  const meta = parseMeta(sub);
  // 源码包提交：先平台侧构建本地镜像（building 状态），构建产物走与镜像包一致的部署链
  let sourceBuiltImage = null;
  if (meta.source_type === "source") {
    if (!meta.built_image) {
      patchMeta(id, { deploy_status: "building", deploy_error: "" });
      try {
        sourceBuiltImage = await buildSourceImage(sub);
      } catch (e) {
        // 保留消息尾部：docker/pip 的真实报错在构建日志末尾，头部只是无害进度
        patchMeta(id, {
          deploy_status: "failed",
          deploy_error: "源码构建失败: " + String((e && e.message) || e).slice(-700),
        });
        return;
      }
    } else {
      sourceBuiltImage = meta.built_image;
    }
  }
  // 优先用已同步进内网的 internal_ref，确保运行时从内网拉取、不走外网；
  // 未同步（未勾选或同步失败）时回退原 image_ref，保证业务可用。
  // recovery_image：workload 对账恢复时从孤儿容器捕获的、本地实际存在的镜像（最高优先），
  // 避免 thv 状态丢失后的重部署因外网 ref 不可达而失败。
  let image = sourceBuiltImage || meta.recovery_image || meta.internal_ref || meta.image_ref;
  // tar 提交但此前未成功解析出镜像名（如审批时 docker load 失败/未完成）：
  // 重新尝试 docker load，让「重新部署」按钮对 tar 类提交真正重试。
  if (!image && meta.source_type === "tar" && meta.artifact_key) {
    try {
      const loaded = await loadTarImage(meta.artifact_key);
      if (loaded) {
        patchMeta(id, { image_ref: loaded, deploy_status: "loaded", mirror_status: "skipped:tar" });
        image = loaded;
      } else {
        patchMeta(id, {
          deploy_status: "failed",
          deploy_error: "该 tar 不是合法的 docker save 镜像包（docker load 未解析出镜像名）。请重新提交 `docker save 镜像名:tag -o 文件.tar` 导出的镜像，或改用 ghcr.io 镜像地址。",
        });
        return;
      }
    } catch (e) {
      const msg = (e.stderr || e.stdout || e.message || "").toString().slice(0, 600);
      patchMeta(id, {
        deploy_status: "failed",
        deploy_error: "镜像 tar 加载失败：" + msg + "（请确认上传的是 docker save 导出的合法镜像包，而非源码压缩包）",
      });
      return;
    }
  }
  if (!image) {
    patchMeta(id, {
      deploy_status: "failed",
      deploy_error: "该提交没有可部署的镜像：请重新提交并填写 ghcr.io 镜像地址（image_ref），或上传 `docker save` 导出的合法镜像 tar 包。",
    });
    return;
  }
  // 可观测：记录本次部署实际用的镜像与是否命中内网源
  patchMeta(id, { deployed_image: image, deployed_from_internal: Boolean(meta.internal_ref) });
  const workload = meta.workload_name || workloadNameFor(id);
  patchMeta(id, { deploy_status: "deploying", workload_name: workload, deploy_error: "" });
  try {
    // 幂等：先清理同名 workload（避免重部署时 "already exists" 冲突），
    // 不存在或已删时 thv rm 会报错，由 try/catch 吞掉即可。
    try {
      await execFileHidden(THV_BIN, ["rm", workload], { timeout: 30000, maxBuffer: MAX_BUFFER });
    } catch (_) { /* 不存在，忽略 */ }
    const args = ["run", "--name", workload, image];
    // 源码构建的 MCP：自起 HTTP 服务，必须显式 sse 代理模式，否则 thv 按 stdio
    // 包裹会出现 "upstream connect failed"。目标端口不写死 3000——自带 Dockerfile
    // 的工程监听端口由作者决定（曾见 8765，写死 3000 会让代理 502）：
    // 优先读镜像 EXPOSE，EXPOSE 3000 或读不到时回退约定值 3000。
    if (meta.source_type === "source") {
      let targetPort = 3000;
      try {
        const insp = await execFileHidden("docker", ["inspect", "--format", "{{json .Config.ExposedPorts}}", image], { timeout: 15000, maxBuffer: MAX_BUFFER });
        const exposed = JSON.parse(String(insp.stdout || "{}").trim() || "{}");
        const keys = Object.keys(exposed);
        if (keys.length) {
          const hit = keys.find((k) => String(k).split("/")[0] === "3000") || keys[0];
          targetPort = parseInt(String(hit).split("/")[0], 10) || 3000;
        }
      } catch (_) { /* 读不到 EXPOSE 就用约定 3000 */ }
      args.push("--proxy-mode", "sse", "--target-port", String(targetPort));
    } else if (meta.transport === "sse") {
      args.push("--proxy-mode", "sse");
    }
    // .env 私密配置注入：secret 引用形态（值由 ToolHive 启动容器时向加密凭据库请求）
    args.push(...envInjectArgs(meta));
    await execFileHidden(THV_BIN, args, { timeout: 180000, maxBuffer: MAX_BUFFER });
  } catch (e) {
    const msg = (e.stderr || e.stdout || e.message || "").toString().slice(0, 600);
    patchMeta(id, { deploy_status: "failed", deploy_error: msg });
    return;
  }
  // 轮询端点（最多 ~10 分钟）。thv runtime 启容器 + health check + 端口 ready
  // 在大镜像/冷启动时可能数分钟，原 60×3s=180s 太短会让 deploying 误判 failed。
  let endpoint = null;
  let lastStatus = "";
  for (let i = 0; i < 200; i++) {
    const list = await thvListJson();
    const entry = list.find((x) => x.name === workload);
    if (entry) {
      lastStatus = entry.status;
      if (entry.url) {
        // thv 报告 url 只代表代理端口已监听，不代表上游容器服务就绪（端口指错时代理会
        // 持续 502，曾把 502 的部署误判成 deployed）。加一次 HTTP 探活：
        // 502/503 视为未就绪继续等；其余任何响应（含 4xx，如 MCP 的 406）都算上游可达。
        try {
          const probe = await fetch(entry.url, { signal: AbortSignal.timeout(3000) });
          if (probe.status !== 502 && probe.status !== 503) { endpoint = entry.url; break; }
        } catch (_) { /* 探测异常（超时/拒连）说明上游未就绪，继续轮询而非误判 deployed */ }
      }
    }
    await sleep(3000);
  }
  if (endpoint) {
    patchMeta(id, { deploy_status: "deployed", endpoint, deploy_error: "" });
    // 提取镜像元数据（脱敏后）供详情页「代码」标签展示；失败不影响部署结果
    extractMcpInspect(image).then((insp) => {
      if (insp) patchMeta(id, { mcp_inspect: insp });
    }).catch(() => {});
    // 源码构建的镜像：部署成功后补一次 Trivy 扫描（本地镜像直扫，结果入 meta.trivy 供审计）
    if (meta.source_type === "source" || !meta.artifact_key) {
      runTrivyScan(id);
    }
    // 主容器跟随 Docker 守护进程自动拉起：thv run 无 restart 选项，宿主机/Docker
    // 重启后主容器会全部停止（巡检只能修 ingress 修不了主容器）——部署成功即
    // 对主容器设置 unless-stopped 策略，重启后自动恢复。
    try {
      const { stdout: names } = await execFileHidden("docker", ["ps", "--filter", `name=${workload}`, "--format", "{{.Names}}"], { timeout: 8000, maxBuffer: MAX_BUFFER });
      for (const cname of names.split(/\r?\n/).map((x) => x.trim()).filter(Boolean)) {
        await execFileHidden("docker", ["update", "--restart", "unless-stopped", cname], { timeout: 8000, maxBuffer: MAX_BUFFER }).catch(() => {});
      }
    } catch (_) { /* 策略设置失败不影响部署结果 */ }
    // 统一收敛到平台固定端口 ingress：thv 报告的端点端口随重建漂移，弃作长期地址；
    // healMcpIngress 建/验固定端口 socat ingress 并把稳定 endpoint 回写 meta
    // （用户侧 URL 走 /mcp-proxy 反代收敛，本就不依赖这个端口——它是详情页/诊断用的真值）。
    try { await healMcpIngress(id); } catch (_) { /* 失败则保留 thv endpoint 兜底 */ }
    // 部署成功拿到 endpoint → 同步发布到 Registry Server（使目录可消费）
    registryPublish(id).catch((e) => console.error("同步 Registry 失败:", e));
  } else {
    patchMeta(id, {
      deploy_status: "failed",
      deploy_error: "部署后未获取到端点，最后状态: " + lastStatus,
    });
  }
}

// 下线一个 MCP：thv rm 删除容器，清掉 endpoint
async function undeployMcp(id) {
  toolsCache?.delete(id); // 停止实例后 tools 清单失效，主动失效 SWR 缓存
  rtCache?.delete(id); // 同步失效实例运行时缓存（端点/健康状态）
  const sub = db.prepare("SELECT * FROM submissions WHERE id=?").get(id);
  if (!sub || sub.type !== "mcp") return;
  const meta = parseMeta(sub);
  const workload = meta.workload_name || workloadNameFor(id);
  try {
    await execFileHidden(THV_BIN, ["rm", workload], { timeout: 30000, maxBuffer: MAX_BUFFER });
  } catch (_) { /* 不存在或已删，忽略 */ }
  patchMeta(id, { deploy_status: "undeployed", endpoint: "", deploy_error: "" });
  // 注：下线只停容器 + 清运行态，Registry 目录条目保留（按设计：仅「删除」才从 Registry 摘除）。
}

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
// 避免对外分发的地址是 127.0.0.1（跨机不可达）。启动时探测一次，开销可忽略。
const LAN_IP = (() => {
  if (IS_WSL) return null; // WSL 内探测到的必是 NAT 地址，禁用
  try {
    const nets = os.networkInterfaces();
    for (const [ifName, list] of Object.entries(nets)) {
      // 排除虚拟交换机网卡（WSL/Hyper-V/Docker）——其地址对局域网不可达，
      // 否则会像 172.20.155.243 那样生成"看起来像样但谁都连不上"的调用 URL
      if (/vethernet|wsl|hyper-v|docker|loopback/i.test(ifName)) continue;
      for (const n of list || []) {
        if (n.family === "IPv4" && !n.internal && n.address) return n.address;
      }
    }
  } catch (_) {
    /* 取不到就用回环兜底 */
  }
  return null;
})();

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
  if (LAN_IP) return `http://${LAN_IP}:${PORT}`;
  return `http://localhost:${PORT}`;
}
// 启动时告警一次：回退 localhost 意味着跨机器不可达，提醒部署者显式声明基址
if (!process.env.PUBLIC_BASE && !LAN_IP) {
  console.warn(
    "[publicBase] 未设置 PUBLIC_BASE 且未探测到真实内网 IP：对外地址回退 localhost（仅本机可用）。跨机器访问请设置 PUBLIC_BASE，如 http://<Windows局域网IP>:4000",
  );
}

// 终端用户访问某个 MCP 的固定入口：走平台后端的反向代理（端口即后端自身端口）。
// 这样复制给用户的 URL 不随容器重建漂移，也绕开 ingress 只绑 127.0.0.1 的限制。
function mcpProxyUrl(name, req) {
  return `${publicBase(req)}/mcp-proxy/${encodeURIComponent(name)}/mcp`;
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
app.use("/mcp-proxy/:name", (req, res) => {
  if (req.method === "OPTIONS") return res.sendStatus(204);

  // P0-1 修复：restricted 可见性的 MCP 必须携带正确 mcp_token（URL ?t=），
  // 否则 403 —— 堵住「任何能访问 4000 的人绕过 visibility 直接调用」的洞。
  // mode=all（含内置 LIVE_MCPS）放行，现有用户复制的配置完全不受影响。
  const name = req.params.name;
  const sid = subIdByWorkload(name) || (String(name).startsWith("sub_") ? name : null);
  let proxyMeta = null;
  if (sid) {
    const row = db.prepare("SELECT meta FROM submissions WHERE id=?").get(sid);
    if (row) {
      const meta = parseMeta(row);
      proxyMeta = meta;
      const v = meta.visibility;
      if (v && v.mode === "restricted") {
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
            audit(req, "proxy_denied", "mcp", sid, { workload: meta.workload_name || "", reason: "restricted without valid token" }, "denied");
          }
          return res.status(403).json({ error: "forbidden: 该 MCP 仅限授权成员调用（缺少或错误的访问令牌）" });
        }
      }
    }
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
});

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

// 接收原始二进制（Skill 包 .tar.gz），落入 ObjectStore，返回内部 key + sha256。
// 制品来源 = 提交者本人，平台存盘后生成 artifact_key 交回前端，提交时写入 meta。
// ---- P0-2 修复：上传防滥用（身份 + 限流 + 体积上限）----
// 两个上传口（/upload、/upload/tar）共用：
//   · 身份：二选一 —— 带内部令牌（前端 Next 服务端转发）或带用户身份 header（网关注入）
//   · 限流：每身份每小时 UPLOAD_RATE_MAX 次（复用提交防刷的窗口）
//   · 体积：UPLOAD_MAX_MB（默认 50MB，真实制品远小于此，100MB 是被滥用空间）
const UPLOAD_MAX_MB = Number(process.env.UPLOAD_MAX_MB || 50);
const UPLOAD_RATE_MAX = Number(process.env.UPLOAD_RATE_MAX || 10);
const uploadRateMap = new Map(); // actor -> [windowStart, count]
function uploadAllowed(actor) {
  const now = Date.now();
  const entry = uploadRateMap.get(actor);
  if (!entry || now - entry[0] > RATE_WINDOW_MS) {
    uploadRateMap.set(actor, [now, 1]);
    // 顺手清理过期项，防 Map 无限膨胀
    if (uploadRateMap.size > 10000) {
      for (const [k, v] of uploadRateMap) {
        if (now - v[0] > RATE_WINDOW_MS) uploadRateMap.delete(k);
      }
    }
    return true;
  }
  entry[1]++;
  return entry[1] <= UPLOAD_RATE_MAX;
}
// 鉴权：内部令牌（Next 服务端转发）或用户身份（网关注入的 x-actor-email）满足其一
function uploadAuthOk(req) {
  if (req.headers["x-internal-proxy"] === INTERNAL_PROXY_TOKEN) return "internal";
  const actor = actorFromReq(req);
  if (actor.email) return actor.email;
  return null;
}

app.post("/upload", express.raw({ type: "*/*", limit: `${UPLOAD_MAX_MB}mb` }), async (req, res) => {
  try {
    const who = uploadAuthOk(req);
    if (!who) {
      if (deniedThrottled("upload:" + (req.socket.remoteAddress || ""))) {
        audit(req, "upload_denied", "skill", "", { reason: "unauthenticated" }, "denied");
      }
      return res.status(401).json({ error: "upload 需要登录身份（请经平台前端上传）" });
    }
    if (!uploadAllowed(who)) return res.status(429).json({ error: "上传过于频繁，请稍后再试" });
    if (!Buffer.isBuffer(req.body) || req.body.length === 0)
      return res.status(400).json({ error: "空文件" });
    const filename = req.query.name || "artifact_" + Date.now() + ".tar.gz";
    const key = stagingKey("skill", filename);
    const info = await objStore.put(key, req.body);
    res.json({ key: info.key, sha256: info.sha256, size: info.size });
  } catch (e) {
    res.status(500).json({ error: String((e && e.message) || e) });
  }
});

// 源码包上传（zip/tar.gz，MCP 自动构建用）。上限 20MB；与镜像包同等身份门。
app.post("/upload/source", express.raw({ type: "*/*", limit: "20mb" }), (req, res) => {
  try {
    const who = uploadAuthOk(req);
    if (!who) {
      if (deniedThrottled("upload:" + (req.socket.remoteAddress || ""))) {
        audit(req, "upload_denied", "mcp", "", { reason: "unauthenticated" }, "denied");
      }
      return res.status(401).json({ error: "upload/source 需要登录身份（请经平台前端上传）" });
    }
    if (!uploadAllowed(who)) return res.status(429).json({ error: "上传过于频繁，请稍后再试" });
    if (!Buffer.isBuffer(req.body) || req.body.length === 0)
      return res.status(400).json({ error: "空文件" });
    const filename = sanitizeUploadName(req.query.name || "source.zip");
    if (!/\.(zip|tar\.gz|tgz)$/i.test(filename))
      return res.status(400).json({ error: "源码包仅支持 .zip / .tar.gz / .tgz" });
    const key = stagingKey("src", filename);
    objStore.put(key, req.body);
    audit(req, "upload", "mcp-source", "", { filename, size: req.body.length });
    res.json({ key, size: req.body.length });
  } catch (e) {
    res.status(500).json({ error: String((e && e.message) || e) });
  }
});

// 提交 MCP 源码包（自动构建）：与普通提交同一入口，meta.source_type="source" 时
// 部署阶段先 buildSourceImage 构建本地镜像再 thv run。
app.post("/submissions/source", express.raw({ type: "*/*", limit: "20mb" }), async (req, res) => {
  try {
    const who = uploadAuthOk(req);
    if (!who) return res.status(401).json({ error: "需要登录身份（请经平台前端提交）" });
    if (!uploadAllowed(who)) return res.status(429).json({ error: "提交过于频繁，请稍后再试" });
    if (!Buffer.isBuffer(req.body) || req.body.length === 0)
      return res.status(400).json({ error: "空文件" });
    const filename = sanitizeUploadName(req.query.name || "source.zip");
    if (!/\.(zip|tar\.gz|tgz)$/i.test(filename))
      return res.status(400).json({ error: "源码包仅支持 .zip / .tar.gz / .tgz" });
    const key = stagingKey("src", filename);
    objStore.put(key, req.body);

    // 提交者身份优先取真实邮箱（内部令牌通道 who=="internal" 时 fromReq 仍有 x-actor-email）
    const actor = actorFromReq(req);
    const user_id = String(actor.email || who || "anonymous");
    const name = String(req.query.display_name || filename.replace(/\.(zip|tar\.gz|tgz)$/i, "")).slice(0, 80);
    const version = String(req.query.version || "1.0.0");
    const id = "sub_" + Date.now();
    const meta = {
      name,
      version,
      source_type: "source",
      artifact_key: key,
      artifact_filename: filename,
      visibility: { mode: "restricted", users: [], groups: [] },
      visibility_configured: false,
    };
    const metaJson = JSON.stringify(meta);
    db.prepare(`INSERT INTO submissions VALUES(?,?,?,?,?,?,?,?)`)
      .run(id, user_id, "mcp", filename, "pending", "pending", new Date().toISOString(), metaJson);
    ensureGroupMeta({ id, payload_ref: filename, meta: metaJson });
    runSubmissionScans(id, "mcp");
    audit(req, "submit", "mcp-source", id, { filename, size: req.body.length });
    res.json({ id, status: "pending" });
  } catch (e) {
    res.status(500).json({ error: String((e && e.message) || e) });
  }
});

// .env 私密配置上传（值入 ToolHive 加密凭据库，平台只存键名与引用）。
// Content-Type: text/plain，body 即 .env 原文。仅提交者本人或管理员。
app.post("/submissions/:id/env", express.raw({ type: "*/*", limit: "256kb" }), (req, res) => {
  const sub = db.prepare("SELECT * FROM submissions WHERE id=?").get(req.params.id);
  if (!sub) return res.status(404).json({ error: "submission 不存在" });
  storeSubmissionEnv(req, res, sub);
});

// .env 键名清单查询（仅提交者本人或管理员；只返回键名，绝不返回值）
app.get("/submissions/:id/env", (req, res) => {
  const actor = actorFromReq(req);
  const sub = db.prepare("SELECT * FROM submissions WHERE id=?").get(req.params.id);
  if (!sub) return res.status(404).json({ error: "submission 不存在" });
  const isOwner = actor.email && String(sub.user_id || "").toLowerCase() === actor.email.toLowerCase();
  if (!actor.admin && !isOwner) return res.status(403).json({ error: "仅提交者本人或管理员可查看" });
  const meta = parseMeta(sub);
  res.json({
    id: sub.id,
    keys: meta.env_keys || [],
    updated_at: meta.env_updated_at || null,
    has_env: Boolean(meta.env_refs && Object.keys(meta.env_refs).length),
  });
});

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

// 提交（落暂存，status=pending）。meta 可选，存放 name/description/download_url 等扩展字段。
app.post("/submissions", async (req, res) => {
  const { user_id, type, payload_ref, meta } = req.body || {};
  if (!user_id || !type || !payload_ref)
    return res.status(400).json({ error: "user_id, type, payload_ref 必填" });

  // 1) 限流：同用户窗口内提交数超限 → 429
  const since = new Date(Date.now() - RATE_WINDOW_MS).toISOString();
  const recent = db.prepare(
    "SELECT COUNT(*) c FROM submissions WHERE user_id=? AND created_at >= ?"
  ).get(user_id, since).c;
  if (recent >= RATE_MAX) {
    return res.status(429).json({
      error: "提交过于频繁，请稍后再试",
      retry_after_sec: Math.ceil(RATE_WINDOW_MS / 1000),
    });
  }

  // 2) 同用户去重：pending/approved 状态内，同 type +（同名 或 同 payload_ref）即视为重复
  // 注意：express.json 已把 meta 解析成对象，勿再 JSON.parse；可能是字符串（老调用方）则解析
  const rawMeta = req.body.meta;
  const m = rawMeta && typeof rawMeta !== "string"
    ? rawMeta
    : (typeof rawMeta === "string" ? (() => { try { return JSON.parse(rawMeta); } catch (_) { return {}; } })() : {});
  // 2.5) MCP 来源分级校验：
  //  - source_type=tar：用户上传的镜像包，受控可信，审批后部署（不强制推内网）
  //  - image_ref：命中档1 内网直通 / 档2 受信白名单留痕 / 档3 未知来源拦截
  if (type === "mcp") {
    if (m.source_type === "tar") {
      if (!m.artifact_key) {
        return res.status(400).json({ error: "tar 方式提交缺少 artifact_key（上传未成功）" });
      }
      m.registry_tier = 0; // 0 = 用户上传镜像包（受控可信源）
      m.source_registry = "user-upload";
      m.auto_mirror = false; // tar 不走内网镜像统一出口
    } else if (m.image_ref) {
      const cls = classifyRegistry(m.image_ref);
      if (!cls.allowed) {
        return res.status(400).json({
          error: "镜像来源未通过校验：" + cls.message,
          registry_tier: cls.tier,
          registry: cls.registry,
        });
      }
      // 留痕：记录来源分级与原始 registry，供审批与审计追溯
      m.registry_tier = cls.tier;
      m.source_registry = cls.registry;
      m.auto_mirror = m.auto_mirror === true || m.auto_mirror === "true" || m.auto_mirror === "1";
    } else {
      return res.status(400).json({
        error: "MCP 需提供 ghcr 镜像地址（image_ref）或上传镜像 tar 包（source_type=tar）",
      });
    }
  }
  if (type === "skill") {
    if (!m.artifact_key) {
      return res.status(400).json({ error: "Skill 需上传制品或填写文件位置" });
    }
    const validation = await validateSkillPackage(m.artifact_key);
    if (!validation.valid) {
      try { await objStore.del(m.artifact_key); } catch (_) {}
      return res.status(400).json({ error: "Skill 包不合规：" + validation.error });
    }
    // 以 SKILL.md 中的 name/description 为权威来源，覆盖表单输入，避免不一致
    m.name = validation.name;
    m.description = validation.description;
  }
  const nm = normName(m.name);
  const existing = db.prepare(
    "SELECT id, status, meta, payload_ref FROM submissions WHERE user_id=? AND type=? AND status IN (" +
    DUP_STATUSES.map(() => "?").join(",") + ")"
  ).all(user_id, type, ...DUP_STATUSES);
  const dup = existing.find((e) => {
    // 多版本场景：同名 + 不同版本号是合法的新版本（如 dws-skill:1.0.0 与 :1.1.0）。
    // 仅当 payload_ref 完全一致时才视为重复提交；这样既能防刷屏，又不阻断版本迭代。
    return e.payload_ref === payload_ref;
  });
  if (dup) {
    return res.status(409).json({
      error: "你已提交过同名/同引用的 " + type + "（当前状态：" + dup.status + "），请勿重复提交",
      existing_id: dup.id,
      existing_status: dup.status,
    });
  }

  // 默认可见范围：新提交默认未上线（visibility_configured=false），仅管理员在已发布管理可见。
  // 管理员审批后在「可见范围」里显式选择并保存 → visibility_configured=true → 才算上线，
  // 此后才对该条目解锁「部署」(MCP) / 对所选成员/组开放目录可见与下载(Skill)。
  // 提交者不感知；存量条目无此字段仍视为已上线（向后兼容）。
  if (!m.visibility) m.visibility = { mode: "restricted", users: [], groups: [] };
  if (typeof m.visibility_configured !== "boolean") m.visibility_configured = false;

  const id = "sub_" + Date.now();
  // 统一用解析后的 m 序列化，保证分级留痕字段（registry_tier 等）一定落库
  const metaJson = rawMeta ? JSON.stringify(m) : null;
  db.prepare(`INSERT INTO submissions VALUES(?,?,?,?,?,?,?,?)`)
    .run(id, user_id, type, payload_ref, "pending", "pending", new Date().toISOString(), metaJson);
  // 派生 group_key / version 并写回 meta，便于后续多版本管理
  ensureGroupMeta({ id, payload_ref, meta: metaJson });
  // 安全扫描（Trivy + Skill 提示词注入规则）异步执行，结果回写 meta.trivy / meta.prompt_scan
  runSubmissionScans(id, type);
  audit(req, "submit", type, id, { payload_ref, source: m.source_type || "unknown" });
  res.json({ id, status: "pending" });
});

// 待审列表。权限规则：管理员看全部；已登录普通用户只看自己的提交；匿名调用返回空。
app.get("/submissions", (req, res) => {
  const actor = actorFromReq(req);
  const rows = db.prepare("SELECT * FROM submissions ORDER BY created_at DESC").all();
  let visible = rows;
  if (!actor.admin) {
    if (!actor.email) {
      visible = [];
    } else {
      visible = rows.filter((r) => String(r.user_id || "").toLowerCase() === actor.email);
    }
  }
  res.json(visible);
});

// 管理员设置条目可见范围（发布时决定哪些成员/组可查看/下载/调用）
app.post("/submissions/:id/visibility", (req, res) => {
  const actor = actorFromReq(req);
  if (!actor.admin)
    return res.status(403).json({ error: "仅管理员可设置可见范围" });
  const sub = db.prepare("SELECT * FROM submissions WHERE id=?").get(req.params.id);
  if (!sub) return res.status(404).json({ error: "submission 不存在" });
  const { mode, users, groups } = req.body || {};
  if (mode !== "all" && mode !== "restricted")
    return res.status(400).json({ error: "mode 必须是 all 或 restricted" });
  const visibility = {
    mode,
    users: Array.isArray(users)
      ? users.map((s) => String(s).trim()).filter(Boolean)
      : [],
    groups: Array.isArray(groups)
      ? groups.map((s) => String(s).trim()).filter(Boolean)
      : [],
  };
  // 管理员显式保存可见范围 = 完成「上线」配置；此后该条目才对所选范围开放可见/下载/调用
  const prevVis = parseMeta(sub).visibility || null;
  patchMeta(sub.id, { visibility, visibility_configured: true });
  // Skill 上架：此前未发布到 Registry（approve 时延后），此刻才发布，使其对目录/用户可发现
  if (sub.type === "skill") {
    registryPublish(sub.id).catch((e) => console.error("同步 Registry 失败(上架):", sub.id, e && e.message));
  }
  audit(req, "visibility_change", sub.type, sub.id, { from: prevVis, to: visibility });
  res.json({ id: sub.id, visibility, visibility_configured: true });
});

// 镜像来源分级查询：供提交表单做实时提示。
// 白名单/内网地址以后端配置为准，避免前端另存一份导致两边不一致。
app.get("/registry/classify", (req, res) => {
  const ref = String(req.query.ref || "").trim();
  if (!ref) return res.status(400).json({ error: "ref 必填" });
  const cls = classifyRegistry(ref);
  res.json({
    ref,
    internal_registry: INTERNAL_REGISTRY,
    internal_only: INTERNAL_ONLY,
    trusted_registries: TRUSTED_REGISTRIES,
    ...cls,
  });
});

// 审批通过 → 管理者确认发布。普通用户提交不带运行地址，MCP 的运行端点由
// 平台在此异步调 ToolHive 部署后自动回填（见 deployMcp）。
app.post("/submissions/:id/approve", async (req, res) => {
  const { id } = req.params;
  const { admin_id, reason, override_scan, confirm_prompt_review } = req.body || {};
  const sub = db.prepare("SELECT * FROM submissions WHERE id=?").get(id);
  if (!sub) return res.status(404).json({ error: "submission 不存在" });
  let meta = parseMeta(sub);
  // ---- 安全扫描闸门（P0 安全链）----
  // Trivy CRITICAL/secret 未特批 → 422，管理员须显式 override_scan=true（写审计）
  if (meta.trivy && meta.trivy.status === "critical" && !override_scan) {
    audit(req, "approve_denied", sub.type, id, { reason: "trivy critical", trivy: meta.trivy }, "denied");
    return res.status(422).json({
      error: "扫描发现 CRITICAL 漏洞或明文密钥，需管理员显式确认放行：请携带 override_scan=true 重新提交审批。",
      trivy: meta.trivy,
    });
  }
  // Skill 提示词注入 alert 未人工确认 → 422，须显式 confirm_prompt_review=true（写审计）
  if (sub.type === "skill" && meta.prompt_scan && meta.prompt_scan.status === "alert" && !confirm_prompt_review) {
    audit(req, "approve_denied", sub.type, id, { reason: "prompt injection alert", prompt_scan: { status: meta.prompt_scan.status, total: meta.prompt_scan.total } }, "denied");
    return res.status(422).json({
      error: "SKILL.md 提示词注入规则命中 alert，需人工逐条审阅并勾选确认：请携带 confirm_prompt_review=true 重新提交审批。",
      prompt_scan: meta.prompt_scan,
    });
  }
  db.prepare("UPDATE submissions SET status='approved', meta=? WHERE id=?")
    .run(JSON.stringify(meta), id);
  db.prepare("INSERT INTO approvals VALUES(?,?,?,?,?,?)")
    .run("ap_" + Date.now(), id, admin_id || "admin", "approved", reason || "", new Date().toISOString());
  audit(req, "approve", sub.type, id, {
    reason: reason || "", admin_id: admin_id || "admin",
    override_scan: Boolean(override_scan), confirm_prompt_review: Boolean(confirm_prompt_review),
    trivy_status: meta.trivy ? meta.trivy.status : "none",
    prompt_scan_status: meta.prompt_scan ? meta.prompt_scan.status : "none",
  });
  // 同步到 Registry Server：先落注册名/版本，便于后续下线/删除时定位条目
  const gv = ensureGroupMeta(sub);
  ensureRegistryMeta(sub);
  // 2026-09-08：active_versions 指针已废弃——用户侧版本下拉可自选已上架版本，
  // 目录默认展示"最新已上架版本"（见 pickDisplayVersions），不再维护激活指针。
  if (sub.type === "skill") {
    // 审批通过：先把 staging 待审暂存区的制品提升(promote)到 published 已发布区。
    // 注意：不在此处 registryPublish —— Skill 默认未上线(visibility_configured=false)，
    // 须等管理员配置可见范围（上架）后才发布到 Registry 目录，真正对用户可发现可下载。
    const m0 = parseMeta(sub);
    if (m0.artifact_key && m0.artifact_key.startsWith("staging/")) {
      const gk = m0.group_key || sub.payload_ref;
      const ver = m0.version || "1.0.0";
      const fn = m0.artifact_filename || path.basename(m0.artifact_key);
      const pub = await promoteArtifact(m0.artifact_key, gk, ver, fn).catch((e) => {
        console.error("[artifact] 提升至已发布区失败(保留原 key):", m0.artifact_key, e && e.message);
        return null;
      });
      if (pub) {
        patchMeta(id, { artifact_key: pub });
        console.log("[artifact] 已提升至已发布区:", m0.artifact_key, "->", pub);
      }
    }
    // 解包 Skill 包提取 README 与文件树（仅当存在制品），结果回写 meta 供详情页展示
    const mInspect = parseMeta(sub);
    if (mInspect.artifact_key) {
      inspectSkillPackage(mInspect.artifact_key).then((insp) => {
        if (insp) patchMeta(id, {
          skill_readme: insp.readme,
          skill_readme_name: insp.readme_name,
          skill_tree: insp.tree,
          skill_file_count: insp.file_count,
        });
      }).catch((e) => console.error("[inspect] skill 解包失败:", id, e && e.message));
    }
  }
  // MCP：审批通过只把制品提升到已发布区 + 落 meta，不再自动部署。
  // 部署改为管理员在「已发布管理/审核队列」里单独点「部署」，成功后再发布到 Registry。
  if (sub.type === "mcp") {
    // tar 提交：把 staging 待审制品提升(promote)到 published 已发布区，供详情页/后续部署读取；
    // 部署按钮内会再 docker load 并 thv run。
    if (meta.source_type === "tar" && meta.artifact_key) {
      if (meta.artifact_key.startsWith("staging/")) {
        const gk = meta.group_key || sub.payload_ref;
        const ver = meta.version || "1.0.0";
        const fn = meta.artifact_filename || path.basename(meta.artifact_key);
        const pub = await promoteArtifact(meta.artifact_key, gk, ver, fn).catch((e) => {
          console.error("[artifact] tar 制品提升至已发布区失败(保留原 key):", meta.artifact_key, e && e.message);
          return null;
        });
        if (pub) {
          patchMeta(id, { artifact_key: pub });
          console.log("[artifact] tar 已提升至已发布区:", meta.artifact_key, "->", pub);
        }
      }
    }
    // 部署状态保持未设置（即 unborn / 未部署），管理员在「已发布管理」里点「部署」才真正拉起。
    // 不写 deploy_status，让前端按其默认态渲染「未部署 + 部署按钮」。
    // 源码包提交（source_type=source）：解包提取 README 回写 meta，供详情页 README 标签展示。
    // 复用 Skill 包解包逻辑，失败不阻断审批主流程。
    if (meta.source_type === "source" && meta.artifact_key) {
      inspectSkillPackage(meta.artifact_key).then((insp) => {
        if (insp) patchMeta(id, {
          mcp_readme: insp.readme,
          mcp_readme_name: insp.readme_name,
          mcp_tree: (insp.tree || []).slice(0, MCP_TREE_MAX),
          mcp_file_count: insp.file_count,
          mcp_readme_inspected: MCP_README_INSPECT_VERSION,
        });
      }).catch((e) => console.error("[inspect] mcp 源码包解包失败:", id, e && e.message));
    }
  }
  res.json({ id, status: "approved" });
});

// 重新部署（失败后重试 / 镜像更新后）
app.post("/submissions/:id/deploy", async (req, res) => {
  const { id } = req.params;
  const sub = db.prepare("SELECT * FROM submissions WHERE id=?").get(id);
  if (!sub) return res.status(404).json({ error: "submission 不存在" });
  if (sub.type !== "mcp") return res.status(400).json({ error: "只有 MCP 可部署" });
  // 部署门禁：必须先由管理员在「可见范围」里显式配置并保存，才算上线、才允许部署
  const dm = parseMeta(sub);
  if (!isOnShelf(dm)) {
    return res.status(400).json({
      id,
      deploy_status: "blocked",
      error: "该 MCP 尚未上线：请先在「可见范围」里选择可查看/调用它的成员或组并保存，之后才能部署。",
    });
  }
  await deployMcp(id);
  const m = parseMeta(db.prepare("SELECT meta FROM submissions WHERE id=?").get(id));
  audit(req, "deploy", sub.type, id, { workload: m.workload_name, deploy_status: m.deploy_status, deploy_error: m.deploy_error || "", image: m.deployed_image || "" }, m.deploy_status === "failed" ? "error" : "success");
  if (m.deploy_status === "failed") {
    return res.status(500).json({ id, deploy_status: "failed", error: m.deploy_error || "部署失败" });
  }
  res.json({ id, deploy_status: m.deploy_status || "deploying" });
});

// 下线：停止容器、清空运行端点，但保留 Registry 目录条目（MCP 界面仍可见）。
app.post("/submissions/:id/undeploy", async (req, res) => {
  const { id } = req.params;
  const sub = db.prepare("SELECT * FROM submissions WHERE id=?").get(id);
  if (!sub) return res.status(404).json({ error: "submission 不存在" });
  if (sub.type !== "mcp") return res.status(400).json({ error: "只有 MCP 可下线" });
  await undeployMcp(id);
  audit(req, "undeploy", sub.type, id, {});
  res.json({ id, deploy_status: "undeployed" });
});

// 重新同步到 Registry Server（同步失败后重试 / 补发布）。
// 仅已发布条目可触发；MCP 需先有运行端点，否则会被 registryPublish 标记 skipped:no-endpoint。
app.post("/submissions/:id/sync", async (req, res) => {
  const { id } = req.params;
  const sub = db.prepare("SELECT * FROM submissions WHERE id=?").get(id);
  if (!sub) return res.status(404).json({ error: "submission 不存在" });
  if (sub.status !== "approved")
    return res.status(400).json({ error: "仅已发布条目可同步到 Registry" });
  await registryPublish(id);
  const m = parseMeta(db.prepare("SELECT meta FROM submissions WHERE id=?").get(id));
  const rs = m.registry_synced || "";
  if (rs === "error") {
    return res.status(500).json({ id, registry_synced: rs, error: m.registry_sync_error || "同步失败" });
  }
  if (rs === "skipped:no-endpoint") {
    return res.status(400).json({ id, registry_synced: rs, error: "该 MCP 尚未成功部署运行（无可用端点），无法同步到 Registry。请先点击「部署」使其启动并产出端点后，再执行同步。" });
  }
  audit(req, "registry_sync", sub.type, id, { registry_synced: rs, error: m.registry_sync_error || "" }, rs === "error" ? "error" : "success");
  res.json({ id, ok: true, registry_synced: rs });
});

// 查询某逻辑产品下的所有已发布版本（MCP / Skill 多版本管理）
// （原 GET /active-versions 与 POST /groups/:group_key/activate/:id 已随激活指针废弃移除）
app.get("/groups/:group_key/versions", (req, res) => {
  const { group_key } = req.params;
  const versions = listGroupVersions(group_key).map((s) => {
    const m = parseMeta(s);
    return {
      id: s.id,
      payload_ref: s.payload_ref,
      version: m.version || "1.0.0",
      name: m.name || s.payload_ref,
      endpoint: m.endpoint || "",
      download_url: m.download_url || "",
      deploy_status: m.deploy_status || "unborn",
      registry_synced: m.registry_synced || "",
      on_shelf: isOnShelf(m), // 是否已上线（管理员配过可见范围）——仅上架版本可被普通用户选择
      created_at: s.created_at,
    };
  });
  res.json({ group_key, versions });
});

// 生命周期状态变更（管理者操作：下架 deprecated / 删除 removed 等）
// 真实同步到 Registry Server（thv-registry-api）的发布/删除会同步执行，
// 确保 Cloud UI /catalog 中的状态与管理后台一致。
app.post("/submissions/:id/status", async (req, res) => {
  const { id } = req.params;
  const { status, admin_id, reason } = req.body || {};
  const sub = db.prepare("SELECT * FROM submissions WHERE id=?").get(id);
  if (!sub) return res.status(404).json({ error: "submission 不存在" });
  const allowed = ["pending", "approved", "deprecated", "removed", "rejected"];
  if (!allowed.includes(status)) {
    return res.status(400).json({ error: "非法的状态: " + status });
  }
  db.prepare("UPDATE submissions SET status=? WHERE id=?").run(status, id);
  db.prepare("INSERT INTO approvals VALUES(?,?,?,?,?,?)")
    .run("ap_" + Date.now(), id, admin_id || "admin", "status:" + status, reason || "", new Date().toISOString());
  audit(req, "status_change", sub.type, id, { from: sub.status, to: status, reason: reason || "" });

  // 拒绝(rejected) 与 删除(removed)：用户上传的制品（Skill zip / MCP tar）已不再需要，
  // 立即释放存储，避免无人回收导致磁盘堆积。下架(deprecated)按设计保留（保温、可恢复），不动制品。
  if (status === "rejected" || status === "removed") {
    deleteSubmissionSecrets(id); // .env 私密配置的凭据库条目同步清除
    const m = parseMeta(sub);
    // 源码构建产生的本地镜像一并清理
    if (m && m.source_type === "source" && m.built_image) {
      execFileHidden("docker", ["rmi", "-f", m.built_image], { timeout: 30000, maxBuffer: MAX_BUFFER }).catch(() => {});
    }
    if (m && m.artifact_key) {
      try {
        await objStore.del(m.artifact_key);
        console.log("[artifact] 已清理制品:", m.artifact_key, "(submission:", id, "status:", status, ")");
      } catch (e) {
        console.error("[artifact] 清理制品失败:", m.artifact_key, e && e.message);
      }
    }
  }

  // 「删除(removed)」：停容器 + 清端点 + 从 Registry 移除 + 清理制品
  // 兜底：单步失败不阻断，保证接口最终能给出响应（否则前端拿不到结果会白屏）
  if (status === "removed" && sub.type === "mcp") {
    try {
      await undeployMcp(id);
    } catch (e) {
      console.error("[lifecycle] 删除时停止实例失败:", id, e && e.message);
    }
  }

  // 「下架(deprecated)」：仅从 Registry 移除目录条目，对用户隐藏；运行实例继续保留，
  // 以便「恢复上架」时无需重新部署即可重新显示。Skill 无容器，同样只删 Registry。
  // 「删除(removed)」：同样从 Registry 移除目录条目。
  if (status === "removed" || status === "deprecated") {
    await registryDelete(id);
  }

  // 恢复上架（approved）：只恢复目录可见性（重新发布到 Registry）。
  // 部署状态（deployed / undeployed / deploying / failed）由「部署 / 下线」独立维护；
  // 上下架属于可见性维度，绝不触碰运行态——否则会出现「容器仍在运行、界面却显示已下线」。
  if (status === "approved") {
    await registryPublish(id);
  }

  res.json({ id, status });
});

// 已审批 skill 列表（供 /skills 浏览页）。多版本场景下每 group 只展示最新已上架的版本。
app.get("/skills", (req, res) => {
  const actor = actorFromReq(req);
  const rows = db.prepare(
    "SELECT * FROM submissions WHERE type='skill' AND status='approved' ORDER BY created_at DESC"
  ).all();
  // 可见性过滤：restricted 条目仅对被授权的成员/组与管理员可见
  const displayRows = pickDisplayVersions(rows)
    .filter((s) => canAccessSubmission(parseMeta(s), actor));

  const dls = db.prepare(
    "SELECT item_ref, COUNT(*) c FROM metric_events WHERE item_type='skill' AND event='download' GROUP BY item_ref"
  ).all();
  const dlMap = {};
  dls.forEach((d) => { dlMap[d.item_ref] = d.c; });
  const result = displayRows.map((s) => {
    const meta = parseMeta(s);
    return {
      id: s.id,
      item_ref: s.id,
      name: meta.name || s.payload_ref,
      description: meta.description || "",
      download_url: meta.artifact_key
        ? `/api/skills/download?group_key=${encodeURIComponent(meta.group_key || s.payload_ref)}&version=${encodeURIComponent(meta.version || "1.0.0")}`
        : (meta.download_url || ""),
      owner: meta.owner || s.user_id,
      download_count: (dlMap[s.id] || 0) + (Number(meta.seed_downloads) || 0),
      created_at: s.created_at,
      registry_synced: meta.registry_synced || "",
      registry_name: meta.registry_name || "",
      group_key: meta.group_key || s.payload_ref,
      version: meta.version || "1.0.0",
      repository_url: meta.repository_url || "",
      skill_readme: meta.skill_readme || null,
      skill_readme_name: meta.skill_readme_name || null,
      skill_tree: meta.skill_tree || [],
      skill_file_count: meta.skill_file_count || 0,
    };
  });
  res.json(result);
});

// Skill 单条（按 submission id），对齐 /mcp/:id 语义：
// 供技能列表卡片版本下拉「就地切换」时按版本取回完整数据。仅当前用户可访问(上架+可见)才返回。
// Skill 源码包元数据懒回填：老记录审批时还没有提取逻辑（skill_readme/skill_tree 为空），
// 详情接口首次访问时补提取一次并落 meta。有 artifact_key 但未提取过的才解包，只做一次。
const SKILL_PKG_INSPECT_VERSION = 1;
async function ensureSkillPackageMeta(s) {
  const meta = parseMeta(s);
  if (!meta.artifact_key) return {};
  if (meta.skill_pkg_inspected === SKILL_PKG_INSPECT_VERSION) {
    return {
      skill_readme: meta.skill_readme || null,
      skill_readme_name: meta.skill_readme_name || null,
      skill_tree: meta.skill_tree || [],
      skill_file_count: meta.skill_file_count || 0,
    };
  }
  const insp = await inspectSkillPackage(meta.artifact_key).catch(() => null);
  const patch = {
    skill_pkg_inspected: SKILL_PKG_INSPECT_VERSION,
    skill_readme: (insp && insp.readme) || null,
    skill_readme_name: (insp && insp.readme_name) || null,
    skill_tree: insp && insp.tree ? insp.tree.slice(0, MCP_TREE_MAX) : [],
    skill_file_count: insp ? insp.file_count : 0,
  };
  patchMeta(s.id, patch);
  return {
    skill_readme: patch.skill_readme,
    skill_readme_name: patch.skill_readme_name,
    skill_tree: patch.skill_tree,
    skill_file_count: patch.skill_file_count,
  };
}

app.get("/skills/:id", async (req, res) => {
  const { id } = req.params;
  const s = db.prepare("SELECT * FROM submissions WHERE id=?").get(id);
  if (!s || s.type !== "skill") return res.status(404).json({ error: "该技能不存在或已被移除" });
  // 未审批/已下架(deprecated)/已删除(removed) 对用户不可见，与列表口径一致
  if (s.status !== "approved")
    return res.status(404).json({ error: "该技能不存在或已下架" });
  if (!canAccessSubmission(parseMeta(s), actorFromReq(req)))
    return res.status(403).json({ error: "你没有权限查看该 Skill（未获管理员授权）" });
  const meta = parseMeta(s);
  const dl = db
    .prepare("SELECT COUNT(*) c FROM metric_events WHERE item_type='skill' AND event='download' AND item_ref=?")
    .get(s.id);
  // 源码包 README/文件树懒回填（老记录首次访问时补提取一次）
  const pkgMeta = await ensureSkillPackageMeta(s);
  res.json({
    id: s.id,
    item_ref: s.id,
    name: meta.name || s.payload_ref,
    description: meta.description || "",
    download_url: meta.artifact_key
      ? `/api/skills/download?group_key=${encodeURIComponent(meta.group_key || s.payload_ref)}&version=${encodeURIComponent(meta.version || "1.0.0")}`
      : (meta.download_url || ""),
    owner: meta.owner || s.user_id,
    download_count: (dl ? dl.c : 0) + (Number(meta.seed_downloads) || 0),
    created_at: s.created_at,
    registry_synced: meta.registry_synced || "",
    registry_name: meta.registry_name || "",
    group_key: meta.group_key || s.payload_ref,
    version: meta.version || "1.0.0",
    repository_url: meta.repository_url || "",
    skill_readme: pkgMeta.skill_readme ?? meta.skill_readme ?? null,
    skill_readme_name: pkgMeta.skill_readme_name ?? meta.skill_readme_name ?? null,
    skill_tree: pkgMeta.skill_tree ?? meta.skill_tree ?? [],
    skill_file_count: pkgMeta.skill_file_count ?? meta.skill_file_count ?? 0,
  });
});

// Skill 指定版本下载：按 group_key + version 定位旧版本（旧版本仍可被引用）
// 流式下载 Skill 制品：优先从 ObjectStore 直接吐字节（带 sha256 校验头），
// 兼容旧的外部/平台 download_url（降级返回 JSON 让客户端二次跳转）。
async function streamSkillArtifact(req, res, s) {
  const m = parseMeta(s);
  db.prepare("INSERT INTO metric_events VALUES(?,?,?,?,?,?)")
    .run("ev_" + Date.now(), "skill", s.id, "download", req.query.user_id || "", new Date().toISOString());
  if (m.artifact_key) {
    try {
      const obj = await objStore.get(m.artifact_key);
      if (obj) {
        // WorkBuddy 导入技能要求 .zip：zip 制品原样透传，tar 系制品解包后重打包为 zip。
        const isZip = m.artifact_key.toLowerCase().endsWith(".zip");
        let payload = obj.buffer;
        let filename = path.basename(m.artifact_key);
        let sha = obj.sha256;
        if (!isZip) {
          payload = await convertArtifactToZip(obj.buffer);
          filename = filename.replace(/\.(tar\.gz|tgz|tar)$/i, "") + ".zip";
          sha = crypto.createHash("sha256").update(payload).digest("hex");
        }
        res.setHeader("Content-Type", "application/zip");
        res.setHeader("Content-Length", payload.length);
        res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
        res.setHeader("X-Content-Sha256", sha);
        return res.send(payload);
      }
    } catch (e) {
      console.error("[download] 取件/转 zip 失败", m.artifact_key, e && e.message);
    }
  }
  const url = m.download_url;
  if (!url) return res.status(404).json({ error: "该版本无可用制品" });
  return res.json({ id: s.id, group_key: m.group_key || req.params.group_key || "", version: m.version || "1.0.0", download_url: url });
}

app.get("/skills/:group_key/:version/download", async (req, res) => {
  const { group_key, version } = req.params;
  const rows = db.prepare(
    "SELECT * FROM submissions WHERE type='skill' AND status='approved' AND (meta LIKE ? OR payload_ref=?)"
  ).all(`%"group_key":"${group_key}"%`, group_key);
  const s = rows.find((r) => {
    const m = parseMeta(r);
    return (m.group_key === group_key || r.payload_ref === group_key) && (m.version || "1.0.0") === version;
  });
  if (!s) return res.status(404).json({ error: "未找到该版本的 Skill" });
  if (!canAccessSubmission(parseMeta(s), actorFromReq(req)))
    return res.status(403).json({ error: "你没有权限下载该 Skill（未获管理员授权）" });
  await streamSkillArtifact(req, res, s);
});

// Skill 按 submission id 直接下载（兼容精确引用）
app.get("/skills/:id/download", async (req, res) => {
  const s = db.prepare("SELECT * FROM submissions WHERE type='skill' AND id=?").get(req.params.id);
  if (!s || s.status !== "approved") return res.status(404).json({ error: "Skill 不存在或未发布" });
  if (!canAccessSubmission(parseMeta(s), actorFromReq(req)))
    return res.status(403).json({ error: "你没有权限下载该 Skill（未获管理员授权）" });
  await streamSkillArtifact(req, res, s);
});

// 已审批 mcp 列表（供 /catalog 浏览页）。多版本场景下每 group 只展示最新已上架的版本。
app.get("/mcp", async (req, res) => {
  const actor = actorFromReq(req);
  const rows = db.prepare(
    "SELECT * FROM submissions WHERE type='mcp' AND status='approved' ORDER BY created_at DESC"
  ).all();
  // 可见性过滤：restricted 条目仅对被授权的成员/组与管理员可见
  const displayRows = pickDisplayVersions(rows)
    .filter((s) => canAccessSubmission(parseMeta(s), actor));
  const calls = db.prepare(
    "SELECT item_ref, COUNT(*) c FROM metric_events WHERE item_type='mcp' AND event='call' GROUP BY item_ref"
  ).all();
  const callMap = {};
  calls.forEach((c) => { callMap[c.item_ref] = c.c; });
  const favs = db.prepare(
    "SELECT item_ref, COUNT(*) c FROM favorites WHERE item_type='mcp' GROUP BY item_ref"
  ).all();
  const favMap = {};
  favs.forEach((f) => { favMap[f.item_ref] = f.c; });
  for (const m of LIVE_MCPS) {
    const ep = await discoverThvEndpoint(m.item_ref);
    if (ep) m.endpoint = ep;
  }
  // 已部署的 MCP 重新发现一次真实 ingress 端口（meta 里存的是部署瞬间的内部端口，
  // 容器重建后会漂移）。每个项一次 docker port 调用，故并发执行并限制条数，
  // 避免条目多时把列表接口拖慢。
  const deployed = displayRows
    .filter((s) => parseMeta(s).deploy_status === "deployed")
    .slice(0, 30);
  // 实例运行时缓存（SWR）：docker 查询 + 探活不再每次全量重做（原先每项 ~450ms）
  const epMap = new Map();
  const rtMissing = [];
  for (const s of deployed) {
    const c = rtCache.get(s.id);
    if (!c) { rtMissing.push(s); continue; }
    const age = Date.now() - c.ts;
    const ttl = c.failed ? RT_FAIL_MS : RT_FRESH_MS;
    // 过期不阻塞：立即用旧值，后台单飞刷新（失败负缓存过期后暂不采用，等刷新结果）
    if (age > ttl && !rtInflight.has(s.id)) rtFetchSingleFlight(s.id, s, { rebuild: false });
    if (!(c.failed && age > RT_FAIL_MS) && c.endpoint) {
      epMap.set(s.id, { endpoint: c.endpoint, healthy: c.healthy });
    }
  }
  await Promise.all(
    rtMissing.map(async (s) => {
      const r = await rtFetchSingleFlight(s.id, s, { rebuild: false });
      if (!r.failed && r.endpoint) {
        epMap.set(s.id, { endpoint: r.endpoint, healthy: r.healthy });
      }
    }),
  );
  const mcpRows = displayRows.map((s) => {
    const row = mapMcpRow(s, callMap, favMap);
    const found = epMap.get(s.id);
    if (found) row.endpoint = found.endpoint;
    // 供列表卡片「复制配置」使用：走后端代理的固定地址（非 127.0.0.1 直连端口）
    if (row.endpoint) {
      row.healthy = found ? found.healthy : false;
      // 不可达就不给对外地址，否则用户复制过去是 502
      if (row.healthy) {
        row.public_endpoint = publicEndpointFor(
          parseMeta(s).workload_name || workloadNameFor(s.id),
          row.endpoint,
          req,
        );
        row.mcp_headers = mcpAuthHeadersFor(
          parseMeta(s).workload_name || workloadNameFor(s.id),
        );
      }
    }
    return row;
  });

  const liveRows = await Promise.all(
    LIVE_MCPS.map(async (m) => {
      const healthy = m.endpoint ? await probeMcpEndpoint(m.endpoint) : undefined;
      return {
        ...m,
        healthy,
        public_endpoint: healthy
          ? publicEndpointFor(m.item_ref, m.endpoint, req)
          : undefined,
        mcp_headers: healthy ? mcpAuthHeadersFor(m.item_ref) : undefined,
        call_count: callMap[m.id] || 0,
        favorite_count: favMap[m.id] || 0,
        created_at: m.created_at || new Date().toISOString(),
      };
    }),
  );
  res.json([...mcpRows, ...liveRows]);
});

// ---- 镜像元数据提取（docker inspect，供详情页「代码」标签展示）----
// 安全红线：Env 一律不提取不展示（镜像常在 ENV 里内置密钥）；entrypoint/cmd 参数与
// labels 按敏感模式（password/secret/token/api key/credential/auth 等）脱敏后才返回。
const INSPECT_SENSITIVE_RE = /(pass(word|wd)?|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential|auth(orization)?|cookie|session|cert|key)/i;
function maskInspectToken(tok) {
  const s = String(tok);
  if (!INSPECT_SENSITIVE_RE.test(s)) return s;
  const eq = s.indexOf("=");
  // key=value 形态保留键名、掩去值；其余整段掩掉
  if (eq > 0 && !/\s/.test(s.slice(0, eq))) return s.slice(0, eq + 1) + "******";
  return "******";
}
function maskInspectLabels(map) {
  const out = {};
  for (const [k, v] of Object.entries(map || {})) {
    out[k] = INSPECT_SENSITIVE_RE.test(k) ? "******" : String(v);
  }
  return out;
}
async function extractMcpInspect(imageRef) {
  try {
    const { stdout } = await execFileHidden(
      "docker", ["inspect", "--format", "{{json .Config}}", imageRef],
      { timeout: 15000, maxBuffer: MAX_BUFFER },
    );
    const cfg = JSON.parse(String(stdout).trim() || "{}");
    const insp = {};
    if (cfg.Labels && Object.keys(cfg.Labels).length) insp.labels = maskInspectLabels(cfg.Labels);
    if (cfg.ExposedPorts) insp.exposed_ports = Object.keys(cfg.ExposedPorts);
    if (Array.isArray(cfg.Entrypoint) && cfg.Entrypoint.length) insp.entrypoint = cfg.Entrypoint.map(maskInspectToken);
    if (Array.isArray(cfg.Cmd) && cfg.Cmd.length) insp.cmd = cfg.Cmd.map(maskInspectToken);
    if (cfg.WorkingDir) insp.working_dir = cfg.WorkingDir;
    // 注意：绝不携带 cfg.Env
    return Object.keys(insp).length ? insp : null;
  } catch (_) {
    return null;
  }
}
// 懒回填：功能上线前已部署成功的记录没有镜像元数据，详情页首次访问时补提取一次
async function ensureMcpInspect(s) {
  const meta = parseMeta(s);
  if (meta.deploy_status !== "deployed" || meta.mcp_inspect) return {};
  const image = meta.deployed_image || meta.recovery_image || meta.internal_ref || meta.image_ref;
  if (!image) return {};
  const insp = await extractMcpInspect(image);
  if (insp) {
    patchMeta(s.id, { mcp_inspect: insp });
    return { mcp_inspect: insp };
  }
  return {};
}

// MCP 源码包 README + 文件树懒回填：功能上线前审批的源码提交没有提取过，
// 详情页首次访问时补提取一次并落 meta。mcp_readme_inspected 存提取规则版本号，
// 规则升级后旧记录会自动用新规则重提一次。
// v3：新增文件树提取（mcp_tree），供「代码」标签页展示 zip 包内文件。
const MCP_README_INSPECT_VERSION = 3;
// 文件树最多落库条数，防止超大包把 meta 撑爆
const MCP_TREE_MAX = 2000;
// 敏感文件不提供内容预览（文件名可列出，内容读取接口会拒绝）
const MCP_SENSITIVE_FILE_RE = /(^|\/)(\.env[^/]*|[^/]*\.(pem|key|p12|pfx|jks|keystore|htpasswd)|id_rsa[^/]*|[^/]*(secret|password|passwd|credential|api[_-]?key)[^/]*)$/i;

async function ensureMcpReadme(s) {
  const meta = parseMeta(s);
  if (meta.source_type !== "source" || !meta.artifact_key) return {};
  if (meta.mcp_readme_inspected === MCP_README_INSPECT_VERSION) {
    return {
      mcp_readme: meta.mcp_readme || null,
      mcp_readme_name: meta.mcp_readme_name || null,
      mcp_tree: meta.mcp_tree || null,
      mcp_file_count: meta.mcp_file_count ?? null,
    };
  }
  const insp = await inspectSkillPackage(meta.artifact_key).catch(() => null);
  const patch = {
    mcp_readme_inspected: MCP_README_INSPECT_VERSION,
    mcp_readme: (insp && insp.readme) || null,
    mcp_readme_name: (insp && insp.readme_name) || null,
    mcp_tree: insp && insp.tree ? insp.tree.slice(0, MCP_TREE_MAX) : null,
    mcp_file_count: insp ? insp.file_count : null,
  };
  patchMeta(s.id, patch);
  return {
    mcp_readme: patch.mcp_readme,
    mcp_readme_name: patch.mcp_readme_name,
    mcp_tree: patch.mcp_tree,
    mcp_file_count: patch.mcp_file_count,
  };
}

// 单个 mcp 详情（供 /mcp/[ref] 详情页）
app.get("/mcp/:id", async (req, res) => {
  const s = db.prepare("SELECT * FROM submissions WHERE id=?").get(req.params.id);
  if (s && !canAccessSubmission(parseMeta(s), actorFromReq(req))) {
    return res.status(403).json({ error: "你没有权限查看该 MCP（未获管理员授权）" });
  }
  if (!s) {
    for (const m of LIVE_MCPS) {
      const ep = await discoverThvEndpoint(m.item_ref);
      if (ep) m.endpoint = ep;
    }
    const live = LIVE_MCPS.find((m) => m.id === req.params.id);
    if (live) {
      const calls = db.prepare(
        "SELECT COUNT(*) c FROM metric_events WHERE item_type='mcp' AND event='call' AND item_ref=?"
      ).get(live.id);
      const favs = db.prepare(
        "SELECT COUNT(*) c FROM favorites WHERE item_type='mcp' AND item_ref=?"
      ).get(live.id);
      const healthy = live.endpoint
        ? await probeMcpEndpoint(live.endpoint)
        : undefined;
      return res.json({
        ...live,
        healthy,
        public_endpoint: healthy
          ? publicEndpointFor(live.item_ref, live.endpoint, req)
          : undefined,
        mcp_headers: healthy ? mcpAuthHeadersFor(live.item_ref) : undefined,
        call_count: calls ? calls.c : 0,
        favorite_count: favs ? favs.c : 0,
        created_at: live.created_at || new Date().toISOString(),
      });
    }
    return res.status(404).json({ error: "mcp 不存在" });
  }
  const calls = db.prepare(
    "SELECT COUNT(*) c FROM metric_events WHERE item_type='mcp' AND event='call' AND item_ref=?"
  ).get(s.id);
  const favs = db.prepare(
    "SELECT COUNT(*) c FROM favorites WHERE item_type='mcp' AND item_ref=?"
  ).get(s.id);
  const row = mapMcpRow(s, { [s.id]: calls.c }, { [s.id]: favs.c });
  // 源码包 README（懒回填：历史提交首次访问时补提取一次，之后读 meta）
  Object.assign(row, await ensureMcpReadme(s));
  // 镜像元数据（懒回填：已部署但未提取过的记录首次访问时补一次）
  Object.assign(row, await ensureMcpInspect(s));
  // 部署时 thv list 报告的内部端口可能不可达；详情页返回前重新动态发现 ingress 端口。
  // 实例运行时缓存（SWR）：命中直接用；miss 时 rebuild 默认开启（保留"访问触发自愈"语义）
  let rt = rtCache.get(s.id);
  if (!rt) {
    rt = await rtFetchSingleFlight(s.id, s);
  } else {
    const age = Date.now() - rt.ts;
    const ttl = rt.failed ? RT_FAIL_MS : RT_FRESH_MS;
    if (age > ttl && !rtInflight.has(s.id)) rtFetchSingleFlight(s.id, s);
  }
  if (rt.endpoint) row.endpoint = rt.endpoint;
  // 只有真的跑起来了才给对外地址，否则用户复制过去是个连不通的空壳
  if (row.endpoint) {
    row.healthy = rt.healthy;
    if (row.healthy) {
      row.public_endpoint = publicEndpointFor(
        parseMeta(s).workload_name || workloadNameFor(s.id),
        row.endpoint,
        req,
      );
      row.mcp_headers = mcpAuthHeadersFor(
        parseMeta(s).workload_name || workloadNameFor(s.id),
      );
    }
  }
  res.json(row);
});

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

app.get("/mcp/:id/file", async (req, res) => {
  const s = db.prepare("SELECT * FROM submissions WHERE id=?").get(req.params.id);
  if (!s) return res.status(404).json({ error: "mcp 不存在" });
  if (!canAccessSubmission(parseMeta(s), actorFromReq(req))) {
    return res.status(403).json({ error: "你没有权限查看该 MCP（未获管理员授权）" });
  }
  await servePackageFile(req, res, s);
});

app.get("/skills/:id/file", async (req, res) => {
  const s = db.prepare("SELECT * FROM submissions WHERE id=?").get(req.params.id);
  if (!s || s.type !== "skill") return res.status(404).json({ error: "skill 不存在" });
  if (!canAccessSubmission(parseMeta(s), actorFromReq(req))) {
    return res.status(403).json({ error: "你没有权限查看该 Skill（未获管理员授权）" });
  }
  await servePackageFile(req, res, s);
});

// 真实 MCP 工具清单：按 id 找到运行中实例，调用 tools/list 返回真实能力。
// 【SWR 缓存层】详情页每点一次都实时握手太慢（秒级），改为三层缓存策略：
//   fresh（60s 内）→ 直接回缓存；stale（60s 后）→ 立即回旧值 + 后台单飞刷新；
//   miss → 现场拉取（并发共享单飞）。失败结果做 30s 负缓存，防对挂掉实例的重试风暴。
//   deploy/undeploy 时主动失效（见 deployMcp/undeployMcp 内 toolsCache.delete）。
const TOOLS_FRESH_MS = 60_000;
const TOOLS_FAIL_MS = 30_000;
const toolsCache = new Map(); // id -> { result, ts, failed }
const toolsInflight = new Map(); // id -> Promise（单飞锁：同 id 并发共享一次握手）

// 现场拉取（原 handler 主体抽出）：无实例/失败均优雅降级，8s 超时防挂住
async function fetchToolsLive(id) {
  let s = db.prepare("SELECT * FROM submissions WHERE id=?").get(id);
  let ep = null;
  if (s) {
    ep = await discoverIngressForSubmission(s);
  } else {
    for (const m of LIVE_MCPS) {
      const e = await discoverThvEndpoint(m.item_ref);
      if (e && m.id === id) { ep = e; break; }
    }
  }
  if (!ep) return { tools: [], live: false };
  const timeout = new Promise((_, rej) => setTimeout(() => rej(new Error("tools/list 超时")), 8000));
  try {
    const r = await Promise.race([mcpCallAuthed(ep, {}, s ? parseMeta(s) : {}), timeout]);
    const last = (r.events && r.events[r.events.length - 1]) || {};
    const tools = last.result && Array.isArray(last.result.tools) ? last.result.tools : [];
    return {
      live: true,
      tools: tools.map((t) => ({
        name: t.name,
        description: t.description || "",
        // 前端按 schema 生成参数模板（字段名/类型/必填），剥离后模板会退化成 {}
        ...(t.inputSchema ? { inputSchema: t.inputSchema } : {}),
      })),
    };
  } catch (e) {
    return { tools: [], live: false, failed: true, error: String((e && e.message) || e) };
  }
}

// 单飞执行：同 id 并发共享同一个进行中的刷新，完成后写缓存
function toolsFetchSingleFlight(id) {
  let p = toolsInflight.get(id);
  if (p) return p;
  p = fetchToolsLive(id)
    .then((r) => {
      toolsCache.set(id, { result: r, ts: Date.now(), failed: !r.live });
      return r;
    })
    .catch((e) => {
      const r = { tools: [], live: false, failed: true, error: String((e && e.message) || e) };
      toolsCache.set(id, { result: r, ts: Date.now(), failed: true });
      return r;
    })
    .finally(() => toolsInflight.delete(id));
  toolsInflight.set(id, p);
  return p;
}

app.get("/mcp/:id/tools", async (req, res) => {
  const id = req.params.id;
  const cached = toolsCache.get(id);
  if (cached) {
    const age = Date.now() - cached.ts;
    const ttl = cached.failed ? TOOLS_FAIL_MS : TOOLS_FRESH_MS;
    // 过期不阻塞：立即回旧值，后台单飞刷新（已有刷新在跑则不重复发起）
    if (age > ttl && !toolsInflight.has(id)) toolsFetchSingleFlight(id);
    return res.json(
      req.query.debug === "1"
        ? { ...cached.result, debug: { cached: true, ageMs: age } }
        : cached.result,
    );
  }
  const r = await toolsFetchSingleFlight(id);
  return res.json(
    req.query.debug === "1" ? { ...r, debug: { cached: false } } : r,
  );
});

// ---- 实例运行时缓存（SWR）：ingress 端点发现（docker 查询）+ 真实探活 ----
// /mcp 列表与 /mcp/:id 每次都对每个实例做 docker 查询 + HTTP 探活（各 ~450ms），
// 目录页 N 轮版本聚合叠加后严重拖慢导航。策略与 toolsCache 一致：
//   fresh 60s 直接回缓存；stale 回旧值 + 后台单飞刷新；失败负缓存 30s；
//   deploy/undeploy 主动失效（与 toolsCache 同点清除）。
const RT_FRESH_MS = 60_000;
const RT_FAIL_MS = 30_000;
const rtCache = new Map(); // id -> { endpoint, healthy, ts, failed }
const rtInflight = new Map(); // id -> Promise（单飞锁）

// 单飞执行：同 id 并发共享同一次 docker 查询 + 探活，完成后写缓存
function rtFetchSingleFlight(id, s, opts = {}) {
  let p = rtInflight.get(id);
  if (p) return p;
  p = (async () => {
    try {
      const ep = await discoverIngressForSubmission(s, opts);
      if (!ep) return { endpoint: null, healthy: false, failed: true };
      const healthy = await probeMcpEndpoint(ep);
      return { endpoint: ep, healthy, failed: !healthy };
    } catch (e) {
      return { endpoint: null, healthy: false, failed: true, error: String((e && e.message) || e) };
    }
  })()
    .then((r) => {
      rtCache.set(id, { ...r, ts: Date.now() });
      return r;
    })
    .finally(() => rtInflight.delete(id));
  rtInflight.set(id, p);
  return p;
}

// 真实 MCP 调用：初始化连接 -> 列出工具 / 调用工具，返回真实结果。
// body: { ref?, endpoint?, tool?, args?, actor_id? }
//   - ref 命中 LIVE_ENDPOINTS 或服务名即 URL 时自动解析端点；
//   - 也可直接传 endpoint 显式指定；
//   - 不传 tool 返回 tools/list，传 tool 返回 tools/call 结果。
app.post("/mcp/call", async (req, res) => {
  const { ref, endpoint, tool, args, actor_id } = req.body || {};
  let ep = null;
  // 1) 对平台已提交的 MCP，优先按 workload 动态发现当前 ingress 端口。
  //    不能信任前端传来的 endpoint，因为 thv list 在部署时报告的是内部端口，浏览器访问不到。
  let s = null;
  if (ref) {
    s = db.prepare("SELECT * FROM submissions WHERE id=? OR payload_ref=?").get(ref, ref);
    if (!s) {
      // ref 是 group_key：回落该组最新已上架版本（激活指针已废弃）
      s = db.prepare(
        "SELECT * FROM submissions WHERE status='approved' AND (meta LIKE ? OR payload_ref=?) ORDER BY created_at DESC"
      ).all(`%"group_key":"${ref}"%`, ref)
       .find((row) => isOnShelf(parseMeta(row)));
    }
  }
  if (s) {
    // 可见性校验：restricted 条目仅对被授权的成员/组与管理员开放调用
    if (!canAccessSubmission(parseMeta(s), actorFromReq(req))) {
      return res.status(403).json({ error: "你没有权限调用该 MCP（未获管理员授权）" });
    }
    ep = rewriteForWsl2(await discoverIngressForSubmission(s));
  }
  // 2) 未命中 submission（如 LIVE_MCPS / Registry Server 条目）按 ref/endpoint 解析
  if (!ep && ref) {
    ep = rewriteForWsl2(await resolveEndpoint(ref, endpoint));
  }
  // 3) 兜底：直接用显式 endpoint
  if (!ep && endpoint) {
    ep = rewriteForWsl2(endpoint);
  }
  if (!ep) return res.status(404).json({ error: "未找到该 MCP 的可调用端点（可能未在平台运行）" });
  if (!(await probeMcpEndpoint(ep))) {
    return res.status(502).json({
      error: "MCP 端点不可达",
      detail: `无法连接到 ${ep}，请确认 ToolHive MCP server 正在运行且端口可访问`,
    });
  }
  try {
    // 平台代调同样自动携带应用自身的 API Key（用户无需也不应知道应用凭证）
    const result = await mcpCallAuthed(ep, { tool, args }, s ? parseMeta(s) : {});
    // 仅在真正执行了某个工具时才记一次调用指标，保持统计语义
    if (tool) {
      db.prepare("INSERT INTO metric_events VALUES(?,?,?,?,?,?)")
        .run("ev_" + Date.now() + "_" + Math.floor(Math.random() * 1000),
          "mcp", ref || ep, "call", actor_id || "", new Date().toISOString());
    }
    res.json({ ok: true, endpoint: ep, ...result });
  } catch (e) {
    res.status(502).json({ error: "调用 MCP 失败", detail: e.message });
  }
});

// 收藏（POST 新增）
app.post("/favorites", (req, res) => {
  const { user_id, item_type, item_ref } = req.body || {};
  if (!user_id || !item_type || !item_ref)
    return res.status(400).json({ error: "user_id, item_type, item_ref 必填" });
  const id = "fav_" + Date.now();
  db.prepare("INSERT INTO favorites VALUES(?,?,?,?,?)")
    .run(id, user_id, item_type, item_ref, new Date().toISOString());
  res.json({ id });
});

// 取消收藏（DELETE，供星标切换）
app.delete("/favorites", (req, res) => {
  const { user_id, item_type, item_ref } = req.body || {};
  if (!user_id || !item_type || !item_ref)
    return res.status(400).json({ error: "user_id, item_type, item_ref 必填" });
  db.prepare("DELETE FROM favorites WHERE user_id=? AND item_type=? AND item_ref=?")
    .run(user_id, item_type, item_ref);
  res.json({ ok: true });
});

// 收藏列表（支持 ?user_id= 只取某用户，用于"我的收藏"）
app.get("/favorites", (req, res) => {
  const { user_id } = req.query;
  const rows = user_id
    ? db
        .prepare(
          "SELECT * FROM favorites WHERE user_id=? ORDER BY created_at DESC",
        )
        .all(user_id)
    : db.prepare("SELECT * FROM favorites ORDER BY created_at DESC").all();
  res.json(rows);
});

// 收藏计数（按 item_type 聚合，返回 {item_ref: count}，供统计页"收藏次数"列）
app.get("/favorites/counts", (req, res) => {
  const { item_type } = req.query;
  if (!item_type)
    return res.status(400).json({ error: "item_type 必填" });
  const rows = db
    .prepare(
      "SELECT item_ref, COUNT(*) c FROM favorites WHERE item_type=? GROUP BY item_ref",
    )
    .all(item_type);
  const map = {};
  rows.forEach((r) => {
    map[r.item_ref] = r.c;
  });
  res.json(map);
});

// 热门排行（按真实事件聚合，Top 20）
app.get("/stats/top", (_req, res) => {
  const rows = db.prepare(`
    SELECT item_type, item_ref, event, COUNT(*) AS cnt
    FROM metric_events GROUP BY item_type, item_ref, event ORDER BY cnt DESC LIMIT 20
  `).all();
  res.json(rows);
});

// 统计明细（全量分组，无 LIMIT，供前端按 mcp/skill 拆分并展示基础信息）
app.get("/stats/detail", (_req, res) => {
  const rows = db.prepare(`
    SELECT item_type, item_ref, event, COUNT(*) AS cnt
    FROM metric_events GROUP BY item_type, item_ref, event ORDER BY cnt DESC
  `).all();
  res.json(rows);
});

// 计数查询：
//   单条  GET /stats/counts?item_type=skill&event=download&item_ref=xxx -> {count:N}
//   批量  GET /stats/counts?item_type=skill&event=download            -> {"ref1":N,"ref2":M}
app.get("/stats/counts", (req, res) => {
  const { item_type, event, item_ref } = req.query;
  if (!item_type || !event)
    return res.status(400).json({ error: "item_type, event 必填" });
  if (item_ref) {
    const row = db.prepare(
      "SELECT COUNT(*) c FROM metric_events WHERE item_type=? AND item_ref=? AND event=?"
    ).get(item_type, item_ref, event);
    return res.json({ count: row ? row.c : 0 });
  }
  const rows = db.prepare(
    "SELECT item_ref, COUNT(*) c FROM metric_events WHERE item_type=? AND event=? GROUP BY item_ref"
  ).all(item_type, event);
  const map = {};
  rows.forEach((r) => { map[r.item_ref] = r.c; });
  res.json(map);
});

// 近 N 天按日事件计数（调用/下载）。返回 {days:[date], series:[{item_type,item_ref,event,data:[cnt...]}]}
app.get("/stats/trend", (req, res) => {
  const days = Math.min(90, Math.max(1, parseInt(String(req.query.days || "30"), 10) || 30));
  const since = new Date(Date.now() - days * 86400000).toISOString().slice(0, 10);
  const rows = db.prepare(
    "SELECT item_type, item_ref, event, substr(occurred_at,1,10) d, COUNT(*) c FROM metric_events " +
    "WHERE occurred_at >= ? AND event IN ('call','download') GROUP BY item_type, item_ref, event, d"
  ).all(since + "T00:00:00");
  // 构建日期轴
  const dayArr = [];
  for (let i = 0; i < days; i++) {
    const d = new Date(Date.now() - (days - 1 - i) * 86400000).toISOString().slice(0, 10);
    dayArr.push(d);
  }
  const map = new Map(); // key type::ref::event
  const idx = {};
  for (const r of rows) {
    const k = r.item_type + "::" + r.item_ref + "::" + r.event;
    if (!map.has(k)) {
      map.set(k, Array(days).fill(0));
      idx[k] = map.size - 1;
    }
    const pos = dayArr.indexOf(r.d);
    if (pos >= 0) map.get(k)[pos] = r.c;
  }
  const series = [];
  for (const [k, data] of map.entries()) {
    const [item_type, item_ref, event] = k.split("::");
    series.push({ item_type, item_ref, event, data });
  }
  res.json({ days: dayArr, series });
});

// 每个 (item_type,item_ref,event) 的去重用户数（近 N 天）
app.get("/stats/unique", (req, res) => {
  const days = Math.min(90, Math.max(1, parseInt(String(req.query.days || "30"), 10) || 30));
  const since = new Date(Date.now() - days * 86400000).toISOString();
  const rows = db.prepare(
    "SELECT item_type, item_ref, event, COUNT(DISTINCT actor_id) u FROM metric_events " +
    "WHERE occurred_at >= ? AND actor_id <> '' GROUP BY item_type, item_ref, event"
  ).all(since);
  res.json(rows);
});

// 指标上报（下载/调用/收藏等事件）
// ---- 反馈 / Issues（平台自建，MCP 与 Skill 共用）----
// target_type: "mcp" | "skill"；target_ref: OCI 引用(serverName:version) 或 submission id
app.post("/issues", (req, res) => {
  const { target_type, target_ref, author, title, body } = req.body || {};
  if (!target_type || !target_ref || !title || !body)
    return res.status(400).json({ error: "target_type / target_ref / title / body 必填" });
  const id = "iss_" + Date.now() + "_" + crypto.randomBytes(3).toString("hex");
  db.prepare("INSERT INTO issues VALUES(?,?,?,?,?,?,?,?,?,?,?)").run(
    id, target_type, target_ref, author || "anonymous", title, body,
    "open", new Date().toISOString(), "", "", "",
  );
  res.json({ id, status: "open" });
});

app.get("/issues", (req, res) => {
  const { target_type, target_ref } = req.query;
  let rows;
  if (target_type && target_ref) {
    rows = db.prepare(
      "SELECT * FROM issues WHERE target_type=? AND target_ref=? ORDER BY created_at DESC"
    ).all(String(target_type), String(target_ref));
  } else if (target_type) {
    rows = db.prepare(
      "SELECT * FROM issues WHERE target_type=? ORDER BY created_at DESC"
    ).all(String(target_type));
  } else {
    rows = db.prepare("SELECT * FROM issues ORDER BY created_at DESC").all();
  }
  res.json(rows);
});

app.put("/issues/:id", (req, res) => {
  const { id } = req.params;
  const { reply, status, reply_by } = req.body || {};
  const row = db.prepare("SELECT * FROM issues WHERE id=?").get(id);
  if (!row) return res.status(404).json({ error: "issue 不存在" });
  const newStatus = status || row.status;
  const newReply = reply !== undefined ? reply : row.reply;
  const repliedAt = reply ? new Date().toISOString() : row.replied_at;
  db.prepare(
    "UPDATE issues SET status=?, reply=?, replied_at=?, reply_by=? WHERE id=?"
  ).run(newStatus, newReply, repliedAt, reply_by || row.reply_by, id);
  res.json({ id, status: newStatus });
});

// 删除 Issue（仅管理员，兜底操作；正常清理以关闭代替删除，对齐 GitHub 模型）
app.delete("/issues/:id", (req, res) => {
  const actor = actorFromReq(req);
  if (!actor.admin) return res.status(403).json({ error: "仅管理员可删除反馈" });
  const { id } = req.params;
  const row = db.prepare("SELECT * FROM issues WHERE id=?").get(id);
  if (!row) return res.status(404).json({ error: "issue 不存在" });
  db.prepare("DELETE FROM issues WHERE id=?").run(id);
  audit(req, "issue_delete", row.target_type, id, { title: row.title, author: row.author });
  res.json({ ok: true, id });
});

// 统一审计轨迹查询（仅管理员）。过滤：actor / action / target_id / from / to（ISO 日期）。
app.get("/audit", (req, res) => {
  const actor = actorFromReq(req);
  if (!actor.admin) return res.status(403).json({ error: "仅管理员可查询审计轨迹" });
  const { actor: filterActor, action, target_id, from, to } = req.query;
  const limit = Math.min(Number(req.query.limit) || 200, 1000);
  const conds = [];
  const params = [];
  if (filterActor) { conds.push("actor_email LIKE ?"); params.push("%" + filterActor + "%"); }
  if (action) { conds.push("action = ?"); params.push(action); }
  if (target_id) { conds.push("target_id = ?"); params.push(target_id); }
  if (from) { conds.push("ts >= ?"); params.push(String(from)); }
  if (to) { conds.push("ts <= ?"); params.push(String(to)); }
  const where = conds.length ? "WHERE " + conds.join(" AND ") : "";
  const rows = db.prepare(
    `SELECT * FROM audit_logs ${where} ORDER BY ts DESC LIMIT ?`
  ).all(...params, limit);
  res.json({ count: rows.length, items: rows });
});

// 管理员手动重跑安全扫描（Trivy + 注入规则），结果回写 meta
app.post("/submissions/:id/rescan", async (req, res) => {
  const actor = actorFromReq(req);
  if (!actor.admin) return res.status(403).json({ error: "仅管理员可重跑扫描" });
  const sub = db.prepare("SELECT * FROM submissions WHERE id=?").get(req.params.id);
  if (!sub || sub.type !== "mcp" && sub.type !== "skill") return res.status(404).json({ error: "submission 不存在" });
  runSubmissionScans(sub.id, sub.type);
  audit(req, "rescan", sub.type, sub.id, {});
  res.json({ id: sub.id, status: "scanning" });
});

app.post("/metrics", (req, res) => {
  const { item_type, item_ref, event, actor_id } = req.body || {};
  if (!item_type || !item_ref || !event)
    return res.status(400).json({ error: "item_type, item_ref, event 必填" });
  const id = "ev_" + Date.now() + "_" + Math.floor(Math.random() * 1000);
  db.prepare("INSERT INTO metric_events VALUES(?,?,?,?,?,?)")
    .run(id, item_type, item_ref, event, actor_id || "", new Date().toISOString());
  res.json({ ok: true });
});

// 显式绑 0.0.0.0：WSL2 下 localhost 常解析到 127.0.0.1，
// 若只绑默认的 IPv6 :: 会导致 curl localhost 连接被拒。
const server = app.listen(PORT, HOST, () =>
  console.log(`平台后端已启动: http://localhost:${PORT} (${HOST}:${PORT})`)
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
