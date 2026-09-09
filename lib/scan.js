// lib/scan.js —— 安全扫描：B) Trivy 漏洞/密钥（扫 tar 本体/本地镜像/Skill 解包）
// C) SKILL.md 提示词注入静态规则。结果落 meta.trivy / meta.prompt_scan。
"use strict";
const fs = require("fs");
const path = require("path");
const os = require("os");

module.exports = function makeScan(ctx) {
  const {
    db, parseMeta, patchMeta, objStore, openSkillPackage, isPathTraversal,
    execFileHidden, PLATFORM_ROOT,
  } = ctx;
  // TAR_ROOT 是 server.js 后部的 const（TDZ），不能在加载期解构——调用期经 ctx 取值
  const tarRoot = () => ctx.TAR_ROOT;

// ---- 安全扫描（B: Trivy 漏洞/密钥；C: SKILL.md 提示词注入静态规则）----
// 结果落 meta.trivy / meta.prompt_scan（patchMeta 惯例），提交后异步执行，不阻塞提交与浏览。
// Trivy 未配置（TRIVY_BIN 不可执行）→ status=skipped，不阻塞审批，日志提示。

// C: 提示词注入静态规则清单（增量维护：加行即扩规则）
// severity: alert=审批须人工逐条确认；warn=提示不强制
const PROMPT_INJECTION_RULES = [
  { id: "INJ-001", category: "指令覆盖", severity: "alert",
    re: /(忽略|无视|覆盖)(以上|之前|先前|前面)?(所有|全部|所有)?(系统)?指令|(disregard|ignore|forget)\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|prompts|rules)/i },
  { id: "INJ-002", category: "指令覆盖", severity: "alert",
    re: /system\s*prompt|系统提示词|你现在是|从现在开始你(是|要|扮演)|act\s+as\s+(an?\s+)?(different|new)/i },
  { id: "INJ-003", category: "数据外传", severity: "alert",
    re: /https?:\/\/(?!localhost|127\.0\.0\.1)[\w.-]+\.[a-z]{2,}/i },
  { id: "INJ-004", category: "数据外传", severity: "alert",
    re: /(发送|上传|上报|外传|post|upload|send|exfiltrate)[^。\n]{0,40}(到|向|to)\s*(外部|远程|第三方)|(send|post|upload)[^。\n]{0,30}(external|remote|third[- ]party)/i },
  { id: "INJ-005", category: "隐匿编码", severity: "alert",
    re: /[\u200b\u200c\u200d\ufeff]/ },
  { id: "INJ-006", category: "隐匿编码", severity: "alert",
    re: /[A-Za-z0-9+/=]{40,}/ },
  { id: "INJ-007", category: "危险API", severity: "warn",
    re: /\beval\s*\(|\bexec\s*\(|child_process|os\.system|subprocess|curl\s+http|wget\s+http/i },
  { id: "INJ-008", category: "危险API", severity: "warn",
    re: /(\.ssh|id_rsa|credentials?|password|api[_-]?key|secret[_-]?key)\s*[:=]/i },
];
// 同形字检测（英文单词中混入西里尔/希腊等同形字母，如 "ѕystem"）
function detectHomoglyph(text) {
  const suspicious = /[\u0400-\u04ff\u0370-\u03ff\u1e00-\u1eff]/g;
  return suspicious.test(text) ? 1 : 0;
}

// B: Trivy 可用性（提交时检测一次，不可执行 → 扫描降级为 skipped）
// 解析顺序：TRIVY_BIN env > 平台自带 tools/trivy/trivy.exe > 不可用（降级 skipped）
const TRIVY_DEFAULT_PATH = path.join(PLATFORM_ROOT, "tools", "trivy", "trivy.exe");
let trivyAvailable = null; // null=未检测
function trivyUsable() {
  if (trivyAvailable !== null) return trivyAvailable;
  if (process.env.TRIVY_BIN && fs.existsSync(process.env.TRIVY_BIN)) {
    trivyAvailable = process.env.TRIVY_BIN;
  } else if (fs.existsSync(TRIVY_DEFAULT_PATH)) {
    trivyAvailable = TRIVY_DEFAULT_PATH;
  } else {
    trivyAvailable = null;
  }
  if (!trivyAvailable) console.warn("[trivy] 未找到 Trivy（TRIVY_BIN 或 tools/trivy/trivy.exe），漏洞扫描降级为 skipped（不阻塞审批）。");
  return trivyAvailable;
}

// B: 对单个 submission 执行 Trivy 扫描并回写 meta.trivy
async function runTrivyScan(id) {
  const sub = db.prepare("SELECT * FROM submissions WHERE id=?").get(id);
  if (!sub || sub.type !== "mcp" && sub.type !== "skill") return;
  const meta = parseMeta(sub);
  const t0 = Date.now();
  const trivyBin = trivyUsable();
  if (!trivyBin) {
    patchMeta(id, { trivy: { status: "skipped", critical: 0, high: 0, secrets: 0, summary: [], scanned_at: new Date().toISOString() } });
    return;
  }
  patchMeta(id, { trivy: { status: "scanning", critical: 0, high: 0, secrets: 0, summary: [], scanned_at: new Date().toISOString() } });
  try {
    let args;
    if (sub.type === "mcp" && meta.source_type === "source" && meta.built_image) {
      // 源码构建提交：直接扫平台构建出的本地镜像
      args = ["image", meta.built_image, "--scanners", "vuln,secret", "--format", "json", "--quiet"];
    } else if (sub.type === "mcp") {
      const tarPath = path.join(tarRoot(), meta.artifact_key || "");
      if (!meta.artifact_key || !fs.existsSync(tarPath)) throw new Error("镜像 tar 不存在: " + meta.artifact_key);
      if (/src\.(tar\.gz|tgz)$|\.zip$/i.test(meta.artifact_key)) {
        // 源码包不是容器镜像，trivy image --input 必然 FATAL（2026-09-07 flowvision 首条即此）。
        // 解包后按 fs 模式扫：lockfile 依赖漏洞 + 全文件密钥。
        const obj = await objStore.get(meta.artifact_key);
        if (!obj || !obj.buffer) throw new Error("制品为空");
        const tmp = path.join(os.tmpdir(), "trivy-src-" + id);
        fs.rmSync(tmp, { recursive: true, force: true });
        fs.mkdirSync(tmp, { recursive: true });
        const pkg = await openSkillPackage(obj.buffer, (meta.artifact_key || "").toLowerCase());
        if (pkg.error) throw new Error("解包失败: " + pkg.error);
        try {
          for (const entry of pkg.entries.slice(0, 500)) {
            if (isPathTraversal(entry)) continue;
            const buf = await pkg.readEntry(entry);
            if (buf && buf.length < 20 * 1024 * 1024) {
              fs.writeFileSync(path.join(tmp, entry.replace(/[\\/]/g, "__")), buf);
            }
          }
        } finally { if (pkg.cleanup) pkg.cleanup(); }
        args = ["fs", tmp, "--scanners", "vuln,secret", "--format", "json", "--quiet"];
      } else {
        args = ["image", "--input", tarPath, "--scanners", "vuln,secret", "--format", "json", "--quiet"];
      }
    } else {
      // Skill 包：解包到临时目录扫密钥泄露
      const obj = await objStore.get(meta.artifact_key);
      if (!obj || !obj.buffer) throw new Error("制品为空");
      const tmp = path.join(os.tmpdir(), "trivy-skill-" + id);
      fs.rmSync(tmp, { recursive: true, force: true });
      fs.mkdirSync(tmp, { recursive: true });
      const lowerKey = (meta.artifact_key || "").toLowerCase();
      const pkg = await openSkillPackage(obj.buffer, lowerKey);
      if (pkg.error) throw new Error("解包失败: " + pkg.error);
      try {
        for (const entry of pkg.entries.slice(0, 200)) {
          if (isPathTraversal(entry)) continue;
          const dest = path.join(tmp, entry.replace(/[\\/]/g, "__"));
          const buf = await pkg.readEntry(entry);
          if (buf && buf.length < 5 * 1024 * 1024) fs.writeFileSync(dest, buf);
        }
      } finally { if (pkg.cleanup) pkg.cleanup(); }
      args = ["fs", tmp, "--scanners", "secret", "--format", "json", "--quiet"];
    }
    // 漏洞库源：默认走 AWS ECR Public（本机环境 mirror.gcr.io/ghcr.io 大文件被代理限速/重置，
    // ECR 实测 110MB 全速下载）。可被 TRIVY_DB_REPOSITORY env 覆盖。
    const out = await execFileHidden(trivyBin, args, {
      timeout: 5 * 60 * 1000,
      maxBuffer: 32 * 1024 * 1024,
      env: { ...process.env, TRIVY_DB_REPOSITORY: process.env.TRIVY_DB_REPOSITORY || "public.ecr.aws/aquasecurity/trivy-db:2" },
    });
    let json;
    try { json = JSON.parse(out.stdout); } catch (_) { throw new Error("trivy 输出解析失败"); }
    let critical = 0, high = 0, secrets = 0;
    const summary = [];
    for (const r of json.Results || []) {
      for (const v of r.Vulnerabilities || []) {
        if (v.Severity === "CRITICAL") { critical++; if (summary.length < 5) summary.push({ id: v.VulnerabilityID, severity: "CRITICAL", pkg: v.PkgName }); }
        else if (v.Severity === "HIGH") high++;
      }
      for (const s of r.Secrets || []) { secrets++; if (summary.length < 5) summary.push({ id: "SECRET", severity: "CRITICAL", pkg: (s.RuleID || "secret") + ":" + (s.StartLine || "?") }); }
    }
    const status = (critical > 0 || secrets > 0) ? "critical" : high > 0 ? "warn" : "clean";
    patchMeta(id, { trivy: { status, critical, high, secrets, summary, scanned_at: new Date().toISOString(), duration_ms: Date.now() - t0 } });
  } catch (e) {
    patchMeta(id, { trivy: { status: "error", critical: 0, high: 0, secrets: 0, summary: [], error: String(e.message || e).slice(0, 300), scanned_at: new Date().toISOString() } });
  }
}

// C: 对 Skill 包执行提示词注入静态规则扫描并回写 meta.prompt_scan
async function runPromptScan(id) {
  const sub = db.prepare("SELECT * FROM submissions WHERE id=?").get(id);
  if (!sub || sub.type !== "skill") return;
  const meta = parseMeta(sub);
  if (!meta.artifact_key) return;
  try {
    const obj = await objStore.get(meta.artifact_key);
    if (!obj || !obj.buffer) throw new Error("制品为空");
    const lowerKey = meta.artifact_key.toLowerCase();
    const pkg = await openSkillPackage(obj.buffer, lowerKey);
    if (pkg.error) throw new Error("解包失败: " + pkg.error);
    const hits = [];
    try {
      for (const entry of pkg.entries) {
        if (isPathTraversal(entry)) continue;
        const lower = entry.toLowerCase();
        const isMd = lower.endsWith(".md");
        const isScript = /\.(py|js|mjs|sh|ps1|bat|cmd)$/.test(lower);
        if (!isMd && !isScript) continue;
        const buf = await pkg.readEntry(entry);
        if (!buf) continue;
        const text = buf.toString("utf8");
        if (detectHomoglyph(text)) {
          hits.push({ rule_id: "INJ-009", category: "隐匿编码", severity: "alert", file: entry, line: 0, excerpt: "检出同形字符（西里尔/希腊字母混入）" });
        }
        const lines = text.split(/\r?\n/);
        for (const rule of PROMPT_INJECTION_RULES) {
          for (let i = 0; i < lines.length; i++) {
            if (rule.re.test(lines[i])) {
              hits.push({ rule_id: rule.id, category: rule.category, severity: rule.severity, file: entry, line: i + 1, excerpt: lines[i].trim().slice(0, 120) });
            }
          }
        }
      }
    } finally { if (pkg.cleanup) pkg.cleanup(); }
    const hasAlert = hits.some((h) => h.severity === "alert");
    patchMeta(id, { prompt_scan: { status: hasAlert ? "alert" : hits.length ? "warn" : "clean", hits: hits.slice(0, 50), total: hits.length, scanned_at: new Date().toISOString() } });
  } catch (e) {
    patchMeta(id, { prompt_scan: { status: "error", hits: [], total: 0, error: String(e.message || e).slice(0, 300), scanned_at: new Date().toISOString() } });
  }
}

// 提交后统一触发（fire-and-forget）。
// 全局串行队列：多条提交并发跑 Trivy 会互踩 trivy-db 缓存锁（Windows 尤甚），必须排队。
// 注释原称"串行"但实现并未串行——2026-09-07 两条同名提交并发扫描，其一挂死卡在 scanning，即此根因。
let scanChain = Promise.resolve();
function runSubmissionScans(id, type) {
  scanChain = scanChain
    .then(async () => {
      try {
        await runTrivyScan(id);
        if (type === "skill") await runPromptScan(id);
      } catch (e) { console.error("[scan] 异常:", e.message); }
    })
    .catch(() => {});
  return scanChain;
}


  return { PROMPT_INJECTION_RULES, trivyUsable, runTrivyScan, runPromptScan, runSubmissionScans };
};
