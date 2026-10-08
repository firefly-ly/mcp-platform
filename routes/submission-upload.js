// routes/submission-upload.js —— 上传/制品入口域（2026-10-08 自 submissions.js 拆出第五刀）
// 覆盖：镜像 tar 上传 / Skill 制品上传 / 源码包上传 / 源码包直接提交，及其共用的
//   防滥用三件套（身份二选一 + 固定窗口限流 + 体积上限）。
// 依赖经 ctx 注入，与 submissions.js 同一份装配块（见 server.js 末尾），语义原样迁出。
"use strict";
const path = require("node:path");
const fs = require("node:fs");
const crypto = require("node:crypto");
const express = require("express");
const createWindowRateLimiter = require("../lib/rate-limit");

module.exports = function registerSubmissionUploadRoutes(app, ctx) {
  const {
    db, parseMeta, actorFromReq, audit, deniedThrottled,
    objStore, stagingKey, sanitizeUploadName, ensureGroupMeta, runSubmissionScans,
    INTERNAL_PROXY_TOKEN, RATE_WINDOW_MS,
    tarListFile, MAX_TAR_UPLOAD_MB, MAX_TAR_UPLOAD_BYTES,
  } = ctx;

  // ---- 上传防滥用（身份 + 限流 + 体积上限）----
  // 上传口（/upload、/upload/tar、/upload/source、/submissions/source）共用：
  //   · 身份：二选一 —— 带内部令牌（前端 Next 服务端转发）或带用户身份 header（网关注入）
  //   · 限流：每身份每小时 UPLOAD_RATE_MAX 次（复用提交防刷的窗口）
  //   · 体积：UPLOAD_MAX_MB（默认 50MB，真实制品远小于此，100MB 是被滥用空间）
  const UPLOAD_MAX_MB = Number(process.env.UPLOAD_MAX_MB || 50);
  const UPLOAD_RATE_MAX = Number(process.env.UPLOAD_RATE_MAX || 10);
  // 固定窗口限流器已抽至 lib/rate-limit.js（now 可注入，可单测），语义与原内联实现一致
  const uploadLimiter = createWindowRateLimiter({ windowMs: RATE_WINDOW_MS, max: UPLOAD_RATE_MAX });
  function uploadAllowed(actor) {
    return uploadLimiter.allowed(actor);
  }
  // 鉴权：内部令牌（Next 服务端转发）或用户身份（网关注入的 x-actor-email）满足其一
  function uploadAuthOk(req) {
    if (req.headers["x-internal-proxy"] === INTERNAL_PROXY_TOKEN) return "internal";
    const actor = actorFromReq(req);
    if (actor.email) return actor.email;
    return null;
  }

  // 接收 docker save 镜像包（.tar/.tar.gz），流式落盘 staging 并校验魔数与 manifest。
  // 2026-09-12 自 server.js 迁入（原留守在 server.js 但调用的 uploadAuthOk/uploadAllowed
  // 已随第四刀迁至本模块 → 任何对该路由的访问都会 ReferenceError 崩溃进程）。
  app.post("/upload/tar", (req, res) => {
    const who = uploadAuthOk(req);
    if (!who) return res.status(401).json({ error: "upload/tar 需要登录身份（请经平台前端上传）" });
    if (!uploadAllowed(who)) return res.status(429).json({ error: "上传过于频繁，请稍后再试" });
    const filename = sanitizeUploadName(req.query.name);
    const key = stagingKey("mcp", filename);
    const fp = path.join(ctx.TAR_ROOT, key);
    fs.mkdirSync(path.dirname(fp), { recursive: true });
    const hash = crypto.createHash("sha256");
    let size = 0;
    let aborted = false;
    const ws = fs.createWriteStream(fp);
    const fail = (code, msg) => {
      if (aborted) return;
      aborted = true;
      try { ws.destroy(); } catch (_) {} // 上传中止后 ws 可能已断开，destroy 幂等
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

  // 接收原始二进制（Skill 包 .tar.gz），落入 ObjectStore，返回内部 key + sha256。
  // 制品来源 = 提交者本人，平台存盘后生成 artifact_key 交回前端，提交时写入 meta。
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
      // 名称自 2026-09-30 起必填：缺失直接拒绝，不再回退文件名
      // （此前回退导致打包文件名里的日期/版本号原样变成条目显示名）
      if (!String(req.query.display_name || "").trim()) {
        return res.status(400).json({ error: "display_name（名称）为必填项" });
      }
      const name = String(req.query.display_name).trim().slice(0, 80);
      // 版本与产品引用：用户表单填了 payload_ref（产品名:版本号）就以其为准；
      // version 缺省时不写死 1.0.0——交由 ensureGroupMeta 从 payload_ref 自动提取
      // （此前前端把空 version 兜底成 "1.0.0" 传入，导致引用里的 :2.0.2 永远不被识别）。
      const userRef = String(req.query.payload_ref || "").trim();
      const version = String(req.query.version || "").trim();
      const id = "sub_" + Date.now();
      const meta = {
        name,
        ...(version ? { version } : {}),
        source_type: "source",
        artifact_key: key,
        artifact_filename: filename,
        visibility: { mode: "restricted", users: [], groups: [] },
        visibility_configured: false,
      };
      const metaJson = JSON.stringify(meta);
      // payload_ref：用户表单填的产品引用（产品名:版本号）优先；未填则回落 zip 文件名
      // （剥掉压缩包扩展名，避免版本提取吃到 ".zip" 尾巴）
      const finalRef = userRef || filename.replace(/\.(zip|tar\.gz|tgz)$/i, "");
      db.prepare(`INSERT INTO submissions VALUES(?,?,?,?,?,?,?,?)`)
        .run(id, user_id, "mcp", finalRef, "pending", "pending", new Date().toISOString(), metaJson);
      ensureGroupMeta({ id, payload_ref: finalRef, meta: metaJson });
      runSubmissionScans(id, "mcp");
      audit(req, "submit", "mcp-source", id, { filename, size: req.body.length });
      res.json({ id, status: "pending" });
    } catch (e) {
      res.status(500).json({ error: String((e && e.message) || e) });
    }
  });
};
