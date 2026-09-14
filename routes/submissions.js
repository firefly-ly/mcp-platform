// routes/submissions.js —— Submissions 路由域（2026-09-11 渐进式拆分第四步，自 server.js 原样迁出）
// 覆盖：制品上传 / 源码提交 / .env 配置 / 提交与列表 / 可见范围 / 来源分级 / 审批 /
//   部署 / 下线 / Registry 同步 / 多版本查询 / 生命周期状态 / 重跑扫描。
// 依赖经 ctx 注入；本模块采用「延迟装配」（在 server.js 末尾注册），
// 因为其依赖的常量（RATE_* / DUP_STATUSES / MCP_TREE_MAX / MCP_README_INSPECT_VERSION 等）
// 声明位置靠后，const 无提升——延迟到文件末尾装配可规避 TDZ。
const path = require("node:path");
const fs = require("node:fs");
const crypto = require("node:crypto");
const express = require("express");

// README/文件树提取规则版本号（与 routes/mcp.js 各自独立持有一份，语义一致）
const MCP_README_INSPECT_VERSION = 3;

module.exports = function registerSubmissionsRoutes(app, ctx) {
  const {
    db, parseMeta, patchMeta, actorFromReq, audit, deniedThrottled,
    objStore, stagingKey, sanitizeUploadName, normName, promoteArtifact,
    ensureGroupMeta, ensureRegistryMeta, registryDelete, registryPublish,
    listGroupVersions, classifyRegistry, runSubmissionScans,
    deleteSubmissionSecrets, storeSubmissionEnv, undeployMcp, deployMcp,
    canAccessSubmission, pickDisplayVersions, isOnShelf,
    validateSkillPackage, inspectSkillPackage,
    INTERNAL_PROXY_TOKEN, INTERNAL_REGISTRY, INTERNAL_ONLY, TRUSTED_REGISTRIES,
    RATE_WINDOW_MS, RATE_MAX, DUP_STATUSES, MAX_BUFFER,
    MCP_TREE_MAX, tarListFile, MAX_TAR_UPLOAD_MB, MAX_TAR_UPLOAD_BYTES,
    // 注意：MCP_README_INSPECT_VERSION 不从 ctx 解构——模块顶层已有同名 const(=3)，
    // 若在此解构会以 undefined 遮蔽它，破坏 README 懒回填的版本判断。
  } = ctx;

  // ---- 上传防滥用（身份 + 限流 + 体积上限）----
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
      const name = String(req.query.display_name || filename.replace(/\.(zip|tar\.gz|tgz)$/i, "")).slice(0, 80);
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

  // .env 私密配置上传（值入 ToolHive 加密凭据库，平台只存键名与引用）。
  // Content-Type: text/plain，body 即 .env 原文。仅提交者本人或管理员。
  app.post("/submissions/:id/env", express.raw({ type: "*/*", limit: "256kb" }), (req, res) => {
    const sub = db.prepare("SELECT * FROM submissions WHERE id=?").get(req.params.id);
    if (!sub) return res.status(404).json({ error: "submission 不存在" });
    ctx.storeSubmissionEnv(req, res, sub);
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
        try { await objStore.del(m.artifact_key); } catch (_) {} // 制品可能已不存在，清理失败不掩盖校验失败的主错误
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
        ctx.execFileHidden("docker", ["rmi", "-f", m.built_image], { timeout: 30000, maxBuffer: MAX_BUFFER }).catch(() => {});
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
};
