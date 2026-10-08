// routes/submissions.js —— Submissions 路由域：提交 / 列表 / 可见范围 / 来源分级 / 审批 /
//   部署 / 下线 / Registry 同步 / 多版本查询 / 生命周期状态 / 重跑扫描。
// （2026-10-08 拆分第五刀：上传域 → routes/submission-upload.js，.env 配置域 → routes/submission-env.js）
// 依赖经 ctx 注入；本模块采用「延迟装配」（在 server.js 末尾注册），
// 因为其依赖的常量（RATE_* / DUP_STATUSES / MCP_TREE_MAX / MCP_README_INSPECT_VERSION 等）
// 声明位置靠后，const 无提升——延迟到文件末尾装配可规避 TDZ。
"use strict";
const path = require("node:path");

// README/文件树提取规则版本号（与 routes/mcp.js 各自独立持有一份，语义一致）
const MCP_README_INSPECT_VERSION = 3;

module.exports = function registerSubmissionsRoutes(app, ctx) {
  const {
    db, parseMeta, patchMeta, actorFromReq, audit,
    objStore, normName, promoteArtifact,
    ensureGroupMeta, ensureRegistryMeta, registryDelete, registryPublish,
    listGroupVersions, classifyRegistry, runSubmissionScans,
    deleteSubmissionSecrets, undeployMcp, deployMcp,
    canAccessSubmission, pickDisplayVersions, isOnShelf,
    validateSkillPackage, inspectSkillPackage,
    INTERNAL_REGISTRY, INTERNAL_ONLY, TRUSTED_REGISTRIES,
    RATE_WINDOW_MS, RATE_MAX, DUP_STATUSES, MAX_BUFFER,
    MCP_TREE_MAX,
    // 注意：MCP_README_INSPECT_VERSION 不从 ctx 解构——模块顶层已有同名 const(=3)，
    // 若在此解构会以 undefined 遮蔽它，破坏 README 懒回填的版本判断。
  } = ctx;

  // 提交（落暂存，status=pending）。meta 存放 name/description/download_url 等扩展字段。
  app.post("/submissions", async (req, res) => {
    const { user_id, type, payload_ref, meta } = req.body || {};
    if (!user_id || !type || !payload_ref)
      return res.status(400).json({ error: "user_id, type, payload_ref 必填" });
    // 名称自 2026-09-30 起必填（meta.name 缺失即拒绝，不再回退 payload_ref 显示）
    if (!meta || !String(meta.name || "").trim())
      return res.status(400).json({ error: "meta.name（名称）为必填项" });

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

    // 数据源声明（两段式豁免第 1 段：提交者声明意图）。可选项：非法/缺失不阻断提交，
    // 规整失败直接丢弃——审批页看不到声明自然不会给豁免，安全默认不受影响。
    if (m.data_source !== undefined) {
      const ds = m.data_source && typeof m.data_source === "object" ? m.data_source : {};
      const dsType = String(ds.type || "none").trim();
      if (["none", "http_api", "database"].includes(dsType)) {
        m.data_source = {
          type: dsType,
          targets: Array.isArray(ds.targets)
            ? ds.targets.map((t) => String(t).trim()).filter(Boolean).slice(0, 10)
            : [],
          note: String(ds.note || "").slice(0, 200),
        };
      } else {
        delete m.data_source;
      }
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
    const { admin_id, reason, override_scan, confirm_prompt_review, exempt_network } = req.body || {};
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
    // 两段式豁免第 2 段：审批授权。admin 显式勾选（exempt_network=true）才写标记，
    // 提交者的 data_source 声明只是意图，永远不能自己生效。授权随审批进审计轨迹。
    if (exempt_network === true || exempt_network === "true") {
      meta.network_exempt = true;
    }
    db.prepare("UPDATE submissions SET status='approved', meta=? WHERE id=?")
      .run(JSON.stringify(meta), id);
    db.prepare("INSERT INTO approvals VALUES(?,?,?,?,?,?)")
      .run("ap_" + Date.now(), id, admin_id || "admin", "approved", reason || "", new Date().toISOString());
    audit(req, "approve", sub.type, id, {
      reason: reason || "", admin_id: admin_id || "admin",
      override_scan: Boolean(override_scan), confirm_prompt_review: Boolean(confirm_prompt_review),
      exempt_network: meta.network_exempt === true,
      data_source: meta.data_source || null,
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
    try {
      await deployMcp(id);
    } catch (e) {
      // DEPLOY_BUSY：同一 MCP 已有部署/下线在进行，拒绝并发触发（前端提示稍后再试）
      if (e && e.code === "DEPLOY_BUSY") return res.status(409).json({ id, error: e.message });
      return res.status(500).json({ id, error: "部署触发失败: " + (e && e.message) });
    }
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
    try {
      await undeployMcp(id);
    } catch (e) {
      if (e && e.code === "DEPLOY_BUSY") return res.status(409).json({ id, error: e.message });
      return res.status(500).json({ id, error: "下线触发失败: " + (e && e.message) });
    }
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
    // hard:true —— 删除提交必须 thv rm 整组移除（下线语义的 stop 会留下已停容器成为孤儿）
    if (status === "removed" && sub.type === "mcp") {
      try {
        await undeployMcp(id, { hard: true });
      } catch (e) {
        if (e && e.code === "DEPLOY_BUSY") {
          // 删除撞上部署/下线进行中：回滚刚写的状态（审批流水保留作痕迹），409 让管理员稍后重删
          db.prepare("UPDATE submissions SET status=? WHERE id=?").run(sub.status, id);
          return res.status(409).json({ id, error: "该 MCP 正在部署/下线中，请等待当前操作完成后再删除" });
        }
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
