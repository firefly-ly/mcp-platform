// routes/skills.js —— Skill 路由（2026-09-11 渐进式拆分第二步，自 server.js 原样迁出）
// 覆盖：列表 / 单条 / 指定版本下载 / 按 id 下载 / 源码包文件预览。
// 依赖经 ctx 注入：db、parseMeta、actorFromReq、canAccessSubmission、pickDisplayVersions、
//   inspectSkillPackage、convertArtifactToZip、objStore、patchMeta、servePackageFile、MCP_TREE_MAX
const crypto = require("node:crypto");
const path = require("node:path");

module.exports = function registerSkillsRoutes(app, ctx) {
  const {
    db, parseMeta, actorFromReq, canAccessSubmission, pickDisplayVersions,
    inspectSkillPackage, convertArtifactToZip, objStore, patchMeta,
    servePackageFile, MCP_TREE_MAX,
  } = ctx;

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

  // 源码包文件预览路由（servePackageFile 共享实现仍留在 server.js，经 ctx 注入）
  app.get("/skills/:id/file", async (req, res) => {
    const s = db.prepare("SELECT * FROM submissions WHERE id=?").get(req.params.id);
    if (!s || s.type !== "skill") return res.status(404).json({ error: "skill 不存在" });
    if (!canAccessSubmission(parseMeta(s), actorFromReq(req))) {
      return res.status(403).json({ error: "你没有权限查看该 Skill（未获管理员授权）" });
    }
    await servePackageFile(req, res, s);
  });
};
