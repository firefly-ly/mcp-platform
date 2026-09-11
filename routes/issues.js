// routes/issues.js —— 反馈 / Issues 路由（2026-09-11 渐进式拆分第一步，自 server.js 原样迁出）
// 平台自建反馈体系，MCP 与 Skill 共用。
// 依赖经 ctx 注入：db、actorFromReq（管理员判定）、audit（删除动作留痕）
const crypto = require("node:crypto");

module.exports = function registerIssuesRoutes(app, ctx) {
  const { db, actorFromReq, audit } = ctx;

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
};
