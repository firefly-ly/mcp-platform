// routes/audit.js —— 审计轨迹查询路由（2026-09-11 渐进式拆分第一步，自 server.js 原样迁出）
// 依赖经 ctx 注入：db、actorFromReq（管理员判定）
module.exports = function registerAuditRoutes(app, ctx) {
  const { db, actorFromReq } = ctx;

  // 统一审计轨迹查询（仅管理员）。过滤：actor / action / target_id / from / to（ISO 日期）。
  // 分页：limit（默认 50，≤200）+ offset；total 返回 WHERE 命中总数（区别于 count=本页条数）。
  app.get("/audit", (req, res) => {
    const actor = actorFromReq(req);
    if (!actor.admin) return res.status(403).json({ error: "仅管理员可查询审计轨迹" });
    const { actor: filterActor, action, target_id, from, to } = req.query;
    const limit = Math.min(Math.max(Number(req.query.limit) || 50, 1), 200);
    const offset = Math.max(Number(req.query.offset) || 0, 0);
    const conds = [];
    const params = [];
    if (filterActor) { conds.push("actor_email LIKE ?"); params.push("%" + filterActor + "%"); }
    if (action) { conds.push("action = ?"); params.push(action); }
    if (target_id) { conds.push("target_id = ?"); params.push(target_id); }
    if (from) { conds.push("ts >= ?"); params.push(String(from)); }
    if (to) { conds.push("ts <= ?"); params.push(String(to)); }
    const where = conds.length ? "WHERE " + conds.join(" AND ") : "";
    const total = db.prepare(
      `SELECT COUNT(*) c FROM audit_logs ${where}`
    ).get(...params).c;
    const rows = db.prepare(
      `SELECT * FROM audit_logs ${where} ORDER BY ts DESC LIMIT ? OFFSET ?`
    ).all(...params, limit, offset);
    res.json({ count: rows.length, total, limit, offset, items: rows });
  });
};
