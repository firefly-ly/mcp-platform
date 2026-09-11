// routes/stats.js —— 用量统计路由（2026-09-11 渐进式拆分第一步，自 server.js 原样迁出）
// 依赖经 ctx 注入：db
module.exports = function registerStatsRoutes(app, ctx) {
  const { db } = ctx;

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
};
