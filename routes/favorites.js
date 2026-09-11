// routes/favorites.js —— 收藏路由（2026-09-11 渐进式拆分第一步，自 server.js 原样迁出）
// 依赖经 ctx 注入：db（保持单一连接与既有事务语义）
module.exports = function registerFavoritesRoutes(app, ctx) {
  const { db } = ctx;

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
};
