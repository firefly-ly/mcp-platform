// routes/submission-env.js —— .env 私密配置域（2026-10-08 自 submissions.js 拆出第五刀）
// 覆盖：.env 上传（值入 ToolHive 加密凭据库，平台只存键名与引用）与键名清单查询。
// 依赖经 ctx 注入，与 submissions.js 同一份装配块（见 server.js 末尾），语义原样迁出。
"use strict";
const express = require("express");

module.exports = function registerSubmissionEnvRoutes(app, ctx) {
  const { db, parseMeta, actorFromReq, storeSubmissionEnv } = ctx;

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
};
