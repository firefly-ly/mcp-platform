// lib/audit.js —— 统一审计轨迹（2.4.4）。
// 七要素：谁/何时/对什么/做了什么/怎么做的/结果。只增不删改；denied 类 60s 节流防灌爆。
"use strict";

module.exports = function makeAudit(ctx) {
  const { db, actorFromReq } = ctx;

// ---- 统一审计轨迹（2.4.4）----
// 七要素：谁/何时/对什么/做了什么/怎么做的/结果。治理动作全量记录，拒绝与失败同权记录。
// detail 里放"决策相关快照"（前后状态、override 标记、扫描摘要），不放请求体全文。
function audit(req, action, targetType, targetId, detail, result = "success") {
  try {
    const actor = actorFromReq(req);
    db.prepare("INSERT INTO audit_logs VALUES(?,?,?,?,?,?,?,?,?)").run(
      "at_" + Date.now() + "_" + Math.floor(Math.random() * 100000),
      new Date().toISOString(),
      actor.email || "(anonymous)",
      actor.admin ? 1 : 0,
      action, targetType, targetId || "",
      typeof detail === "string" ? detail : JSON.stringify(detail || {}),
      result,
    );
  } catch (e) {
    console.error("[audit] 写入失败:", e.message);
  }
}

// denied 类审计节流：同 key 60s 只记一条，防止攻击者刷接口灌爆审计表
const deniedThrottleMap = new Map();
function deniedThrottled(key) {
  const now = Date.now();
  if (now - (deniedThrottleMap.get(key) || 0) < 60 * 1000) return false;
  deniedThrottleMap.set(key, now);
  if (deniedThrottleMap.size > 5000) deniedThrottleMap.clear();
  return true;
}


  return { audit, deniedThrottled };
};
