// lib/maintenance.js —— 数据库日常维护（2026-10-14 自检整改自 server.js 外迁，逻辑零改动）。
// 每日两件事：① VACUUM INTO 一致性快照备份（保留最近 N 份）；② metric_events 埋点表
// 90 天清理（无限增长会拖慢列表页/stats 全表聚合查询）。
"use strict";
const fs = require("node:fs");
const path = require("node:path");

/** 每日备份：VACUUM INTO 生成一致性快照（在线安全，不动 WAL），同日已有则跳过，保留最近 keep 份 */
/**
 * @param {import("better-sqlite3").Database} db
 * @param {{ info(...args: unknown[]): void; error(...args: unknown[]): void }} logger
 * @param {string} backupDir
 * @param {number} [keep=14]
 */
function backupDatabase(db, logger, backupDir, keep = 14) {
  try {
    fs.mkdirSync(backupDir, { recursive: true });
    const stamp = new Date().toISOString().slice(0, 10);
    const dest = path.join(backupDir, `platform-${stamp}.db`);
    if (fs.existsSync(dest)) return; // 同一天已有备份，不覆盖
    db.prepare("VACUUM INTO ?").run(dest);
    // 只保留最近 N 份
    const files = fs.readdirSync(backupDir)
      .filter((f) => /^platform-\d{4}-\d{2}-\d{2}\.db$/.test(f))
      .sort();
    while (files.length > keep) {
      const f = files.shift();
      if (!f) break;
      try { fs.unlinkSync(path.join(backupDir, f)); } catch (_) { break; }
    }
    logger.info("[维护] 数据库备份完成:", dest);
  } catch (e) {
    logger.error("[维护] 数据库备份失败:", e instanceof Error ? e.message : String(e));
  }
}

/** metric_events 埋点表清理：保留 90 天（ISO 字符串可直接字典序比较） */
/**
 * @param {import("better-sqlite3").Database} db
 * @param {{ info(...args: unknown[]): void; error(...args: unknown[]): void }} logger
 */
function pruneMetricEvents(db, logger) {
  try {
    const cutoff = new Date(Date.now() - 90 * 24 * 3600 * 1000).toISOString();
    const info = db.prepare("DELETE FROM metric_events WHERE occurred_at < ?").run(cutoff);
    if (info.changes > 0) logger.info(`[维护] metric_events 清理 ${info.changes} 条（>90 天）`);
  } catch (e) {
    logger.error("[维护] metric_events 清理失败:", e instanceof Error ? e.message : String(e));
  }
}

/** 执行一轮维护（备份 + 清理） */
function runDailyMaintenance(db, logger, backupDir, keep = 14) {
  backupDatabase(db, logger, backupDir, keep);
  pruneMetricEvents(db, logger);
}

/** 启动时先跑一次（当天已有备份则跳过），并挂 24h 周期任务（unref 不阻止进程退出） */
function scheduleDailyMaintenance(db, logger, backupDir, keep = 14) {
  runDailyMaintenance(db, logger, backupDir, keep);
  return setInterval(() => runDailyMaintenance(db, logger, backupDir, keep), 24 * 3600 * 1000).unref();
}

module.exports = { backupDatabase, pruneMetricEvents, runDailyMaintenance, scheduleDailyMaintenance };
