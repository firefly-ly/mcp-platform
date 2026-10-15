// lib/requeue-scans.js —— 启动对账：卡在「扫描中」的提交重新排队（2026-10-15 自 server.js 外迁）。
// 扫描是 fire-and-forget：后端进程在扫描完成前重启/崩溃，异步任务连同超时定时器一起丢失，
// meta.trivy / meta.prompt_scan 会永远停在 scanning（2026-09-07 flowvision 首条提交即此情况）。
// 启动后统一检查，把卡在 scanning 的记录重新入队（runSubmissionScans 内部为全局串行队列）。
"use strict";

/**
 * @param {import("better-sqlite3").Database} db
 * @param {{ info(...args: unknown[]): void }} logger
 * @param {(id: string, type: string) => void} runSubmissionScans
 */
function requeueStuckScans(db, logger, runSubmissionScans) {
  let n = 0;
  const rows = /** @type {{ id: string, type: string, meta: string }[]} */ (db.prepare("SELECT id, type, meta FROM submissions").all());
  for (const r of rows) {
    let m;
    try { m = JSON.parse(r.meta || "{}"); } catch { continue; }
    const trivyStuck = m.trivy && m.trivy.status === "scanning";
    const promptStuck = m.prompt_scan && m.prompt_scan.status === "scanning";
    if (trivyStuck || promptStuck) {
      runSubmissionScans(r.id, r.type);
      n++;
    }
  }
  if (n) logger.info(`[scan] 启动对账：${n} 条提交卡在扫描中，已重新排队`);
}

module.exports = { requeueStuckScans };
