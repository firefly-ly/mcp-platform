// lib/startup-recovery.js —— 启动恢复（2026-10-15 自 server.js 外迁，逻辑零改动）。
// 进程被杀可能留下永久卡死的 deploy_status='deploying'（部署轮询随进程一起死）。
// 重启后按事实对齐：workload 真在跑 → 收敛为 deployed（含固定端口 ingress/endpoint 回写）；
// workload 不在 → 标记 failed，让管理员用「重新部署」按钮重试（deployMcp 本身幂等可重入）。
"use strict";

/**
 * @param {Object} deps
 * @param {import("better-sqlite3").Database} deps.db
 * @param {{ info(...args: unknown[]): void; error(...args: unknown[]): void }} deps.logger
 * @param {(s: import("./types").SubmissionRow) => import("./types").SubmissionMeta} deps.parseMeta
 * @param {() => Promise<Array<{ name: string, status: string }>>} deps.thvListJson
 * @param {(id: string) => Promise<string|null>} deps.healMcpIngress
 * @param {(id: string, patch: Record<string, unknown>) => void} deps.patchMeta
 * @param {(id: string) => string} deps.workloadNameFor
 */
async function recoverStaleDeploys(deps) {
  const { db, logger, parseMeta, thvListJson, healMcpIngress, patchMeta, workloadNameFor } = deps;
  try {
    const staleRows = /** @type {{ id: string }[]} */ (
      db.prepare("SELECT id FROM submissions WHERE type='mcp'").all()
    );
    const stale = staleRows.filter((r) => {
      const sub = /** @type {import("./types").SubmissionRow} */ (db.prepare("SELECT meta FROM submissions WHERE id=?").get(r.id));
      return parseMeta(sub).deploy_status === "deploying";
    });
    if (!stale.length) return;
    const list = await thvListJson().catch(() => []);
    for (const r of stale) {
      const sub = /** @type {import("./types").SubmissionRow} */ (db.prepare("SELECT meta FROM submissions WHERE id=?").get(r.id));
      const meta = parseMeta(sub);
      const workload = meta.workload_name || workloadNameFor(r.id);
      const entry = list.find((x) => x.name === workload);
      if (entry && entry.status === "running") {
        await healMcpIngress(r.id).catch(() => {});
        const now = parseMeta(/** @type {import("./types").SubmissionRow} */ (db.prepare("SELECT meta FROM submissions WHERE id=?").get(r.id)));
        if (now.deploy_status === "deploying") {
          // 容器在跑但 ingress 收敛失败：至少把状态从 deploying 里解放出来
          patchMeta(r.id, { deploy_status: "deployed", deploy_error: "" });
        }
      } else {
        patchMeta(r.id, { deploy_status: "failed", deploy_error: "服务重启中断部署，workload 不在运行。请点击「重新部署」重试。" });
      }
      logger.info("[启动恢复] 处理卡死的部署:", r.id);
    }
  } catch (e) {
    logger.error("[启动恢复] 失败:", e.message);
  }
}

module.exports = { recoverStaleDeploys };
