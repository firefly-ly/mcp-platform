// lib/self-heal.js —— 后台自愈「健康探测自愈」层（2026-10-15 自 server.js 外迁，逻辑零改动）。
// 每 60s 巡检所有 deployed MCP 的固定端口 ingress：探测失败 → 重建 socat ingress
// （端口不变，hash 派生）→ 回写 meta.endpoint。这样即使无人访问列表页/代理（以前只有
// 被动触发），坏 ingress 也会在 1 分钟内被修好。单飞锁防重入；巡检逐条串行避免打爆 docker。
"use strict";

/**
 * @param {Object} deps
 * @param {import("better-sqlite3").Database} deps.db
 * @param {{ info(...args: unknown[]): void; error(...args: unknown[]): void; debug(...args: unknown[]): void }} deps.logger
 * @param {() => Promise<void>} deps.reconcileMcpWorkloads
 * @param {(id: string) => Promise<string|null>} deps.healMcpIngress
 * @param {Map<string, { fails: number, nextTryAt: number }>} deps.healFailState
 * @param {number} deps.HEAL_BACKOFF_MS
 */
function createSelfHeal(deps) {
  const { db, logger, reconcileMcpWorkloads, healMcpIngress, healFailState, HEAL_BACKOFF_MS } = deps;
  let healing = false;

  async function selfHealIngresses() {
    if (healing) return;
    healing = true;
    try {
      await reconcileMcpWorkloads().catch((e) => logger.error("[workload 对账] 异常:", e.message));
      const now = Date.now();
      const rows = /** @type {{ id: string }[]} */ (db.prepare("SELECT id FROM submissions WHERE type='mcp'").all());
      for (const r of rows) {
        const st = healFailState.get(r.id);
        if (st && st.fails >= 3 && now < st.nextTryAt) continue; // 退避中
        try {
          const p = await healMcpIngress(r.id);
          if (p) healFailState.delete(r.id);
          else {
            const fails = ((healFailState.get(r.id) || {}).fails || 0) + 1;
            healFailState.set(r.id, { fails, nextTryAt: now + (fails >= 3 ? HEAL_BACKOFF_MS : 0) });
          }
        } catch (_) { /* 单条失败不影响其余 */ }
      }
    } finally {
      healing = false;
    }
  }

  /** 每 60s 巡检一次（unref 不阻止进程退出） */
  function scheduleSelfHeal() {
    return setInterval(() => { selfHealIngresses().catch(() => {}); }, 60 * 1000).unref();
  }

  return { selfHealIngresses, scheduleSelfHeal };
}

module.exports = { createSelfHeal };
