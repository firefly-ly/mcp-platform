// lib/rate-limit.js —— 固定窗口限流器（纯逻辑，2026-10-08 自 routes/submissions.js 抽出）。
// 语义与原 uploadAllowed 完全一致：窗口内首次访问计数置 1 并放行；超窗口重置；
// Map 超 10000 项时顺手清理过期项防膨胀。差异仅一点：now 可注入，便于单测。
"use strict";

/** @param {Object} opts @param {number} opts.windowMs 窗口毫秒 @param {number} opts.max 窗口内最大次数 */
module.exports = function createWindowRateLimiter({ windowMs, max }) {
  const map = new Map(); // key -> [windowStart, count]

  return {
    /** @param {string} key 身份键（邮箱/令牌） @param {number} [now] 可注入时钟 */
    allowed(key, now = Date.now()) {
      const entry = map.get(key);
      if (!entry || now - entry[0] > windowMs) {
        map.set(key, [now, 1]);
        // 顺手清理过期项，防 Map 无限膨胀
        if (map.size > 10000) {
          for (const [k, v] of map) {
            if (now - v[0] > windowMs) map.delete(k);
          }
        }
        return true;
      }
      entry[1]++;
      return entry[1] <= max;
    },
    /** 仅供测试/运维观测 */
    get size() {
      return map.size;
    },
  };
};
