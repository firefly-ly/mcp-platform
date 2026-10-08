// 固定窗口限流器单测（lib/rate-limit.js）——now 可注入，覆盖窗口边界语义
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const createWindowRateLimiter = require("../../lib/rate-limit");

test("窗口内首次访问放行并计数 1", () => {
  const rl = createWindowRateLimiter({ windowMs: 3600_000, max: 3 });
  assert.equal(rl.allowed("a@x.com", 1000), true);
  assert.equal(rl.size, 1);
});

test("窗口内超过 max 次后拒绝", () => {
  const rl = createWindowRateLimiter({ windowMs: 3600_000, max: 3 });
  assert.equal(rl.allowed("a@x.com", 1000), true);
  assert.equal(rl.allowed("a@x.com", 1001), true);
  assert.equal(rl.allowed("a@x.com", 1002), true);
  assert.equal(rl.allowed("a@x.com", 1003), false);
  assert.equal(rl.allowed("a@x.com", 1004), false);
});

test("不同身份各自独立计数", () => {
  const rl = createWindowRateLimiter({ windowMs: 3600_000, max: 1 });
  assert.equal(rl.allowed("a@x.com", 1000), true);
  assert.equal(rl.allowed("a@x.com", 1001), false);
  assert.equal(rl.allowed("b@x.com", 1001), true);
});

test("窗口过期后重新计数（语义 = 原 uploadAllowed：now - entry[0] > windowMs 即重置）", () => {
  const rl = createWindowRateLimiter({ windowMs: 1000, max: 1 });
  assert.equal(rl.allowed("a@x.com", 1000), true);
  assert.equal(rl.allowed("a@x.com", 1000 + 1000), false); // 恰好等于窗口长度：仍在窗口内
  assert.equal(rl.allowed("a@x.com", 1000 + 1000 + 1), true); // 超过窗口：重置放行
});

test("Map 超 10000 项触发过期清理（防膨胀逻辑）", () => {
  const rl = createWindowRateLimiter({ windowMs: 1000, max: 1 });
  const base = 1000;
  for (let i = 0; i < 10001; i++) rl.allowed(`user${i}@x.com`, base);
  // 第 10001 次触发清理：只有过期项（now - v[0] > windowMs）会被清掉，未过期的保留
  assert.ok(rl.size <= 10001);
  // 时间推进后再次触发清理，过期项全部被清掉
  rl.allowed("fresh@x.com", base + 5000);
  assert.equal(rl.size, 1);
});
