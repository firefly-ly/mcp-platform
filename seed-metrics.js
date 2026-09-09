// 一次性造数脚本：给近 30 天 metric_events 灌入模拟使用数据
// 用法：node seed-metrics.js （在 platform-backend 目录下运行，复用其 better-sqlite3）
const Database = require("better-sqlite3");
const db = new Database("platform.db");
db.pragma("busy_timeout = 5000");

// 8 个模拟用户
const ACTORS = [
  "zhang.san", "li.si", "wang.wu", "zhao.liu",
  "chen.qi", "sun.ba", "zhou.jiu", "wu.shi",
];

// 每个 item 的用量画像：base 基量、growth 日增长系数、weekday 工作日加成、
// tailDay 截止日（该日之后归零，模拟下线/故障）、spike [日,倍数]（临时高峰）
const PROFILE = [
  // MCP 调用（event=call）
  { type: "mcp", ref: "sub_1788829366889", base: 4, growth: 1.045, weekday: 1.7, actors: 8 },   // 新零售：持续增长的主力
  { type: "mcp", ref: "seed_mcp_1", base: 5, growth: 0.92, weekday: 1.2, tailDay: 21, actors: 4 }, // SQL查询：前 3 周活跃后故障下线
  { type: "mcp", ref: "seed_mcp_0", base: 1, growth: 1.0, weekday: 1.3, actors: 3 },            // 钉钉通知：低频稳定
  { type: "mcp", ref: "sub_1787904001595", base: 0, spikeDays: [9, 14, 22], perSpike: [6, 4, 3], actors: 2 }, // endpoint-verify：偶发验证
  // Skill 下载（event=download）
  { type: "skill", ref: "seed_skill_0", base: 2, growth: 1.06, weekday: 1.4, actors: 7 },       // DWS 探查器：快速增长
  { type: "skill", ref: "seed_skill_1", base: 4, growth: 1.0, weekday: 1.5, actors: 6 },        // 会议纪要：平稳高频
  { type: "skill", ref: "seed_skill_2", base: 1, growth: 1.02, weekday: 1.2, spike: [14, 9], actors: 4 }, // 代码审查：中期推广高峰
  { type: "skill", ref: "sub_1788404379662", base: 4, growth: 0.9, weekday: 1.2, actors: 5 },   // hello-report 旧版：衰减
  { type: "skill", ref: "sub_1788423526647", base: 1, growth: 1.09, weekday: 1.4, actors: 5 },  // hello-report 新版：接棒增长
];

const EVENT = { mcp: "call", skill: "download" };
const DAYS = 30;

function pick(arr) { return arr[Math.floor(Math.random() * arr.length)]; }

const rows = [];
const now = new Date();
for (const p of PROFILE) {
  for (let i = 0; i < DAYS; i++) {
    const dayOffset = DAYS - 1 - i; // 29(最早) -> 0(今天)
    if (p.tailDay !== undefined && i > p.tailDay) continue; // tailDay 之前（日序）停止
    const date = new Date(now.getTime() - dayOffset * 86400000);
    const dow = date.getUTCDay();
    let n = Math.round(p.base * Math.pow(p.growth || 1, i) * (p.weekday && dow >= 1 && dow <= 5 ? p.weekday : 0.45));
    if (p.spike && p.spike[0] === i) n += p.spike[1];
    if (p.spikeDays) {
      const si = p.spikeDays.indexOf(i);
      if (si >= 0) n += p.perSpike[si];
    }
    n = Math.max(0, n + Math.floor(Math.random() * 3) - 1); // ±1 抖动
    const pool = ACTORS.slice(0, p.actors);
    for (let j = 0; j < n; j++) {
      const h = 1 + Math.floor(Math.random() * 13); // UTC 1-13 时 ≈ 本地 9-21 点
      const t = new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate(), h, Math.floor(Math.random() * 60)));
      rows.push([
        `ev_seed_${p.ref}_${i}_${j}`, p.type, p.ref, EVENT[p.type],
        pick(pool), t.toISOString(),
      ]);
    }
  }
}

const tx = db.transaction(() => {
  const ins = db.prepare("INSERT OR IGNORE INTO metric_events VALUES(?,?,?,?,?,?)");
  let n = 0;
  for (const r of rows) n += ins.run(...r).changes;
  return n;
});
const inserted = tx();
console.log(`计划 ${rows.length} 条，实际插入 ${inserted} 条`);

// 汇总校验
const check = db.prepare(
  "SELECT item_type, item_ref, event, COUNT(*) c, COUNT(DISTINCT actor_id) u " +
  "FROM metric_events WHERE occurred_at >= ? GROUP BY item_type, item_ref, event ORDER BY c DESC"
).all(new Date(now.getTime() - 30 * 86400000).toISOString());
console.log("近30天分布：");
for (const r of check) console.log(`  ${r.item_type}/${r.ref} ${r.event}: ${r.c} 次, ${r.u} 人`);
