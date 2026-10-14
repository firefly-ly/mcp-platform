// lib/seed.js —— 首次运行种子数据（2026-10-14 自检整改自 server.js 外迁，逻辑零改动）。
// 仅当 submissions 表为空时写入 demo skill / demo mcp 与指标事件，给空库一个可浏览的初始形态。
"use strict";

/** @param {object} db better-sqlite3 实例 @param {object} logger logger 实例（info/warn） */
function seedIfEmpty(db, logger) {
  try {
    const subCnt = db.prepare("SELECT COUNT(*) c FROM submissions").get().c;
    if (subCnt > 0) return; // 已有人提交过，不再塞 demo
    const now = Date.now();
    const insSub = db.prepare("INSERT INTO submissions VALUES(?,?,?,?,?,?,?,?)");
    const insMet = db.prepare("INSERT INTO metric_events VALUES(?,?,?,?,?,?)");

    // demo 已审批 skill
    const skills = [
      { ref: "dws-explorer:1.0.0", name: "DWS 数据探查器", desc: "一键连接数仓、自动探查表结构与数据质量，生成可视化探查报告。", dl: 128 },
      { ref: "meeting-minutes:0.2.1", name: "会议纪要生成器", desc: "上传会议录音或文字记录，自动提炼决议、待办与责任人，推送企微。", dl: 64 },
      { ref: "code-reviewer:1.1.0", name: "代码审查助手", desc: "针对 PR/MR 做增量审查，给出风险点、合规项与修复建议。", dl: 211 },
    ];
    skills.forEach((d, i) => {
      const id = "seed_skill_" + i;
      insSub.run(
        id, "admin", "skill", d.ref, "approved", "passed",
        new Date(now - i * 86400000).toISOString(),
        JSON.stringify({ name: d.name, description: d.desc, download_url: "", seed_downloads: d.dl, owner: "platform" }),
      );
      const k = Math.min(5, d.dl);
      for (let j = 0; j < k; j++) {
        insMet.run("ev_seed_" + i + "_" + j, "skill", id, "download", "demo", new Date(now - j * 3600000).toISOString());
      }
    });

    // demo 已审批 mcp（用户提交的 MCP，审核通过后进入目录）
    const mcps = [
      { ref: "dingtalk-notify:0.3.0", name: "钉钉通知 MCP", desc: "把告警、审批、定时任务结果推送到钉钉群，支持富文本与@人。", owner: "alice" },
      { ref: "sql-query:1.4.2", name: "SQL 查询 MCP", desc: "面向业务人员的自然语言转 SQL，只读模式连接内网数据库并可视化结果。", owner: "bob" },
    ];
    mcps.forEach((d, i) => {
      const id = "seed_mcp_" + i;
      insSub.run(
        id, d.owner, "mcp", d.ref, "approved", "passed",
        new Date(now - i * 86400000).toISOString(),
        JSON.stringify({ name: d.name, description: d.desc, owner: d.owner }),
      );
      const k = i + 2; // 一些调用事件
      for (let j = 0; j < k; j++) {
        insMet.run("ev_mcp_seed_" + i + "_" + j, "mcp", id, "call", "demo", new Date(now - j * 3600000).toISOString());
      }
    });

    logger.info("已写入 demo skill / mcp 与指标种子数据");
  } catch (e) {
    logger.warn("种子数据写入失败（可忽略，不影响运行）:", e.message);
  }
}

module.exports = { seedIfEmpty };
