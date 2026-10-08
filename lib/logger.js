// lib/logger.js —— 轻量统一日志（零依赖）：时间戳 + 级别前缀，stderr/stdout 分流。
// 2026-10-08 引入：替代 server.js 中的散装 console.log/error，保留 console 的
// 输出通道（stdout=info、stderr=warn/error）以便 journalctl / 重定向按现状消费。
"use strict";

function ts() {
  return new Date().toISOString();
}

function fmt(level, args) {
  return `[${ts()}] [${level}] ${args.map((a) => (typeof a === "string" ? a : JSON.stringify(a))).join(" ")}`;
}

const logger = {
  info(...args) {
    console.log(fmt("INFO", args));
  },
  warn(...args) {
    console.error(fmt("WARN", args));
  },
  error(...args) {
    console.error(fmt("ERROR", args));
  },
};

module.exports = logger;
